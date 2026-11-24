"""Executor-boundary orchestration between Home Assistant and the TCP transport.

:class:`TcpStationTransport` is blocking by design (one TCP socket, two daemon
threads). This module is the only place allowed to drive it, and it does so
exclusively through ``hass.async_add_executor_job`` so the event loop never
touches a socket or ffmpeg. It also enforces the behaviour the station's own
firmware demands:

* **one session at a time** -- the station serves a single app session; a live
  view, a ringing call or the phone app blocks snapshot, stream and unlock. A
  per-station lock serialises every command here.
* **a short gap** -- after a session closes the station needs about a second
  before the next one carries video (:data:`SESSION_MIN_GAP`); a session opened
  sooner logs in but stays without video and is retried once. The gap is skipped
  when the station never took a session (it stayed silent).
* **nothing is held** -- a session is closed the moment its command is done, so
  the phone app and the indoor monitor are not locked out. ``warm_idle`` (off by
  default) can keep it open for a few seconds for a quick second command.
* **a door command never waits for a live view** -- while one runs, the command
  goes out over the live view's own session and the picture keeps running.

Transport errors are mapped to the entity-facing exceptions that camera.py and
lock.py expect (:class:`StationBusyError`, :class:`StationSilentError`).

Attribution: the slot / warm-session lifecycle, the single-session serialisation,
the snapshot/stream/clip/open-door flow shapes and the mjpeg transcoding pipe are
ported from ``p2p.py`` of balter-evo-ha (https://github.com/LucaHerrero/balter-evo-ha,
MIT licensed), re-pointed from the UDP ``_P2PTransport`` onto
:class:`TcpStationTransport`.
"""

from __future__ import annotations

import contextlib
import functools
import logging
import queue
import secrets
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import IO

from homeassistant.core import HomeAssistant

from . import media, protocol
from .const import (
    DEFAULT_WARM_IDLE,
    LOGIN_TIMEOUT,
    MEDIA_START_TIMEOUT,
    OEM_ID_COMPACT,
    SESSION_MIN_GAP,
    STATION_PORT,
    STREAM_DURATION,
)
from .models import Credentials, Device
from .protocol import MediaPacket
from .transport import (
    DoorRejectedError,
    StationBusyError,
    StationSilentError,
    TcpStationTransport,
    TransportError,
)

_LOGGER = logging.getLogger(__name__)

__all__ = [
    "StationManager",
    "DoorRejectedError",
    "StationBusyError",
    "StationSilentError",
    "TransportError",
]

# How long the whole door-unlock session may take (handshake + readiness + ack).
DOOR_SESSION_TIMEOUT = 20.0

# Snapshot recording window: an upper bound. A still ends it as soon as the
# first keyframe has arrived (about half a second after the login).
SNAPSHOT_WINDOW = 6.0

# A clip records for its whole window; video starts ~0.5 s after the login.
CLIP_LEAD_SECONDS = 1.0

# A session kept open after a command is reused on the next one only while the
# socket is still alive; nothing else is probed, since TCP self-maintains.

# Signature that makes a warm session reusable: same secrets, same OEM. A cloud
# key rotation changes it and the stale session is dropped instead of reused.
type _Signature = tuple[str, str, str]


# --- Result of one unlock attempt -------------------------------------------


@dataclass
class UnlockResult:
    """How far one unlock attempt got.

    Truthy exactly when the station acknowledged the command. The flags tell the
    two failure modes apart: a stalled handshake means the command never left the
    client (safe to retry), a missing ack means the door may have opened (must
    not be retried).
    """

    ready: bool = False  # station freed its app session
    sent: bool = False  # OPENDOOR left the client
    acked: bool = False  # station acknowledged (0xFE msg13=4)
    rejected: bool = False  # station refused the command (wrong door PIN)
    silent: bool = False  # station never answered the handshake

    def __bool__(self) -> bool:
        """Report whether the door station confirmed the unlock."""
        return self.acked


# --- Warm-session bookkeeping -----------------------------------------------


class _WarmSession:
    """A session kept open after a command, with a timer that closes it.

    The transport maintains itself (receive + keepalive threads), so keeping a
    session "warm" is only a matter of not closing it yet. A one-shot timer
    closes it when the hold time runs out; :meth:`take` adopts it before then.
    Exactly one of expiry / take / discard ever closes it.
    """

    def __init__(
        self,
        manager: StationManager,
        duid: str,
        transport: TcpStationTransport,
        signature: _Signature,
        idle: float,
    ) -> None:
        """Start holding ``transport`` open for at most ``idle`` seconds."""
        self._manager = manager
        self.duid = duid
        self.transport = transport
        self.signature = signature
        self._lock = threading.Lock()
        self._done = False
        self._timer = threading.Timer(idle, self._expire)
        self._timer.daemon = True
        self._timer.start()

    def take(self) -> TcpStationTransport | None:
        """Adopt the still-open session, or ``None`` if it expired or died."""
        with self._lock:
            if self._done or not self.transport.is_alive:
                return None
            self._done = True
            self._timer.cancel()
            return self.transport

    def discard(self) -> None:
        """Stop the timer and close the session now."""
        with self._lock:
            if self._done:
                return
            self._done = True
            self._timer.cancel()
        self.transport.close()
        self._manager._mark_session_end(self.duid)

    def _expire(self) -> None:
        with self._lock:
            if self._done:
                return
            self._done = True
        _LOGGER.debug(
            "Warm session with %s expired -- releasing the station", self.duid
        )
        self._manager._forget_warm(self.duid, self)
        self.transport.close()
        self._manager._mark_session_end(self.duid)


class _Slot:
    """Mutable holder passed to a command body while it owns the station slot."""

    def __init__(self, warm_idle: float) -> None:
        """Start with no session; the context manager fills it."""
        self.transport: TcpStationTransport | None = None
        self.keep_warm = False
        self.settle = 0.0
        self.warm_idle = warm_idle

    def drop_transport(self) -> None:
        """Close the current session -- it turned out unusable -- without a gap.

        A session that was handed in but is already dead means the station freed
        it itself, so no recovery gap applies; the body then reconnects.
        """
        transport = self.transport
        self.transport = None
        self.keep_warm = False
        if transport is not None:
            transport.close()


class StationManager:
    """One manager per config entry; owns every local session to the stations."""

    def __init__(
        self,
        hass: HomeAssistant,
        host_resolver: Callable[[Device], str | None],
        client_id: str | None = None,
        oem: str = OEM_ID_COMPACT,
        warm_idle: float = DEFAULT_WARM_IDLE,
    ) -> None:
        """Create the manager.

        ``host_resolver`` maps a :class:`Device` to its current LAN host (the
        station wanders without a DHCP reservation). ``client_id`` is the 16-hex
        identity put in the station LOGIN; the station accepts any well-formed id
        (verified live), so a throwaway one is generated when none is given.
        ``warm_idle`` keeps a session open after a command for that many seconds.
        """
        self._hass = hass
        self._resolve_host = host_resolver
        self._client_id = (client_id or secrets.token_hex(8)).lower()
        self._oem = oem
        # Seconds a session stays open after a command (0 = close at once).
        self._warm_idle = max(float(warm_idle), 0.0)

        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()
        self._last_end: dict[str, float] = {}
        self._warm: dict[str, _WarmSession] = {}
        self._warm_guard = threading.Lock()
        # Number of unlocks waiting for the slot, per station (a count, not a
        # flag: two may wait at once and the first must not clear the second).
        self._unlock_wanted: dict[str, int] = {}
        self._unlock_guard = threading.Lock()
        # Serialises door commands sent over a running live view and keeps the
        # live view from closing its session while one is awaiting its answer.
        self._live_locks: dict[str, threading.Lock] = {}
        # Session of a running live view per station: a door command is sent
        # over it instead of ending the view to open a session of its own.
        self._live: dict[str, TcpStationTransport] = {}
        self._last_handshake: dict[str, str] = {}

    # --- Diagnostics ---------------------------------------------------------

    def handshake_states(self) -> dict[str, str]:
        """Return the last handshake state seen per station (for diagnostics)."""
        return dict(self._last_handshake)

    # --- Public async API ----------------------------------------------------

    async def async_snapshot(self, device: Device, creds: Credentials) -> bytes | None:
        """Fetch a single JPEG still over one short station session."""
        return await self._hass.async_add_executor_job(
            functools.partial(self._snapshot_sync, device, creds)
        )

    async def async_stream(
        self,
        device: Device,
        creds: Credentials,
        duration: float,
        on_jpeg: Callable[[bytes], None],
        should_stop: Callable[[], bool],
    ) -> int:
        """Run a bounded live MJPEG stream; returns the number of frames emitted."""
        return await self._hass.async_add_executor_job(
            functools.partial(
                self._stream_sync, device, creds, duration, on_jpeg, should_stop
            )
        )

    async def async_record_clip(
        self, device: Device, creds: Credentials, seconds: float
    ) -> bytes | None:
        """Record a short MP4 clip."""
        return await self._hass.async_add_executor_job(
            functools.partial(self._record_clip_sync, device, creds, seconds)
        )

    async def async_open_door(
        self,
        device: Device,
        creds: Credentials,
        door: int,
        locknumber: int,
        pin_sha256: str | None,
    ) -> bool:
        """Unlock a door relay. ``True`` on ack; ``False`` sent-but-unacked.

        Raises :class:`DoorRejectedError` when the station refused the command
        (wrong door PIN), :class:`StationBusyError` when the station never freed its session
        (the command provably never went out -> safe to retry later) and
        :class:`StationSilentError` when it never answered at all (retry now, no
        recovery gap). A sent-but-unacknowledged open returns ``False`` and is
        NEVER retried here: a second send could open the door twice.
        """
        result = await self._hass.async_add_executor_job(
            functools.partial(
                self._open_door_sync, device, creds, door, locknumber, pin_sha256
            )
        )
        if result.acked:
            return True
        if result.rejected:
            raise DoorRejectedError(
                "The door station refused the command -- the door PIN is wrong."
            )
        if result.sent:
            return False
        if result.silent:
            raise StationSilentError(
                "The door station did not answer the connection attempt."
            )
        raise StationBusyError(
            "The door station did not free its single app session "
            "(probably still busy with an earlier session)."
        )

    async def async_release_all(self) -> None:
        """Close every warm session so the station is free again (on unload)."""
        await self._hass.async_add_executor_job(self._release_all_sync)

    # --- Slot / warm-session internals (executor thread) ---------------------

    def _lock_for(self, duid: str) -> threading.Lock:
        with self._locks_guard:
            lock = self._locks.get(duid)
            if lock is None:
                lock = threading.Lock()
                self._locks[duid] = lock
            return lock

    def _mark_session_end(self, duid: str) -> None:
        self._last_end[duid] = time.monotonic()

    def _forget_warm(self, duid: str, warm: _WarmSession) -> None:
        with self._warm_guard:
            if self._warm.get(duid) is warm:
                del self._warm[duid]

    def _take_warm(
        self, duid: str | None, signature: _Signature | None
    ) -> TcpStationTransport | None:
        """Adopt the warm session of ``duid``; discard this station's stale one.

        The single-session constraint is per physical station, so only a warm
        session held for *this* ``duid`` is touched -- reused when its secrets
        still match, discarded when they were rotated. Other stations keep their
        warm sessions (they have their own slot), so a command on one station no
        longer tears down another's.
        """
        wanted: _WarmSession | None = None
        stale: list[_WarmSession] = []
        with self._warm_guard:
            if duid is not None and duid in self._warm:
                session = self._warm.pop(duid)
                if signature is not None and session.signature == signature:
                    wanted = session
                else:
                    stale.append(session)
        for warm in stale:
            warm.discard()
        return wanted.take() if wanted is not None else None

    def _store_warm(
        self,
        duid: str,
        transport: TcpStationTransport,
        signature: _Signature,
        idle: float,
    ) -> None:
        if idle <= 0 or not transport.is_alive:
            transport.close()
            self._mark_session_end(duid)
            return
        with self._warm_guard:
            self._warm[duid] = _WarmSession(self, duid, transport, signature, idle)
        _LOGGER.debug("Keeping the session with %s warm for %.0fs", duid, idle)

    def _release_all_sync(self) -> None:
        with self._warm_guard:
            warm = list(self._warm.values())
            self._warm.clear()
        for session in warm:
            session.discard()

    @contextmanager
    def _slot(
        self,
        purpose: str,
        duid: str,
        signature: _Signature,
        reuse: bool,
        warm_idle: float,
    ) -> Iterator[_Slot]:
        """Hold the station's single slot for one command (executor thread)."""
        lock = self._lock_for(duid)
        started = time.monotonic()
        lock.acquire()
        blocked = time.monotonic() - started
        if blocked > 1.0:
            _LOGGER.info("%s waited %.0fs for the station slot", purpose, blocked)
        slot = _Slot(warm_idle)
        try:
            slot.transport = self._take_warm(duid if reuse else None, signature)
            if slot.transport is not None:
                _LOGGER.debug("%s reuses the open session with %s", purpose, duid)
            else:
                last = self._last_end.get(duid, time.monotonic() - SESSION_MIN_GAP)
                wait = SESSION_MIN_GAP - (time.monotonic() - last)
                if wait > 0:
                    _LOGGER.info(
                        "%s waits %.1fs so the station can recover", purpose, wait
                    )
                    time.sleep(wait)
            yield slot
        except BaseException:
            transport = slot.transport
            slot.transport = None
            if transport is not None:
                silent = getattr(transport, "station_silent", False)
                transport.close()
                if not silent:
                    self._mark_session_end(duid)
            raise
        else:
            transport = slot.transport
            slot.transport = None
            if transport is not None and slot.keep_warm and warm_idle > 0:
                self._store_warm(duid, transport, signature, warm_idle)
            elif transport is not None:
                if slot.settle > 0:
                    time.sleep(slot.settle)
                silent = getattr(transport, "station_silent", False)
                transport.close()
                if not silent:
                    self._mark_session_end(duid)
        finally:
            lock.release()

    # --- Session construction ------------------------------------------------

    def _make_transport(
        self, device: Device, creds: Credentials
    ) -> TcpStationTransport:
        host = self._resolve_host(device)
        if not host:
            raise TransportError(
                f"No LAN host known for {device.duid} -- set it in the integration "
                "options (the station has no DHCP reservation)."
            )
        return TcpStationTransport(
            host,
            STATION_PORT,
            device.duid,
            creds.dynamic_password,
            creds.data_encode_key,
            self._client_id,
            self._oem,
        )

    def _signature(self, creds: Credentials) -> _Signature:
        return (creds.dynamic_password, creds.data_encode_key, self._oem)

    def _record_handshake(self, transport: TcpStationTransport) -> None:
        self._last_handshake[transport.duid] = transport.handshake_states()

    def _video_session(
        self,
        slot: _Slot,
        device: Device,
        creds: Credentials,
        on_media: Callable[[MediaPacket], None],
        should_stop: Callable[[], bool] | None = None,
    ) -> TcpStationTransport | None:
        """Return a session that is delivering video, or ``None``.

        Reuses a warm session the slot handed in (just re-point the media sink);
        otherwise connects fresh. There is no play command -- the station streams
        on its own once the login is accepted. A session that logs in but gets no
        video (the station was reconnected to too soon, or somebody else is
        watching) is closed and tried once more after the minimum gap.
        """
        transport = slot.transport
        if transport is not None:
            if transport.is_alive and transport.media_started.is_set():
                transport.set_media_sink(on_media)
                return transport
            reached = transport.logged_in.is_set()
            slot.drop_transport()
            if reached:
                # It did occupy the station: the gap applies before reconnecting.
                self._mark_session_end(device.duid)
                time.sleep(SESSION_MIN_GAP)

        if not creds.dynamic_password:
            _LOGGER.error(
                "No dynamic_password for %s -- not opening a session", device.duid
            )
            return None

        for attempt in (1, 2):
            transport = self._make_transport(device, creds)
            transport.set_media_sink(on_media)
            slot.transport = transport
            connected = transport.connect(LOGIN_TIMEOUT)
            if connected and transport.wait(transport.logged_in, LOGIN_TIMEOUT):
                transport.send_session_setup()
                if transport.wait(transport.media_started, MEDIA_START_TIMEOUT):
                    self._record_handshake(transport)
                    return transport
            self._record_handshake(transport)
            reached = transport.logged_in.is_set()
            slot.drop_transport()
            if not reached:
                # Unreachable or refused: a second attempt would not differ.
                return None
            self._mark_session_end(device.duid)
            if should_stop is not None and should_stop():
                return None
            if attempt == 1:
                _LOGGER.debug(
                    "Station %s opened a session without video -- retrying once",
                    device.duid,
                )
                time.sleep(SESSION_MIN_GAP)
        _LOGGER.warning(
            "Station %s accepted the login but sent no video -- it is probably "
            "serving another viewer (phone app or indoor monitor)",
            device.duid,
        )
        return None

    # --- Priority signal (unlock preempts a running stream) ------------------

    def _set_unlock_wanted(self, duid: str, wanted: bool) -> None:
        with self._unlock_guard:
            count = self._unlock_wanted.get(duid, 0) + (1 if wanted else -1)
            self._unlock_wanted[duid] = max(count, 0)

    def _unlock_pending(self, duid: str) -> bool:
        return self._unlock_wanted.get(duid, 0) > 0

    def _live_lock(self, duid: str) -> threading.Lock:
        with self._locks_guard:
            lock = self._live_locks.get(duid)
            if lock is None:
                lock = self._live_locks[duid] = threading.Lock()
            return lock

    def _release_or_hand_over(
        self, slot: _Slot, transport: TcpStationTransport, what: str
    ) -> None:
        """Hand a camera session to a waiting unlock, or close it.

        An unlock that interrupted a stream would otherwise pay the whole
        handshake plus the recovery gap again, for a session already logged in.
        """
        transport.set_media_sink(None)
        if (
            slot.warm_idle > 0
            and self._unlock_pending(transport.duid)
            and transport.device_ready.is_set()
            and transport.is_alive
        ):
            _LOGGER.info(
                "Handing the open session over from the %s to the unlock", what
            )
            slot.keep_warm = True
            return
        # Not handed over and not kept warm: close now and record the session end
        # so the recovery gap applies before the next command. A live session
        # that just ended DID occupy the station (unlike the warm-reuse-found-dead
        # case drop_transport handles), so skipping the gap here would let the
        # next snapshot/stream start too soon and stall at LOGIN.
        mark_end = transport.logged_in.is_set() and not getattr(
            transport, "station_silent", False
        )
        slot.transport = None
        slot.keep_warm = False
        transport.close()
        if mark_end:
            self._mark_session_end(transport.duid)

    # --- Sync workers (executor thread) --------------------------------------

    def _snapshot_sync(self, device: Device, creds: Credentials) -> bytes | None:
        packets = self._grab_video_sync(
            "Snapshot", device, creds, SNAPSHOT_WINDOW, stop_on_keyframe=True
        )
        keyframe = next((p for p in packets if p.is_keyframe), None)
        return media.h264_to_jpeg(keyframe.data) if keyframe else None

    def _record_clip_sync(
        self, device: Device, creds: Credentials, seconds: float
    ) -> bytes | None:
        window = float(seconds) + CLIP_LEAD_SECONDS
        packets = self._grab_video_sync(
            "Clip", device, creds, window, stop_on_keyframe=False
        )
        h264 = protocol.video_stream(packets)
        return media.h264_to_mp4(h264, seconds) if h264 else None

    def _grab_video_sync(
        self,
        purpose: str,
        device: Device,
        creds: Credentials,
        duration: float,
        stop_on_keyframe: bool,
    ) -> list[MediaPacket]:
        """Open a session, collect video for ``duration`` and return the packets."""
        sink = _VideoSink()
        with self._slot(
            purpose,
            device.duid,
            self._signature(creds),
            reuse=True,
            warm_idle=self._warm_idle,
        ) as slot:
            transport = self._video_session(slot, device, creds, sink)
            if transport is None:
                return []
            deadline = time.monotonic() + duration

            def _done() -> bool:
                if self._unlock_pending(device.duid):
                    return True
                return stop_on_keyframe and sink.has_keyframe

            try:
                transport.run_until(deadline, until=_done)
            except TransportError:
                # A vanished socket is a stop, not a failure: keep what arrived.
                _LOGGER.debug("Station %s closed mid-capture", device.duid)
            finally:
                self._release_or_hand_over(slot, transport, purpose.lower())

        packets = sink.packets()
        if not packets:
            _LOGGER.debug("No video received from %s", device.duid)
        return packets

    def _stream_sync(
        self,
        device: Device,
        creds: Credentials,
        duration: float,
        on_jpeg: Callable[[bytes], None],
        should_stop: Callable[[], bool],
    ) -> int:
        """Pipe the live H.264 stream through ffmpeg to JPEGs via ``on_jpeg``."""
        if on_jpeg is None:
            return 0
        packets_q: queue.Queue[MediaPacket] = queue.Queue()
        with self._slot(
            "Live stream",
            device.duid,
            self._signature(creds),
            reuse=True,
            warm_idle=self._warm_idle,
        ) as slot:
            arrivals = _ArrivalStats()

            def _on_packet(packet: MediaPacket) -> None:
                if packet.is_video:
                    arrivals.add(packet.timestamp)
                packets_q.put(packet)

            transport = self._video_session(
                slot, device, creds, _on_packet, should_stop
            )
            if transport is None:
                return 0
            if should_stop is not None and should_stop():
                # Stopped while the session was being set up.
                self._release_or_hand_over(slot, transport, "live stream")
                return 0
            ffmpeg = _start_mjpeg_transcoder()
            if ffmpeg is None:
                self._release_or_hand_over(slot, transport, "live stream")
                return 0

            stop = threading.Event()
            frames_out = [0]
            workers = [
                threading.Thread(
                    target=_jpeg_reader,
                    args=(ffmpeg, stop, on_jpeg, frames_out),
                    name=f"balter_evo2-mjpeg-{device.duid}",
                    daemon=True,
                ),
                threading.Thread(
                    target=_video_pump,
                    args=(ffmpeg, stop, packets_q),
                    name=f"balter_evo2-video-{device.duid}",
                    daemon=True,
                ),
            ]
            deadline = time.monotonic() + (duration or STREAM_DURATION)
            self._live[device.duid] = transport
            try:
                for worker in workers:
                    worker.start()
                _LOGGER.debug(
                    "Live stream started for %s (max %.0fs)", device.duid, duration
                )
                transport.run_until(
                    deadline,
                    until=lambda: (
                        self._unlock_pending(device.duid)
                        or bool(should_stop and should_stop())
                    ),
                )
            except TransportError:
                _LOGGER.debug("Station %s closed the live stream", device.duid)
            finally:
                # Wait for a door command that is in flight on this session.
                with self._live_lock(device.duid):
                    self._live.pop(device.duid, None)
                stop.set()
                try:
                    self._release_or_hand_over(slot, transport, "live stream")
                finally:
                    _stop_ffmpeg(ffmpeg)
                    for worker in workers:
                        if worker.is_alive():
                            worker.join(timeout=1.0)

        _LOGGER.debug(
            "Live stream ended for %s (%d frames shown; %s)",
            device.duid,
            frames_out[0],
            arrivals.summary(),
        )
        return frames_out[0]

    def _open_door_sync(
        self,
        device: Device,
        creds: Credentials,
        door: int,
        locknumber: int,
        pin_sha256: str | None,
    ) -> UnlockResult:
        """Unlock one door relay, reusing a warm session when there is one."""
        result = UnlockResult()
        if not creds.dynamic_password:
            _LOGGER.error(
                "No dynamic_password for %s -- not opening the door", device.duid
            )
            return result
        pin_hash = pin_sha256 or protocol.SHA256_OF_EMPTY

        # A live view is running: its session is logged in and ready, so the
        # command goes out on it at once and the picture keeps running. The lock
        # keeps the live view from closing that session until the answer is in.
        with self._live_lock(device.duid):
            live = self._live.get(device.duid)
            if live is not None and live.is_alive and live.device_ready.is_set():
                try:
                    result.acked = live.send_open(door, locknumber, pin_hash)
                except StationBusyError:
                    pass  # provably not sent: take the normal path below
                except DoorRejectedError:
                    result.ready = result.sent = result.rejected = True
                    return result
                except TransportError:
                    result.ready = result.sent = True
                    return result
                else:
                    result.ready = result.sent = True
                    return result

        self._set_unlock_wanted(device.duid, True)
        try:
            with self._slot(
                "Door unlock",
                device.duid,
                self._signature(creds),
                reuse=True,
                warm_idle=self._warm_idle,
            ) as slot:
                transport = slot.transport
                if transport is not None and not transport.is_alive:
                    slot.drop_transport()
                    transport = None

                if transport is None:
                    transport = self._make_transport(device, creds)
                    slot.transport = transport
                    if not transport.connect(LOGIN_TIMEOUT):
                        self._record_handshake(transport)
                        result.silent = transport.station_silent
                        return result
                    deadline = time.monotonic() + DOOR_SESSION_TIMEOUT
                    if not transport.wait(transport.logged_in, LOGIN_TIMEOUT):
                        # Acked the a9 but not the LOGIN -> still holding an older
                        # session; nothing changes in the remaining budget. Give
                        # up now (command never sent) and leave it the gap.
                        self._record_handshake(transport)
                        _LOGGER.error(
                            "Station %s did not confirm LOGIN within %.0fs -- "
                            "OPENDOOR not sent (%s)",
                            device.duid,
                            LOGIN_TIMEOUT,
                            transport.handshake_states(),
                        )
                        return result
                    if not transport.wait(
                        transport.device_ready, max(deadline - time.monotonic(), 0.0)
                    ):
                        self._record_handshake(transport)
                        _LOGGER.error(
                            "Station %s never signalled session-ready -- OPENDOOR "
                            "not sent (%s). The station serves one session at a "
                            "time: a stream, a phone live view or a ring blocks it.",
                            device.duid,
                            transport.handshake_states(),
                        )
                        return result
                    transport.send_session_setup()

                self._record_handshake(transport)
                result.ready = True
                try:
                    acked = transport.send_open(door, locknumber, pin_hash)
                except StationBusyError:
                    # device_ready was lost between the check and the send.
                    return result
                except DoorRejectedError:
                    result.sent = result.rejected = True
                    return result
                except TransportError:
                    # Socket died while sending: treat as sent-but-unacked so the
                    # caller surfaces a hard error and never auto-retries.
                    result.sent = True
                    return result
                result.sent = True
                result.acked = acked
                if acked:
                    # Keep the session warm: a second open costs one frame, and
                    # the station gets the same settle time the real app allows.
                    slot.keep_warm = True
                return result
        except StationSilentError:
            result.silent = True
            return result
        finally:
            self._set_unlock_wanted(device.duid, False)


# --- Media collection --------------------------------------------------------


class _ArrivalStats:
    """How evenly the video frames of one live view arrived (for the debug log).

    Compares the station's own clock on the frames with the time they reached
    us: a station that records 18 frames a second but delivers them in clumps
    shows as a capture rate well above what the gaps suggest.
    """

    def __init__(self) -> None:
        """Start empty."""
        self.count = 0
        self._first_seen = self._last_seen = 0.0
        self._first_stamp = self._last_stamp = 0.0
        self._long_gaps = 0
        self._max_gap = 0.0

    def add(self, stamp: float) -> None:
        """Note one video frame carrying the station time ``stamp``."""
        now = time.monotonic()
        if self.count == 0:
            self._first_seen, self._first_stamp = now, stamp
        else:
            gap = now - self._last_seen
            self._max_gap = max(self._max_gap, gap)
            if gap > 0.2:
                self._long_gaps += 1
        self._last_seen, self._last_stamp = now, stamp
        self.count += 1

    def summary(self) -> str:
        """Return a one-line description."""
        if self.count < 2:
            return f"{self.count} video frames received"
        seen = max(self._last_seen - self._first_seen, 0.001)
        recorded = max(self._last_stamp - self._first_stamp, 0.001)
        return (
            f"{self.count} video frames received in {seen:.1f}s, recorded at "
            f"{(self.count - 1) / recorded:.1f}/s, {self._long_gaps} gaps over "
            f"0.2s, longest {self._max_gap:.2f}s"
        )


class _VideoSink:
    """Thread-safe media sink: collects the video packets in arrival order."""

    def __init__(self) -> None:
        """Start empty."""
        self._lock = threading.Lock()
        self._packets: list[MediaPacket] = []
        self.has_keyframe = False

    def __call__(self, packet: MediaPacket) -> None:
        """Keep one video packet (called from the transport's receive thread)."""
        if not packet.is_video:
            return
        with self._lock:
            self._packets.append(packet)
            if packet.is_keyframe:
                self.has_keyframe = True

    def packets(self) -> list[MediaPacket]:
        """Return a copy of the packets collected so far."""
        with self._lock:
            return list(self._packets)


# --- Live MJPEG transcoding pipe ---------------------------------------------


def _start_mjpeg_transcoder() -> subprocess.Popen[bytes] | None:
    """Start ffmpeg as an H.264 -> MJPEG pipe, or ``None`` if unavailable."""
    try:
        return subprocess.Popen(
            [
                "ffmpeg",
                "-hide_banner",
                "-loglevel",
                "error",
                "-fflags",
                "nobuffer",
                "-flags",
                "low_delay",
                "-probesize",
                "32768",
                "-analyzeduration",
                "0",
                "-f",
                "h264",
                "-i",
                "pipe:0",
                "-f",
                "mjpeg",
                "-q:v",
                "5",
                "-flush_packets",
                "1",
                "pipe:1",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            # Unbuffered pipes: a read returns what is there instead of waiting
            # for a full block, so a frame is not held back until the next one.
            bufsize=0,
        )
    except (OSError, ValueError) as err:
        _LOGGER.error(
            "ffmpeg could not be started -- the live stream needs ffmpeg on the "
            "Home Assistant host: %s",
            err,
        )
        return None


def _stop_ffmpeg(ffmpeg: subprocess.Popen[bytes]) -> None:
    """Close the pipe and make sure the transcoder is gone.

    Nothing still inside ffmpeg is wanted once a live view ends, so it is killed
    rather than drained -- draining blocks on the output pipe nobody reads.
    """
    if ffmpeg.stdin is not None:
        with contextlib.suppress(OSError):
            ffmpeg.stdin.close()
    with contextlib.suppress(OSError):
        ffmpeg.kill()
    with contextlib.suppress(subprocess.TimeoutExpired):
        ffmpeg.wait(timeout=3)


def _jpeg_reader(
    ffmpeg: subprocess.Popen[bytes],
    stop: threading.Event,
    on_jpeg: Callable[[bytes], None],
    frames_out: list[int],
) -> None:
    """Cut whole JPEGs (SOI ffd8 ... EOI ffd9) out of the ffmpeg output."""
    if ffmpeg.stdout is None:
        return
    buf = bytearray()
    while not stop.is_set():
        chunk = ffmpeg.stdout.read(65536)
        if not chunk:
            return
        buf.extend(chunk)
        while True:
            start = buf.find(b"\xff\xd8")
            if start < 0:
                break
            end = buf.find(b"\xff\xd9", start + 2)
            if end < 0:
                del buf[:start]
                break
            jpeg = bytes(buf[start : end + 2])
            del buf[: end + 2]
            frames_out[0] += 1
            with contextlib.suppress(Exception):
                on_jpeg(jpeg)


def _video_pump(
    ffmpeg: subprocess.Popen[bytes],
    stop: threading.Event,
    packets_q: queue.Queue[MediaPacket],
) -> None:
    """Feed the arriving video packets to ffmpeg, starting at a keyframe.

    Audio packets are skipped and everything before the first keyframe is
    dropped: a decoder cannot start on a delta frame.
    """
    if ffmpeg.stdin is None:
        return
    started = False
    while not stop.is_set():
        try:
            packet = packets_q.get(timeout=0.2)
        except queue.Empty:
            continue
        if not packet.is_video:
            continue
        if not started:
            if not packet.is_keyframe:
                continue
            started = True
        try:
            _write_all(ffmpeg.stdin, packet.data)
        except (BrokenPipeError, OSError, ValueError):
            return


def _write_all(pipe: IO[bytes], data: bytes) -> None:
    """Write all of ``data`` to an unbuffered pipe (a raw write may be partial)."""
    view = memoryview(data)
    while view:
        written = pipe.write(view)
        if not written:
            raise BrokenPipeError("the transcoder pipe closed")
        view = view[written:]
