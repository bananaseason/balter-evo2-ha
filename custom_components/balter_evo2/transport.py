"""Direct-TCP transport to a Qualvision door station (port 34567).

This is the core of the integration and the one piece that had to be reverse
engineered from scratch for the TCP path: the legacy community integration drove
the station over a UDP/KCP P2P tunnel (``C1EFABFF``) that never opens a channel
on the Balter EVO 2 we target. The official app instead talks to the station
over a *plain TCP* connection that carries the very same Qualvision application
frames -- without the UDP transport header, the KCP ARQ, the 56-byte
``ff ff ff ff`` outer frame, the hole punch or any of the NAT machinery.

What travels on the wire (verified byte-exact against ``balter_tcp.pcap``):

* the client writes the 32-byte plaintext ``a9`` setup body as the very first
  bytes, raw;
* the station echoes a 32-byte ``a9`` reply (``byte0=0xA9, byte10=0x02,
  byte11=0x01`` = setup accepted);
* the client writes the LOGIN control frame (:func:`protocol.ctrl_frame` output),
  raw, no wrapper;
* the client writes a small ``0xFE`` session-setup frame;
* the station then streams media (type ``0xA0``) on its own -- there is no
  play/start command;
* both sides send a 64-byte keepalive control frame every ~10 s.

The receive stream is a back-to-back concatenation of application frames. Each
frame is *self-describing through its AES-encrypted 32-byte head*
(:func:`protocol.parse_head`): a control frame is ``32 + encrypted_len`` bytes,
a media frame ``32 + content_len`` bytes of which only the first
``encrypted_len`` are encrypted. Media payloads are parsed into
:class:`protocol.MediaPacket` (video frame, keyframe or audio chunk) before they
reach the sink, so no consumer ever has to guess a boundary.

TCP owns ordering, retransmission and reassembly, so there is deliberately no
seq/ack/ARQ/checksum logic here. Every call blocks and must run in an executor
thread; :mod:`station` enforces that boundary and the single-session-at-a-time
serialisation.

Attribution: the application-frame *sequence* (a9 -> echo -> LOGIN -> setup ->
auto-stream, keepalive, OPENDOOR delivery proof) and the session-ready /
video-is-flowing heuristics are ported from ``p2p.py`` of balter-evo-ha
(https://github.com/LucaHerrero/balter-evo-ha, MIT licensed); the TCP framing
itself was re-derived from the capture. All byte builders live in
:mod:`protocol`.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from collections import deque
from collections.abc import Callable

from .const import KEEPALIVE_INTERVAL, LOGIN_TIMEOUT, OEM_ID_COMPACT
from .protocol import (
    FTYPE_AUDIO_FORMAT,
    FTYPE_AUDIO_LOGIN,
    FTYPE_CLOSE,
    FTYPE_CONTROL,
    FTYPE_KEEPALIVE,
    FTYPE_LOGIN,
    FTYPE_TALK,
    HEAD_LEN,
    KNOWN_FTYPES,
    TALK_FRAME_BYTES,
    TALK_FRAME_SECONDS,
    MediaPacket,
    audio_format_frame,
    audio_login_frame,
    build_a9_body,
    build_login_payload,
    build_open_payload,
    cbc_decrypt,
    control_payload,
    ctrl_frame,
    parse_audio_channel_head,
    parse_head,
    parse_media,
    session_key,
    talk_frame,
    talk_state_frame,
)

_LOGGER = logging.getLogger(__name__)


# --- Exceptions --------------------------------------------------------------


class TransportError(RuntimeError):
    """A TCP session with the door station could not be established or used."""


class StationSilentError(TransportError):
    """The station never answered the handshake at all.

    It therefore took no session either, so the next attempt may start right
    away without the recovery gap.
    """


class SessionClosedError(TransportError):
    """The session was already closed, so nothing was written to the station."""


class DoorRejectedError(TransportError):
    """The station answered the door command with a refusal.

    ``answer`` is the station's two-byte answer: ``01 00`` for a wrong door PIN,
    ``01 01`` for a target it does not have (seen for door station 2 of a
    one-door EVO 2).
    """

    def __init__(self, message: str, answer: bytes = b"") -> None:
        """Keep the station's answer for the caller's message."""
        super().__init__(message)
        self.answer = answer


class StationBusyError(TransportError):
    """The station answered but never freed its single app session in time.

    The command provably never left the client, so it is safe to try again in a
    few seconds.
    """


# --- Protocol / timing constants --------------------------------------------

# Receive-socket poll timeout: short enough to notice ``_stop`` promptly, long
# enough not to spin.
RX_POLL_TIMEOUT = 0.2

# How long to wait for the station's OPENDOOR acknowledgement (``0xFE
# msg13=4``). The real app sees it within ~2 s. The frame is sent exactly ONCE
# and never retried: a second unlock could open the door twice.
OPENDOOR_ACK_TIMEOUT = 6.0

# Once this many media bytes have arrived after the LOGIN, the station has
# demonstrably freed its app session: it streams video only after accepting the
# login, and there is no separate start command (P2P_PROTOCOL.md 9.2). A second,
# independent readiness signal besides the explicit ``0xFE msg13=2`` marker.
STREAM_IS_PROOF = 4096

# a9 echo recognition: byte0 = 0xA9, byte10 = 0x02, byte11 = 0x01 (accepted).
_A9_ECHO_MARKER = {0: 0xA9, 10: 0x02, 11: 0x01}

# Message ids of the ``0xFE`` control family seen on a live station.
MSG_SESSION_READY = 2  # answer to the client's msg13=2 setup frame
MSG_OPENDOOR = 4  # OPENDOOR and its acknowledgement
MSG_HEARTBEAT = 8  # station tick, about once a second while streaming
MSG_PROFILE = 18  # JSON description of the station's channels and locks

# First payload byte of the station's OPENDOOR answer when it accepted the
# command (``00 00`` to the phone app, ``00 01`` to this client; what the second
# byte says is not known); a refusal starts with ``01``.
DOOR_OPENED = b"\x00"
DOOR_WRONG_PIN = b"\x01\x00"


def _quick_ack(sock: socket.socket) -> None:
    """Acknowledge what was received right away (Linux; a no-op elsewhere).

    The station sends every frame as its own small write and, like any TCP
    sender with Nagle's algorithm, holds the next small write back until the
    previous one is acknowledged. A receiver that delays its ACKs (the default)
    therefore gets small frames -- a quiet or dark picture -- in clumps instead
    of one by one, which shows as stutter. The option is not sticky, so it is
    set again after every read.
    """
    option = getattr(socket, "TCP_QUICKACK", None)
    if option is None:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, option, 1)
    except OSError:
        pass


# Type of the media sink: called from the receive thread with every parsed
# media packet, in stream order.
MediaSink = Callable[[MediaPacket], None]


class TcpStationTransport:
    """One live TCP session with a door station.

    Covers the per-connection handshake up to "the station accepts commands" and
    then runs two daemon threads for the lifetime of the session: a receive
    thread that walks the self-describing frame stream (dispatching media to the
    sink and control acks/readiness to waiters) and a keepalive thread that sends
    the 64-byte control frame every :data:`KEEPALIVE_INTERVAL` seconds.

    The station serves only ONE session at a time; callers must :meth:`close`
    every instance. All methods block and belong in an executor thread.
    """

    def __init__(
        self,
        host: str,
        port: int,
        duid: str,
        dynamic_password: str,
        data_encode_key: str | None,
        client_id: str,
        oem: str = OEM_ID_COMPACT,
    ) -> None:
        """Prepare (but do not open) a session; see :meth:`connect`."""
        self._host = host
        self._port = port
        self._duid = duid
        self._dynamic_password = dynamic_password
        self._client_id = client_id
        self._oem = oem
        self._key = session_key(data_encode_key)

        # A fixed protocol timestamp for the stateless frames. The captured
        # keepalive is byte-identical across both connections and across runs,
        # which only holds for a constant ts; a wall-clock value would make the
        # keepalive (and LOGIN) ciphertext differ every run and break the
        # byte-exact invariant. The station tolerates any ts (the SHA-256 trailer
        # stays internally consistent), so this stays 0 until a live decrypt ever
        # proves a monotonic ts is required.
        self._ts = 0
        self._sock: socket.socket | None = None
        self._buf = bytearray()
        self._on_media: MediaSink | None = None
        self._media_bytes = 0
        self._resyncs = 0  # how often frame alignment was lost
        self._aligned = True
        self._unknown_types: set[int] = set()
        self._door_answer: bytes | None = None

        self._stop = threading.Event()
        self._send_lock = threading.Lock()
        self._rx_thread: threading.Thread | None = None
        self._ka_thread: threading.Thread | None = None
        self._peer_closed = False
        self._closed = False
        self._state = "INIT"

        # Public readiness signals.
        self.logged_in = threading.Event()  # first valid down frame parsed
        self.device_ready = threading.Event()  # app session free (0xFE msg13=2)
        self.session_ready = threading.Event()  # station answered our setup frames
        self.media_started = threading.Event()  # first media packet arrived
        self.station_silent = False  # station never answered the handshake

        # Down control-frame acks, for send_ctrl() / send_open() waiters. The
        # deque holds the most recent frames; ``_ack_total`` counts every frame
        # ever seen so a "new acks since index N" wait survives deque overflow.
        self._ack_cv = threading.Condition()
        self._ack_log: deque[tuple[int, int]] = deque(maxlen=128)
        self._ack_total = 0

    # --- Properties ----------------------------------------------------------

    @property
    def duid(self) -> str:
        """Return the device this session belongs to."""
        return self._duid

    @property
    def is_alive(self) -> bool:
        """Return whether the session can still carry a command."""
        return (
            not self._closed
            and not self._stop.is_set()
            and not self._peer_closed
            and self._sock is not None
        )

    def handshake_states(self) -> str:
        """Return a short progress summary for diagnostics / error logs."""
        return (
            f"state={self._state} logged_in={self.logged_in.is_set()} "
            f"device_ready={self.device_ready.is_set()} "
            f"media={self.media_started.is_set()} "
            f"peer_closed={self._peer_closed}"
        )

    def set_media_sink(self, on_media: MediaSink | None) -> None:
        """Redirect -- or switch off -- the media callback of a running session.

        A session handed from one command to another must stop feeding the
        previous command's collector, or it keeps buffering video nobody reads.
        """
        self._on_media = on_media

    # --- Connect / handshake -------------------------------------------------

    def connect(self, timeout: float = LOGIN_TIMEOUT) -> bool:
        """Open the socket and run the handshake up to "LOGIN written".

        Returns ``True`` once the station accepted the ``a9`` setup and the LOGIN
        frame has been written and the receive/keepalive threads are running.
        Returns ``False`` on failure -- with :attr:`station_silent` set when the
        station never answered at all, so the caller can tell "busy" (wait out
        the recovery gap) from "silent" (retry immediately) apart.
        :meth:`close` must be called either way.
        """
        try:
            return self._connect(timeout)
        except StationSilentError as err:
            self.station_silent = True
            _LOGGER.error("Door station %s stayed silent: %s", self._duid, err)
            return False
        except TransportError as err:
            _LOGGER.error(
                "TCP session with %s could not be established: %s", self._duid, err
            )
            return False
        except (OSError, ValueError) as err:
            _LOGGER.error(
                "TCP session with %s could not be established: %s", self._duid, err
            )
            return False

    def _connect(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        try:
            sock = socket.create_connection((self._host, self._port), timeout=timeout)
        except (TimeoutError, OSError) as err:
            self.station_silent = True
            raise StationSilentError(
                f"Could not reach the door station at {self._host}:{self._port}: {err}"
            ) from err
        sock.settimeout(RX_POLL_TIMEOUT)
        _quick_ack(sock)
        self._sock = sock
        self._state = "CONNECTED"

        # 1. Raw 32-byte plaintext a9 setup body (video / CH0) as the first bytes.
        self._raw_send(build_a9_body(0))
        self._state = "SENT_A9"

        # 2. Read and recognise the 32-byte a9 echo.
        echo = self._recv_exact(32, deadline)
        if echo is None or not self._is_a9_echo(echo):
            self.station_silent = echo is None
            if echo is None:
                raise StationSilentError(
                    f"The door station {self._duid} did not echo the a9 setup"
                )
            raise TransportError(
                f"The door station {self._duid} returned an unexpected a9 echo"
            )
        self._state = "A9_ACKED"

        # 3. Raw LOGIN control frame (ftype 0x01, msg13=1, f15=f16=1 for CH0).
        login = ctrl_frame(
            FTYPE_LOGIN,
            self._ts,
            build_login_payload(self._dynamic_password, self._client_id, self._oem),
            self._key,
            msg13=1,
            f15=1,
            f16=1,
        )
        self._raw_send(login)
        self._state = "SENT_LOGIN"

        # 4. Start the receive + keepalive threads; the station streams on its own.
        self._start_threads()
        return True

    def _is_a9_echo(self, echo: bytes) -> bool:
        return len(echo) >= 32 and all(
            echo[pos] == val for pos, val in _A9_ECHO_MARKER.items()
        )

    def _recv_exact(self, count: int, deadline: float) -> bytes | None:
        """Read exactly ``count`` bytes before ``deadline`` (handshake only)."""
        out = bytearray()
        while len(out) < count:
            if time.monotonic() >= deadline:
                return None
            sock = self._sock
            if sock is None:
                return None
            try:
                chunk = sock.recv(count - len(out))
            except TimeoutError:
                continue
            except OSError:
                return None
            if not chunk:
                return None
            out += chunk
        # Anything beyond ``count`` would belong to the next frame; the handshake
        # reads land exactly on frame boundaries (a9 echo is its own 32 bytes), so
        # there is no spill-over to preserve here.
        return bytes(out)

    def _start_threads(self) -> None:
        self._rx_thread = threading.Thread(
            target=self._rx_loop, name=f"balter_evo2-rx-{self._duid}", daemon=True
        )
        self._rx_thread.start()
        self._ka_thread = threading.Thread(
            target=self._keepalive_loop,
            name=f"balter_evo2-keepalive-{self._duid}",
            daemon=True,
        )
        self._ka_thread.start()

    # --- Sending -------------------------------------------------------------

    def _raw_send(self, data: bytes) -> None:
        """Write raw bytes to the socket (no wrapper); ordered by the send lock."""
        with self._send_lock:
            sock = self._sock
            if sock is None:
                raise SessionClosedError("the session is closed")
            sock.sendall(data)

    def send_ctrl(
        self,
        ftype: int,
        msg: int = 0,
        payload: bytes = b"",
        msg13: int = 0,
        *,
        expect: tuple[int, int] | None = None,
        timeout: float = 0.0,
    ) -> tuple[int, int]:
        """Build a control frame, write it raw and optionally await its ack.

        ``msg`` is an outer message counter kept for API parity; the TCP path has
        no outer app-frame wrapper, so it does not travel on the wire. When
        ``timeout > 0`` the call waits for a down control frame matching
        ``expect`` (``(ftype, msg13)``) and returns that ``(ftype, msg13)``;
        otherwise, and on timeout, it returns ``(-1, -1)``.
        """
        with self._ack_cv:
            start = self._ack_total
        self._raw_send(ctrl_frame(ftype, self._ts, payload, self._key, msg13=msg13))
        if timeout <= 0 or expect is None:
            return (-1, -1)
        return self._wait_ack(expect, timeout, start)

    def _wait_ack(
        self, expect: tuple[int, int], timeout: float, start_total: int
    ) -> tuple[int, int]:
        """Wait for a down control frame matching ``expect`` seen after ``start_total``."""
        want_ftype, want_msg13 = expect
        deadline = time.monotonic() + timeout
        with self._ack_cv:
            while True:
                # The deque holds global indices [_ack_total - len, _ack_total).
                oldest = self._ack_total - len(self._ack_log)
                for global_idx in range(max(start_total, oldest), self._ack_total):
                    ftype, msg13 = self._ack_log[global_idx - oldest]
                    if ftype == want_ftype and msg13 == want_msg13:
                        return (ftype, msg13)
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self._peer_closed or self._stop.is_set():
                    return (-1, -1)
                self._ack_cv.wait(timeout=min(remaining, 0.2))

    def send_session_setup(self) -> None:
        """Send the small post-login setup frames the real app always sends.

        Three ``0xFE`` control frames (msg13 5, 6, 2, payload ``0x00``) -- the
        same sequence the official app emits after its LOGIN (P2P_PROTOCOL.md
        9.1). The station streams video regardless of these; they do not start
        it. On the door path they precede the OPENDOOR frame.
        """
        for msg, msg13 in ((2, 5), (3, 6), (4, 2)):
            self.send_ctrl(FTYPE_CONTROL, msg, b"\x00", msg13=msg13)
            time.sleep(0.02)

    def send_open(self, door: int, locknumber: int, pin_sha256: str) -> bool:
        """Send the OPENDOOR frame exactly once and await the station's answer.

        ``ctrl_frame(0xFE, build_open_payload, msg13=4)`` on the video socket,
        after :attr:`device_ready`. The station answers with its own ``0xFE
        msg13=4`` frame whose first payload byte is the result: ``00`` =
        accepted, ``01 00`` = wrong door PIN, ``01 01`` = no such target.

        Returns ``True`` when the station opened the door and ``False`` when no
        answer arrived (sent-but-unacknowledged: a hard failure for the caller to
        surface). Raises :class:`DoorRejectedError` on a refusal and
        :class:`StationBusyError` when the command provably never left. The
        frame is NEVER retried here: a second send could open the door twice.
        """
        if not self.device_ready.is_set():
            raise StationBusyError(
                f"{self._duid} has not signalled session-ready -- not sending OPENDOOR"
            )
        payload = build_open_payload(door, locknumber, pin_sha256)
        with self._ack_cv:
            start = self._ack_total
            self._door_answer = None
        try:
            self._raw_send(
                ctrl_frame(
                    FTYPE_CONTROL, self._ts, payload, self._key, msg13=MSG_OPENDOOR
                )
            )
        except SessionClosedError as err:
            raise StationBusyError(
                f"the session with {self._duid} closed before OPENDOOR was sent"
            ) from err
        except (OSError, TransportError) as err:
            raise TransportError(
                f"the socket closed while sending OPENDOOR to {self._duid}: {err}"
            ) from err
        _LOGGER.debug(
            "OPENDOOR sent to %s (door=%d lock=%d) -- awaiting ack, no retry",
            self._duid,
            door,
            locknumber,
        )
        ftype, _ = self._wait_ack(
            (FTYPE_CONTROL, MSG_OPENDOOR), OPENDOOR_ACK_TIMEOUT, start
        )
        if ftype != FTYPE_CONTROL:
            _LOGGER.error(
                "OPENDOOR to %s was sent but never acknowledged (0xFE msg13=4 not "
                "seen). The door may or may not have opened -- not retrying.",
                self._duid,
            )
            return False
        answer = self._door_answer or b""
        if answer[:1] != DOOR_OPENED:
            raise DoorRejectedError(
                f"{self._duid} refused the door command (answer {answer.hex()})",
                answer,
            )
        _LOGGER.debug("Door unlock confirmed by %s (0xFE msg13=4)", self._duid)
        return True

    # --- Receiving -----------------------------------------------------------

    def _rx_loop(self) -> None:
        """Read the socket and walk the concatenated frame stream."""
        while not self._stop.is_set():
            sock = self._sock
            if sock is None:
                return
            try:
                chunk = sock.recv(65536)
            except TimeoutError:
                continue
            except OSError:
                chunk = b""
            if not chunk:
                self._peer_closed = True
                self._wake_waiters()
                return
            _quick_ack(sock)
            self._buf += chunk
            self._process_buffer()

    def _process_buffer(self) -> None:
        """Consume every complete frame in the receive buffer."""
        buf = self._buf
        while len(buf) >= HEAD_LEN:
            head = parse_head(cbc_decrypt(bytes(buf[:HEAD_LEN]), self._key))
            if head is None:
                if not self._resync():
                    return
                continue
            self._aligned = True
            total = HEAD_LEN + head.body_len
            if len(buf) < total:
                return
            encrypted_end = HEAD_LEN + head.encrypted_len
            plain = cbc_decrypt(bytes(buf[HEAD_LEN:encrypted_end]), self._key)
            if head.is_media:
                payload = plain + bytes(buf[encrypted_end:total])
                del buf[:total]
                self._emit_media(payload)
            else:
                del buf[:total]
                self._emit_control(head.ftype, head.msg13, control_payload(head, plain))

    def _resync(self) -> bool:
        """Drop bytes until the buffer starts on a frame head again.

        A safety net only: frame boundaries are exact, so this runs when the key
        is wrong or the station sends a frame type never seen before. Returns
        ``True`` once realigned, ``False`` when more data is needed.
        """
        buf = self._buf
        first = self._aligned and self._resyncs == 0
        if self._aligned:
            self._aligned = False
            self._resyncs += 1
        if first:
            _LOGGER.warning(
                "The stream from %s lost frame alignment -- resynchronising. "
                "If this repeats, the station key may have rotated.",
                self._duid,
            )
        for pos in range(1, len(buf) - HEAD_LEN + 1):
            candidate = cbc_decrypt(bytes(buf[pos : pos + HEAD_LEN]), self._key)
            if parse_head(candidate) is not None:
                del buf[:pos]
                return True
        # Nothing found; keep only a tail that might hold the start of a head,
        # so a persistent desync cannot grow the buffer without bound.
        if len(buf) >= HEAD_LEN:
            del buf[: len(buf) - (HEAD_LEN - 1)]
        return False

    def _emit_media(self, payload: bytes) -> None:
        self._media_bytes += len(payload)
        self._mark_logged_in()
        if not self.media_started.is_set():
            self.media_started.set()
            self._wake_waiters()
        if not self.device_ready.is_set() and self._media_bytes > STREAM_IS_PROOF:
            self.device_ready.set()
            self._wake_waiters()
            _LOGGER.debug(
                "Video is flowing from %s -- the station has opened the session",
                self._duid,
            )
        sink = self._on_media
        if sink is None:
            return
        packet = parse_media(payload)
        if packet is None:
            _LOGGER.debug(
                "Unparsable media payload from %s (%d bytes)", self._duid, len(payload)
            )
            return
        try:
            sink(packet)
        except Exception:  # noqa: BLE001 -- a bad sink must not kill the RX loop
            _LOGGER.exception("Media sink for %s raised", self._duid)

    def _emit_control(self, ftype: int, msg13: int, payload: bytes) -> None:
        self._mark_logged_in()
        if ftype == FTYPE_CONTROL and msg13 == MSG_HEARTBEAT:
            return
        if ftype not in KNOWN_FTYPES and ftype not in self._unknown_types:
            self._unknown_types.add(ftype)
            _LOGGER.debug(
                "Station %s sent an unknown frame type 0x%02x (msg13=%d, %d bytes)"
                " -- skipped",
                self._duid,
                ftype,
                msg13,
                len(payload),
            )
        if (
            ftype == FTYPE_CONTROL
            and msg13 == MSG_SESSION_READY
            and not self.device_ready.is_set()
        ):
            self.device_ready.set()
            _LOGGER.debug(
                "Station %s signalled session ready (0xFE msg13=2)", self._duid
            )
        _LOGGER.debug(
            "Station %s: frame type 0x%02x msg13=%d, %d bytes, starts %s",
            self._duid,
            ftype,
            msg13,
            len(payload),
            payload[:8].hex() or "-",
        )
        if ftype == FTYPE_CONTROL and msg13 == MSG_SESSION_READY:
            self.session_ready.set()
        if ftype == FTYPE_CONTROL and msg13 == MSG_OPENDOOR:
            self._door_answer = payload
            _LOGGER.debug(
                "Station %s answered OPENDOOR with %s", self._duid, payload.hex()
            )
        with self._ack_cv:
            self._ack_log.append((ftype, msg13))
            self._ack_total += 1
            self._ack_cv.notify_all()

    def _mark_logged_in(self) -> None:
        if not self.logged_in.is_set():
            self.logged_in.set()
            self._state = "LOGGED_IN"
            self._wake_waiters()

    def _wake_waiters(self) -> None:
        with self._ack_cv:
            self._ack_cv.notify_all()

    # --- Session servicing ---------------------------------------------------

    def run_until(
        self, deadline: float, until: Callable[[], bool] | None = None
    ) -> None:
        """Service the session until ``deadline`` or ``until()`` is true.

        The receive and keepalive threads do the real work; this only blocks the
        caller's executor thread. A socket that vanishes mid-session is a stop,
        not a clean end: it raises :class:`TransportError` unless ``until()`` is
        already satisfied.
        """
        while time.monotonic() < deadline:
            if until is not None and until():
                return
            if self._peer_closed:
                if until is not None and until():
                    return
                raise TransportError(
                    f"the door station {self._duid} closed the connection"
                )
            time.sleep(0.02)

    def wait(self, event: threading.Event, timeout: float) -> bool:
        """Wait ``timeout`` seconds for ``event``; never raises.

        Used for the readiness events (:attr:`logged_in`, :attr:`device_ready`),
        where a peer that closes early simply means the event will not arrive.
        """
        deadline = time.monotonic() + timeout
        with self._ack_cv:
            while not event.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self._peer_closed or self._stop.is_set():
                    break
                self._ack_cv.wait(timeout=min(remaining, 0.2))
        return event.is_set()

    # --- Teardown ------------------------------------------------------------

    def close(self) -> None:
        """Say goodbye and release the station's single session slot.

        Doing this promptly matters: while the session stands, the station turns
        down every other connection -- the doorbell's own included.
        """
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        if self._sock is not None and not self._peer_closed:
            # Best-effort close frame (ftype 0x07). Never fatal if it fails.
            try:
                self._raw_send(ctrl_frame(FTYPE_CLOSE, self._ts, b"", self._key))
            except (OSError, TransportError):
                pass
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        self._wake_waiters()
        for thread in (self._rx_thread, self._ka_thread):
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=1.0)

    def __enter__(self) -> TcpStationTransport:
        """Enter the runtime context (the session is not opened here)."""
        return self

    def __exit__(self, *exc: object) -> None:
        """Close the session on context exit."""
        self.close()

    # --- Keepalive -----------------------------------------------------------

    def _keepalive_loop(self) -> None:
        """Send the 64-byte keepalive control frame every interval."""
        while not self._stop.wait(KEEPALIVE_INTERVAL):
            try:
                self._raw_send(ctrl_frame(FTYPE_KEEPALIVE, self._ts, b"", self._key))
            except (OSError, TransportError):
                self._peer_closed = True
                self._wake_waiters()
                return


# --- Talk-back: the audio channel ---------------------------------------------

# How long the station gets to answer one frame on the audio channel. It answers
# within a few tens of milliseconds (live, 2026-11-24).
TALK_ANSWER_TIMEOUT = 2.0

# Microphone audio waiting to be sent is capped at this many bytes (400 ms of
# 8 kHz A-law); the oldest is dropped, so a late burst never builds up delay.
TALK_BUFFER_MAX = 10 * TALK_FRAME_BYTES

# A sender that fell this far behind its 40 ms schedule (a stall of the host)
# starts a new schedule instead of sending the backlog in one burst.
TALK_SCHEDULE_SLACK = 2 * TALK_FRAME_SECONDS


class TcpTalkChannel:
    """The audio channel of a running live view: talk-back to the door station.

    A second TCP connection to the station, opened while the video session
    (connection 1) runs -- verified live on a Balter EVO 2 (2026-11-24,
    ``reference/tools/talk_spike.py``):

    1. raw ``build_a9_body(1)`` (byte 9 = 2); the station echoes ``a9 .. 02 01``;
    2. LOGIN ``0x0B`` (msg13 and byte 14 ``0xFF``, the video LOGIN payload); the
       station answers ``0x0B``;
    3. the format ``0x0C`` (8000 Hz) and the talk state ``0x0D`` "not talking";
       the station answers both;
    4. talking: ``0x0D`` msg13=0, then one ``0xA2`` frame (320 bytes of G.711
       A-law = 40 ms) every 40 ms; ``0x0D`` msg13=1 ends it. Each ``0x0D`` is
       answered with a ``0x0D``.

    The station's own audio is not on this channel: it arrives as media packets
    (kind ``0xE3``) on the video connection. Closing sends ``0x07``.

    Every blocking method belongs in an executor thread; :meth:`feed` only
    appends to a buffer and may be called from the event loop. A sender thread
    paces the buffered audio at one frame per 40 ms.
    """

    def __init__(
        self,
        host: str,
        port: int,
        duid: str,
        dynamic_password: str,
        data_encode_key: str | None,
        client_id: str,
        oem: str = OEM_ID_COMPACT,
    ) -> None:
        """Prepare (but do not open) the audio channel; see :meth:`open`."""
        self._host = host
        self._port = port
        self._duid = duid
        self._dynamic_password = dynamic_password
        self._client_id = client_id
        self._oem = oem
        self._key = session_key(data_encode_key)
        # The frame counter of this channel; taken and sent under the send lock
        # (see :meth:`_send_frame`), so the frames leave in counter order.
        self._ts = 0
        self._sock: socket.socket | None = None
        self._buf = bytearray()
        self._stop = threading.Event()
        self._send_lock = threading.Lock()
        # When the last frame left (time.monotonic()), for the keepalive.
        self._last_sent = 0.0
        self._threads: list[threading.Thread] = []
        self._peer_closed = False
        self._closed = False
        self._on_closed: Callable[[], None] | None = None
        self._closed_reported = False

        # Station answers: (ftype, msg13, content_len) in arrival order.
        self._answer_cv = threading.Condition()
        self._answers: list[tuple[int, int, int]] = []

        # Talking state and the microphone audio waiting to be sent.
        self._audio_cv = threading.Condition()
        self._talking = False
        self._pending = bytearray()
        self.frames_sent = 0
        self.bytes_dropped = 0

    # --- Properties ----------------------------------------------------------

    @property
    def duid(self) -> str:
        """Return the device this channel belongs to."""
        return self._duid

    @property
    def is_alive(self) -> bool:
        """Return whether the channel is open and the station has not left it."""
        return (
            not self._closed
            and not self._stop.is_set()
            and not self._peer_closed
            and self._sock is not None
        )

    @property
    def talking(self) -> bool:
        """Return whether microphone audio is being sent."""
        return self._talking

    def set_close_callback(self, callback: Callable[[], None] | None) -> None:
        """Call ``callback`` (from a channel thread) once the station drops the channel."""
        self._on_closed = callback

    def answers(self) -> list[tuple[int, int, int]]:
        """Return the station's answers so far (for diagnostics and tests)."""
        with self._answer_cv:
            return list(self._answers)

    # --- Open ----------------------------------------------------------------

    def open(self, timeout: float = LOGIN_TIMEOUT) -> None:
        """Connect and run the audio-channel handshake up to "not talking".

        Raises :class:`StationSilentError` when the station cannot be reached or
        does not echo the setup, :class:`TransportError` when it refuses a step.
        The channel is closed on failure.
        """
        try:
            self._open(timeout)
        except TransportError:
            self.close()
            raise
        except (OSError, ValueError) as err:
            self.close()
            raise TransportError(
                f"The audio channel to {self._duid} could not be opened: {err}"
            ) from err

    def _open(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        try:
            sock = socket.create_connection((self._host, self._port), timeout=timeout)
        except (TimeoutError, OSError) as err:
            raise StationSilentError(
                f"Could not reach the door station at {self._host}:{self._port} "
                f"for the audio channel: {err}"
            ) from err
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(RX_POLL_TIMEOUT)
        _quick_ack(sock)
        self._sock = sock

        self._raw_send(build_a9_body(1))
        echo = self._recv_exact(32, deadline)
        if echo is None:
            raise StationSilentError(
                f"The door station {self._duid} did not echo the audio setup"
            )
        if not all(echo[pos] == val for pos, val in _A9_ECHO_MARKER.items()):
            raise TransportError(
                f"The door station {self._duid} refused the audio channel "
                f"(echo {echo[:12].hex()})"
            )

        thread = threading.Thread(
            target=self._rx_loop, name=f"balter_evo2-talk-rx-{self._duid}", daemon=True
        )
        self._threads.append(thread)
        thread.start()

        start = self._answer_count()
        self._send_frame(
            lambda ts: audio_login_frame(
                ts,
                self._dynamic_password,
                self._client_id,
                self._oem,
                self._key,
            )
        )
        if not self._wait_answer(FTYPE_AUDIO_LOGIN, start, deadline):
            raise TransportError(
                f"The door station {self._duid} did not answer the audio LOGIN"
            )
        start = self._answer_count()
        self._send_frame(
            lambda ts: (
                audio_format_frame(ts, self._key)
                + talk_state_frame(ts, False, self._key)
            )
        )
        if not (
            self._wait_answer(FTYPE_AUDIO_FORMAT, start, deadline)
            and self._wait_answer(FTYPE_TALK, start, deadline)
        ):
            raise TransportError(
                f"The door station {self._duid} did not accept the audio format"
            )

        thread = threading.Thread(
            target=self._send_loop,
            name=f"balter_evo2-talk-tx-{self._duid}",
            daemon=True,
        )
        self._threads.append(thread)
        thread.start()
        _LOGGER.debug("Audio channel to %s is open", self._duid)

    def _recv_exact(self, count: int, deadline: float) -> bytes | None:
        out = bytearray()
        while len(out) < count:
            if time.monotonic() >= deadline or self._sock is None:
                return None
            try:
                chunk = self._sock.recv(count - len(out))
            except TimeoutError:
                continue
            except OSError:
                return None
            if not chunk:
                return None
            out += chunk
        return bytes(out)

    # --- Talking ---------------------------------------------------------------

    def set_talking(self, talking: bool) -> bool:
        """Switch talking on or off; ``True`` once the station answered.

        Off takes effect at once (no more audio leaves), whether or not the
        station answers; on starts sending only after the station's answer.
        """
        if not talking:
            with self._audio_cv:
                self._talking = False
                self._pending.clear()
        if not self.is_alive:
            return False
        start = self._answer_count()
        try:
            self._send_frame(lambda ts: talk_state_frame(ts, talking, self._key))
        except (OSError, TransportError) as err:
            _LOGGER.debug("Talk state to %s not sent: %s", self._duid, err)
            self._mark_peer_closed()
            return False
        answered = self._wait_answer(
            FTYPE_TALK, start, time.monotonic() + TALK_ANSWER_TIMEOUT
        )
        if not answered:
            _LOGGER.warning(
                "The door station %s did not answer the talk %s",
                self._duid,
                "start" if talking else "stop",
            )
            return False
        if talking:
            with self._audio_cv:
                self._talking = True
                self._pending.clear()
                self._audio_cv.notify_all()
        _LOGGER.debug("Talking to %s %s", self._duid, "on" if talking else "off")
        return True

    def feed(self, alaw: bytes) -> int:
        """Queue microphone audio (G.711 A-law, 8 kHz); return the bytes dropped.

        Audio is dropped while not talking. The queue keeps at most
        :data:`TALK_BUFFER_MAX` bytes, the oldest going first. Never blocks on I/O.
        """
        with self._audio_cv:
            if not self._talking:
                return len(alaw)
            self._pending += alaw
            excess = len(self._pending) - TALK_BUFFER_MAX
            if excess > 0:
                del self._pending[:excess]
                self.bytes_dropped += excess
            self._audio_cv.notify_all()
            return max(excess, 0)

    def _send_loop(self) -> None:
        """Send the queued audio as one 320-byte frame every 40 ms.

        While nothing else goes out (muted, or no microphone audio), it sends the
        protocol's keepalive (``0x00``) every :data:`KEEPALIVE_INTERVAL`, as the
        video connection does, so a muted channel is not left silent.
        """
        due = 0.0
        while not self._stop.is_set():
            chunk: bytes | None = None
            with self._audio_cv:
                while not self._stop.is_set():
                    if self._talking and len(self._pending) >= TALK_FRAME_BYTES:
                        chunk = bytes(self._pending[:TALK_FRAME_BYTES])
                        del self._pending[:TALK_FRAME_BYTES]
                        break
                    idle = time.monotonic() - self._last_sent
                    if idle >= KEEPALIVE_INTERVAL:
                        break
                    self._audio_cv.wait(min(0.2, KEEPALIVE_INTERVAL - idle))
                if self._stop.is_set():
                    return
            if chunk is None:
                try:
                    self._send_frame(
                        lambda ts: ctrl_frame(FTYPE_KEEPALIVE, ts, b"", self._key)
                    )
                except (OSError, TransportError) as err:
                    _LOGGER.debug("Keepalive to %s not sent: %s", self._duid, err)
                    self._mark_peer_closed()
                    return
                continue
            now = time.monotonic()
            if due < now - TALK_SCHEDULE_SLACK:
                due = now
            elif due > now and self._stop.wait(due - now):
                return
            if not self._talking:
                continue  # switched off while waiting for the slot
            try:
                self._send_frame(lambda ts, data=chunk: talk_frame(ts, data, self._key))
            except (OSError, TransportError) as err:
                _LOGGER.debug("Talk audio to %s not sent: %s", self._duid, err)
                self._mark_peer_closed()
                return
            self.frames_sent += 1
            due += TALK_FRAME_SECONDS

    # --- Receiving -------------------------------------------------------------

    def _answer_count(self) -> int:
        with self._answer_cv:
            return len(self._answers)

    def _wait_answer(self, ftype: int, start: int, deadline: float) -> bool:
        """Wait for an answer of type ``ftype`` that arrived after index ``start``."""
        with self._answer_cv:
            while True:
                if any(a[0] == ftype for a in self._answers[start:]):
                    return True
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self._peer_closed or self._stop.is_set():
                    return False
                self._answer_cv.wait(timeout=min(remaining, 0.2))

    def _rx_loop(self) -> None:
        while not self._stop.is_set():
            sock = self._sock
            if sock is None:
                return
            try:
                chunk = sock.recv(65536)
            except TimeoutError:
                continue
            except OSError:
                chunk = b""
            if not chunk:
                self._mark_peer_closed()
                return
            _quick_ack(sock)
            self._buf += chunk
            self._process_buffer()

    def _process_buffer(self) -> None:
        buf = self._buf
        while len(buf) >= HEAD_LEN:
            head = parse_audio_channel_head(
                cbc_decrypt(bytes(buf[:HEAD_LEN]), self._key)
            )
            if head is None:
                _LOGGER.debug(
                    "Unreadable frame on the audio channel of %s -- closing it",
                    self._duid,
                )
                self._mark_peer_closed()
                return
            total = HEAD_LEN + head.body_len
            if len(buf) < total:
                return
            del buf[:total]
            if head.ftype == FTYPE_CLOSE:
                _LOGGER.debug("The station closed the audio channel of %s", self._duid)
                self._mark_peer_closed()
                return
            if head.ftype == FTYPE_KEEPALIVE:
                continue
            _LOGGER.debug(
                "Audio channel of %s: answer type 0x%02x msg13=%d content=%04x",
                self._duid,
                head.ftype,
                head.msg13,
                head.content_len,
            )
            with self._answer_cv:
                self._answers.append((head.ftype, head.msg13, head.content_len))
                self._answer_cv.notify_all()

    def _mark_peer_closed(self) -> None:
        self._peer_closed = True
        with self._answer_cv:
            self._answer_cv.notify_all()
        with self._audio_cv:
            self._talking = False
            self._pending.clear()
            self._audio_cv.notify_all()
        callback = self._on_closed
        if callback is not None and not self._closed and not self._closed_reported:
            self._closed_reported = True
            try:
                callback()
            except Exception:  # noqa: BLE001 -- never kill a channel thread
                _LOGGER.exception("Close callback of the audio channel raised")

    # --- Sending / teardown ----------------------------------------------------

    def _raw_send(self, data: bytes) -> None:
        with self._send_lock:
            self._sendall(data)

    def _send_frame(self, build: Callable[[int], bytes]) -> None:
        """Send ``build(ts)`` with the next frame counter.

        Counter and write happen under one lock: the sender thread and the
        executor threads (talk state, close) never send out of counter order.
        """
        with self._send_lock:
            self._ts = (self._ts + 1) & 0xFFFFFFFF
            self._sendall(build(self._ts))

    def _sendall(self, data: bytes) -> None:
        """Write ``data`` (send lock held)."""
        sock = self._sock
        if sock is None:
            raise SessionClosedError("the audio channel is closed")
        sock.sendall(data)
        self._last_sent = time.monotonic()

    def close(self) -> None:
        """Stop talking, say goodbye (``0x07``) and close the connection."""
        if self._closed:
            return
        self._closed = True
        was_talking = self._talking
        with self._audio_cv:
            self._talking = False
            self._pending.clear()
            self._audio_cv.notify_all()
        self._stop.set()
        if self._sock is not None and not self._peer_closed:
            try:
                if was_talking:
                    self._send_frame(lambda ts: talk_state_frame(ts, False, self._key))
                self._send_frame(lambda ts: ctrl_frame(FTYPE_CLOSE, ts, b"", self._key))
            except (OSError, TransportError):
                pass
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        with self._answer_cv:
            self._answer_cv.notify_all()
        for thread in self._threads:
            if thread is not threading.current_thread():
                thread.join(timeout=1.0)
        _LOGGER.debug("Audio channel to %s closed", self._duid)
