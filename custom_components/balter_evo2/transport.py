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

The receive stream is a back-to-back concatenation of inner application frames.
Each frame is *self-describing through its AES-encrypted head*: the only way to
find a frame boundary is to decrypt the 32/64-byte head with the device's
``data_encode_key``. Control frames are ``32 + head[9]`` bytes; media frames are
a 64-byte AES head plus plaintext H.264 whose length is **not** in ``head[9]``
and is resolved by :class:`MediaLengthResolver` (see its docstring for the one
remaining live-validation blocker).

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
import struct
import threading
import time
from collections import deque
from collections.abc import Callable

from .const import KEEPALIVE_INTERVAL, LOGIN_TIMEOUT, OEM_ID_COMPACT
from .protocol import (
    MEDIA_HEAD_LEN,
    build_a9_body,
    build_login_payload,
    build_open_payload,
    cbc_decrypt,
    ctrl_frame,
    session_key,
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


class StationBusyError(TransportError):
    """The station answered but never freed its single app session in time.

    The command provably never left the client, so it is safe to try again in a
    few seconds.
    """


# --- Protocol / timing constants --------------------------------------------

# Control-frame geometry. ``head[9]`` is the padded length of the payload plus
# its 32-byte SHA-256 trailer; a frame is ``32 + head[9]`` bytes. An empty
# payload gives ``head[9] == 32`` -> the 64-byte keepalive. A plausible control
# frame has ``head[9]`` a positive multiple of 16, bounded well below anything a
# door station sends on its control channel.
MAX_CTRL_FRAME = 4096

# Media frames carry plaintext H.264 of unbounded length; this only guards the
# fallback length resolver against runaway buffering on a desync.
MAX_MEDIA_FRAME = 1 << 20  # 1 MiB

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

# Control-head field offsets (decrypted), from ctrl_frame()'s layout.
_HEAD_TYPE = 0
_HEAD_PLEN = 9
_HEAD_CLEN = 11
_HEAD_MSG13 = 13

# Media-head field offsets (decrypted 32/64-byte head), from P2P_PROTOCOL.md 5b.
_MEDIA_TYPE = 0xA0
_MEDIA_WIDTH_OFF = 0x30
_MEDIA_HEIGHT_OFF = 0x32
_MEDIA_MAX_DIM = 4096

# a9 echo recognition: byte0 = 0xA9, byte10 = 0x02, byte11 = 0x01 (accepted).
_A9_ECHO_MARKER = {0: 0xA9, 10: 0x02, 11: 0x01}

# Control frame types ever seen on the station's down stream (keepalive, LOGIN
# echo, close, the 0xFE control/ready/ack family). The fallback length scanner
# only accepts a candidate control head whose type is one of these, instead of
# any head whose plen happens to be a multiple of 16 -- the latter matches ~6 %
# of random plaintext positions and mis-frames the H.264 body.
_KNOWN_CTRL_FTYPES = frozenset({0x00, 0x01, 0x07, 0xFE})

# Media length resolver: the EXACT offset of the H.264 body length inside the
# decrypted 64-byte media head is UNRESOLVED from the capture (candidate regions:
# 6 bytes @0x0a-0x10, or a uint32 in the @0x20 block). Until it is pinned live,
# leave this ``None`` and the resolver uses its next-head scan fallback. Once the
# offset is known, set these three and the resolver reads it directly -- the only
# change needed to swap the fallback for the exact field.
MEDIA_LEN_OFFSET: int | None = None
MEDIA_LEN_FORMAT = "<I"  # struct format of the length field, when pinned
MEDIA_LEN_INCLUDES_HEAD = False  # does the field count the 64-byte head?


class MediaLengthResolver:
    """Delimit one media (``0xA0``) frame on the TCP stream.

    A media frame is a 64-byte AES head followed by plaintext H.264 whose length
    is **not** carried in ``head[9]``. Two strategies:

    * **primary** -- read a pinned length field from the decrypted 64-byte head
      at :data:`MEDIA_LEN_OFFSET`. Unknown until a live decrypt pins it; wired up
      and ready, simply off by default.
    * **fallback** -- scan forward from offset 64 at 16-byte-aligned boundaries
      for the next decodable frame head (a ``0xA0`` head with a sane width and
      height, or a plausible control head), treating everything up to it as this
      frame's H.264 body. Works without the pinned offset: the media is ~17 fps,
      ~1 keyframe/s, 352x280, and only keyframe start codes are visible raw --
      P-frame leading start codes are encrypted inside each head, which is why
      per-frame head decryption is unavoidable.
    """

    def __init__(
        self,
        key: bytes,
        offset: int | None = MEDIA_LEN_OFFSET,
        fmt: str = MEDIA_LEN_FORMAT,
        includes_head: bool = MEDIA_LEN_INCLUDES_HEAD,
    ) -> None:
        """Bind the resolver to the session key and the (optional) pinned offset."""
        self._key = key
        self._offset = offset
        self._fmt = fmt
        self._includes_head = includes_head
        # Picture size (width, height) latched from the first validly decoded
        # media head; subsequent media boundaries must match it exactly, which
        # narrows the fallback scanner's false positives by orders of magnitude.
        self._dims: tuple[int, int] | None = None

    def resolve(self, buf: bytes, head64: bytes, *, flush: bool) -> int | None:
        """Return the total frame length, or ``None`` if more data is needed.

        ``buf`` is the receive buffer starting at this frame's head, ``head64``
        its decrypted 64-byte head. ``flush`` (the socket has closed) forces a
        best-effort boundary at the end of the buffer.
        """
        if self._offset is not None:
            total = self._resolve_pinned(head64)
            if total is not None:
                return total
            # A pinned field that reads back nonsense: fall through to the scan
            # rather than emit a corrupt frame.
        self._latch_dims(head64)
        boundary = self._scan(buf)
        if boundary is not None:
            return boundary
        if flush and len(buf) >= MEDIA_HEAD_LEN:
            return len(buf)
        if len(buf) - MEDIA_HEAD_LEN >= MAX_MEDIA_FRAME:
            # No decodable boundary within the whole scan window: emit a
            # best-effort boundary at the cap so a persistent desync cannot grow
            # the receive buffer without bound (the next head realigns via
            # _resync). The frame itself is dropped as undecodable downstream.
            return MEDIA_HEAD_LEN + MAX_MEDIA_FRAME
        return None

    def _latch_dims(self, head64: bytes) -> None:
        if self._dims is not None or len(head64) < _MEDIA_HEIGHT_OFF + 2:
            return
        width = struct.unpack_from("<H", head64, _MEDIA_WIDTH_OFF)[0]
        height = struct.unpack_from("<H", head64, _MEDIA_HEIGHT_OFF)[0]
        if 0 < width <= _MEDIA_MAX_DIM and 0 < height <= _MEDIA_MAX_DIM:
            self._dims = (width, height)

    def _resolve_pinned(self, head64: bytes) -> int | None:
        size = struct.calcsize(self._fmt)
        if self._offset is None or self._offset + size > len(head64):
            return None
        value = struct.unpack_from(self._fmt, head64, self._offset)[0]
        total = value if self._includes_head else MEDIA_HEAD_LEN + value
        if MEDIA_HEAD_LEN <= total <= MAX_MEDIA_FRAME:
            return total
        return None

    def _scan(self, buf: bytes) -> int | None:
        limit = min(len(buf) - MEDIA_HEAD_LEN, MAX_MEDIA_FRAME)
        pos = MEDIA_HEAD_LEN
        while pos <= limit:
            if self._is_frame_head(buf, pos):
                return pos
            pos += 16
        return None

    def _is_frame_head(self, buf: bytes, pos: int) -> bool:
        head = cbc_decrypt(bytes(buf[pos : pos + 32]), self._key)
        if len(head) < 32:
            return False
        if head[_HEAD_TYPE] == _MEDIA_TYPE:
            if pos + MEDIA_HEAD_LEN > len(buf):
                return False
            wide = cbc_decrypt(bytes(buf[pos : pos + MEDIA_HEAD_LEN]), self._key)
            width = struct.unpack_from("<H", wide, _MEDIA_WIDTH_OFF)[0]
            height = struct.unpack_from("<H", wide, _MEDIA_HEIGHT_OFF)[0]
            if self._dims is not None:
                # Once the stream's picture size is known, a real media head must
                # carry exactly it; "merely sane" dimensions are a coincidence.
                return (width, height) == self._dims
            return 0 < width <= _MEDIA_MAX_DIM and 0 < height <= _MEDIA_MAX_DIM
        plen = head[_HEAD_PLEN]
        return (
            head[_HEAD_TYPE] in _KNOWN_CTRL_FTYPES
            and 32 <= plen <= MAX_CTRL_FRAME
            and plen % 16 == 0
        )


# Type of the media sink: ``(seq, frame_bytes)`` where ``frame_bytes`` is one
# complete media frame starting at its 64-byte AES head (what protocol.decode_media
# expects). ``seq`` is a monotonically increasing counter -- TCP already orders
# the stream, so it is informational only.
MediaSink = Callable[[int, bytes], None]


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
        enable_audio: bool = False,
        media_len_offset: int | None = MEDIA_LEN_OFFSET,
    ) -> None:
        """Prepare (but do not open) a session; see :meth:`connect`."""
        self._host = host
        self._port = port
        self._duid = duid
        self._dynamic_password = dynamic_password
        self._client_id = client_id
        self._oem = oem
        self._key = session_key(data_encode_key)
        # The audio channel (CH1, a second socket) is not needed for camera +
        # lock and is left unimplemented on purpose; the flag is accepted for API
        # parity and only noted.
        self._enable_audio = enable_audio
        self._resolver = MediaLengthResolver(self._key, media_len_offset)

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
        self._media_seq = 0
        self._since_login = 0

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
        if self._enable_audio:
            _LOGGER.debug(
                "Audio channel requested for %s but not implemented on the TCP "
                "path -- continuing video + control only",
                self._duid,
            )
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
            0x01,
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
                raise TransportError("socket is closed")
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
                if remaining <= 0 or self._peer_closed:
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
            self.send_ctrl(0xFE, msg, b"\x00", msg13=msg13)
            time.sleep(0.02)

    def send_open(self, door: int, locknumber: int, pin_sha256: str) -> bool:
        """Send the OPENDOOR frame exactly once and await the station's ack.

        ``ctrl_frame(0xFE, build_open_payload, msg13=4)`` on the video socket,
        after :attr:`device_ready`. Returns ``True`` only when the station
        acknowledges with its own ``0xFE msg13=4`` frame. The frame is sent
        exactly ONCE and NEVER retried: a second send could open the door twice,
        so an unacknowledged send returns ``False`` (sent-but-unacked, a hard
        failure for the caller to surface, not retry).
        """
        if not self.device_ready.is_set():
            raise StationBusyError(
                f"{self._duid} has not signalled session-ready -- not sending OPENDOOR"
            )
        payload = build_open_payload(door, locknumber, pin_sha256)
        with self._ack_cv:
            start = self._ack_total
        try:
            self._raw_send(ctrl_frame(0xFE, self._ts, payload, self._key, msg13=4))
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
        ftype, _ = self._wait_ack((0xFE, 4), OPENDOOR_ACK_TIMEOUT, start)
        acked = ftype == 0xFE
        if acked:
            _LOGGER.debug("Door unlock confirmed by %s (0xFE msg13=4)", self._duid)
        else:
            _LOGGER.error(
                "OPENDOOR to %s was sent but never acknowledged (0xFE msg13=4 not "
                "seen). The door may or may not have opened -- not retrying.",
                self._duid,
            )
        return acked

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
                self._process_buffer()
                continue
            except OSError:
                self._peer_closed = True
                self._wake_waiters()
                return
            if not chunk:
                self._peer_closed = True
                self._process_buffer(flush=True)
                self._wake_waiters()
                return
            self._buf += chunk
            self._process_buffer()

    def _process_buffer(self, flush: bool = False) -> None:
        """Consume whole frames from the receive buffer."""
        buf = self._buf
        while True:
            if len(buf) < 32:
                return
            head = cbc_decrypt(bytes(buf[:32]), self._key)
            if head[_HEAD_TYPE] == _MEDIA_TYPE:
                if len(buf) < MEDIA_HEAD_LEN:
                    return
                head64 = cbc_decrypt(bytes(buf[:MEDIA_HEAD_LEN]), self._key)
                total = self._resolver.resolve(bytes(buf), head64, flush=flush)
                if total is None or len(buf) < total:
                    return
                frame = bytes(buf[:total])
                del buf[:total]
                self._emit_media(frame)
                continue
            plen = head[_HEAD_PLEN]
            if not (32 <= plen <= MAX_CTRL_FRAME and plen % 16 == 0):
                if not self._resync():
                    return
                continue
            total = 32 + plen
            if len(buf) < total:
                return
            del buf[:total]
            self._emit_control(head[_HEAD_TYPE], head[_HEAD_MSG13])

    def _resync(self) -> bool:
        """Drop bytes until the buffer starts on a decodable head again.

        A safety net for a desync (a mis-resolved media length): normal control
        and media boundaries are exact. Returns ``True`` once realigned.
        """
        buf = self._buf
        scan_limit = min(len(buf) - 32, MAX_MEDIA_FRAME)
        for pos in range(1, scan_limit + 1):
            head = cbc_decrypt(bytes(buf[pos : pos + 32]), self._key)
            if head[_HEAD_TYPE] == _MEDIA_TYPE:
                del buf[:pos]
                return True
            plen = head[_HEAD_PLEN]
            if 32 <= plen <= MAX_CTRL_FRAME and plen % 16 == 0:
                del buf[:pos]
                return True
        # Nothing found; keep only a tail that might hold the start of a head.
        if len(buf) > 32:
            del buf[: len(buf) - 32]
        return False

    def _emit_media(self, frame: bytes) -> None:
        self._media_seq += 1
        self._since_login += len(frame)
        self._mark_logged_in()
        if not self.device_ready.is_set() and self._since_login > STREAM_IS_PROOF:
            self.device_ready.set()
            self._wake_waiters()
            _LOGGER.debug(
                "Video is flowing from %s -- the station has opened the session",
                self._duid,
            )
        sink = self._on_media
        if sink is not None:
            try:
                sink(self._media_seq, frame)
            except Exception:  # noqa: BLE001 -- a bad sink must not kill the RX loop
                _LOGGER.exception("Media sink for %s raised", self._duid)

    def _emit_control(self, ftype: int, msg13: int) -> None:
        self._mark_logged_in()
        if ftype == 0xFE and msg13 == 2 and not self.device_ready.is_set():
            self.device_ready.set()
            _LOGGER.debug("Station %s signalled session ready (0xFE msg13=2)", self._duid)
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
                if remaining <= 0 or self._peer_closed:
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
                self._raw_send(ctrl_frame(0x07, self._ts, b"", self._key))
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
                self._raw_send(ctrl_frame(0x00, self._ts, b"", self._key))
            except (OSError, TransportError):
                self._peer_closed = True
                self._wake_waiters()
                return
