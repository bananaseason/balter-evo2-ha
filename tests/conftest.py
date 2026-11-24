"""Shared test scaffolding for the Qualvision integration.

Everything here is keyless: the AES key used in the tests is a made-up 32-character
string, never a real station key, and the ``.bin`` vectors in ``fixtures/`` are the
non-secret, pcap-derived byte strings (plaintext ``a9`` setup body / echo, and the
AES ciphertext of the first 1968 client bytes, which cannot be decrypted without
the real key).

Provides:

* ``fixture_bytes`` / vector fixtures loaded from ``tests/fixtures``;
* helpers that build and parse the wire frames the way a station would (32-byte
  AES head on every frame; control frames fully encrypted; media frames with the
  first ``encrypted_len`` payload bytes encrypted and the rest plaintext; a
  20-byte packet header in front of every video / audio payload);
* :class:`FakeStation`, a real loopback TCP server that speaks the station side of
  the handshake (a9 echo, the ~830-byte ``0xFE msg13=18`` profile right after the
  login, the ready marker, interleaved video / audio / heartbeat frames), so the
  blocking transport can be driven end to end without any hardware.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import sys
import threading
import time
import types
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:  # make ``custom_components`` importable
    sys.path.insert(0, str(ROOT))


FIXTURES = Path(__file__).parent / "fixtures"

# Home Assistant's camera component imports ``turbojpeg`` at import time (it is
# installed on demand in a real installation, but is not in requirements-dev.txt).
# The camera tests never scale an image, so a stand-in module is enough.
try:  # pragma: no cover - depends on the environment
    import turbojpeg  # noqa: F401
except ImportError:  # pragma: no cover
    _turbojpeg = types.ModuleType("turbojpeg")
    _turbojpeg.TurboJPEG = type("TurboJPEG", (), {})  # type: ignore[attr-defined]
    sys.modules["turbojpeg"] = _turbojpeg

# Made-up test secrets (never real).
TEST_KEY_STR = "k" * 32
TEST_KEY = TEST_KEY_STR.encode("ascii")
TEST_DYNPW = "p" * 96  # ~96 chars -> the 208-byte LOGIN frame of the capture
TEST_CLIENT_ID = "0123456789abcdef"
TEST_DUID = "testduid0001"
TEST_OEM = "G0028G0126"
TEST_PIN_SHA256 = "ab" * 32


# --- Home Assistant -------------------------------------------------------------


def bypass_frontend(hass: object) -> object:
    """Count the ``frontend`` dependency as set up, without the frontend package.

    The integration depends on ``frontend`` (it loads the call card on every
    page), whose setup needs the ``hass_frontend`` package -- not installed for
    the tests. What the integration uses of it is the extra-module list, which
    is provided here; returns it so a test can look at the registered URLs.
    """
    from homeassistant.components.frontend import DATA_EXTRA_MODULE_URL, UrlManager

    hass.config.components.add("frontend")  # type: ignore[attr-defined]
    return hass.data.setdefault(  # type: ignore[attr-defined]
        DATA_EXTRA_MODULE_URL, UrlManager(lambda *_: None, [])
    )


# --- vectors ---------------------------------------------------------------------


def load_fixture(name: str) -> bytes:
    """Return the bytes of ``tests/fixtures/<name>``."""
    return (FIXTURES / name).read_bytes()


@pytest.fixture(scope="session")
def handshake_client() -> bytes:
    """The 1968 client->station bytes of the captured TCP handshake (ciphertext)."""
    return load_fixture("handshake_client.bin")


@pytest.fixture(scope="session")
def a9_echo() -> bytes:
    """The station's 32-byte raw a9 echo."""
    return load_fixture("a9_echo.bin")


@pytest.fixture(scope="session")
def station_head() -> bytes:
    """The first 4096 station->client bytes (echo + encrypted frames)."""
    return load_fixture("station_head.bin")


@pytest.fixture
def key() -> bytes:
    """AES key used by the tests."""
    return TEST_KEY


# --- frame helpers (station side) -------------------------------------------------

MEDIA_VIDEO = 0xE0
MEDIA_KEYFRAME = 0xE1
MEDIA_AUDIO = 0xE3

HEARTBEAT_MSG13 = 8
OPEN_MSG13 = 4
READY_MSG13 = 2
PROFILE_MSG13 = 18
PROFILE_LEN = 830


def make_profile_json(length: int = PROFILE_LEN) -> bytes:
    """A JSON "profile" of exactly ``length`` bytes, like the one the real station
    sends as ``0xFE msg13=18`` right after the login (~830 bytes, i.e. a control
    payload far above the 223 bytes the old 8-bit length field could carry)."""
    doc = {
        "Name": "profile",
        "Channels": [
            {"Id": 0, "Video": {"W": 768, "H": 432, "Codec": "H264"}},
            {"Id": 1, "Audio": {"Codec": "G711A", "Rate": 8000}},
        ],
        "Locks": [{"Door": 1, "Lock": 1, "Name": "Door opener"}],
        "Pad": "",
    }
    base = len(json.dumps(doc, separators=(",", ":")))
    doc["Pad"] = "x" * (length - base)
    out = json.dumps(doc, separators=(",", ":")).encode()
    assert len(out) == length
    return out


def parse_ctrl_frame(buf: bytes, key: bytes) -> tuple[int, int, bytes, int] | None:
    """Parse one control frame at the start of ``buf``.

    Returns ``(ftype, msg13, payload, total_len)`` or None if ``buf`` is incomplete.
    Lengths are the 16-bit fields of the head; the payload is verified against its
    SHA-256 trailer.
    """
    import hashlib

    from custom_components.balter_evo2.protocol import cbc_decrypt

    if len(buf) < 32:
        return None
    head = cbc_decrypt(buf[:32], key)
    enc_len = struct.unpack_from("<H", head, 9)[0]
    total = 32 + enc_len
    if len(buf) < total:
        return None
    clen = struct.unpack_from("<H", head, 11)[0]
    body = cbc_decrypt(buf[32:total], key)
    payload = body[:clen]
    assert body[clen : clen + 32] == hashlib.sha256(head + payload).digest(), (
        "control frame trailer mismatch"
    )
    return head[0], head[13], payload, total


def build_head(
    ftype: int,
    encrypted_len: int,
    content_len: int,
    *,
    msg13: int = 0,
    ts: int = 0,
    media: bool | None = None,
) -> bytearray:
    """Build a PLAINTEXT 32-byte frame head (bytes 17..31 zero).

    ``content_len`` is a u32 at offset 11 for a media frame, a u16 otherwise.
    """
    head = bytearray(32)
    head[0] = ftype
    struct.pack_into("<I", head, 1, ts)
    struct.pack_into("<H", head, 9, encrypted_len)
    if media is None:
        media = ftype == 0xA0
    if media:
        struct.pack_into("<I", head, 11, content_len)
    else:
        struct.pack_into("<H", head, 11, content_len)
        head[13] = msg13
    return head


def build_media_packet(
    kind: int,
    data: bytes,
    *,
    seconds: int = 1_700_000_000,
    millis: int = 0,
    width: int = 768,
    height: int = 432,
) -> bytes:
    """Build a decrypted media payload: 20-byte packet header + ``data``.

    Header: ``00 00 01 <kind>``, data length u32, seconds u32, millis u16, six codec
    bytes (video ``01 64 <w u16> <h u16>``, audio ``04 01 40 1f 00 00``).
    """
    if kind == MEDIA_AUDIO:
        codec = bytes.fromhex("0401401f0000")
    else:
        codec = struct.pack("<BBHH", 0x01, 0x64, width, height)
    header = (
        b"\x00\x00\x01"
        + bytes([kind])
        + struct.pack("<IIH", len(data), seconds, millis)
        + codec
    )
    assert len(header) == 20
    return header + data


def build_media_frame(
    key: bytes,
    packet: bytes,
    *,
    ts: int = 0,
    encrypted_len: int = 32,
) -> bytes:
    """Build a media (type 0xA0) frame around a decrypted media payload.

    Wire: ``enc(head32)`` + ``content_len`` payload bytes whose first
    ``encrypted_len`` are AES-CBC encrypted separately and the rest plaintext.
    """
    from custom_components.balter_evo2.protocol import cbc_encrypt

    encrypted_len = min(encrypted_len, len(packet) // 16 * 16)
    head = build_head(0xA0, encrypted_len, len(packet), ts=ts)
    return (
        cbc_encrypt(bytes(head), key)
        + cbc_encrypt(packet[:encrypted_len], key)
        + packet[encrypted_len:]
    )


def video_frame(key: bytes, data: bytes, *, keyframe: bool, ts: int = 0, **kw) -> bytes:
    """One wire media frame carrying a video (delta) or key frame packet."""
    kind = MEDIA_KEYFRAME if keyframe else MEDIA_VIDEO
    return build_media_frame(
        key, build_media_packet(kind, data, seconds=1_700_000_000 + ts, **kw), ts=ts
    )


def audio_frame(key: bytes, data: bytes, *, ts: int = 0) -> bytes:
    """One wire media frame carrying a G.711 audio packet."""
    return build_media_frame(
        key,
        build_media_packet(MEDIA_AUDIO, data, seconds=1_700_000_000 + ts, millis=20),
        ts=ts,
    )


def control_frame(
    key: bytes, msg13: int, payload: bytes = b"\x00", ftype: int = 0xFE
) -> bytes:
    """One wire control frame."""
    from custom_components.balter_evo2.protocol import ctrl_frame

    return ctrl_frame(ftype, 0, payload, key, msg13=msg13)


def profile_frame(key: bytes) -> bytes:
    """The station's ~830-byte JSON profile (``0xFE msg13=18``)."""
    return control_frame(key, PROFILE_MSG13, make_profile_json())


def heartbeat_frame(key: bytes) -> bytes:
    """The station's heartbeat (``0xFE msg13=8``)."""
    return control_frame(key, HEARTBEAT_MSG13, b"\x00" * 4)


def make_h264_keyframe(seed: int = 0) -> bytes:
    """A synthetic Annex-B keyframe: SPS + PPS + IDR (> 400 bytes in total)."""
    filler = bytes((seed + i * 7) % 251 + 1 for i in range(400))
    return (
        b"\x00\x00\x00\x01\x67"
        + bytes(range(1, 20))
        + b"\x00\x00\x00\x01\x68"
        + b"\xce\x3c\x80"
        + b"\x00\x00\x00\x01\x65"
        + filler
    )


def make_h264_pframe(seed: int = 0) -> bytes:
    """A synthetic Annex-B delta frame (a start code and a non-IDR slice)."""
    return b"\x00\x00\x00\x01\x41" + bytes(
        (seed * 3 + i * 5) % 251 + 1 for i in range(300)
    )


def make_audio_chunk(seed: int = 0, length: int = 160) -> bytes:
    """A synthetic G.711 chunk (160 bytes unless told otherwise)."""
    return bytes((seed + i) % 256 for i in range(length))


def station_empty_frame(key: bytes, ftype: int, msg13: int, content_len: int) -> bytes:
    """An answer of the station on the audio channel: a head and its SHA-256."""
    import hashlib

    from custom_components.balter_evo2.protocol import cbc_encrypt

    head = build_head(ftype, 32, content_len, msg13=msg13, media=False)
    return cbc_encrypt(bytes(head), key) + cbc_encrypt(
        hashlib.sha256(bytes(head)).digest(), key
    )


def parse_audio_channel_frame(
    buf: bytes, key: bytes
) -> tuple[int, int, int, bytes, int] | None:
    """Parse one client frame of the audio channel at the start of ``buf``.

    Returns ``(ftype, msg13, content_len, payload, total_len)`` or None if
    incomplete. ``payload`` is the decrypted control payload, or for a talk
    frame (``0xA2``) the whole payload (first 32 bytes decrypted).
    """
    from custom_components.balter_evo2.protocol import cbc_decrypt

    if len(buf) < 32:
        return None
    head = cbc_decrypt(buf[:32], key)
    ftype = head[0]
    enc_len = struct.unpack_from("<H", head, 9)[0]
    if ftype == 0xA2:
        clen = struct.unpack_from("<I", head, 11)[0]
        total = 32 + clen
        if len(buf) < total:
            return None
        payload = cbc_decrypt(buf[32 : 32 + enc_len], key) + buf[32 + enc_len : total]
        return ftype, 0, clen, payload, total
    total = 32 + enc_len
    if len(buf) < total:
        return None
    clen = struct.unpack_from("<H", head, 11)[0]
    body = cbc_decrypt(buf[32:total], key)
    payload = b"" if clen == 0xFFFF else body[:clen]
    return ftype, head[13], clen, payload, total


def audio_frame_counter(head: bytes, key: bytes) -> int:
    """Return the frame counter (head bytes 1..4) of an audio-channel frame."""
    from custom_components.balter_evo2.protocol import cbc_decrypt

    return struct.unpack_from("<I", cbc_decrypt(head[:32], key), 1)[0]


# --- fake ffmpeg ---------------------------------------------------------------------

LIVE_JPEG = b"\xff\xd8live\xff\xd9"


class FakeFFmpeg:
    """Stand-in for the ffmpeg transcoder: one JPEG out per chunk written in."""

    def __init__(self) -> None:
        read_fd, self._write_fd = os.pipe()
        self.stdout = os.fdopen(read_fd, "rb", buffering=0)
        self.stdin = self  # the pump writes to ``stdin.write`` / ``flush`` / ``close``
        self.written = bytearray()
        self.killed = False
        self._lock = threading.Lock()

    def write(self, data: bytes) -> int:
        with self._lock:
            self.written += data
            if self._write_fd is not None:
                os.write(self._write_fd, LIVE_JPEG)
        return len(data)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        with self._lock:
            if self._write_fd is not None:
                os.close(self._write_fd)
                self._write_fd = None

    def kill(self) -> None:
        self.killed = True
        self.close()

    def wait(self, timeout: float | None = None) -> int:
        return 0


# --- fake station -------------------------------------------------------------------


class FakeStation:
    """Loopback TCP server playing the door station.

    Flow per connection: read the raw 32-byte a9 body -> send the raw a9 echo ->
    read LOGIN -> send the ~830-byte profile (``0xFE msg13=18``) -> send the ready
    marker (``0xFE msg13=2``) -> send ``media`` frames once, or, with
    ``stream=True``, an endless interleaved stream (keyframe, then audio + delta
    pairs, a heartbeat now and then) until the client leaves -> keep reading client
    frames (keepalives, open-door) and answer an open-door with a ``0xFE msg13=4``
    ack (preceded by the profile frame and a heartbeat, which is what makes a
    naive parser lose track).

    Per-connection numbering is 1-based. ``no_video_connections=N`` makes the
    first N connections log in and become ready but never send video (the station
    that was reconnected to too soon).

    Video connections are served one at a time, like the real station's single
    session. A connection whose a9 body has byte 9 = 2 is the **audio channel**
    and is served alongside: the station answers its LOGIN ``0x0B``, the format
    ``0x0C`` and every talk state ``0x0D`` (``content_len`` 0 = talking, 1 =
    not) with an empty frame of the same type, and records every frame (see
    :attr:`audio_frames`, :meth:`talk_audio`). ``audio_accept=False`` leaves the
    LOGIN unanswered, ``talk_answer=False`` the talk states.
    """

    def __init__(
        self,
        key: bytes = TEST_KEY,
        *,
        echo: bytes | None = None,
        send_echo: bool = True,
        send_ready: bool = True,
        ready_after_setup: float | None = None,
        send_profile: bool = True,
        media: list[bytes] | None = None,
        stream: bool = False,
        frame_interval: float = 0.02,
        no_video_connections: int = 0,
        ack_open: bool = True,
        noisy_ack: bool = True,
        open_answer: bytes = b"\x00\x01",
        ack_delay: float = 0.0,
        close_after_media: bool = False,
        keepalive_every: float | None = None,
        heartbeat_every: float | None = None,
        chunk: int | None = None,
        audio_chunk_len: int = 160,
        audio_accept: bool = True,
        talk_answer: bool = True,
    ) -> None:
        self.key = key
        self.echo = echo if echo is not None else load_fixture("a9_echo.bin")
        self.send_echo = send_echo
        self.send_ready = send_ready
        # Like the real station: "session ready" is the answer to the client's
        # msg13=2 setup frame and comes this many seconds after it.
        self.ready_after_setup = ready_after_setup
        self.events: list[str] = []
        self.send_profile = send_profile
        self.media = media or []
        self.stream = stream
        self.frame_interval = frame_interval
        self.no_video_connections = no_video_connections
        self.ack_open = ack_open
        self.noisy_ack = noisy_ack
        self.open_answer = open_answer  # 00 01 = opened, 01 00 = wrong PIN
        self.ack_delay = ack_delay
        self.close_after_media = close_after_media
        self.keepalive_every = keepalive_every
        self.heartbeat_every = heartbeat_every
        self.chunk = chunk
        self.audio_chunk_len = audio_chunk_len
        self.audio_accept = audio_accept
        self.talk_answer = talk_answer
        self.a9_body: bytes | None = None
        self.frames: list[tuple[int, int, bytes, bytes]] = []  # ftype,msg13,payload,raw
        self.raw_stream = bytearray()
        self.connections = 0
        self.connect_times: list[float] = []
        self.disconnect_times: list[float] = []
        self.sent_video: list[bytes] = []  # data of every video packet sent
        self.sent_audio: list[bytes] = []  # data of every 0xE3 packet sent
        # Audio channel: (ftype, msg13, content_len, payload, monotonic time).
        self.audio_frames: list[tuple[int, int, int, bytes, float]] = []
        # The frame counter of each of them, in arrival order.
        self.audio_counters: list[int] = []
        self.audio_connections = 0
        self.audio_disconnect_times: list[float] = []
        self._audio_conns: list[socket.socket] = []
        self._lock = threading.Lock()
        self._video_slot = threading.Lock()
        self._workers: list[threading.Thread] = []
        self._stop = threading.Event()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(2)
        self._srv.settimeout(0.2)
        self.port: int = self._srv.getsockname()[1]
        self._thread = threading.Thread(
            target=self._serve, daemon=True, name="fake-station"
        )
        self._thread.start()

    # -- lifecycle
    def close(self) -> None:
        """Stop the server and join its threads."""
        self._stop.set()
        self._thread.join(timeout=3)
        for worker in list(self._workers):
            worker.join(timeout=3)
        self._srv.close()

    def __enter__(self) -> FakeStation:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- inspection (thread safe)
    def received(self, ftype: int | None = None) -> list[tuple[int, int, bytes, bytes]]:
        """Return the client control frames received so far (optionally by type)."""
        with self._lock:
            return [f for f in self.frames if ftype is None or f[0] == ftype]

    def audio_received(
        self, ftype: int | None = None
    ) -> list[tuple[int, int, int, bytes, float]]:
        """Return the frames received on audio channels (optionally by type)."""
        with self._lock:
            return [f for f in self.audio_frames if ftype is None or f[0] == ftype]

    def talk_audio(self) -> list[bytes]:
        """Return the A-law data of every talk frame (``0xA2``) received."""
        out = []
        for _, _, _, payload, _ in self.audio_received(0xA2):
            assert payload[:6] == b"\x00\x00\x01\xf0\x0e\x02", payload[:8].hex()
            length = struct.unpack_from("<H", payload, 6)[0]
            out.append(payload[8 : 8 + length])
        return out

    def talk_states(self) -> list[int]:
        """Return the msg13 of every talk state (``0x0D``): 0 = talking, 1 = not."""
        return [f[1] for f in self.audio_received(0x0D)]

    def drop_audio_channels(self) -> None:
        """Close every open audio channel from the station's side."""
        with self._lock:
            conns = list(self._audio_conns)
        for conn in conns:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def opens(self) -> list[tuple[int, int, bytes, bytes]]:
        """Return the OPENDOOR frames (``0xFE msg13=4``) received so far."""
        return [f for f in self.received(0xFE) if f[1] == OPEN_MSG13]

    def wait_for(self, predicate: Callable[[], bool], timeout: float = 5.0) -> bool:
        """Poll ``predicate`` until true or ``timeout``."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if predicate():
                return True
            time.sleep(0.01)
        return predicate()

    # -- server
    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except (TimeoutError, OSError):
                continue
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            worker = threading.Thread(
                target=self._serve_conn, args=(conn,), daemon=True, name="fake-conn"
            )
            self._workers.append(worker)
            worker.start()

    def _serve_conn(self, conn: socket.socket) -> None:
        """Serve one connection: the audio channel alongside, video one at a time."""
        conn.settimeout(0.02)
        try:
            body = self._recv_exact(conn, 32)
        except OSError:
            body = None
        if body is not None and len(body) == 32 and body[9] == 0x02:
            try:
                self._handle_audio(conn, body)
            except OSError:
                pass
            finally:
                with self._lock:
                    if conn in self._audio_conns:
                        self._audio_conns.remove(conn)
                conn.close()
                self.audio_disconnect_times.append(time.monotonic())
            return
        with self._video_slot:
            self.connections += 1
            self.connect_times.append(time.monotonic())
            try:
                self._handle(conn, self.connections, body)
            except OSError:
                pass
            finally:
                conn.close()
                self.disconnect_times.append(time.monotonic())

    def _handle_audio(self, conn: socket.socket, body: bytes) -> None:
        """Play the station side of the audio channel."""
        self.audio_connections += 1
        with self._lock:
            self._audio_conns.append(conn)
        self._send(conn, self.echo)
        buf = bytearray()
        while not self._stop.is_set():
            try:
                chunk = conn.recv(65536)
            except TimeoutError:
                continue
            if not chunk:
                return
            buf += chunk
            while True:
                parsed = parse_audio_channel_frame(bytes(buf), self.key)
                if parsed is None:
                    break
                ftype, msg13, clen, payload, total = parsed
                counter = audio_frame_counter(bytes(buf[:32]), self.key)
                del buf[:total]
                with self._lock:
                    self.audio_frames.append(
                        (ftype, msg13, clen, payload, time.monotonic())
                    )
                    self.audio_counters.append(counter)
                if ftype == 0x07:
                    return
                if ftype == 0x0B and self.audio_accept:
                    self._send(conn, station_empty_frame(self.key, 0x0B, 0, 0xFFFF))
                elif ftype == 0x0C:
                    self._send(conn, station_empty_frame(self.key, 0x0C, 1, 0xFFFF))
                elif ftype == 0x0D and self.talk_answer:
                    self._send(conn, station_empty_frame(self.key, 0x0D, 0, msg13))

    def _recv_exact(self, conn: socket.socket, n: int) -> bytes | None:
        data = b""
        while len(data) < n and not self._stop.is_set():
            try:
                chunk = conn.recv(n - len(data))
            except TimeoutError:
                continue
            if not chunk:
                return None
            data += chunk
        return data

    def _send(self, conn: socket.socket, data: bytes) -> None:
        if not self.chunk:
            conn.sendall(data)
            return
        for i in range(0, len(data), self.chunk):
            conn.sendall(data[i : i + self.chunk])

    def _stream_frames(self, n: int) -> list[bytes]:
        """Frames of tick ``n`` of the endless stream."""
        key = self.key
        if n == 0:
            data = make_h264_keyframe(0)
            self.sent_video.append(data)
            return [video_frame(key, data, keyframe=True)]
        data = make_h264_pframe(n)
        self.sent_video.append(data)
        audio = make_audio_chunk(n, self.audio_chunk_len)
        self.sent_audio.append(audio)
        out = [
            audio_frame(key, audio, ts=n),
            video_frame(key, data, keyframe=False, ts=n),
        ]
        if n % 10 == 0:
            out.append(heartbeat_frame(key))
        return out

    def _handle(self, conn: socket.socket, index: int, body: bytes | None) -> None:
        if body is None:
            return
        self.a9_body = body
        self.raw_stream += body
        buf = bytearray()
        if not self.send_echo:
            while not self._stop.is_set():
                if not self._pump(conn, buf):
                    return
            return
        self._send(conn, self.echo)
        login_seen = len(self.received(0x01))
        # The LOGIN frame precedes everything else the station sends.
        while len(self.received(0x01)) <= login_seen and not self._stop.is_set():
            if not self._pump(conn, buf):
                return
        if self.send_profile:
            self._send(conn, profile_frame(self.key))
        if self.send_ready and self.ready_after_setup is None:
            self._send(conn, control_frame(self.key, READY_MSG13, b"\x00\x01"))
        video = index > self.no_video_connections
        if video:
            for frame in self.media:
                self._send(conn, frame)
        if self.close_after_media:
            return
        last_ka = last_hb = last_tick = time.monotonic()
        tick = 0
        while not self._stop.is_set():
            now = time.monotonic()
            if self.keepalive_every and now - last_ka >= self.keepalive_every:
                self._send(conn, control_frame(self.key, 0, b"", ftype=0x00))
                last_ka = now
            if self.heartbeat_every and now - last_hb >= self.heartbeat_every:
                self._send(conn, heartbeat_frame(self.key))
                last_hb = now
            if video and self.stream and now - last_tick >= self.frame_interval:
                for frame in self._stream_frames(tick):
                    self._send(conn, frame)
                tick += 1
                last_tick = now
            if not self._pump(conn, buf):
                return

    def _pump(self, conn: socket.socket, buf: bytearray) -> bool:
        """Read some bytes, parse complete client frames. False when peer closed."""
        try:
            chunk = conn.recv(4096)
        except TimeoutError:
            return True
        if not chunk:
            return False
        buf += chunk
        self.raw_stream += chunk
        while True:
            parsed = parse_ctrl_frame(bytes(buf), self.key)
            if parsed is None:
                return True
            ftype, msg13, payload, total = parsed
            raw = bytes(buf[:total])
            del buf[:total]
            with self._lock:
                self.frames.append((ftype, msg13, payload, raw))
            if (
                ftype == 0xFE
                and msg13 == READY_MSG13
                and self.ready_after_setup is not None
            ):
                time.sleep(self.ready_after_setup)
                self._send(conn, control_frame(self.key, READY_MSG13, b"\x01\x01"))
                self.events.append("ready sent")
            if ftype == 0xFE and msg13 == OPEN_MSG13:
                self.events.append("open received")
            if ftype == 0xFE and msg13 == OPEN_MSG13 and self.ack_open:
                if self.ack_delay:
                    time.sleep(self.ack_delay)
                if self.noisy_ack:
                    # The big profile and a heartbeat ride in front of the ack.
                    self._send(conn, profile_frame(self.key))
                    self._send(conn, heartbeat_frame(self.key))
                self._send(conn, control_frame(self.key, OPEN_MSG13, self.open_answer))


@pytest.fixture
def fake_station_factory() -> Iterator[Callable[..., FakeStation]]:
    """Create :class:`FakeStation` servers; all are closed at teardown."""
    made: list[FakeStation] = []

    def factory(**kwargs: object) -> FakeStation:
        st = FakeStation(**kwargs)  # type: ignore[arg-type]
        made.append(st)
        return st

    yield factory
    for st in made:
        st.close()
