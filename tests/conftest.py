"""Shared test scaffolding for the Qualvision integration.

Everything here is keyless: the AES key used in the tests is a made-up 32-character
string, never a real station key, and the ``.bin`` vectors in ``fixtures/`` are the
non-secret, pcap-derived byte strings (plaintext ``a9`` setup body / echo, and the
AES ciphertext of the first 1968 client bytes, which cannot be decrypted without
the real key).

Provides:

* ``fixture_bytes`` / vector fixtures loaded from ``tests/fixtures``;
* helpers that build and parse the wire frames the way a station would;
* :class:`FakeStation`, a real loopback TCP server that speaks the station side of
  the handshake, so the blocking transport can be driven end to end without any
  hardware and without depending on how the transport opens its socket.
"""

from __future__ import annotations

import socket
import struct
import sys
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:  # make ``custom_components`` importable
    sys.path.insert(0, str(ROOT))


FIXTURES = Path(__file__).parent / "fixtures"

# Made-up test secrets (never real).
TEST_KEY_STR = "k" * 32
TEST_KEY = TEST_KEY_STR.encode("ascii")
TEST_DYNPW = "p" * 96  # ~96 chars -> the 208-byte LOGIN frame of the capture
TEST_CLIENT_ID = "0123456789abcdef"
TEST_DUID = "testduid0001"
TEST_OEM = "G0028G0126"
TEST_PIN_SHA256 = "ab" * 32


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


def parse_ctrl_frame(buf: bytes, key: bytes) -> tuple[int, int, bytes, int] | None:
    """Parse one control frame at the start of ``buf``.

    Returns ``(ftype, msg13, payload, total_len)`` or None if ``buf`` is incomplete.
    ``total_len == 32 + head[9]``; the payload is verified against its SHA-256 trailer.
    """
    from custom_components.balter_evo2.protocol import cbc_decrypt

    if len(buf) < 32:
        return None
    head = cbc_decrypt(buf[:32], key)
    total = 32 + head[9]
    if len(buf) < total:
        return None
    clen = head[11]
    body = cbc_decrypt(buf[32:total], key)
    payload = body[:clen]
    import hashlib

    assert body[clen : clen + 32] == hashlib.sha256(head + payload).digest(), (
        "control frame trailer mismatch"
    )
    return head[0], head[13], payload, total


def build_media_frame(
    key: bytes,
    h264: bytes,
    *,
    ts: int = 0,
    width: int = 352,
    height: int = 280,
    align: int = 16,
) -> bytes:
    """Build a media (type 0xA0) frame: AES 64-byte head + plaintext H.264 body.

    The decrypted head carries ``type@0``, ``ts@1``, ``byte9=0x20`` and the picture
    size at 0x30/0x32. The total length is padded to ``align`` bytes so the
    fallback next-head scanner can find boundaries.
    """
    from custom_components.balter_evo2.protocol import cbc_encrypt

    plain = bytearray(64)
    plain[0] = 0xA0
    struct.pack_into("<I", plain, 1, ts)
    plain[9] = 0x20
    struct.pack_into("<HH", plain, 0x30, width, height)
    body = bytes(h264)
    pad = (-(64 + len(body))) % align
    body += b"\xee" * pad  # filler that is not a start code
    return cbc_encrypt(bytes(plain), key) + body


def make_h264_keyframe(seed: int = 0) -> bytes:
    """A synthetic Annex-B keyframe: SPS + PPS + IDR (> 500 bytes in total)."""
    filler = bytes((seed + i * 7) % 251 + 1 for i in range(400))
    return (
        b"\x00\x00\x00\x01\x67" + bytes(range(1, 20))
        + b"\x00\x00\x00\x01\x68" + b"\xce\x3c\x80"
        + b"\x00\x00\x00\x01\x65" + filler
    )


def make_h264_pframe(seed: int = 0) -> bytes:
    """A synthetic non-keyframe body (no start code: it is inside the enc. head)."""
    return bytes((seed * 3 + i * 5) % 251 + 1 for i in range(300))


# --- fake station -------------------------------------------------------------------


class FakeStation:
    """Loopback TCP server playing the door station of the captured handshake.

    Flow per connection: read the raw 32-byte a9 body -> send the raw a9 echo ->
    read LOGIN -> send the "ready" control frame
    (0xFE, msg13=2, payload 00 01) -> send ``media`` frames -> keep reading client
    frames (keepalives, open-door) and answer an open-door with a 0xFE msg13=4 ack.
    """

    def __init__(
        self,
        key: bytes = TEST_KEY,
        *,
        echo: bytes | None = None,
        send_echo: bool = True,
        send_ready: bool = True,
        media: list[bytes] | None = None,
        ack_open: bool = True,
        close_after_media: bool = False,
        keepalive_every: float | None = None,
    ) -> None:
        self.key = key
        self.echo = echo if echo is not None else load_fixture("a9_echo.bin")
        self.send_echo = send_echo
        self.send_ready = send_ready
        self.media = media or []
        self.ack_open = ack_open
        self.close_after_media = close_after_media
        self.keepalive_every = keepalive_every
        self.a9_body: bytes | None = None
        self.frames: list[tuple[int, int, bytes, bytes]] = []  # ftype,msg13,payload,raw
        self.raw_stream = bytearray()
        self.connections = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(2)
        self._srv.settimeout(0.2)
        self.port: int = self._srv.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True, name="fake-station")
        self._thread.start()

    # -- lifecycle
    def close(self) -> None:
        """Stop the server and join its thread."""
        self._stop.set()
        self._thread.join(timeout=3)
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
            self.connections += 1
            try:
                self._handle(conn)
            except OSError:
                pass
            finally:
                conn.close()

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

    def _handle(self, conn: socket.socket) -> None:
        from custom_components.balter_evo2.protocol import ctrl_frame

        conn.settimeout(0.2)
        body = self._recv_exact(conn, 32)
        if body is None:
            return
        self.a9_body = body
        self.raw_stream += body
        if not self.send_echo:
            self._drain(conn, ctrl_frame, until_closed=True)
            return
        conn.sendall(self.echo)
        buf = bytearray()
        # The LOGIN frame (setup 0xFE comes later, on request) precedes the ready marker.
        while len(self.frames) < 1 and not self._stop.is_set():
            if not self._pump(conn, buf):
                return
        if self.send_ready:
            conn.sendall(ctrl_frame(0xFE, 0, b"\x00\x01", self.key, msg13=2))
        for frame in self.media:
            conn.sendall(frame)
        if self.close_after_media:
            return
        last_ka = time.monotonic()
        while not self._stop.is_set():
            if self.keepalive_every and time.monotonic() - last_ka >= self.keepalive_every:
                conn.sendall(ctrl_frame(0x00, 0, b"", self.key))
                last_ka = time.monotonic()
            if not self._pump(conn, buf):
                return

    def _drain(self, conn: socket.socket, _cf: object, *, until_closed: bool) -> None:
        while not self._stop.is_set():
            try:
                if not conn.recv(4096):
                    return
            except TimeoutError:
                continue

    def _pump(self, conn: socket.socket, buf: bytearray) -> bool:
        """Read some bytes, parse complete client frames. False when peer closed."""
        from custom_components.balter_evo2.protocol import ctrl_frame

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
            if ftype == 0xFE and msg13 == 4 and self.ack_open:
                conn.sendall(ctrl_frame(0xFE, 0, b"\x00", self.key, msg13=4))


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
