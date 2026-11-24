"""Pure application-layer codec for Qualvision door stations.

This module is transport-agnostic: the same application frames travel over the
legacy UDP/KCP transport and over the direct TCP connection to the station
(port 34567) that this integration uses. It contains no sockets, no threads and
no Home Assistant imports -- only byte builders and parsers, so it can be tested
byte-exactly against packet-capture vectors.

Attribution: the frame builders, the AES helpers and the H.264 extraction are
lifted from ``p2p.py`` of the community integration balter-evo-ha
(https://github.com/LucaHerrero/balter-evo-ha, MIT licensed), whose author
reverse-engineered the protocol. They are byte-exact against captures of the
official app -- do not "tidy them up" without a fresh capture.

What is deliberately NOT here: the UDP transport header, KCP, the 56-byte
``ff ff ff ff`` outer app frame, HELLO76, hole punching and NAT checks. None of
them appear on the TCP stream, which carries the bare inner application frames:

* a plaintext 32-byte ``a9`` setup body as the very first stream bytes,
* control frames = :func:`ctrl_frame` output (AES-256-CBC, constant IV),
* media frames = a 32-byte AES head, then ``content_len`` payload bytes of which
  the first ``encrypted_len`` are AES encrypted and the rest is plaintext. The
  payload is a 20-byte packet header (video / keyframe / audio, see
  :class:`MediaPacket`) followed by the elementary stream.

Every frame starts with the same 32-byte head and is self-delimiting through
it, see :func:`parse_head`. This was verified against live captures of a Balter
EVO 2: 1692 video frames in 93 s walked without a single resync.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Iterable
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- Protocol constants (byte-exact against the captures) ------------------------

# Channel indices. The wire value is carried by byte 9 of the a9 setup body
# (0 = video/control, 2 = audio), see build_a9_body().
CH0 = 0x01000000  # video + authenticated control channel
CH1 = 0x02000001  # audio channel

# AES-256-CBC with a constant IV of sixteen ASCII "0" characters.
IV_ZERO = b"0" * 16

# Fallback key if no data-encode key is passed in. The real key is device
# specific, rotates weekly and comes from the cloud device list at runtime.
FALLBACK_KEY = b"1" * 32

# Default OEM identifier of the LOGIN payload (the cloud's "G0028,G0126" without
# the comma). Kept literal so this module needs no other module of the package.
DEFAULT_OEM = "G0028G0126"

SHA256_OF_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Frame geometry.
A9_BODY_LEN = 32  # plaintext setup body / echo
HEAD_LEN = 32  # AES-encrypted head every frame starts with
CTRL_HEAD_LEN = HEAD_LEN  # historical name

# Frame types (head byte 0).
FTYPE_KEEPALIVE = 0x00
FTYPE_LOGIN = 0x01
FTYPE_CLOSE = 0x07
FTYPE_MEDIA = 0xA0
FTYPE_CONTROL = 0xFE
KNOWN_FTYPES = frozenset(
    {FTYPE_KEEPALIVE, FTYPE_LOGIN, FTYPE_CLOSE, FTYPE_MEDIA, FTYPE_CONTROL}
)

# Head field offsets (decrypted head).
_HEAD_ENC_LEN = 9  # u16 LE: number of AES-encrypted bytes after the head
_HEAD_CONTENT_LEN = 11  # u16 LE (control) / u32 LE (media): real content length
_HEAD_MSG13 = 13  # control frames only: message id
_HEAD_ZERO_FROM = 17  # bytes 17..31 (and 5..8) are zero in every frame captured

# Upper bounds, only there to reject a mis-decrypted head.
MAX_CTRL_BODY = 0xFFF0
MAX_MEDIA_PAYLOAD = 4 << 20  # 4 MiB; a 768x432 keyframe is ~36 kB

# Media packet header (first 20 bytes of a media payload).
MEDIA_PACKET_HEAD_LEN = 20
MEDIA_VIDEO = 0xE0  # H.264 delta frame (Annex B)
MEDIA_KEYFRAME = 0xE1  # H.264 SPS + PPS + IDR (Annex B)
MEDIA_AUDIO = 0xE3  # G.711 A-law, 8 kHz


# --- AES -----------------------------------------------------------------------------


def cbc_encrypt(data: bytes, key: bytes) -> bytes:
    """AES-256-CBC encryption with a zero IV (a trailing partial block is dropped)."""
    n = len(data) - (len(data) % 16)
    if n == 0:
        return b""
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV_ZERO)).encryptor()
    return cipher.update(data[:n]) + cipher.finalize()


def cbc_decrypt(data: bytes, key: bytes) -> bytes:
    """AES-256-CBC decryption with a zero IV (trailing partial block kept as is)."""
    n = len(data) - (len(data) % 16)
    if n == 0:
        return data
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV_ZERO)).decryptor()
    return cipher.update(data[:n]) + cipher.finalize() + data[n:]


def session_key(data_encode_key: str | None) -> bytes:
    """Return the AES key of the session (device key, or the family default)."""
    return data_encode_key.encode("ascii") if data_encode_key else FALLBACK_KEY


# --- Frame builders ----------------------------------------------------------------------


def ctrl_frame(
    ftype: int,
    ts: int,
    payload: bytes,
    key: bytes = FALLBACK_KEY,
    msg13: int = 0,
    b14: int = 0,
    f15: int = 0,
    f16: int = 0,
    b17: int = 0,
) -> bytes:
    """Build and encrypt an application control frame.

    Layout of the plaintext 32-byte head: ``ftype@0``, ``ts@1`` (u32 LE),
    ``plen@9`` (u16 LE, padded length of payload + SHA-256 trailer), ``clen@0xb``
    (u16 LE, real payload length), ``msg13@0xd`` and flag bytes at 0xe..0x11. The head and the
    ``payload || SHA256(head || payload)`` body (zero padded to a block) are
    encrypted separately. An empty payload yields the 64-byte keepalive.
    """
    clen = len(payload)
    body_len = clen + 32
    plen = body_len + ((16 - body_len % 16) % 16)
    if plen > MAX_CTRL_BODY:
        raise ValueError(
            f"control payload too large: {clen} bytes -> body {plen} exceeds the "
            f"16-bit frame-length field (max {MAX_CTRL_BODY})"
        )
    head = bytearray(HEAD_LEN)
    head[0] = ftype
    struct.pack_into("<I", head, 1, ts)
    struct.pack_into("<H", head, _HEAD_ENC_LEN, plen)
    struct.pack_into("<H", head, _HEAD_CONTENT_LEN, clen)
    head[_HEAD_MSG13] = msg13
    head[14] = b14
    head[15] = f15
    head[16] = f16
    if b17:
        head[17] = b17
    trailer = hashlib.sha256(bytes(head) + bytes(payload)).digest()
    nutz = bytes(payload) + trailer
    if len(nutz) % 16:
        nutz += b"\x00" * (16 - len(nutz) % 16)
    return cbc_encrypt(bytes(head), key) + cbc_encrypt(nutz, key)


def build_a9_body(ch_idx: int) -> bytes:
    """Build the 32-byte plaintext setup body that opens a connection.

    Byte 0 = 0xA9; byte 9 = stream type: 0 = video (CH0), 2 = audio (CH1).
    On TCP this is the very first thing written to the socket, raw.
    """
    body = bytearray(32)
    body[0] = 0xA9
    if ch_idx:
        body[9] = 0x02
    return bytes(body)


def build_login_payload(dynpw: str, client_id: str, oem: str = DEFAULT_OEM) -> bytes:
    """Build the payload of the LOGIN (ftype 0x01) frame.

    ``adminapp&&<dynamic_password>\\0<oem>\\0clientid=<16 hex>\\0``
    """
    return (
        b"adminapp&&"
        + dynpw.encode("ascii")
        + b"\x00"
        + oem.encode("ascii")
        + b"\x00clientid="
        + client_id.encode("ascii")
        + b"\x00"
    )


def build_open_payload(door: int, locknumber: int, pin_sha256: str) -> bytes:
    """Build the payload of the OPENDOOR (ftype 0xFE, msg13=4) frame."""
    payload = bytearray(16)
    payload[0] = door
    payload[2] = locknumber
    payload[3] = 1
    return bytes(payload) + pin_sha256.encode("ascii")


# --- Parsing ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FrameHead:
    """The decoded 32-byte head of one frame on the stream."""

    ftype: int
    encrypted_len: int  # AES-encrypted bytes that follow the head
    content_len: int  # control: real payload length; media: whole payload length
    msg13: int

    @property
    def is_media(self) -> bool:
        """Return whether this is a media (``0xA0``) frame."""
        return self.ftype == FTYPE_MEDIA

    @property
    def body_len(self) -> int:
        """Return how many bytes follow the head on the wire.

        A control frame is fully encrypted (payload + SHA-256 trailer, padded).
        A media frame carries ``content_len`` bytes, only the first
        ``encrypted_len`` of them encrypted.
        """
        return self.content_len if self.is_media else self.encrypted_len


def parse_head(head: bytes) -> FrameHead | None:
    """Decode a decrypted 32-byte head, or return ``None`` if it is not one.

    ``None`` means the bytes are not a frame head (the stream is out of sync or
    the key is wrong); it is never returned for a frame the station really sent.
    The check is strict on purpose -- nineteen bytes that must be zero and a
    block-aligned encrypted length -- so a resync cannot lock onto video data.
    The type byte is deliberately NOT part of it: a frame type this code has
    never seen still carries valid lengths and is skipped by them (as a control
    frame) instead of costing a resync on every occurrence.
    """
    if len(head) < HEAD_LEN:
        return None
    if any(head[_HEAD_ZERO_FROM:HEAD_LEN]) or any(head[5:_HEAD_ENC_LEN]):
        return None
    ftype = head[0]
    encrypted_len = struct.unpack_from("<H", head, _HEAD_ENC_LEN)[0]
    if encrypted_len % 16:
        return None
    if ftype == FTYPE_MEDIA:
        content_len = struct.unpack_from("<I", head, _HEAD_CONTENT_LEN)[0]
        if not (
            MEDIA_PACKET_HEAD_LEN <= content_len <= MAX_MEDIA_PAYLOAD
            and encrypted_len <= content_len
        ):
            return None
        return FrameHead(ftype, encrypted_len, content_len, 0)
    if not 32 <= encrypted_len <= MAX_CTRL_BODY:
        return None
    content_len = struct.unpack_from("<H", head, _HEAD_CONTENT_LEN)[0]
    return FrameHead(ftype, encrypted_len, content_len, head[_HEAD_MSG13])


def control_payload(head: FrameHead, body: bytes) -> bytes:
    """Return the real payload of a decrypted control-frame body.

    The body is ``payload || SHA-256 || padding``. Some station replies (the
    LOGIN answer) put a status word where the length normally sits, so the
    length is clamped to what the body can hold.
    """
    return body[: min(head.content_len, max(len(body) - 32, 0))]


@dataclass(frozen=True, slots=True)
class MediaPacket:
    """One media packet: a video frame, a keyframe or an audio chunk."""

    kind: int  # MEDIA_VIDEO, MEDIA_KEYFRAME or MEDIA_AUDIO
    timestamp: float  # station wall clock, seconds since the epoch
    width: int  # video only, else 0
    height: int  # video only, else 0
    data: bytes  # H.264 Annex B (video) or G.711 A-law (audio)

    @property
    def is_video(self) -> bool:
        """Return whether the packet carries H.264."""
        return self.kind in (MEDIA_VIDEO, MEDIA_KEYFRAME)

    @property
    def is_keyframe(self) -> bool:
        """Return whether the packet is a self-contained picture (SPS+PPS+IDR)."""
        return self.kind == MEDIA_KEYFRAME


def parse_media(payload: bytes) -> MediaPacket | None:
    """Decode a decrypted media payload, or return ``None`` if it is malformed.

    Packet header (20 bytes): ``00 00 01 <kind>``, data length (u32 LE), seconds
    (u32 LE), milliseconds (u16 LE), then six codec bytes -- for video
    ``01 64 <width u16> <height u16>``, for audio ``<fmt> 01 <rate u16> 00 00``.
    """
    if len(payload) < MEDIA_PACKET_HEAD_LEN or payload[:3] != b"\x00\x00\x01":
        return None
    kind = payload[3]
    length, seconds, millis = struct.unpack_from("<IIH", payload, 4)
    data = payload[MEDIA_PACKET_HEAD_LEN : MEDIA_PACKET_HEAD_LEN + length]
    if len(data) != length:
        return None
    width = height = 0
    if kind in (MEDIA_VIDEO, MEDIA_KEYFRAME):
        width, height = struct.unpack_from("<HH", payload, 16)
    return MediaPacket(kind, seconds + millis / 1000.0, width, height, bytes(data))


def video_stream(packets: Iterable[MediaPacket]) -> bytes:
    """Join the video packets into one H.264 stream, starting at a keyframe.

    Everything before the first keyframe is dropped (a decoder cannot start on a
    delta frame) and audio packets are skipped. Returns ``b""`` when no keyframe
    is present.
    """
    out = bytearray()
    started = False
    for packet in packets:
        if not packet.is_video:
            continue
        if not started:
            if not packet.is_keyframe:
                continue
            started = True
        out += packet.data
    return bytes(out)
