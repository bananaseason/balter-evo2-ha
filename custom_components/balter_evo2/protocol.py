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
# Audio channel (a second connection opened with ``build_a9_body(1)``).
FTYPE_AUDIO_LOGIN = 0x0B  # LOGIN of the audio channel and its answer
FTYPE_AUDIO_FORMAT = 0x0C  # audio format (sample rate in head bytes 15..16)
FTYPE_TALK = 0x0D  # talk state: msg13 0 = talking, 1 = not talking
FTYPE_TALK_AUDIO = 0xA2  # microphone audio, laid out like a media frame
KNOWN_FTYPES = frozenset(
    {
        FTYPE_KEEPALIVE,
        FTYPE_LOGIN,
        FTYPE_CLOSE,
        FTYPE_MEDIA,
        FTYPE_CONTROL,
        FTYPE_AUDIO_LOGIN,
        FTYPE_AUDIO_FORMAT,
        FTYPE_TALK,
        FTYPE_TALK_AUDIO,
    }
)
# Frame types whose head carries a u32 content length (payload partly plaintext).
LONG_FTYPES = frozenset({FTYPE_MEDIA, FTYPE_TALK_AUDIO})

# Talk state values (``msg13`` of a ``FTYPE_TALK`` frame).
TALK_ON = 0
TALK_OFF = 1

# Talk-back audio: G.711 A-law, 8 kHz mono, 320 bytes = 40 ms per frame.
TALK_SAMPLE_RATE = 8000
TALK_FRAME_BYTES = 320
TALK_FRAME_SECONDS = 0.04
# Content length of an "empty" audio-channel frame (no payload at all).
EMPTY_CONTENT_LEN = 0xFFFF
# Prefix of a talk frame's payload, followed by the data length (u16 LE).
_TALK_PREFIX = b"\x00\x00\x01\xf0\x0e\x02"

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


def empty_frame(
    ftype: int,
    ts: int,
    msg13: int,
    key: bytes = FALLBACK_KEY,
    b15: int = 0,
    b16: int = 0,
) -> bytes:
    """Build an "empty" audio-channel frame (types ``0x0C`` / ``0x0D``).

    A 32-byte head with ``encrypted_len = 32`` and ``content_len = 0xFFFF``,
    followed by the SHA-256 of the plaintext head; both encrypted separately.
    Verified live on a Balter EVO 2 (2026-11-24, ``reference/tools/talk_spike.py``).
    """
    head = bytearray(HEAD_LEN)
    head[0] = ftype
    struct.pack_into("<I", head, 1, ts)
    struct.pack_into("<H", head, _HEAD_ENC_LEN, 32)
    struct.pack_into("<H", head, _HEAD_CONTENT_LEN, EMPTY_CONTENT_LEN)
    head[_HEAD_MSG13] = msg13
    head[15] = b15
    head[16] = b16
    return cbc_encrypt(bytes(head), key) + cbc_encrypt(
        hashlib.sha256(bytes(head)).digest(), key
    )


def audio_login_frame(
    ts: int,
    dynpw: str,
    client_id: str,
    oem: str = DEFAULT_OEM,
    key: bytes = FALLBACK_KEY,
) -> bytes:
    """Build the LOGIN of the audio channel: type ``0x0B``, msg13 and byte 14 ``0xFF``.

    It carries the same payload as the video LOGIN.
    """
    return ctrl_frame(
        FTYPE_AUDIO_LOGIN,
        ts,
        build_login_payload(dynpw, client_id, oem),
        key,
        msg13=0xFF,
        b14=0xFF,
    )


def audio_format_frame(ts: int, key: bytes = FALLBACK_KEY) -> bytes:
    """Build the audio-format frame: type ``0x0C``, msg13 1, 8000 Hz in bytes 15..16."""
    rate = struct.pack("<H", TALK_SAMPLE_RATE)
    return empty_frame(FTYPE_AUDIO_FORMAT, ts, 1, key, b15=rate[0], b16=rate[1])


def talk_state_frame(ts: int, talking: bool, key: bytes = FALLBACK_KEY) -> bytes:
    """Build the talk-state frame: type ``0x0D``, msg13 0 = talking, 1 = not."""
    return empty_frame(FTYPE_TALK, ts, TALK_ON if talking else TALK_OFF, key)


def talk_frame(ts: int, alaw: bytes, key: bytes = FALLBACK_KEY) -> bytes:
    """Build one talk-back audio frame (type ``0xA2``).

    Laid out like a media frame: a head with ``encrypted_len = 32`` and a u32
    content length, then the payload ``00 00 01 f0 0e 02 <len u16 LE> <A-law>``
    whose first 32 bytes are encrypted and the rest is plaintext.
    """
    payload = _TALK_PREFIX + struct.pack("<H", len(alaw)) + bytes(alaw)
    if len(payload) < 32:
        raise ValueError(f"talk audio too short: {len(alaw)} bytes")
    head = bytearray(HEAD_LEN)
    head[0] = FTYPE_TALK_AUDIO
    struct.pack_into("<I", head, 1, ts)
    struct.pack_into("<H", head, _HEAD_ENC_LEN, 32)
    struct.pack_into("<I", head, _HEAD_CONTENT_LEN, len(payload))
    return cbc_encrypt(bytes(head), key) + cbc_encrypt(payload[:32], key) + payload[32:]


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
    """Build the payload of the OPENDOOR (ftype 0xFE, msg13=4) frame.

    Byte 0 is the lock number, byte 2 the door station (channel), byte 3 the
    action (1 = open). The order comes from a capture of the phone app on an
    EVO 2 with two locks: its second button sends ``02 00 01 01``. With the two
    numbers the other way round the station takes "lock 2" for a door station
    it does not have and refuses (``01 01``).
    """
    payload = bytearray(16)
    payload[0] = locknumber
    payload[2] = door
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
        A media (or talk audio) frame carries ``content_len`` bytes, only the
        first ``encrypted_len`` of them encrypted.
        """
        return self.content_len if self.ftype in LONG_FTYPES else self.encrypted_len


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
    if ftype in LONG_FTYPES:
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


@dataclass(frozen=True, slots=True)
class AudioChannelHead:
    """The decoded head of one frame on the audio channel."""

    ftype: int
    msg13: int
    content_len: int  # u16 (u32 for a talk audio frame)
    body_len: int  # bytes that follow the head on the wire


def parse_audio_channel_head(head: bytes) -> AudioChannelHead | None:
    """Decode a decrypted head read on the audio channel.

    The station's answers there (``0x0B``, ``0x0C``, ``0x0D``) carry flag bytes
    whose meaning is not known, so only the lengths are checked -- the way the
    verified probe (``reference/tools/talk_spike.py``) walks the stream. TCP
    keeps the stream aligned; ``None`` means the head is not usable at all.
    """
    if len(head) < HEAD_LEN:
        return None
    ftype = head[0]
    encrypted_len = struct.unpack_from("<H", head, _HEAD_ENC_LEN)[0]
    if encrypted_len % 16:
        return None
    if ftype in LONG_FTYPES:
        content_len = struct.unpack_from("<I", head, _HEAD_CONTENT_LEN)[0]
        if not encrypted_len <= content_len <= MAX_MEDIA_PAYLOAD:
            return None
        return AudioChannelHead(ftype, 0, content_len, content_len)
    content_len = struct.unpack_from("<H", head, _HEAD_CONTENT_LEN)[0]
    return AudioChannelHead(ftype, head[_HEAD_MSG13], content_len, encrypted_len)


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
