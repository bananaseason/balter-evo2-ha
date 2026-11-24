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
* control frames = :func:`ctrl_frame` output (AES-256-CBC, zero IV),
* media frames = AES-encrypted 64-byte head followed by plaintext H.264.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Iterable

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
CTRL_HEAD_LEN = 32  # decrypted head of a control frame
MEDIA_HEAD_LEN = 64  # AES-encrypted prefix of a media frame


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
    ``plen@9`` (padded length of payload + SHA-256 trailer), ``clen@0xb`` (real
    payload length), ``msg13@0xd`` and flag bytes at 0xe..0x11. The head and the
    ``payload || SHA256(head || payload)`` body (zero padded to a block) are
    encrypted separately. An empty payload yields the 64-byte keepalive.
    """
    clen = len(payload)
    nutzlen = clen + 32
    plen = nutzlen + ((16 - nutzlen % 16) % 16)
    if plen > 0xFF:
        # ``head[9]`` is a single byte; a payload this large cannot be framed.
        # Fail with a clear, mappable error instead of a raw bytearray
        # assignment ValueError (reachable only with an abnormally long rotated
        # dynamic password in the LOGIN payload).
        raise ValueError(
            f"control payload too large: {clen} bytes -> plen {plen} exceeds the "
            "one-byte frame-length field (max payload is 223 bytes)"
        )
    head = bytearray(32)
    head[0] = ftype
    struct.pack_into("<I", head, 1, ts)
    head[9] = plen
    head[11] = clen
    head[13] = msg13
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


# --- Parsing / media -----------------------------------------------------------------------


def decrypt_head(payload: bytes, key: bytes) -> bytes:
    """Decrypt the 64-byte encrypted head of a frame, returning the full plaintext frame.

    Everything after the first 64 bytes is already plaintext (H.264 Annex-B) and
    is passed through unchanged. Payloads shorter than 64 bytes are returned as is.
    """
    if len(payload) < MEDIA_HEAD_LEN:
        return payload
    return cbc_decrypt(payload[:MEDIA_HEAD_LEN], key) + payload[MEDIA_HEAD_LEN:]


def h264_is_decodable(buf: bytes) -> bool:
    """Return True if the buffer carries a parameter set (SPS) and a keyframe (IDR).

    Used to pick between decrypt candidates. Length is a misleading criterion: an
    undecrypted raw stream is always the longest one because it still carries the
    encrypted head of each media frame -- it scans as "H.264" but no decoder can
    use it.
    """
    kinds = set()
    p = buf.find(b"\x00\x00\x00\x01")
    while p >= 0:
        if p + 4 < len(buf):
            kinds.add(buf[p + 4] & 0x1F)
        p = buf.find(b"\x00\x00\x00\x01", p + 4)
    return 7 in kinds and 5 in kinds


def first_nal_offset(buf: bytes) -> int:
    """Return the offset of the first usable H.264 NAL start code, or -1."""
    for pattern in (
        b"\x00\x00\x00\x01\x67",
        b"\x00\x00\x00\x01\x27",  # SPS
        b"\x00\x00\x00\x01\x68",
        b"\x00\x00\x00\x01\x28",  # PPS
        b"\x00\x00\x00\x01\x65",
        b"\x00\x00\x00\x01\x25",  # IDR
    ):
        offset = buf.find(pattern)
        if offset >= 0:
            return offset
    return -1


def extract_h264(plain: bytes) -> bytes:
    """Return the decrypted stream from its first valid H.264 NAL unit onwards."""
    offset = first_nal_offset(plain)
    return plain[offset:] if offset >= 0 else b""


def decode_media(frames: Iterable[bytes], keys: Iterable[bytes]) -> bytes | None:
    """Decrypt captured media frames and return the best H.264 elementary stream.

    ``frames`` are complete media frames as delimited on the TCP stream, each
    starting at its AES-encrypted 64-byte head (there is no outer header to
    skip). Each candidate key is tried; the first stream containing SPS *and* IDR
    wins, NOT the longest one: a wrongly decrypted stream is usually the longest
    and still undecodable. Returns None if no candidate holds a decodable stream
    -- a clean "no frame" is better than handing ffmpeg the longest (most likely
    mis-decrypted) candidate.
    """
    frame_list = list(frames)
    candidates = []
    for key in dict.fromkeys(keys):  # skip duplicate keys
        plain = bytearray()
        for frame in frame_list:
            plain += decrypt_head(frame, key)
        stream = extract_h264(bytes(plain))
        if len(stream) > 500:
            candidates.append(stream)
    if not candidates:
        return None
    return next(
        (stream for stream in candidates if h264_is_decodable(stream)),
        None,
    )


# Historical alias of the upstream name.
_decode_media = decode_media
