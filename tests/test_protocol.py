"""Byte-exact tests of the application-layer codec (no sockets, no HA objects).

Vectors come from the TCP capture of the official app (``tests/fixtures``); the real
AES key is not part of the repository, so everything that needs a key uses a made-up
one and checks structure, lengths and round trips instead.
"""

from __future__ import annotations

import hashlib
import struct

import pytest
from conftest import (
    TEST_CLIENT_ID,
    TEST_DYNPW,
    TEST_KEY,
    TEST_OEM,
    TEST_PIN_SHA256,
    build_media_frame,
    make_h264_keyframe,
    make_h264_pframe,
    parse_ctrl_frame,
)

from custom_components.balter_evo2 import protocol as p

WRONG_KEY = b"w" * 32


# --- a9 setup body / echo ------------------------------------------------------------


def test_a9_body_video_is_a9_then_zeros() -> None:
    body = p.build_a9_body(0)
    assert body == bytes([0xA9]) + bytes(31)
    assert len(body) == 32


def test_a9_body_audio_sets_byte9() -> None:
    body = p.build_a9_body(1)
    assert len(body) == 32
    assert body[0] == 0xA9
    assert body[9] == 0x02
    assert body[:9] == bytes([0xA9]) + bytes(8)
    assert body[10:] == bytes(22)


def test_a9_body_matches_captured_handshake(handshake_client: bytes) -> None:
    """The capture starts with the raw plaintext a9 body, no wrapper."""
    assert len(handshake_client) == 1968
    assert handshake_client[:32] == p.build_a9_body(0)


def test_a9_echo_vector(a9_echo: bytes, station_head: bytes) -> None:
    assert len(a9_echo) == 32
    assert a9_echo[0] == 0xA9
    assert a9_echo[10] == 0x02
    assert a9_echo[11] == 0x01  # setup accepted
    assert station_head[:32] == a9_echo


# --- no UDP / KCP leftovers --------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "build_app_frame",
        "build_hello76",
        "build_transport_hdr",
        "inet_cksum",
        "build_punch",
        "build_mtu_probe",
        "build_natcheck",
        "parse_header",
        "split_app_frames",
        "extract_app_frames",
    ],
)
def test_udp_builders_are_gone(name: str) -> None:
    assert not hasattr(p, name)


def test_capture_has_no_udp_markers(handshake_client: bytes, station_head: bytes) -> None:
    for blob in (handshake_client, station_head):
        assert b"\xff\xff\xff\xff" not in blob
        assert b"\xc1\xef\xab\xff" not in blob


def test_constants() -> None:
    assert p.IV_ZERO == b"0" * 16
    assert len(p.FALLBACK_KEY) == 32
    assert hashlib.sha256(b"").hexdigest() == p.SHA256_OF_EMPTY
    assert p.CH0 != p.CH1


# --- AES ----------------------------------------------------------------------------------


def test_cbc_roundtrip_and_zero_iv_determinism() -> None:
    data = bytes(range(64))
    enc = p.cbc_encrypt(data, TEST_KEY)
    assert len(enc) == 64 and enc != data
    assert p.cbc_decrypt(enc, TEST_KEY) == data
    # zero IV -> identical ciphertext every time and for identical first blocks
    assert p.cbc_encrypt(data, TEST_KEY) == enc
    assert p.cbc_encrypt(data[:16], TEST_KEY) == enc[:16]


def test_cbc_partial_block_handling() -> None:
    assert p.cbc_encrypt(b"short", TEST_KEY) == b""
    assert len(p.cbc_encrypt(bytes(20), TEST_KEY)) == 16  # trailing partial dropped
    assert p.cbc_decrypt(b"short", TEST_KEY) == b"short"  # kept as is
    enc = p.cbc_encrypt(bytes(32), TEST_KEY)
    assert p.cbc_decrypt(enc + b"tail", TEST_KEY) == bytes(32) + b"tail"


def test_cbc_matches_reference_openssl_style_vector() -> None:
    """AES-256-CBC, IV '0'*16: first block of the all-zero plaintext is key dependent."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    expected = (
        Cipher(algorithms.AES(TEST_KEY), modes.CBC(b"0" * 16)).encryptor().update(bytes(16))
    )
    assert p.cbc_encrypt(bytes(16), TEST_KEY) == expected


def test_session_key() -> None:
    assert p.session_key("a" * 32) == b"a" * 32
    assert p.session_key(None) == p.FALLBACK_KEY
    assert p.session_key("") == p.FALLBACK_KEY


# --- control frames --------------------------------------------------------------------------


def test_keepalive_is_64_bytes_and_stable() -> None:
    ka = p.ctrl_frame(0x00, 0, b"", TEST_KEY)
    assert len(ka) == 64
    # "Identical on both connections": same key + zero IV + same head -> same bytes.
    assert ka == p.ctrl_frame(0x00, 0, b"", TEST_KEY)
    head = p.cbc_decrypt(ka[:32], TEST_KEY)
    assert head[0] == 0x00
    assert head[9] == 32  # plen = padded(0 + 32)
    assert head[11] == 0  # clen
    body = p.cbc_decrypt(ka[32:], TEST_KEY)
    assert body == hashlib.sha256(head).digest()  # trailer over head||payload(empty)
    assert b"\xff\xff\xff\xff" not in ka


def test_keepalive_differs_per_key() -> None:
    assert p.ctrl_frame(0, 0, b"", TEST_KEY) != p.ctrl_frame(0, 0, b"", WRONG_KEY)


def test_ctrl_frame_head_layout() -> None:
    payload = b"hello"
    frame = p.ctrl_frame(0x0B, 0x01020304, payload, TEST_KEY, msg13=7, b14=9, f15=1, f16=1, b17=3)
    head = p.cbc_decrypt(frame[:32], TEST_KEY)
    assert head[0] == 0x0B
    assert struct.unpack_from("<I", head, 1)[0] == 0x01020304
    assert head[9] == 48  # 5 + 32 -> padded to 48
    assert head[11] == 5
    assert head[13] == 7
    assert head[14] == 9
    assert head[15] == 1 and head[16] == 1
    assert head[17] == 3


@pytest.mark.parametrize("plen", [0, 1, 15, 16, 17, 100, 144, 200])
def test_ctrl_frame_length_is_32_plus_plen(plen: int) -> None:
    frame = p.ctrl_frame(0xFE, 0, bytes(plen), TEST_KEY, msg13=4)
    head = p.cbc_decrypt(frame[:32], TEST_KEY)
    assert len(frame) == 32 + head[9]
    assert head[9] % 16 == 0
    assert head[9] >= plen + 32
    parsed = parse_ctrl_frame(frame, TEST_KEY)  # also verifies the SHA-256 trailer
    assert parsed is not None
    ftype, msg13, payload, total = parsed
    assert (ftype, msg13, payload, total) == (0xFE, 4, bytes(plen), len(frame))


def test_login_payload_exact() -> None:
    payload = p.build_login_payload("PW", "abcdef0123456789", "OEM")
    assert payload == b"adminapp&&PW\x00OEM\x00clientid=abcdef0123456789\x00"


def test_login_frame_is_208_bytes_for_96_char_password() -> None:
    """Capture: LOGIN is 208 B = 32 + 176 for a ~96 character dynamic password."""
    payload = p.build_login_payload(TEST_DYNPW, TEST_CLIENT_ID, TEST_OEM)
    assert len(payload) == 144
    frame = p.ctrl_frame(0x01, 0, payload, TEST_KEY, msg13=1, f15=1, f16=1)
    assert len(frame) == 208
    head = p.cbc_decrypt(frame[:32], TEST_KEY)
    assert head[0] == 0x01
    assert head[9] == 176
    assert head[11] == 144
    assert head[13] == 1 and head[15] == 1 and head[16] == 1
    parsed = parse_ctrl_frame(frame, TEST_KEY)
    assert parsed is not None
    assert parsed[2] == payload
    assert payload.startswith(b"adminapp&&" + TEST_DYNPW.encode())
    assert payload.endswith(b"\x00clientid=" + TEST_CLIENT_ID.encode() + b"\x00")


def test_default_oem_matches_const() -> None:
    from custom_components.balter_evo2.const import OEM_ID_COMPACT

    assert p.DEFAULT_OEM == OEM_ID_COMPACT == "G0028G0126"
    assert p.build_login_payload("x", "y").split(b"\x00")[1] == b"G0028G0126"


def test_open_payload_layout() -> None:
    payload = p.build_open_payload(2, 3, TEST_PIN_SHA256)
    assert len(payload) == 16 + 64
    assert payload[0] == 2
    assert payload[2] == 3
    assert payload[3] == 1
    assert payload[16:] == TEST_PIN_SHA256.encode("ascii")
    frame = p.ctrl_frame(0xFE, 0, payload, TEST_KEY, msg13=4)
    assert parse_ctrl_frame(frame, TEST_KEY)[:3] == (0xFE, 4, payload)  # type: ignore[index]


# --- capture ciphertext properties (no key needed) -----------------------------------------------


def test_capture_contains_repeating_keepalive_ciphertext(handshake_client: bytes) -> None:
    """A constant keepalive under a zero IV repeats byte for byte in the capture."""
    body = handshake_client[32:]
    blocks: dict[bytes, int] = {}
    repeated = False
    for off in range(0, len(body) - 63, 16):
        chunk = body[off : off + 64]
        if chunk in blocks and off - blocks[chunk] >= 64:
            repeated = True
            break
        blocks.setdefault(chunk, off)
    assert repeated


# --- decrypt_head ------------------------------------------------------------------------------------


def test_decrypt_head_roundtrip() -> None:
    plain_head = bytes([0xA0]) + bytes(range(1, 64))
    tail = b"\x00\x00\x00\x01\x65" + b"x" * 100
    wire = p.cbc_encrypt(plain_head, TEST_KEY) + tail
    assert p.decrypt_head(wire, TEST_KEY) == plain_head + tail


def test_decrypt_head_short_passthrough() -> None:
    assert p.decrypt_head(b"x" * 63, TEST_KEY) == b"x" * 63
    assert p.decrypt_head(b"", TEST_KEY) == b""


def test_decrypt_head_media_frame() -> None:
    body = make_h264_keyframe()
    frame = build_media_frame(TEST_KEY, body, ts=5)
    plain = p.decrypt_head(frame, TEST_KEY)
    assert plain[0] == 0xA0
    assert plain[9] == 0x20
    assert struct.unpack_from("<HH", plain, 0x30) == (352, 280)
    assert plain[64 : 64 + len(body)] == body


# --- H.264 helpers ----------------------------------------------------------------------------------------


def test_h264_is_decodable() -> None:
    assert p.h264_is_decodable(make_h264_keyframe())
    assert not p.h264_is_decodable(b"\x00\x00\x00\x01\x41" + b"x" * 50)  # P frame only
    assert not p.h264_is_decodable(b"\x00\x00\x00\x01\x67abc")  # SPS but no IDR
    assert not p.h264_is_decodable(b"")


def test_first_nal_offset_and_extract() -> None:
    kf = make_h264_keyframe()
    assert p.first_nal_offset(b"junk" + kf) == 4
    assert p.first_nal_offset(b"nothing here") == -1
    assert p.extract_h264(b"junk" + kf) == kf
    assert p.extract_h264(b"no nal") == b""


def test_decode_media_picks_decodable_candidate_not_longest() -> None:
    kf = make_h264_keyframe()
    frames = [build_media_frame(TEST_KEY, kf, ts=1), build_media_frame(TEST_KEY, make_h264_pframe(), ts=2)]
    expected = p.extract_h264(b"".join(p.decrypt_head(f, TEST_KEY) for f in frames))
    stream = p.decode_media(frames, [TEST_KEY, WRONG_KEY, TEST_KEY])  # duplicates tolerated
    assert stream == expected
    assert p.h264_is_decodable(stream)
    assert stream.startswith(b"\x00\x00\x00\x01\x67")
    # The first candidate that is decodable wins, not the longest one.
    assert p.decode_media(frames, [TEST_KEY]) == expected
    assert p._decode_media is p.decode_media


def test_decode_media_none_without_h264() -> None:
    assert p.decode_media([b"\x01" * 200], [TEST_KEY]) is None
    assert p.decode_media([], [TEST_KEY]) is None
