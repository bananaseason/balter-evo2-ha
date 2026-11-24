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
    build_head,
    build_media_packet,
    make_audio_chunk,
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


def test_capture_has_no_udp_markers(
    handshake_client: bytes, station_head: bytes
) -> None:
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
        Cipher(algorithms.AES(TEST_KEY), modes.CBC(b"0" * 16))
        .encryptor()
        .update(bytes(16))
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
    frame = p.ctrl_frame(
        0x0B, 0x01020304, payload, TEST_KEY, msg13=7, b14=9, f15=1, f16=1, b17=3
    )
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
    assert payload[0] == 3  # lock number
    assert payload[2] == 2  # door station
    assert payload[3] == 1
    assert payload[16:] == TEST_PIN_SHA256.encode("ascii")
    frame = p.ctrl_frame(0xFE, 0, payload, TEST_KEY, msg13=4)
    assert parse_ctrl_frame(frame, TEST_KEY)[:3] == (0xFE, 4, payload)  # type: ignore[index]


def test_open_payload_of_the_second_lock_is_what_the_phone_app_sends() -> None:
    """Captured from the app on an EVO 2: its second button, door PIN 0000."""
    pin = "9af15b336e6a9619928537df30b2e6a2376569fcf9d7e773eccede65606529a0"
    captured = bytes.fromhex("02000101" + "00" * 12) + pin.encode("ascii")
    assert p.build_open_payload(1, 2, pin) == captured
    assert p.build_open_payload(1, 1, pin)[:4] == bytes.fromhex("01000101")


# --- capture ciphertext properties (no key needed) -----------------------------------------------


def test_capture_contains_repeating_keepalive_ciphertext(
    handshake_client: bytes,
) -> None:
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


# --- removed helpers ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "decrypt_head",
        "first_nal_offset",
        "extract_h264",
        "decode_media",
        "_decode_media",
        "h264_is_decodable",
        "MEDIA_HEAD_LEN",
    ],
)
def test_old_media_helpers_are_gone(name: str) -> None:
    assert not hasattr(p, name)


# --- control frames: 16-bit lengths -------------------------------------------------------------------------


def _decrypted_head(frame: bytes) -> bytes:
    return p.cbc_decrypt(frame[:32], TEST_KEY)


@pytest.mark.parametrize("size", [0, 1, 200, 223, 224, 800, 4000])
def test_ctrl_frame_roundtrips_through_parse_head_and_control_payload(
    size: int,
) -> None:
    payload = bytes((i * 7 + 3) % 256 for i in range(size))
    frame = p.ctrl_frame(0xFE, 0x01020304, payload, TEST_KEY, msg13=18)
    head = p.parse_head(_decrypted_head(frame))
    assert head is not None
    assert head.ftype == 0xFE
    assert head.msg13 == 18
    assert head.content_len == size
    assert not head.is_media
    # padded payload + 32-byte SHA-256 trailer, block aligned
    assert head.encrypted_len == (size + 32 + 15) // 16 * 16
    assert head.body_len == head.encrypted_len
    assert len(frame) == 32 + head.body_len
    body = p.cbc_decrypt(frame[32:], TEST_KEY)
    assert p.control_payload(head, body) == payload
    head_plain = _decrypted_head(frame)
    assert body[size : size + 32] == hashlib.sha256(head_plain + payload).digest()
    assert not any(body[size + 32 :])  # zero padding
    # and the conftest parser agrees
    assert parse_ctrl_frame(frame, TEST_KEY) == (0xFE, 18, payload, len(frame))


def test_ctrl_frame_length_fields_are_16_bit_little_endian() -> None:
    frame = p.ctrl_frame(0xFE, 0, bytes(800), TEST_KEY, msg13=18)
    head = _decrypted_head(frame)
    assert (
        struct.unpack_from("<H", head, 9)[0] == 832
    )  # 800 + 32 = 832, already aligned
    assert struct.unpack_from("<H", head, 11)[0] == 800
    assert head[13] == 18
    assert not any(head[17:32])  # the head's tail stays zero


def test_ctrl_frame_largest_legal_payload_and_overflow() -> None:
    biggest = p.MAX_CTRL_BODY - 32
    frame = p.ctrl_frame(0xFE, 0, bytes(biggest), TEST_KEY, msg13=1)
    head = p.parse_head(_decrypted_head(frame))
    assert head is not None and head.content_len == biggest
    with pytest.raises(ValueError):
        p.ctrl_frame(0xFE, 0, bytes(biggest + 1), TEST_KEY)


def test_control_payload_clamps_to_body() -> None:
    head = p.FrameHead(0x01, 48, 5000, 0)  # LOGIN answers carry a status word here
    assert p.control_payload(head, bytes(range(48))) == bytes(range(16))
    assert p.control_payload(head, b"") == b""
    assert p.control_payload(head, bytes(10)) == b""


# --- parse_head -----------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("ftype", [0x00, 0x01, 0x07, 0xFE])
def test_parse_head_accepts_every_control_type(ftype: int) -> None:
    head = p.parse_head(bytes(build_head(ftype, 48, 7, msg13=9)))
    assert head == p.FrameHead(ftype, 48, 7, 9)
    assert head.body_len == 48


def test_parse_head_media() -> None:
    head = p.parse_head(bytes(build_head(0xA0, 32, 70000)))
    assert head == p.FrameHead(0xA0, 32, 70000, 0)
    assert head.is_media
    assert head.body_len == 70000  # a media frame is content_len bytes long on the wire


def test_parse_head_media_without_encrypted_part() -> None:
    head = p.parse_head(bytes(build_head(0xA0, 0, 20)))
    assert head is not None and head.body_len == 20


def test_parse_head_ignores_bytes_after_32() -> None:
    raw = bytes(build_head(0xFE, 32, 0, msg13=8)) + b"\xff" * 10
    assert p.parse_head(raw) == p.FrameHead(0xFE, 32, 0, 8)


@pytest.mark.parametrize("ftype", [0x02, 0x42, 0x80, 0xA1, 0xFF, 0xE1])
def test_parse_head_accepts_an_unknown_type_as_a_control_frame(ftype: int) -> None:
    """The type byte is not checked: such a frame is skipped by its lengths."""
    assert ftype not in p.KNOWN_FTYPES
    head = p.parse_head(bytes(build_head(ftype, 64, 33, msg13=5)))
    assert head == p.FrameHead(ftype, 64, 33, 5)
    assert not head.is_media
    assert head.body_len == 64


def test_known_ftypes() -> None:
    assert p.KNOWN_FTYPES == {0x00, 0x01, 0x07, 0xA0, 0xFE, 0x0B, 0x0C, 0x0D, 0xA2}


@pytest.mark.parametrize("pos", [5, 6, 7, 8])
@pytest.mark.parametrize("ftype", [0xFE, 0xA0, 0x42])
def test_parse_head_rejects_nonzero_bytes_5_to_8(ftype: int, pos: int) -> None:
    head = build_head(ftype, 32, 100)
    head[pos] = 1
    assert p.parse_head(bytes(head)) is None


@pytest.mark.parametrize("pos", [17, 18, 24, 31])
@pytest.mark.parametrize("ftype", [0xFE, 0xA0])
def test_parse_head_rejects_nonzero_tail(ftype: int, pos: int) -> None:
    head = build_head(ftype, 32, 100)
    head[pos] = 1
    assert p.parse_head(bytes(head)) is None


@pytest.mark.parametrize("enc", [1, 17, 33, 47])
def test_parse_head_rejects_unaligned_encrypted_len_control(enc: int) -> None:
    assert p.parse_head(bytes(build_head(0xFE, enc, 0))) is None


@pytest.mark.parametrize("enc", [1, 15, 17, 33])
def test_parse_head_rejects_unaligned_encrypted_len_media(enc: int) -> None:
    assert p.parse_head(bytes(build_head(0xA0, enc, 100))) is None


@pytest.mark.parametrize("content", [0, 1, 19])
def test_parse_head_rejects_media_shorter_than_packet_header(content: int) -> None:
    assert p.parse_head(bytes(build_head(0xA0, 0, content))) is None


def test_parse_head_rejects_media_content_shorter_than_encrypted_len() -> None:
    assert p.parse_head(bytes(build_head(0xA0, 48, 32))) is None
    assert p.parse_head(bytes(build_head(0xA0, 32, 32))) is not None  # equal is fine


def test_parse_head_rejects_oversized_media() -> None:
    assert p.parse_head(bytes(build_head(0xA0, 32, p.MAX_MEDIA_PAYLOAD + 1))) is None
    assert p.parse_head(bytes(build_head(0xA0, 32, p.MAX_MEDIA_PAYLOAD))) is not None


@pytest.mark.parametrize("enc", [0, 16])
def test_parse_head_rejects_control_body_too_short_for_the_trailer(enc: int) -> None:
    assert p.parse_head(bytes(build_head(0xFE, enc, 0))) is None


def test_parse_head_rejects_short_input() -> None:
    assert p.parse_head(b"") is None
    assert p.parse_head(bytes(build_head(0xFE, 32, 0))[:31]) is None


def test_parse_head_rejects_a_wrongly_decrypted_head() -> None:
    frame = p.ctrl_frame(0xFE, 0, b"hello", TEST_KEY, msg13=4)
    assert p.parse_head(p.cbc_decrypt(frame[:32], TEST_KEY)) is not None
    assert p.parse_head(p.cbc_decrypt(frame[:32], WRONG_KEY)) is None


# --- parse_media ------------------------------------------------------------------------------------------------------


def test_parse_media_keyframe() -> None:
    data = make_h264_keyframe()
    packet = p.parse_media(
        build_media_packet(
            p.MEDIA_KEYFRAME, data, seconds=1000, millis=250, width=768, height=432
        )
    )
    assert packet == p.MediaPacket(p.MEDIA_KEYFRAME, 1000.25, 768, 432, data)
    assert packet.is_video and packet.is_keyframe


def test_parse_media_delta_frame() -> None:
    data = make_h264_pframe()
    packet = p.parse_media(
        build_media_packet(
            p.MEDIA_VIDEO, data, seconds=5, millis=999, width=352, height=288
        )
    )
    assert packet == p.MediaPacket(p.MEDIA_VIDEO, 5.999, 352, 288, data)
    assert packet.is_video and not packet.is_keyframe


def test_parse_media_audio() -> None:
    data = make_audio_chunk()
    packet = p.parse_media(
        build_media_packet(p.MEDIA_AUDIO, data, seconds=7, millis=40)
    )
    assert packet == p.MediaPacket(p.MEDIA_AUDIO, 7.04, 0, 0, data)
    assert not packet.is_video and not packet.is_keyframe


def test_media_kinds() -> None:
    assert (p.MEDIA_VIDEO, p.MEDIA_KEYFRAME, p.MEDIA_AUDIO) == (0xE0, 0xE1, 0xE3)


def test_parse_media_header_layout_is_byte_exact() -> None:
    raw = build_media_packet(p.MEDIA_AUDIO, b"AB", seconds=1, millis=2)
    assert raw == (
        b"\x00\x00\x01\xe3"  # start code + kind
        b"\x02\x00\x00\x00"  # data length
        b"\x01\x00\x00\x00"  # seconds
        b"\x02\x00"  # millis
        b"\x04\x01\x40\x1f\x00\x00"  # audio codec bytes
        b"AB"
    )
    video = build_media_packet(p.MEDIA_KEYFRAME, b"", width=768, height=432)
    assert video[14:20] == b"\x01\x64" + struct.pack("<HH", 768, 432)


def test_parse_media_ignores_trailing_bytes() -> None:
    raw = build_media_packet(p.MEDIA_VIDEO, b"abc") + b"\x00" * 7
    packet = p.parse_media(raw)
    assert packet is not None and packet.data == b"abc"


def test_parse_media_truncated_is_none() -> None:
    raw = build_media_packet(p.MEDIA_KEYFRAME, make_h264_keyframe())
    assert p.parse_media(raw) is not None
    assert p.parse_media(raw[:-1]) is None  # one data byte missing
    assert p.parse_media(raw[:25]) is None
    assert p.parse_media(raw[:19]) is None  # shorter than the header
    assert p.parse_media(b"") is None


def test_parse_media_rejects_bad_start_code() -> None:
    raw = bytearray(build_media_packet(p.MEDIA_VIDEO, b"abc"))
    raw[2] = 0x02
    assert p.parse_media(bytes(raw)) is None


# --- video_stream -----------------------------------------------------------------------------------------------------------


def _pkt(kind: int, data: bytes) -> p.MediaPacket:
    return p.MediaPacket(kind, 0.0, 0 if kind == p.MEDIA_AUDIO else 768, 0, data)


def test_video_stream_starts_at_first_keyframe_and_skips_audio() -> None:
    packets = [
        _pkt(p.MEDIA_VIDEO, b"d0"),  # leading delta frames are dropped
        _pkt(p.MEDIA_AUDIO, b"a0"),
        _pkt(p.MEDIA_VIDEO, b"d1"),
        _pkt(p.MEDIA_KEYFRAME, b"K1"),
        _pkt(p.MEDIA_AUDIO, b"a1"),
        _pkt(p.MEDIA_VIDEO, b"d2"),
        _pkt(p.MEDIA_AUDIO, b"a2"),
        _pkt(p.MEDIA_KEYFRAME, b"K2"),  # later keyframes are kept
        _pkt(p.MEDIA_VIDEO, b"d3"),
    ]
    assert p.video_stream(packets) == b"K1d2K2d3"


def test_video_stream_without_keyframe_is_empty() -> None:
    assert p.video_stream([_pkt(p.MEDIA_VIDEO, b"d"), _pkt(p.MEDIA_AUDIO, b"a")]) == b""
    assert p.video_stream([]) == b""


def test_video_stream_accepts_an_iterator() -> None:
    assert (
        p.video_stream(iter([_pkt(p.MEDIA_KEYFRAME, b"K"), _pkt(p.MEDIA_VIDEO, b"d")]))
        == b"Kd"
    )


# --- audio channel / talk-back (reference/tools/talk_spike.py) ------------------------
#
# The builders below are copied verbatim (re-indented) from the probe that talked to
# a Balter EVO 2 live on 2026-11-24; the integration's builders must reproduce their
# bytes exactly. ``P`` stands for the protocol module, ``key`` for the station key.


def _spike_head(ftype, ts, enc, clen16=None, clen32=None, msg13=0, b14=0, b15=0, b16=0):
    h = bytearray(32)
    h[0] = ftype
    struct.pack_into("<I", h, 1, ts)
    struct.pack_into("<H", h, 9, enc)
    if clen32 is not None:
        struct.pack_into("<I", h, 11, clen32)
    else:
        struct.pack_into("<H", h, 11, clen16)
        h[13] = msg13
        h[14] = b14
        h[15] = b15
        h[16] = b16
    return bytes(h)


def _spike_empty_frame(ftype, ts, msg13, b15=0, b16=0, key=TEST_KEY):
    h = _spike_head(ftype, ts, 32, clen16=0xFFFF, msg13=msg13, b15=b15, b16=b16)
    return p.cbc_encrypt(h, key) + p.cbc_encrypt(hashlib.sha256(h).digest(), key)


def _spike_talk_frame(ts, alaw, key=TEST_KEY):
    pl = b"\x00\x00\x01\xf0\x0e\x02" + struct.pack("<H", len(alaw)) + alaw
    h = _spike_head(0xA2, ts, 32, clen32=len(pl))
    return p.cbc_encrypt(h, key) + p.cbc_encrypt(pl[:32], key) + pl[32:]


def test_audio_channel_setup_body_selects_the_audio_stream() -> None:
    body = p.build_a9_body(1)
    assert body[0] == 0xA9 and body[9] == 0x02
    assert body[:9] == b"\xa9" + bytes(8) and not any(body[10:])


def test_audio_login_matches_the_spike() -> None:
    login = p.build_login_payload(TEST_DYNPW, TEST_CLIENT_ID)
    spike = p.ctrl_frame(0x0B, 1, login, TEST_KEY, msg13=0xFF, b14=0xFF)
    ours = p.audio_login_frame(1, TEST_DYNPW, TEST_CLIENT_ID, TEST_OEM, TEST_KEY)
    assert ours == spike
    head = p.cbc_decrypt(ours[:32], TEST_KEY)
    assert head[0] == 0x0B and head[13] == 0xFF and head[14] == 0xFF
    ftype, msg13, payload, total = parse_ctrl_frame(ours, TEST_KEY)
    assert (ftype, msg13, payload, total) == (0x0B, 0xFF, login, len(ours))


def test_audio_format_and_idle_frames_match_the_spike() -> None:
    assert p.audio_format_frame(2, TEST_KEY) == _spike_empty_frame(
        0x0C, 2, 1, b15=0x40, b16=0x1F
    )
    assert p.talk_state_frame(2, False, TEST_KEY) == _spike_empty_frame(0x0D, 2, 1)


def test_talk_start_and_stop_match_the_spike() -> None:
    assert p.talk_state_frame(3, True, TEST_KEY) == _spike_empty_frame(0x0D, 3, 0)
    assert p.talk_state_frame(200, False, TEST_KEY) == _spike_empty_frame(0x0D, 200, 1)


def test_empty_frame_layout() -> None:
    frame = p.empty_frame(0x0C, 7, 1, TEST_KEY, b15=0x40, b16=0x1F)
    assert len(frame) == 64
    head = p.cbc_decrypt(frame[:32], TEST_KEY)
    assert head[0] == 0x0C
    assert struct.unpack_from("<I", head, 1)[0] == 7
    assert struct.unpack_from("<H", head, 9)[0] == 32  # encrypted bytes after the head
    assert struct.unpack_from("<H", head, 11)[0] == 0xFFFF  # "no payload"
    assert head[13] == 1 and head[15:17] == b"\x40\x1f"  # 8000 Hz
    assert struct.unpack_from("<H", head, 15)[0] == p.TALK_SAMPLE_RATE == 8000
    assert p.cbc_decrypt(frame[32:], TEST_KEY) == hashlib.sha256(head).digest()


@pytest.mark.parametrize("ts", [4, 5, 123, 0xFFFFFFFF])
def test_talk_frame_matches_the_spike(ts: int) -> None:
    silence = b"\xd5" * 320
    assert p.talk_frame(ts, silence, TEST_KEY) == _spike_talk_frame(ts, silence)
    voice = make_audio_chunk(ts % 251, 320)
    assert p.talk_frame(ts, voice, TEST_KEY) == _spike_talk_frame(ts, voice)


def test_talk_frame_layout() -> None:
    alaw = make_audio_chunk(9, p.TALK_FRAME_BYTES)
    frame = p.talk_frame(4, alaw, TEST_KEY)
    assert len(frame) == 32 + 8 + 320
    head = p.cbc_decrypt(frame[:32], TEST_KEY)
    assert head[0] == p.FTYPE_TALK_AUDIO == 0xA2
    assert struct.unpack_from("<H", head, 9)[0] == 32
    assert struct.unpack_from("<I", head, 11)[0] == 328
    payload = p.cbc_decrypt(frame[32:64], TEST_KEY) + frame[64:]
    assert payload[:6] == b"\x00\x00\x01\xf0\x0e\x02"
    assert struct.unpack_from("<H", payload, 6)[0] == 320
    assert payload[8:] == alaw
    assert frame[64:] == alaw[24:]  # only the first 32 payload bytes are encrypted
    # The strict stream parser walks it like a media frame (u32 length).
    parsed = p.parse_head(head)
    assert parsed is not None and parsed.body_len == 328 and not parsed.is_media


def test_talk_frame_refuses_audio_shorter_than_one_block() -> None:
    with pytest.raises(ValueError):
        p.talk_frame(1, b"\xd5" * 10, TEST_KEY)


def test_audio_channel_head_parser() -> None:
    answer = p.cbc_decrypt(_spike_empty_frame(0x0D, 9, 0)[:32], TEST_KEY)
    parsed = p.parse_audio_channel_head(answer)
    assert parsed == p.AudioChannelHead(0x0D, 0, 0xFFFF, 32)
    talk = p.cbc_decrypt(p.talk_frame(1, b"\xd5" * 320, TEST_KEY)[:32], TEST_KEY)
    assert p.parse_audio_channel_head(talk) == p.AudioChannelHead(0xA2, 0, 328, 328)
    # Flag bytes of unknown meaning do not matter here (the strict parser refuses).
    flagged = bytearray(answer)
    flagged[20] = 0x55
    assert p.parse_head(bytes(flagged)) is None
    assert p.parse_audio_channel_head(bytes(flagged)) is not None
    bad = bytearray(answer)
    struct.pack_into("<H", bad, 9, 33)  # not block aligned
    assert p.parse_audio_channel_head(bytes(bad)) is None
    assert p.parse_audio_channel_head(b"\x00" * 10) is None
