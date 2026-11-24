"""Tests of ``TcpStationTransport`` against a loopback fake station.

The fake station (see ``conftest.FakeStation``) is a real TCP server on 127.0.0.1,
so the blocking transport is exercised exactly as against hardware: raw a9 body ->
raw a9 echo -> raw LOGIN -> the ~830-byte profile -> ready marker -> interleaved
media / heartbeats. The AES key is made up; nothing here needs a live station.

The receive framing itself (``_process_buffer`` / ``_resync``) is tested twice: by
feeding bytes straight into an unconnected transport (deterministic chunking) and
over a real socket (the fake station can dribble out one byte at a time).
"""

from __future__ import annotations

import socket
import time
from collections.abc import Callable

import pytest
from conftest import (
    HEARTBEAT_MSG13,
    OPEN_MSG13,
    PROFILE_LEN,
    PROFILE_MSG13,
    READY_MSG13,
    TEST_CLIENT_ID,
    TEST_DUID,
    TEST_DYNPW,
    TEST_KEY,
    TEST_KEY_STR,
    TEST_OEM,
    TEST_PIN_SHA256,
    FakeStation,
    audio_frame,
    control_frame,
    heartbeat_frame,
    make_audio_chunk,
    make_h264_keyframe,
    make_h264_pframe,
    make_profile_json,
    parse_ctrl_frame,
    profile_frame,
    video_frame,
)

from custom_components.balter_evo2 import protocol
from custom_components.balter_evo2 import transport as tr
from custom_components.balter_evo2.protocol import MediaPacket
from custom_components.balter_evo2.transport import (
    DoorRejectedError,
    SessionClosedError,
    StationBusyError,
    StationSilentError,
    TcpStationTransport,
    TransportError,
)

# These tests drive the real blocking transport against a loopback FakeStation,
# so they need actual sockets, which pytest-socket (bundled with phcc) blocks by
# default; ``socket_enabled`` re-enables them for the duration of each test.
pytestmark = pytest.mark.usefixtures("socket_enabled")


def make_transport(port: int, **kwargs: object) -> TcpStationTransport:
    return TcpStationTransport(
        "127.0.0.1",
        port,
        TEST_DUID,
        TEST_DYNPW,
        TEST_KEY_STR,
        TEST_CLIENT_ID,
        TEST_OEM,
        **kwargs,
    )


def run_for(
    t: TcpStationTransport, seconds: float, until: Callable[[], bool] | None = None
) -> None:
    t.run_until(time.monotonic() + seconds, until)


# --- a scripted stream and what must come out of it -----------------------------------------------------------


def _expected(kind: int, ts: int, data: bytes, *, millis: int = 0) -> MediaPacket:
    video = kind != protocol.MEDIA_AUDIO
    return MediaPacket(
        kind,
        1_700_000_000 + ts + millis / 1000.0,
        768 if video else 0,
        432 if video else 0,
        data,
    )


def build_script() -> tuple[list[bytes], list[MediaPacket], list[tuple[int, int]]]:
    """Return ``(wire frames, expected packets, expected control acks)``.

    control, 830-byte profile, ready, keyframe, audio, delta, heartbeat, delta,
    audio, delta -- every kind of frame the real station interleaves.
    """
    key = TEST_KEY
    kf, d1, d2, d3 = (
        make_h264_keyframe(1),
        make_h264_pframe(1),
        make_h264_pframe(2),
        make_h264_pframe(3),
    )
    a1, a2 = make_audio_chunk(1), make_audio_chunk(2)
    frames = [
        control_frame(key, 5),
        profile_frame(key),
        control_frame(key, READY_MSG13, b"\x00\x01"),
        video_frame(key, kf, keyframe=True, ts=0),
        audio_frame(key, a1, ts=1),
        video_frame(key, d1, keyframe=False, ts=1),
        heartbeat_frame(key),
        video_frame(key, d2, keyframe=False, ts=2),
        audio_frame(key, a2, ts=3),
        video_frame(key, d3, keyframe=False, ts=3),
    ]
    packets = [
        _expected(protocol.MEDIA_KEYFRAME, 0, kf),
        _expected(protocol.MEDIA_AUDIO, 1, a1, millis=20),
        _expected(protocol.MEDIA_VIDEO, 1, d1),
        _expected(protocol.MEDIA_VIDEO, 2, d2),
        _expected(protocol.MEDIA_AUDIO, 3, a2, millis=20),
        _expected(protocol.MEDIA_VIDEO, 3, d3),
    ]
    # The heartbeat (msg13=8) is not recorded as an ack candidate.
    acks = [(0xFE, 5), (0xFE, PROFILE_MSG13), (0xFE, READY_MSG13)]
    return frames, packets, acks


def idle_transport() -> tuple[TcpStationTransport, list[MediaPacket]]:
    """An unconnected transport whose receive buffer the test fills by hand."""
    t = make_transport(0)
    got: list[MediaPacket] = []
    t.set_media_sink(got.append)
    return t, got


def feed(t: TcpStationTransport, data: bytes) -> None:
    t._buf += data
    t._process_buffer()


# --- exceptions ---------------------------------------------------------------------------


def test_exception_hierarchy() -> None:
    assert issubclass(StationSilentError, TransportError)
    assert issubclass(StationBusyError, TransportError)
    assert issubclass(SessionClosedError, TransportError)
    assert issubclass(DoorRejectedError, TransportError)
    assert issubclass(TransportError, Exception)


def test_old_media_length_machinery_is_gone() -> None:
    for name in (
        "MediaLengthResolver",
        "MAX_MEDIA_FRAME",
        "MAX_CTRL_FRAME",
        "MEDIA_LEN_AUTO",
    ):
        assert not hasattr(tr, name)
    with pytest.raises(TypeError):
        make_transport(0, media_len_offset=3)
    with pytest.raises(TypeError):
        make_transport(0, enable_audio=True)


# --- handshake -------------------------------------------------------------------------------


def test_handshake_login_then_ready(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    station = fake_station_factory(media=[])
    with make_transport(station.port) as t:
        assert t.connect(5.0) is True
        assert t.wait(t.device_ready, 5.0)
        assert t.logged_in.is_set()
        assert t.device_ready.is_set()
        assert not t.media_started.is_set()  # no video was sent
        assert t.station_silent is False
        assert isinstance(t.handshake_states(), str)
        assert t._resyncs == 0  # the 830-byte profile was walked without a resync

    # First stream bytes are the raw plaintext a9 body, no wrapper.
    assert station.a9_body == protocol.build_a9_body(0)
    assert station.raw_stream[:32] == protocol.build_a9_body(0)
    assert b"\xff\xff\xff\xff" not in bytes(station.raw_stream)
    assert b"\xc1\xef\xab\xff" not in bytes(station.raw_stream)

    # LOGIN: raw ctrl_frame, 208 B for a ~96 char dynamic password.
    assert station.wait_for(lambda: bool(station.received(0x01)))
    ftype, msg13, payload, raw = station.received(0x01)[0]
    assert (ftype, msg13) == (0x01, 1)
    assert len(raw) == 208
    assert payload == protocol.build_login_payload(TEST_DYNPW, TEST_CLIENT_ID, TEST_OEM)
    assert station.raw_stream[32 : 32 + 208] == raw


def test_audio_socket_is_off_by_default(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    station = fake_station_factory()
    with make_transport(station.port) as t:
        assert t.connect(5.0)
        t.wait(t.device_ready, 5.0)
    assert station.connections == 1
    assert station.a9_body is not None and station.a9_body[9] == 0  # video, not audio


def test_silent_station_sets_station_silent(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    """No a9 echo within the timeout -> connect() returns False with station_silent."""
    station = fake_station_factory(send_echo=False)
    t = make_transport(station.port)
    try:
        assert t.connect(0.6) is False
        assert t.station_silent is True
        assert not t.device_ready.is_set()
    finally:
        t.close()


def test_refused_connection_is_silent() -> None:
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nobody listens here now
    t = make_transport(port)
    try:
        assert t.connect(1.0) is False
        assert t.station_silent is True
    finally:
        t.close()


def test_ready_not_set_without_marker_but_login_is(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    station = fake_station_factory(send_ready=False)
    with make_transport(station.port) as t:
        t.connect(5.0)
        assert t.wait(t.logged_in, 5.0)  # the profile frame proves the login
        assert t.wait(t.device_ready, 0.5) is False
        assert not t.media_started.is_set()


def test_stream_volume_is_proof_of_ready(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    """No ready marker, but more than STREAM_IS_PROOF media bytes -> device_ready."""
    big = video_frame(TEST_KEY, b"\x00\x00\x00\x01\x65" + bytes(5000), keyframe=True)
    station = fake_station_factory(send_ready=False, media=[big])
    with make_transport(station.port) as t:
        t.connect(5.0)
        assert t.wait(t.media_started, 5.0)
        assert t.wait(t.device_ready, 5.0)
        assert t._resyncs == 0


# --- session setup + keepalive --------------------------------------------------------------------


def test_session_setup_sends_small_0xfe_frames(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    station = fake_station_factory()
    with make_transport(station.port) as t:
        t.connect(5.0)
        t.wait(t.device_ready, 5.0)
        t.send_session_setup()
        assert station.wait_for(lambda: len(station.received(0xFE)) >= 3)
    assert [f[1] for f in station.received(0xFE)] == [5, 6, 2]
    for _f, _m, _payload, raw in station.received(0xFE):
        assert len(raw) < 208  # small frames, not another LOGIN


def test_keepalives_are_sent_on_interval(
    fake_station_factory: Callable[..., FakeStation], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tr, "KEEPALIVE_INTERVAL", 0.2)
    station = fake_station_factory()
    with make_transport(station.port) as t:
        t.connect(5.0)
        t.wait(t.device_ready, 5.0)
        run_for(t, 1.0)
    keepalives = station.received(0x00)
    assert len(keepalives) >= 2
    expected = protocol.ctrl_frame(0x00, 0, b"", TEST_KEY)
    for _f, _m, payload, raw in keepalives:
        assert len(raw) == 64
        assert payload == b""
        assert raw == expected  # identical ciphertext every time (zero IV)


def test_station_keepalives_and_heartbeats_are_consumed(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    frames, packets, _ = build_script()
    station = fake_station_factory(
        keepalive_every=0.05, heartbeat_every=0.05, media=frames
    )
    got: list[MediaPacket] = []
    with make_transport(station.port) as t:
        t.set_media_sink(got.append)
        t.connect(5.0)
        run_for(t, 3.0, lambda: len(got) >= len(packets))
        time.sleep(0.3)  # let a few keepalives/heartbeats land after the media
        assert t.station_silent is False
        assert t._resyncs == 0
    assert got == packets


# --- RX framing: fed by hand ---------------------------------------------------------------------------


def test_whole_stream_in_one_feed() -> None:
    frames, packets, acks = build_script()
    t, got = idle_transport()
    feed(t, b"".join(frames))
    assert got == packets
    assert t._resyncs == 0
    assert list(t._ack_log) == acks
    assert not t._buf  # every byte consumed


@pytest.mark.parametrize("chunk", [1, 5, 31, 32, 33, 100, 1000])
def test_stream_in_awkward_chunks_yields_exactly_the_packets_sent(chunk: int) -> None:
    frames, packets, acks = build_script()
    wire = b"".join(frames)
    t, got = idle_transport()
    for i in range(0, len(wire), chunk):
        feed(t, wire[i : i + chunk])
    assert got == packets
    assert t._resyncs == 0
    assert list(t._ack_log) == acks
    assert not t._buf


def test_stream_split_in_the_middle_of_every_head() -> None:
    frames, packets, acks = build_script()
    t, got = idle_transport()
    for frame in frames:
        feed(t, frame[:16])  # half of the encrypted head
        assert t._buf == frame[:16]
        feed(t, frame[16:40])  # rest of the head and a bit of the body
        feed(t, frame[40:])
    assert got == packets
    assert t._resyncs == 0
    assert list(t._ack_log) == acks


def test_split_between_the_encrypted_and_plaintext_part_of_a_media_frame() -> None:
    frame = video_frame(TEST_KEY, make_h264_keyframe(), keyframe=True)
    t, got = idle_transport()
    feed(t, frame[: 32 + 32])  # head + exactly the encrypted 32 bytes
    assert got == []
    feed(t, frame[32 + 32 :])
    assert [p.data for p in got] == [make_h264_keyframe()]


def test_big_profile_frame_is_one_control_frame() -> None:
    t, got = idle_transport()
    wire = profile_frame(TEST_KEY)
    assert len(wire) == 32 + (PROFILE_LEN + 32 + 15) // 16 * 16
    assert parse_ctrl_frame(wire, TEST_KEY) == (
        0xFE,
        PROFILE_MSG13,
        make_profile_json(),
        len(wire),
    )
    feed(t, wire + control_frame(TEST_KEY, READY_MSG13, b"\x00\x01"))
    assert t._resyncs == 0
    assert list(t._ack_log) == [(0xFE, PROFILE_MSG13), (0xFE, READY_MSG13)]
    assert t.device_ready.is_set()


def test_media_payload_reaches_the_sink_decrypted_and_stitched() -> None:
    """The first 32 payload bytes are AES, the rest plaintext: data must be seamless."""
    data = make_h264_keyframe(9)
    t, got = idle_transport()
    feed(t, video_frame(TEST_KEY, data, keyframe=True))
    assert len(got) == 1
    assert got[0].data == data
    assert got[0].is_keyframe and (got[0].width, got[0].height) == (768, 432)


def test_garbage_between_frames_costs_exactly_one_resync() -> None:
    frames, packets, _ = build_script()
    garbage = bytes((i * 37 + 11) % 251 for i in range(77))
    # frames[3] = keyframe, frames[4] = audio, frames[5] = delta
    wire = b"".join(frames[:4]) + garbage + b"".join(frames[4:])
    t, got = idle_transport()
    feed(t, wire)
    assert t._resyncs == 1
    assert got == packets  # nothing lost around the garbage
    assert not t._buf


def test_garbage_at_the_start_costs_one_resync_and_frames_still_arrive() -> None:
    frames, packets, _ = build_script()
    t, got = idle_transport()
    feed(t, bytes(range(1, 60)) + b"".join(frames))
    assert t._resyncs == 1
    assert got == packets


def test_garbage_dribbled_byte_by_byte_still_recovers() -> None:
    frames, packets, _ = build_script()
    garbage = bytes((i * 13 + 5) % 251 for i in range(50))
    wire = b"".join(frames[:4]) + garbage + b"".join(frames[4:])
    t, got = idle_transport()
    for i in range(len(wire)):
        feed(t, wire[i : i + 1])
    assert t._resyncs == 1  # one run of garbage, however it is chunked
    assert got == packets


@pytest.mark.parametrize("chunk", [1, 3, 31, 33, 77])
def test_one_garbage_run_is_one_resync_for_any_chunking(chunk: int) -> None:
    frames, packets, _ = build_script()
    garbage = bytes((i * 17 + 9) % 251 for i in range(150))
    wire = b"".join(frames[:4]) + garbage + b"".join(frames[4:])
    t, got = idle_transport()
    for i in range(0, len(wire), chunk):
        feed(t, wire[i : i + chunk])
    assert t._resyncs == 1
    assert got == packets


def test_two_separate_garbage_runs_are_two_resyncs() -> None:
    frames, packets, _ = build_script()
    g1 = bytes((i * 17 + 9) % 251 for i in range(60))
    g2 = bytes((i * 23 + 4) % 251 for i in range(45))
    wire = b"".join(frames[:4]) + g1 + b"".join(frames[4:7]) + g2 + b"".join(frames[7:])
    t, got = idle_transport()
    feed(t, wire)
    assert t._resyncs == 2
    assert got == packets


def test_frame_of_an_unknown_type_is_skipped_by_its_lengths() -> None:
    """A type never seen before (control layout) costs neither a resync nor a frame."""
    frames, packets, acks = build_script()
    odd = protocol.ctrl_frame(0x42, 0, bytes(32), TEST_KEY, msg13=33)
    assert len(odd) == 32 + 64  # a 64-byte body
    wire = b"".join(frames[:4]) + odd + b"".join(frames[4:])
    t, got = idle_transport()
    for i in range(0, len(wire), 29):
        feed(t, wire[i : i + 29])
    assert t._resyncs == 0
    assert got == packets  # every frame after it arrived
    assert (0x42, 33) in t._ack_log
    assert not t._buf


def test_wrong_key_never_emits_and_keeps_the_buffer_bounded() -> None:
    """A rotated key: every head fails, resync keeps only a head-sized tail."""
    wire = b"".join(build_script()[0]) * 3
    t = TcpStationTransport(
        "127.0.0.1", 0, TEST_DUID, TEST_DYNPW, "w" * 32, TEST_CLIENT_ID, TEST_OEM
    )
    got: list[MediaPacket] = []
    t.set_media_sink(got.append)
    feed(t, wire)
    assert got == []
    assert not t.logged_in.is_set()
    assert len(t._buf) < protocol.HEAD_LEN


def test_a_raising_sink_does_not_stop_the_stream() -> None:
    frames, packets, _ = build_script()
    t = make_transport(0)
    seen: list[MediaPacket] = []

    def sink(packet: MediaPacket) -> None:
        seen.append(packet)
        raise RuntimeError("boom")

    t.set_media_sink(sink)
    feed(t, b"".join(frames))
    assert seen == packets


def test_unparsable_media_payload_is_skipped_not_fatal() -> None:
    from conftest import build_media_frame, build_media_packet

    bad = bytearray(build_media_packet(protocol.MEDIA_VIDEO, b"abc"))
    bad[2] = 0x07  # not a 00 00 01 start code
    good = video_frame(TEST_KEY, make_h264_keyframe(), keyframe=True)
    t, got = idle_transport()
    feed(t, build_media_frame(TEST_KEY, bytes(bad)) + good)
    assert len(got) == 1 and got[0].is_keyframe
    assert t._resyncs == 0


def test_no_sink_just_counts() -> None:
    t = make_transport(0)
    feed(t, video_frame(TEST_KEY, make_h264_keyframe(), keyframe=True))
    assert t.media_started.is_set()
    t.set_media_sink(None)


# --- events -----------------------------------------------------------------------------------------------------------


def test_events_follow_the_frames() -> None:
    t, _ = idle_transport()
    assert not (
        t.logged_in.is_set() or t.device_ready.is_set() or t.media_started.is_set()
    )

    feed(t, profile_frame(TEST_KEY))  # a control frame: logged in, nothing else
    assert t.logged_in.is_set()
    assert not t.device_ready.is_set()
    assert not t.media_started.is_set()

    feed(t, heartbeat_frame(TEST_KEY))  # the heartbeat never means "ready"
    assert not t.device_ready.is_set()
    assert (0xFE, HEARTBEAT_MSG13) not in t._ack_log

    feed(t, control_frame(TEST_KEY, READY_MSG13, b"\x00\x01"))
    assert t.device_ready.is_set()
    assert not t.media_started.is_set()

    feed(t, video_frame(TEST_KEY, make_h264_keyframe(), keyframe=True))
    assert t.media_started.is_set()


def test_media_alone_logs_in_and_starts_but_a_small_stream_is_not_ready() -> None:
    t, _ = idle_transport()
    feed(t, video_frame(TEST_KEY, make_h264_keyframe(), keyframe=True))
    assert t.logged_in.is_set() and t.media_started.is_set()
    assert not t.device_ready.is_set()  # ~450 bytes < STREAM_IS_PROOF


def test_stream_is_proof_threshold() -> None:
    t, _ = idle_transport()
    one = video_frame(TEST_KEY, bytes(1000), keyframe=False)
    while t._media_bytes <= tr.STREAM_IS_PROOF:
        assert not t.device_ready.is_set()
        feed(t, one)
    assert t.device_ready.is_set()


def test_media_started_is_set_by_audio_too() -> None:
    t, _ = idle_transport()
    feed(t, audio_frame(TEST_KEY, make_audio_chunk()))
    assert t.media_started.is_set()


# --- RX framing: over a real socket -------------------------------------------------------------------------


@pytest.mark.parametrize("chunk", [None, 1, 17])
def test_socket_stream_yields_exactly_the_packets_sent(
    fake_station_factory: Callable[..., FakeStation], chunk: int | None
) -> None:
    frames, packets, _ = build_script()
    station = fake_station_factory(media=frames, chunk=chunk)
    got: list[MediaPacket] = []
    with make_transport(station.port) as t:
        t.set_media_sink(got.append)
        assert t.connect(5.0)
        run_for(t, 10.0, lambda: len(got) >= len(packets))
        assert t.media_started.is_set()
        assert t.device_ready.is_set()
        assert t.logged_in.is_set()
        assert t._resyncs == 0
    assert got == packets  # all of them, last one included, in order


def test_socket_garbage_is_survived(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    frames, packets, _ = build_script()
    garbage = bytes((i * 29 + 3) % 251 for i in range(90))
    media = frames[3:5] + [garbage] + frames[5:]
    station = fake_station_factory(media=media)
    got: list[MediaPacket] = []
    with make_transport(station.port) as t:
        t.set_media_sink(got.append)
        t.connect(5.0)
        run_for(t, 5.0, lambda: len(got) >= len(packets))
        assert t._resyncs >= 1
    assert got == packets


def test_the_sink_can_be_switched_on_a_running_session(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    station = fake_station_factory(stream=True, frame_interval=0.01)
    first: list[MediaPacket] = []
    second: list[MediaPacket] = []
    with make_transport(station.port) as t:
        t.set_media_sink(first.append)
        t.connect(5.0)
        run_for(t, 5.0, lambda: len(first) >= 5)
        t.set_media_sink(second.append)
        run_for(t, 5.0, lambda: len(second) >= 5)
        t.set_media_sink(None)
        frozen = (len(first), len(second))
        time.sleep(0.15)
        assert (len(first), len(second)) == frozen
        assert t._resyncs == 0
    assert first[0].is_keyframe  # a stream starts on a keyframe
    assert any(p.kind == protocol.MEDIA_AUDIO for p in first + second)


# --- door open ---------------------------------------------------------------------------------------------------


def test_send_open_acked_even_when_the_big_profile_precedes_the_ack(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    station = fake_station_factory(ack_open=True, noisy_ack=True)
    with make_transport(station.port) as t:
        t.connect(5.0)
        assert t.wait(t.device_ready, 5.0)
        assert t.send_open(1, 1, TEST_PIN_SHA256) is True
        assert t._resyncs == 0
    opens = station.opens()
    assert len(opens) == 1  # sent exactly once
    _f, _m, payload, _raw = opens[0]
    assert payload == protocol.build_open_payload(1, 1, TEST_PIN_SHA256)


def test_send_open_acked_in_the_middle_of_a_video_stream(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    station = fake_station_factory(stream=True, frame_interval=0.005)
    with make_transport(station.port) as t:
        t.connect(5.0)
        assert t.wait(t.device_ready, 5.0)
        assert t.wait(t.media_started, 5.0)
        assert t.send_open(2, 3, TEST_PIN_SHA256) is True
        assert t._resyncs == 0
    assert len(station.opens()) == 1


def test_send_open_unacked_returns_false_and_is_sent_once(
    fake_station_factory: Callable[..., FakeStation], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tr, "OPENDOOR_ACK_TIMEOUT", 0.6)
    # Heartbeats keep arriving, but a heartbeat is not an ack.
    station = fake_station_factory(ack_open=False, heartbeat_every=0.05)
    with make_transport(station.port) as t:
        t.connect(5.0)
        assert t.wait(t.device_ready, 5.0)
        started = time.monotonic()
        assert t.send_open(1, 1, TEST_PIN_SHA256) is False
        assert time.monotonic() - started >= 0.5  # it really waited for the ack
        time.sleep(0.2)
    assert len(station.opens()) == 1  # NEVER auto-retry a sent-but-unacked open


def test_send_open_acked_with_an_answer_starting_00(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    station = fake_station_factory(open_answer=b"\x00\x01")
    with make_transport(station.port) as t:
        t.connect(5.0)
        assert t.wait(t.device_ready, 5.0)
        assert t.send_open(1, 1, TEST_PIN_SHA256) is True


@pytest.mark.parametrize("answer", [b"\x01\x00", b"\x02", b""])
def test_send_open_refusal_raises_door_rejected_and_is_sent_once(
    fake_station_factory: Callable[..., FakeStation], answer: bytes
) -> None:
    """``01 00`` is the real answer to a wrong PIN; an empty answer is no consent."""
    station = fake_station_factory(open_answer=answer)
    with make_transport(station.port) as t:
        t.connect(5.0)
        assert t.wait(t.device_ready, 5.0)
        with pytest.raises(DoorRejectedError):
            t.send_open(1, 1, TEST_PIN_SHA256)
        time.sleep(0.15)
    assert len(station.opens()) == 1


def test_send_open_on_a_closed_session_is_busy_and_nothing_is_sent(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    station = fake_station_factory()
    t = make_transport(station.port)
    t.connect(5.0)
    assert t.wait(t.device_ready, 5.0)
    t.close()
    with pytest.raises(StationBusyError):  # provably not sent
        t.send_open(1, 1, TEST_PIN_SHA256)
    with pytest.raises(SessionClosedError):
        t.send_ctrl(0x00, 0, b"")
    assert station.opens() == []


def test_close_wakes_a_pending_open_wait_at_once(
    fake_station_factory: Callable[..., FakeStation], monkeypatch: pytest.MonkeyPatch
) -> None:
    import threading

    monkeypatch.setattr(tr, "OPENDOOR_ACK_TIMEOUT", 10.0)
    station = fake_station_factory(ack_open=False)
    t = make_transport(station.port)
    t.connect(5.0)
    assert t.wait(t.device_ready, 5.0)
    threading.Timer(0.2, t.close).start()
    started = time.monotonic()
    assert t.send_open(1, 1, TEST_PIN_SHA256) is False
    assert time.monotonic() - started < 3.0
    never = threading.Event()
    started = time.monotonic()
    assert t.wait(never, 10.0) is False  # wait() also returns early once closed
    assert time.monotonic() - started < 1.0


def test_send_open_ack_of_another_message_does_not_count(
    fake_station_factory: Callable[..., FakeStation], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tr, "OPENDOOR_ACK_TIMEOUT", 0.5)
    station = fake_station_factory(ack_open=False)
    with make_transport(station.port) as t:
        t.connect(5.0)
        assert t.wait(t.device_ready, 5.0)
        # An old ack seen BEFORE the send must not satisfy the wait either.
        t._emit_control(0xFE, OPEN_MSG13, b"\x00")
        assert t.send_open(1, 1, TEST_PIN_SHA256) is False


def test_send_open_without_ready_is_refused_and_nothing_is_sent(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    station = fake_station_factory(send_ready=False)
    with make_transport(station.port) as t:
        t.connect(5.0)
        assert t.wait(t.logged_in, 5.0)
        with pytest.raises(StationBusyError):
            t.send_open(1, 1, TEST_PIN_SHA256)
        time.sleep(0.1)
    assert station.opens() == []


def test_send_ctrl_returns_ack_ids(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    station = fake_station_factory(ack_open=True)
    with make_transport(station.port) as t:
        t.connect(5.0)
        t.wait(t.device_ready, 5.0)
        # send_ctrl only awaits an ack when given expect + a positive timeout;
        # otherwise it is fire-and-forget and returns (-1, -1).
        assert t.send_ctrl(0xFE, 0, b"\x00", msg13=9) == (-1, -1)
        ack = t.send_ctrl(
            0xFE,
            0,
            protocol.build_open_payload(1, 1, TEST_PIN_SHA256),
            msg13=OPEN_MSG13,
            expect=(0xFE, OPEN_MSG13),
            timeout=5.0,
        )
        assert tuple(ack) == (0xFE, OPEN_MSG13)


def test_a_client_frame_larger_than_255_bytes_reaches_the_station_intact(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    station = fake_station_factory()
    payload = bytes((i * 3) % 256 for i in range(800))
    with make_transport(station.port) as t:
        t.connect(5.0)
        t.wait(t.device_ready, 5.0)
        t.send_ctrl(0xFE, 0, payload, msg13=21)
        assert station.wait_for(lambda: any(f[1] == 21 for f in station.received(0xFE)))
    big = next(f for f in station.received(0xFE) if f[1] == 21)
    assert big[2] == payload
    assert len(big[3]) == 32 + 832


# --- teardown ---------------------------------------------------------------------------------------------------------


def test_vanished_socket_raises_not_ends(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    """A station that drops the connection is a stop, not a clean end."""
    station = fake_station_factory(media=build_script()[0], close_after_media=True)
    with make_transport(station.port) as t:
        t.connect(5.0)
        with pytest.raises(TransportError):
            run_for(t, 3.0)


def test_vanished_socket_is_not_an_error_when_the_goal_was_reached(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    frames, packets, _ = build_script()
    station = fake_station_factory(media=frames, close_after_media=True)
    got: list[MediaPacket] = []
    with make_transport(station.port) as t:
        t.set_media_sink(got.append)
        t.connect(5.0)
        run_for(t, 3.0, lambda: len(got) >= len(packets))
    assert got == packets


def test_close_is_clean_and_idempotent(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    station = fake_station_factory()
    t = make_transport(station.port)
    t.connect(5.0)
    t.wait(t.device_ready, 5.0)
    t.close()
    t.close()  # second close must not raise
    assert not t.is_alive
    with pytest.raises(TransportError):
        t.send_ctrl(0x00, 0, b"")  # writing to a closed transport is an error
    assert station.wait_for(lambda: len(station.disconnect_times) == 1)
    # the goodbye frame (type 0x07) was the last thing the station saw
    assert station.wait_for(lambda: bool(station.received(0x07)))


def test_context_manager_closes(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    station = fake_station_factory()
    with make_transport(station.port) as t:
        t.connect(5.0)
    with pytest.raises(TransportError):
        t.send_ctrl(0x00, 0, b"")


def test_control_frame_parser_matches_fixture_helper() -> None:
    frame = protocol.ctrl_frame(0x0B, 0, b"abc", TEST_KEY, msg13=3)
    assert parse_ctrl_frame(frame + b"rest", TEST_KEY) == (0x0B, 3, b"abc", len(frame))
    assert parse_ctrl_frame(frame[:40], TEST_KEY) is None


# --- talk-back channel ----------------------------------------------------------------


def make_talk(port: int) -> tr.TcpTalkChannel:
    return tr.TcpTalkChannel(
        "127.0.0.1", port, TEST_DUID, TEST_DYNPW, TEST_KEY_STR, TEST_CLIENT_ID, TEST_OEM
    )


def test_talk_channel_handshake_follows_the_live_probe(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    station = fake_station_factory()
    talk = make_talk(station.port)
    try:
        talk.open(2.0)
        assert talk.is_alive and not talk.talking
        assert station.audio_connections == 1
        assert station.connections == 0  # the video slot is not touched
        frames = station.audio_received()
        assert [(f[0], f[1]) for f in frames] == [(0x0B, 0xFF), (0x0C, 1), (0x0D, 1)]
        assert frames[0][3] == protocol.build_login_payload(
            TEST_DYNPW, TEST_CLIENT_ID, TEST_OEM
        )
        assert frames[1][2] == frames[2][2] == 0xFFFF  # empty frames
        assert [a[0] for a in talk.answers()] == [0x0B, 0x0C, 0x0D]
    finally:
        talk.close()
    assert station.wait_for(lambda: len(station.audio_disconnect_times) == 1)
    assert station.audio_received()[-1][0] == 0x07  # goodbye


def test_talk_audio_is_paced_at_40_ms_and_carries_the_data(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    station = fake_station_factory()
    talk = make_talk(station.port)
    try:
        talk.open(2.0)
        assert talk.feed(b"\xd5" * 320) == 320  # not talking yet: dropped
        assert talk.set_talking(True) is True
        assert talk.talking and station.talk_states() == [1, 0]
        chunks = [make_audio_chunk(i, 320) for i in range(6)]
        talk.feed(b"".join(chunks[:3]))  # a burst ...
        time.sleep(0.05)
        talk.feed(chunks[3])
        talk.feed(chunks[4] + chunks[5][:100])  # ... and a partial frame
        assert station.wait_for(lambda: len(station.talk_audio()) == 5, 3)
        time.sleep(0.15)
        assert station.talk_audio() == chunks[:5]  # the partial frame waits
        times = [f[4] for f in station.audio_received(0xA2)]
        gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
        assert min(gaps) >= 0.03, gaps  # one frame per 40 ms, never a burst
        talk.feed(chunks[5][100:])
        assert station.wait_for(lambda: len(station.talk_audio()) == 6, 3)
        assert station.talk_audio()[5] == chunks[5]

        assert talk.set_talking(False) is True
        assert station.talk_states() == [1, 0, 1]
        talk.feed(b"\x55" * 640)
        time.sleep(0.2)
        assert len(station.talk_audio()) == 6  # nothing while not talking
    finally:
        talk.close()


def test_a_muted_talk_channel_sends_keepalives_in_counter_order(
    fake_station_factory: Callable[..., FakeStation],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Muted, nothing else leaves the channel: the keepalive keeps it from going
    # silent for minutes, and stops while talk audio flows.
    monkeypatch.setattr(tr, "KEEPALIVE_INTERVAL", 0.2)
    station = fake_station_factory()
    talk = make_talk(station.port)
    try:
        talk.open(2.0)
        assert station.wait_for(lambda: len(station.audio_received(0x00)) >= 2, 3)
        assert talk.is_alive
        assert talk.set_talking(True)
        keepalives = len(station.audio_received(0x00))
        for i in range(12):  # ~0.5 s of audio, fed in real time
            talk.feed(make_audio_chunk(i, 320))
            time.sleep(0.04)
        assert station.wait_for(lambda: len(station.talk_audio()) == 12, 3)
        assert len(station.audio_received(0x00)) <= keepalives + 1
    finally:
        talk.close()
    assert station.wait_for(lambda: len(station.audio_disconnect_times) == 1)
    # Every frame carries the next counter value, in the order sent.
    # (The format and the first talk state share one counter, as in the spike.)
    counters = list(station.audio_counters)
    assert counters[:3] == [1, 2, 2]
    assert counters[2:] == list(range(2, len(counters)))


def test_talk_buffer_is_capped_at_400_ms_dropping_the_oldest(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    station = fake_station_factory()
    talk = make_talk(station.port)
    try:
        talk.open(2.0)
        assert talk.set_talking(True)
        chunks = [make_audio_chunk(i, 320) for i in range(20)]
        with talk._audio_cv:  # one burst of 800 ms, before the sender wakes up
            talk._pending += b"".join(chunks[:10])
        dropped = talk.feed(b"".join(chunks[10:]))
        assert dropped == 10 * 320 and talk.bytes_dropped == 10 * 320
        assert station.wait_for(lambda: len(station.talk_audio()) == 10, 3)
        time.sleep(0.15)
        assert station.talk_audio() == chunks[10:]  # the newest 400 ms
    finally:
        talk.close()


def test_closing_while_talking_stops_talking_first(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    station = fake_station_factory()
    talk = make_talk(station.port)
    talk.open(2.0)
    assert talk.set_talking(True)
    talk.close()
    assert station.wait_for(lambda: len(station.audio_disconnect_times) == 1)
    assert [f[0] for f in station.audio_received()][-2:] == [0x0D, 0x07]
    assert station.talk_states()[-1] == 1
    assert not talk.is_alive and not talk.talking
    talk.close()  # idempotent


def test_an_unanswered_audio_login_fails_and_closes(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    station = fake_station_factory(audio_accept=False)
    talk = make_talk(station.port)
    started = time.monotonic()
    with pytest.raises(TransportError, match="audio LOGIN"):
        talk.open(0.5)
    assert time.monotonic() - started < 2
    assert not talk.is_alive
    assert station.wait_for(lambda: len(station.audio_disconnect_times) == 1)


def test_an_unanswered_talk_start_keeps_the_microphone_off(
    fake_station_factory: Callable[..., FakeStation],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tr, "TALK_ANSWER_TIMEOUT", 0.3)
    station = fake_station_factory(talk_answer=False)
    talk = make_talk(station.port)
    try:
        # The handshake needs the 0x0D answer too.
        with pytest.raises(TransportError, match="audio format"):
            talk.open(0.5)
    finally:
        talk.close()
    station.talk_answer = True
    talk = make_talk(station.port)
    try:
        talk.open(2.0)
        station.talk_answer = False
        assert talk.set_talking(True) is False
        assert not talk.talking
        talk.feed(b"\xd5" * 640)
        time.sleep(0.15)
        assert station.talk_audio() == []
    finally:
        talk.close()


def test_a_dropped_talk_channel_is_reported(
    fake_station_factory: Callable[..., FakeStation],
) -> None:
    station = fake_station_factory()
    talk = make_talk(station.port)
    closed: list[bool] = []
    talk.set_close_callback(lambda: closed.append(True))
    try:
        talk.open(2.0)
        assert talk.set_talking(True)
        station.drop_audio_channels()
        assert station.wait_for(lambda: closed == [True], 3)
        assert not talk.is_alive and not talk.talking
        assert talk.set_talking(True) is False
    finally:
        talk.close()
    assert closed == [True]  # once, and not again for our own close


def test_an_unreachable_station_is_silent_for_the_talk_channel() -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    talk = make_talk(port)
    with pytest.raises(StationSilentError):
        talk.open(0.5)
    assert not talk.is_alive
