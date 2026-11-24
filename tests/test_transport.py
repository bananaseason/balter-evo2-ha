"""Tests of ``TcpStationTransport`` against a loopback fake station.

The fake station (see ``conftest.FakeStation``) is a real TCP server on 127.0.0.1,
so the blocking transport is exercised exactly as against hardware: raw a9 body ->
raw a9 echo -> raw LOGIN -> ready marker -> media + keepalives. The AES key is made
up; nothing here needs a live station or real credentials.

TODO(live): once the media-frame length offset is pinned against a real station,
add a vector test for the exact-offset resolver and drop the xfail below.
"""

from __future__ import annotations

import time
from collections.abc import Callable

import pytest
from conftest import (
    TEST_CLIENT_ID,
    TEST_DUID,
    TEST_DYNPW,
    TEST_KEY,
    TEST_KEY_STR,
    TEST_OEM,
    TEST_PIN_SHA256,
    FakeStation,
    build_media_frame,
    make_h264_keyframe,
    make_h264_pframe,
    parse_ctrl_frame,
)

from custom_components.balter_evo2 import protocol
from custom_components.balter_evo2 import transport as tr
from custom_components.balter_evo2.transport import (
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


def run_for(t: TcpStationTransport, seconds: float, until: Callable[[], bool] | None = None) -> None:
    t.run_until(time.monotonic() + seconds, until)


def media_frames(n: int = 4) -> list[bytes]:
    out = [build_media_frame(TEST_KEY, make_h264_keyframe(0), ts=0)]
    out += [build_media_frame(TEST_KEY, make_h264_pframe(i), ts=i) for i in range(1, n)]
    return out


# --- exceptions ---------------------------------------------------------------------------


def test_exception_hierarchy() -> None:
    assert issubclass(StationSilentError, TransportError)
    assert issubclass(StationBusyError, TransportError)
    assert issubclass(TransportError, Exception)


# --- handshake -------------------------------------------------------------------------------


def test_handshake_login_then_ready(fake_station_factory: Callable[..., FakeStation]) -> None:
    station = fake_station_factory(media=[])
    with make_transport(station.port) as t:
        assert t.connect(5.0) is True
        assert t.wait(t.device_ready, 5.0)
        assert t.logged_in.is_set()
        assert t.device_ready.is_set()
        assert t.station_silent is False
        assert isinstance(t.handshake_states(), str)

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


def test_audio_socket_is_off_by_default(fake_station_factory: Callable[..., FakeStation]) -> None:
    station = fake_station_factory()
    with make_transport(station.port) as t:
        assert t.connect(5.0)
        t.wait(t.device_ready, 5.0)
    assert station.connections == 1
    assert station.a9_body is not None and station.a9_body[9] == 0  # video, not audio


def test_silent_station_sets_station_silent(fake_station_factory: Callable[..., FakeStation]) -> None:
    """No a9 echo within the timeout -> connect() returns False with station_silent.

    connect() never raises for a silent station (the station-facing contract the
    manager depends on): it reports the failure through its return value and the
    station_silent flag so the caller can skip the recovery gap.
    """
    station = fake_station_factory(send_echo=False)
    t = make_transport(station.port)
    try:
        assert t.connect(0.6) is False
        assert t.station_silent is True
        assert not t.device_ready.is_set()
    finally:
        t.close()


def test_refused_connection_raises_transport_error() -> None:
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nobody listens here now
    t = make_transport(port)
    try:
        with pytest.raises((TransportError, OSError)):
            result = t.connect(1.0)
            if result is False:
                raise TransportError("connect returned False")
    finally:
        t.close()


def test_ready_not_set_without_marker(fake_station_factory: Callable[..., FakeStation]) -> None:
    station = fake_station_factory(send_ready=False)
    with make_transport(station.port) as t:
        t.connect(5.0)
        assert t.wait(t.device_ready, 0.5) is False


# --- session setup + keepalive --------------------------------------------------------------------


def test_session_setup_sends_small_0xfe_frame(fake_station_factory: Callable[..., FakeStation]) -> None:
    station = fake_station_factory()
    with make_transport(station.port) as t:
        t.connect(5.0)
        t.wait(t.device_ready, 5.0)
        t.send_session_setup()
        assert station.wait_for(lambda: bool(station.received(0xFE)))
    ftype, _msg13, _payload, raw = station.received(0xFE)[0]
    assert ftype == 0xFE
    assert len(raw) == 32 + protocol.cbc_decrypt(raw[:32], TEST_KEY)[9]
    assert len(raw) < 208  # a small frame, not another LOGIN


def test_keepalives_are_sent_on_interval(
    fake_station_factory: Callable[..., FakeStation], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tr, "KEEPALIVE_INTERVAL", 0.2, raising=False)
    station = fake_station_factory()
    with make_transport(station.port) as t:
        t.connect(5.0)
        t.wait(t.device_ready, 5.0)
        run_for(t, 1.5)
    keepalives = station.received(0x00)
    assert len(keepalives) >= 2
    expected = protocol.ctrl_frame(0x00, 0, b"", TEST_KEY)
    for _f, _m, payload, raw in keepalives:
        assert len(raw) == 64
        assert payload == b""
        assert raw == expected  # identical ciphertext every time (zero IV)


def test_station_keepalives_are_consumed(fake_station_factory: Callable[..., FakeStation]) -> None:
    station = fake_station_factory(keepalive_every=0.1, media=media_frames(3))
    frames: list[tuple[int, bytes]] = []
    with make_transport(station.port) as t:
        t.set_media_sink(lambda kind, data: frames.append((kind, data)))
        t.connect(5.0)
        run_for(t, 1.0)
        assert t.station_silent is False
    assert frames  # keepalives in between did not break the framer


# --- RX framing ------------------------------------------------------------------------------------------


def test_framer_delivers_media_frames(fake_station_factory: Callable[..., FakeStation]) -> None:
    """Concatenated control + media frames, no ff-ff-ff-ff, walked via decrypted heads."""
    sent = media_frames(5)
    station = fake_station_factory(media=sent)
    got: list[tuple[int, bytes]] = []
    with make_transport(station.port) as t:
        t.set_media_sink(lambda kind, data: got.append((kind, data)))
        t.connect(5.0)
        run_for(t, 3.0, lambda: len(got) >= len(sent) - 1)
    # The last frame may stay buffered until another head follows (fallback scanner).
    assert len(got) >= len(sent) - 1
    # The sink is called (seq, frame): seq is a positive, monotonically
    # increasing counter (not a frame type), and each frame starts at its
    # encrypted 64-byte media head.
    seqs = [seq for seq, _ in got]
    assert seqs == sorted(seqs) and all(seq > 0 for seq in seqs)
    for (_seq, data), original in zip(got, sent, strict=False):
        assert data[:64] == original[:64]  # starts at the encrypted head
        assert data.startswith(original[:64])
    # The delivered frames decode to a decodable H.264 stream.
    stream = protocol.decode_media([d for _, d in got], [TEST_KEY])
    assert stream is not None and protocol.h264_is_decodable(stream)


def test_framer_many_frames_in_one_burst(fake_station_factory: Callable[..., FakeStation]) -> None:
    """A burst of back-to-back frames (arbitrary TCP segmentation) is walked correctly."""
    big = media_frames(6)
    station = fake_station_factory(media=big)
    got: list[tuple[int, bytes]] = []
    with make_transport(station.port) as t:
        t.set_media_sink(lambda kind, data: got.append((kind, data)))
        t.connect(5.0)
        run_for(t, 3.0, lambda: len(got) >= len(big) - 1)
    assert len(got) >= len(big) - 1


@pytest.mark.xfail(
    reason="exact media-length offset not pinned yet (needs a live-decrypted 0xA0 head vector)",
    strict=False,
)
def test_media_length_pinned_offset_resolver(fake_station_factory: Callable[..., FakeStation]) -> None:
    sent = media_frames(3)
    station = fake_station_factory(media=sent)
    got: list[tuple[int, bytes]] = []
    with make_transport(station.port) as t:
        t.set_media_sink(lambda kind, data: got.append((kind, data)))
        t.connect(5.0)
        run_for(t, 2.0, lambda: len(got) >= len(sent))
    assert [d for _, d in got] == sent  # needs the pinned offset: last frame included


# --- door open ---------------------------------------------------------------------------------------------------


def test_send_open_acked(fake_station_factory: Callable[..., FakeStation]) -> None:
    station = fake_station_factory(ack_open=True)
    with make_transport(station.port) as t:
        t.connect(5.0)
        assert t.wait(t.device_ready, 5.0)
        assert t.send_open(1, 1, TEST_PIN_SHA256) is True
    opens = [f for f in station.received(0xFE) if f[1] == 4]
    assert len(opens) == 1  # sent exactly once
    _f, _m, payload, _raw = opens[0]
    assert payload == protocol.build_open_payload(1, 1, TEST_PIN_SHA256)


def test_send_open_unacked_returns_false_and_is_not_retried(
    fake_station_factory: Callable[..., FakeStation], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tr, "REQUEST_TIMEOUT", 0.8, raising=False)
    station = fake_station_factory(ack_open=False)
    with make_transport(station.port) as t:
        t.connect(5.0)
        t.wait(t.device_ready, 5.0)
        try:
            result = t.send_open(1, 1, TEST_PIN_SHA256)
        except TransportError:
            result = False  # a hard error is an acceptable surfacing, never a retry
        assert result is False
    opens = [f for f in station.received(0xFE) if f[1] == 4]
    assert len(opens) == 1  # NEVER auto-retry a sent-but-unacked open


def test_send_ctrl_returns_ack_ids(fake_station_factory: Callable[..., FakeStation]) -> None:
    station = fake_station_factory(ack_open=True)
    with make_transport(station.port) as t:
        t.connect(5.0)
        t.wait(t.device_ready, 5.0)
        # send_ctrl only awaits an ack when given expect + a positive timeout;
        # otherwise it is fire-and-forget and returns (-1, -1).
        ack = t.send_ctrl(
            0xFE,
            0,
            protocol.build_open_payload(1, 1, TEST_PIN_SHA256),
            msg13=4,
            expect=(0xFE, 4),
            timeout=5.0,
        )
        assert tuple(ack) == (0xFE, 4)


# --- teardown ---------------------------------------------------------------------------------------------------------


def test_vanished_socket_raises_not_ends(fake_station_factory: Callable[..., FakeStation]) -> None:
    """A station that drops the connection is a stop, not a clean end."""
    station = fake_station_factory(media=media_frames(2), close_after_media=True)
    with make_transport(station.port) as t:
        t.connect(5.0)
        with pytest.raises(TransportError):
            run_for(t, 3.0)


def test_close_is_clean_and_idempotent(fake_station_factory: Callable[..., FakeStation]) -> None:
    station = fake_station_factory()
    t = make_transport(station.port)
    t.connect(5.0)
    t.wait(t.device_ready, 5.0)
    t.close()
    t.close()  # second close must not raise
    with pytest.raises(TransportError):
        t.send_ctrl(0x00, 0, b"")  # writing to a closed transport is an error


def test_context_manager_closes(fake_station_factory: Callable[..., FakeStation]) -> None:
    station = fake_station_factory()
    with make_transport(station.port) as t:
        t.connect(5.0)
    with pytest.raises(TransportError):
        t.send_ctrl(0x00, 0, b"")


def test_control_frame_parser_matches_fixture_helper() -> None:
    frame = protocol.ctrl_frame(0x0B, 0, b"abc", TEST_KEY, msg13=3)
    assert parse_ctrl_frame(frame + b"rest", TEST_KEY) == (0x0B, 3, b"abc", len(frame))
    assert parse_ctrl_frame(frame[:40], TEST_KEY) is None
