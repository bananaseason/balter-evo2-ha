"""Tests of ``StationManager`` against loopback fake stations.

The manager drives the REAL blocking :class:`TcpStationTransport` over TCP to a
:class:`conftest.FakeStation` on 127.0.0.1 (the port is redirected per station;
the production port is a constant). What is covered is the orchestration: a
snapshot ends with the first keyframe and releases the station at once, commands
keep ``SESSION_MIN_GAP`` apart, a login without video is retried exactly once, a
door command during a live view travels over the live view's own session, and the
door-open error mapping (never retry an unacked open).

ffmpeg is never needed: ``media.h264_to_jpeg`` / ``h264_to_mp4`` and the live
transcoder are replaced by recording fakes.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from conftest import (
    TEST_DUID,
    TEST_KEY,
    TEST_PIN_SHA256,
    FakeStation,
    audio_frame,
    make_audio_chunk,
    make_h264_keyframe,
    make_h264_pframe,
    video_frame,
)
from homeassistant.core import HomeAssistant

from custom_components.balter_evo2 import media as media_mod
from custom_components.balter_evo2 import station as station_mod
from custom_components.balter_evo2 import transport as transport_mod
from custom_components.balter_evo2.models import Credentials, Device
from custom_components.balter_evo2.transport import (
    DoorRejectedError,
    StationBusyError,
    StationSilentError,
)

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.usefixtures("socket_enabled", "enable_custom_integrations"),
]

GAP = 0.3
MEDIA_START = 0.4
FAKE_JPEG = b"\xff\xd8fake-jpeg\xff\xd9"
FAKE_MP4 = b"fake-mp4"
LIVE_JPEG = b"\xff\xd8live\xff\xd9"


class Recorder:
    """What the fake media converters were called with."""

    def __init__(self) -> None:
        self.jpeg_inputs: list[bytes] = []
        self.mp4_inputs: list[tuple[bytes, float]] = []
        self.ports: dict[str, int] = {}
        self.transports: list[Any] = []


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


@pytest.fixture
def rec(monkeypatch: pytest.MonkeyPatch) -> Iterator[Recorder]:
    r = Recorder()
    real_transport = station_mod.TcpStationTransport

    def build(host: str, port: int, duid: str, *args: Any, **kwargs: Any) -> Any:
        t = real_transport(host, r.ports.get(duid, r.ports["*"]), duid, *args, **kwargs)
        r.transports.append(t)
        return t

    monkeypatch.setattr(station_mod, "TcpStationTransport", build)
    monkeypatch.setattr(station_mod, "SESSION_MIN_GAP", GAP)
    monkeypatch.setattr(station_mod, "MEDIA_START_TIMEOUT", MEDIA_START)
    monkeypatch.setattr(station_mod, "LOGIN_TIMEOUT", 2.0)

    def to_jpeg(h264: bytes) -> bytes:
        r.jpeg_inputs.append(h264)
        return FAKE_JPEG

    def to_mp4(h264: bytes, seconds: float) -> bytes:
        r.mp4_inputs.append((h264, seconds))
        return FAKE_MP4

    monkeypatch.setattr(media_mod, "h264_to_jpeg", to_jpeg)
    monkeypatch.setattr(media_mod, "h264_to_mp4", to_mp4)
    yield r


@pytest.fixture
def make_station(
    rec: Recorder, fake_station_factory: Callable[..., FakeStation]
) -> Callable[..., FakeStation]:
    def factory(duid: str = "*", **kwargs: Any) -> FakeStation:
        station = fake_station_factory(**kwargs)
        rec.ports[duid] = station.port
        return station

    return factory


@pytest.fixture
def device() -> Device:
    return Device(duid=TEST_DUID, name="Door", model="IDS94A6FW", host="127.0.0.1")


@pytest.fixture
def creds() -> Credentials:
    return Credentials(
        dynamic_password="p" * 96,
        data_encode_key="k" * 32,
        out_auth_code=TEST_PIN_SHA256,
    )


@pytest.fixture
def manager(hass: HomeAssistant) -> Any:
    return station_mod.StationManager(hass, lambda device: "127.0.0.1")


async def until(predicate: Callable[[], bool], timeout: float = 5.0) -> bool:
    """Await ``predicate`` without blocking the event loop."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return predicate()


async def test_defaults_of_the_manager() -> None:
    assert station_mod.DEFAULT_WARM_IDLE == 0
    assert station_mod.SESSION_MIN_GAP == 2.0
    assert station_mod.MEDIA_START_TIMEOUT == 3.0


def _workers_alive() -> list[str]:
    return [t.name for t in threading.enumerate() if t.name.startswith("balter_evo2-")]


# --- snapshot ----------------------------------------------------------------------------------


async def test_snapshot_returns_after_first_keyframe_and_closes_the_session(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
    rec: Recorder,
) -> None:
    kf = make_h264_keyframe(0)
    # leading delta frame + audio, then the keyframe, then more video
    media = [
        video_frame(TEST_KEY, make_h264_pframe(1), keyframe=False, ts=1),
        audio_frame(TEST_KEY, make_audio_chunk(1), ts=1),
        video_frame(TEST_KEY, kf, keyframe=True, ts=2),
        video_frame(TEST_KEY, make_h264_keyframe(7), keyframe=True, ts=3),
    ]
    station = make_station(media=media)
    started = time.monotonic()
    image = await manager.async_snapshot(device, creds)
    elapsed = time.monotonic() - started

    assert image == FAKE_JPEG
    assert rec.jpeg_inputs == [kf]  # the FIRST keyframe's data, stitched correctly
    assert elapsed < station_mod.SNAPSHOT_WINDOW - 1  # did not wait out the window
    assert station.connections == 1
    # default warm_idle=0: the session is closed right after the command
    assert await until(lambda: len(station.disconnect_times) == 1)
    assert station.received(0x07)  # the close frame went out
    await asyncio.sleep(0.3)
    assert station.connections == 1  # and nothing reconnected on its own


async def test_snapshot_without_keyframe_is_none(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
    rec: Recorder,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(station_mod, "SNAPSHOT_WINDOW", 0.5)
    station = make_station(
        media=[
            video_frame(TEST_KEY, make_h264_pframe(i), keyframe=False, ts=i)
            for i in range(3)
        ]
    )
    assert await manager.async_snapshot(device, creds) is None
    assert rec.jpeg_inputs == []
    assert station.connections == 1  # video did flow: no retry
    assert await until(lambda: len(station.disconnect_times) == 1)


async def test_snapshot_without_password_never_connects(
    manager: Any, device: Device, make_station: Callable[..., FakeStation]
) -> None:
    station = make_station(stream=True)
    empty = Credentials(dynamic_password="", data_encode_key="k" * 32)
    assert await manager.async_snapshot(device, empty) is None
    assert station.connections == 0


async def test_snapshot_never_blocks_the_event_loop(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
) -> None:
    """The loop keeps ticking while the (blocking) transport runs in an executor."""
    make_station(no_video_connections=99)
    ticks = 0

    async def ticker() -> None:
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0.01)

    task = asyncio.create_task(ticker())
    assert await manager.async_snapshot(device, creds) is None
    task.cancel()
    assert ticks > 20  # the call lasted > 0.8 s; the loop was never held


# --- single session slot + recovery gap -----------------------------------------------------------


async def test_two_commands_are_at_least_the_gap_apart(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
) -> None:
    station = make_station(stream=True)
    t0 = time.monotonic()
    assert await manager.async_snapshot(device, creds) == FAKE_JPEG
    assert await manager.async_snapshot(device, creds) == FAKE_JPEG
    assert station.connections == 2
    first_connect, second_connect = station.connect_times
    first_close = station.disconnect_times[0]
    assert first_connect - t0 < GAP  # the first command is not delayed
    assert second_connect - first_connect >= GAP
    assert second_connect - first_close >= GAP * 0.7  # measured at the station


async def test_gap_applies_to_a_door_command_after_a_snapshot(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
) -> None:
    station = make_station(stream=True)
    await manager.async_snapshot(device, creds)
    assert await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256) is True
    assert station.connections == 2
    assert station.connect_times[1] - station.disconnect_times[0] >= GAP * 0.7


async def test_gap_is_per_station(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
) -> None:
    other = Device(duid="otherduid", name="Other", model="x", host="127.0.0.1")
    make_station(stream=True)
    other_station = make_station("otherduid", stream=True)
    await manager.async_snapshot(device, creds)
    after_first = time.monotonic()
    assert await manager.async_snapshot(other, creds) == FAKE_JPEG
    assert other_station.connect_times[0] - after_first < GAP * 0.7


async def test_running_stream_blocks_concurrent_snapshot(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    station = make_station(stream=True)
    monkeypatch.setattr(station_mod, "_start_mjpeg_transcoder", lambda: FakeFFmpeg())
    stop = threading.Event()
    jpegs: list[bytes] = []
    stream = asyncio.create_task(
        manager.async_stream(device, creds, 30.0, jpegs.append, stop.is_set)
    )
    assert await until(lambda: len(jpegs) >= 2)
    assert station.connections == 1

    snap = asyncio.create_task(manager.async_snapshot(device, creds))
    await asyncio.sleep(0.5)
    assert not snap.done()  # waits for the slot
    assert station.connections == 1  # no second session while one is running

    stop.set()
    await asyncio.wait_for(stream, 10)
    assert await asyncio.wait_for(snap, 10) == FAKE_JPEG
    assert station.connections == 2
    assert station.connect_times[1] - station.disconnect_times[0] >= GAP * 0.7
    assert await until(lambda: not _workers_alive())


# --- a login without video ---------------------------------------------------------------------------


async def test_login_without_video_is_retried_exactly_once(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
    rec: Recorder,
) -> None:
    station = make_station(stream=True, no_video_connections=1)
    assert await manager.async_snapshot(device, creds) == FAKE_JPEG
    assert station.connections == 2
    # the first session logged in (profile + ready) but never sent video
    first, second = station.connect_times
    assert second - first >= MEDIA_START + GAP * 0.8
    assert await until(lambda: len(station.disconnect_times) == 2)
    assert rec.jpeg_inputs == [make_h264_keyframe(0)]
    # both sessions logged in: the setup frames went out twice
    assert len(station.received(0x01)) == 2


async def test_a_station_that_never_sends_video_gets_two_attempts_not_three(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
    rec: Recorder,
) -> None:
    station = make_station(stream=True, no_video_connections=99)
    assert await manager.async_snapshot(device, creds) is None
    await asyncio.sleep(MEDIA_START + GAP + 0.3)  # a hidden third try would show up
    assert station.connections == 2
    assert await until(lambda: len(station.disconnect_times) == 2)
    assert rec.jpeg_inputs == []
    first, second = station.connect_times
    assert second - first >= MEDIA_START + GAP * 0.8


async def test_unreachable_station_is_not_retried(
    manager: Any, device: Device, creds: Credentials, rec: Recorder
) -> None:
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    rec.ports["*"] = s.getsockname()[1]
    s.close()  # nobody listens
    t0 = time.monotonic()
    assert await manager.async_snapshot(device, creds) is None
    assert time.monotonic() - t0 < MEDIA_START + GAP  # no second attempt, no gap


# --- live stream + door command ---------------------------------------------------------------------------


async def test_door_command_during_a_stream_goes_over_the_streams_session(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    station = make_station(stream=True, frame_interval=0.01)
    ffmpeg = FakeFFmpeg()
    monkeypatch.setattr(station_mod, "_start_mjpeg_transcoder", lambda: ffmpeg)
    stop = threading.Event()
    jpegs: list[bytes] = []
    stream = asyncio.create_task(
        manager.async_stream(device, creds, 30.0, jpegs.append, stop.is_set)
    )
    assert await until(lambda: len(jpegs) >= 3)

    acked = await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256)
    assert acked is True
    assert station.connections == 1  # ONE connection: the stream's own session
    assert len(station.opens()) == 1
    assert station.opens()[0][2].endswith(TEST_PIN_SHA256.encode())

    # the stream keeps running after the command
    seen = len(jpegs)
    assert await until(lambda: len(jpegs) >= seen + 3)
    assert not stream.done()
    assert not station.disconnect_times

    # a second door command rides the same session
    assert await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256) is True
    assert station.connections == 1 and len(station.opens()) == 2

    stop.set()
    frames = await asyncio.wait_for(stream, 10)
    assert frames >= seen + 3
    assert frames == len(jpegs)
    assert await until(lambda: len(station.disconnect_times) == 1)
    assert station.connections == 1
    assert ffmpeg.killed
    assert await until(lambda: not _workers_alive())  # the stream's workers exit

    # ffmpeg got video only, starting at the first keyframe (no audio, no profile)
    written = bytes(ffmpeg.written)
    assert written.startswith(make_h264_keyframe(0))
    assert b"".join(station.sent_video).startswith(written)


async def test_stream_ends_at_its_duration_and_releases_the_station(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    station = make_station(stream=True)
    monkeypatch.setattr(station_mod, "_start_mjpeg_transcoder", lambda: FakeFFmpeg())
    jpegs: list[bytes] = []
    frames = await manager.async_stream(device, creds, 0.6, jpegs.append, lambda: False)
    assert frames == len(jpegs) > 0
    assert set(jpegs) == {LIVE_JPEG}
    assert await until(lambda: len(station.disconnect_times) == 1)
    assert await until(lambda: not _workers_alive())


async def test_stream_without_ffmpeg_gives_up_and_releases_the_station(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    station = make_station(stream=True)
    monkeypatch.setattr(station_mod, "_start_mjpeg_transcoder", lambda: None)
    assert (
        await manager.async_stream(device, creds, 5.0, lambda jpg: None, lambda: False)
        == 0
    )
    assert await until(lambda: len(station.disconnect_times) == 1)


# --- warm idle / release --------------------------------------------------------------------------------


async def test_warm_session_is_reused_by_the_next_door_command_and_released(
    hass: HomeAssistant,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
) -> None:
    station = make_station()
    manager = station_mod.StationManager(hass, lambda d: "127.0.0.1", warm_idle=30.0)
    assert await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256) is True
    await asyncio.sleep(0.2)
    assert not station.disconnect_times  # kept warm for the next press
    assert await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256) is True
    assert station.connections == 1  # no second handshake
    assert len(station.opens()) == 2
    await manager.async_release_all()
    assert await until(lambda: len(station.disconnect_times) == 1)


async def test_default_warm_idle_closes_after_a_door_command(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
) -> None:
    station = make_station()
    assert await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256) is True
    assert await until(lambda: len(station.disconnect_times) == 1)


async def test_release_all_without_sessions_is_noop(manager: Any) -> None:
    await manager.async_release_all()
    await manager.async_release_all()


# --- record clip -----------------------------------------------------------------------------------------------


async def test_record_clip_returns_mp4_of_the_video_from_the_first_keyframe(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
    rec: Recorder,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(station_mod, "CLIP_LEAD_SECONDS", 0.0)
    station = make_station(stream=True, frame_interval=0.01)
    assert await manager.async_record_clip(device, creds, 0.5) == FAKE_MP4
    ((h264, seconds),) = rec.mp4_inputs
    assert seconds == 0.5
    assert h264.startswith(make_h264_keyframe(0))
    assert len(h264) > len(make_h264_keyframe(0)) + 300  # deltas followed
    assert make_audio_chunk(1) not in h264
    assert b"".join(station.sent_video).startswith(h264)
    assert await until(lambda: len(station.disconnect_times) == 1)


async def test_record_clip_none_without_video(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
    rec: Recorder,
) -> None:
    make_station(no_video_connections=99)
    assert await manager.async_record_clip(device, creds, 1) is None
    assert rec.mp4_inputs == []


# --- door open -------------------------------------------------------------------------------------------------


async def test_open_door_true_only_on_ack(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
) -> None:
    station = make_station()
    assert await manager.async_open_door(device, creds, 2, 3, TEST_PIN_SHA256) is True
    ((_f, msg13, payload, _raw),) = station.opens()
    assert msg13 == 4
    assert payload[0] == 2 and payload[2] == 3
    assert payload[16:] == TEST_PIN_SHA256.encode()


async def test_open_door_without_a_pin_sends_the_hash_of_an_empty_pin(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
) -> None:
    station = make_station()
    assert await manager.async_open_door(device, creds, 1, 1, None) is True
    assert station.opens()[0][2][16:] == station_mod.protocol.SHA256_OF_EMPTY.encode()


async def test_open_door_unacked_returns_false_and_is_never_retried(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_mod, "OPENDOOR_ACK_TIMEOUT", 0.5)
    station = make_station(ack_open=False)
    assert await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256) is False
    await asyncio.sleep(GAP + 0.2)
    assert len(station.opens()) == 1  # sent exactly once
    assert station.connections == 1  # and no reconnect-and-resend


async def test_open_door_silent_station(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(station_mod, "LOGIN_TIMEOUT", 0.4)
    station = make_station(send_echo=False)
    with pytest.raises(StationSilentError):
        await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256)
    assert station.connections == 1  # one attempt, no hidden retry
    assert station.opens() == []


async def test_open_door_busy_station(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(station_mod, "DOOR_SESSION_TIMEOUT", 0.5)
    station = make_station(send_ready=False)
    with pytest.raises(StationBusyError):
        await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256)
    assert station.connections == 1
    assert station.opens() == []  # the command provably never left


async def test_silent_error_skips_recovery_gap(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A station that never answered never took a session: retry right away."""
    monkeypatch.setattr(station_mod, "LOGIN_TIMEOUT", 0.3)
    station = make_station(send_echo=False)
    for _ in range(2):
        with pytest.raises(StationSilentError):
            await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256)
    assert station.connections == 2
    assert station.connect_times[1] - station.disconnect_times[0] < GAP * 0.5


async def test_busy_error_applies_the_recovery_gap(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A station that logged in but never freed its slot did take a session."""
    monkeypatch.setattr(station_mod, "DOOR_SESSION_TIMEOUT", 0.3)
    station = make_station(send_ready=False)
    for _ in range(2):
        with pytest.raises(StationBusyError):
            await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256)
    assert station.connections == 2
    assert station.connect_times[1] - station.disconnect_times[0] >= GAP * 0.7


# --- refusal (wrong PIN) ------------------------------------------------------------------------------


async def test_open_door_refused_raises_door_rejected(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
) -> None:
    station = make_station(open_answer=b"\x01\x00")
    with pytest.raises(DoorRejectedError):
        await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256)
    assert len(station.opens()) == 1  # and never retried
    assert station.connections == 1


async def test_a_refusal_carries_the_stations_answer(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
) -> None:
    # 01 01: the PIN was right, but the station does not open this lock.
    make_station(open_answer=b"\x01\x01")
    with pytest.raises(DoorRejectedError) as raised:
        await manager.async_open_door(device, creds, 1, 2, TEST_PIN_SHA256)
    assert raised.value.answer == b"\x01\x01"


async def test_door_command_waits_for_the_answer_to_the_setup_frames(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
) -> None:
    # The real station answers "session ready" only to the client's own setup
    # frames, about half a second later; a command sent before that answer can
    # be dropped without any reply.
    station = make_station(ready_after_setup=0.3)
    assert await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256) is True
    control = [msg13 for ftype, msg13, _p, _r in station.received(0xFE)]
    assert control == [5, 6, 2, 4]
    assert station.events == ["ready sent", "open received"]


async def test_door_command_goes_out_to_a_station_that_streams_but_never_says_ready(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(station_mod, "SETUP_ANSWER_TIMEOUT", 0.2)
    station = make_station(send_ready=False, stream=True)
    assert await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256) is True
    assert len(station.opens()) == 1


async def test_open_door_refused_over_a_live_view_raises_and_the_view_goes_on(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    station = make_station(stream=True, frame_interval=0.01, open_answer=b"\x01\x00")
    monkeypatch.setattr(station_mod, "_start_mjpeg_transcoder", lambda: FakeFFmpeg())
    stop = threading.Event()
    jpegs: list[bytes] = []
    stream = asyncio.create_task(
        manager.async_stream(device, creds, 30.0, jpegs.append, stop.is_set)
    )
    assert await until(lambda: len(jpegs) >= 2)
    with pytest.raises(DoorRejectedError):
        await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256)
    assert station.connections == 1 and len(station.opens()) == 1
    seen = len(jpegs)
    assert await until(lambda: len(jpegs) >= seen + 2)
    stop.set()
    await asyncio.wait_for(stream, 10)


# --- door command in flight while the live view ends ----------------------------------------------------


async def test_stopping_the_stream_waits_for_a_door_command_in_flight(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    station = make_station(stream=True, frame_interval=0.01, ack_delay=0.3)
    monkeypatch.setattr(station_mod, "_start_mjpeg_transcoder", lambda: FakeFFmpeg())
    stop = threading.Event()
    jpegs: list[bytes] = []
    stream = asyncio.create_task(
        manager.async_stream(device, creds, 30.0, jpegs.append, stop.is_set)
    )
    assert await until(lambda: len(jpegs) >= 2)
    opening = asyncio.create_task(
        manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256)
    )
    assert await until(lambda: len(station.opens()) == 1)  # the command is out
    stop.set()  # the view ends immediately, with the answer still 0.3 s away
    assert await asyncio.wait_for(opening, 10) is True
    await asyncio.wait_for(stream, 10)
    assert station.connections == 1
    assert await until(lambda: len(station.disconnect_times) == 1)


async def test_concurrent_door_commands_over_a_live_view_are_serialised(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    station = make_station(stream=True, frame_interval=0.01, ack_delay=0.2)
    monkeypatch.setattr(station_mod, "_start_mjpeg_transcoder", lambda: FakeFFmpeg())
    stop = threading.Event()
    jpegs: list[bytes] = []
    stream = asyncio.create_task(
        manager.async_stream(device, creds, 30.0, jpegs.append, stop.is_set)
    )
    assert await until(lambda: len(jpegs) >= 2)
    first, second = await asyncio.gather(
        manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256),
        manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256),
    )
    assert first is True and second is True  # each got its own answer
    assert len(station.opens()) == 2 and station.connections == 1
    stop.set()
    await asyncio.wait_for(stream, 10)


# --- a stop requested while the session is being set up -------------------------------------------------


async def test_stop_during_setup_prevents_the_retry_and_ffmpeg(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    station = make_station(stream=True, no_video_connections=99)
    started: list[int] = []
    monkeypatch.setattr(
        station_mod,
        "_start_mjpeg_transcoder",
        lambda: started.append(1) or FakeFFmpeg(),
    )
    t0 = time.monotonic()
    frames = await manager.async_stream(
        device, creds, 30.0, lambda jpg: None, lambda: time.monotonic() - t0 > 0.1
    )
    assert frames == 0
    await asyncio.sleep(GAP + MEDIA_START)  # a retry would show up here
    assert station.connections == 1
    assert started == []
    assert await until(lambda: len(station.disconnect_times) == 1)


async def test_stop_set_before_the_first_frame_starts_no_ffmpeg(
    manager: Any,
    device: Device,
    creds: Credentials,
    make_station: Callable[..., FakeStation],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    station = make_station(stream=True)
    started: list[int] = []
    monkeypatch.setattr(
        station_mod,
        "_start_mjpeg_transcoder",
        lambda: started.append(1) or FakeFFmpeg(),
    )
    assert (
        await manager.async_stream(device, creds, 30.0, lambda j: None, lambda: True)
        == 0
    )
    assert started == []
    assert await until(lambda: len(station.disconnect_times) == 1)
