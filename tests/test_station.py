"""Tests of ``StationManager``: the executor boundary and the single-session slot.

The blocking transport is replaced by ``FakeTransport`` (same interface as
``TcpStationTransport``), so these tests cover the orchestration only: one session
at a time per station, the recovery gap between sessions, warm-idle hold, release
on unload and the door-open error mapping (never retry an unacked open).

Seams assumed from the plan: ``station.TcpStationTransport`` is the transport class
the manager instantiates, ``StationManager(hass, host_resolver)`` takes a callable
``duid -> host``, and ``SESSION_MIN_GAP`` / ``DEFAULT_WARM_IDLE`` are module-level
constants of ``station`` (patched here to keep the tests fast).
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from conftest import (
    TEST_DUID,
    TEST_KEY,
    TEST_PIN_SHA256,
    build_media_frame,
    make_h264_keyframe,
)
from homeassistant.core import HomeAssistant

from custom_components.balter_evo2 import media as media_mod
from custom_components.balter_evo2 import station as station_mod
from custom_components.balter_evo2.models import Credentials, Device
from custom_components.balter_evo2.transport import (
    StationBusyError,
    StationSilentError,
    TransportError,
)

pytestmark = [pytest.mark.asyncio, pytest.mark.usefixtures("enable_custom_integrations")]

GAP = 0.4
FAKE_JPEG = b"\xff\xd8fake-jpeg\xff\xd9"
FAKE_MP4 = b"fake-mp4"


class Behaviour:
    """Knobs shared by every FakeTransport created during one test."""

    connect_error: Exception | None = None
    open_result: bool = True
    send_frames: int = 3
    hold_until: threading.Event | None = None  # run_until blocks on this when set

    def __init__(self) -> None:
        self.instances: list[FakeTransport] = []
        self.log: list[tuple[str, float]] = []


class FakeTransport:
    """Stand-in for TcpStationTransport (same public interface)."""

    behaviour = Behaviour()

    def __init__(self, host: str, port: int, duid: str, dynamic_password: str,
                 data_encode_key: str, client_id: str, oem: str, enable_audio: bool = False) -> None:
        self.host, self.port, self.duid = host, port, duid
        self.logged_in = threading.Event()
        self.device_ready = threading.Event()
        self.station_silent = False
        self.closed = False
        self.opens: list[tuple[int, int, str]] = []
        self._sink: Callable[[int, bytes], None] | None = None
        self.connected_at = 0.0
        self.closed_at = 0.0
        self.behaviour.instances.append(self)

    def __enter__(self) -> FakeTransport:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def is_alive(self) -> bool:
        return not self.closed

    def connect(self, timeout: float = 8.0) -> bool:
        self.connected_at = time.monotonic()
        self.behaviour.log.append(("connect", self.connected_at))
        err = self.behaviour.connect_error
        if err is not None:
            self.station_silent = isinstance(err, StationSilentError)
            raise err
        self.logged_in.set()
        self.device_ready.set()
        return True

    def set_media_sink(self, cb: Callable[[int, bytes], None]) -> None:
        self._sink = cb

    def send_ctrl(self, ftype: int, msg: int, payload: bytes, msg13: int = 0) -> tuple[int, int]:
        return (ftype, msg13)

    def send_session_setup(self) -> None:
        return None

    def send_open(self, door: int, locknumber: int, pin_sha256: str) -> bool:
        self.opens.append((door, locknumber, pin_sha256))
        return self.behaviour.open_result

    def run_until(self, deadline: float, until: Callable[[], bool] | None = None) -> None:
        if self._sink is not None:
            frame = build_media_frame(TEST_KEY, make_h264_keyframe())
            for _ in range(self.behaviour.send_frames):
                self._sink(0xA0, frame)
        hold = self.behaviour.hold_until
        if hold is None:
            return
        while time.monotonic() < deadline:
            if (until is not None and until()) or hold.is_set():
                return
            time.sleep(0.01)

    def wait(self, event: threading.Event, timeout: float) -> bool:
        return event.wait(timeout)

    def handshake_states(self) -> str:
        return "fake"

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self.closed_at = time.monotonic()
            self.behaviour.log.append(("close", self.closed_at))


class _FakeFFmpeg:
    """Stand-in for the ffmpeg transcoder Popen (no real binary in the tests).

    stdin/stdout are None so the reader/pump worker threads return at once; the
    live-stream path then holds the station slot in ``run_until`` exactly as it
    would with a real transcoder, without needing ffmpeg installed.
    """

    stdin = None
    stdout = None

    def wait(self, timeout: float | None = None) -> int:
        return 0

    def terminate(self) -> None:
        return None


@pytest.fixture
def behaviour(monkeypatch: pytest.MonkeyPatch) -> Iterator[Behaviour]:
    b = Behaviour()
    FakeTransport.behaviour = b
    monkeypatch.setattr(station_mod, "TcpStationTransport", FakeTransport)
    monkeypatch.setattr(station_mod, "SESSION_MIN_GAP", GAP, raising=False)
    monkeypatch.setattr(station_mod, "DEFAULT_WARM_IDLE", 0.0, raising=False)
    # The live stream shells out to ffmpeg; replace it so the tests do not need a
    # real binary (they exercise the slot orchestration, not transcoding).
    monkeypatch.setattr(station_mod, "_start_mjpeg_transcoder", lambda: _FakeFFmpeg())
    monkeypatch.setattr(station_mod, "_stop_ffmpeg", lambda ffmpeg: None)
    for mod in (station_mod, media_mod):
        monkeypatch.setattr(mod, "decode_media", lambda frames, keys: b"\x00\x00\x00\x01\x67h264", raising=False)
        monkeypatch.setattr(mod, "h264_to_jpeg", lambda h264: FAKE_JPEG, raising=False)
        monkeypatch.setattr(mod, "h264_to_mp4", lambda h264, seconds: FAKE_MP4, raising=False)
    yield b
    FakeTransport.behaviour = Behaviour()


@pytest.fixture
def device() -> Device:
    return Device(duid=TEST_DUID, name="Door", model="IDS94A6FW", host="127.0.0.1")


@pytest.fixture
def creds() -> Credentials:
    return Credentials(dynamic_password="p" * 96, data_encode_key="k" * 32, out_auth_code=TEST_PIN_SHA256)


@pytest.fixture
def manager(hass: HomeAssistant, behaviour: Behaviour) -> Any:
    return station_mod.StationManager(hass, lambda duid: "127.0.0.1")


# --- snapshot ----------------------------------------------------------------------------------


async def test_snapshot_returns_jpeg_and_closes_session(manager: Any, device: Device, creds: Credentials,
                                                        behaviour: Behaviour) -> None:
    image = await manager.async_snapshot(device, creds)
    assert image == FAKE_JPEG
    assert len(behaviour.instances) == 1
    assert behaviour.instances[0].closed  # warm idle 0 -> not kept open
    assert behaviour.instances[0].host == "127.0.0.1"


async def test_snapshot_never_blocks_the_event_loop(manager: Any, device: Device, creds: Credentials,
                                                    behaviour: Behaviour) -> None:
    """The loop keeps ticking while the (blocking) transport runs in an executor."""
    ticks = 0

    async def ticker() -> None:
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0.01)

    task = asyncio.create_task(ticker())
    behaviour.hold_until = threading.Event()
    snap = asyncio.create_task(manager.async_snapshot(device, creds))
    await asyncio.sleep(0.3)
    assert ticks > 5
    behaviour.hold_until.set()
    await snap
    task.cancel()


async def test_snapshot_none_when_no_decodable_frame(manager: Any, device: Device, creds: Credentials,
                                                     behaviour: Behaviour, monkeypatch: pytest.MonkeyPatch) -> None:
    for mod in (station_mod, media_mod):
        monkeypatch.setattr(mod, "decode_media", lambda frames, keys: None, raising=False)
    assert await manager.async_snapshot(device, creds) is None


# --- single session slot + recovery gap -----------------------------------------------------------


async def test_running_stream_blocks_concurrent_snapshot(manager: Any, device: Device, creds: Credentials,
                                                         behaviour: Behaviour) -> None:
    behaviour.hold_until = threading.Event()  # the stream runs until released
    stop = threading.Event()
    jpegs: list[bytes] = []
    stream = asyncio.create_task(
        manager.async_stream(device, creds, 30.0, jpegs.append, stop.is_set)
    )
    await asyncio.sleep(0.3)
    assert len(behaviour.instances) == 1

    snap = asyncio.create_task(manager.async_snapshot(device, creds))
    await asyncio.sleep(0.5)
    assert not snap.done()  # waits for the slot
    assert len(behaviour.instances) == 1  # no second session while one is running

    stop.set()
    behaviour.hold_until.set()
    await asyncio.wait_for(stream, 10)
    assert await asyncio.wait_for(snap, 10) == FAKE_JPEG
    assert len(behaviour.instances) == 2
    assert isinstance(jpegs, list)


async def test_min_gap_between_sessions(manager: Any, device: Device, creds: Credentials,
                                        behaviour: Behaviour) -> None:
    await manager.async_snapshot(device, creds)
    await manager.async_snapshot(device, creds)
    first, second = behaviour.instances
    assert first.closed_at > 0
    assert second.connected_at - first.closed_at >= GAP * 0.9


async def test_gap_is_per_station(manager: Any, device: Device, creds: Credentials,
                                  behaviour: Behaviour) -> None:
    other = Device(duid="otherduid", name="Other", model="x", host="127.0.0.2")
    await manager.async_snapshot(device, creds)
    t0 = time.monotonic()
    await manager.async_snapshot(other, creds)
    assert time.monotonic() - t0 < GAP  # a different station has its own slot


# --- warm idle / release --------------------------------------------------------------------------------


async def test_release_all_closes_warm_session(hass: HomeAssistant, manager: Any, device: Device, creds: Credentials,
                                               behaviour: Behaviour, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(station_mod, "DEFAULT_WARM_IDLE", 30.0, raising=False)
    manager = station_mod.StationManager(hass, lambda duid: "127.0.0.1")
    await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256)
    transport = behaviour.instances[0]
    assert transport.closed is False  # kept warm for the next press
    await manager.async_release_all()
    assert transport.closed is True


async def test_release_all_without_sessions_is_noop(manager: Any) -> None:
    await manager.async_release_all()
    await manager.async_release_all()


# --- record clip ---------------------------------------------------------------------------------------------


async def test_record_clip_returns_mp4(manager: Any, device: Device, creds: Credentials) -> None:
    assert await manager.async_record_clip(device, creds, 3) == FAKE_MP4


# --- door open -------------------------------------------------------------------------------------------------


async def test_open_door_true_only_on_ack(manager: Any, device: Device, creds: Credentials,
                                          behaviour: Behaviour) -> None:
    behaviour.open_result = True
    assert await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256) is True
    assert behaviour.instances[0].opens == [(1, 1, TEST_PIN_SHA256)]


async def test_open_door_unacked_is_hard_error_and_never_retried(manager: Any, device: Device,
                                                                 creds: Credentials, behaviour: Behaviour) -> None:
    behaviour.open_result = False
    try:
        result = await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256)
    except TransportError:
        result = False
    assert result is False
    assert sum(len(t.opens) for t in behaviour.instances) == 1  # sent exactly once
    assert len(behaviour.instances) == 1  # and no reconnect-and-resend


async def test_open_door_silent_station(manager: Any, device: Device, creds: Credentials,
                                        behaviour: Behaviour) -> None:
    behaviour.connect_error = StationSilentError("no answer")
    with pytest.raises(StationSilentError):
        await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256)
    assert len(behaviour.instances) == 1  # one attempt, no hidden retry
    assert sum(len(t.opens) for t in behaviour.instances) == 0


async def test_open_door_busy_station(manager: Any, device: Device, creds: Credentials,
                                      behaviour: Behaviour) -> None:
    behaviour.connect_error = StationBusyError("busy")
    with pytest.raises(StationBusyError):
        await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256)
    assert len(behaviour.instances) == 1
    assert sum(len(t.opens) for t in behaviour.instances) == 0


async def test_silent_error_skips_recovery_gap(manager: Any, device: Device, creds: Credentials,
                                               behaviour: Behaviour) -> None:
    """A station that never answered never took a session: retry right away."""
    behaviour.connect_error = StationSilentError("no answer")
    with pytest.raises(StationSilentError):
        await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256)
    behaviour.connect_error = None
    t0 = time.monotonic()
    assert await manager.async_open_door(device, creds, 1, 1, TEST_PIN_SHA256) is True
    assert time.monotonic() - t0 < GAP
