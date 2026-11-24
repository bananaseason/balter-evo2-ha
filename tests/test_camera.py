"""Tests of the camera platform: stored still, on-demand live view, MJPEG lifetime.

The integration is set up for real (``MockConfigEntry`` + the real coordinator and
platforms) against a mocked cloud client and a fake ``StationManager`` that stands
in for the whole station layer. That way the entity services registered by the
camera platform, the options and the Home Assistant state machine are all
exercised; only the station session is faked.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import voluptuous as vol
from homeassistant.components.camera import DATA_COMPONENT
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.storage import STORAGE_DIR
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.balter_evo2 import camera as camera_mod
from custom_components.balter_evo2.const import (
    CONF_CLIENT_ID,
    CONF_SNAPSHOT_TTL,
    CONF_STREAM_DURATION,
    DEFAULT_SNAPSHOT_TTL,
    DOMAIN,
    SERVICE_REFRESH_SNAPSHOT,
    SERVICE_START_LIVE_VIEW,
    SERVICE_STOP_LIVE_VIEW,
    STREAM_DURATION_MAX,
)
from custom_components.balter_evo2.station import DoorRejectedError

pytestmark = [pytest.mark.asyncio, pytest.mark.usefixtures("enable_custom_integrations")]

DUID = "duid-one"
ENTITY_ID = "camera.front_door"
STILL = b"\xff\xd8stored-still\xff\xd9"
SNAP = b"\xff\xd8fresh-snapshot\xff\xd9"
ENTRY_ID = "entry1"


def jpeg(n: int) -> bytes:
    return b"\xff\xd8frame-%d\xff\xd9" % n


class FakeManager:
    """Stand-in for ``StationManager``: counts calls, plays a scripted live view."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.snapshot_calls = 0
        self.snapshot_results: list[bytes | Exception | None] = []
        self.stream_calls: list[float] = []
        self.stream_frames: list[bytes] = [jpeg(1), jpeg(2), jpeg(3)]
        self.endless = False  # keep producing new frames until stopped
        self.release = asyncio.Event()  # lets a running view end by itself
        self.stopped_by_caller = 0
        self.released_all = 0
        self.linger = 0.0  # time a view needs to wind down after should_stop
        self.last_should_stop: Callable[[], bool] | None = None
        self.hang = False  # never produce anything, wait for should_stop only
        self.clip: bytes | None = b"fake-mp4"
        self.clip_calls: list[float] = []
        self.door_error: Exception | None = None

    async def async_snapshot(self, device: Any, creds: Any) -> bytes | None:
        self.snapshot_calls += 1
        result = self.snapshot_results.pop(0) if self.snapshot_results else SNAP
        if isinstance(result, Exception):
            raise result
        return result

    async def async_stream(
        self,
        device: Any,
        creds: Any,
        duration: float,
        on_jpeg: Callable[[bytes], None],
        should_stop: Callable[[], bool],
    ) -> int:
        self.stream_calls.append(duration)
        self.last_should_stop = should_stop
        emitted = 0
        if self.hang:
            while not should_stop():
                await asyncio.sleep(0.01)
            self.stopped_by_caller += 1
            return 0
        for frame in self.stream_frames:
            on_jpeg(frame)
            emitted += 1
        n = 100
        while not self.release.is_set():
            if should_stop():
                self.stopped_by_caller += 1
                break
            if self.endless:
                n += 1
                on_jpeg(jpeg(n))
                emitted += 1
            await asyncio.sleep(0.01)
        if self.linger:
            await asyncio.sleep(self.linger)
        return emitted

    async def async_record_clip(self, device: Any, creds: Any, seconds: float) -> bytes | None:
        self.clip_calls.append(seconds)
        return self.clip

    async def async_open_door(self, *args: Any, **kwargs: Any) -> bool:
        if self.door_error is not None:
            raise self.door_error
        return True

    async def async_release_all(self) -> None:
        self.released_all += 1


@pytest.fixture
def storage(hass: HomeAssistant, tmp_path: Any) -> str:
    """Point the config dir at a temp dir with an (empty) ``.storage``."""
    hass.config.config_dir = str(tmp_path)
    os.makedirs(tmp_path / STORAGE_DIR)
    return str(tmp_path / STORAGE_DIR / f"{DOMAIN}.{ENTRY_ID}.{DUID}.jpg")


@pytest.fixture
def manager() -> FakeManager:
    return FakeManager()


@pytest.fixture
def setup_camera(
    hass: HomeAssistant, manager: FakeManager, storage: str
) -> Iterator[Callable[..., Any]]:
    """Return an async ``setup(options=None)`` that loads the integration."""
    entries: list[MockConfigEntry] = []
    client = MagicMock()
    client.get_device_list = AsyncMock(
        return_value=[
            {
                "duid": DUID,
                "name": "Front door",
                "model": "IDS94A6FW",
                "dynamic_password": "p" * 96,
                "data_encode_key": "k" * 32,
            }
        ]
    )
    client.get_subdev_list = AsyncMock(return_value=[])
    client.get_device_credentials = AsyncMock(
        return_value={"dynamic_password": "p" * 96, "data_encode_key": "k" * 32}
    )
    client.async_close = AsyncMock(return_value=None)

    async def setup(
        options: dict[str, Any] | None = None,
        *,
        minor_version: int = 2,
        version: int = 1,
        expect_ok: bool = True,
    ) -> MockConfigEntry:
        entry = MockConfigEntry(
            domain=DOMAIN,
            entry_id=ENTRY_ID,
            minor_version=minor_version,
            unique_id="user@example.com",
            title="user@example.com",
            version=version,
            data={
                CONF_EMAIL: "user@example.com",
                CONF_PASSWORD: "not-a-real-password",
                CONF_CLIENT_ID: "0123456789abcdef",
            },
            options={"host": "192.0.2.72", **(options or {})},
        )
        entry.add_to_hass(hass)
        entries.append(entry)
        # The manifest depends on the ffmpeg component, whose setup probes the
        # binary; ffmpeg is not needed (nor wanted) here.
        hass.config.components.add("ffmpeg")
        ok = await hass.config_entries.async_setup(entry.entry_id)
        assert ok is expect_ok
        await hass.async_block_till_done()
        return entry

    with (
        patch("custom_components.balter_evo2.BalterEvo2CloudClient", return_value=client),
        patch("custom_components.balter_evo2.StationManager", return_value=manager),
    ):
        yield setup


def entity(hass: HomeAssistant) -> camera_mod.BalterEvo2Camera:
    cam = hass.data[DATA_COMPONENT].get_entity(ENTITY_ID)
    assert cam is not None
    return cam


async def until(predicate: Callable[[], bool], timeout: float = 5.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return predicate()


def state_of(hass: HomeAssistant) -> str:
    state = hass.states.get(ENTITY_ID)
    assert state is not None
    return state.state


async def call(hass: HomeAssistant, service: str, **data: Any) -> None:
    await hass.services.async_call(
        DOMAIN, service, {"entity_id": ENTITY_ID, **data}, blocking=True
    )


def write_still(path: str, data: bytes, age: float = 0.0) -> None:
    with open(path, "wb") as handle:
        handle.write(data)
    if age:
        old = time.time() - age
        os.utime(path, (old, old))


def read_still(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


async def test_defaults() -> None:
    assert DEFAULT_SNAPSHOT_TTL == 0  # never refresh by itself
    assert camera_mod.STILL_RETRY_AFTER > 0
    assert camera_mod.UNWATCHED_GRACE > 0


# --- stored still ---------------------------------------------------------------------------


async def test_stored_still_is_served_without_touching_the_station(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager, storage: str
) -> None:
    write_still(storage, STILL, age=7 * 86400)  # a week old: still not refreshed
    await setup_camera()
    cam = entity(hass)
    for _ in range(3):
        assert await cam.async_camera_image() == STILL
    assert manager.snapshot_calls == 0
    assert manager.stream_calls == []


async def test_still_is_loaded_from_disk_when_the_entity_is_added(
    hass: HomeAssistant, setup_camera: Any, storage: str
) -> None:
    write_still(storage, STILL)
    mtime = os.path.getmtime(storage)
    await setup_camera()
    state = hass.states.get(ENTITY_ID)
    assert state is not None and state.state == "idle"
    assert state.attributes["still_taken"] == dt_util.utc_from_timestamp(mtime).isoformat()
    assert await entity(hass).async_camera_image() == STILL


async def test_a_corrupt_empty_still_file_counts_as_no_still(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager, storage: str
) -> None:
    write_still(storage, b"")
    await setup_camera()
    assert hass.states.get(ENTITY_ID).attributes["still_taken"] is None
    assert await entity(hass).async_camera_image() == SNAP  # fetched, not served empty
    assert manager.snapshot_calls == 1


async def test_no_still_at_all_fetches_exactly_once_and_stores_it(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager, storage: str
) -> None:
    await setup_camera()
    cam = entity(hass)
    assert hass.states.get(ENTITY_ID).attributes["still_taken"] is None
    assert await cam.async_camera_image() == SNAP
    assert manager.snapshot_calls == 1
    assert read_still(storage) == SNAP  # persisted
    assert hass.states.get(ENTITY_ID).attributes["still_taken"] is not None
    # now it is stored: no more station traffic
    assert await cam.async_camera_image() == SNAP
    assert manager.snapshot_calls == 1


async def test_concurrent_requests_share_one_snapshot(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager
) -> None:
    await setup_camera()
    cam = entity(hass)
    results = await asyncio.gather(*(cam.async_camera_image() for _ in range(5)))
    assert results == [SNAP] * 5
    assert manager.snapshot_calls == 1


@pytest.mark.parametrize("failure", [None, RuntimeError("station down")])
async def test_failed_still_is_not_retried_within_still_retry_after(
    hass: HomeAssistant,
    setup_camera: Any,
    manager: FakeManager,
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception | None,
) -> None:
    now = [1_800_000_000.0]
    monkeypatch.setattr(camera_mod, "time", SimpleNamespace(time=lambda: now[0]))
    manager.snapshot_results = [failure, failure, SNAP]
    await setup_camera({CONF_SNAPSHOT_TTL: 300})  # with ttl 0 a failure is final
    cam = entity(hass)

    assert await cam.async_camera_image() is None
    assert manager.snapshot_calls == 1
    now[0] += camera_mod.STILL_RETRY_AFTER - 1
    assert await cam.async_camera_image() is None
    assert await cam.async_camera_image() is None
    assert manager.snapshot_calls == 1  # not hammered by every dashboard refresh

    now[0] += 2  # the retry window is over
    assert await cam.async_camera_image() is None  # second scripted failure
    assert manager.snapshot_calls == 2
    now[0] += camera_mod.STILL_RETRY_AFTER + 1
    assert await cam.async_camera_image() == SNAP
    assert manager.snapshot_calls == 3


@pytest.mark.parametrize("failure", [None, RuntimeError("station down")])
async def test_without_ttl_a_failed_first_fetch_is_never_repeated_by_image_requests(
    hass: HomeAssistant,
    setup_camera: Any,
    manager: FakeManager,
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception | None,
    storage: str,
) -> None:
    now = [1_800_000_000.0]
    monkeypatch.setattr(camera_mod, "time", SimpleNamespace(time=lambda: now[0]))
    manager.snapshot_results = [failure, SNAP]
    await setup_camera()  # snapshot_ttl defaults to 0
    cam = entity(hass)
    assert await cam.async_camera_image() is None
    for _ in range(3):
        now[0] += camera_mod.STILL_RETRY_AFTER * 10  # long past any retry window
        assert await cam.async_camera_image() is None
    assert manager.snapshot_calls == 1
    # only an explicit refresh produces a still then
    await call(hass, SERVICE_REFRESH_SNAPSHOT)
    assert manager.snapshot_calls == 2
    assert await cam.async_camera_image() == SNAP
    assert read_still(storage) == SNAP


async def test_without_ttl_a_live_view_produces_the_still_after_a_failed_fetch(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager
) -> None:
    manager.snapshot_results = [None]
    await setup_camera()
    cam = entity(hass)
    assert await cam.async_camera_image() is None
    await call(hass, SERVICE_START_LIVE_VIEW)
    assert await until(lambda: cam._live_jpeg == jpeg(3))
    manager.release.set()
    assert await until(lambda: state_of(hass) == "idle")
    assert await cam.async_camera_image() == jpeg(3)
    assert manager.snapshot_calls == 1


async def test_the_first_fetch_happens_once_per_entity_lifetime(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager
) -> None:
    """A fetch that succeeded is not a reason to fetch again, nor is a lost still."""
    await setup_camera()
    cam = entity(hass)
    assert await cam.async_camera_image() == SNAP
    cam._last_image = None  # (as if it had been lost)
    assert await cam.async_camera_image() is None
    assert manager.snapshot_calls == 1


async def test_snapshot_ttl_refreshes_an_old_still_only_when_exceeded(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager, storage: str
) -> None:
    write_still(storage, STILL, age=600)
    await setup_camera({CONF_SNAPSHOT_TTL: 300})
    cam = entity(hass)
    assert await cam.async_camera_image() == SNAP  # 600 s > 300 s
    assert manager.snapshot_calls == 1
    assert await cam.async_camera_image() == SNAP  # fresh now
    assert manager.snapshot_calls == 1


async def test_snapshot_ttl_not_exceeded_keeps_the_still(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager, storage: str
) -> None:
    write_still(storage, STILL, age=10)
    await setup_camera({CONF_SNAPSHOT_TTL: 300})
    assert await entity(hass).async_camera_image() == STILL
    assert manager.snapshot_calls == 0


async def test_failed_refresh_with_ttl_keeps_serving_the_old_still(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager, storage: str
) -> None:
    write_still(storage, STILL, age=600)
    manager.snapshot_results = [None]
    await setup_camera({CONF_SNAPSHOT_TTL: 300})
    cam = entity(hass)
    assert await cam.async_camera_image() == STILL
    assert await cam.async_camera_image() == STILL
    assert manager.snapshot_calls == 1  # and left alone for STILL_RETRY_AFTER


# --- refresh_snapshot service ---------------------------------------------------------------------


async def test_refresh_snapshot_service_replaces_the_still(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager, storage: str
) -> None:
    write_still(storage, STILL)
    await setup_camera()
    await call(hass, SERVICE_REFRESH_SNAPSHOT)
    assert manager.snapshot_calls == 1
    assert await entity(hass).async_camera_image() == SNAP
    assert read_still(storage) == SNAP


async def test_refresh_snapshot_failure_raises_and_ignores_the_retry_window(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager, storage: str
) -> None:
    write_still(storage, STILL)
    manager.snapshot_results = [None, SNAP]
    await setup_camera()
    with pytest.raises(HomeAssistantError):
        await call(hass, SERVICE_REFRESH_SNAPSHOT)
    assert await entity(hass).async_camera_image() == STILL  # old still survives
    await call(hass, SERVICE_REFRESH_SNAPSHOT)  # an explicit request is not throttled
    assert manager.snapshot_calls == 2
    assert await entity(hass).async_camera_image() == SNAP


# --- live view ---------------------------------------------------------------------------------------


async def test_start_live_view_streams_then_returns_to_idle_and_keeps_the_last_frame(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager, storage: str
) -> None:
    write_still(storage, STILL)
    await setup_camera()
    cam = entity(hass)
    assert state_of(hass) == "idle"

    await call(hass, SERVICE_START_LIVE_VIEW)
    assert state_of(hass) == "streaming"
    assert await until(lambda: manager.stream_calls != [])
    # the manager only gets the hard cap; the real length is the should_stop callback
    assert manager.stream_calls == [STREAM_DURATION_MAX]
    # while it runs, the newest live frame is the image, not the stored still
    assert await until(lambda: cam._live_jpeg == jpeg(3))
    assert await cam.async_camera_image() == jpeg(3)
    assert manager.snapshot_calls == 0
    assert read_still(storage) == STILL  # not written per frame

    manager.release.set()  # the fake stream ends by itself
    assert await until(lambda: state_of(hass) == "idle")
    assert not cam.is_streaming
    # the last frame is the still now, in memory and on disk
    assert await cam.async_camera_image() == jpeg(3)
    assert read_still(storage) == jpeg(3)
    assert hass.states.get(ENTITY_ID).attributes["still_taken"] is not None
    assert manager.snapshot_calls == 0
    assert manager.stream_calls == [STREAM_DURATION_MAX]


async def test_the_view_length_is_enforced_through_should_stop(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager
) -> None:
    await setup_camera()
    cam = entity(hass)
    started = time.monotonic()
    await cam.async_start_live_view(duration=0.4)  # (below the service minimum)
    assert state_of(hass) == "streaming"
    assert await until(lambda: state_of(hass) == "idle")
    assert 0.35 <= time.monotonic() - started < 3
    assert manager.stream_calls == [STREAM_DURATION_MAX]
    assert manager.last_should_stop() is True
    assert manager.stopped_by_caller == 1


async def test_default_duration_is_the_configured_one(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager
) -> None:
    await setup_camera({CONF_STREAM_DURATION: 45})
    cam = entity(hass)
    await call(hass, SERVICE_START_LIVE_VIEW)
    assert 40 < cam._deadline - time.monotonic() <= 45
    await call(hass, SERVICE_START_LIVE_VIEW, duration=120)  # prolongs
    assert 115 < cam._deadline - time.monotonic() <= 120
    await call(hass, SERVICE_START_LIVE_VIEW, duration=20)  # never shortens
    assert 115 < cam._deadline - time.monotonic() <= 120
    assert len(manager.stream_calls) <= 1
    await call(hass, SERVICE_STOP_LIVE_VIEW)
    assert await until(lambda: state_of(hass) == "idle")


async def test_start_on_a_running_view_prolongs_it(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager
) -> None:
    await setup_camera()
    cam = entity(hass)
    await cam.async_start_live_view(duration=0.4)
    await asyncio.sleep(0.2)
    await cam.async_start_live_view(duration=0.8)  # now + 0.8 s
    await asyncio.sleep(0.5)  # past the first deadline
    assert state_of(hass) == "streaming"
    assert len(manager.stream_calls) == 1
    assert await until(lambda: state_of(hass) == "idle")


async def test_a_viewer_joining_does_not_prolong_the_view(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager, hass_client: Any
) -> None:
    await setup_camera()
    cam = entity(hass)
    await cam.async_start_live_view(duration=0.6)
    deadline = cam._deadline
    client = await hass_client()
    resp = await client.get(f"/api/camera_proxy_stream/{ENTITY_ID}")
    assert resp.status == 200
    assert cam._deadline == deadline
    await asyncio.wait_for(resp.read(), 5)  # the response ends with the view
    assert await until(lambda: state_of(hass) == "idle")


async def test_start_waits_for_a_stopping_view_and_then_starts_a_new_one(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager
) -> None:
    manager.linger = 0.3  # the old view needs a moment to release the station
    await setup_camera()
    await call(hass, SERVICE_START_LIVE_VIEW)
    assert await until(lambda: manager.stream_calls != [])
    first_stop = manager.last_should_stop
    await call(hass, SERVICE_STOP_LIVE_VIEW)
    started = time.monotonic()
    await call(hass, SERVICE_START_LIVE_VIEW)  # must not be swallowed by the old one
    assert time.monotonic() - started >= 0.2  # it waited for the old view
    assert state_of(hass) == "streaming"
    assert await until(lambda: len(manager.stream_calls) == 2)
    assert first_stop() is True
    await asyncio.sleep(0.5)  # the old view's stop flag does not kill the new one
    assert state_of(hass) == "streaming"
    assert manager.last_should_stop() is False
    manager.linger = 0
    await call(hass, SERVICE_STOP_LIVE_VIEW)
    assert await until(lambda: state_of(hass) == "idle")


async def test_a_feed_opened_while_a_view_stops_gets_a_fresh_view(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager, hass_client: Any
) -> None:
    manager.linger = 0.3
    manager.endless = True
    await setup_camera()
    await call(hass, SERVICE_START_LIVE_VIEW)
    assert await until(lambda: manager.stream_calls != [])
    await call(hass, SERVICE_STOP_LIVE_VIEW)
    client = await hass_client()
    resp = await client.get(f"/api/camera_proxy_stream/{ENTITY_ID}")
    assert resp.status == 200
    await resp.content.readany()
    assert len(manager.stream_calls) == 2
    assert state_of(hass) == "streaming"
    resp.close()
    manager.linger = 0
    await call(hass, SERVICE_STOP_LIVE_VIEW)
    assert await until(lambda: state_of(hass) == "idle")


async def test_cancelling_the_stream_task_leaves_the_stop_flag_set(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager
) -> None:
    """Shutdown cancels the task while the manager is still "connecting"."""
    manager.hang = True
    await setup_camera()
    cam = entity(hass)
    await call(hass, SERVICE_START_LIVE_VIEW)
    assert await until(lambda: manager.stream_calls != [])
    assert manager.last_should_stop() is False
    task = cam._stream_task
    task.cancel()
    await asyncio.wait({task}, timeout=2)
    assert manager.last_should_stop() is True  # the executor thread will let go
    assert not cam.is_streaming


async def test_unloading_while_the_manager_is_still_connecting_returns(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager
) -> None:
    manager.hang = True  # blocks until should_stop() is true
    entry = await setup_camera()
    await call(hass, SERVICE_START_LIVE_VIEW)
    assert await until(lambda: manager.stream_calls != [])
    assert await asyncio.wait_for(hass.config_entries.async_unload(entry.entry_id), 10)
    assert manager.stopped_by_caller == 1
    assert manager.last_should_stop() is True


@pytest.mark.parametrize("duration", [1, 9, 301, 99999])
async def test_start_live_view_rejects_an_out_of_range_duration(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager, duration: float
) -> None:
    await setup_camera()
    with pytest.raises(vol.Invalid):
        await call(hass, SERVICE_START_LIVE_VIEW, duration=duration)
    assert manager.stream_calls == []


async def test_second_start_while_streaming_does_not_open_a_second_view(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager
) -> None:
    await setup_camera()
    await call(hass, SERVICE_START_LIVE_VIEW)
    await call(hass, SERVICE_START_LIVE_VIEW)
    assert await until(lambda: manager.stream_calls != [])
    await asyncio.sleep(0.1)
    assert len(manager.stream_calls) == 1
    manager.release.set()
    assert await until(lambda: state_of(hass) == "idle")


async def test_stop_live_view_ends_the_view_early(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager, storage: str
) -> None:
    await setup_camera()
    await call(hass, SERVICE_START_LIVE_VIEW)
    assert await until(lambda: manager.stream_calls != [])
    await call(hass, SERVICE_STOP_LIVE_VIEW)
    assert await until(lambda: state_of(hass) == "idle")
    assert manager.stopped_by_caller == 1
    assert read_still(storage) == jpeg(3)


async def test_stop_live_view_when_idle_is_harmless(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager
) -> None:
    await setup_camera()
    await call(hass, SERVICE_STOP_LIVE_VIEW)
    await call(hass, SERVICE_START_LIVE_VIEW)  # and it does not poison the next view
    assert state_of(hass) == "streaming"
    assert await until(lambda: manager.stream_calls != [])
    await asyncio.sleep(0.1)
    assert state_of(hass) == "streaming"
    manager.release.set()
    assert await until(lambda: state_of(hass) == "idle")


async def test_refresh_snapshot_during_a_live_view_is_a_noop(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager
) -> None:
    await setup_camera()
    await call(hass, SERVICE_START_LIVE_VIEW)
    await call(hass, SERVICE_REFRESH_SNAPSHOT)
    assert manager.snapshot_calls == 0
    manager.release.set()
    assert await until(lambda: state_of(hass) == "idle")


async def test_a_failing_live_view_ends_idle_and_keeps_the_old_still(
    hass: HomeAssistant,
    setup_camera: Any,
    manager: FakeManager,
    storage: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_still(storage, STILL)
    await setup_camera()

    async def boom(*args: Any, **kwargs: Any) -> int:
        raise RuntimeError("station busy")

    monkeypatch.setattr(manager, "async_stream", boom)
    await call(hass, SERVICE_START_LIVE_VIEW)
    assert await until(lambda: state_of(hass) == "idle")
    assert await entity(hass).async_camera_image() == STILL
    assert read_still(storage) == STILL


async def test_unloading_the_entry_stops_a_running_view(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager
) -> None:
    entry = await setup_camera()
    await call(hass, SERVICE_START_LIVE_VIEW)
    assert await until(lambda: manager.stream_calls != [])
    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
    assert manager.stopped_by_caller == 1
    assert manager.released_all == 1


async def test_camera_entity_basics(hass: HomeAssistant, setup_camera: Any) -> None:
    await setup_camera()
    cam = entity(hass)
    assert cam.is_on is True  # pinned: the image proxy must serve the still
    assert cam.available
    assert er.async_get(hass).async_get(ENTITY_ID).unique_id == f"{DUID}_camera"


# --- MJPEG viewer lifetime ----------------------------------------------------------------------------


async def test_mjpeg_view_starts_a_live_view_and_the_response_ends_with_it(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager, hass_client: Any
) -> None:
    await setup_camera()
    client = await hass_client()
    manager.stream_frames = [jpeg(1), jpeg(2)]
    request = asyncio.create_task(client.get(f"/api/camera_proxy_stream/{ENTITY_ID}"))
    assert await until(lambda: state_of(hass) == "streaming")
    assert await until(lambda: manager.stream_calls != [])
    await asyncio.sleep(0.3)
    manager.release.set()  # the live view is over ...
    resp = await asyncio.wait_for(request, 5)
    body = await asyncio.wait_for(resp.read(), 5)  # ... so the body is complete
    assert resp.status == 200
    assert jpeg(2) in body
    assert await until(lambda: state_of(hass) == "idle")


async def test_viewer_started_view_ends_shortly_after_the_last_viewer_leaves(
    hass: HomeAssistant,
    setup_camera: Any,
    manager: FakeManager,
    hass_client: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(camera_mod, "UNWATCHED_GRACE", 0.3)
    manager.endless = True  # keeps producing frames, so a gone viewer is noticed
    await setup_camera()
    client = await hass_client()
    resp = await client.get(f"/api/camera_proxy_stream/{ENTITY_ID}")
    assert resp.status == 200
    await resp.content.readany()
    assert state_of(hass) == "streaming"
    left = time.monotonic()
    resp.close()
    assert await until(lambda: state_of(hass) == "idle", 5)
    assert time.monotonic() - left >= 0.3  # not before the grace period
    assert manager.stopped_by_caller == 1  # ended by the camera, not by itself
    assert entity(hass)._last_image is not None


async def test_service_started_view_survives_its_viewer_leaving(
    hass: HomeAssistant,
    setup_camera: Any,
    manager: FakeManager,
    hass_client: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(camera_mod, "UNWATCHED_GRACE", 0.2)
    manager.endless = True
    await setup_camera()
    await call(hass, SERVICE_START_LIVE_VIEW)  # e.g. a doorbell automation
    client = await hass_client()
    resp = await client.get(f"/api/camera_proxy_stream/{ENTITY_ID}")
    await resp.content.readany()
    resp.close()
    await asyncio.sleep(0.8)  # well past the grace period
    assert state_of(hass) == "streaming"  # the automation's view runs its duration
    assert manager.stopped_by_caller == 0
    await call(hass, SERVICE_STOP_LIVE_VIEW)
    assert await until(lambda: state_of(hass) == "idle")


async def test_service_start_takes_over_a_viewer_owned_view(
    hass: HomeAssistant,
    setup_camera: Any,
    manager: FakeManager,
    hass_client: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(camera_mod, "UNWATCHED_GRACE", 0.2)
    manager.endless = True
    await setup_camera()
    client = await hass_client()
    resp = await client.get(f"/api/camera_proxy_stream/{ENTITY_ID}")
    await resp.content.readany()
    await call(hass, SERVICE_START_LIVE_VIEW)  # a view is running: keep it, own it
    resp.close()
    await asyncio.sleep(0.8)
    assert state_of(hass) == "streaming"
    assert len(manager.stream_calls) == 1
    await call(hass, SERVICE_STOP_LIVE_VIEW)
    assert await until(lambda: state_of(hass) == "idle")


# --- record_clip through the service layer -------------------------------------------------------------


async def test_record_clip_service_writes_the_file_and_returns_details(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager, tmp_path: Any
) -> None:
    await setup_camera()
    hass.config.allowlist_external_dirs = {str(tmp_path)}
    target = str(tmp_path / "clip.mp4")
    result = await hass.services.async_call(
        DOMAIN,
        "record_clip",
        {"entity_id": ENTITY_ID, "filename": target, "seconds": 7},
        blocking=True,
        return_response=True,
    )
    assert manager.clip_calls == [7.0]
    assert open(target, "rb").read() == b"fake-mp4"
    assert result[ENTITY_ID] == {"filename": target, "size": 8, "seconds": 7.0}


async def test_record_clip_service_refuses_a_path_outside_the_allowlist(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager, tmp_path: Any
) -> None:
    await setup_camera()
    hass.config.allowlist_external_dirs = {str(tmp_path / "allowed")}
    target = str(tmp_path / "clip.mp4")
    with pytest.raises(HomeAssistantError):
        await hass.services.async_call(
            DOMAIN,
            "record_clip",
            {"entity_id": ENTITY_ID, "filename": target},
            blocking=True,
        )
    assert manager.clip_calls == [] and not os.path.exists(target)


@pytest.mark.parametrize("seconds", [0, 31])
async def test_record_clip_service_validates_the_length(
    hass: HomeAssistant, setup_camera: Any, tmp_path: Any, seconds: float
) -> None:
    await setup_camera()
    hass.config.allowlist_external_dirs = {str(tmp_path)}
    with pytest.raises(vol.Invalid):
        await hass.services.async_call(
            DOMAIN,
            "record_clip",
            {"entity_id": ENTITY_ID, "filename": str(tmp_path / "c.mp4"), "seconds": seconds},
            blocking=True,
        )


async def test_record_clip_service_without_video_raises_and_writes_nothing(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager, tmp_path: Any
) -> None:
    manager.clip = None
    await setup_camera()
    hass.config.allowlist_external_dirs = {str(tmp_path)}
    target = str(tmp_path / "clip.mp4")
    with pytest.raises(HomeAssistantError):
        await hass.services.async_call(
            DOMAIN,
            "record_clip",
            {"entity_id": ENTITY_ID, "filename": target},
            blocking=True,
        )
    assert not os.path.exists(target)


# --- lock: a refused PIN ---------------------------------------------------------------------------------


def _lock_entity_id(hass: HomeAssistant) -> str:
    reg = er.async_get(hass)
    ids = [e.entity_id for e in reg.entities.values() if e.platform == DOMAIN and e.domain == "lock"]
    assert len(ids) == 1
    return ids[0]


async def test_a_refused_pin_raises_a_clear_error_and_creates_no_notification(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager
) -> None:
    manager.door_error = DoorRejectedError("refused (answer 0100)")
    await setup_camera()
    lock_id = _lock_entity_id(hass)
    with patch("homeassistant.components.persistent_notification.async_create") as note:
        with pytest.raises(HomeAssistantError, match="PIN"):
            await hass.services.async_call(
                "lock", "unlock", {"entity_id": lock_id}, blocking=True
            )
    assert hass.states.get(lock_id).state == "locked"  # not reported as opened
    assert not note.called


async def test_an_acked_unlock_flips_the_state_without_a_notification(
    hass: HomeAssistant, setup_camera: Any, manager: FakeManager
) -> None:
    await setup_camera()
    lock_id = _lock_entity_id(hass)
    with patch("homeassistant.components.persistent_notification.async_create") as note:
        await hass.services.async_call(
            "lock", "unlock", {"entity_id": lock_id}, blocking=True
        )
    assert hass.states.get(lock_id).state == "unlocked"
    assert not note.called


# --- migration (1.1 -> 1.2) and removal ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("old", "kept"),
    [
        ({"enable_audio": False, "snapshot_ttl": 90, "warm_idle": 10}, {}),
        ({"enable_audio": True, "snapshot_ttl": 90.0, "warm_idle": 10.0}, {}),
        ({"snapshot_ttl": 120, "warm_idle": 5}, {"snapshot_ttl": 120, "warm_idle": 5}),
        ({"snapshot_ttl": 90, "warm_idle": 5}, {"warm_idle": 5}),
        (
            {"snapshot_ttl": 120, "warm_idle": 10, "stream_duration": 90, "door_pin": "1234"},
            {"snapshot_ttl": 120, "stream_duration": 90, "door_pin": "1234"},
        ),
    ],
)
async def test_migration_drops_only_the_old_defaults(
    hass: HomeAssistant, setup_camera: Any, old: dict[str, Any], kept: dict[str, Any]
) -> None:
    entry = await setup_camera(old, minor_version=1)
    assert entry.state is ConfigEntryState.LOADED
    assert entry.minor_version == 2
    assert entry.options == {"host": "192.0.2.72", **kept}
    assert "enable_audio" not in entry.options


async def test_migration_leaves_a_current_entry_alone(
    hass: HomeAssistant, setup_camera: Any
) -> None:
    opts = {"snapshot_ttl": 90, "warm_idle": 10}  # chosen on purpose after 1.2
    entry = await setup_camera(opts, minor_version=2)
    assert entry.options == {"host": "192.0.2.72", **opts}


async def test_an_entry_of_a_newer_major_version_is_refused(
    hass: HomeAssistant, setup_camera: Any
) -> None:
    entry = await setup_camera({"snapshot_ttl": 90}, version=2, expect_ok=False)
    assert entry.state is ConfigEntryState.MIGRATION_ERROR
    assert entry.options["snapshot_ttl"] == 90  # untouched


async def test_config_flow_writes_the_current_minor_version() -> None:
    from custom_components.balter_evo2.config_flow import BalterEvo2ConfigFlow

    assert (BalterEvo2ConfigFlow.VERSION, BalterEvo2ConfigFlow.MINOR_VERSION) == (1, 2)


async def test_removing_the_entry_deletes_only_its_own_stills(
    hass: HomeAssistant, setup_camera: Any, storage: str
) -> None:
    folder = os.path.dirname(storage)
    other = os.path.join(folder, f"{DOMAIN}.otherentry.{DUID}.jpg")
    unrelated = os.path.join(folder, "something.else.jpg")
    legacy = os.path.join(folder, f"{DOMAIN}.{DUID}.jpg")  # pre-1.1 name: not ours
    for path in (storage, other, unrelated, legacy):
        write_still(path, STILL)
    entry = await setup_camera()
    await hass.config_entries.async_remove(entry.entry_id)
    await hass.async_block_till_done()
    assert not os.path.exists(storage)
    assert os.path.exists(other) and os.path.exists(unrelated) and os.path.exists(legacy)
