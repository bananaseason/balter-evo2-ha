"""Camera platform for Qualvision video door stations.

One camera per station, built around the fact that the station serves a single
session at a time -- the phone app and the indoor monitor included:

* the entity shows a **stored still** (the last frame of the latest live view)
  and never contacts the station just because a dashboard is on screen;
* a **live view** runs only on demand -- when somebody opens the camera, or an
  automation calls ``balter_evo2.start_live_view`` (e.g. on a doorbell ring) --
  and always ends by itself after the configured duration;
* nothing holds the station between those moments.

The transport and session handling live in :mod:`station`; the rotating secrets
come from the coordinator. The entity/service skeleton is ported from
balter-evo-ha (MIT, https://github.com/LucaHerrero/balter-evo-ha).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
import threading
import time
from collections.abc import Awaitable, Callable
from typing import Any

import voluptuous as vol
from aiohttp import web
from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.core import HomeAssistant, SupportsResponse
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import entity_platform
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.storage import STORAGE_DIR
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from . import BalterEvo2ConfigEntry
from .const import (
    ATTR_DURATION,
    ATTR_END_WHEN_UNWATCHED,
    ATTR_FILENAME,
    ATTR_SECONDS,
    CONF_SNAPSHOT_TTL,
    CONF_STREAM_DURATION,
    DEFAULT_SNAPSHOT_TTL,
    DEFAULT_STREAM_DURATION,
    DOMAIN,
    MANUFACTURER,
    RECORD_CLIP_MAX_SECONDS,
    RECORD_CLIP_MIN_SECONDS,
    SERVICE_RECORD_CLIP,
    SERVICE_REFRESH_SNAPSHOT,
    SERVICE_START_LIVE_VIEW,
    SERVICE_STOP_LIVE_VIEW,
    STREAM_DURATION_MAX,
    STREAM_DURATION_MIN,
    STREAM_STOP_TIMEOUT,
)
from .coordinator import BalterEvo2Coordinator
from .models import Device
from .station import StationManager

_LOGGER = logging.getLogger(__name__)

# After a failed still fetch the station is left alone for this long, so an
# unreachable station is not hammered by every dashboard refresh.
STILL_RETRY_AFTER = 60.0

# A live view somebody opened by looking at it ends this long after the last
# viewer left: the station is to be released at once, the second only bridges a
# frontend that re-opens the feed while it rearranges its page.
UNWATCHED_GRACE = 1.0

# Upper bound of one wait for the next live frame; only a liveness check, the
# viewers are woken by the frames themselves.
FRAME_WAIT = 1.0

# A viewer that has not taken a frame for this long is gone, whatever its
# connection says: a phone app that went to the background, a tablet that fell
# asleep or a client that left the Wi-Fi keeps the connection open without
# reading from it. Left alone it would hold the live view, and with it the
# station, for the whole live view length.
VIEWER_STALL_TIMEOUT = 2.0

# Send buffer of a viewer's connection. The operating system would otherwise
# queue seconds of video for a viewer that stopped reading before a write
# blocks, and the stall above would be noticed that much later.
VIEWER_SEND_BUFFER = 32 * 1024

# The response is laid out exactly like Home Assistant's own MJPEG helper
# (async_get_still_stream), which every frontend and app is known to show.
MJPEG_BOUNDARY = "--frameboundary"
MJPEG_CONTENT_TYPE = f"multipart/x-mixed-replace;boundary={MJPEG_BOUNDARY}"


def _mjpeg_part(jpeg: bytes) -> bytes:
    """Wrap one JPEG as a part of the multipart response."""
    return (
        (
            f"{MJPEG_BOUNDARY}\r\nContent-Type: image/jpeg\r\n"
            f"Content-Length: {len(jpeg)}\r\n\r\n"
        ).encode("ascii")
        + jpeg
        + b"\r\n"
    )


def _bound_send_buffer(request: web.BaseRequest) -> None:
    """Keep little unsent video queued for one viewer (see VIEWER_SEND_BUFFER)."""
    transport = request.transport
    if transport is None:
        return
    sock = transport.get_extra_info("socket")
    if sock is not None:
        with contextlib.suppress(OSError):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, VIEWER_SEND_BUFFER)
    with contextlib.suppress(AttributeError, NotImplementedError, ValueError):
        transport.set_write_buffer_limits(high=VIEWER_SEND_BUFFER)


def still_path(hass: HomeAssistant, entry_id: str, duid: str) -> str:
    """Return where the stored still of a station lives on disk."""
    return hass.config.path(STORAGE_DIR, f"{DOMAIN}.{entry_id}.{duid}.jpg")


async def async_setup_entry(
    hass: HomeAssistant,
    entry: BalterEvo2ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the Qualvision camera entities."""
    data = entry.runtime_data
    snapshot_ttl = float(data.options.get(CONF_SNAPSHOT_TTL, DEFAULT_SNAPSHOT_TTL))
    stream_duration = float(
        data.options.get(CONF_STREAM_DURATION, DEFAULT_STREAM_DURATION)
    )
    async_add_entities(
        BalterEvo2Camera(
            data.coordinator,
            data.manager,
            device,
            entry_id=entry.entry_id,
            snapshot_ttl=snapshot_ttl,
            stream_duration=stream_duration,
        )
        for device in data.devices.values()
    )

    platform = entity_platform.async_get_current_platform()
    platform.async_register_entity_service(
        SERVICE_RECORD_CLIP,
        {
            vol.Required(ATTR_FILENAME): cv.string,
            vol.Optional(ATTR_SECONDS, default=5.0): vol.All(
                vol.Coerce(float),
                vol.Range(min=RECORD_CLIP_MIN_SECONDS, max=RECORD_CLIP_MAX_SECONDS),
            ),
        },
        "async_record_clip",
        supports_response=SupportsResponse.OPTIONAL,
    )
    platform.async_register_entity_service(
        SERVICE_START_LIVE_VIEW,
        {
            vol.Optional(ATTR_DURATION): vol.All(
                vol.Coerce(float),
                vol.Range(min=STREAM_DURATION_MIN, max=STREAM_DURATION_MAX),
            ),
            vol.Optional(ATTR_END_WHEN_UNWATCHED, default=False): cv.boolean,
        },
        "async_start_live_view",
    )
    platform.async_register_entity_service(
        SERVICE_STOP_LIVE_VIEW, None, "async_stop_live_view"
    )
    platform.async_register_entity_service(
        SERVICE_REFRESH_SNAPSHOT, None, "async_refresh_snapshot"
    )


class BalterEvo2Camera(CoordinatorEntity[BalterEvo2Coordinator], Camera):
    """Camera entity for a Qualvision video door station."""

    _attr_has_entity_name = True
    _attr_name = None  # the device name is the camera name
    _attr_icon = "mdi:doorbell-video"
    # No ON_OFF: ``is_on`` is pinned True so the image proxy always serves the
    # stored still. A live view is started by opening the MJPEG feed or by the
    # ``start_live_view`` service; ``is_streaming`` (state ``streaming``) tells
    # whether one is running.
    _attr_supported_features = CameraEntityFeature(0)
    # Only used by Home Assistant's own fallbacks; the MJPEG feed of this entity
    # is driven by the frames themselves (the station delivers ~18 a second).
    _attr_frame_interval = 0.05

    def __init__(
        self,
        coordinator: BalterEvo2Coordinator,
        manager: StationManager,
        device: Device,
        *,
        entry_id: str,
        snapshot_ttl: float,
        stream_duration: float,
    ) -> None:
        """Initialise the doorbell camera entity."""
        CoordinatorEntity.__init__(self, coordinator)
        Camera.__init__(self)
        self._manager = manager
        self._device = device
        self._duid = device.duid
        self._entry_id = entry_id
        self._snapshot_ttl = snapshot_ttl
        self._stream_duration = stream_duration
        self._attr_unique_id = f"{device.duid}_camera"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device.duid)},
            name=device.name,
            manufacturer=MANUFACTURER,
            # Match lock.py: an empty cloud model becomes None, not "".
            model=device.model or None,
        )
        # The stored still and when it was taken (wall clock).
        self._last_image: bytes | None = None
        self._last_image_time: float = 0.0
        self._still_retry_at: float = 0.0
        # Whether the one unasked still fetch (when none is stored yet) was made.
        self._first_still_tried = False
        self._lock = asyncio.Lock()
        # Live-view state. Each live view has its own stop flag, read by the
        # executor thread that runs it; it is never cleared, so a view that was
        # told to stop cannot come back to life.
        self._streaming = False
        self._stop_event: threading.Event | None = None
        self._deadline = 0.0  # time.monotonic() at which the live view ends
        self._live_jpeg: bytes | None = None
        self._stream_task: asyncio.Task | None = None
        self._viewers = 0
        # Replaced (and the old one set) on every live frame, so each viewer
        # wakes exactly once per frame instead of polling.
        self._frame_event = asyncio.Event()
        # True while the live view exists only because somebody is looking at
        # it; such a view ends when the last viewer leaves. A view started by the
        # service (doorbell automation) runs its full duration.
        self._viewer_owned = False
        self._unwatched_handle: asyncio.TimerHandle | None = None

    async def async_added_to_hass(self) -> None:
        """Bring back the stored still, so a restart does not blank the card."""
        await super().async_added_to_hass()
        path = still_path(self.hass, self._entry_id, self._duid)

        def _load() -> tuple[bytes, float] | None:
            try:
                with open(path, "rb") as handle:
                    return handle.read(), os.path.getmtime(path)
            except OSError:
                return None

        stored = await self.hass.async_add_executor_job(_load)
        if stored and stored[0]:
            self._last_image, self._last_image_time = stored

    @property
    def available(self) -> bool:
        """Report availability from the coordinator's per-device online flag."""
        if not super().available:
            return False
        state = self.coordinator.data.get(self._duid)
        return state is not None and state.online

    @property
    def is_on(self) -> bool:
        """Report that the camera is available -- it always is.

        This must NOT be tied to the live view: Home Assistant's image proxy
        answers 503 for a camera whose ``is_on`` is False before the entity is
        ever asked, which would leave every card empty in the normal
        (not-streaming) state -- exactly when the stored still is on offer.
        Whether a live view runs is :attr:`is_streaming`.
        """
        return True

    @property
    def is_streaming(self) -> bool:
        """Return True while a live view is running."""
        return self._streaming

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Expose when the stored still was taken."""
        taken = (
            dt_util.utc_from_timestamp(self._last_image_time).isoformat()
            if self._last_image_time
            else None
        )
        return {"still_taken": taken}

    # --- Live view ------------------------------------------------------------

    def _on_jpeg(self, jpg: bytes) -> None:
        """Handle one decoded live frame (called from the executor thread)."""
        self._live_jpeg = jpg
        self._last_image = jpg
        self._last_image_time = time.time()
        self.hass.loop.call_soon_threadsafe(self._wake_viewers)

    def _wake_viewers(self) -> None:
        event, self._frame_event = self._frame_event, asyncio.Event()
        event.set()

    async def async_start_live_view(
        self, duration: float | None = None, end_when_unwatched: bool = False
    ) -> None:
        """Start a live view that ends by itself (``start_live_view`` service).

        Runs for ``duration`` seconds (default: the configured live-view length).
        By default it runs that long whether or not anybody watches, so the
        stored still is fresh afterwards -- this is what a doorbell automation
        calls. With ``end_when_unwatched`` it also ends shortly after the last
        viewer closed the picture, which suits a dashboard button. A view that is
        already running is kept and runs at least ``duration`` longer; one that
        was started without that flag keeps running in full.
        """
        await self._async_wait_if_stopping()
        if self._streaming:
            self._viewer_owned = self._viewer_owned and end_when_unwatched
        else:
            self._viewer_owned = end_when_unwatched
        if not self._viewer_owned:
            self._cancel_unwatched_stop()
        self._start_stream(duration, extend=True)

    async def async_stop_live_view(self) -> None:
        """Stop the running live view (``stop_live_view`` service)."""
        self._request_stop()

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Start a live view (kept for scripts that call ``camera.turn_on``)."""
        await self.async_start_live_view()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Stop the running live view."""
        await self.async_stop_live_view()

    def _request_stop(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()

    def _is_stopping(self) -> bool:
        """Return whether the running live view is already on its way out."""
        return self._streaming and (
            (self._stop_event is not None and self._stop_event.is_set())
            or time.monotonic() >= self._deadline
        )

    async def _async_wait_if_stopping(self) -> None:
        """Let a live view that is ending finish, so a new one can start."""
        task = self._stream_task
        if self._is_stopping() and task is not None and not task.done():
            await asyncio.wait({task}, timeout=STREAM_STOP_TIMEOUT)

    def _start_stream(
        self, duration: float | None = None, extend: bool = False
    ) -> None:
        length = min(duration or self._stream_duration, STREAM_DURATION_MAX)
        if self._streaming:
            if extend:
                self._deadline = max(self._deadline, time.monotonic() + length)
            return
        stop = threading.Event()
        self._stop_event = stop
        self._deadline = time.monotonic() + length
        self._streaming = True
        self._live_jpeg = None
        self.async_write_ha_state()
        # Background task: Home Assistant does not wait for it on start and
        # cancels it on shutdown.
        self._stream_task = self.hass.async_create_background_task(
            self._run_stream(stop), name=f"{DOMAIN}_stream_{self._duid}"
        )

    async def _run_stream(self, stop: threading.Event) -> None:
        """Drive one bounded live view and release the station afterwards."""
        _LOGGER.debug("Starting a live view for %s", self._duid)
        cancelled = False
        try:
            creds = await self.coordinator.async_credentials(self._duid)
            # The length is enforced through the stop callback so a running view
            # can be prolonged; the manager's own limit is only the hard cap.
            await self._manager.async_stream(
                self._device,
                creds,
                STREAM_DURATION_MAX,
                self._on_jpeg,
                lambda: stop.is_set() or time.monotonic() >= self._deadline,
            )
        except asyncio.CancelledError:
            # Entity removal or shutdown: the executor thread cannot be
            # cancelled, but it reads this flag and lets go of the station.
            cancelled = True
            raise
        except Exception as err:  # noqa: BLE001 -- surface, never crash the loop
            _LOGGER.warning("Live view for %s failed: %s", self._duid, err)
        finally:
            stop.set()
            self._streaming = False
            self._viewer_owned = False
            self._live_jpeg = None
            self._cancel_unwatched_stop()
            self._wake_viewers()
            if not cancelled:
                await self._async_store_still()
                self.async_write_ha_state()

    async def handle_async_mjpeg_stream(self, request: Any) -> Any:
        """Serve the MJPEG feed; opening it starts a live view.

        The response ends when the live view does, so the browser is left with
        the last frame instead of a connection that never finishes. A viewer
        counts only while it takes the frames: one that stops reading is dropped
        (see VIEWER_STALL_TIMEOUT) and no longer keeps the live view alive.
        """
        await self._async_wait_if_stopping()
        if not self._streaming:
            self._viewer_owned = True
            self._start_stream()
        self._viewers += 1
        self._cancel_unwatched_stop()
        try:
            return await self._async_serve_mjpeg(request)
        finally:
            self._viewers -= 1
            if self._viewers <= 0 and self._streaming and self._viewer_owned:
                self._unwatched_handle = self.hass.loop.call_later(
                    UNWATCHED_GRACE, self._stop_if_unwatched
                )

    async def _async_serve_mjpeg(self, request: web.BaseRequest) -> web.StreamResponse:
        """Write the live frames to one viewer until the view ends or it stalls."""
        response = web.StreamResponse()
        response.content_type = MJPEG_CONTENT_TYPE
        await response.prepare(request)
        _bound_send_buffer(request)
        next_frame = self._frame_source()
        first = True
        while (frame := await next_frame()) is not None:
            part = _mjpeg_part(frame)
            try:
                async with asyncio.timeout(VIEWER_STALL_TIMEOUT):
                    await response.write(part)
                    if first:
                        # Chrome shows a frame only when the next one arrives
                        # (https://issues.chromium.org/issues/41199053), so the
                        # first one is sent twice.
                        await response.write(part)
            except TimeoutError:
                _LOGGER.debug(
                    "A viewer of %s took no frame for %.0f s -- dropped",
                    self._duid,
                    VIEWER_STALL_TIMEOUT,
                )
                # The connection is full of video nobody reads; it cannot be
                # finished in an orderly way, so it is cut.
                if request.transport is not None:
                    request.transport.abort()
                break
            first = False
        return response

    def _frame_source(self) -> Callable[[], Awaitable[bytes | None]]:
        """Return a per-viewer callback that yields each live frame once.

        It hands out the stored still first (so the viewer has a picture while
        the station connects), then waits for every new live frame, and returns
        ``None`` once the live view is over -- which ends the MJPEG response.
        """
        sent: bytes | None = None

        async def _next_frame() -> bytes | None:
            nonlocal sent
            while self._streaming:
                frame = self._live_jpeg or self._last_image
                if frame is not None and frame is not sent:
                    sent = frame
                    return frame
                event = self._frame_event
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(event.wait(), FRAME_WAIT)
            return None

        return _next_frame

    def _stop_if_unwatched(self) -> None:
        self._unwatched_handle = None
        if self._viewers <= 0 and self._streaming and self._viewer_owned:
            _LOGGER.debug(
                "Nobody watches %s any more -- ending the live view", self._duid
            )
            self._request_stop()

    def _cancel_unwatched_stop(self) -> None:
        if self._unwatched_handle is not None:
            self._unwatched_handle.cancel()
            self._unwatched_handle = None

    # --- Still image ------------------------------------------------------------

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Return the newest frame without bothering the station.

        During a live view that is its latest frame; otherwise the stored still.
        The station is contacted from here in two cases only: once when no still
        exists at all yet (so a new installation has a picture), and when the
        optional refresh age is set and exceeded.
        """
        if self._streaming:
            return self._live_jpeg or self._last_image
        if self._still_is_due():
            await self._async_fetch_still()
        return self._last_image

    def _still_is_due(self) -> bool:
        now = time.time()
        if now < self._still_retry_at:
            return False
        if self._last_image is None:
            return not self._first_still_tried or self._snapshot_ttl > 0
        return (
            self._snapshot_ttl > 0 and now - self._last_image_time > self._snapshot_ttl
        )

    async def async_refresh_snapshot(self) -> None:
        """Fetch a fresh still now (``refresh_snapshot`` service)."""
        if self._streaming:
            return  # the live view keeps the still fresh on its own
        self._still_retry_at = 0.0
        if not await self._async_fetch_still(force=True):
            raise HomeAssistantError(
                "The door station did not deliver a picture -- it may be busy "
                "with the phone app or a call"
            )

    async def _async_fetch_still(self, force: bool = False) -> bool:
        """Take one still over a short station session (about half a second)."""
        async with self._lock:
            if self._streaming or (not force and not self._still_is_due()):
                return self._last_image is not None
            self._first_still_tried = True
            image: bytes | None = None
            try:
                creds = await self.coordinator.async_credentials(self._duid)
                image = await self._manager.async_snapshot(self._device, creds)
            except Exception as err:  # noqa: BLE001
                _LOGGER.warning("Could not fetch a still for %s: %s", self._duid, err)
            if not image:
                self._still_retry_at = time.time() + STILL_RETRY_AFTER
                return False
            self._last_image = image
            self._last_image_time = time.time()
            self._still_retry_at = 0.0
        await self._async_store_still()
        self.async_write_ha_state()
        return True

    async def _async_store_still(self) -> None:
        """Write the still to disk so it survives a restart."""
        image = self._last_image
        if not image:
            return
        path = still_path(self.hass, self._entry_id, self._duid)

        def _write() -> None:
            tmp = f"{path}.tmp"
            with open(tmp, "wb") as handle:
                handle.write(image)
            os.replace(tmp, path)

        try:
            await self.hass.async_add_executor_job(_write)
        except OSError as err:
            _LOGGER.debug("Could not store the still of %s: %s", self._duid, err)

    async def async_will_remove_from_hass(self) -> None:
        """Stop any running live view when the entity goes away."""
        self._request_stop()
        self._cancel_unwatched_stop()
        task = self._stream_task
        self._stream_task = None
        if task is None or task.done():
            return
        # The runner checks should_stop and releases the slot itself; only cancel
        # if it does not finish in time. asyncio.wait (not await) so it does not
        # swallow a CancelledError of our own task.
        done, _ = await asyncio.wait({task}, timeout=STREAM_STOP_TIMEOUT)
        if not done:
            _LOGGER.warning(
                "Live view for %s did not stop in time -- cancelling it",
                self._duid,
            )
            task.cancel()

    async def async_record_clip(self, seconds: float, filename: str) -> dict[str, Any]:
        """Record a short MP4 clip and write it to ``filename``.

        Backs the ``balter_evo2.record_clip`` entity service. The path must be in
        Home Assistant's allowlist (``allowlist_external_dirs``).
        """
        if not self.hass.config.is_allowed_path(filename):
            raise HomeAssistantError(
                f"Path {filename} is not allowed (see allowlist_external_dirs)"
            )

        async with self._lock:
            creds = await self.coordinator.async_credentials(self._duid)
            clip = await self._manager.async_record_clip(self._device, creds, seconds)

        if not clip:
            raise HomeAssistantError(
                "No video clip received -- the station handshake failed or "
                "ffmpeg is missing"
            )

        def _write() -> None:
            with open(filename, "wb") as fh:
                fh.write(clip)

        await self.hass.async_add_executor_job(_write)
        _LOGGER.info("Wrote %.1fs clip (%d bytes) to %s", seconds, len(clip), filename)
        return {"filename": filename, "size": len(clip), "seconds": seconds}
