"""Camera platform for Qualvision video door stations.

One camera per station. Designed for on-demand snapshot access with no
continuous background streaming, so the station's single session slot is never
held open and the doorbell / phone app are never starved. Ported from
balter-evo-ha (MIT, https://github.com/LucaHerrero/balter-evo-ha); the P2P calls
are replaced by the StationManager (direct TCP transport) and the rotating
secrets come from the coordinator.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import voluptuous as vol
from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.core import HomeAssistant, SupportsResponse
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import entity_platform
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import BalterEvo2ConfigEntry
from .const import (
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
    STREAM_STOP_TIMEOUT,
)
from .coordinator import BalterEvo2Coordinator
from .models import Device
from .station import StationManager

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: BalterEvo2ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the Qualvision camera entities."""
    data = entry.runtime_data
    snapshot_ttl = float(
        data.options.get(CONF_SNAPSHOT_TTL, DEFAULT_SNAPSHOT_TTL)
    )
    stream_duration = float(
        data.options.get(CONF_STREAM_DURATION, DEFAULT_STREAM_DURATION)
    )
    async_add_entities(
        BalterEvo2Camera(
            data.coordinator,
            data.manager,
            device,
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
                vol.Range(
                    min=RECORD_CLIP_MIN_SECONDS, max=RECORD_CLIP_MAX_SECONDS
                ),
            ),
        },
        "async_record_clip",
        supports_response=SupportsResponse.OPTIONAL,
    )


class BalterEvo2Camera(CoordinatorEntity[BalterEvo2Coordinator], Camera):
    """Camera entity for a Qualvision video door station."""

    _attr_has_entity_name = True
    _attr_name = None  # the device name is the camera name
    _attr_icon = "mdi:doorbell-video"
    # No ON_OFF: ``is_on`` is pinned True so the image proxy always serves the
    # cached snapshot, so a camera.turn_on/off toggle could never reflect state
    # and would misrepresent the entity. Live streaming starts on its own when a
    # viewer opens the MJPEG feed (see handle_async_mjpeg_stream); ``is_streaming``
    # reports whether it is running.
    _attr_supported_features = CameraEntityFeature(0)
    # Poll rate of the default MJPEG loop: while a stream runs it reads the newest
    # JPEG ~11x/s -> fluid video instead of a slideshow.
    _attr_frame_interval = 0.09

    def __init__(
        self,
        coordinator: BalterEvo2Coordinator,
        manager: StationManager,
        device: Device,
        *,
        snapshot_ttl: float,
        stream_duration: float,
    ) -> None:
        """Initialise the doorbell camera entity."""
        CoordinatorEntity.__init__(self, coordinator)
        Camera.__init__(self)
        self._manager = manager
        self._device = device
        self._duid = device.duid
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
        self._last_image: bytes | None = None
        self._last_image_time: float = 0.0
        self._lock = asyncio.Lock()
        # Live-stream state.
        self._streaming = False
        self._stop_stream = False
        self._live_jpeg: bytes | None = None
        self._stream_task: asyncio.Task | None = None

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

        This must NOT be tied to the live stream: Home Assistant's image proxy
        answers 503 for a camera whose ``is_on`` is False before the entity is
        ever asked, which would leave every snapshot card empty in the normal
        (not-streaming) state -- exactly when a still image is on offer. Whether
        a stream runs is :attr:`is_streaming`.
        """
        return True

    @property
    def is_streaming(self) -> bool:
        """Return True while a live stream is running."""
        return self._streaming

    def _on_jpeg(self, jpg: bytes) -> None:
        """Handle one decoded live frame (called from the executor thread)."""
        self._live_jpeg = jpg
        self._last_image = jpg
        self._last_image_time = time.time()

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Start a bounded live stream (auto-stops after the configured duration)."""
        if self._streaming:
            return
        self._stop_stream = False
        self._streaming = True
        self.async_write_ha_state()
        # Background task: Home Assistant does not wait for it on start and tears
        # it down on shutdown.
        self._stream_task = self.hass.async_create_background_task(
            self._run_stream(), name=f"{DOMAIN}_stream_{self._duid}"
        )

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Stop the running live stream."""
        self._stop_stream = True

    async def _run_stream(self) -> None:
        """Drive one bounded live stream and release the station slot afterwards."""
        _LOGGER.info("Starting live stream for %s", self._duid)
        try:
            creds = await self.coordinator.async_credentials(self._duid)
            await self._manager.async_stream(
                self._device,
                creds,
                self._stream_duration,
                self._on_jpeg,
                lambda: self._stop_stream,
            )
        except Exception as err:  # noqa: BLE001 -- surface, never crash the loop
            _LOGGER.warning("Live stream for %s failed: %s", self._duid, err)
        finally:
            self._streaming = False
            self._stop_stream = False
            self._live_jpeg = None
            self.async_write_ha_state()

    async def handle_async_mjpeg_stream(self, request: Any) -> Any:
        """Serve the MJPEG feed, auto-starting the stream when a viewer opens it."""
        if not self._streaming:
            await self.async_turn_on()
        return await super().handle_async_mjpeg_stream(request)

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Return the current frame.

        While a live stream runs, serve its newest decoded frame (this is what
        makes the MJPEG feed move). Otherwise fetch a single cached snapshot over
        one short station session, so the door intercom is never held open.
        """
        if self._streaming and self._live_jpeg:
            return self._live_jpeg

        now = time.time()
        if self._last_image and (now - self._last_image_time < self._snapshot_ttl):
            return self._last_image

        async with self._lock:
            # Re-check the cache after acquiring the lock.
            if self._last_image and (
                time.time() - self._last_image_time < self._snapshot_ttl
            ):
                return self._last_image

            try:
                creds = await self.coordinator.async_credentials(self._duid)
                image_bytes = await self._manager.async_snapshot(
                    self._device, creds
                )
                if image_bytes:
                    self._last_image = image_bytes
                    self._last_image_time = time.time()
                    return image_bytes
            except Exception as err:  # noqa: BLE001
                _LOGGER.warning(
                    "Could not fetch snapshot for %s: %s", self._duid, err
                )

        return self._last_image

    async def async_will_remove_from_hass(self) -> None:
        """Stop any running stream when the entity goes away."""
        self._stop_stream = True
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
                "Live stream for %s did not stop in time -- cancelling it",
                self._duid,
            )
            task.cancel()

    async def async_record_clip(
        self, seconds: float, filename: str
    ) -> dict[str, Any]:
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
            clip = await self._manager.async_record_clip(
                self._device, creds, seconds
            )

        if not clip:
            raise HomeAssistantError(
                "No video clip received -- the station handshake failed or "
                "ffmpeg is missing"
            )

        def _write() -> None:
            with open(filename, "wb") as fh:
                fh.write(clip)

        await self.hass.async_add_executor_job(_write)
        _LOGGER.info(
            "Wrote %.1fs clip (%d bytes) to %s", seconds, len(clip), filename
        )
        return {"filename": filename, "size": len(clip), "seconds": seconds}
