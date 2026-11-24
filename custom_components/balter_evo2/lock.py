"""Lock entities for each Qualvision door-release relay.

Each relay is momentary: the station buzzes the door open and re-locks on its
own, so the entity is an optimistic (assumed-state) lock that flips to
``unlocked`` on a confirmed open and back to ``locked`` after a short delay. The
open command travels over the direct TCP transport via the StationManager.

NOTE ON VOICE EXPOSURE: a door opener should not be voice-operable. Integration
code CANNOT remove an entity from Assist's default exposure -- ``lock`` is in
Home Assistant's default-exposed domains, so this entity is auto-exposed to the
conversation agent unless the user removes it manually (Settings > Voice
assistants > Expose, or ``homeassistant.expose_entity``). The diagnostics
``lock_exposed_to_assist`` flag only *reports* the current exposure; it does not
enforce anything. The README documents the required manual step. Ported from
balter-evo-ha (MIT, https://github.com/LucaHerrero/balter-evo-ha).
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from homeassistant.components.lock import LockEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.event import async_call_later
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import BalterEvo2ConfigEntry
from .api import BalterEvo2ApiError
from .const import CONF_DOOR_PIN, DOMAIN, MANUFACTURER, RELOCK_DELAY
from .coordinator import BalterEvo2Coordinator
from .models import Device, DoorLock
from .station import (
    DOOR_WRONG_PIN,
    DoorRejectedError,
    StationBusyError,
    StationManager,
    StationSilentError,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: BalterEvo2ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Create one lock entity per discovered door-release relay."""
    data = entry.runtime_data
    pin = data.options.get(CONF_DOOR_PIN, "")
    entities: list[BalterEvo2DoorLock] = []
    for lock in data.locks:
        device = data.devices.get(lock.duid)
        if device is None:
            continue
        entities.append(
            BalterEvo2DoorLock(data.coordinator, data.manager, device, lock, pin)
        )
    async_add_entities(entities)


class BalterEvo2DoorLock(CoordinatorEntity[BalterEvo2Coordinator], LockEntity):
    """A single door-release relay, exposed as an optimistic (momentary) lock."""

    _attr_has_entity_name = True
    _attr_assumed_state = True
    _attr_icon = "mdi:door"

    def __init__(
        self,
        coordinator: BalterEvo2Coordinator,
        manager: StationManager,
        device: Device,
        lock: DoorLock,
        pin: str,
    ) -> None:
        """Initialise one door-release relay entity."""
        CoordinatorEntity.__init__(self, coordinator)
        self._manager = manager
        self._device = device
        self._lock = lock
        self._pin = pin
        self._duid = lock.duid
        self._attr_is_locked = True
        self._relock_unsub: Any = None
        self._attr_unique_id = f"{lock.duid}_{lock.code}"
        self._attr_name = lock.name
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, lock.duid)},
            name=lock.device_name,
            manufacturer=MANUFACTURER,
            model=lock.device_model or None,
        )

    @property
    def available(self) -> bool:
        """Report availability from the coordinator's per-device online flag."""
        if not super().available:
            return False
        state = self.coordinator.data.get(self._duid)
        return state is not None and state.online

    async def async_unlock(self, **kwargs: Any) -> None:
        """Trigger the door-release relay over the direct TCP transport."""
        _LOGGER.info("Door unlock requested for %s (%s)", self.name, self._duid)
        try:
            # dynamic_password and data_encode_key rotate weekly -- always fetch
            # fresh (cached). allow_stale: on the way to the door a slow or broken
            # cloud connection must not hold up the command; a pair from this
            # morning is practically always still valid and is refreshed in the
            # background.
            # async_credentials raises BalterEvo2ApiError when no usable password
            # exists (handled below), so creds.dynamic_password is always set here.
            creds = await self.coordinator.async_credentials(
                self._duid, allow_stale=True
            )

            # Without a configured PIN, use the cloud out-auth-code: verified that
            # out_auth_code == SHA256(<door PIN>), so the device gets the same hash
            # either way.
            pin_sha256 = None if self._pin else (creds.out_auth_code or None)

            # The station refuses a wrong PIN (see DoorRejectedError below). The
            # cloud knows the right hash, so a mismatch is already visible here.
            expected_hash = creds.out_auth_code or ""
            if self._pin and expected_hash:
                own_hash = hashlib.sha256(self._pin.encode("utf-8")).hexdigest()
                if own_hash != expected_hash:
                    _LOGGER.warning(
                        "The door PIN stored in Home Assistant does not match the "
                        "station's out-auth-code. The station will refuse the "
                        "command. Correct the PIN in the integration "
                        "options or leave it empty to use the cloud hash."
                    )
                else:
                    pin_sha256 = expected_hash

            if self._pin and pin_sha256 is None:
                pin_sha256 = hashlib.sha256(self._pin.encode("utf-8")).hexdigest()

            success = await self._manager.async_open_door(
                self._device,
                creds,
                self._lock.door,
                self._lock.locknumber,
                pin_sha256,
            )
            if not success:
                # Sent but never acked -- NEVER auto-retry (double-open risk).
                raise HomeAssistantError(
                    "The door opener did not acknowledge the command. The door "
                    "was probably not opened; do not retry automatically."
                )
        except DoorRejectedError as err:
            _LOGGER.warning("Door unlock refused by %s: %s", self._duid, err)
            if err.answer[:2] == DOOR_WRONG_PIN:
                raise HomeAssistantError(
                    "The door station refused the command: the door PIN is wrong. "
                    "Correct it in the integration options, or leave it empty to "
                    "use the code registered for the station."
                ) from err
            raise HomeAssistantError(
                f"The door station refused to open this lock (answer "
                f"{err.answer.hex() or 'none'}). The door PIN was accepted; the "
                "station does not know this lock."
            ) from err
        except StationSilentError as err:
            # The station never answered, so it accepted no session: the next
            # attempt may start immediately, no recovery gap needed.
            _LOGGER.warning("Door unlock could not start: %s", err)
            raise HomeAssistantError(
                "The door station did not answer the connection attempt. "
                "Please open again right away."
            ) from err
        except StationBusyError as err:
            # The command provably never went out -> safe to try again later.
            _LOGGER.warning("Door unlock could not start: %s", err)
            raise HomeAssistantError(
                "The door station is busy with another session (the phone app or "
                "the indoor monitor?) and did not accept the command. Nothing was "
                "sent; try again in a few seconds."
            ) from err
        except BalterEvo2ApiError as err:
            # No usable login secret could be loaded (cloud down, nothing cached).
            _LOGGER.warning("Door unlock could not start: %s", err)
            raise HomeAssistantError(
                "The door station credentials could not be loaded from the cloud. "
                "Check the internet connection; if the error persists, "
                "re-authenticate the integration."
            ) from err
        except HomeAssistantError:
            raise
        except Exception as err:  # noqa: BLE001 -- show network/protocol errors
            _LOGGER.error("Door unlock failed: %s", err)
            raise HomeAssistantError(f"Door open failed: {err}") from err

        # The station confirmed that it opened; the entity shows "unlocked" for
        # RELOCK_DELAY seconds as the feedback for users who cannot hear the buzzer.
        _LOGGER.info(
            "Door unlock confirmed by device for %s (%s)", self.name, self._duid
        )
        self._attr_is_locked = False
        self.async_write_ha_state()
        self._schedule_relock()

    async def async_lock(self, **kwargs: Any) -> None:
        """Reset the shown state to locked (the relay re-locks on its own)."""
        self._cancel_relock()
        self._attr_is_locked = True
        self.async_write_ha_state()

    @callback
    def _schedule_relock(self) -> None:
        self._cancel_relock()
        self._relock_unsub = async_call_later(self.hass, RELOCK_DELAY, self._relock)

    @callback
    def _relock(self, _now: Any) -> None:
        self._relock_unsub = None
        self._attr_is_locked = True
        self.async_write_ha_state()

    @callback
    def _cancel_relock(self) -> None:
        if self._relock_unsub is not None:
            self._relock_unsub()
            self._relock_unsub = None

    async def async_will_remove_from_hass(self) -> None:
        """Cancel the pending optimistic re-lock."""
        self._cancel_relock()
