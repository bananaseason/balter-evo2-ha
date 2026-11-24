"""Cloud data coordinator for the Balter EVO 2 Door Station integration.

Polls the Quvii cloud device list on a slow interval. Its jobs:

* keep the weekly-rotating per-device secrets (dynamic password, data-encode key)
  fresh in the cloud client's cache,
* report per-device availability to the entities,
* serve those secrets to the local station code (``async_credentials``), with the
  proven stale fallback: when the cloud is unreachable a cached pair is better
  than nothing, because the secrets rotate only weekly.

All station traffic itself is local (TCP, executor threads); the coordinator only
ever talks to the cloud REST API and therefore never blocks the event loop.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import BalterEvo2ApiError, BalterEvo2AuthError, BalterEvo2CloudClient
from .const import CONF_HOST, DEFAULT_LOCK, DOMAIN, UPDATE_INTERVAL
from .models import Credentials, Device, DeviceState, DoorLock

if TYPE_CHECKING:
    from .models import BalterEvo2ConfigEntry

_LOGGER = logging.getLogger(__name__)


def _credentials_from(raw: Mapping[str, str]) -> Credentials:
    """Build a Credentials object from the cloud client's dict."""
    return Credentials(
        dynamic_password=raw.get("dynamic_password") or "",
        data_encode_key=raw.get("data_encode_key") or "",
        out_auth_code=raw.get("out_auth_code") or None,
    )


class BalterEvo2Coordinator(DataUpdateCoordinator[dict[str, DeviceState]]):
    """Poll the cloud device list; data maps ``duid`` to its :class:`DeviceState`."""

    config_entry: BalterEvo2ConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        entry: BalterEvo2ConfigEntry,
        client: BalterEvo2CloudClient,
    ) -> None:
        """Initialise the coordinator for one config entry."""
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"{DOMAIN} ({entry.title})" if entry.title else DOMAIN,
            update_interval=timedelta(seconds=UPDATE_INTERVAL),
        )
        self._client = client
        # duid -> locks reported by the cloud. Locks change practically never, so
        # they are fetched once per device (and again only after a failed fetch).
        self._locks: dict[str, list[DoorLock]] = {}
        self._locks_complete: set[str] = set()
        self._cloud_outage_logged = False

    # ------------------------------------------------------------ properties

    @property
    def client(self) -> BalterEvo2CloudClient:
        """Return the cloud client used by this coordinator."""
        return self._client

    @property
    def devices(self) -> dict[str, Device]:
        """Return the known stations, keyed by duid."""
        return {duid: state.device for duid, state in (self.data or {}).items()}

    @property
    def locks(self) -> list[DoorLock]:
        """Return all door-release relays of all known stations."""
        return [lock for locks in self._locks.values() for lock in locks]

    def device_online(self, duid: str) -> bool:
        """Return whether the cloud lists the station with usable secrets."""
        state = (self.data or {}).get(duid)
        return state is not None and state.online

    # ---------------------------------------------------------------- update

    def _host_for(self, duid: str, only_device: bool) -> str | None:
        """Resolve the LAN address of a station from the entry options/data.

        ``CONF_HOST`` is either a mapping ``duid -> host`` (per-device options) or,
        for the common single-station account, one plain string.
        """
        entry = self.config_entry
        for source in (entry.options, entry.data):
            value: Any = source.get(CONF_HOST)
            if isinstance(value, Mapping):
                host = value.get(duid)
                if host:
                    return str(host)
            elif value and only_device:
                return str(value)
        return None

    async def _async_update_data(self) -> dict[str, DeviceState]:
        """Fetch the device list (and with it the fresh secrets) from the cloud."""
        try:
            raw_devices = await self._client.get_device_list()
        except BalterEvo2AuthError as err:
            raise ConfigEntryAuthFailed("Cloud login rejected") from err
        except BalterEvo2ApiError as err:
            return self._stale_or_fail(err)

        if self._cloud_outage_logged:
            _LOGGER.info("Quvii cloud reachable again")
            self._cloud_outage_logged = False

        listed = [raw for raw in raw_devices if raw.get("duid")]
        only_device = len(listed) == 1
        data: dict[str, DeviceState] = {}
        for raw in listed:
            duid = raw["duid"]
            credentials = _credentials_from(raw)
            device = Device(
                duid=duid,
                name=raw.get("name") or duid,
                model=raw.get("model") or "",
                host=self._host_for(duid, only_device),
            )
            # Online = the cloud lists the station AND handed out a login secret;
            # without one the station silently rejects every login.
            data[duid] = DeviceState(
                device=device,
                online=bool(credentials.dynamic_password),
                credentials=credentials,
            )

        # Stations that vanished from the account are no longer served.
        for duid in list(self._locks):
            if duid not in data:
                self._locks.pop(duid, None)
                self._locks_complete.discard(duid)

        for state in data.values():
            await self._async_update_locks(state.device)
        return data

    def _stale_or_fail(self, err: BalterEvo2ApiError) -> dict[str, DeviceState]:
        """Cloud unreachable: keep serving the last known data, else fail.

        The first refresh has nothing to fall back on and raises ``UpdateFailed``
        (the entry then retries as "not ready"). Afterwards the station keeps
        working locally with the cached secrets, so entities stay available.
        """
        if not self.data:
            raise UpdateFailed(f"Quvii cloud unreachable: {err}") from err
        if not self._cloud_outage_logged:
            _LOGGER.warning(
                "Quvii cloud unreachable (%s) -- keeping the cached device secrets", err
            )
            self._cloud_outage_logged = True
        return self.data

    async def _async_update_locks(self, device: Device) -> None:
        """Fetch the lock sub-devices of one station once and cache them."""
        if device.duid in self._locks_complete:
            return
        try:
            raw_locks = await self._client.get_subdev_list(device.duid)
        except BalterEvo2AuthError as err:
            raise ConfigEntryAuthFailed("Cloud login rejected") from err
        except BalterEvo2ApiError as err:
            _LOGGER.debug("Lock list for %s unavailable (%s)", device.duid, err)
            # Fall back to the default opener so the entity exists, but try again
            # on the next poll. Never overwrite a list we already have.
            if device.duid not in self._locks:
                raw_locks = [dict(DEFAULT_LOCK)]
            else:
                return
        else:
            if not raw_locks:
                # door=1 / lock=1 is the opener of every EVO 2 station.
                raw_locks = [dict(DEFAULT_LOCK)]
            self._locks_complete.add(device.duid)

        self._locks[device.duid] = [
            DoorLock(
                duid=device.duid,
                code=raw["code"],
                name=raw["name"],
                door=raw["door"],
                locknumber=raw["locknumber"],
                device_name=device.name,
                device_model=device.model,
            )
            for raw in raw_locks
        ]

    # ----------------------------------------------------------- credentials

    async def async_credentials(
        self, duid: str, *, allow_stale: bool = False
    ) -> Credentials:
        """Return the current per-device secrets.

        ``allow_stale`` serves a cached pair (a few hours old at most) without
        waiting for the cloud -- for the latency-critical door-open path. The
        client falls back to its cache when the cloud is down either way.

        Raises :class:`BalterEvo2ApiError` if no usable login secret exists at
        all: a made-up password is indistinguishable from a real one at the
        transport layer, so there is deliberately no offline default.
        """
        raw = await self._client.get_device_credentials(duid, allow_stale=allow_stale)
        credentials = _credentials_from(raw)
        if not credentials.dynamic_password:
            # The client came back empty (cloud down, nothing cached): use what
            # the last successful poll stored, if anything.
            state = (self.data or {}).get(duid)
            if state is not None and state.credentials is not None:
                credentials = state.credentials
        if not credentials.dynamic_password:
            raise BalterEvo2ApiError(
                f"No login credentials available for device {duid}"
            )
        return credentials
