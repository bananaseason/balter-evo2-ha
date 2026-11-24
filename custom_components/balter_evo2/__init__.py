"""The Balter EVO 2 Door Station integration.

Brings a Qualvision / Quvii / Homaxi door station (sold as Balter EVO, among
others) into Home Assistant over a direct LAN TCP connection to the station,
with the rotating per-device secrets fetched from the Quvii cloud.

Cloud discovery, the cloud REST client and the application-layer frame formats
were reverse-engineered by the community integration balter-evo-ha (MIT,
https://github.com/LucaHerrero/balter-evo-ha); the pieces reused here keep that
attribution. This integration is unofficial and not affiliated with Qualvision,
Quvii, Balter or Homaxi.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import secrets
from collections.abc import Mapping
from dataclasses import replace

from homeassistant.components.frontend import add_extra_js_url
from homeassistant.components.http import StaticPathConfig
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD, EVENT_HOMEASSISTANT_STOP
from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.helpers import aiohttp_client
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.storage import STORAGE_DIR
from homeassistant.helpers.typing import ConfigType
from homeassistant.loader import async_get_integration

from . import websocket
from .api import BalterEvo2CloudClient
from .call import DATA_CALLS, CallManager
from .const import (
    CARD_FILE,
    CARD_URL,
    CONF_CLIENT_ID,
    CONF_HOST,
    CONF_SNAPSHOT_TTL,
    CONF_WARM_IDLE,
    DEFAULT_WARM_IDLE,
    DOMAIN,
    PLATFORMS,
)
from .coordinator import BalterEvo2Coordinator
from .models import (
    BalterEvo2ConfigEntry,
    Device,
    RuntimeData,
)
from .station import StationManager

_LOGGER = logging.getLogger(__name__)

# Re-exported so the platforms can type their config entry as
# ``BalterEvo2ConfigEntry`` without importing from models directly.
__all__ = ["BalterEvo2ConfigEntry"]

HEX16 = re.compile(r"^[0-9a-f]{16}$")

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up what serves every entry: the call card and its websocket API."""
    if DATA_CALLS in hass.data:
        return True
    manager = hass.data[DATA_CALLS] = CallManager(hass)
    websocket.async_register(hass)

    @callback
    def _stop(_event: Event) -> None:
        manager.end_all()

    hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _stop)
    await _async_register_card(hass)
    return True


async def _async_register_card(hass: HomeAssistant) -> None:
    """Serve the call card and load it on every frontend page.

    The version in the URL makes browsers and the phone app fetch the card anew
    after an update of the integration.
    """
    integration = await async_get_integration(hass, DOMAIN)
    path = os.path.join(os.path.dirname(__file__), CARD_FILE)
    await hass.http.async_register_static_paths(
        [StaticPathConfig(CARD_URL, path, cache_headers=False)]
    )
    add_extra_js_url(hass, f"{CARD_URL}?v={integration.version}")


def _client_identity(hass: HomeAssistant, entry: BalterEvo2ConfigEntry) -> str:
    """Return the 16-hex installation id, generating and persisting one if absent.

    A single self-generated client id is used for the cloud login and for the
    station LOGIN frame; the station accepts any 16-hex id (verified live), so no
    registration is needed. Entries that predate the id (or carry a malformed
    one) are repaired in place.
    """
    data = dict(entry.data)
    client_id = (data.get(CONF_CLIENT_ID) or "").strip().lower()
    if not HEX16.match(client_id):
        client_id = secrets.token_hex(8)
        data[CONF_CLIENT_ID] = client_id
        hass.config_entries.async_update_entry(entry, data=data)
        _LOGGER.debug("Generated a new 16-hex client id for this installation")
    return client_id


def _host_resolver(entry: BalterEvo2ConfigEntry):
    """Return a callable that resolves the current LAN host of a device.

    The options host (set in the config flow / reconfigure step) wins over the
    address stored on the device, so a station that moved on the LAN can be
    pointed at its new address without re-adding the integration.

    ``CONF_HOST`` is normally a plain string, but the coordinator's resolver also
    accepts a ``duid -> host`` mapping; this mirrors that so the two never
    disagree (and ``resolve`` never returns the whole mapping as a host).
    """

    def resolve(device: Device) -> str | None:
        for source in (entry.options, entry.data):
            value = source.get(CONF_HOST)
            if isinstance(value, Mapping):
                host = value.get(device.duid)
                if host:
                    return str(host)
            elif value:
                return str(value)
        return device.host

    return resolve


async def async_setup_entry(hass: HomeAssistant, entry: BalterEvo2ConfigEntry) -> bool:
    """Set up Qualvision from a config entry."""
    client_id = _client_identity(hass, entry)
    client = BalterEvo2CloudClient(
        aiohttp_client.async_get_clientsession(hass),
        entry.data[CONF_EMAIL],
        entry.data[CONF_PASSWORD],
        client_id=client_id,
    )

    coordinator = BalterEvo2Coordinator(hass, entry, client)
    # Gates setup: raises ConfigEntryNotReady when the cloud is unreachable and
    # ConfigEntryAuthFailed when the credentials are rejected.
    await coordinator.async_config_entry_first_refresh()

    resolve_host = _host_resolver(entry)

    # Resolve each station's current LAN host. The door-release relays were
    # already fetched by the coordinator's first refresh (its ``locks`` property
    # is the single source of truth), so they are not fetched again here.
    devices: dict[str, Device] = {}
    for duid, state in coordinator.data.items():
        device = state.device
        host = resolve_host(device)
        if host and host != device.host:
            device = replace(device, host=host)
        devices[duid] = device

    manager = StationManager(
        hass,
        resolve_host,
        client_id,
        warm_idle=float(entry.options.get(CONF_WARM_IDLE, DEFAULT_WARM_IDLE)),
    )

    entry.runtime_data = RuntimeData(
        client=client,
        coordinator=coordinator,
        manager=manager,
        client_id=client_id,
        devices=devices,
        locks=coordinator.locks,
        options=dict(entry.options),
    )

    entry.async_on_unload(entry.add_update_listener(async_reload_entry))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: BalterEvo2ConfigEntry) -> bool:
    """Unload a config entry, leaving nothing of ours running.

    A warm station session would keep occupying the station's single slot (also
    for the doorbell and the phone app) until its hold time expires, so it is
    released explicitly; the cloud client's aiohttp session is closed too.
    """
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        data = entry.runtime_data
        await data.manager.async_release_all()
        await data.client.async_close()
    return unloaded


async def async_remove_entry(hass: HomeAssistant, entry: BalterEvo2ConfigEntry) -> None:
    """Delete the entry's stored stills when it is removed for good."""
    storage = hass.config.path(STORAGE_DIR)

    def _purge() -> None:
        with contextlib.suppress(OSError):
            for name in os.listdir(storage):
                if name.startswith(f"{DOMAIN}.{entry.entry_id}.") and name.endswith(
                    ".jpg"
                ):
                    with contextlib.suppress(OSError):
                        os.remove(os.path.join(storage, name))

    await hass.async_add_executor_job(_purge)


async def async_reload_entry(hass: HomeAssistant, entry: BalterEvo2ConfigEntry) -> None:
    """Reload the entry when its options change (host, PIN, warm idle, ...)."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_migrate_entry(
    hass: HomeAssistant, entry: BalterEvo2ConfigEntry
) -> bool:
    """Migrate an old config entry to the current schema.

    1.1 -> 1.2 (integration 1.1.0): the options form of 1.0.0 stored its
    defaults whenever it was saved -- a still refresh every 90 s and a 10 s
    session hold. Both now default to off, so values that are exactly the old
    defaults are dropped (a value somebody chose is kept); the audio option is
    gone. A future major version is refused rather than risking a mangled entry.
    """
    if entry.version > 1:
        # Entry written by a newer version than this one -- do not touch it.
        return False
    if entry.minor_version < 2:
        options = dict(entry.options)
        options.pop("enable_audio", None)
        if options.get(CONF_SNAPSHOT_TTL) == 90:
            options.pop(CONF_SNAPSHOT_TTL)
        if options.get(CONF_WARM_IDLE) == 10:
            options.pop(CONF_WARM_IDLE)
        hass.config_entries.async_update_entry(entry, options=options, minor_version=2)
    return True
