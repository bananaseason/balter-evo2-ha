"""Diagnostics for the Balter EVO 2 Door Station integration.

Everything here is redacted for safe inclusion in a public bug report: the
account e-mail/password, the rotating device secrets and the door PIN never
appear. No raw video is ever included.
"""

from __future__ import annotations

import contextlib
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import DeviceEntry

from .const import DOMAIN
from .models import BalterEvo2ConfigEntry

TO_REDACT = {
    "password",
    "data_encode_key",
    "dynamic_password",
    "out_auth_code",
    "door_pin",
    "email",
}


def _handshake_states(entry: BalterEvo2ConfigEntry) -> Any:
    """Return the station manager's last handshake state(s), if it exposes them."""
    manager = entry.runtime_data.manager
    states = getattr(manager, "handshake_states", None)
    if not callable(states):
        return None
    with contextlib.suppress(Exception):
        return states()
    return None


def _lock_exposed_to_assist(hass: HomeAssistant, entry: BalterEvo2ConfigEntry) -> Any:
    """Advisory flag: are any lock entities exposed to the voice assistant?

    A door opener should stay out of voice control. This cannot be enforced from
    integration code, so it is only reported here for awareness.
    """
    registry = er.async_get(hass)
    lock_entities = [
        reg_entry.entity_id
        for reg_entry in er.async_entries_for_config_entry(
            registry, entry.entry_id
        )
        if reg_entry.domain == "lock"
    ]
    if not lock_entities:
        return None

    try:
        from homeassistant.components.homeassistant.exposed_entities import (
            async_should_expose,
        )
    except ImportError:
        return "unknown"

    exposed: dict[str, bool] = {}
    for entity_id in lock_entities:
        with contextlib.suppress(Exception):
            exposed[entity_id] = async_should_expose(
                hass, "conversation", entity_id
            )
    return exposed or "unknown"


def _device_rows(entry: BalterEvo2ConfigEntry) -> list[dict[str, Any]]:
    """Return redacted per-device coordinator rows."""
    coordinator = entry.runtime_data.coordinator
    rows: list[dict[str, Any]] = []
    for duid, state in (coordinator.data or {}).items():
        rows.append(
            {
                "duid": duid,
                "name": state.device.name,
                "model": state.device.model,
                "host_configured": state.device.host is not None,
                "online": state.online,
                "has_credentials": state.credentials is not None,
            }
        )
    return rows


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: BalterEvo2ConfigEntry
) -> dict[str, Any]:
    """Return redacted diagnostics for the config entry."""
    data = entry.runtime_data
    coordinator = data.coordinator
    return {
        "entry": {
            "title": entry.title,
            "version": entry.version,
            "data": async_redact_data(dict(entry.data), TO_REDACT),
            "options": async_redact_data(dict(entry.options), TO_REDACT),
        },
        "coordinator": {
            "last_update_success": coordinator.last_update_success,
            "device_count": len(data.devices),
            "lock_count": len(data.locks),
        },
        "devices": _device_rows(entry),
        "locks": [
            {
                "duid": lock.duid,
                "code": lock.code,
                "door": lock.door,
                "locknumber": lock.locknumber,
            }
            for lock in data.locks
        ],
        "handshake_states": _handshake_states(entry),
        "lock_exposed_to_assist": _lock_exposed_to_assist(hass, entry),
    }


async def async_get_device_diagnostics(
    hass: HomeAssistant, entry: BalterEvo2ConfigEntry, device: DeviceEntry
) -> dict[str, Any]:
    """Return redacted diagnostics for one station device."""
    duid = next(
        (ident[1] for ident in device.identifiers if ident[0] == DOMAIN), None
    )
    data = entry.runtime_data
    state = (data.coordinator.data or {}).get(duid) if duid else None

    return {
        "duid": duid,
        "device": None
        if state is None
        else {
            "name": state.device.name,
            "model": state.device.model,
            "host_configured": state.device.host is not None,
            "online": state.online,
            "has_credentials": state.credentials is not None,
        },
        "locks": [
            {
                "code": lock.code,
                "door": lock.door,
                "locknumber": lock.locknumber,
            }
            for lock in data.locks
            if lock.duid == duid
        ],
        "handshake_states": _handshake_states(entry),
    }
