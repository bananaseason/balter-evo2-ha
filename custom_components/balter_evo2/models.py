"""Typed data models shared by the Qualvision integration.

The field names of these dataclasses are a cross-module contract (coordinator,
camera, lock, diagnostics, ``__init__``): do not rename them without updating
every user.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from homeassistant.config_entries import ConfigEntry

if TYPE_CHECKING:
    from .api import BalterEvo2CloudClient
    from .coordinator import BalterEvo2Coordinator
    from .station import StationManager


@dataclass(frozen=True, slots=True)
class Device:
    """A door station as reported by the cloud device list."""

    duid: str
    name: str
    model: str
    host: str | None = None  # LAN address; None until the user supplied one


@dataclass(frozen=True, slots=True)
class DoorLock:
    """One door-release relay of a station."""

    duid: str
    code: str  # canonical "door<d>-lock<l>", used in the unique id
    name: str
    door: int
    locknumber: int
    device_name: str = ""
    device_model: str = ""


@dataclass(frozen=True, slots=True)
class Credentials:
    """Weekly-rotating per-device secrets from the cloud."""

    dynamic_password: str
    data_encode_key: str
    out_auth_code: str | None = None  # SHA256(door PIN) as hex, if the cloud has one

    def __repr__(self) -> str:
        """Never leak secrets through repr/logging."""
        return "Credentials(<redacted>)"


@dataclass(frozen=True, slots=True)
class DeviceState:
    """Coordinator data for one station."""

    device: Device
    online: bool
    credentials: Credentials | None = None


@dataclass(slots=True)
class RuntimeData:
    """Runtime objects of one config entry (``entry.runtime_data``)."""

    client: BalterEvo2CloudClient
    coordinator: BalterEvo2Coordinator
    manager: StationManager
    client_id: str
    devices: dict[str, Device] = field(default_factory=dict)  # duid -> Device
    locks: list[DoorLock] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)


type BalterEvo2ConfigEntry = ConfigEntry[RuntimeData]
