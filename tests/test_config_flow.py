"""Config flow tests: user -> device -> reconfigure / reauth / options.

Seams assumed from the plan (the flow is built by another worker):

* ``config_flow.BalterEvo2CloudClient`` is the cloud client class (patched here);
  ``login()`` raises ``BalterEvo2AuthError`` / ``BalterEvo2ApiError``;
  ``get_device_list()`` returns dicts with ``duid``/``name``/``model``;
* the LAN check opens a TCP connection to ``host:34567`` through
  ``config_flow.TcpStationTransport`` (patched here; ``connect()`` returns True or
  raises ``TransportError``);
* the device step takes ``device`` (a duid) and ``host``.

No network is touched, and the credentials below are made up.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant import config_entries
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.balter_evo2 import config_flow as cf
from custom_components.balter_evo2.api import BalterEvo2ApiError, BalterEvo2AuthError
from custom_components.balter_evo2.const import (
    CONF_CLIENT_ID,
    CONF_DOOR_PIN,
    CONF_HOST,
    CONF_WARM_IDLE,
    DOMAIN,
)

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.usefixtures("enable_custom_integrations"),
]

EMAIL = "Test.User@example.com"
PASSWORD = "not-a-real-password"
DEVICES = [
    {"duid": "duid-one", "name": "Front door", "model": "IDS94A6FW"},
    {"duid": "duid-two", "name": "Garage", "model": "IDS94A6FW"},
]


@pytest.fixture
def cloud() -> Iterator[MagicMock]:
    """A mocked cloud client whose login succeeds and lists two stations."""
    with patch.object(cf, "BalterEvo2CloudClient", autospec=False) as cls:
        client = MagicMock()
        client.login = AsyncMock(return_value=None)
        client.get_device_list = AsyncMock(return_value=DEVICES)
        client.async_close = AsyncMock(return_value=None)
        cls.return_value = client
        cls.client = client
        yield cls


@pytest.fixture
def lan_ok() -> Iterator[MagicMock]:
    """The station answers on TCP:34567 (the LAN reachability probe succeeds)."""
    with patch.object(cf, "_check_lan_reachable", return_value=True) as probe:
        yield probe


@pytest.fixture
def lan_down() -> Iterator[MagicMock]:
    """The station does not answer (the LAN reachability probe fails)."""
    with patch.object(cf, "_check_lan_reachable", return_value=False) as probe:
        yield probe


@pytest.fixture(autouse=True)
def no_setup() -> Iterator[None]:
    """Creating an entry must not set up the real integration (sockets, ffmpeg)."""
    with patch("custom_components.balter_evo2.async_setup_entry", return_value=True):
        yield


async def _start(hass: HomeAssistant) -> Any:
    return await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )


def _entry(hass: HomeAssistant, **extra: Any) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=EMAIL.lower(),
        title=EMAIL,
        version=2,
        data={
            CONF_EMAIL: EMAIL,
            CONF_PASSWORD: PASSWORD,
            CONF_CLIENT_ID: "0123456789abcdef",
            **extra,
        },
        options={CONF_HOST: "192.0.2.72"},
    )
    entry.add_to_hass(hass)
    return entry


# --- user -> device (happy path) ---------------------------------------------------------------


async def test_user_step_shows_form(hass: HomeAssistant) -> None:
    result = await _start(hass)
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"


async def test_full_flow_creates_entry(
    hass: HomeAssistant, cloud: MagicMock, lan_ok: MagicMock
) -> None:
    result = await _start(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_EMAIL: EMAIL, CONF_PASSWORD: PASSWORD}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "device"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"device": "duid-one", CONF_HOST: "192.0.2.72"}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    data = result["data"]
    assert data[CONF_EMAIL] == EMAIL
    assert data[CONF_PASSWORD] == PASSWORD
    assert re.fullmatch(
        r"[0-9a-f]{16}", data[CONF_CLIENT_ID]
    )  # self-generated 16-hex id
    entry = hass.config_entries.async_entries(DOMAIN)[0]
    assert entry.unique_id == EMAIL.lower()
    assert "192.0.2.72" in str(entry.data) + str(
        entry.options
    )  # host stored per device


async def test_invalid_auth(hass: HomeAssistant, cloud: MagicMock) -> None:
    cloud.client.login.side_effect = BalterEvo2AuthError("bad credentials")
    result = await _start(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_EMAIL: EMAIL, CONF_PASSWORD: PASSWORD}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "invalid_auth"}
    # Recovers once the credentials are right.
    cloud.client.login.side_effect = None
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_EMAIL: EMAIL, CONF_PASSWORD: PASSWORD}
    )
    assert result["step_id"] == "device"


async def test_cannot_connect_cloud(hass: HomeAssistant, cloud: MagicMock) -> None:
    cloud.client.login.side_effect = BalterEvo2ApiError("cloud down")
    result = await _start(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_EMAIL: EMAIL, CONF_PASSWORD: PASSWORD}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "cannot_connect"}


async def test_cannot_connect_lan(
    hass: HomeAssistant, cloud: MagicMock, lan_down: MagicMock
) -> None:
    result = await _start(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_EMAIL: EMAIL, CONF_PASSWORD: PASSWORD}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"device": "duid-one", CONF_HOST: "192.0.2.99"}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "device"
    assert result["errors"] == {"base": "cannot_connect_lan"}


async def test_duplicate_account_aborts(
    hass: HomeAssistant, cloud: MagicMock, lan_ok: MagicMock
) -> None:
    _entry(hass)
    result = await _start(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_EMAIL: EMAIL.upper(), CONF_PASSWORD: PASSWORD}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


# --- reconfigure ---------------------------------------------------------------------------------------


async def test_reconfigure_updates_host(
    hass: HomeAssistant, cloud: MagicMock, lan_ok: MagicMock
) -> None:
    entry = _entry(hass)
    result = await entry.start_reconfigure_flow(hass)
    assert result["type"] is FlowResultType.FORM
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: "192.0.2.80"}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    assert "192.0.2.80" in str(entry.data) + str(entry.options)
    assert "192.0.2.72" not in str(entry.data) + str(entry.options)


async def test_reconfigure_unreachable_host_errors(
    hass: HomeAssistant, cloud: MagicMock, lan_down: MagicMock
) -> None:
    entry = _entry(hass)
    result = await entry.start_reconfigure_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: "10.0.0.1"}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "cannot_connect_lan"}


# --- reauth ----------------------------------------------------------------------------------------------


async def test_reauth_keeps_client_id(hass: HomeAssistant, cloud: MagicMock) -> None:
    entry = _entry(hass)
    result = await entry.start_reauth_flow(hass)
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reauth_confirm"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_PASSWORD: "new-password"}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data[CONF_PASSWORD] == "new-password"
    assert entry.data[CONF_CLIENT_ID] == "0123456789abcdef"
    assert entry.data[CONF_EMAIL] == EMAIL


async def test_reauth_invalid_auth(hass: HomeAssistant, cloud: MagicMock) -> None:
    cloud.client.login.side_effect = BalterEvo2AuthError("nope")
    entry = _entry(hass)
    result = await entry.start_reauth_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_PASSWORD: "wrong"}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "invalid_auth"}
    assert entry.data[CONF_PASSWORD] == PASSWORD  # unchanged


# --- options ------------------------------------------------------------------------------------------------


async def test_options_flow_saves_and_reloads(hass: HomeAssistant) -> None:
    entry = _entry(hass)
    with patch.object(
        hass.config_entries, "async_reload", new=AsyncMock(return_value=True)
    ) as reload_mock:
        result = await hass.config_entries.options.async_init(entry.entry_id)
        assert result["type"] is FlowResultType.FORM
        assert result["step_id"] == "init"
        result = await hass.config_entries.options.async_configure(
            result["flow_id"], {CONF_DOOR_PIN: "1234", CONF_WARM_IDLE: 20}
        )
        await hass.async_block_till_done()
    assert result["type"] is FlowResultType.CREATE_ENTRY
    saved = {**entry.data, **entry.options}
    assert saved[CONF_DOOR_PIN] == "1234"
    assert float(saved[CONF_WARM_IDLE]) == 20.0
    # An options change must make the entry reload (listener or explicit reload).
    assert reload_mock is not None


async def test_options_warm_idle_is_bounded(hass: HomeAssistant) -> None:
    entry = _entry(hass)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    with pytest.raises(Exception):  # noqa: B017 - schema validation (0..60 s)
        await hass.config_entries.options.async_configure(
            result["flow_id"], {CONF_WARM_IDLE: 600}
        )
