"""Config flow for the Balter EVO 2 Door Station integration.

Flow shape ported from balter-evo-ha (MIT, https://github.com/LucaHerrero/balter-evo-ha):
a self-generated 16-hex client id, unique_id = account e-mail, and a reauth step.
The device/host selection and the reconfigure step are new, because the local
transport is a direct TCP connection to the station instead of the (broken on
EVO 2) UDP/P2P relay.
"""

from __future__ import annotations

import logging
import secrets
import socket
from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import callback
from homeassistant.helpers import aiohttp_client, selector

from .api import BalterEvo2ApiError, BalterEvo2AuthError, BalterEvo2CloudClient
from .const import (
    CONF_CLIENT_ID,
    CONF_DOOR_PIN,
    CONF_HOST,
    CONF_SNAPSHOT_TTL,
    CONF_STREAM_DURATION,
    CONF_WARM_IDLE,
    DEFAULT_SNAPSHOT_TTL,
    DEFAULT_STREAM_DURATION,
    DEFAULT_WARM_IDLE,
    DOMAIN,
    LOGIN_TIMEOUT,
    SNAPSHOT_TTL_MAX,
    STATION_PORT,
    WARM_IDLE_MAX,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_EMAIL): str,
        vol.Required(CONF_PASSWORD): str,
    }
)

STEP_REAUTH_SCHEMA = vol.Schema({vol.Required(CONF_PASSWORD): str})


def _check_lan_reachable(host: str, port: int = STATION_PORT) -> bool:
    """Return True if ``host:port`` accepts a TCP connection (blocking).

    Only probes reachability -- it does NOT log in, so it never occupies the
    station's single session slot. Must run in an executor thread.
    """
    try:
        with socket.create_connection((host, port), timeout=LOGIN_TIMEOUT):
            return True
    except OSError:
        return False


class BalterEvo2ConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle the Qualvision config flow."""

    VERSION = 1
    MINOR_VERSION = 2

    def __init__(self) -> None:
        """Initialise the flow's cross-step state."""
        self._login: dict[str, str] = {}
        self._devices: list[dict[str, Any]] = []

    # --------------------------------------------------------------- helpers

    async def _async_try_login(
        self, email: str, password: str, client_id: str
    ) -> tuple[str | None, list[dict[str, Any]]]:
        """Verify credentials and fetch the device list.

        Returns ``(error_key, devices)``; ``error_key`` is None on success.
        """
        client = BalterEvo2CloudClient(
            aiohttp_client.async_get_clientsession(self.hass),
            email,
            password,
            client_id=client_id,
        )
        try:
            await client.login()
            devices = await client.get_device_list()
        except BalterEvo2AuthError:
            return "invalid_auth", []
        except BalterEvo2ApiError as err:
            _LOGGER.error("Cloud connection error: %s", err)
            return "cannot_connect", []
        finally:
            await client.async_close()
        return None, devices

    # ------------------------------------------------------------ user step

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Step 1: account login."""
        errors: dict[str, str] = {}
        if user_input is not None:
            # Self-generated 16-hex identity; the station accepts any 16-hex id
            # (verified live), so no registration is required.
            client_id = secrets.token_hex(8)
            error, devices = await self._async_try_login(
                user_input[CONF_EMAIL], user_input[CONF_PASSWORD], client_id
            )
            if error:
                errors["base"] = error
            else:
                await self.async_set_unique_id(user_input[CONF_EMAIL].lower())
                self._abort_if_unique_id_configured()
                self._login = {
                    CONF_EMAIL: user_input[CONF_EMAIL],
                    CONF_PASSWORD: user_input[CONF_PASSWORD],
                    CONF_CLIENT_ID: client_id,
                }
                self._devices = devices
                return await self.async_step_device()

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_SCHEMA, errors=errors
        )

    async def async_step_device(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Step 2: pick a station and give its LAN address."""
        errors: dict[str, str] = {}
        if user_input is not None:
            host = user_input[CONF_HOST].strip()
            reachable = await self.hass.async_add_executor_job(
                _check_lan_reachable, host
            )
            if not reachable:
                errors["base"] = "cannot_connect_lan"
            else:
                duid = user_input["device"]
                device = next(
                    (d for d in self._devices if d.get("duid") == duid), None
                )
                title = device.get("name") if device else self._login[CONF_EMAIL]
                return self.async_create_entry(
                    title=title or self._login[CONF_EMAIL],
                    data=self._login,
                    options={CONF_HOST: host},
                )

        device_options = [
            selector.SelectOptionDict(
                value=device["duid"],
                label=f"{device.get('name') or device['duid']}"
                + (f" ({device['model']})" if device.get("model") else ""),
            )
            for device in self._devices
            if device.get("duid")
        ]
        # If the account exposes no devices, the entry cannot do anything local.
        if not device_options:
            return self.async_abort(reason="no_devices")

        schema = vol.Schema(
            {
                vol.Required("device", default=device_options[0]["value"]): (
                    selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=device_options,
                            mode=selector.SelectSelectorMode.DROPDOWN,
                        )
                    )
                ),
                vol.Required(CONF_HOST, default=""): str,
            }
        )
        return self.async_show_form(
            step_id="device", data_schema=schema, errors=errors
        )

    # ------------------------------------------------------- reconfigure step

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Update the station's LAN address (it wanders without a DHCP lease)."""
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            host = user_input[CONF_HOST].strip()
            reachable = await self.hass.async_add_executor_job(
                _check_lan_reachable, host
            )
            if not reachable:
                errors["base"] = "cannot_connect_lan"
            else:
                return self.async_update_reload_and_abort(
                    entry, options={**entry.options, CONF_HOST: host}
                )

        schema = vol.Schema(
            {
                vol.Required(
                    CONF_HOST,
                    default=entry.options.get(CONF_HOST, ""),
                ): str
            }
        )
        return self.async_show_form(
            step_id="reconfigure", data_schema=schema, errors=errors
        )

    # ------------------------------------------------------------ reauth step

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Handle re-authentication after the cloud rejected the credentials."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for the password again, keeping the existing client id."""
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}

        if user_input is not None:
            error, _ = await self._async_try_login(
                entry.data[CONF_EMAIL],
                user_input[CONF_PASSWORD],
                entry.data.get(CONF_CLIENT_ID) or secrets.token_hex(8),
            )
            if error:
                errors["base"] = error
            else:
                return self.async_update_reload_and_abort(
                    entry, data_updates={CONF_PASSWORD: user_input[CONF_PASSWORD]}
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=STEP_REAUTH_SCHEMA,
            description_placeholders={"email": entry.data[CONF_EMAIL]},
            errors=errors,
        )

    # ------------------------------------------------------------- options

    @staticmethod
    @callback
    def async_get_options_flow(config_entry) -> OptionsFlow:
        """Return the options flow handler."""
        return BalterEvo2OptionsFlow()


class BalterEvo2OptionsFlow(OptionsFlow):
    """Options: door PIN, session hold time, live view / still behaviour, host."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage the per-entry options."""
        if user_input is not None:
            options = {
                CONF_DOOR_PIN: user_input.get(CONF_DOOR_PIN, ""),
                CONF_WARM_IDLE: float(
                    user_input.get(CONF_WARM_IDLE, DEFAULT_WARM_IDLE)
                ),
                CONF_STREAM_DURATION: float(
                    user_input.get(CONF_STREAM_DURATION, DEFAULT_STREAM_DURATION)
                ),
                CONF_SNAPSHOT_TTL: float(
                    user_input.get(CONF_SNAPSHOT_TTL, DEFAULT_SNAPSHOT_TTL)
                ),
            }
            host = (user_input.get(CONF_HOST) or "").strip()
            if host:
                options[CONF_HOST] = host
            return self.async_create_entry(title="", data=options)

        current = self.config_entry.options
        schema = vol.Schema(
            {
                vol.Optional(
                    CONF_DOOR_PIN,
                    default=current.get(CONF_DOOR_PIN, ""),
                ): str,
                vol.Optional(
                    CONF_HOST,
                    default=current.get(CONF_HOST, ""),
                ): str,
                vol.Optional(
                    CONF_WARM_IDLE,
                    default=float(current.get(CONF_WARM_IDLE, DEFAULT_WARM_IDLE)),
                ): selector.NumberSelector(
                    selector.NumberSelectorConfig(
                        min=0,
                        max=WARM_IDLE_MAX,
                        step=1,
                        unit_of_measurement="s",
                        mode=selector.NumberSelectorMode.BOX,
                    )
                ),
                vol.Optional(
                    CONF_STREAM_DURATION,
                    default=float(
                        current.get(CONF_STREAM_DURATION, DEFAULT_STREAM_DURATION)
                    ),
                ): selector.NumberSelector(
                    selector.NumberSelectorConfig(
                        min=10,
                        max=300,
                        step=5,
                        unit_of_measurement="s",
                        mode=selector.NumberSelectorMode.BOX,
                    )
                ),
                vol.Optional(
                    CONF_SNAPSHOT_TTL,
                    default=float(
                        current.get(CONF_SNAPSHOT_TTL, DEFAULT_SNAPSHOT_TTL)
                    ),
                ): selector.NumberSelector(
                    selector.NumberSelectorConfig(
                        min=0,
                        max=SNAPSHOT_TTL_MAX,
                        step=10,
                        unit_of_measurement="s",
                        mode=selector.NumberSelectorMode.BOX,
                    )
                ),
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
