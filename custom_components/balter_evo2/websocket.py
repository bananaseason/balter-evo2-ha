"""Websocket API of the call card (``balter_evo2/call/*``).

The card starts a call with ``balter_evo2/call/start`` (a subscription: state and
audio events arrive on it), keeps it alive with ``balter_evo2/call/heartbeat``
every second while its call screen is visible, talks with ``call/talk`` and
``call/audio``, prolongs it with ``call/extend`` and ends it with ``call/end``.
Unsubscribing, or the connection closing, ends the call too. Video is not on the
websocket: the card shows the camera's MJPEG feed. See :mod:`call`.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

import voluptuous as vol
from homeassistant.auth.permissions.const import POLICY_READ
from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import Unauthorized
from homeassistant.helpers import config_validation as cv

from .call import (
    DATA_CALLS,
    ERR_NOT_FOUND,
    REASON_HANGUP,
    CallError,
    CallManager,
)
from .transport import TALK_BUFFER_MAX

# Largest microphone chunk one ``call/audio`` message may carry (base64 text).
MAX_AUDIO_B64 = (TALK_BUFFER_MAX * 4) // 3 + 4


@callback
def async_register(hass: HomeAssistant) -> None:
    """Register the call commands (once per Home Assistant run)."""
    for handler in (
        ws_call_start,
        ws_call_heartbeat,
        ws_call_talk,
        ws_call_audio,
        ws_call_extend,
        ws_call_end,
    ):
        websocket_api.async_register_command(hass, handler)


def _manager(hass: HomeAssistant) -> CallManager:
    return hass.data[DATA_CALLS]


def _error(
    connection: websocket_api.ActiveConnection, msg_id: int, err: CallError
) -> None:
    connection.send_error(msg_id, err.code, str(err))


@websocket_api.websocket_command(
    {
        vol.Required("type"): "balter_evo2/call/start",
        vol.Required("entity_id"): cv.entity_id,
    }
)
@websocket_api.async_response
async def ws_call_start(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Start a call (a subscription carrying the call's state and audio)."""
    entity_id: str = msg["entity_id"]
    msg_id: int = msg["id"]
    if not connection.user.permissions.check_entity(entity_id, POLICY_READ):
        raise Unauthorized(entity_id=entity_id)
    manager = _manager(hass)

    def send(payload: dict[str, Any]) -> None:
        # Looked up on every call: a closed connection swaps its sender.
        connection.send_message(websocket_api.event_message(msg_id, payload))

    try:
        call_id = manager.create(entity_id, connection, send)
    except CallError as err:
        _error(connection, msg_id, err)
        return

    @callback
    def unsubscribe() -> None:
        manager.end(call_id, REASON_HANGUP, notify=False)

    connection.subscriptions[msg_id] = unsubscribe
    connection.send_result(msg_id, {"call_id": call_id})
    await manager.async_join(call_id)


@websocket_api.websocket_command(
    {
        vol.Required("type"): "balter_evo2/call/heartbeat",
        vol.Required("call_id"): str,
    }
)
@callback
def ws_call_heartbeat(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Keep a call alive (the card sends one every second while visible)."""
    try:
        _manager(hass).heartbeat(msg["call_id"], connection)
    except CallError as err:
        _error(connection, msg["id"], err)
        return
    connection.send_result(msg["id"], {})


@websocket_api.websocket_command(
    {
        vol.Required("type"): "balter_evo2/call/talk",
        vol.Required("call_id"): str,
        vol.Required("talking"): bool,
    }
)
@websocket_api.async_response
async def ws_call_talk(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Start or stop talking (opens the talk-back channel on first use)."""
    try:
        talking = await _manager(hass).async_talk(
            msg["call_id"], connection, msg["talking"]
        )
    except CallError as err:
        _error(connection, msg["id"], err)
        return
    connection.send_result(msg["id"], {"talking": talking})


@websocket_api.websocket_command(
    {
        vol.Required("type"): "balter_evo2/call/audio",
        vol.Required("call_id"): str,
        vol.Required("data"): vol.All(str, vol.Length(max=MAX_AUDIO_B64)),
    }
)
@callback
def ws_call_audio(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Queue microphone audio (base64 G.711 A-law, 8 kHz mono)."""
    try:
        data = base64.b64decode(msg["data"], validate=True)
    except (binascii.Error, ValueError):
        connection.send_error(
            msg["id"], websocket_api.ERR_INVALID_FORMAT, "data is not base64"
        )
        return
    try:
        _manager(hass).audio(msg["call_id"], connection, data)
    except CallError as err:
        _error(connection, msg["id"], err)
        return
    connection.send_result(msg["id"], {})


@websocket_api.websocket_command(
    {
        vol.Required("type"): "balter_evo2/call/extend",
        vol.Required("call_id"): str,
    }
)
@callback
def ws_call_extend(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Prolong a call by another maximum call length."""
    try:
        ends_at = _manager(hass).extend(msg["call_id"], connection)
    except CallError as err:
        _error(connection, msg["id"], err)
        return
    connection.send_result(msg["id"], {"ends_at": round(ends_at, 3)})


@websocket_api.websocket_command(
    {
        vol.Required("type"): "balter_evo2/call/end",
        vol.Required("call_id"): str,
    }
)
@callback
def ws_call_end(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Hang up."""
    try:
        _manager(hass).end_by_owner(msg["call_id"], connection)
    except CallError as err:
        if err.code != ERR_NOT_FOUND:
            _error(connection, msg["id"], err)
            return
        # Ending a call that already ended is not an error for the card.
    connection.send_result(msg["id"], {})
