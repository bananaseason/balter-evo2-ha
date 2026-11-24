"""Calls of the call card: live view, the visitor's voice, talk-back, door.

A *call* is what the Lovelace call card (``custom:balter-evo2-call-card``) holds
while its call screen is on screen. It is driven over the websocket API (see
:mod:`websocket`) and obeys the house rules of a station that serves one session
at a time:

* a call exists only while the card sends a heartbeat; none for
  :data:`CALL_HEARTBEAT_TIMEOUT` seconds ends it. That is what releases the
  station when the phone app goes to the background: its MJPEG connection may
  stay open, so it is no sign that anybody watches;
* a call lasts at most :data:`CALL_MAX_DURATION` (the card may extend it
  :data:`CALL_MAX_EXTENSIONS` times), and never beyond the hard cap of the live
  view it is on (``ends_at`` tells the card the truth);
* the live view of the calls ends :data:`CALL_RELEASE_GRACE` after the last call
  on it ended, whoever started it (see ``BalterEvo2Camera.call_join``);
* the microphone channel is opened only when a call starts talking.

Several calls on one camera (two cards, two phones) share one live view and one
talk-back channel; talking is exclusive -- the last call to start talking takes
over, the others are told they no longer talk.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from homeassistant.components.camera import DATA_COMPONENT as CAMERA_DATA
from homeassistant.core import HomeAssistant, callback
from homeassistant.util.hass_dict import HassKey

from .api import BalterEvo2ApiError
from .const import (
    CALL_HEARTBEAT_TIMEOUT,
    CALL_MAX_DURATION,
    CALL_MAX_EXTENSIONS,
    DOMAIN,
)
from .protocol import TALK_FRAME_BYTES
from .station import NotLiveError
from .transport import TcpTalkChannel, TransportError

if TYPE_CHECKING:
    from .camera import BalterEvo2Camera

_LOGGER = logging.getLogger(__name__)

DATA_CALLS: HassKey[CallManager] = HassKey(f"{DOMAIN}_calls")

# Call states as the card sees them.
STATE_CONNECTING = "connecting"
STATE_LIVE = "live"
STATE_ENDED = "ended"

# Why a call ended.
REASON_HANGUP = "hangup"
REASON_TIMEOUT = "timeout"
REASON_HEARTBEAT = "heartbeat"
REASON_STATION_BUSY = "station_busy"
REASON_ERROR = "error"
REASON_MAX_DURATION = "max_duration"

# Error codes of the websocket commands.
ERR_NOT_FOUND = "not_found"
ERR_STATION_BUSY = "station_busy"
ERR_NOT_LIVE = "not_live"
ERR_FAILED = "failed"

# An extension that would add less than this (the live view's hard cap is near)
# is not offered.
CALL_EXTEND_MIN = 5.0


class CallError(Exception):
    """A call command failed; ``code`` is the websocket error code."""

    def __init__(self, code: str, message: str) -> None:
        """Keep the code next to the message."""
        super().__init__(message)
        self.code = code


type Sender = Callable[[dict[str, Any]], None]


@dataclass(eq=False)
class _Call:
    """One call: one call screen on one device."""

    manager: CallManager
    call_id: str
    group: _Group
    owner: object  # the websocket connection that started it
    send: Sender
    ends_at: float  # wall clock (epoch seconds)
    state: str = STATE_CONNECTING
    talking: bool = False
    extensions: int = 0
    ended: bool = False
    audio_seq: int = 0
    heartbeat_handle: asyncio.TimerHandle | None = None
    limit_handle: asyncio.TimerHandle | None = None

    # --- camera.CallListener ---------------------------------------------------

    def call_live(self) -> None:
        """The live view shows the picture."""
        if self.ended or self.state == STATE_LIVE:
            return
        self.state = STATE_LIVE
        self.manager.send_state(self)

    def call_ended(self, reason: str, message: str | None) -> None:
        """The live view ended under the call."""
        self.manager.end(self.call_id, reason, message)


@dataclass(eq=False)
class _Group:
    """The calls on one camera: their live view, the station audio, talk-back."""

    entity_id: str
    camera: BalterEvo2Camera
    calls: dict[str, _Call] = field(default_factory=dict)
    talk: TcpTalkChannel | None = None
    talk_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    talker: str | None = None  # id of the call that talks
    audio_rest: bytearray = field(default_factory=bytearray)
    remove_audio_listener: Callable[[], None] | None = None
    dissolved: bool = False

    @property
    def talk_ready(self) -> bool:
        """Return whether the talk-back channel is open."""
        return self.talk is not None and self.talk.is_alive


class CallManager:
    """All calls of this Home Assistant instance (one per instance)."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Start without calls."""
        self._hass = hass
        self._calls: dict[str, _Call] = {}
        self._groups: dict[str, _Group] = {}

    # --- Lookups ---------------------------------------------------------------

    def _camera(self, entity_id: str) -> BalterEvo2Camera:
        from .camera import BalterEvo2Camera  # here: camera imports this package

        component = self._hass.data.get(CAMERA_DATA)
        entity = component.get_entity(entity_id) if component is not None else None
        if not isinstance(entity, BalterEvo2Camera):
            raise CallError(
                ERR_NOT_FOUND, f"{entity_id} is not a Balter EVO 2 door station camera"
            )
        return entity

    def _get(self, call_id: str, owner: object) -> _Call:
        call = self._calls.get(call_id)
        if call is None or call.ended or call.owner is not owner:
            raise CallError(ERR_NOT_FOUND, "No such call (it has ended)")
        return call

    def calls_of(self, entity_id: str) -> int:
        """Return how many calls hold the live view of ``entity_id``."""
        group = self._groups.get(entity_id)
        return len(group.calls) if group is not None else 0

    # --- Lifecycle -------------------------------------------------------------

    @callback
    def create(self, entity_id: str, owner: object, send: Sender) -> str:
        """Register a new call on ``entity_id``; :meth:`async_join` starts it.

        Raises :class:`CallError` ``not_found`` for anything but a camera of
        this integration.
        """
        camera = self._camera(entity_id)
        group = self._groups.get(entity_id)
        if group is not None and group.camera is not camera:
            # The entity was set up again; the old group belongs to the old one.
            self._dissolve(group)
            group = None
        if group is None:
            group = self._groups[entity_id] = _Group(entity_id, camera)
            group.remove_audio_listener = camera.add_station_audio_listener(
                self._audio_listener(group)
            )
        call = _Call(
            manager=self,
            call_id=uuid.uuid4().hex,
            group=group,
            owner=owner,
            send=send,
            ends_at=time.time() + CALL_MAX_DURATION,
        )
        self._calls[call.call_id] = call
        group.calls[call.call_id] = call
        self._arm_heartbeat(call)
        self._arm_limit(call)
        _LOGGER.debug("Call %s on %s created", call.call_id, entity_id)
        return call.call_id

    async def async_join(self, call_id: str) -> None:
        """Tell the card where the call stands and let it hold the live view."""
        call = self._calls.get(call_id)
        if call is None or call.ended:
            return
        self.send_state(call)
        camera = call.group.camera
        await camera.async_wait_ready()
        if call.ended:
            # Hung up (or timed out) while an ending view finished: no session
            # may be opened for nobody.
            return
        camera.call_join(call_id, call)
        hard_end = camera.view_hard_end
        if hard_end is not None and call.ends_at > hard_end:
            # Joined a view that has run a while: the call ends with it.
            call.ends_at = hard_end
            self._arm_limit(call)
            self.send_state(call)

    @callback
    def heartbeat(self, call_id: str, owner: object) -> None:
        """Keep the call alive for another heartbeat period."""
        self._arm_heartbeat(self._get(call_id, owner))

    @callback
    def extend(self, call_id: str, owner: object) -> float:
        """Prolong the call by another :data:`CALL_MAX_DURATION`; return ``ends_at``."""
        call = self._get(call_id, owner)
        ends_at = self._extended_end(call)
        if ends_at is None:
            raise CallError(ERR_FAILED, "The call cannot be extended any further")
        call.extensions += 1
        call.ends_at = ends_at
        self._arm_limit(call)
        self.send_state(call)
        return call.ends_at

    @staticmethod
    def _extended_end(call: _Call) -> float | None:
        """Return the ``ends_at`` an extension would give, None if none is left.

        Capped by the live view's hard cap: the view (and with it the call) ends
        there whatever the countdown says.
        """
        if call.extensions >= CALL_MAX_EXTENSIONS:
            return None
        ends_at = call.ends_at + CALL_MAX_DURATION
        hard_end = call.group.camera.view_hard_end
        if hard_end is not None and hard_end < ends_at:
            if hard_end - call.ends_at < CALL_EXTEND_MIN:
                return None
            ends_at = hard_end
        return ends_at

    @callback
    def end_by_owner(self, call_id: str, owner: object) -> None:
        """Hang up (``call/end``)."""
        self._get(call_id, owner)
        self.end(call_id, REASON_HANGUP)

    @callback
    def end(
        self,
        call_id: str,
        reason: str,
        message: str | None = None,
        *,
        notify: bool = True,
    ) -> None:
        """End a call: stop its talking and release its hold on the live view.

        ``notify=False`` when the card is gone already (unsubscribed or its
        connection closed).
        """
        call = self._calls.pop(call_id, None)
        if call is None or call.ended:
            return
        call.ended = True
        call.talking = False
        for handle in (call.heartbeat_handle, call.limit_handle):
            if handle is not None:
                handle.cancel()
        call.heartbeat_handle = call.limit_handle = None
        group = call.group
        group.calls.pop(call_id, None)
        _LOGGER.debug(
            "Call %s on %s ended (%s%s)",
            call_id,
            group.entity_id,
            reason,
            f": {message}" if message else "",
        )
        if notify:
            self._send(call, self._state_message(call, reason, message))
        if group.talker == call_id:
            group.talker = None
            if group.calls and group.talk is not None:
                # Others stay on the call: only the talking stops.
                self._hass.async_create_background_task(
                    self._async_set_talking(group, False),
                    name=f"{DOMAIN}_talk_off",
                )
        group.camera.call_leave(call_id)
        if not group.calls:
            self._dissolve(group)

    @callback
    def _dissolve(self, group: _Group) -> None:
        """Drop a group without calls: no audio listener, no talk-back channel."""
        if group.dissolved:
            return
        group.dissolved = True
        if self._groups.get(group.entity_id) is group:
            del self._groups[group.entity_id]
        if group.remove_audio_listener is not None:
            group.remove_audio_listener()
            group.remove_audio_listener = None
        group.audio_rest.clear()
        channel, group.talk = group.talk, None
        if channel is not None:
            self._hass.async_create_background_task(
                group.camera.async_close_talk(channel), name=f"{DOMAIN}_talk_close"
            )
        for call in list(group.calls.values()):
            self.end(call.call_id, REASON_ERROR, "The call was reset")

    @callback
    def end_all(self) -> None:
        """End every call (Home Assistant stops)."""
        for call_id in list(self._calls):
            self.end(call_id, REASON_ERROR, "Home Assistant is stopping")

    # --- Timers ------------------------------------------------------------------

    def _arm_heartbeat(self, call: _Call) -> None:
        if call.heartbeat_handle is not None:
            call.heartbeat_handle.cancel()
        call.heartbeat_handle = self._hass.loop.call_later(
            CALL_HEARTBEAT_TIMEOUT, self.end, call.call_id, REASON_HEARTBEAT
        )

    def _arm_limit(self, call: _Call) -> None:
        if call.limit_handle is not None:
            call.limit_handle.cancel()
        call.limit_handle = self._hass.loop.call_later(
            max(call.ends_at - time.time(), 0.0),
            self.end,
            call.call_id,
            REASON_MAX_DURATION,
        )

    # --- Talk-back ---------------------------------------------------------------

    async def async_talk(self, call_id: str, owner: object, talking: bool) -> bool:
        """Start or stop talking for a call; return whether it talks now."""
        call = self._get(call_id, owner)
        group = call.group
        if not talking:
            async with group.talk_lock:
                if group.talker == call_id:
                    group.talker = None
                    await self._async_set_talking(group, False, locked=True)
                if call.talking:
                    call.talking = False
                    self.send_state(call)
            return False

        if not group.camera.is_call_live:
            raise CallError(ERR_NOT_LIVE, "The picture is not live yet")
        async with group.talk_lock:
            if call.ended:
                raise CallError(ERR_NOT_FOUND, "The call has ended")
            if not group.talk_ready:
                await self._async_open_talk(group)
                if call.ended:
                    raise CallError(ERR_NOT_FOUND, "The call has ended")
            channel = group.talk
            assert channel is not None
            if not channel.talking:
                ok = await self._hass.async_add_executor_job(channel.set_talking, True)
                if not ok:
                    raise CallError(
                        ERR_FAILED, "The door station did not confirm talking"
                    )
            if call.ended:
                # Hung up while the station confirmed: nobody may talk now.
                if group.talker is None and not group.dissolved:
                    await self._async_set_talking(group, False, locked=True)
                raise CallError(ERR_NOT_FOUND, "The call has ended")
            if group.talk is not channel or not channel.is_alive:
                raise CallError(ERR_FAILED, "The talk-back channel was closed")
            previous = group.calls.get(group.talker) if group.talker else None
            group.talker = call_id
            if previous is not None and previous is not call and previous.talking:
                previous.talking = False
                self.send_state(previous)
            call.talking = True
            self.send_state(call)
        return True

    async def _async_open_talk(self, group: _Group) -> None:
        """Open the group's talk-back channel (talk lock held)."""
        try:
            channel = await group.camera.async_open_talk()
        except NotLiveError as err:
            raise CallError(ERR_NOT_LIVE, str(err)) from err
        except (TransportError, BalterEvo2ApiError) as err:
            raise CallError(ERR_FAILED, str(err)) from err
        except Exception as err:
            _LOGGER.exception(
                "The talk-back channel of %s could not be opened", group.entity_id
            )
            raise CallError(
                ERR_FAILED, "The talk-back channel could not be opened"
            ) from err
        if group.dissolved:
            await group.camera.async_close_talk(channel)
            raise CallError(ERR_NOT_FOUND, "The call has ended")
        group.talk = channel
        channel.set_close_callback(
            lambda: self._hass.loop.call_soon_threadsafe(
                self._talk_closed, group, channel
            )
        )
        for other in group.calls.values():
            self.send_state(other)

    @callback
    def _talk_closed(self, group: _Group, channel: TcpTalkChannel) -> None:
        """The station dropped the talk-back channel."""
        if group.talk is not channel:
            return
        _LOGGER.debug("The talk-back channel of %s was closed", group.entity_id)
        group.talk = None
        group.talker = None
        self._hass.async_create_background_task(
            group.camera.async_close_talk(channel), name=f"{DOMAIN}_talk_close"
        )
        for call in group.calls.values():
            call.talking = False
            self.send_state(call)

    async def _async_set_talking(
        self, group: _Group, talking: bool, *, locked: bool = False
    ) -> None:
        """Switch the shared channel's talking (the lock is taken unless held)."""
        if not locked:
            async with group.talk_lock:
                await self._async_set_talking(group, talking, locked=True)
            return
        channel = group.talk
        if channel is None or channel.talking == talking:
            return
        if not talking and group.talker is not None:
            return  # somebody took over meanwhile
        await self._hass.async_add_executor_job(channel.set_talking, talking)

    @callback
    def audio(self, call_id: str, owner: object, data: bytes) -> None:
        """Queue microphone audio of a call; dropped unless the call talks."""
        call = self._get(call_id, owner)
        group = call.group
        if group.talker != call_id or group.talk is None:
            return
        group.talk.feed(data)

    # --- Station audio -------------------------------------------------------------

    def _audio_listener(self, group: _Group) -> Callable[[bytes], None]:
        """Return the listener that hands the station's audio to the loop."""
        loop = self._hass.loop

        def listener(data: bytes) -> None:
            loop.call_soon_threadsafe(self._station_audio, group, data)

        return listener

    @callback
    def _station_audio(self, group: _Group, data: bytes) -> None:
        """Send the visitor's voice to the cards, in whole 40 ms frames."""
        if group.dissolved:
            return
        rest = group.audio_rest
        rest += data
        usable = len(rest) - len(rest) % TALK_FRAME_BYTES
        if not usable:
            return
        chunk = base64.b64encode(bytes(rest[:usable])).decode("ascii")
        del rest[:usable]
        for call in list(group.calls.values()):
            if call.ended:
                continue
            call.audio_seq += 1
            self._send(
                call,
                {
                    "type": "audio",
                    "call_id": call.call_id,
                    "data": chunk,
                    "seq": call.audio_seq,
                },
            )

    # --- Messages -------------------------------------------------------------------

    def _state_message(
        self, call: _Call, reason: str | None = None, message: str | None = None
    ) -> dict[str, Any]:
        group = call.group
        ended = call.ended
        return {
            "type": "state",
            "call_id": call.call_id,
            "state": STATE_ENDED if ended else call.state,
            "talking": call.talking and not ended,
            "talk_ready": group.talk_ready and not ended,
            "ends_at": None if ended else round(call.ends_at, 3),
            "reason": reason if ended else None,
            "message": message if ended else None,
            "can_extend": not ended and self._extended_end(call) is not None,
        }

    def send_state(self, call: _Call) -> None:
        """Send the call's current state to its card."""
        if not call.ended:
            self._send(call, self._state_message(call))

    @staticmethod
    def _send(call: _Call, payload: dict[str, Any]) -> None:
        try:
            call.send(payload)
        except Exception:  # noqa: BLE001 -- a gone card must not break the others
            _LOGGER.debug("Could not send to the card of call %s", call.call_id)
