"""End-to-end tests of the call card's backend: websocket API -> calls -> station.

The integration is set up for real -- the camera and lock platforms, the real
``StationManager`` and the real TCP transports -- against a loopback
:class:`conftest.FakeStation` that streams video and the visitor's audio and
serves the talk-back channel. Only the cloud client and ffmpeg are faked. The
card's side is a real websocket client of Home Assistant.

What is pinned down: a call holds the live view only while it is heartbeating,
ends on hang-up, unsubscribe, a closed connection, its time limit or the live
view's end, and the station is released about a second after the last call; the
microphone channel opens only on a talk command; talking is exclusive between
calls; the visitor's audio reaches every call in whole 40 ms frames; the door
opens during a call without disturbing it.
"""

from __future__ import annotations

import asyncio
import base64
import itertools
import time
from collections.abc import AsyncIterator, Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from conftest import FakeFFmpeg, FakeStation, bypass_frontend, make_audio_chunk
from homeassistant.components.camera import DATA_COMPONENT
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.storage import STORAGE_DIR
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.balter_evo2 import call as call_mod
from custom_components.balter_evo2 import camera as camera_mod
from custom_components.balter_evo2 import station as station_mod
from custom_components.balter_evo2.const import (
    CALL_MAX_DURATION,
    CARD_URL,
    CONF_CLIENT_ID,
    DOMAIN,
    SERVICE_START_LIVE_VIEW,
    SERVICE_STOP_LIVE_VIEW,
)

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.usefixtures("socket_enabled", "enable_custom_integrations"),
]

DUID = "duid-one"
ENTITY_ID = "camera.front_door"
GRACE = 0.2  # CALL_RELEASE_GRACE in these tests
HEARTBEAT_TIMEOUT = 0.6  # CALL_HEARTBEAT_TIMEOUT in these tests
START = "balter_evo2/call/start"


async def until(predicate: Callable[[], bool], timeout: float = 5.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return predicate()


class Card:
    """The card's side of one websocket connection."""

    def __init__(self, ws: Any) -> None:
        self.ws = ws
        self.messages: list[dict[str, Any]] = []
        self._ids = itertools.count(1000)
        self._changed = asyncio.Event()
        self._reader = asyncio.create_task(self._read())
        self._beating: asyncio.Task | None = None
        self.sub: int | None = None
        self.call_id: str | None = None

    async def _read(self) -> None:
        while True:
            try:
                msg = await self.ws.receive_json()
            except Exception:  # noqa: BLE001 -- the connection closed
                return
            self.messages.append(msg)
            self._changed.set()

    async def wait(
        self, predicate: Callable[[dict[str, Any]], bool], timeout: float = 5.0
    ) -> dict[str, Any]:
        end = time.monotonic() + timeout
        while True:
            for msg in self.messages:
                if predicate(msg):
                    return msg
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"not seen; got {self.messages[-5:]}")
            self._changed.clear()
            try:
                await asyncio.wait_for(self._changed.wait(), remaining)
            except TimeoutError:
                pass

    async def send(self, type_: str, **data: Any) -> int:
        msg_id = next(self._ids)
        await self.ws.send_json({"id": msg_id, "type": type_, **data})
        return msg_id

    async def cmd(self, type_: str, **data: Any) -> dict[str, Any]:
        msg_id = await self.send(type_, **data)
        return await self.wait(lambda m: m["type"] == "result" and m["id"] == msg_id)

    async def start(self, entity_id: str = ENTITY_ID) -> dict[str, Any]:
        result = await self.cmd(START, entity_id=entity_id)
        if result["success"]:
            self.sub = result["id"]
            self.call_id = result["result"]["call_id"]
        return result

    def events(self, kind: str | None = None) -> list[dict[str, Any]]:
        return [
            m["event"]
            for m in self.messages
            if m["type"] == "event"
            and m["id"] == self.sub
            and (kind is None or m["event"]["type"] == kind)
        ]

    def states(self) -> list[dict[str, Any]]:
        return self.events("state")

    async def wait_state(self, timeout: float = 5.0, **fields: Any) -> dict[str, Any]:
        msg = await self.wait(
            lambda m: (
                m["type"] == "event"
                and m["id"] == self.sub
                and m["event"]["type"] == "state"
                and all(m["event"].get(k) == v for k, v in fields.items())
            ),
            timeout,
        )
        return msg["event"]

    def heard(self) -> bytes:
        return b"".join(base64.b64decode(e["data"]) for e in self.events("audio"))

    def beat(self, every: float = 0.15) -> None:
        async def run() -> None:
            while True:
                await self.send("balter_evo2/call/heartbeat", call_id=self.call_id)
                await asyncio.sleep(every)

        self._beating = asyncio.create_task(run())

    async def stop_beat(self) -> None:
        if self._beating is not None:
            self._beating.cancel()
            await asyncio.gather(self._beating, return_exceptions=True)
            self._beating = None

    async def talk(self, talking: bool) -> dict[str, Any]:
        return await self.cmd(
            "balter_evo2/call/talk", call_id=self.call_id, talking=talking
        )

    async def say(self, data: bytes) -> dict[str, Any]:
        return await self.cmd(
            "balter_evo2/call/audio",
            call_id=self.call_id,
            data=base64.b64encode(data).decode(),
        )

    async def end(self) -> dict[str, Any]:
        return await self.cmd("balter_evo2/call/end", call_id=self.call_id)

    async def close(self) -> None:
        await self.stop_beat()
        await self.ws.close()
        await asyncio.gather(self._reader, return_exceptions=True)


@pytest.fixture
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(station_mod, "SESSION_MIN_GAP", 0.3)
    monkeypatch.setattr(station_mod, "MEDIA_START_TIMEOUT", 0.4)
    monkeypatch.setattr(station_mod, "LOGIN_TIMEOUT", 2.0)
    monkeypatch.setattr(station_mod, "_start_mjpeg_transcoder", lambda: FakeFFmpeg())
    monkeypatch.setattr(camera_mod, "CALL_RELEASE_GRACE", GRACE)
    monkeypatch.setattr(call_mod, "CALL_HEARTBEAT_TIMEOUT", HEARTBEAT_TIMEOUT)


@pytest.fixture
def setup(
    hass: HomeAssistant,
    tmp_path: Any,
    fast: None,
    fake_station_factory: Callable[..., FakeStation],
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[..., Any]:
    """Return ``setup(**station_kwargs) -> FakeStation`` loading the integration."""
    hass.config.config_dir = str(tmp_path)
    (tmp_path / STORAGE_DIR).mkdir()
    client = MagicMock()
    client.get_device_list = AsyncMock(
        return_value=[
            {
                "duid": DUID,
                "name": "Front door",
                "model": "IDS94A6FW",
                "dynamic_password": "p" * 96,
                "data_encode_key": "k" * 32,
            }
        ]
    )
    client.get_subdev_list = AsyncMock(return_value=[])
    client.get_device_credentials = AsyncMock(
        return_value={"dynamic_password": "p" * 96, "data_encode_key": "k" * 32}
    )
    client.async_close = AsyncMock(return_value=None)

    async def _setup(**station_kwargs: Any) -> FakeStation:
        kwargs: dict[str, Any] = {"stream": True, "frame_interval": 0.02}
        kwargs.update(station_kwargs)
        station = fake_station_factory(**kwargs)
        monkeypatch.setattr(station_mod, "STATION_PORT", station.port)
        entry = MockConfigEntry(
            domain=DOMAIN,
            entry_id="entry1",
            minor_version=2,
            unique_id="user@example.com",
            title="user@example.com",
            data={
                CONF_EMAIL: "user@example.com",
                CONF_PASSWORD: "not-a-real-password",
                CONF_CLIENT_ID: "0123456789abcdef",
            },
            options={"host": "127.0.0.1"},
        )
        entry.add_to_hass(hass)
        hass.config.components.add("ffmpeg")
        hass.data["test_urls"] = bypass_frontend(hass)
        with patch(
            "custom_components.balter_evo2.BalterEvo2CloudClient", return_value=client
        ):
            assert await hass.config_entries.async_setup(entry.entry_id)
            await hass.async_block_till_done()
        return station

    return _setup


@pytest.fixture
async def cards(hass: HomeAssistant, hass_ws_client: Any) -> AsyncIterator[Any]:
    """Return ``open_card() -> Card``; every card is closed at teardown."""
    made: list[Card] = []

    async def open_card() -> Card:
        card = Card(await hass_ws_client(hass))
        made.append(card)
        return card

    yield open_card
    for card in made:
        await card.close()
    await hass.async_block_till_done()


def camera_state(hass: HomeAssistant) -> str:
    state = hass.states.get(ENTITY_ID)
    assert state is not None
    return state.state


def station_manager(hass: HomeAssistant) -> Any:
    return hass.config_entries.async_get_entry("entry1").runtime_data.manager


def released(station: FakeStation, sessions: int = 1) -> Callable[[], bool]:
    return lambda: len(station.disconnect_times) >= sessions


# --- the card -------------------------------------------------------------------------


async def test_the_card_is_served_and_loaded_on_every_page(
    hass: HomeAssistant, setup: Any
) -> None:
    await setup()
    urls = hass.data["test_urls"].urls
    assert any(url.startswith(f"{CARD_URL}?v=") for url in urls)
    routes = [r.resource.canonical for r in hass.http.app.router.routes()]
    assert CARD_URL == "/balter_evo2/balter-evo2-call-card.js"
    assert CARD_URL in routes


# --- life of a call -------------------------------------------------------------------


async def test_a_tap_goes_live_with_sound_and_hang_up_releases_the_station(
    hass: HomeAssistant, setup: Any, cards: Any
) -> None:
    station = await setup()
    card = await cards()
    before = time.time()
    result = await card.start()
    assert result["success"] and result["result"] == {"call_id": card.call_id}
    first = card.states()[0] if card.states() else await card.wait_state()
    assert first["state"] == "connecting"
    # Every event names its call: the card needs no access to the start result.
    assert first["call_id"] == card.call_id
    assert first["talking"] is False and first["talk_ready"] is False
    assert first["reason"] is None and first["can_extend"] is True
    assert before + CALL_MAX_DURATION - 1 <= first["ends_at"]
    assert first["ends_at"] <= time.time() + CALL_MAX_DURATION + 0.01
    card.beat()

    await card.wait_state(state="live")
    assert camera_state(hass) == "streaming"
    assert station.connections == 1

    # The visitor's voice: whole 40 ms frames (the station sends 20 ms chunks
    # here), in order, numbered.
    assert await until(lambda: len(card.heard()) >= 320 * 5)
    audio = card.events("audio")
    assert all(len(base64.b64decode(e["data"])) % 320 == 0 for e in audio)
    assert {e["call_id"] for e in audio} == {card.call_id}
    assert [e["seq"] for e in audio] == list(range(1, len(audio) + 1))
    assert b"".join(station.sent_audio).startswith(card.heard())
    # The microphone channel is never opened without a talk command.
    assert station.audio_connections == 0

    hung_up = time.monotonic()
    assert (await card.end())["success"]
    ended = await card.wait_state(state="ended")
    assert ended["reason"] == "hangup" and ended["talking"] is False
    assert ended["call_id"] == card.call_id
    assert await until(released(station), 3)
    assert time.monotonic() - hung_up < GRACE + 1.0
    assert await until(lambda: camera_state(hass) == "idle")
    assert station_manager(hass)._audio_listeners == {}
    assert hass.data[call_mod.DATA_CALLS].calls_of(ENTITY_ID) == 0
    # Ending it again is no error for the card.
    assert (await card.end())["success"]


async def test_heartbeats_keep_the_call_and_silence_releases_the_station(
    hass: HomeAssistant, setup: Any, cards: Any
) -> None:
    station = await setup()
    card = await cards()
    await card.start()
    card.beat(0.15)
    await card.wait_state(state="live")
    await asyncio.sleep(HEARTBEAT_TIMEOUT * 2.5)
    assert not [s for s in card.states() if s["state"] == "ended"]
    assert not station.disconnect_times

    # The app goes to the background: its timers freeze, no more heartbeats.
    await card.stop_beat()
    left = time.monotonic()
    ended = await card.wait_state(state="ended", timeout=3)
    assert ended["reason"] == "heartbeat"
    assert await until(released(station), 3)
    assert time.monotonic() - left < HEARTBEAT_TIMEOUT + GRACE + 1.0
    assert await until(lambda: camera_state(hass) == "idle")


async def test_a_call_that_never_heartbeats_ends(
    hass: HomeAssistant, setup: Any, cards: Any
) -> None:
    station = await setup()
    card = await cards()
    await card.start()
    ended = await card.wait_state(state="ended", timeout=3)
    assert ended["reason"] == "heartbeat"
    assert await until(released(station), 3)


async def test_unsubscribing_ends_the_call(
    hass: HomeAssistant, setup: Any, cards: Any
) -> None:
    station = await setup()
    card = await cards()
    await card.start()
    card.beat()
    await card.wait_state(state="live")
    result = await card.cmd("unsubscribe_events", subscription=card.sub)
    assert result["success"]
    assert await until(released(station), 3)
    assert hass.data[call_mod.DATA_CALLS].calls_of(ENTITY_ID) == 0
    heartbeat = await card.cmd("balter_evo2/call/heartbeat", call_id=card.call_id)
    assert heartbeat["error"]["code"] == "not_found"


async def test_a_closed_connection_ends_the_call(
    hass: HomeAssistant, setup: Any, cards: Any
) -> None:
    station = await setup()
    card = await cards()
    await card.start()
    card.beat()
    await card.wait_state(state="live")
    await card.close()
    assert await until(released(station), 3)
    assert await until(lambda: camera_state(hass) == "idle")
    assert hass.data[call_mod.DATA_CALLS].calls_of(ENTITY_ID) == 0


async def test_an_open_mjpeg_feed_does_not_hold_the_view_after_the_call(
    hass: HomeAssistant, setup: Any, cards: Any, hass_client: Any
) -> None:
    # The phone app keeps reading the feed after its screen closed: the call,
    # not the feed, decides how long the station is held.
    station = await setup()
    card = await cards()
    await card.start()
    card.beat()
    await card.wait_state(state="live")
    http = await hass_client()
    feed = await http.get(f"/api/camera_proxy_stream/{ENTITY_ID}")
    assert feed.status == 200

    async def keep_reading() -> None:
        while await feed.content.readany():
            pass

    reader = asyncio.create_task(keep_reading())
    await asyncio.sleep(0.3)
    await card.end()
    assert await until(released(station), 3)
    assert await until(lambda: camera_state(hass) == "idle")
    await asyncio.wait_for(reader, 5)  # the feed ends with the view
    feed.close()


async def test_a_call_takes_over_a_view_opened_by_a_viewer(
    hass: HomeAssistant, setup: Any, cards: Any, hass_client: Any
) -> None:
    station = await setup()
    card = await cards()  # (a websocket first: the HTTP client freezes the router)
    http = await hass_client()
    feed = await http.get(f"/api/camera_proxy_stream/{ENTITY_ID}")
    await feed.content.readany()
    assert await until(lambda: camera_state(hass) == "streaming")

    async def keep_reading() -> None:
        while await feed.content.readany():
            pass

    reader = asyncio.create_task(keep_reading())
    await card.start()
    card.beat()
    await card.wait_state(state="live")
    assert station.connections == 1  # joined, no second session
    await card.end()
    assert await until(released(station), 3)
    assert station.connections == 1
    await asyncio.wait_for(reader, 5)
    feed.close()


async def test_an_answered_automation_view_ends_with_the_call(
    hass: HomeAssistant, setup: Any, cards: Any
) -> None:
    # The doorbell recipe: the ring starts a live view of the full length; the
    # owner answers on the card and hangs up -- the station is free at once, not
    # at the end of the automation's 90 s.
    station = await setup()
    await hass.services.async_call(
        DOMAIN, SERVICE_START_LIVE_VIEW, {"entity_id": ENTITY_ID}, blocking=True
    )
    assert await until(lambda: station.connections == 1)
    card = await cards()
    await card.start()
    card.beat()
    await card.wait_state(state="live")
    assert station.connections == 1  # answered on the automation's session
    hung_up = time.monotonic()
    await card.end()
    assert await until(released(station), 3)
    assert time.monotonic() - hung_up < GRACE + 1.0
    assert await until(lambda: camera_state(hass) == "idle")


async def test_a_ring_during_a_call_does_not_outlive_the_call(
    hass: HomeAssistant, setup: Any, cards: Any
) -> None:
    station = await setup()
    card = await cards()
    await card.start()
    card.beat()
    await card.wait_state(state="live")
    await hass.services.async_call(
        DOMAIN, SERVICE_START_LIVE_VIEW, {"entity_id": ENTITY_ID}, blocking=True
    )
    hung_up = time.monotonic()
    await card.end()
    assert await until(released(station), 3)
    assert time.monotonic() - hung_up < GRACE + 1.0
    assert station.connections == 1


async def test_an_automation_view_nobody_answered_runs_its_length(
    hass: HomeAssistant, setup: Any
) -> None:
    station = await setup()
    await hass.services.async_call(
        DOMAIN, SERVICE_START_LIVE_VIEW, {"entity_id": ENTITY_ID}, blocking=True
    )
    await asyncio.sleep(GRACE + 0.5)
    assert camera_state(hass) == "streaming"
    assert not station.disconnect_times
    await hass.services.async_call(
        DOMAIN, SERVICE_STOP_LIVE_VIEW, {"entity_id": ENTITY_ID}, blocking=True
    )
    assert await until(released(station), 3)


async def test_a_call_ended_while_a_view_stops_opens_no_session(
    hass: HomeAssistant, setup: Any, cards: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The card hangs up (or stops heartbeating) while the previous view is still
    # on its way out: no new station session may be opened for nobody.
    station = await setup()
    cam = hass.data[DATA_COMPONENT].get_entity(ENTITY_ID)
    gate = asyncio.Event()
    waiting = asyncio.Event()

    async def slow_wait() -> None:
        waiting.set()
        await gate.wait()

    monkeypatch.setattr(cam, "async_wait_ready", slow_wait)
    card = await cards()
    await card.start()
    await asyncio.wait_for(waiting.wait(), 3)
    assert (await card.end())["success"]
    await card.wait_state(state="ended")
    gate.set()
    await asyncio.sleep(0.5)
    assert station.connections == 0
    assert camera_state(hass) == "idle"
    assert cam._calls == {}


async def test_a_call_outlives_the_view_length(
    hass: HomeAssistant, setup: Any, cards: Any
) -> None:
    station = await setup()
    cam = hass.data[DATA_COMPONENT].get_entity(ENTITY_ID)
    card = await cards()
    await card.start()
    card.beat()
    await card.wait_state(state="live")
    cam._deadline = time.monotonic() - 1  # the configured length ran out
    await asyncio.sleep(0.5)
    assert camera_state(hass) == "streaming"  # the call holds it
    await card.end()
    assert await until(released(station), 3)


async def test_a_busy_station_ends_the_call_as_station_busy(
    hass: HomeAssistant, setup: Any, cards: Any
) -> None:
    station = await setup(no_video_connections=99)
    card = await cards()
    await card.start()
    card.beat()
    talk = await card.talk(True)  # nothing to talk to yet
    assert talk["error"]["code"] == "not_live"
    ended = await card.wait_state(state="ended", timeout=6)
    assert ended["reason"] == "station_busy"
    assert ended["message"] is None
    assert station.audio_connections == 0  # no retry loop, no microphone
    connections = station.connections
    await asyncio.sleep(1.0)
    assert station.connections == connections


async def test_an_unknown_camera_is_not_found(
    hass: HomeAssistant, setup: Any, cards: Any
) -> None:
    await setup()
    card = await cards()
    result = await card.start("camera.nope")
    assert result["error"]["code"] == "not_found"
    for command in ("heartbeat", "extend"):
        result = await card.cmd(f"balter_evo2/call/{command}", call_id="nope")
        assert result["error"]["code"] == "not_found"
    result = await card.cmd("balter_evo2/call/talk", call_id="nope", talking=True)
    assert result["error"]["code"] == "not_found"


async def test_another_connection_cannot_steer_a_call(
    hass: HomeAssistant, setup: Any, cards: Any
) -> None:
    station = await setup()
    mine, other = await cards(), await cards()
    await mine.start()
    mine.beat()
    await mine.wait_state(state="live")
    for command, extra in (("heartbeat", {}), ("talk", {"talking": True})):
        result = await other.cmd(
            f"balter_evo2/call/{command}", call_id=mine.call_id, **extra
        )
        assert result["error"]["code"] == "not_found"
    assert (await other.cmd("balter_evo2/call/end", call_id=mine.call_id))["success"]
    await asyncio.sleep(0.3)
    assert not [s for s in mine.states() if s["state"] == "ended"]
    assert station.audio_connections == 0
    await mine.end()


# --- talking --------------------------------------------------------------------------


async def test_talk_opens_the_microphone_channel_and_toggles_it(
    hass: HomeAssistant, setup: Any, cards: Any
) -> None:
    station = await setup()
    card = await cards()
    await card.start()
    card.beat()
    await card.wait_state(state="live")

    result = await card.talk(True)
    assert result["success"] and result["result"] == {"talking": True}
    state = await card.wait_state(talking=True)
    assert state["talk_ready"] is True and state["state"] == "live"
    assert station.audio_connections == 1
    assert [(f[0], f[1]) for f in station.audio_received()] == [
        (0x0B, 0xFF),
        (0x0C, 1),
        (0x0D, 1),
        (0x0D, 0),
    ]

    chunks = [make_audio_chunk(i, 320) for i in range(4)]
    assert (await card.say(chunks[0] + chunks[1]))["success"]
    assert (await card.say(chunks[2]))["success"]
    assert await until(lambda: len(station.talk_audio()) == 3)
    assert station.talk_audio() == chunks[:3]

    result = await card.talk(False)
    assert result["result"] == {"talking": False}
    state = await card.wait_state(talking=False, talk_ready=True)
    assert station.talk_states() == [1, 0, 1]
    await card.say(chunks[3])  # muted: dropped
    await asyncio.sleep(0.2)
    assert len(station.talk_audio()) == 3

    await card.talk(True)  # the channel stays open: instant unmute
    assert station.audio_connections == 1 and station.talk_states() == [1, 0, 1, 0]
    await card.say(chunks[3])
    assert await until(lambda: len(station.talk_audio()) == 4)

    await card.end()
    assert await until(lambda: len(station.audio_disconnect_times) == 1, 3)
    assert await until(released(station), 3)
    assert station.audio_disconnect_times[0] <= station.disconnect_times[0]
    assert [f[0] for f in station.audio_received()][-2:] == [0x0D, 0x07]


async def test_the_door_opens_while_talking_without_breaking_the_call(
    hass: HomeAssistant, setup: Any, cards: Any
) -> None:
    station = await setup()
    card = await cards()
    await card.start()
    card.beat()
    await card.wait_state(state="live")
    await card.talk(True)
    heard = len(card.heard())

    locks = [
        e.entity_id
        for e in er.async_get(hass).entities.values()
        if e.platform == DOMAIN and e.domain == "lock"
    ]
    await hass.services.async_call(
        "lock", "unlock", {"entity_id": locks[0]}, blocking=True
    )
    assert len(station.opens()) == 1
    assert station.connections == 1  # over the call's own session
    chunk = make_audio_chunk(7, 320)
    await card.say(chunk)
    assert await until(lambda: station.talk_audio()[-1:] == [chunk])
    assert await until(lambda: len(card.heard()) > heard + 640)
    assert not [s for s in card.states() if s["state"] == "ended"]
    assert card.states()[-1]["talking"] is True
    assert not station.disconnect_times
    await card.end()


async def test_two_calls_share_the_view_and_the_last_talker_wins(
    hass: HomeAssistant, setup: Any, cards: Any
) -> None:
    station = await setup()
    first, second = await cards(), await cards()
    await first.start()
    first.beat()
    await first.wait_state(state="live")
    await second.start()
    second.beat()
    await second.wait_state(state="live")
    assert station.connections == 1  # one live view for both

    await first.talk(True)
    await first.wait_state(talking=True)
    await second.talk(True)
    await second.wait_state(talking=True)
    await first.wait_state(talking=False, talk_ready=True)  # taken over
    assert station.audio_connections == 1
    assert station.talk_states() == [1, 0]  # no toggling between talkers

    mine, theirs = make_audio_chunk(1, 320), make_audio_chunk(2, 320)
    await first.say(mine)  # no longer the talker: dropped
    await second.say(theirs)
    assert await until(lambda: station.talk_audio() == [theirs])
    await asyncio.sleep(0.15)
    assert station.talk_audio() == [theirs]

    # Both hear the visitor.
    assert await until(lambda: len(first.heard()) > 640 and len(second.heard()) > 640)

    await second.end()  # the talker leaves: talking stops, the view goes on
    assert await until(lambda: station.talk_states() == [1, 0, 1])
    await asyncio.sleep(GRACE + 0.3)
    assert not station.disconnect_times
    assert first.states()[-1]["state"] == "live"
    await first.end()
    assert await until(released(station), 3)
    assert station.connections == 1


async def test_a_dropped_talk_channel_turns_talking_off(
    hass: HomeAssistant, setup: Any, cards: Any
) -> None:
    station = await setup()
    card = await cards()
    await card.start()
    card.beat()
    await card.wait_state(state="live")
    await card.talk(True)
    await card.wait_state(talking=True)
    station.drop_audio_channels()
    await card.wait_state(talking=False, talk_ready=False)
    assert not station.disconnect_times  # the picture goes on
    result = await card.talk(True)  # opens a new one
    assert result["result"] == {"talking": True}
    assert station.audio_connections == 2
    await card.end()


async def test_a_refused_talk_channel_keeps_the_microphone_off(
    hass: HomeAssistant, setup: Any, cards: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    station = await setup(audio_accept=False)
    monkeypatch.setattr(station_mod, "LOGIN_TIMEOUT", 0.5)
    card = await cards()
    await card.start()
    card.beat()
    await card.wait_state(state="live")
    result = await card.talk(True)
    assert result["error"]["code"] == "failed"
    assert card.states()[-1]["talking"] is False
    assert card.states()[-1]["state"] == "live"  # the call goes on
    await card.end()
    assert await until(released(station), 3)


# --- time limit -----------------------------------------------------------------------


async def test_the_time_limit_ends_the_call_and_extend_prolongs_it(
    hass: HomeAssistant, setup: Any, cards: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(call_mod, "CALL_MAX_DURATION", 0.8)
    station = await setup()
    card = await cards()
    started = time.monotonic()
    await card.start()
    card.beat()
    live = await card.wait_state(state="live")
    ends_at = live["ends_at"]

    result = await card.cmd("balter_evo2/call/extend", call_id=card.call_id)
    assert result["result"]["ends_at"] == pytest.approx(ends_at + 0.8, abs=0.01)
    state = await card.wait_state(can_extend=True, ends_at=result["result"]["ends_at"])
    assert state["state"] == "live"
    result = await card.cmd("balter_evo2/call/extend", call_id=card.call_id)
    assert result["success"]
    await card.wait_state(can_extend=False)
    result = await card.cmd("balter_evo2/call/extend", call_id=card.call_id)
    assert result["error"]["code"] == "failed"  # capped at two extensions

    ended = await card.wait_state(state="ended", timeout=5)
    assert ended["reason"] == "max_duration"
    assert time.monotonic() - started >= 3 * 0.8 - 0.1
    assert await until(released(station), 3)


async def test_extensions_stop_at_the_hard_cap_of_the_live_view(
    hass: HomeAssistant, setup: Any, cards: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The call joins a view the doorbell automation started a while ago; the
    # view's hard cap counts from its own start, so the countdown must too.
    monkeypatch.setattr(camera_mod, "LIVE_VIEW_HARD_CAP", 2.5)
    monkeypatch.setattr(camera_mod, "VIEW_END_MARGIN", 0.5)
    monkeypatch.setattr(call_mod, "CALL_MAX_DURATION", 1.0)
    monkeypatch.setattr(call_mod, "CALL_MAX_EXTENSIONS", 5)
    monkeypatch.setattr(call_mod, "CALL_EXTEND_MIN", 0.1)
    station = await setup()
    cam = hass.data[DATA_COMPONENT].get_entity(ENTITY_ID)
    await hass.services.async_call(
        DOMAIN, SERVICE_START_LIVE_VIEW, {"entity_id": ENTITY_ID}, blocking=True
    )
    hard_end = cam.view_hard_end
    assert hard_end is not None
    await asyncio.sleep(0.4)
    card = await cards()
    await card.start()
    card.beat()
    await card.wait_state(state="live")
    result = await card.cmd("balter_evo2/call/extend", call_id=card.call_id)
    assert result["result"]["ends_at"] == pytest.approx(hard_end, abs=0.01)
    await card.wait_state(can_extend=False, ends_at=result["result"]["ends_at"])
    result = await card.cmd("balter_evo2/call/extend", call_id=card.call_id)
    assert result["error"]["code"] == "failed"  # nothing left to give

    ended = await card.wait_state(state="ended", timeout=5)
    assert ended["reason"] == "max_duration"  # the countdown, not the view, ran out
    assert await until(released(station), 3)


async def test_a_late_call_is_told_when_the_live_view_ends(
    hass: HomeAssistant, setup: Any, cards: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(camera_mod, "LIVE_VIEW_HARD_CAP", 2.0)
    monkeypatch.setattr(camera_mod, "VIEW_END_MARGIN", 0.5)
    station = await setup()
    cam = hass.data[DATA_COMPONENT].get_entity(ENTITY_ID)
    await hass.services.async_call(
        DOMAIN, SERVICE_START_LIVE_VIEW, {"entity_id": ENTITY_ID}, blocking=True
    )
    hard_end = cam.view_hard_end
    card = await cards()
    await card.start()
    card.beat()
    state = await card.wait_state(ends_at=round(hard_end, 3))
    assert state["can_extend"] is False
    ended = await card.wait_state(state="ended", timeout=5)
    assert ended["reason"] == "max_duration"
    assert await until(released(station), 3)
