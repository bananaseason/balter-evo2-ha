"""Tests for the cloud client's lock discovery.

Which door openers a station has comes from the cloud's sub-device list. The
codes in that list differ between firmwares; a code that is not understood used
to be dropped without a word, which left an EVO 2 with a guessed first opener and
no entity for its second one.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.balter_evo2 import api as api_mod
from custom_components.balter_evo2.api import BalterEvo2CloudClient

# The list the cloud returns for an EVO 2 (IDS94A6FW), as observed live.
EVO2_SUBDEVS = [
    {"type": "chn", "id": 1, "code": "Channel_1", "name": "Türstation 1", "enable": 1},
    {
        "type": "lock",
        "id": 1,
        "code": "Channel_1 lock1",
        "name": "Türstation 1 lock1",
        "enable": 1,
    },
    {
        "type": "lock",
        "id": 2,
        "code": "Channel_1 lock2",
        "name": "Türstation 1 lock2",
        "enable": 1,
    },
]


def reply(subdevs: list[dict[str, Any]]) -> str:
    return json.dumps({"header": {"result": 0}, "content": [{"sub-devlist": subdevs}]})


async def locks_for(subdevs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    client = BalterEvo2CloudClient(MagicMock(), "user@example.com", "secret")
    client._post = AsyncMock(return_value=reply(subdevs))  # type: ignore[method-assign]
    return await client.get_subdev_list("duid1")


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("Channel_1 lock1", (1, 1)),
        ("Channel_1 lock2", (1, 2)),
        ("channel 2 lock 1", (2, 1)),
        ("lock_chn1 2", (1, 2)),
        ("door2-lock1", (2, 1)),
        ("garage", None),
        ("", None),
    ],
)
def test_lock_codes(code: str, expected: tuple[int, int] | None) -> None:
    assert api_mod._parse_lock_code(code) == expected


@pytest.mark.parametrize(
    ("name", "door", "lock", "doors", "expected"),
    [
        ("Türstation 1 lock1", 1, 1, 1, "Door opener"),
        ("Türstation 1 lock2", 1, 2, 1, "Door opener 2"),
        ("", 1, 1, 1, "Door opener"),
        ("Garden gate", 1, 2, 1, "Garden gate"),  # the owner's own name is kept
        ("Türstation 2 lock1", 2, 1, 2, "Door 2 opener"),
        ("Türstation 2 lock2", 2, 2, 2, "Door 2 opener 2"),
    ],
)
def test_lock_names(name: str, door: int, lock: int, doors: int, expected: str) -> None:
    assert api_mod._lock_name(name, door, lock, doors) == expected


async def test_an_evo2_has_both_of_its_door_openers() -> None:
    locks = await locks_for(EVO2_SUBDEVS)
    assert [
        (lock["code"], lock["door"], lock["locknumber"], lock["name"]) for lock in locks
    ] == [
        ("door1-lock1", 1, 1, "Door opener"),
        ("door1-lock2", 1, 2, "Door opener 2"),
    ]


async def test_a_disabled_lock_gets_no_entity() -> None:
    subdevs = [dict(sub) for sub in EVO2_SUBDEVS]
    subdevs[2]["enable"] = 0
    assert [lock["code"] for lock in await locks_for(subdevs)] == ["door1-lock1"]


async def test_an_unknown_lock_code_is_reported_not_dropped_silently(
    caplog: pytest.LogCaptureFixture,
) -> None:
    subdevs = [*EVO2_SUBDEVS, {"type": "lock", "id": 3, "code": "relay-x", "name": "X"}]
    with caplog.at_level(logging.WARNING):
        locks = await locks_for(subdevs)
    assert len(locks) == 2
    assert "relay-x" in caplog.text
