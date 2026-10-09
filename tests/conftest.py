# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures: a paired pair of runtimes with agents and tokens."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

import pytest

from selfkin_ref import capability, envelope
from selfkin_ref.identity import Owner
from selfkin_ref.runtime import Runtime
from selfkin_ref.util import new_id, utcnow

ACTION = "calendar.propose_meeting"
WORK = "urn:selfkin:calendar:alice/work"
ALL = "urn:selfkin:calendar:alice/*"


@dataclass
class World:
    now: object
    alice: object
    a: Runtime
    b: Runtime
    planner: object
    assistant: object
    helper: object
    calendar: object
    session: str
    root: dict
    delegated: dict
    executed: list

    @property
    def receiver(self) -> envelope.Receiver:
        return self.b.receivers[self.calendar.did]

    def instruction(self, sender=None, token=None, *, resource=WORK, action=ACTION, idem=None,
                    data_classes=("calendar.availability",), tags=("CH-EU",), seq=None, **kwargs):
        sender = sender or self.assistant
        token = self.delegated if token is None else token
        return envelope.make(sender, aud=kwargs.pop("aud", self.calendar.did), session=kwargs.pop("session", self.session),
                             seq=self.a.next_seq(self.session, sender) if seq is None else seq,
                             form="F6", intent="scheduling.propose", cap_token=token,
                             instructions={"action": action, "resource": resource, "params": {"title": "sync"}},
                             idem_key=idem or new_id("idem-key"), residency_tags=list(tags),
                             data_classes=list(data_classes), now=kwargs.pop("now", self.now), **kwargs)


def make_world(region_b: str = "CH", tags=("CH-EU",)) -> World:
    now = utcnow()
    alice = Owner.create("alice")
    a = Runtime(alice, alice.add_device("phone", "CH", now=now), now=now)
    b = Runtime(alice, alice.add_device("homebox", region_b, now=now), now=now)
    planner = a.add_agent("planner", now=now)
    assistant = a.add_agent("assistant", now=now)
    helper = a.add_agent("helper", now=now)
    executed: list = []
    calendar = b.add_agent("calendar", handlers={ACTION: lambda env: executed.append(env) or {"ok": True}}, now=now)
    request = a.pairing_request(b.core.did, forms=["F1", "F6"], tags=list(tags), actions=[ACTION], now=now)
    response, _ = b.accept_pairing(request, now=now)
    confirm, _ = a.complete_pairing(response, now=now)
    b.finish_pairing(confirm, now=now)
    root = capability.issue(alice.key, sub=planner.did, aud=calendar.did, lifetime=timedelta(minutes=50), now=now,
                            rights=[{"action": ACTION, "resource": ALL,
                                     "constraints": {"data_classes": ["calendar.availability", "calendar.events"],
                                                     "max_uses": 5}}],
                            budget={"messages": 10})
    delegated = capability.delegate(root, planner.key, sub=assistant.did, lifetime=timedelta(minutes=30), now=now,
                                    rights=[{"action": ACTION, "resource": WORK,
                                             "constraints": {"data_classes": ["calendar.availability"], "max_uses": 3}}],
                                    budget={"messages": 4})
    return World(now, alice, a, b, planner, assistant, helper, calendar, request["session"], root, delegated, executed)


@pytest.fixture
def world() -> World:
    return make_world()
