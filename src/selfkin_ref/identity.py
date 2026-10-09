# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Selfkin reference contributors
"""Owners, devices, agents, and owner-signed statements (SK-COM A2, SK-RT 10).

The drafts require that owner identity is bound to devices and agents through
owner-signed statements, but v0.1 defines no format for those statements.
This module uses a small, clearly reference-only format:

``{"v", "id", "kind": "device"|"agent", "iss": owner, "sub": device or agent,
"device": device (agents only), "iat", "exp", "sig"}``

It is signed like every other Selfkin object (SK-COM A5.1). Treat it as an
illustration, not as part of the standard.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .errors import Refused
from .keys import SigningKey, short
from .signing import sign_object, verify_object
from .util import new_id, parse_ts, ts, utcnow

STATEMENT_LIFETIME = timedelta(days=30)
CLOCK_SKEW = timedelta(seconds=30)


def issue_statement(owner: SigningKey, subject: str, kind: str, *, device: str | None = None,
                    now: datetime | None = None, lifetime: timedelta = STATEMENT_LIFETIME) -> dict:
    now = now or utcnow()
    body = {"v": "0.1", "id": new_id("stmt"), "kind": kind, "iss": owner.did, "sub": subject,
            "iat": ts(now), "exp": ts(now + lifetime)}
    if kind == "agent":
        if device is None:
            raise ValueError("agent statements name the device the agent runs on")
        body["device"] = device
    return sign_object(body, owner)


@dataclass
class Agent:
    name: str
    key: SigningKey
    device: "Device"
    statement: dict = field(default_factory=dict)

    @property
    def did(self) -> str:
        return self.key.did


@dataclass
class Device:
    name: str
    key: SigningKey
    owner: "Owner"
    region: str
    statement: dict = field(default_factory=dict)
    agents: dict[str, Agent] = field(default_factory=dict)

    @property
    def did(self) -> str:
        return self.key.did

    def add_agent(self, name: str, now: datetime | None = None) -> Agent:
        """Agent identity is separate from device identity: each agent has its own key."""
        agent = Agent(name, SigningKey.generate(name), self)
        agent.statement = issue_statement(self.owner.key, agent.did, "agent", device=self.did, now=now)
        self.agents[name] = agent
        return agent


@dataclass
class Owner:
    name: str
    key: SigningKey

    @classmethod
    def create(cls, name: str) -> "Owner":
        return cls(name, SigningKey.generate(name))

    @property
    def did(self) -> str:
        return self.key.did

    def add_device(self, name: str, region: str, now: datetime | None = None) -> Device:
        device = Device(name, SigningKey.generate(name), self, region)
        device.statement = issue_statement(self.key, device.did, "device", now=now)
        return device


class TrustStore:
    """What one runtime knows: trusted owners and verified statements."""

    def __init__(self) -> None:
        self.owners: dict[str, str] = {}
        self.statements: dict[str, dict] = {}
        self.revoked: set[str] = set()
        self.labels: dict[str, str] = {}

    def trust_owner(self, owner_did: str, label: str = "") -> None:
        self.owners[owner_did] = label
        self.labels[owner_did] = label or short(owner_did)

    def add_statement(self, statement: dict, now: datetime | None = None, label: str = "") -> None:
        """Verify an owner statement and remember it. Raises ``Refused``."""
        now = now or utcnow()
        issuer = statement.get("iss")
        if issuer not in self.owners:
            raise Refused("unauthorized", "statement issuer is not a trusted owner")
        verify_object(statement, expected_signer=issuer)
        try:
            iat, exp = parse_ts(statement["iat"]), parse_ts(statement["exp"])
            kind, subject = statement["kind"], statement["sub"]
        except (KeyError, ValueError):
            raise Refused("malformed", "owner statement is missing members or has invalid timestamps") from None
        if kind not in ("device", "agent") or not isinstance(subject, str):
            raise Refused("malformed", "owner statement has an unknown kind or subject")
        if not iat - CLOCK_SKEW <= now < exp:
            raise Refused("expired", "owner statement is not currently valid")
        if kind == "agent":
            device = self.statements.get(statement.get("device"))
            if device is None or device["iss"] != issuer:
                raise Refused("unauthorized", "agent statement names an unknown device")
        self.statements[subject] = statement
        if label:
            self.labels[subject] = label

    def revoke(self, identity: str) -> None:
        self.revoked.add(identity)

    def owner_of(self, identity: str) -> str | None:
        """Owner of an owner, device, or agent identity, or ``None`` if unknown."""
        if identity in self.owners:
            return identity
        statement = self.statements.get(identity)
        return statement["iss"] if statement else None

    def check_agent(self, agent: str, device: str) -> str:
        """Check that ``agent`` runs on ``device`` under a trusted owner; return the owner."""
        for identity in (agent, device):
            if identity in self.revoked:
                raise Refused("revoked", f"{short(identity)} is revoked")
        statement = self.statements.get(agent)
        if statement is None or statement["kind"] != "agent":
            raise Refused("unauthorized", "no owner statement for the sending agent")
        if statement["device"] != device:
            raise Refused("unauthorized", "agent is not bound to the sending device")
        return statement["iss"]

    def label(self, identity: str) -> str:
        return self.labels.get(identity.split("#", 1)[0], short(identity))
