# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Selfkin reference contributors
"""A toy runtime: one owner's device with a core agent and app agents.

It ties the pieces together: owner statements, pairing (e2e.py), encrypted
frames, envelope checks (envelope.py), refusals, and a local log of every
envelope sent and received (SK-COM A10: form, peer, intent, decision; no
secrets and no payload values).
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from . import dcbor, envelope
from .e2e import PAIRING_TYPE, Channel, Ephemeral, FrameRejected, derive, transcript_hash
from .errors import Refused
from .identity import Agent, Device, Owner, TrustStore
from .util import b64u, b64u_decode, new_id, ts, utcnow

PAIRING_LIFETIME = timedelta(days=30)


@dataclass
class LogEntry:
    direction: str
    form: str
    peer: str
    intent: str
    decision: str


@dataclass
class Delivery:
    status: str  # executed, duplicate, refused, dropped
    reason: str | None = None
    detail: str | None = None
    outcome: envelope.Outcome | None = None
    reply: bytes | None = None
    envelope: dict | None = None


@dataclass
class _Pending:
    ephemeral: Ephemeral
    request: dict
    response: dict | None = None
    keys: object = None
    record: dict = field(default_factory=dict)


class Runtime:
    def __init__(self, owner: Owner, device: Device, *, now: datetime | None = None) -> None:
        self.owner, self.device = owner, device
        self.trust = TrustStore()
        self.trust.trust_owner(owner.did, owner.name)
        self.trust.add_statement(device.statement, now, label=device.name)
        self.receivers: dict[str, envelope.Receiver] = {}
        self.core = self.add_agent("core", now=now)
        self.channels: dict[str, Channel] = {}
        self.pending: dict[str, _Pending] = {}
        self.seqs: dict[tuple[str, str], int] = {}
        self.log: list[LogEntry] = []

    # ---------------------------------------------------------------- setup

    def add_agent(self, name: str, handlers=None, now: datetime | None = None) -> Agent:
        agent = self.device.add_agent(name, now=now)
        self.trust.add_statement(agent.statement, now, label=f"{name}@{self.device.name}")
        self.receivers[agent.did] = envelope.Receiver(agent, self.trust, handlers=handlers)
        return agent

    def statements(self) -> list[dict]:
        return [self.device.statement] + [a.statement for a in self.device.agents.values()]

    def next_seq(self, session: str, agent: Agent) -> int:
        key = (session, agent.did)
        self.seqs[key] = self.seqs.get(key, -1) + 1
        return self.seqs[key]

    def _record(self, direction: str, env: dict, decision: str) -> None:
        peer_key = "aud" if direction == "sent" else "sender_agent"
        self.log.append(LogEntry(direction, env.get("form", "?"), self.trust.label(env.get(peer_key, "?")),
                                 env.get("intent", "?"), decision))

    def _learn(self, data: dict, now: datetime | None) -> None:
        for statement in data.get("statements", []):
            self.trust.add_statement(statement, now)

    # -------------------------------------------------------------- pairing

    def _pairing_data(self, ephemeral: Ephemeral, forms: list[str], tags: list[str], actions: list[str]) -> dict:
        return {"v": "0.1", "owner": self.owner.did, "statements": self.statements(), "eph": ephemeral.public_b64,
                "forms": forms, "residency": tags, "capabilities": actions}

    def pairing_request(self, peer_core: str, *, forms: list[str], tags: list[str], actions: list[str],
                        now: datetime | None = None) -> dict:
        session = new_id("pair")
        ephemeral = Ephemeral()
        env = envelope.make(self.core, aud=peer_core, session=session, seq=self.next_seq(session, self.core),
                            intent="sk.pairing.request", data=self._pairing_data(ephemeral, forms, tags, actions),
                            payload_type=PAIRING_TYPE, residency_tags=tags, now=now)
        self.pending[session] = _Pending(ephemeral, env)
        self.receivers[self.core.did].open_session(session, [])
        self._record("sent", env, "sent")
        return env

    def accept_pairing(self, request: dict, *, now: datetime | None = None) -> tuple[dict, str]:
        """Responder side. The owner has already consented to pairing with this owner."""
        session = request["session"]
        receiver = self.receivers[self.core.did]
        # The initiator picks the session identifier. Reusing a live or pending
        # one would replace its channel keys and reset its pairing record.
        if session in self.channels or session in self.pending or session in receiver.session_tags:
            raise Refused("unauthorized", "session identifier is already in use")
        self._learn(request["data"], now)
        receiver.open_session(session, [])
        try:
            receiver.receive(request, now)
        except Refused:
            receiver.close_session(session)
            raise
        self._record("received", request, "accepted")
        data = request["data"]
        ephemeral = Ephemeral()
        response = envelope.make(self.core, aud=request["sender_agent"], session=session,
                                 seq=self.next_seq(session, self.core), intent="sk.pairing.response",
                                 data=self._pairing_data(ephemeral, data["forms"], data["residency"], data["capabilities"]),
                                 payload_type=PAIRING_TYPE, residency_tags=data["residency"], now=now)
        keys = derive(ephemeral.exchange(data["eph"]), transcript_hash(request, response))
        self.channels[session] = Channel(session, keys.responder_to_initiator, keys.initiator_to_responder, "r2i", "i2r")
        self.pending[session] = _Pending(ephemeral, copy.deepcopy(request), copy.deepcopy(response), keys)
        self._record("sent", response, "sent")
        return response, keys.sas

    def complete_pairing(self, response: dict, *, now: datetime | None = None) -> tuple[dict, str]:
        """Initiator side: derive keys, compare SAS, send the pairing record."""
        session = response["session"]
        pending = self.pending[session]
        self._learn(response["data"], now)
        self.receivers[self.core.did].receive(response, now)
        self._record("received", response, "accepted")
        transcript = transcript_hash(pending.request, response)
        keys = derive(pending.ephemeral.exchange(response["data"]["eph"]), transcript)
        now_ = now or utcnow()
        req = pending.request["data"]
        record = {"v": "0.1", "session": session, "devices": [self.device.did, response["sender_device"]],
                  "forms": req["forms"], "residency": req["residency"], "capabilities": req["capabilities"],
                  "expires": ts(now_ + PAIRING_LIFETIME)}
        confirm = envelope.make(self.core, aud=response["sender_agent"], session=session,
                                seq=self.next_seq(session, self.core), intent="sk.pairing.confirm",
                                data={"v": "0.1", "transcript": b64u(transcript), "record": record},
                                payload_type=PAIRING_TYPE, residency_tags=req["residency"], now=now)
        self._open(session, Channel(session, keys.initiator_to_responder, keys.responder_to_initiator, "i2r", "r2i"), record)
        del self.pending[session]
        self._record("sent", confirm, "sent")
        return confirm, keys.sas

    def finish_pairing(self, confirm: dict, *, now: datetime | None = None) -> dict:
        session = confirm["session"]
        pending = self.pending.pop(session)
        self.receivers[self.core.did].receive(confirm, now)
        expected = transcript_hash(pending.request, pending.response)
        if b64u_decode(confirm["data"]["transcript"]) != expected:
            raise Refused("unauthorized", "pairing transcript mismatch")
        record = confirm["data"]["record"]
        for key in ("forms", "residency", "capabilities"):
            if record[key] != pending.request["data"][key]:
                raise Refused("unauthorized", f"pairing record {key} differs from the request")
        self._open(session, self.channels[session], record)
        self._record("received", confirm, "accepted")
        return record

    def _open(self, session: str, channel: Channel, record: dict) -> None:
        channel.record = record
        self.channels[session] = channel
        for did, receiver in self.receivers.items():
            actions = record["capabilities"] if did != self.core.did else None
            receiver.open_session(session, record["residency"], actions, record["devices"])

    # ------------------------------------------------------------ messaging

    def seal(self, session: str, env: dict) -> bytes:
        self._record("sent", env, "sent")
        return self.channels[session].seal(dcbor.encode(env))

    def deliver(self, session: str, frame: bytes, *, now: datetime | None = None) -> Delivery:
        channel = self.channels.get(session)
        if channel is None:
            return Delivery("dropped", "unknown-session")
        try:
            env = dcbor.decode(channel.open(frame))
        except FrameRejected as exc:
            return Delivery("dropped", exc.reason)
        except Exception:
            return Delivery("dropped", "malformed-envelope")
        aud = env.get("aud") if isinstance(env, dict) else None
        receiver = self.receivers.get(aud) or self.receivers[self.core.did]
        try:
            outcome = receiver.receive(env, now)
        except Refused as exc:
            self._record("received", env if isinstance(env, dict) else {}, f"refused: {exc.reason}")
            if isinstance(env, dict) and env.get("intent") == "sk.refused":
                return Delivery("refused", exc.reason, exc.detail, envelope=env)
            refusal = envelope.make_refusal(receiver.agent, env, exc.reason, session=session,
                                            seq=self.next_seq(session, receiver.agent), now=now)
            return Delivery("refused", exc.reason, exc.detail, reply=self.seal(session, refusal), envelope=refusal)
        self._record("received", env, outcome.status)
        return Delivery(outcome.status, outcome=outcome, envelope=env)
