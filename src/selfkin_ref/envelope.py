# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Selfkin reference contributors
"""Selfkin Envelope (SK-COM A5): build, sign, and receive.

``Receiver.receive`` runs the receiver checks in a fixed order and either
executes the requested action or raises ``Refused`` with a registry reason
code. ``make_refusal`` turns that into a signed ``sk.refused`` envelope.

Check order (cheap and structural first, authority last):

1. major version known (``unsupported-version``)
2. JSON Schema (``malformed``)
3. ``aud`` is this agent (``wrong-audience``)
4. sender agent bound to sender device by a trusted owner (``unauthorized``, ``revoked``)
5. envelope signature by ``sender_agent`` (``bad-signature``)
6. ``issued`` and ``expires`` within limits (``expired``)
7. nonce not seen (``replayed``), ``seq`` inside the window (``out-of-sequence``, ``replayed``)
8. session paired with the sender device; residency: tags known, and this device's region allowed by the
   intersection of the envelope tags and the session tags (``residency-*``)
9. capability token: chain valid, bound to the envelope, rights cover the
   instruction, data classes allowed, budget and uses left
   (``unauthorized``, ``expired``, ``data-class-forbidden``, ``budget-exceeded``)
10. local policy: a handler exists for the action (``policy-denied``)
11. ``idem_key`` executed at most once (a repeat returns the stored result)
"""

from __future__ import annotations

import re
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable

from . import capability, residency, schemas
from .errors import Refused
from .identity import Agent, TrustStore
from .signing import sign_object, verify_object
from .util import new_nonce, parse_ts, ts, utcnow

VERSION = "0.1"
REFUSAL_TYPE = "application/vnd.selfkin.refusal+json"
_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$")


def needs_token(intent: str) -> bool:
    return not (intent.startswith("sk.pairing.") or intent == "sk.refused")


def build(sender: Agent, *, aud: str, session: str, seq: int, intent: str, form: str = "F1",
          instructions: dict | None = None, data=None, payload_type: str | None = None,
          residency_tags: list[str] | None = None, data_classes: list[str] | None = None,
          cap_token: dict | None = None, idem_key: str | None = None, provenance: list | None = None,
          model_ref: dict | None = None, lifetime: timedelta = timedelta(minutes=5),
          now: datetime | None = None) -> dict:
    """Build an unsigned envelope with every required member."""
    now = now or utcnow()
    env = {
        "v": VERSION, "form": form, "sender_agent": sender.did, "sender_device": sender.device.did,
        "aud": aud, "session": session, "seq": seq, "attestation_ref": None, "intent": intent,
        "residency": {"tags": list(residency_tags or []), "data_classes": list(data_classes or [])},
        "nonce": new_nonce(), "issued": ts(now), "expires": ts(now + lifetime),
        "provenance": list(provenance or []),
    }
    if cap_token is not None:
        env["cap_token"] = cap_token
    if instructions is not None:
        env["instructions"] = instructions
        if idem_key is None:
            raise ValueError("instructions require an idem_key (SK-COM A5)")
    if idem_key is not None:
        env["idem_key"] = idem_key
    if (data is None) != (payload_type is None):
        raise ValueError("data and payload_type appear together or not at all (SK-COM A5)")
    if data is not None:
        env["data"], env["payload_type"] = data, payload_type
    if model_ref is not None:
        env["model_ref"] = model_ref
    return env


def sign(env: dict, sender: Agent, canon: str = "dcbor") -> dict:
    return sign_object(env, sender.key, canon=canon)


def make(sender: Agent, **kwargs) -> dict:
    """Build, sign, and schema-check an envelope."""
    env = sign(build(sender, **kwargs), sender)
    schemas.validate("envelope", env)
    return env


def _safe_ref(env) -> dict:
    """Refusal ``ref`` from values the requester sent, keeping only valid ones."""
    ref = {}
    if not isinstance(env, dict):
        return ref
    for key in ("session", "seq", "nonce", "idem_key"):
        if key in env:
            candidate = {"v": VERSION, "reason": "malformed", "ref": {key: env[key]}}
            if not schemas.errors("refusal", candidate):
                ref[key] = env[key]
    return ref


def make_refusal(sender: Agent, request, reason: str, *, session: str, seq: int,
                 retry_after: str | None = None, now: datetime | None = None) -> dict:
    """A signed ``sk.refused`` envelope. Carries a code and references only."""
    refusal = {"v": VERSION, "reason": reason}
    ref = _safe_ref(request)
    if ref:
        refusal["ref"] = ref
    if retry_after:
        refusal["retry_after"] = retry_after
    schemas.validate("refusal", refusal)
    aud = request.get("sender_agent") if isinstance(request, dict) else None
    if not isinstance(aud, str) or not _IDENTIFIER.match(aud):
        aud = "urn:selfkin:unknown"
    return make(sender, aud=aud, session=session, seq=seq, intent="sk.refused",
                data=refusal, payload_type=REFUSAL_TYPE, now=now)


# ------------------------------------------------------------- receiver


@dataclass
class Outcome:
    status: str  # "executed" or "duplicate"
    action: str | None
    result: dict | None
    token_links: int = 0


@dataclass
class SessionState:
    tags: list[str]
    highest: int = -1
    seen: set[int] = field(default_factory=set)


Handler = Callable[[dict], dict]


class Receiver:
    """Receiving side of one agent. Holds replay, sequence, and budget state."""

    def __init__(self, agent: Agent, trust: TrustStore, *, handlers: dict[str, Handler] | None = None,
                 seq_window: int = 64, max_skew: timedelta = timedelta(seconds=30),
                 max_lifetime: timedelta = timedelta(minutes=10), communication_profile: str = "C1",
                 owner_tags: dict | None = None) -> None:
        self.agent = agent
        self.trust = trust
        self.handlers = dict(handlers or {})
        self.seq_window = seq_window
        self.max_skew = max_skew
        self.max_lifetime = max_lifetime
        self.profile = communication_profile
        self.owner_tags = owner_tags
        self.sessions: dict[tuple[str, str], SessionState] = {}
        self.session_tags: dict[str, list[str]] = {}
        self.session_actions: dict[str, set[str] | None] = {}
        self.session_devices: dict[str, set[str] | None] = {}
        self.nonces: OrderedDict[str, datetime] = OrderedDict()
        self.idem: dict[tuple[str, str], Outcome] = {}
        self.usage: dict[str, int] = {}

    # sessions are opened by pairing (e2e.py) with the residency tags agreed there
    def open_session(self, session: str, tags: list[str] | None = None, actions: list[str] | None = None,
                     devices: list[str] | None = None) -> None:
        """Accept envelopes on ``session``. ``devices`` limits who may send on it."""
        self.session_tags[session] = list(tags or [])
        self.session_actions[session] = set(actions) if actions is not None else None
        self.session_devices[session] = set(devices) if devices is not None else None

    def close_session(self, session: str) -> None:
        """Stop accepting envelopes on ``session``."""
        for table in (self.session_tags, self.session_actions, self.session_devices):
            table.pop(session, None)

    def receive(self, env, now: datetime | None = None) -> Outcome:
        now = now or utcnow()
        # 1. version
        version = env.get("v") if isinstance(env, dict) else None
        if not isinstance(version, str) or version.split(".")[0] != VERSION.split(".")[0]:
            raise Refused("unsupported-version", f"version {version!r}")
        # 2. structure
        schemas.validate("envelope", env)
        # 3. audience
        if env["aud"] != self.agent.did:
            raise Refused("wrong-audience", "envelope is addressed to someone else")
        # 4. identity
        self.trust.check_agent(env["sender_agent"], env["sender_device"], now)
        # 5. signature
        verify_object(env, expected_signer=env["sender_agent"])
        # 6. freshness
        try:
            issued, expires = parse_ts(env["issued"]), parse_ts(env["expires"])
        except ValueError:
            raise Refused("malformed", "issued or expires is not a valid timestamp") from None
        if expires <= issued or expires - issued > self.max_lifetime:
            raise Refused("expired", "invalid lifetime")
        if issued > now + self.max_skew:
            raise Refused("expired", "issued in the future")
        if expires <= now:
            raise Refused("expired", "envelope expired")
        # 7. replay and order
        self._check_replay(env, now, expires)
        # 8. residency
        if env["session"] not in self.session_tags:
            raise Refused("unauthorized", "no paired session with this identifier")
        devices = self.session_devices.get(env["session"])
        if devices is not None and env["sender_device"] not in devices:
            raise Refused("unauthorized", "sender device is not part of this paired session")
        tags = list(env["residency"]["tags"]) + self.session_tags[env["session"]]
        residency.check_destination(tags, self.agent.device.region, self.owner_tags)
        if env["intent"] == "sk.refused" or env["intent"].startswith("sk.pairing."):
            return Outcome("executed", None, None)
        # 9. capability
        token = env["cap_token"]
        if "format" in token:
            raise Refused("unsupported-token-format", f"format {token['format']!r}")
        verified = self._check_token(env, token, now)
        # 10 and 11. local policy and idempotency
        return self._execute(env, verified)

    def _check_replay(self, env: dict, now: datetime, expires: datetime) -> None:
        for nonce, until in list(self.nonces.items()):
            if until > now:
                break
            del self.nonces[nonce]
        if env["nonce"] in self.nonces:
            raise Refused("replayed", "nonce already seen")
        key = (env["session"], env["sender_agent"])
        state = self.sessions.setdefault(key, SessionState(tags=[]))
        seq = env["seq"]
        if seq in state.seen:
            raise Refused("replayed", f"seq {seq} already seen")
        if seq <= state.highest - self.seq_window:
            raise Refused("out-of-sequence", f"seq {seq} is outside the window")
        self.nonces[env["nonce"]] = expires + self.max_skew
        state.seen.add(seq)
        state.highest = max(state.highest, seq)
        state.seen = {s for s in state.seen if s > state.highest - self.seq_window}

    def _check_token(self, env: dict, token: dict, now: datetime) -> capability.VerifiedToken:
        roots = {self.agent.did, self.agent.device.owner.did}
        verified = capability.verify_chain(token, now=now, trusted_roots=roots)
        if self.profile in ("C0", "C1"):
            self._check_same_owner(token)
        if token["sub"] != env["sender_agent"]:
            raise Refused("unauthorized", "token sub is not the sender agent")
        if token["aud"] != env["aud"]:
            raise Refused("unauthorized", "token aud is not the envelope aud")
        if "instructions" not in env:
            raise Refused("unauthorized", "token-bearing envelope without instructions is not supported here")
        ins = env["instructions"]
        right = capability.find_right(token, ins["action"], ins.get("resource"))
        allowed = right.get("constraints", {}).get("data_classes")
        if allowed is not None and not set(env["residency"]["data_classes"]) <= set(allowed):
            raise Refused("data-class-forbidden", "envelope data classes exceed the token")
        verified.right = right
        return verified

    def _check_same_owner(self, token: dict) -> None:
        """Below C2, F6 delegation must not cross owners (SK-COM A6)."""
        links = token["chain"] + [token]
        for link in links[1:]:
            owners = {self.trust.owner_of(link["iss"]), self.trust.owner_of(link["sub"])}
            if None in owners or len(owners) != 1:
                raise Refused("unauthorized", "delegation crosses owners below C2")

    def _check_budget(self, token: dict, right: dict) -> None:
        links = token["chain"] + [token]
        for link in links:
            limit = link.get("budget", {}).get("messages")
            if limit is not None and self.usage.get("msg:" + link["id"], 0) >= limit:
                raise Refused("budget-exceeded", f"message budget of token {link['id']} used up")
        uses = right.get("constraints", {}).get("max_uses")
        use_key = f"use:{token['id']}:{right['action']}:{right['resource']}"
        if uses is not None and self.usage.get(use_key, 0) >= uses:
            raise Refused("budget-exceeded", "max_uses reached")
        for link in links:
            self.usage["msg:" + link["id"]] = self.usage.get("msg:" + link["id"], 0) + 1
        self.usage[use_key] = self.usage.get(use_key, 0) + 1

    def _execute(self, env: dict, verified: capability.VerifiedToken) -> Outcome:
        ins = env["instructions"]
        key = (env["sender_agent"], env["idem_key"])
        if key in self.idem:
            previous = self.idem[key]
            return Outcome("duplicate", previous.action, previous.result, verified.links)
        allowed = self.session_actions.get(env["session"])
        if allowed is not None and ins["action"] not in allowed:
            raise Refused("policy-denied", "the pairing record does not allow this action")
        handler = self.handlers.get(ins["action"])
        if handler is None:
            raise Refused("policy-denied", "no local handler for this action")
        self._check_budget(verified.token, verified.right)
        outcome = Outcome("executed", ins["action"], handler(env), verified.links)
        self.idem[key] = outcome
        return outcome
