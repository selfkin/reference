# SPDX-License-Identifier: Apache-2.0
"""Envelope build and receiver checks (SK-COM A5, A6, A7, A9)."""

import copy
from datetime import timedelta

import pytest

from conftest import ACTION, ALL, WORK, make_world
from selfkin_ref import capability, envelope, schemas
from selfkin_ref.errors import Refused
from selfkin_ref.identity import Owner
from selfkin_ref.signing import sign_object


def refused(world, env, now=None):
    with pytest.raises(Refused) as info:
        world.receiver.receive(env, now or world.now)
    return info.value.reason


def resign(world, env, sender=None):
    return sign_object({k: v for k, v in env.items() if k != "sig"}, (sender or world.assistant).key)


def test_built_envelope_has_required_members(world):
    env = world.instruction()
    schemas.validate("envelope", env)
    assert env["attestation_ref"] is None and env["provenance"] == []
    assert len(env["nonce"]) >= 22 and env["sig"]["canon"] == "dcbor"


def test_happy_path_executes_once(world):
    outcome = world.receiver.receive(world.instruction(), world.now)
    assert outcome.status == "executed" and outcome.token_links == 1
    assert len(world.executed) == 1


def test_build_rejects_inconsistent_members(world):
    with pytest.raises(ValueError):
        envelope.build(world.assistant, aud=world.calendar.did, session=world.session, seq=0, intent="task.run",
                       instructions={"action": ACTION})
    with pytest.raises(ValueError):
        envelope.build(world.assistant, aud=world.calendar.did, session=world.session, seq=0, intent="task.run",
                       data={"x": 1})


def test_unknown_major_version(world):
    env = resign(world, dict(world.instruction(), v="1.0"))
    assert refused(world, env) == "unsupported-version"


@pytest.mark.parametrize("change", [
    lambda e: e.update({"unknown": 1}),
    lambda e: e.pop("idem_key"),
    lambda e: e.pop("cap_token"),
    lambda e: e.update({"data": {"x": 1}}),
    lambda e: e.update({"form": "F5"}),
    lambda e: e.update({"nonce": "short"}),
    lambda e: e["residency"].update({"tags": ["ch"]}),
    lambda e: e.pop("sig"),
])
def test_malformed(world, change):
    env = copy.deepcopy(world.instruction())
    change(env)
    if "sig" in env:
        env = resign(world, env)
    assert refused(world, env) == "malformed"


def test_wrong_audience(world):
    env = world.instruction(aud=world.b.core.did)
    assert refused(world, env) == "wrong-audience"


def test_unknown_or_revoked_sender(world):
    stranger = Owner.create("mallory").add_device("x", "CH").add_agent("agent")
    env = envelope.make(stranger, aud=world.calendar.did, session=world.session, seq=0, intent="scheduling.propose",
                        cap_token=world.delegated, instructions={"action": ACTION, "resource": WORK},
                        idem_key="idem-key-0123456789", now=world.now)
    assert refused(world, env) == "unauthorized"
    world.b.trust.revoke(world.assistant.did)
    assert refused(world, world.instruction()) == "revoked"


def test_agent_must_match_device(world):
    env = dict(world.instruction(), sender_device=world.b.device.did)
    assert refused(world, resign(world, env)) == "unauthorized"


def test_tampered_or_wrongly_signed(world):
    env = copy.deepcopy(world.instruction())
    env["instructions"]["resource"] = "urn:selfkin:calendar:alice/private"
    assert refused(world, env) == "bad-signature"
    assert refused(world, resign(world, world.instruction(), sender=world.planner)) == "bad-signature"


def test_freshness(world):
    later = world.now + timedelta(minutes=6)
    assert refused(world, world.instruction(), now=later) == "expired"
    future = world.instruction(now=world.now + timedelta(minutes=2))
    assert refused(world, future) == "expired"
    too_long = envelope.make(world.assistant, aud=world.calendar.did, session=world.session, seq=99,
                             intent="scheduling.propose", cap_token=world.delegated,
                             instructions={"action": ACTION, "resource": WORK}, idem_key="idem-key-0123456789",
                             data_classes=["calendar.availability"], lifetime=timedelta(hours=1), now=world.now)
    assert refused(world, too_long) == "expired"


def test_replayed_nonce_and_seq(world):
    env = world.instruction()
    world.receiver.receive(env, world.now)
    assert refused(world, env) == "replayed"
    same_seq = world.instruction(seq=env["seq"])
    assert refused(world, same_seq) == "replayed"


def test_out_of_order_inside_window_is_accepted_but_old_seq_is_not(world):
    world.receiver.receive(world.instruction(seq=5), world.now)
    world.receiver.receive(world.instruction(seq=3), world.now)
    world.receiver.receive(world.instruction(seq=70), world.now)
    assert refused(world, world.instruction(seq=6)) == "out-of-sequence"


def test_unpaired_session(world):
    env = world.instruction(session="other-session-1")
    assert refused(world, env) == "unauthorized"


def test_residency_checks(world):
    assert refused(world, world.instruction(tags=("EU",))) == "residency-unsupported"
    assert refused(world, world.instruction(tags=("x-family",))) == "residency-unknown-tag"


def test_session_residency_intersects_with_envelope():
    world = make_world(region_b="EU", tags=("CH-EU",))
    world.receiver.receive(world.instruction(tags=()), world.now)
    assert refused(world, world.instruction(tags=("CH",))) == "residency-unsupported"


def test_wrapped_token_format(world):
    env = world.instruction(token={"format": "biscuit", "token": "abc"})
    assert refused(world, env) == "unsupported-token-format"


def test_token_binding(world):
    # token held by assistant, presented by planner
    assert refused(world, world.instruction(sender=world.planner)) == "unauthorized"
    # token for another audience
    other = capability.issue(world.alice.key, sub=world.assistant.did, aud=world.b.core.did, now=world.now,
                             rights=[{"action": ACTION, "resource": WORK}])
    assert refused(world, world.instruction(token=other)) == "unauthorized"


def test_rights_must_cover_instruction(world):
    assert refused(world, world.instruction(resource="urn:selfkin:calendar:alice/home")) == "unauthorized"
    assert refused(world, world.instruction(action="calendar.delete")) == "unauthorized"


def test_data_classes_bounded_by_token(world):
    env = world.instruction(data_classes=("calendar.availability", "calendar.events"))
    assert refused(world, env) == "data-class-forbidden"


def test_budget_and_max_uses(world):
    for _ in range(3):
        world.receiver.receive(world.instruction(), world.now)
    assert refused(world, world.instruction()) == "budget-exceeded"  # max_uses 3


def test_message_budget_counts_across_chain():
    world = make_world()
    token = capability.delegate(world.root, world.planner.key, sub=world.assistant.did, now=world.now,
                                rights=[{"action": ACTION, "resource": WORK,
                                         "constraints": {"data_classes": ["calendar.availability"], "max_uses": 5}}],
                                budget={"messages": 2})
    world.receiver.receive(world.instruction(token=token), world.now)
    world.receiver.receive(world.instruction(token=token), world.now)
    assert refused(world, world.instruction(token=token)) == "budget-exceeded"


def test_cross_owner_delegation_refused_below_c2(world):
    bob = Owner.create("bob")
    bob_agent = bob.add_device("bobphone", "CH", now=world.now).add_agent("helper", now=world.now)
    # alice's planner hands the task to bob's agent: F6 across owners
    token = capability.delegate(world.root, world.planner.key, sub=bob_agent.did, now=world.now,
                                rights=[{"action": ACTION, "resource": WORK,
                                         "constraints": {"data_classes": ["calendar.availability"], "max_uses": 1}}],
                                budget={"messages": 1})
    # homebox knows bob and has a session with bob's device, so only the owner rule can refuse
    world.b.trust.trust_owner(bob.did, "bob")
    world.b.trust.add_statement(bob_agent.device.statement, world.now)
    world.b.trust.add_statement(bob_agent.statement, world.now)
    world.receiver.open_session("bob-session-1", ["CH"], [ACTION], [bob_agent.device.did])
    env = envelope.make(bob_agent, aud=world.calendar.did, session="bob-session-1", seq=0, form="F6",
                        intent="scheduling.propose", cap_token=token, instructions={"action": ACTION, "resource": WORK},
                        idem_key="idem-key-0123456789", data_classes=["calendar.availability"], now=world.now)
    with pytest.raises(Refused, match="crosses owners") as info:
        world.receiver.receive(env, world.now)
    assert info.value.reason == "unauthorized"
    world.receiver.profile = "C2"  # at C2 the verified, attenuated chain is acceptable
    assert world.receiver.receive(envelope.make(bob_agent, aud=world.calendar.did, session="bob-session-1", seq=1,
                                                form="F6", intent="scheduling.propose", cap_token=token,
                                                instructions={"action": ACTION, "resource": WORK},
                                                idem_key="idem-key-0123456789b",
                                                data_classes=["calendar.availability"], now=world.now),
                                  world.now).status == "executed"


def test_sender_device_must_belong_to_session(world):
    other = world.alice.add_device("tablet", "CH", now=world.now)
    world.b.trust.add_statement(other.statement, world.now)
    agent = other.add_agent("assistant", now=world.now)
    world.b.trust.add_statement(agent.statement, world.now)
    token = capability.issue(world.alice.key, sub=agent.did, aud=world.calendar.did, now=world.now,
                             rights=[{"action": ACTION, "resource": WORK}])
    env = envelope.make(agent, aud=world.calendar.did, session=world.session, seq=0, intent="scheduling.propose",
                        cap_token=token, instructions={"action": ACTION, "resource": WORK},
                        idem_key="idem-key-0123456789", now=world.now)
    with pytest.raises(Refused, match="not part of this paired session"):
        world.receiver.receive(env, world.now)


def test_action_outside_pairing_record_is_policy_denied(world):
    world.receiver.handlers["calendar.read"] = lambda env: {}
    token = capability.issue(world.alice.key, sub=world.assistant.did, aud=world.calendar.did, now=world.now,
                             rights=[{"action": "calendar.read", "resource": ALL}])
    assert refused(world, world.instruction(token=token, action="calendar.read")) == "policy-denied"


def test_idempotency_key_executes_once(world):
    first = world.receiver.receive(world.instruction(idem="idem-key-fixed-0001"), world.now)
    second = world.receiver.receive(world.instruction(idem="idem-key-fixed-0001"), world.now)
    assert (first.status, second.status) == ("executed", "duplicate")
    assert second.result == first.result and len(world.executed) == 1


def test_refusal_envelope(world):
    env = world.instruction()
    refusal = envelope.make_refusal(world.calendar, env, "replayed", session=world.session, seq=0, now=world.now)
    schemas.validate("envelope", refusal)
    assert refusal["intent"] == "sk.refused" and "cap_token" not in refusal and "instructions" not in refusal
    assert refusal["payload_type"] == "application/vnd.selfkin.refusal+json"
    assert refusal["data"] == {"v": "0.1", "reason": "replayed",
                               "ref": {k: env[k] for k in ("session", "seq", "nonce", "idem_key")}}


def test_refusal_for_garbage_input_has_no_ref(world):
    refusal = envelope.make_refusal(world.calendar, {"nonce": "x", "sender_agent": "not a uri"}, "malformed",
                                    session=world.session, seq=0, now=world.now)
    assert refusal["data"] == {"v": "0.1", "reason": "malformed"}
    assert refusal["aud"] == "urn:selfkin:unknown"


def test_refusals_are_accepted_without_token(world):
    refusal = envelope.make_refusal(world.calendar, world.instruction(), "unauthorized", session=world.session,
                                    seq=0, now=world.now)
    receiver = world.a.receivers[world.assistant.did]
    assert receiver.receive(refusal, world.now).status == "executed"
