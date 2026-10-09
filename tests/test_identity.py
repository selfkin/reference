# SPDX-License-Identifier: Apache-2.0
"""Owner-signed statements binding devices and agents (reference-only format)."""

from datetime import timedelta

import pytest

from selfkin_ref.errors import Refused
from selfkin_ref.identity import Owner, TrustStore, issue_statement
from selfkin_ref.util import utcnow

NOW = utcnow()


def setup():
    alice = Owner.create("alice")
    device = alice.add_device("phone", "CH", now=NOW)
    agent = device.add_agent("planner", now=NOW)
    trust = TrustStore()
    trust.trust_owner(alice.did, "alice")
    return alice, device, agent, trust


def test_statements_bind_agent_to_device_and_owner():
    alice, device, agent, trust = setup()
    assert agent.did != device.did != alice.did
    trust.add_statement(device.statement, NOW)
    trust.add_statement(agent.statement, NOW)
    assert trust.check_agent(agent.did, device.did, NOW) == alice.did
    assert trust.owner_of(agent.did) == alice.did and trust.owner_of(alice.did) == alice.did
    assert trust.owner_of("did:key:zunknown") is None


def test_untrusted_owner_and_tampering():
    alice, device, agent, trust = setup()
    mallory = Owner.create("mallory")
    with pytest.raises(Refused):
        trust.add_statement(issue_statement(mallory.key, device.did, "device", now=NOW), NOW)
    forged = dict(device.statement, sub=agent.did)
    with pytest.raises(Refused) as info:
        trust.add_statement(forged, NOW)
    assert info.value.reason == "bad-signature"


def test_agent_needs_known_device_first():
    alice, device, agent, trust = setup()
    with pytest.raises(Refused, match="unknown device"):
        trust.add_statement(agent.statement, NOW)


def test_statement_validity_window():
    alice, device, agent, trust = setup()
    with pytest.raises(Refused) as info:
        trust.add_statement(device.statement, NOW + timedelta(days=31))
    assert info.value.reason == "expired"


def test_revocation_and_wrong_device():
    alice, device, agent, trust = setup()
    other = alice.add_device("tablet", "CH", now=NOW)
    for statement in (device.statement, other.statement, agent.statement):
        trust.add_statement(statement, NOW)
    with pytest.raises(Refused, match="not bound"):
        trust.check_agent(agent.did, other.did)
    trust.revoke(device.did)
    with pytest.raises(Refused) as info:
        trust.check_agent(agent.did, device.did)
    assert info.value.reason == "revoked"


def test_agent_statement_requires_device():
    alice = Owner.create("alice")
    with pytest.raises(ValueError):
        issue_statement(alice.key, "did:key:zabc", "agent")


def test_expired_statement_stops_working_at_use_time():
    alice, device, agent, trust = setup()
    trust.add_statement(device.statement, NOW)
    trust.add_statement(agent.statement, NOW)
    with pytest.raises(Refused) as info:
        trust.check_agent(agent.did, device.did, NOW + timedelta(days=31))
    assert info.value.reason == "expired"


def test_revoked_owner_stops_its_agents():
    alice, device, agent, trust = setup()
    trust.add_statement(device.statement, NOW)
    trust.add_statement(agent.statement, NOW)
    trust.revoke(alice.did)
    with pytest.raises(Refused) as info:
        trust.check_agent(agent.did, device.did, NOW)
    assert info.value.reason == "revoked"
