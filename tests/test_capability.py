# SPDX-License-Identifier: Apache-2.0
"""Capability tokens: issue, delegate with narrowing, verify (SK-COM A6)."""

from datetime import timedelta

import pytest

from selfkin_ref import capability, schemas
from selfkin_ref.capability import resource_covers
from selfkin_ref.errors import Refused
from selfkin_ref.keys import SigningKey
from selfkin_ref.signing import sign_object
from selfkin_ref.util import parse_ts, ts, utcnow

A = "calendar.propose_meeting"
NOW = utcnow()


@pytest.fixture
def keys():
    return {name: SigningKey.generate(name) for name in ("owner", "aud", "k1", "k2", "k3")}


def root_token(keys, **overrides):
    args = dict(sub=keys["k1"].did, aud=keys["aud"].did, now=NOW, lifetime=timedelta(minutes=50),
                rights=[{"action": A, "resource": "urn:x:alice/*",
                         "constraints": {"max_uses": 5, "data_classes": ["calendar.availability", "calendar.events"],
                                         "max_amount": {"amount": "20.00", "currency": "CHF"}}}],
                budget={"messages": 10, "money": {"amount": "50", "currency": "CHF"}})
    args.update(overrides)
    return capability.issue(keys["owner"], **args)


def narrow_right(**constraints):
    base = {"max_uses": 2, "data_classes": ["calendar.availability"], "max_amount": {"amount": "5", "currency": "CHF"}}
    base.update(constraints)
    return [{"action": A, "resource": "urn:x:alice/work", "constraints": {k: v for k, v in base.items() if v is not None}}]


NARROW_BUDGET = {"messages": 3, "money": {"amount": "10", "currency": "CHF"}}


def verify(token, keys, **kw):
    return capability.verify_chain(token, now=kw.pop("now", NOW), trusted_roots={keys["owner"].did, keys["aud"].did}, **kw)


def test_root_token_valid_and_schema(keys):
    token = root_token(keys)
    schemas.validate("capability-token", token)
    assert token["chain"] == []
    result = verify(token, keys)
    assert result.links == 0 and result.root_issuer == keys["owner"].did


def test_delegation_narrows_and_verifies(keys):
    child = capability.delegate(root_token(keys), keys["k1"], sub=keys["k2"].did, now=NOW,
                                rights=narrow_right(), budget=NARROW_BUDGET)
    schemas.validate("capability-token", child)
    assert len(child["chain"]) == 1 and "chain" not in child["chain"][0]
    assert verify(child, keys).links == 1


def test_delegate_clamps_lifetime_to_parent(keys):
    parent = root_token(keys, lifetime=timedelta(minutes=10))
    child = capability.delegate(parent, keys["k1"], sub=keys["k2"].did, now=NOW, lifetime=timedelta(minutes=30),
                                rights=narrow_right(), budget=NARROW_BUDGET)
    assert parse_ts(child["exp"]) == parse_ts(parent["exp"])


WIDENINGS = {
    "wider resource": dict(rights=[{"action": A, "resource": "urn:x:*", "constraints": narrow_right()[0]["constraints"]}]),
    "other action": dict(rights=[{"action": "calendar.delete", "resource": "urn:x:alice/work",
                                  "constraints": narrow_right()[0]["constraints"]}]),
    "more uses": dict(rights=narrow_right(max_uses=6)),
    "dropped max_uses": dict(rights=narrow_right(max_uses=None)),
    "more data classes": dict(rights=narrow_right(data_classes=["calendar.availability", "health"])),
    "dropped data classes": dict(rights=narrow_right(data_classes=None)),
    "higher amount": dict(rights=narrow_right(max_amount={"amount": "20.01", "currency": "CHF"})),
    "other currency": dict(rights=narrow_right(max_amount={"amount": "1", "currency": "EUR"})),
    "higher budget": dict(budget={"messages": 11, "money": {"amount": "1", "currency": "CHF"}}),
    "dropped budget limit": dict(budget={"messages": 3}),
    "no budget": dict(budget=None),
}


@pytest.mark.parametrize("case", sorted(WIDENINGS))
def test_widening_is_refused_by_delegate_and_by_verifier(keys, case):
    parent = root_token(keys)
    args = dict(sub=keys["k2"].did, now=NOW, rights=narrow_right(), budget=NARROW_BUDGET)
    args.update(WIDENINGS[case])
    with pytest.raises(ValueError):
        capability.delegate(parent, keys["k1"], **args)
    forged = capability.delegate(parent, keys["k1"], check=False, **args)
    with pytest.raises(Refused) as info:
        verify(forged, keys)
    assert info.value.reason == "unauthorized"


def _relink(parent, child_body, signer):
    child_body = dict(child_body)
    child_body["chain"] = parent["chain"] + [{k: v for k, v in parent.items() if k != "chain"}]
    return sign_object(child_body, signer)


def test_rule_a_issuer_must_be_parent_holder(keys):
    parent = root_token(keys)
    child = capability.delegate(parent, keys["k1"], sub=keys["k2"].did, now=NOW, rights=narrow_right(), budget=NARROW_BUDGET)
    body = {k: v for k, v in child.items() if k not in ("sig", "chain")}
    body["iss"] = keys["k3"].did
    with pytest.raises(Refused, match="iss"):
        verify(_relink(parent, body, keys["k3"]), keys)


def test_rule_b_audience_unchanged(keys):
    parent = root_token(keys)
    child = capability.delegate(parent, keys["k1"], sub=keys["k2"].did, now=NOW, rights=narrow_right(), budget=NARROW_BUDGET)
    body = {k: v for k, v in child.items() if k not in ("sig", "chain")}
    body["aud"] = keys["k3"].did
    with pytest.raises(Refused, match="aud"):
        verify(_relink(parent, body, keys["k1"]), keys)


def test_rule_c_expiry_not_later(keys):
    parent = root_token(keys, lifetime=timedelta(minutes=10))
    forged = capability.delegate(parent, keys["k1"], sub=keys["k2"].did, now=NOW, lifetime=timedelta(minutes=20),
                                 rights=narrow_right(), budget=NARROW_BUDGET, check=False)
    with pytest.raises(Refused, match=r"\(c\)"):
        verify(forged, keys)


def chain_of(keys, length):
    holders = [SigningKey.generate(f"h{i}") for i in range(length + 1)]
    token = capability.issue(keys["owner"], sub=holders[0].did, aud=keys["aud"].did, now=NOW,
                             rights=[{"action": A, "resource": "urn:x:alice/*"}], lifetime=timedelta(minutes=50))
    for i in range(length):
        token = capability.delegate(token, holders[i], sub=holders[i + 1].did, now=NOW,
                                    rights=[{"action": A, "resource": "urn:x:alice/*"}])
    return token


def test_sixteen_links_allowed(keys):
    token = chain_of(keys, 16)
    assert len(token["chain"]) == 16
    schemas.validate("capability-token", token)
    assert verify(token, keys).links == 16


def test_delegate_refuses_seventeenth_link(keys):
    with pytest.raises(ValueError, match="16"):
        chain_of(keys, 17)


def test_verifier_refuses_more_than_sixteen_links(keys):
    holders = [SigningKey.generate() for _ in range(18)]
    token = capability.issue(keys["owner"], sub=holders[0].did, aud=keys["aud"].did, now=NOW,
                             rights=[{"action": A, "resource": "urn:x:alice/*"}])
    for i in range(17):
        token = capability.delegate(token, holders[i], sub=holders[i + 1].did, now=NOW,
                                    rights=[{"action": A, "resource": "urn:x:alice/*"}], check=False)
    assert len(token["chain"]) == 17
    assert schemas.errors("capability-token", token)
    with pytest.raises(Refused, match="16"):
        verify(token, keys)


def test_lifetime_over_one_hour_refused(keys):
    token = root_token(keys, lifetime=timedelta(minutes=61))
    with pytest.raises(Refused, match="lifetime"):
        verify(token, keys)


def test_expired_and_not_yet_valid(keys):
    token = root_token(keys, lifetime=timedelta(minutes=5))
    with pytest.raises(Refused) as info:
        verify(token, keys, now=NOW + timedelta(minutes=5))
    assert info.value.reason == "expired"
    body = {k: v for k, v in token.items() if k != "sig"}
    body["nbf"] = ts(NOW + timedelta(minutes=1))
    with pytest.raises(Refused, match="not yet valid"):
        verify(sign_object(body, keys["owner"]), keys)


def test_untrusted_root_issuer(keys):
    token = capability.issue(keys["k3"], sub=keys["k1"].did, aud=keys["aud"].did, now=NOW,
                             rights=[{"action": A, "resource": "urn:x:alice/*"}])
    with pytest.raises(Refused, match="root issuer"):
        verify(token, keys)


def test_cnf_must_match_holder(keys):
    body = {k: v for k, v in root_token(keys).items() if k != "sig"}
    body["cnf"] = {"jkt": keys["k2"].thumbprint}
    with pytest.raises(Refused, match="cnf"):
        verify(sign_object(body, keys["owner"]), keys)
    body["cnf"] = {"kid": keys["k1"].kid}
    verify(sign_object(body, keys["owner"]), keys)
    body["cnf"] = {"x5t#S256": "abc"}
    with pytest.raises(Refused, match="proof-of-possession"):
        verify(sign_object(body, keys["owner"]), keys)


def test_tampered_link_in_chain(keys):
    child = capability.delegate(root_token(keys), keys["k1"], sub=keys["k2"].did, now=NOW,
                                rights=narrow_right(), budget=NARROW_BUDGET)
    child["chain"][0]["rights"][0]["resource"] = "urn:*"
    with pytest.raises(Refused, match="link 0"):
        verify(child, keys)


def test_find_right(keys):
    token = root_token(keys)
    assert capability.find_right(token, A, "urn:x:alice/work/today")["action"] == A
    for action, resource in ((A, "urn:x:bob/work"), ("calendar.delete", "urn:x:alice/work"), (A, None)):
        with pytest.raises(Refused):
            capability.find_right(token, action, resource)


@pytest.mark.parametrize("parent,child,expected", [
    ("urn:x:a/b", "urn:x:a/b", True),
    ("urn:x:a/*", "urn:x:a/b", True),
    ("urn:x:a/*", "urn:x:a/b/c", True),
    ("urn:x:a/*", "urn:x:a/*", True),
    ("urn:x:a/*", "urn:x:a/", False),
    ("urn:x:a/*", "urn:x:a", False),
    ("urn:x:a/*", "urn:x:ab", False),
    ("urn:x:a/b", "urn:x:a/b/c", False),
    ("urn:x:a/b", "urn:x:a/*", False),
])
def test_resource_covers(parent, child, expected):
    assert resource_covers(parent, child) is expected
