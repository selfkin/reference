# SPDX-License-Identifier: Apache-2.0
"""Privacy Gateway and privacy reports (SK-RT section 13)."""

import hashlib
import json

import pytest

from selfkin_ref import dcbor, schemas
from selfkin_ref.errors import Refused
from selfkin_ref.privacy import ContextItem, PrivacyGateway, Provider
from selfkin_ref.util import b64u

SECRET_VALUES = ("bob@example.org", "Alice Example", "physio", "46.948,7.447", "hunter2", "CH93 0000")


def context():
    return [
        ContextItem("request.title", "query.general", "Draft an invite"),
        ContextItem("calendar.free_slots", "calendar.availability", ["Tue 10:00"]),
        ContextItem("attendee.email", "contacts.email", "bob@example.org"),
        ContextItem("owner.name", "identity.name", "Alice Example"),
        ContextItem("owner.health_note", "health.records", "physio"),
        ContextItem("owner.location", "location.precise", "46.948,7.447"),
        ContextItem("api.password", "secrets", "hunter2"),
        ContextItem("owner.iban", "finance.account", "CH93 0000"),
        ContextItem("calendar.history", "calendar.events", ["..."], needed=False),
    ]


P0 = Provider(id="urn:selfkin:provider:p0", region="CH", retention="undeclared")
VERIFIED = Provider(id="urn:selfkin:provider:p2", claimed="P2", verified=True, region="CH", retention="PT0S")
RELAY = {"type": "ohttp", "id": "urn:selfkin:relay:example"}


def prepare(provider=P0, relay=None, tags=("CH-EU",)):
    return PrivacyGateway("did:key:z6MkAgent", relay=relay).prepare(provider, context(), residency_tags=list(tags))


@pytest.mark.parametrize("provider,relay", [(P0, None), (P0, RELAY), (VERIFIED, None), (VERIFIED, RELAY)])
def test_report_is_schema_valid_and_has_no_values(provider, relay):
    call = prepare(provider, relay)
    schemas.validate("privacy-report", call.report)
    text = json.dumps(call.report)
    for value in SECRET_VALUES:
        assert value not in text


def test_p0_uses_full_gateway_mode():
    call = prepare()
    report = call.report
    assert report["gateway_mode"] == "full" and report["account"] == {"mode": "anonymous", "linkable": False}
    assert report["provider_profile"] == {"claimed": None, "effective": "P0", "verified": False}
    payload = call.payload["input"]
    assert set(payload) == {"request.title", "calendar.free_slots", "attendee.email", "owner.name"}
    assert payload["attendee.email"] != "bob@example.org" and payload["owner.name"] != "Alice Example"
    assert report["redacted"]["pseudonymised"] == ["attendee.email", "owner.name"]
    assert "contacts.email" not in report["sent"]["data_classes"]


def test_missing_relay_is_visible_and_relay_required_classes_withheld():
    call = prepare()
    assert call.report["relay"] == {"used": False} and call.report["network_identity"] == "direct"
    assert {"owner.health_note", "owner.location", "owner.iban"} <= set(call.report["redacted"]["fields"])
    assert any("no relay" in w for w in call.warnings)


def test_relay_used():
    call = prepare(relay=RELAY)
    assert call.report["relay"] == {"used": True, **RELAY} and call.report["network_identity"] == "relay"
    assert "relay" in call.report["minimisation"]["steps"]
    # with a relay, health is still redacted in full mode, because it is sensitive
    assert "owner.health_note" not in call.payload["input"]


def test_secrets_and_local_only_never_leave():
    for provider, relay in ((P0, None), (VERIFIED, RELAY)):
        call = prepare(provider, relay)
        assert "api.password" not in call.payload["input"]
        assert "hunter2" not in json.dumps(call.payload)


def test_verified_provider_mode():
    call = prepare(VERIFIED, RELAY)
    assert call.report["gateway_mode"] == "verified-provider"
    assert call.report["provider_profile"] == {"claimed": "P2", "effective": "P2", "verified": True}
    assert call.report["retention"] == {"declared": "PT0S"}


def test_unverified_claim_is_a_visible_downgrade():
    provider = Provider(id="urn:selfkin:provider:x", claimed="P3", verified=False, verification_failure="expired", region="CH")
    report = prepare(provider).report
    assert report["provider_profile"]["effective"] == "P0"
    assert report["provider_profile"]["downgrade"] == {"from": "P3", "reason": "expired"}
    assert report["gateway_mode"] == "full"


def test_digest_matches_exact_payload():
    call = prepare()
    encoded = dcbor.encode(call.payload)
    assert call.report["minimisation"]["payload_digest"] == {"alg": "sha-256", "value": b64u(hashlib.sha256(encoded).digest())}
    assert call.report["sent"]["bytes"] == len(encoded)


def test_residency_blocks_call():
    with pytest.raises(Refused) as info:
        prepare(Provider(id="urn:selfkin:provider:us", region="US"))
    assert info.value.reason == "residency-unsupported"
    with pytest.raises(Refused):
        prepare(Provider(id="urn:selfkin:provider:unknown-region"))
    prepare(Provider(id="urn:selfkin:provider:unknown-region"), tags=())


def test_pseudonyms_are_stable_and_not_reported():
    gateway = PrivacyGateway("did:key:z6MkAgent")
    first = gateway.prepare(P0, context(), residency_tags=["CH"])
    second = gateway.prepare(P0, context(), residency_tags=["CH"])
    assert first.payload["input"]["attendee.email"] == second.payload["input"]["attendee.email"]
    assert first.report["id"] != second.report["id"]
    assert "bob@example.org" not in json.dumps(first.report)
