# SPDX-License-Identifier: Apache-2.0
"""Malformed but signed input is refused with a reason code, never a crash."""

from datetime import timedelta

import pytest

from selfkin_ref import capability
from selfkin_ref.errors import Refused
from selfkin_ref.identity import TrustStore, issue_statement
from selfkin_ref.signing import sign_object
from selfkin_ref.util import parse_ts, ts


def _resign(obj, key, **changes):
    body = {k: v for k, v in obj.items() if k != "sig"}
    body.update(changes)
    return sign_object(body, key)


@pytest.mark.parametrize("value", ["2026-13-45T25:61:61Z", "2026-02-30T00:00:00Z", "2026-10-09T10:00:60Z"])
def test_envelope_with_impossible_timestamp_is_malformed(world, value):
    env = _resign(world.instruction(), world.assistant.key, issued=value)
    with pytest.raises(Refused) as info:
        world.receiver.receive(env, world.now)
    assert info.value.reason == "malformed"


def test_token_link_with_impossible_timestamp_is_malformed(world):
    token = _resign(world.root, world.alice.key, exp="2026-02-30T00:00:00Z")
    with pytest.raises(Refused) as info:
        capability.verify_chain(token, now=world.now, trusted_roots={world.alice.did})
    assert info.value.reason == "malformed"


def test_owner_statement_with_bad_members_is_malformed(world):
    trust = TrustStore()
    trust.trust_owner(world.alice.did)
    statement = issue_statement(world.alice.key, world.assistant.did, "device", now=world.now)
    for change in ({"iat": "yesterday"}, {"kind": "owner"}):
        with pytest.raises(Refused) as info:
            trust.add_statement(_resign(statement, world.alice.key, **change), world.now)
        assert info.value.reason == "malformed"


def test_parse_ts_accepts_long_fractions_and_offsets():
    assert parse_ts("2026-10-09T10:00:00.123456789+02:00") == parse_ts("2026-10-09T08:00:00.123456Z")
    assert ts(parse_ts("2026-10-09T10:00:00Z") + timedelta(seconds=1)) == "2026-10-09T10:00:01Z"


@pytest.mark.parametrize("value", ["2026-10-09 10:00:00Z", "2026-10-09T10:00:00", "2026-10-09T10:00:00+24:00", 5, None])
def test_parse_ts_rejects(value):
    with pytest.raises(ValueError):
        parse_ts(value)
