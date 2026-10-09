# SPDX-License-Identifier: Apache-2.0
"""Pairing, session keys, and encrypted frames (simplified, not Noise or MLS)."""

import pytest

from conftest import ACTION, make_world
from selfkin_ref import dcbor, schemas
from selfkin_ref.e2e import Channel, Ephemeral, FrameRejected, derive, transcript_hash
from selfkin_ref.errors import Refused
from selfkin_ref.identity import Owner
from selfkin_ref.runtime import Runtime
from selfkin_ref.signing import sign_object


def pair(a, b, now=None):
    request = a.pairing_request(b.core.did, forms=["F1"], tags=["CH"], actions=[ACTION], now=now)
    response, sas_b = b.accept_pairing(request, now=now)
    confirm, sas_a = a.complete_pairing(response, now=now)
    record = b.finish_pairing(confirm, now=now)
    return request, response, confirm, record, sas_a, sas_b


def runtimes(owner_b=None):
    alice = Owner.create("alice")
    owner_b = owner_b or alice
    return Runtime(alice, alice.add_device("phone", "CH")), Runtime(owner_b, owner_b.add_device("homebox", "CH"))


def test_pairing_messages_are_valid_envelopes_without_token_or_instructions():
    a, b = runtimes()
    request, response, confirm, record, sas_a, sas_b = pair(a, b)
    for env in (request, response, confirm):
        schemas.validate("envelope", env)
        assert env["intent"].startswith("sk.pairing.")
        assert "cap_token" not in env and "instructions" not in env
    assert sas_a == sas_b and len(sas_a) == 6 and sas_a.isdigit()
    assert record["forms"] == ["F1"] and record["capabilities"] == [ACTION]
    assert set(record["devices"]) == {a.device.did, b.device.did}


def test_session_keys_match_and_frames_roundtrip():
    a, b = runtimes()
    session = pair(a, b)[0]["session"]
    ca, cb = a.channels[session], b.channels[session]
    assert ca.send_key == cb.recv_key and ca.recv_key == cb.send_key and ca.send_key != ca.recv_key
    for i in range(3):
        assert cb.open(ca.seal(f"hello {i}".encode())) == f"hello {i}".encode()
    assert ca.open(cb.seal(b"back")) == b"back"


def test_frames_hide_plaintext():
    a, b = runtimes()
    session = pair(a, b)[0]["session"]
    frame = a.channels[session].seal(b"secret calendar entry")
    assert b"secret" not in frame


def test_replayed_reordered_and_reflected_frames_are_dropped():
    a, b = runtimes()
    session = pair(a, b)[0]["session"]
    ca, cb = a.channels[session], b.channels[session]
    f0, f1 = ca.seal(b"0"), ca.seal(b"1")
    cb.open(f1)
    for frame, reason in ((f1, "replayed-frame"), (f0, "replayed-frame"), (f1, "replayed-frame")):
        with pytest.raises(FrameRejected) as info:
            cb.open(frame)
        assert info.value.reason == reason
    with pytest.raises(FrameRejected) as info:
        ca.open(ca.seal(b"reflect"))  # own frame sent back
    assert info.value.reason == "wrong-session"


def test_header_and_ciphertext_are_authenticated():
    a, b = runtimes()
    session = pair(a, b)[0]["session"]
    ca, cb = a.channels[session], b.channels[session]
    frame = dcbor.decode(ca.seal(b"payload"))
    bumped = dict(frame, ctr=frame["ctr"] + 5)
    with pytest.raises(FrameRejected, match="decrypt-failed"):
        cb.open(dcbor.encode(bumped))
    flipped = dict(frame, ct=bytes([frame["ct"][0] ^ 1]) + frame["ct"][1:])
    with pytest.raises(FrameRejected, match="decrypt-failed"):
        cb.open(dcbor.encode(flipped))
    for garbage in (b"", b"\xa0", dcbor.encode(dict(frame, extra=1)), dcbor.encode(dict(frame, ct="text"))):
        with pytest.raises(FrameRejected, match="malformed-frame"):
            cb.open(garbage)


def test_different_sessions_get_different_keys():
    a, b = runtimes()
    s1, s2 = pair(a, b)[0]["session"], pair(a, b)[0]["session"]
    assert a.channels[s1].send_key != a.channels[s2].send_key


def test_derive_is_deterministic_and_transcript_bound():
    e1, e2 = Ephemeral(), Ephemeral()
    shared = e1.exchange(e2.public_b64)
    assert shared == e2.exchange(e1.public_b64)
    k1, k2 = derive(shared, b"t" * 32), derive(shared, b"u" * 32)
    assert k1 == derive(shared, b"t" * 32)
    assert k1.initiator_to_responder != k2.initiator_to_responder and k1.sas != k2.sas or k1 != k2


def test_low_order_point_rejected():
    with pytest.raises(ValueError):
        Ephemeral().exchange("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")


def test_pairing_requires_trusted_owner():
    a, b = runtimes(owner_b=Owner.create("bob"))
    request = a.pairing_request(b.core.did, forms=["F2"], tags=[], actions=[ACTION])
    with pytest.raises(Refused) as info:
        b.accept_pairing(request)
    assert info.value.reason == "unauthorized"
    b.trust.trust_owner(a.owner.did, "alice")  # owner consent on the receiving side
    response, _ = b.accept_pairing(request)
    with pytest.raises(Refused):
        a.complete_pairing(response)  # alice has not consented to bob yet
    a.trust.trust_owner(b.owner.did, "bob")


def test_tampered_pairing_message_rejected():
    a, b = runtimes()
    request = a.pairing_request(b.core.did, forms=["F1"], tags=["CH"], actions=[ACTION])
    request["data"]["eph"] = Ephemeral().public_b64  # man in the middle swaps the key
    with pytest.raises(Refused) as info:
        b.accept_pairing(request)
    assert info.value.reason == "bad-signature"


def test_confirm_with_wrong_transcript_or_record_rejected():
    for field in ("transcript", "record"):
        a, b = runtimes()
        request = a.pairing_request(b.core.did, forms=["F1"], tags=["CH"], actions=[ACTION])
        response, _ = b.accept_pairing(request)
        # tamper what the initiator believes it received, then sign an honest confirm over it
        if field == "transcript":
            a.pending[request["session"]].request = dict(request, nonce="A" * 22)
        else:
            a.pending[request["session"]].request = dict(request, data=dict(request["data"], forms=["F1", "F6"]))
        confirm, _ = a.complete_pairing(response)
        with pytest.raises(Refused, match="pairing"):
            b.finish_pairing(confirm)


def test_runtime_delivery_end_to_end():
    world = make_world()
    frame = world.a.seal(world.session, world.instruction())
    delivery = world.b.deliver(world.session, frame, now=world.now)
    assert delivery.status == "executed"
    assert world.b.deliver(world.session, frame, now=world.now).reason == "replayed-frame"
    assert world.b.deliver("no-such-session", frame).reason == "unknown-session"
    bad = world.instruction(resource="urn:selfkin:calendar:alice/home")
    refused = world.b.deliver(world.session, world.a.seal(world.session, bad), now=world.now)
    assert refused.status == "refused" and refused.reason == "unauthorized"
    back = world.a.deliver(world.session, refused.reply, now=world.now)
    assert back.status == "executed" and back.envelope["data"]["reason"] == "unauthorized"


def test_local_log_records_decisions_without_values():
    world = make_world()
    world.b.deliver(world.session, world.a.seal(world.session, world.instruction()), now=world.now)
    entry = world.b.log[-1]
    assert (entry.direction, entry.form, entry.intent, entry.decision) == ("received", "F6", "scheduling.propose", "executed")
    assert "sync" not in repr(world.b.log)


def test_transcript_hash_covers_both_messages():
    a, b = runtimes()
    request, response = pair(a, b)[:2]
    assert transcript_hash(request, response) != transcript_hash(response, request)


def test_pairing_request_cannot_reuse_a_live_session(world):
    receiver = world.b.receivers[world.b.core.did]
    channel = world.b.channels[world.session]
    tags = list(receiver.session_tags[world.session])
    devices = set(receiver.session_devices[world.session])
    request = world.a.pairing_request(world.b.core.did, forms=["F1"], tags=[], actions=[ACTION], now=world.now)
    body = {k: v for k, v in request.items() if k != "sig"}
    body.update(session=world.session, seq=50)
    with pytest.raises(Refused) as info:
        world.b.accept_pairing(sign_object(body, world.a.core.key), now=world.now)
    assert info.value.reason == "unauthorized"
    assert world.b.channels[world.session] is channel
    assert receiver.session_tags[world.session] == tags and receiver.session_devices[world.session] == devices
    frame = world.a.seal(world.session, world.instruction())
    assert world.b.deliver(world.session, frame, now=world.now).status == "executed"


def test_refused_pairing_request_leaves_no_open_session(world):
    request = world.a.pairing_request(world.b.core.did, forms=["F1"], tags=[], actions=[ACTION], now=world.now)
    body = {k: v for k, v in request.items() if k != "sig"}
    body["aud"] = world.b.receivers[world.calendar.did].agent.did  # wrong audience for the core agent
    with pytest.raises(Refused):
        world.b.accept_pairing(sign_object(body, world.a.core.key), now=world.now)
    assert request["session"] not in world.b.receivers[world.b.core.did].session_tags
