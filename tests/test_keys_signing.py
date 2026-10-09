# SPDX-License-Identifier: Apache-2.0
"""Keys, did:key, JWK thumbprints, and A5.1 signatures."""

import pytest

from selfkin_ref.errors import Refused
from selfkin_ref.keys import SigningKey, b58decode, b58encode, did_from_public, jwk_thumbprint, public_from_did, raw_public
from selfkin_ref.signing import sign_object, verify_object
from selfkin_ref.util import b64u_decode

RFC8032_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
RFC8032_PUB = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
RFC8032_SIG = ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
               "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")


def test_rfc8032_test1():
    key = SigningKey.from_seed(RFC8032_SEED)
    assert raw_public(key.public).hex() == RFC8032_PUB
    assert key.sign(b"").hex() == RFC8032_SIG


def test_rfc8037_thumbprint():
    # RFC 8037 appendix A.3
    key = public_from_did(did_from_public(SigningKey.from_seed(RFC8032_SEED).public))
    assert jwk_thumbprint(key) == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"


def test_did_key_roundtrip_and_prefix():
    key = SigningKey.generate()
    assert key.did.startswith("did:key:z6Mk")
    assert raw_public(public_from_did(key.kid)) == raw_public(key.public)
    assert key.kid.split("#")[0] == key.did


def test_base58_leading_zeros():
    assert b58encode(b"\0\0\x01") == "112"
    assert b58decode("112") == b"\0\0\x01"


@pytest.mark.parametrize("bad", ["did:web:example.org", "did:key:zQ3s", "did:key:z" + b58encode(b"\x12\x00" + bytes(32))])
def test_public_from_did_rejects_other_keys(bad):
    with pytest.raises(ValueError):
        public_from_did(bad)


@pytest.mark.parametrize("canon", ["dcbor", "jcs"])
def test_sign_verify(canon):
    key = SigningKey.generate()
    obj = sign_object({"v": "0.1", "n": 1, "nested": {"b": [1, 2]}}, key, canon=canon)
    assert obj["sig"]["canon"] == canon and obj["sig"]["alg"] == "EdDSA"
    assert len(b64u_decode(obj["sig"]["value"])) == 64
    verify_object(obj, expected_signer=key.did)


def test_resigning_replaces_sig():
    key = SigningKey.generate()
    once = sign_object({"a": 1}, key)
    twice = sign_object(once, key)
    verify_object(twice, expected_signer=key.did)


def mutate(obj, **changes):
    copy = dict(obj)
    copy.update(changes)
    return copy


def test_verify_failures():
    key, other = SigningKey.generate(), SigningKey.generate()
    obj = sign_object({"a": 1}, key)
    cases = [
        mutate(obj, a=2),  # changed content
        {k: v for k, v in obj.items() if k != "sig"},  # unsigned
        mutate(obj, sig=dict(obj["sig"], alg="ES256")),
        mutate(obj, sig=dict(obj["sig"], canon="jcs")),  # wrong canonical form
        mutate(obj, sig=dict(obj["sig"], value=obj["sig"]["value"] + "==")),
        mutate(obj, sig=dict(obj["sig"], kid=other.kid)),
    ]
    for case in cases:
        with pytest.raises(Refused) as info:
            verify_object(case, expected_signer=case["sig"]["kid"].split("#")[0] if "sig" in case else key.did)
        assert info.value.reason == "bad-signature"
    with pytest.raises(Refused):
        verify_object(obj, expected_signer=other.did)  # kid belongs to someone else


@pytest.mark.parametrize("text", ["AA.A", "AA A", "AA+/", "AAA=", "A", "AB"])
def test_b64u_decode_is_strict(text):
    # "AB" decodes to one byte but is not the canonical encoding of it ("AA" is).
    with pytest.raises(ValueError):
        b64u_decode(text)


def test_kid_fragment_must_name_the_did_key():
    key = SigningKey.from_seed(RFC8032_SEED)
    signed = sign_object({"v": "0.1", "x": 1}, key)
    sig = dict(signed["sig"], kid=key.did + "#zSomethingElse")
    with pytest.raises(Refused) as info:
        verify_object(dict(signed, sig=sig), expected_signer=key.did)
    assert info.value.reason == "bad-signature"


def test_unknown_canon_is_refused():
    key = SigningKey.from_seed(RFC8032_SEED)
    signed = sign_object({"v": "0.1", "x": 1}, key)
    with pytest.raises(Refused):
        verify_object(dict(signed, sig=dict(signed["sig"], canon="cbor")), expected_signer=key.did)
