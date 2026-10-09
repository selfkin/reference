# SPDX-License-Identifier: Apache-2.0
"""Deterministic CBOR (RFC 8949 section 4.2) and JCS (RFC 8785)."""

import cbor2
import pytest

from selfkin_ref import dcbor


def test_rfc8949_appendix_vector():
    assert dcbor.encode({"a": 1, "b": [2, 3]}).hex() == "a26161016162820203"


def test_map_keys_sorted_by_encoded_bytes():
    # Shorter text keys sort first because the length is in the initial byte.
    encoded = dcbor.encode({"bb": 1, "a": 2, "c": 3})
    assert encoded == bytes.fromhex("a3") + cbor2.dumps("a") + b"\x02" + cbor2.dumps("c") + b"\x03" + cbor2.dumps("bb") + b"\x01"


def test_insertion_order_does_not_matter():
    assert dcbor.encode({"x": {"b": 1, "a": 2}, "y": None}) == dcbor.encode({"y": None, "x": {"a": 2, "b": 1}})


def test_minimal_integer_encoding():
    assert dcbor.encode(23) == b"\x17"
    assert dcbor.encode(24) == b"\x18\x18"
    assert dcbor.encode(2**64 - 1) == b"\x1b" + b"\xff" * 8


@pytest.mark.parametrize("bad", [1.5, {"a": 0.1}, {1: "x"}])
def test_rejects_floats_and_non_text_keys(bad):
    with pytest.raises((TypeError, ValueError)):
        dcbor.encode(bad)


def test_decode_roundtrip_and_strictness():
    value = {"session": "s-1", "ctr": 3, "ct": b"\x00\x01", "list": [True, False, None]}
    assert dcbor.decode(dcbor.encode(value)) == value
    with pytest.raises(ValueError):
        dcbor.decode(b"\x18\x01")  # non-minimal integer
    with pytest.raises(Exception):
        dcbor.decode(bytes.fromhex("a2616101616102"))  # duplicate key
    with pytest.raises(ValueError):
        dcbor.decode(bytes.fromhex("a2616201616101"))  # keys out of order
    with pytest.raises(Exception):
        dcbor.decode(bytes.fromhex("9f01ff"))  # indefinite length


def test_jcs_rfc8785_style_ordering():
    assert dcbor.jcs({"b": 1, "a": [True, None, "\u00e9"], "A": 2}) == '{"A":2,"a":[true,null,"\u00e9"],"b":1}'.encode()


def test_jcs_rejects_unsafe_numbers():
    with pytest.raises(ValueError):
        dcbor.jcs({"n": 2**53})
    with pytest.raises((TypeError, ValueError)):
        dcbor.jcs({"n": 1.0})


def test_signing_input_removes_only_top_level_sig():
    obj = {"a": 1, "sig": {"value": "x"}, "inner": {"sig": 2}}
    assert dcbor.signing_input(obj, "dcbor") == dcbor.encode({"a": 1, "inner": {"sig": 2}})
    assert dcbor.signing_input(obj, "jcs") == b'{"a":1,"inner":{"sig":2}}'
    with pytest.raises(ValueError):
        dcbor.signing_input(obj, "cbor")
