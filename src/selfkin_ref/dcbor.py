# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Selfkin reference contributors
"""Canonical encodings for signing (SK-COM A5.1).

``dcbor``: deterministic CBOR per RFC 8949 section 4.2.1 (core deterministic
encoding requirements): preferred (shortest) serialization of integers and
lengths, definite-length items only, and map keys sorted by the bytewise
lexicographic order of their deterministic encodings.

``jcs``: JSON Canonicalization Scheme (RFC 8785) for the subset of JSON this
implementation produces (no floating point numbers).

Interpretation choices (see README, "Spec ambiguities"):

* The signed object is the JSON data model. Timestamps stay text strings in
  CBOR; they are not converted to CBOR tag 1.
* Floating point numbers are rejected, because none of the v0.1 schemas need
  them and their deterministic encoding is a common interoperability trap.
"""

from __future__ import annotations

import json
from typing import Any

import cbor2

SIG_MEMBER = "sig"


def _normalise(value: Any) -> Any:
    """Return a copy with maps re-ordered for RFC 8949 section 4.2.1."""
    if isinstance(value, bool) or value is None or isinstance(value, (str, bytes)):
        return value
    if isinstance(value, int):
        if not -(2**64) <= value < 2**64:
            raise ValueError("integer outside the CBOR major type 0/1 range")
        return value
    if isinstance(value, float):
        raise ValueError("floating point numbers are not allowed in signed objects")
    if isinstance(value, (list, tuple)):
        return [_normalise(item) for item in value]
    if isinstance(value, dict):
        items = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("map keys must be text strings")
            items.append((cbor2.dumps(key), key, _normalise(item)))
        items.sort(key=lambda entry: entry[0])
        for index in range(1, len(items)):
            if items[index][0] == items[index - 1][0]:
                raise ValueError(f"duplicate map key {items[index][1]!r}")
        return {key: item for _, key, item in items}
    raise TypeError(f"unsupported type in signed object: {type(value).__name__}")


def encode(value: Any) -> bytes:
    """Deterministic CBOR encoding (RFC 8949 section 4.2.1)."""
    # cbor2 keeps dict insertion order when canonical=False and always uses
    # the shortest integer and length encodings with definite lengths.
    return cbor2.dumps(_normalise(value))


def decode(data: bytes) -> Any:
    """Decode CBOR and require that it was deterministically encoded.

    Rejects indefinite lengths, duplicate keys, trailing bytes, and any
    encoding that differs from the deterministic re-encoding.
    """
    value = cbor2.loads(data, allow_indefinite=False, allow_duplicate_keys=False)
    if encode(value) != data:
        raise ValueError("CBOR input is not deterministically encoded")
    return value


def _jcs_key(text: str) -> bytes:
    # RFC 8785 section 3.2.3: sort by UTF-16 code units.
    return text.encode("utf-16-be")


def _jcs(value: Any) -> str:
    if isinstance(value, bool) or value is None:
        return json.dumps(value)
    if isinstance(value, int):
        if abs(value) > 2**53 - 1:
            raise ValueError("integer outside the I-JSON safe range for jcs")
        return str(value)
    if isinstance(value, float):
        raise ValueError("floating point numbers are not allowed in signed objects")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=_jcs_key)
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _jcs(value[k]) for k in keys) + "}"
    raise TypeError(f"unsupported type for jcs: {type(value).__name__}")


def jcs(value: Any) -> bytes:
    """JSON Canonicalization Scheme (RFC 8785), float-free subset."""
    return _jcs(value).encode("utf-8")


def signing_input(obj: dict, canon: str) -> bytes:
    """Bytes a signature covers: the canonical encoding of ``obj`` without ``sig``."""
    if not isinstance(obj, dict):
        raise TypeError("signed objects are maps")
    unsigned = {k: v for k, v in obj.items() if k != SIG_MEMBER}
    if canon == "dcbor":
        return encode(unsigned)
    if canon == "jcs":
        return jcs(unsigned)
    raise ValueError(f"unknown canonical encoding {canon!r}")
