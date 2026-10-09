# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Selfkin reference contributors
"""Signing and verifying Selfkin objects (SK-COM A5.1).

The signature covers the canonical encoding of the object with its ``sig``
member removed. The ``sig`` block holds ``alg``, ``kid``, ``canon``,
``value``, and optionally ``signer``. This reference signs with EdDSA
(Ed25519) and ``dcbor``, and verifies both ``dcbor`` and ``jcs``.
"""

from __future__ import annotations

import copy

from cryptography.exceptions import InvalidSignature

from . import dcbor
from .errors import Refused
from .keys import SigningKey, public_from_did
from .util import b64u, b64u_decode

ALG = "EdDSA"


def sign_object(obj: dict, key: SigningKey, *, canon: str = "dcbor", signer: str | None = None) -> dict:
    """Return a copy of ``obj`` with a fresh ``sig`` block."""
    signed = copy.deepcopy(obj)
    signed.pop("sig", None)
    value = key.sign(dcbor.signing_input(signed, canon))
    block = {"alg": ALG, "kid": key.kid, "canon": canon, "value": b64u(value)}
    if signer is not None:
        block["signer"] = signer
    signed["sig"] = block
    return signed


def verify_object(obj: dict, *, expected_signer: str) -> None:
    """Verify ``obj['sig']`` and that the key belongs to ``expected_signer``.

    ``expected_signer`` is the identity that must have signed (for example the
    envelope's ``sender_agent`` or a token's ``iss``). With ``did:key`` the
    ``kid`` must be a DID URL of that same DID.

    Raises ``Refused('bad-signature')`` on any failure.
    """
    sig = obj.get("sig") if isinstance(obj, dict) else None
    if not isinstance(sig, dict):
        raise Refused("bad-signature", "missing sig block")
    if sig.get("alg") != ALG:
        raise Refused("bad-signature", f"unsupported alg {sig.get('alg')!r}")
    kid = sig.get("kid", "")
    if not isinstance(kid, str) or kid.split("#", 1)[0] != expected_signer:
        raise Refused("bad-signature", "kid does not belong to the expected signer")
    try:
        public = public_from_did(kid)
        message = dcbor.signing_input(obj, sig.get("canon", ""))
        public.verify(b64u_decode(sig.get("value", "")), message)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise Refused("bad-signature", f"signature check failed ({type(exc).__name__})") from None
