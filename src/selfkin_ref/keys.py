# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Selfkin reference contributors
"""Keys and identifiers.

Every owner, device, and agent has its own Ed25519 signing key (SK-COM A2,
SK-RT section 10). Identifiers are ``did:key`` DIDs, so a verifier can derive
the public key from the identifier without a registry. Key identifiers
(``kid``) are DID URLs of the form ``did:key:z...#z...``.

Real runtimes keep these keys in hardware (TPM, secure enclave, TEE). This
reference keeps them in memory.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .util import b64u

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ED25519_MULTICODEC = b"\xed\x01"


def b58encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, rem = divmod(number, 58)
        out = _B58[rem] + out
    pad = len(data) - len(data.lstrip(b"\0"))
    return "1" * pad + out


def b58decode(text: str) -> bytes:
    number = 0
    for char in text:
        number = number * 58 + _B58.index(char)
    pad = len(text) - len(text.lstrip("1"))
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * pad + body


def raw_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def did_from_public(key: Ed25519PublicKey) -> str:
    """``did:key`` identifier for an Ed25519 public key (multicodec 0xed01, base58btc)."""
    return "did:key:z" + b58encode(_ED25519_MULTICODEC + raw_public(key))


def public_from_did(identifier: str) -> Ed25519PublicKey:
    """Recover the Ed25519 public key from a ``did:key`` identifier or DID URL."""
    did = identifier.split("#", 1)[0]
    if not did.startswith("did:key:z"):
        raise ValueError("only did:key identifiers are supported by this reference")
    decoded = b58decode(did[len("did:key:z"):])
    if decoded[:2] != _ED25519_MULTICODEC or len(decoded) != 34:
        raise ValueError("did:key does not encode an Ed25519 public key")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def jwk_thumbprint(key: Ed25519PublicKey) -> str:
    """RFC 7638 JWK SHA-256 thumbprint of an Ed25519 key (RFC 8037 OKP JWK)."""
    members = {"crv": "Ed25519", "kty": "OKP", "x": b64u(raw_public(key))}
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True).encode("ascii")
    return b64u(hashlib.sha256(canonical).digest())


@dataclass
class SigningKey:
    """An Ed25519 key pair with its ``did:key`` identity."""

    private: Ed25519PrivateKey
    label: str = ""

    @classmethod
    def generate(cls, label: str = "") -> "SigningKey":
        return cls(Ed25519PrivateKey.generate(), label)

    @classmethod
    def from_seed(cls, seed: bytes, label: str = "") -> "SigningKey":
        """Deterministic key for test vectors only."""
        return cls(Ed25519PrivateKey.from_private_bytes(seed), label)

    @property
    def public(self) -> Ed25519PublicKey:
        return self.private.public_key()

    @property
    def did(self) -> str:
        return did_from_public(self.public)

    @property
    def kid(self) -> str:
        return self.did + "#" + self.did[len("did:key:"):]

    @property
    def thumbprint(self) -> str:
        return jwk_thumbprint(self.public)

    def sign(self, message: bytes) -> bytes:
        return self.private.sign(message)


def short(identifier: str) -> str:
    """Shorten a DID for logs, for example ``did:key:z6Mk...a1b2``."""
    did = identifier.split("#", 1)[0]
    if did.startswith("did:key:z") and len(did) > 24:
        return did[:13] + "..." + did[-4:]
    return identifier
