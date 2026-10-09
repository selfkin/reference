# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Selfkin reference contributors
"""Pairing, session keys, and encrypted frames.

SIMPLIFIED ILLUSTRATION. This is NOT the Noise Protocol Framework and NOT
MLS, which SK-COM A4 recommends. It shows the shape of the requirements
(mutual authentication, out-of-band verification, forward secrecy through
ephemeral keys, authenticated encryption, replay protection) with a few
lines of standard primitives so the rest of the reference has something to
run on. It has not been analysed and must not be used to protect real data.
Use a reviewed Noise or MLS implementation in a real runtime.

How it works:

1. Both sides send a signed pairing envelope (``sk.pairing.request`` and
   ``sk.pairing.response``). The ``data`` carries owner statements for the
   device and its agents, a fresh X25519 public key, and the forms and
   residency tags the pairing should allow.
2. ``transcript = SHA-256(dcbor(request) || dcbor(response))`` binds both
   signed messages, so both ephemeral keys are authenticated by the agent
   signatures.
3. ``HKDF-SHA256(X25519 shared secret, salt=transcript)`` yields one key per
   direction and a 6-digit short authentication string (SAS) that the owner
   compares on both screens (SK-COM A3 out-of-band verification).
4. ``sk.pairing.confirm`` carries the transcript hash and the pairing record
   (allowed forms, residency, expiry).
5. Every later envelope travels inside a frame: ChaCha20-Poly1305 under the
   direction key, nonce = 4 zero bytes + 64-bit counter, AAD = the dcbor frame
   header. Counters only go up, so a replayed or reordered frame is dropped.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import dcbor
from .util import b64u, b64u_decode

PAIRING_TYPE = "application/vnd.selfkin.ref.pairing+json"
KDF_INFO = b"selfkin-ref v0.1 pairing"
MAX_COUNTER = 2**64 - 1


class FrameRejected(Exception):
    """A frame was dropped at the transport layer (no refusal is sent)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class Ephemeral:
    def __init__(self) -> None:
        self._private = X25519PrivateKey.generate()

    @property
    def public_b64(self) -> str:
        raw = self._private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return b64u(raw)

    def exchange(self, peer_b64: str) -> bytes:
        shared = self._private.exchange(X25519PublicKey.from_public_bytes(b64u_decode(peer_b64)))
        if shared == bytes(32):
            raise ValueError("low-order X25519 point")
        return shared


def transcript_hash(request: dict, response: dict) -> bytes:
    return hashlib.sha256(dcbor.encode(request) + dcbor.encode(response)).digest()


@dataclass
class SessionKeys:
    initiator_to_responder: bytes
    responder_to_initiator: bytes
    sas: str


def derive(shared: bytes, transcript: bytes) -> SessionKeys:
    okm = HKDF(algorithm=hashes.SHA256(), length=68, salt=transcript, info=KDF_INFO).derive(shared)
    sas = f"{int.from_bytes(okm[64:68], 'big') % 1_000_000:06d}"
    return SessionKeys(okm[:32], okm[32:64], sas)


@dataclass
class Channel:
    """One direction pair of an encrypted session."""

    session: str
    send_key: bytes
    recv_key: bytes
    send_dir: str
    recv_dir: str
    send_ctr: int = 0
    recv_highest: int = -1
    record: dict = field(default_factory=dict)

    @staticmethod
    def _nonce(counter: int) -> bytes:
        return b"\0\0\0\0" + counter.to_bytes(8, "big")

    def seal(self, plaintext: bytes) -> bytes:
        if self.send_ctr >= MAX_COUNTER:
            raise RuntimeError("counter exhausted, pair again")
        header = {"session": self.session, "dir": self.send_dir, "ctr": self.send_ctr}
        ct = ChaCha20Poly1305(self.send_key).encrypt(self._nonce(self.send_ctr), plaintext, dcbor.encode(header))
        self.send_ctr += 1
        return dcbor.encode(dict(header, ct=ct))

    def open(self, frame: bytes) -> bytes:
        try:
            parsed = dcbor.decode(frame)
            header = {"session": parsed["session"], "dir": parsed["dir"], "ctr": parsed["ctr"]}
            ct = parsed["ct"]
        except Exception:
            raise FrameRejected("malformed-frame") from None
        if set(parsed) != {"session", "dir", "ctr", "ct"} or not isinstance(ct, bytes):
            raise FrameRejected("malformed-frame")
        if header["session"] != self.session or header["dir"] != self.recv_dir:
            raise FrameRejected("wrong-session")
        if not isinstance(header["ctr"], int) or not 0 <= header["ctr"] <= MAX_COUNTER:
            raise FrameRejected("malformed-frame")
        if header["ctr"] <= self.recv_highest:
            raise FrameRejected("replayed-frame")
        try:
            plaintext = ChaCha20Poly1305(self.recv_key).decrypt(self._nonce(header["ctr"]), ct, dcbor.encode(header))
        except InvalidTag:
            raise FrameRejected("decrypt-failed") from None
        self.recv_highest = header["ctr"]
        return plaintext
