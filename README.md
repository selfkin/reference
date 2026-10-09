# Selfkin reference implementation (Python)

> **Status: Draft. Not for production.** This code makes the Selfkin draft
> standards concrete and testable. It has not been reviewed or audited, keeps
> keys in memory, and its end-to-end session (`e2e.py`) is a simplified
> illustration, **not Noise and not MLS**. Do not use it to protect real data.

[![CI](https://github.com/selfkin/reference/actions/workflows/ci.yml/badge.svg)](https://github.com/selfkin/reference/actions/workflows/ci.yml)

A minimal, well-tested Python implementation of the core of the
[Selfkin open standards](https://github.com/selfkin/standards) (open standards
for personal AI on your own devices). It covers:

- **Keys and identity**: Ed25519 device, agent, and owner keys as `did:key`
  identifiers, owner-signed statements that bind agents to devices and
  devices to owners (SK-COM A2).
- **Envelope**: build, canonicalise (`dcbor`, RFC 8949 section 4.2; `jcs`,
  RFC 8785), sign with the `sig` member removed (SK-COM A5.1), and verify with
  every receiver check: version, schema, `aud`, identity, signature,
  `issued`/`expires`, nonce, `seq` window, residency intersection, capability,
  local policy, and `idem_key` (SK-COM A5, A9).
- **Capability tokens**: issue, delegate with narrowing, and verify the chain
  (rules (a) to (f), at most 16 links, at most 1 hour lifetime, `cnf` holder
  binding), bound to the envelope (`sub`, `aud`, rights cover the
  instruction), with `max_uses` and message budgets (SK-COM A6, A7).
- **Refusals**: signed `sk.refused` envelopes with a reason code and
  references only, never free text (SK-COM A7).
- **Privacy reports**: one per cloud call from a small Privacy Gateway (context
  selection, redaction, pseudonymisation, relay awareness, payload digest),
  listing field names and data classes but never values, validated against
  the schema (SK-RT section 13).
- **E2E (simplified)**: pairing with owner consent, X25519 + HKDF session keys,
  a 6-digit short authentication string, and ChaCha20-Poly1305 frames with
  counters (SK-COM A3, A4).

Every object it produces validates against the
[vendored v0.1 schemas](src/selfkin_ref/schema_files/SOURCE.md), and CI also
checks the demo's documents with the
[upstream validator](https://github.com/selfkin/standards/tree/main/tools/validate).

## Quick start

```
python -m venv .venv && . .venv/bin/activate
pip install -e ".[test]"
python -m selfkin_ref.demo        # add --no-report to hide the full privacy report
pytest
```

Python 3.10 or later. Dependencies: `cryptography`, `cbor2`, `jsonschema`,
`referencing`.

## The demo

`python -m selfkin_ref.demo` runs in one process with no network access. Two
of Alice's devices pair; `assistant@phone` sends a signed, encrypted
instruction with a capability delegated by `planner@phone` to
`calendar@homebox`, which verifies it and runs a toy action that makes one
cloud call through the Privacy Gateway. Then it shows what gets rejected.
Excerpt (identifiers and keys change on every run):

```
[2] Pairing: owner consent on both devices, X25519 + HKDF, 6-digit SAS
    phone     -> sk.pairing.request  session=pair-069ae16e0ba7ea11
    homebox   -> sk.pairing.response (signed, with ephemeral X25519 key)
    phone     SAS 152322
    homebox   SAS 152322
    PASS      both screens show the same SAS; alice confirms on both devices

[4] assistant@phone -> calendar@homebox: signed, encrypted instruction
    phone     -> envelope seq=0 intent=scheduling.propose action=calendar.propose_meeting
    phone        frame of 2560 bytes (ChaCha20-Poly1305), envelope signed with dcbor
    homebox   checks: version, schema, aud, owner statements, signature, freshness, nonce, seq,
                      residency CH-EU vs region CH, chain root -> delegated, binding, rights, budget
    gateway   WARNING no relay available: withheld owner.health_note (health.records)
    gateway   WARNING no relay available: withheld owner.location (location.precise)
    gateway   WARNING no relay available: provider sees the device network identity
    PASS      executed calendar.propose_meeting -> {'status': 'proposed', 'slots': ['Tue 10:00', 'Thu 14:00']}

[5] Replay: the same frame is injected again
    PASS      dropped at the transport layer (replayed-frame); counter already used

[6] Replay: the same signed envelope in a fresh frame
    PASS      refused with reason 'replayed'; nonce already seen

[7] Tamper: one bit of ciphertext flipped in transit
    PASS      dropped (decrypt-failed); AEAD tag does not verify

[8] Tamper: resource changed after signing (alice/work -> alice/private)
    PASS      refused with reason 'bad-signature'

[9] Over-broad delegation: assistant -> helper widens alice/work to alice/*
    phone     delegate() refuses locally: (d)/(e) right calendar.propose_meeting on urn:selfkin:calendar:alice/* is not covered by the parent
    PASS      refused with reason 'unauthorized'

11/11 checks passed
```

`--export DIR` writes the produced envelopes, tokens, refusal, and privacy
report as JSON files.

## Layout

| Module | What it does | Spec |
|---|---|---|
| [`dcbor.py`](src/selfkin_ref/dcbor.py) | Deterministic CBOR and JCS, strict decoding, signing input | SK-COM A5.1 |
| [`keys.py`](src/selfkin_ref/keys.py) | Ed25519 keys, `did:key`, RFC 7638 JWK thumbprints | SK-COM A2, A6 `cnf` |
| [`signing.py`](src/selfkin_ref/signing.py) | `sig` blocks: sign and verify any Selfkin object | SK-COM A5.1 |
| [`identity.py`](src/selfkin_ref/identity.py) | Owners, devices, agents, owner statements, trust store, revocation | SK-COM A2 |
| [`residency.py`](src/selfkin_ref/residency.py) | Residency tags, intersection, fail closed | SK-RT 11, SK-COM A5, A8 |
| [`capability.py`](src/selfkin_ref/capability.py) | Issue, delegate, narrowing rules, chain verification | SK-COM A6 |
| [`envelope.py`](src/selfkin_ref/envelope.py) | Build, sign, receiver checks, refusals, budgets, idempotency | SK-COM A5, A6, A7, A9 |
| [`e2e.py`](src/selfkin_ref/e2e.py) | Simplified pairing, session keys, AEAD frames (not Noise or MLS) | SK-COM A3, A4 |
| [`runtime.py`](src/selfkin_ref/runtime.py) | A toy runtime tying it together, with the local log | SK-COM A10 |
| [`privacy.py`](src/selfkin_ref/privacy.py) | Privacy Gateway and privacy reports | SK-RT 13, SK-PRV 12 |
| [`schemas.py`](src/selfkin_ref/schemas.py) | Validation against the vendored schemas | schemas/ |
| [`demo.py`](src/selfkin_ref/demo.py) | The walkthrough above | |

## Interpretation choices

Where the v0.1 drafts leave a detail open, this code makes one explicit
choice so that it can run. These choices are **not** part of the standard.
Each one is tracked as an `open-question` issue in selfkin/standards (see
below); the code will follow whatever is decided there.

1. **Chain link signatures.** ([#17](https://github.com/selfkin/standards/issues/17)) A token is signed with `chain` set to the links
   before it (`[]` for a root). Links are carried without their own `chain`,
   so a verifier rebuilds `chain = chain[:i]` for link `i` before checking its
   signature.
2. **Owner statements.** ([#18](https://github.com/selfkin/standards/issues/18)) `{v, id, kind: device|agent, iss, sub, device?, iat,
   exp, sig}`, signed like every other object. The drafts require such
   statements but define no format.
3. **Root issuer.** ([#19](https://github.com/selfkin/standards/issues/19)) A root token must be issued by the audience itself or by
   the audience's owner.
4. **Proof of possession.** ([#20](https://github.com/selfkin/standards/issues/20)) `cnf.jkt` is the RFC 7638 thumbprint of the
   holder's Ed25519 key (`cnf.kid` naming the holder DID is also accepted).
   The envelope signature by `sender_agent` is the proof of possession.
5. **Sequence and replay window.** ([#21](https://github.com/selfkin/standards/issues/21)) `seq` is tracked per session and sender
   agent; anything within 64 of the highest seen `seq` and not seen before is
   accepted. Nonces are remembered until the envelope expires plus 30 seconds
   of clock skew. Envelopes may live at most 10 minutes.
6. **Idempotency.** ([#22](https://github.com/selfkin/standards/issues/22)) `idem_key` is scoped to the sender agent. A repeat with a
   fresh nonce is not executed again; the stored result is returned (status
   `duplicate`) and no budget is consumed.
7. **Resource matching.** ([#23](https://github.com/selfkin/standards/issues/23)) `urn:x:a/*` covers `urn:x:a/b` and `urn:x:a/b/c`,
   but not `urn:x:a/` or `urn:x:a`. Wildcard coverage fails closed when the
   part below the prefix has an empty, `.` or `..` segment or any
   percent-encoding, so `urn:x:a/*` never covers `urn:x:a/../b`
   ([#48](https://github.com/selfkin/standards/issues/48)). An instruction
   without `resource` is never covered.
8. **Budgets.** ([#24](https://github.com/selfkin/standards/issues/24)) Every accepted instruction counts against `budget.messages`
   of every link in the chain and against `max_uses` of the right that
   covered it.
9. **Cross-owner rule.** ([#25](https://github.com/selfkin/standards/issues/25)) Below C2, every delegated link (not the root) must
   have `iss` and `sub` under the same owner, determined from owner
   statements. A root token from the audience's owner to another owner's
   agent is treated as F2, not F6.
10. **Residency on receive.** ([#26](https://github.com/selfkin/standards/issues/26)) The receiving device's region must be allowed by
    the intersection of the envelope's tags and the tags in the pairing
    record. Regions are modelled as `CH` and `EU` (EU and EEA).
11. **Pairing payload and record.** ([#27](https://github.com/selfkin/standards/issues/27)) Pairing data uses the media type
    `application/vnd.selfkin.ref.pairing+json` (reference-only), and the
    pairing record is `{v, session, devices, forms, residency, capabilities,
    expires}`.
12. **Privacy reports.** ([#28](https://github.com/selfkin/standards/issues/28)) A pseudonymised field is listed in `sent.fields` and
    `redacted.pseudonymised`, and its data class only in
    `redacted.data_classes`. Full gateway mode is always used for P0
    providers (identified mode is not implemented). There is no network
    code: the gateway returns the payload a runtime would send.
13. **Timestamps in CBOR.** ([#10](https://github.com/selfkin/standards/issues/10)) Timestamps stay RFC 3339 text strings inside the
    dcbor signing input, exactly as in the JSON data model.
14. **Token time bounds.** ([#47](https://github.com/selfkin/standards/issues/47)) A token or chain link whose `iat` lies more than
    30 seconds in the future, or whose `exp` is not later than its `iat`, is
    refused. Otherwise a future `iat` would keep a token usable for longer
    than 1 hour.

## Spec ambiguities

Filed in [selfkin/standards](https://github.com/selfkin/standards/issues?q=is%3Aissue+label%3Aopen-question)
with the label `open-question`:

- [#17](https://github.com/selfkin/standards/issues/17) What each capability token chain link is signed over (SK-COM §A6, §A5.1)
- [#18](https://github.com/selfkin/standards/issues/18) Format of owner-signed statements for devices and agents (SK-COM §A2)
- [#19](https://github.com/selfkin/standards/issues/19) Who may issue a root capability token (SK-COM §A6)
- [#20](https://github.com/selfkin/standards/issues/20) How cnf proof of possession binds a token to an envelope (SK-COM §A6)
- [#21](https://github.com/selfkin/standards/issues/21) Seq window, nonce retention, clock skew, and envelope lifetime (SK-COM §A5, §A9)
- [#22](https://github.com/selfkin/standards/issues/22) Idem_key scope and what a receiver returns for a repeat (SK-COM §A9)
- [#23](https://github.com/selfkin/standards/issues/23) Resource wildcard matching and instructions without resource (SK-COM §A6)
- [#24](https://github.com/selfkin/standards/issues/24) How budgets and max_uses are counted along a delegation chain (SK-COM §A6, §A7)
- [#25](https://github.com/selfkin/standards/issues/25) Does the below-C2 cross-owner rule apply to the root token (SK-COM §A6)
- [#26](https://github.com/selfkin/standards/issues/26) Residency checks when receiving, and pairing record residency (SK-COM §A5, §A8)
- [#27](https://github.com/selfkin/standards/issues/27) Pairing message payload and pairing record format (SK-COM §A3)
- [#28](https://github.com/selfkin/standards/issues/28) How pseudonymised fields appear in a privacy report (SK-RT §13)
- [#10](https://github.com/selfkin/standards/issues/10) Normative CBOR profile and type mappings (comment: timestamps and base64url inside the dcbor signing input)

## Not implemented

Discovery (F5), negotiation and downgrade protection (B7), streams (F7),
store-and-forward and relays (F8, F9), MLS groups, revocation distribution,
key rotation, attestation (C3), hardware-backed keys, Provider Manifests,
module manifests, and real network transport.

## License

Apache License 2.0, see [LICENSE](LICENSE). The vendored schemas come from
[selfkin/standards](https://github.com/selfkin/standards) under the same
license. Contributions need a DCO sign-off, see [CONTRIBUTING.md](CONTRIBUTING.md).
Security: see [SECURITY.md](SECURITY.md).

"Selfkin" is used here to refer to the open standards project; see the
[trademark note](https://github.com/selfkin/standards/blob/main/TRADEMARKS.md).
