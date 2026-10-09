# Changelog

All notable changes to this project are recorded here.

## 0.1.0.dev0 (unreleased)

- First draft reference implementation of the Selfkin v0.1 core: did:key
  identities and owner statements, dcbor and jcs canonical encoding, A5.1
  signatures, the Selfkin Envelope with receiver checks and refusals,
  capability tokens with delegation, narrowing, and chain verification, a
  Privacy Gateway with schema-valid privacy reports, a simplified pairing and
  encrypted session (not Noise or MLS), and the `python -m selfkin_ref.demo`
  walkthrough.
- Schemas vendored from selfkin/standards (see
  `src/selfkin_ref/schema_files/SOURCE.md`).
- Repository: CODEOWNERS, a bug or spec mismatch issue template, links for
  private security reports and spec questions, and a pull request template
  with the DCO checkbox. `main` is protected: changes land through squash
  merged pull requests with passing CI.
- Identity: owner statements are checked for validity on every envelope,
  not only when they are added, and a revoked owner stops its devices and
  agents.
- CI hardening: actions pinned to commit SHAs, checkout without persisted
  credentials, job timeouts, DCO step without inline expressions, a
  pip-audit and bandit job, and Dependabot for actions and pip.
- Require `cbor2>=6.1`: `dcbor.decode` uses `allow_indefinite` and
  `allow_duplicate_keys`, which older cbor2 releases do not have. CI now
  also runs the tests with the lowest supported versions.
- Strict input decoding: base64url must be unpadded, from the URL-safe
  alphabet, and canonical; a `kid` fragment must name the did:key key;
  `canon` must be `dcbor` or `jcs`; owner-defined residency tags must start
  with `x-` and can no longer redefine `CH`, `EU`, or `CH-EU`.
- Resource matching: `a/*` no longer covers resources below it with empty,
  `.` or `..` segments or percent-encoding, such as `a/../b`
  (selfkin/standards#48).
- Receiver hardening: signed input with impossible timestamps or missing
  statement members is refused as `malformed` instead of raising a raw
  `ValueError` or `KeyError`; `parse_ts` accepts every timestamp form the
  schemas allow on all supported Python versions; `dcbor.decode` raises only
  `ValueError`.
- Pairing: refuse a pairing request whose session identifier is already in
  use, and leave no session open when a request is refused
  (selfkin/standards#49).
- Capability tokens: refuse links with `iat` in the future (beyond 30 s of
  skew) or `exp` not later than `iat`, so no token outlives the 1 hour
  bound (selfkin/standards#47).
- Schemas re-vendored from selfkin/standards after the owner residency tag
  fix (selfkin/standards#60): an owner tag such as `x-family` now has at most
  64 characters, as the drafts say. A test checks 64 accepted and 65 refused.
