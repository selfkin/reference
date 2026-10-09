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
- Resource matching: `a/*` no longer covers resources below it with empty,
  `.` or `..` segments or percent-encoding, such as `a/../b`
  (selfkin/standards#48).
