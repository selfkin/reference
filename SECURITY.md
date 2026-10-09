# Security Policy

**This is draft reference code. It is not for production and must not be used
to protect real data.** The end-to-end session in `e2e.py` is a simplified
illustration, not Noise or MLS, and none of this code has been reviewed or
audited.

## What to report where

- **A flaw in the specifications** (a rule that permits replay, downgrade,
  impersonation, a consent bypass, or a privacy leak): report it privately
  through the standards repository, as described in
  [selfkin/standards SECURITY.md](https://github.com/selfkin/standards/blob/main/SECURITY.md)
  ([report a vulnerability](https://github.com/selfkin/standards/security/advisories/new)).
  Finding such a flaw by running this code is very welcome.
- **A bug in this code** that makes it accept something the drafts say must
  be rejected (for example a widened delegation, a replayed envelope, or a
  report that leaks a value): use
  [private vulnerability reporting on this repository](https://github.com/selfkin/reference/security/advisories/new).
  Because this code is not meant to protect anything, a public issue is also
  acceptable when the bug does not point to a flaw in the drafts.

Do not report by email. The response times and coordinated disclosure terms
of the standards repository apply.
