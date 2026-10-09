# Contributing

Thank you for helping. This repository is the Python reference implementation
of the Selfkin draft standards. The standards themselves live in
[selfkin/standards](https://github.com/selfkin/standards), and the policies of
that repository apply here too:

- [CONTRIBUTING.md](https://github.com/selfkin/standards/blob/main/CONTRIBUTING.md)
  (process, DCO sign-off, style rules)
- [PATENT-POLICY.md](https://github.com/selfkin/standards/blob/main/PATENT-POLICY.md)
- [CODE_OF_CONDUCT.md](https://github.com/selfkin/standards/blob/main/CODE_OF_CONDUCT.md)
- [GOVERNANCE.md](https://github.com/selfkin/standards/blob/main/GOVERNANCE.md)

## Where to send what

- **A bug in this code**, or a place where it does not match the drafts: open
  an issue or pull request here.
- **A question about what the drafts mean**: open an issue in
  [selfkin/standards](https://github.com/selfkin/standards/issues) with the
  label `open-question`. This code then follows whatever is decided there.
- **A security problem in the drafts**: follow
  [SECURITY.md](SECURITY.md); never open a public issue.

## Developer Certificate of Origin (DCO)

Every commit must be signed off (`git commit -s`), which adds:

```
Signed-off-by: Your Name <your.email@example.com>
```

By signing off you certify the [Developer Certificate of Origin 1.1](https://developercertificate.org/)
and agree that your contribution is licensed under the Apache License 2.0
([LICENSE](LICENSE)). The DCO sign-off also confirms the patent commitment in
the standards repository's Patent Policy.

## Ground rules

- Match the drafts and the vendored schemas exactly. Field names are never
  renamed or abbreviated. Where the drafts leave something open, write down
  the choice in the README ("Interpretation choices") and open an
  `open-question` issue upstream.
- Keep it small and readable. This is a teaching implementation, not a
  product: prefer clear code over clever code and standard primitives from
  `cryptography` over anything hand-written.
- Every behaviour change needs a test. Run `pytest` and
  `python -m selfkin_ref.demo` before opening a pull request.
- Do not edit `src/selfkin_ref/schema_files/*.schema.json` by hand. Change the
  schemas upstream, then run `python scripts/vendor_schemas.py PATH_TO_STANDARDS`.
- Plain English, no em dashes or en dashes (same style rule as the standards).

## Development setup

```
python -m venv .venv && . .venv/bin/activate
pip install -e ".[test]"
pytest
python -m selfkin_ref.demo
```

To also run the interop tests against the upstream validator:

```
git clone https://github.com/selfkin/standards standards
pip install -r standards/tools/validate/requirements.txt
SELFKIN_STANDARDS=standards pytest tests/test_upstream_validator.py
```
