# Source of the vendored schemas

These JSON Schemas are copied byte for byte from the Selfkin standards
repository. Do not edit them here; change them upstream and re-vendor with
`python scripts/vendor_schemas.py PATH_TO_STANDARDS_CHECKOUT`.

- Repository: https://github.com/selfkin/standards
- Commit: [`753ac37`](https://github.com/selfkin/standards/tree/753ac37fc381bbc5c6753f34d8e65cfa61f87911/schemas) (`753ac37fc381bbc5c6753f34d8e65cfa61f87911`)
- Directory: `schemas/`
- License: Apache-2.0 (the schemas are code under LICENSE-CODE in selfkin/standards)
- Status upstream: Draft, not for implementation

| File | SHA-256 |
|---|---|
| `common.schema.json` | `e9b1f2ef5e879e97e76bfc8b1305727588cb0818f57d26d7ad5f5b0892de9d77` |
| `envelope.schema.json` | `397e90dbf58fb592a1f0e8500fdabb539e7dffdb2e7f4a61cf8fceba46677eb0` |
| `capability-token.schema.json` | `93ab5ec5aad075b2c7058b79bd977fff00a36d20bb8325fcaf5183e5141858c7` |
| `privacy-report.schema.json` | `c3de9884d3e544692b575c09dcda0bd9d6f91bf8aa65d9258e0476dbf1b0b436` |
| `refusal.schema.json` | `6384d90b7317702c6c94b8e8807575a62f71447be44f71b99de0a27de4a90d34` |
