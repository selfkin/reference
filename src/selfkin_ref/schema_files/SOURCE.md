# Source of the vendored schemas

These JSON Schemas are copied byte for byte from the Selfkin standards
repository. Do not edit them here; change them upstream and re-vendor with
`python scripts/vendor_schemas.py PATH_TO_STANDARDS_CHECKOUT`.

- Repository: https://github.com/selfkin/standards
- Commit: [`9c3ce68`](https://github.com/selfkin/standards/tree/9c3ce68e72dfeccb437352a60835a663fc579fbc/schemas) (`9c3ce68e72dfeccb437352a60835a663fc579fbc`)
- Directory: `schemas/`
- License: Apache-2.0 (the schemas are code under LICENSE-CODE in selfkin/standards)
- Status upstream: Draft, not for implementation

| File | SHA-256 |
|---|---|
| `common.schema.json` | `373862db9a19b9455ab2a2fb6cd45555a97501df67ddd1f8031c91a076b0c59e` |
| `envelope.schema.json` | `3a1226209db3d6f384de86b1a079431fa29727f0ce0c032368a145b6f26b297e` |
| `capability-token.schema.json` | `93ab5ec5aad075b2c7058b79bd977fff00a36d20bb8325fcaf5183e5141858c7` |
| `privacy-report.schema.json` | `c3de9884d3e544692b575c09dcda0bd9d6f91bf8aa65d9258e0476dbf1b0b436` |
| `refusal.schema.json` | `6384d90b7317702c6c94b8e8807575a62f71447be44f71b99de0a27de4a90d34` |
