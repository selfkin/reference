#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Copy the Selfkin schemas from a checkout of selfkin/standards and write SOURCE.md.

Usage:
    python scripts/vendor_schemas.py PATH_TO_STANDARDS_CHECKOUT          # copy and record
    python scripts/vendor_schemas.py PATH_TO_STANDARDS_CHECKOUT --check  # exit 1 on drift

The files are copied byte for byte. SOURCE.md records the commit and a
SHA-256 for each file; tests/test_schemas.py checks those digests.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

NAMES = ("common", "envelope", "capability-token", "privacy-report", "refusal")
DEST = Path(__file__).resolve().parent.parent / "src" / "selfkin_ref" / "schema_files"


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    source = Path(sys.argv[1])
    check = "--check" in sys.argv[2:]
    commit = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True, text=True,
                            check=True).stdout.strip()
    drift = []
    rows = []
    for name in NAMES:
        filename = f"{name}.schema.json"
        upstream = (source / "schemas" / filename).read_bytes()
        local = (DEST / filename).read_bytes() if (DEST / filename).exists() else b""
        if upstream != local:
            drift.append(filename)
        if not check:
            shutil.copyfile(source / "schemas" / filename, DEST / filename)
        rows.append(f"| `{filename}` | `{hashlib.sha256(upstream).hexdigest()}` |")
    if check:
        for filename in drift:
            print(f"drift: {filename} differs from selfkin/standards at {commit}")
        if not drift:
            print(f"vendored schemas match selfkin/standards at {commit}")
        return 1 if drift else 0
    (DEST / "SOURCE.md").write_text(TEMPLATE.format(commit=commit, short=commit[:7], rows="\n".join(rows)), "utf-8")
    print(f"vendored {len(NAMES)} schemas from {commit}")
    return 0


TEMPLATE = """# Source of the vendored schemas

These JSON Schemas are copied byte for byte from the Selfkin standards
repository. Do not edit them here; change them upstream and re-vendor with
`python scripts/vendor_schemas.py PATH_TO_STANDARDS_CHECKOUT`.

- Repository: https://github.com/selfkin/standards
- Commit: [`{short}`](https://github.com/selfkin/standards/tree/{commit}/schemas) (`{commit}`)
- Directory: `schemas/`
- License: Apache-2.0 (the schemas are code under LICENSE-CODE in selfkin/standards)
- Status upstream: Draft, not for implementation

| File | SHA-256 |
|---|---|
{rows}
"""

if __name__ == "__main__":
    raise SystemExit(main())
