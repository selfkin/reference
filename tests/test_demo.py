# SPDX-License-Identifier: Apache-2.0
"""The CLI demo runs, passes every check, and its output is readable."""

import io
import subprocess
import sys

from selfkin_ref import demo, schemas


def test_demo_run_passes_all_checks():
    out = io.StringIO()
    result = demo.run(out=out)
    text = out.getvalue()
    assert result["ok"], text
    names = [name for name, _ in result["checks"]]
    for expected in ("sas", "execute", "replay-frame", "replay-envelope", "tamper-frame", "tamper-envelope",
                     "over-broad", "idempotent", "privacy-report"):
        assert expected in names
    assert schemas.errors("privacy-report", result["report"]) == []
    assert "\u2014" not in text and "\u2013" not in text
    assert "FAIL" not in text and "11/11 checks passed" in text


def test_demo_module_entry_point():
    proc = subprocess.run([sys.executable, "-m", "selfkin_ref.demo", "--no-report"], capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "checks passed" in proc.stdout
