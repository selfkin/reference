# SPDX-License-Identifier: Apache-2.0
"""Interop: the demo's documents pass the validator in selfkin/standards.

Set SELFKIN_STANDARDS to a checkout of https://github.com/selfkin/standards
to run these tests (CI does this in the ``interop`` job). The upstream
validator runs JSON Schema plus its semantic checks (attenuation, lifetime,
envelope binding, privacy report consistency) against the upstream schemas.
"""

import importlib.util
import io
import os
from pathlib import Path

import pytest

from selfkin_ref import demo

STANDARDS = os.environ.get("SELFKIN_STANDARDS")
pytestmark = pytest.mark.skipif(not STANDARDS, reason="SELFKIN_STANDARDS is not set")


@pytest.fixture(scope="module")
def upstream():
    path = Path(STANDARDS) / "tools" / "validate" / "validate.py"
    spec = importlib.util.spec_from_file_location("selfkin_upstream_validate", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    schemas = module.load_schemas(Path(STANDARDS) / "schemas")
    return module, schemas, module.build_registry(schemas)


@pytest.fixture(scope="module")
def artifacts():
    return demo.run(out=io.StringIO(), show_report=False)["artifacts"]


def test_demo_documents_pass_upstream_validator(upstream, artifacts):
    module, schemas, registry = upstream
    for name, document in artifacts.items():
        schema = name.split(".")[0]
        assert module.validate_document(document, schema, schemas, registry) == [], name
