# SPDX-License-Identifier: Apache-2.0
"""Outputs validate against the vendored Selfkin v0.1 schemas, which match their source."""

import hashlib
import re
from importlib import resources

import pytest

from conftest import make_world
from selfkin_ref import envelope, schemas
from selfkin_ref.errors import SchemaError


def source_note():
    return resources.files("selfkin_ref.schema_files").joinpath("SOURCE.md").read_text("utf-8")


def test_vendored_schemas_match_recorded_checksums():
    recorded = dict(re.findall(r"`([a-z-]+\.schema\.json)`\s*\|\s*`([0-9a-f]{64})`", source_note()))
    assert set(recorded) == {f"{name}.schema.json" for name in schemas.NAMES}
    for filename, digest in recorded.items():
        data = resources.files("selfkin_ref.schema_files").joinpath(filename).read_bytes()
        assert hashlib.sha256(data).hexdigest() == digest, filename


def test_schema_ids_point_to_the_standards_repo():
    for name in schemas.NAMES:
        assert schemas.load(name)["$id"] == f"https://github.com/selfkin/standards/schemas/{name}.schema.json"


def test_all_produced_objects_validate():
    world = make_world()
    produced = {
        "capability-token": [world.root, world.delegated],
        "envelope": [world.instruction(), envelope.make_refusal(world.calendar, world.instruction(), "expired",
                                                                 session=world.session, seq=1, now=world.now)],
    }
    for name, objects in produced.items():
        for obj in objects:
            assert schemas.errors(name, obj) == []
    refusal = produced["envelope"][1]["data"]
    assert schemas.errors("refusal", refusal) == []


def test_schemas_reject_bad_objects():
    world = make_world()
    env = dict(world.instruction(), surprise=True)
    with pytest.raises(SchemaError) as info:
        schemas.validate("envelope", env)
    assert info.value.reason == "malformed"
    token = dict(world.delegated, cnf={})
    assert schemas.errors("capability-token", token)
    assert schemas.errors("refusal", {"v": "0.1", "reason": "because I said so"})
    assert schemas.errors("privacy-report", {"v": "0.1"})
