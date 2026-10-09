# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Selfkin reference contributors
"""Validation against the vendored Selfkin v0.1 JSON Schemas.

The schema files in ``selfkin_ref/schema_files`` are copied unchanged from
https://github.com/selfkin/standards (see ``schema_files/SOURCE.md``).
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from .errors import SchemaError

NAMES = ("common", "envelope", "capability-token", "privacy-report", "refusal")


@lru_cache(maxsize=None)
def load(name: str) -> dict:
    text = resources.files("selfkin_ref.schema_files").joinpath(f"{name}.schema.json").read_text("utf-8")
    return json.loads(text)


@lru_cache(maxsize=None)
def _registry() -> Registry:
    pairs = []
    for name in NAMES:
        schema = load(name)
        pairs.append((schema["$id"], Resource.from_contents(schema, default_specification=DRAFT202012)))
    return Registry().with_resources(pairs)


@lru_cache(maxsize=None)
def validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(load(name), registry=_registry(), format_checker=FormatChecker())


def errors(name: str, obj) -> list[str]:
    found = sorted(validator(name).iter_errors(obj), key=lambda e: list(e.absolute_path))
    return [f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}" for e in found]


def validate(name: str, obj) -> None:
    """Raise ``SchemaError`` (reason ``malformed``) if ``obj`` does not match."""
    problems = errors(name, obj)
    if problems:
        raise SchemaError(name, problems[:5])
