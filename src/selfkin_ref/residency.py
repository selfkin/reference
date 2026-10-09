# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Selfkin reference contributors
"""Residency tags (SK-RT section 11, SK-COM A5 and A8).

Standard tags: ``CH`` (Switzerland only), ``EU`` (EU and EEA member states
only), ``CH-EU`` (either). Owner-defined tags start with ``x-``. Several tags
combine by intersection; an empty list means no residency restriction was set.
Unknown tags are treated as not allowed (fail closed).

Regions are modelled as two jurisdictions, ``CH`` and ``EU`` (EU and EEA),
plus anything else, which no standard tag allows.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from .errors import Refused

STANDARD_TAGS: dict[str, frozenset[str]] = {
    "CH": frozenset({"CH"}),
    "EU": frozenset({"EU"}),
    "CH-EU": frozenset({"CH", "EU"}),
}
ANYWHERE = None  # sentinel: no residency restriction


def allowed_regions(tags: Iterable[str], owner_tags: Mapping[str, frozenset[str]] | None = None):
    """Return the set of regions every tag allows, or ``ANYWHERE`` for no tags.

    Raises ``Refused('residency-unknown-tag')`` for a tag this runtime does not
    recognise.
    """
    for tag in owner_tags or {}:
        if not tag.startswith("x-"):
            raise ValueError(f"owner-defined residency tags start with x- (got {tag!r})")
    known = {**(owner_tags or {}), **STANDARD_TAGS}
    result = ANYWHERE
    for tag in tags:
        if tag not in known:
            raise Refused("residency-unknown-tag", f"unknown residency tag {tag!r}")
        result = set(known[tag]) if result is ANYWHERE else result & known[tag]
    return result


def check_destination(tags: Iterable[str], region: str, owner_tags=None) -> None:
    """Raise ``Refused('residency-unsupported')`` if ``region`` is not allowed."""
    regions = allowed_regions(tags, owner_tags)
    if regions is not ANYWHERE and region not in regions:
        raise Refused("residency-unsupported", f"region {region!r} not in {sorted(regions)}")
