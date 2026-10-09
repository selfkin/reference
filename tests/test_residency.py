# SPDX-License-Identifier: Apache-2.0
"""Residency tags combine by intersection and fail closed."""

import pytest

from selfkin_ref.errors import Refused
from selfkin_ref.residency import ANYWHERE, allowed_regions, check_destination


def test_empty_means_no_restriction():
    assert allowed_regions([]) is ANYWHERE
    check_destination([], "US")


@pytest.mark.parametrize("tags,expected", [
    (["CH"], {"CH"}), (["EU"], {"EU"}), (["CH-EU"], {"CH", "EU"}),
    (["CH-EU", "CH"], {"CH"}), (["CH", "EU"], set()),
])
def test_intersection(tags, expected):
    assert allowed_regions(tags) == expected


def test_never_widens():
    for region in ("CH", "EU", "US"):
        if region not in allowed_regions(["CH", "CH-EU"]):
            with pytest.raises(Refused) as info:
                check_destination(["CH", "CH-EU"], region)
            assert info.value.reason == "residency-unsupported"


def test_unknown_tags_fail_closed():
    with pytest.raises(Refused) as info:
        allowed_regions(["CH", "x-family"])
    assert info.value.reason == "residency-unknown-tag"
    assert allowed_regions(["x-family"], {"x-family": frozenset({"CH"})}) == {"CH"}
