# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Selfkin reference contributors
"""Small helpers: base64url, RFC 3339 timestamps, random identifiers."""

from __future__ import annotations

import base64
import re
import secrets
from datetime import datetime, timedelta, timezone


def b64u(data: bytes) -> str:
    """Unpadded base64url (RFC 4648 section 5)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


_B64U = re.compile(r"^[A-Za-z0-9_-]*$")


def b64u_decode(text: str) -> bytes:
    """Strict unpadded base64url: no padding, no other characters, canonical bits."""
    if not isinstance(text, str) or not _B64U.match(text) or len(text) % 4 == 1:
        raise ValueError("expected unpadded base64url text")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64u(data) != text:
        raise ValueError("non-canonical base64url text")
    return data


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def ts(moment: datetime) -> str:
    """Format as RFC 3339 with an explicit offset (Z), second precision."""
    if moment.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return moment.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


_RFC3339 = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$")


def parse_ts(text: str) -> datetime:
    """Parse an RFC 3339 timestamp that has an explicit offset or Z.

    Accepts the form the schemas allow (any number of fraction digits, which
    ``datetime.fromisoformat`` on Python 3.10 does not). Raises ``ValueError``
    for anything else, including impossible dates and leap seconds.
    """
    match = _RFC3339.match(text) if isinstance(text, str) else None
    if match is None:
        raise ValueError("timestamp must be RFC 3339 with an explicit offset or Z")
    year, month, day, hour, minute, second, fraction, offset = match.groups()
    micro = int((fraction or "0")[:6].ljust(6, "0"))
    if offset == "Z":
        zone = timezone.utc
    else:
        sign = 1 if offset[0] == "+" else -1
        hours, minutes = int(offset[1:3]), int(offset[4:6])
        if hours > 23 or minutes > 59:
            raise ValueError("timestamp offset out of range")
        zone = timezone(sign * timedelta(hours=hours, minutes=minutes))
    return datetime(int(year), int(month), int(day), int(hour), int(minute), int(second), micro, tzinfo=zone)


def new_nonce() -> str:
    """128 bits of randomness as unpadded base64url (22 characters)."""
    return b64u(secrets.token_bytes(16))


def new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(8)}"


ONE_HOUR = timedelta(hours=1)
