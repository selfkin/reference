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


def parse_ts(text: str) -> datetime:
    """Parse an RFC 3339 timestamp that has an explicit offset or Z."""
    if not isinstance(text, str):
        raise ValueError("timestamp must be a string")
    value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError("timestamp needs an explicit offset")
    return value


def new_nonce() -> str:
    """128 bits of randomness as unpadded base64url (22 characters)."""
    return b64u(secrets.token_bytes(16))


def new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(8)}"


ONE_HOUR = timedelta(hours=1)
