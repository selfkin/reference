# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Selfkin reference contributors
"""Errors that map to refusal reason codes (registries/refusal-reasons.md)."""

from __future__ import annotations


class Refused(Exception):
    """A check failed. ``reason`` is a refusal reason code from the registry.

    ``detail`` is a human-readable explanation for local logs only. It must
    never be sent to a peer: refusals carry codes, not free text (SK-COM A7).
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class SchemaError(Refused):
    """The object does not match its JSON Schema (refusal reason ``malformed``)."""

    def __init__(self, schema: str, messages: list[str]) -> None:
        super().__init__("malformed", f"{schema}: " + "; ".join(messages))
        self.schema = schema
        self.messages = messages
