# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Selfkin reference contributors
"""Privacy Gateway and privacy reports (SK-RT section 13, SK-PRV).

Every outbound cloud call goes through ``PrivacyGateway.prepare``. It
minimises the context, builds the exact outbound payload, and returns a
privacy report that lists field names and data classes, never values
(schemas/privacy-report.schema.json). The pseudonym map stays in the gateway
and never appears in a report.

Data class handling follows registries/data-classes.md:

* ``secrets`` never leave the device; ``biometric`` and ``adaptation`` are
  treated as local only (the registry marks them "local-only proposed");
* other sensitive classes are redacted, except ``identity`` and
  ``contacts``, which are pseudonymised so the task still works;
* relay-required classes are dropped when no relay is available, and the
  report shows ``relay.used: false`` so the missing relay is visible.

This reference makes no network calls. ``prepare`` returns the payload a
real runtime would send.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime

from . import dcbor, residency, schemas
from .errors import Refused
from .util import b64u, new_id, ts, utcnow

SENSITIVE = {"identity", "contacts", "communications", "location", "health", "biometric", "finance",
             "media", "usage", "adaptation", "memory", "secrets", "home.presence"}
RELAY_REQUIRED = {"communications", "location", "health", "finance"}
LOCAL_ONLY = {"secrets", "biometric", "adaptation"}
PSEUDONYMISE = {"identity", "contacts"}


def _classes(data_class: str) -> set[str]:
    """``home.presence.x`` belongs to ``home.presence`` and ``home``."""
    parts = data_class.split(".")
    return {".".join(parts[: i + 1]) for i in range(len(parts))}


def _has(data_class: str, group: set[str]) -> bool:
    return bool(_classes(data_class) & group)


@dataclass
class Provider:
    id: str
    name: str = ""
    claimed: str | None = None
    verified: bool = False
    verification_failure: str = "other"
    region: str | None = None
    retention: str = "undeclared"
    retention_purpose: list[str] = field(default_factory=list)


@dataclass
class ContextItem:
    field: str
    data_class: str
    value: object
    needed: bool = True


@dataclass
class PreparedCall:
    payload: dict
    report: dict
    warnings: list[str]


class PrivacyGateway:
    def __init__(self, agent: str, *, relay: dict | None = None, owner_tags: dict | None = None) -> None:
        self.agent = agent
        self.relay = relay  # for example {"type": "ohttp", "id": "urn:..."}; None when unavailable
        self.owner_tags = owner_tags
        self._pseudonyms: dict[tuple[str, str], str] = {}  # never leaves the device

    def _pseudonym(self, item: ContextItem) -> str:
        key = (item.data_class, repr(item.value))
        if key not in self._pseudonyms:
            self._pseudonyms[key] = f"{item.data_class.split('.')[0]}-{len(self._pseudonyms) + 1}"
        return self._pseudonyms[key]

    def prepare(self, provider: Provider, context: list[ContextItem], *, residency_tags: list[str],
                model: dict | None = None, now: datetime | None = None) -> PreparedCall:
        now = now or utcnow()
        if provider.region is None and residency.allowed_regions(residency_tags, self.owner_tags) is not None:
            raise Refused("residency-unsupported", "provider declares no region for residency-tagged data")
        if provider.region is not None:
            residency.check_destination(residency_tags, provider.region, self.owner_tags)

        effective = provider.claimed if (provider.verified and provider.claimed) else "P0"
        full_mode = effective == "P0"  # this reference always uses full mode for P0, never identified mode
        warnings: list[str] = []
        steps: list[str] = ["context-selection"]
        sent_fields, sent_classes = [], []
        red_fields, red_classes, pseudonymised = [], [], []
        payload_input: dict = {}

        for item in context:
            if not item.needed:
                red_fields.append(item.field)
                red_classes.append(item.data_class)
                continue
            if _has(item.data_class, LOCAL_ONLY):
                red_fields.append(item.field)
                red_classes.append(item.data_class)
                _add(steps, "redaction")
                continue
            if self.relay is None and _has(item.data_class, RELAY_REQUIRED):
                warnings.append(f"no relay available: withheld {item.field} ({item.data_class})")
                red_fields.append(item.field)
                red_classes.append(item.data_class)
                _add(steps, "redaction")
                continue
            if full_mode and _has(item.data_class, PSEUDONYMISE):
                # The pseudonym is sent, the original value is not: the field is
                # listed in sent.fields and redacted.pseudonymised, and its data
                # class only under redacted.data_classes.
                payload_input[item.field] = self._pseudonym(item)
                pseudonymised.append(item.field)
                red_classes.append(item.data_class)
                _add(steps, "pseudonymisation")
                sent_fields.append(item.field)
                continue
            elif full_mode and _has(item.data_class, SENSITIVE):
                red_fields.append(item.field)
                red_classes.append(item.data_class)
                _add(steps, "redaction")
                continue
            else:
                payload_input[item.field] = item.value
            sent_fields.append(item.field)
            sent_classes.append(item.data_class)

        if full_mode:
            steps += ["no-persistent-id"]
        if self.relay is not None:
            steps.append("relay")
        else:
            warnings.append("no relay available: provider sees the device network identity")

        payload = {"input": payload_input}
        encoded = dcbor.encode(payload)
        report = {
            "v": "0.1",
            "id": new_id("pr"),
            "call_at": ts(now),
            "agent": self.agent,
            "provider": {"id": provider.id, **({"name": provider.name} if provider.name else {})},
            "provider_profile": {"claimed": provider.claimed, "effective": effective, "verified": bool(provider.verified and provider.claimed)},
            "gateway_mode": "full" if full_mode else "verified-provider",
            "relay": {"used": True, **self.relay} if self.relay else {"used": False},
            "network_identity": "relay" if self.relay else "direct",
            "account": {"mode": "anonymous", "linkable": False},
            "sent": {"data_classes": _unique(sent_classes), "fields": _unique(sent_fields), "bytes": len(encoded)},
            "redacted": {"data_classes": _unique(red_classes), "fields": _unique(red_fields),
                         "pseudonymised": _unique(pseudonymised)},
            "minimisation": {"steps": _unique(steps),
                             "payload_digest": {"alg": "sha-256", "value": b64u(hashlib.sha256(encoded).digest())}},
            "residency": {"tags": list(residency_tags), **({"provider_region": provider.region} if provider.region else {})},
            "retention": {"declared": provider.retention,
                          **({"purpose": provider.retention_purpose} if provider.retention_purpose else {})},
        }
        if provider.claimed and effective == "P0" and provider.claimed != "P0":
            report["provider_profile"]["downgrade"] = {"from": provider.claimed, "reason": provider.verification_failure}
        if model is not None:
            report["model"] = model
        schemas.validate("privacy-report", report)
        return PreparedCall(payload, report, warnings)


def _add(steps: list[str], step: str) -> None:
    if step not in steps:
        steps.append(step)


def _unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))
