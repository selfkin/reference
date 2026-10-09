# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Selfkin reference contributors
"""Capability tokens (SK-COM A6, schemas/capability-token.schema.json).

* ``issue`` creates a root token, ``delegate`` creates a narrower child.
* ``verify_chain`` checks signatures, lifetimes, proof-of-possession binding,
  and the narrowing rules (a) to (f) of SK-COM A6 for every link.
* ``authorise`` binds a verified token to an envelope: ``sub`` equals
  ``sender_agent``, ``aud`` equals the envelope ``aud``, and a right covers
  the requested action and resource.

Interpretation choices (see README, "Spec ambiguities"):

* Each link in ``chain`` was signed with its own ``chain`` member set to the
  links before it (a root token has ``chain: []``). A verifier rebuilds that
  member before checking a link signature, so the A5.1 rule "signature over
  the object without ``sig``" holds for every link.
* ``chain`` holds at most 16 links (the token itself is not counted), matching
  the schema's ``maxItems``.
* The root issuer must be the audience itself or the audience's owner.
* Proof of possession: the envelope signature by ``sender_agent`` proves
  possession when ``cnf.jkt`` is the RFC 7638 thumbprint of that agent key
  (or ``cnf.kid`` names it). Every link's ``cnf`` must match its own ``sub``.
* An ``instructions`` object without ``resource`` is never covered.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal

from .errors import Refused
from .keys import SigningKey, jwk_thumbprint, public_from_did
from .signing import sign_object, verify_object
from .util import ONE_HOUR, new_id, parse_ts, ts, utcnow

MAX_CHAIN = 16
MAX_LIFETIME = ONE_HOUR


def _cnf_for(holder: str) -> dict:
    return {"jkt": jwk_thumbprint(public_from_did(holder))}


def issue(issuer: SigningKey, *, sub: str, aud: str, rights: list[dict], lifetime: timedelta = timedelta(minutes=30),
          budget: dict | None = None, now: datetime | None = None, token_id: str | None = None) -> dict:
    """Issue a root token signed by ``issuer`` (an owner or the audience agent)."""
    now = now or utcnow()
    body = {"v": "0.1", "id": token_id or new_id("tok"), "iss": issuer.did, "sub": sub, "aud": aud,
            "iat": ts(now), "exp": ts(now + lifetime), "cnf": _cnf_for(sub), "rights": copy.deepcopy(rights)}
    if budget is not None:
        body["budget"] = copy.deepcopy(budget)
    body["chain"] = []
    return sign_object(body, issuer)


def _as_link(token: dict) -> dict:
    return {k: v for k, v in token.items() if k != "chain"}


def delegate(parent: dict, holder: SigningKey, *, sub: str, rights: list[dict], lifetime: timedelta = timedelta(minutes=15),
             budget: dict | None = None, now: datetime | None = None, check: bool = True,
             token_id: str | None = None) -> dict:
    """Create a child token. ``holder`` must be the parent's ``sub``.

    With ``check=True`` (the default) the child is checked against rules (a)
    to (e) and ``ValueError`` is raised if it would widen anything. Tests and
    the demo pass ``check=False`` to build a deliberately over-broad token and
    show that receivers reject it.
    """
    now = now or utcnow()
    exp = min(now + lifetime, parse_ts(parent["exp"])) if check else now + lifetime
    body = {"v": "0.1", "id": token_id or new_id("tok"), "iss": holder.did, "sub": sub, "aud": parent["aud"],
            "iat": ts(now), "exp": ts(exp), "cnf": _cnf_for(sub), "rights": copy.deepcopy(rights)}
    if budget is not None:
        body["budget"] = copy.deepcopy(budget)
    body["chain"] = copy.deepcopy(parent["chain"]) + [_as_link(parent)]
    if check:
        _check_narrowing(parent, body)
        if len(body["chain"]) > MAX_CHAIN:
            raise ValueError("delegation chain would exceed 16 links")
    return sign_object(body, holder)


# ------------------------------------------------------------- narrowing


def resource_covers(parent: str, child: str) -> bool:
    """Equal, or ``child`` lies below a parent resource that ends in ``/*``."""
    if parent == child:
        return True
    return parent.endswith("/*") and child.startswith(parent[:-1]) and len(child) > len(parent) - 1


def _money_le(child: dict, parent: dict) -> bool:
    return child["currency"] == parent["currency"] and Decimal(child["amount"]) <= Decimal(parent["amount"])


def _constraints_narrow(parent: dict, child: dict) -> bool:
    if "max_amount" in parent and ("max_amount" not in child or not _money_le(child["max_amount"], parent["max_amount"])):
        return False
    if "max_uses" in parent and child.get("max_uses", parent["max_uses"] + 1) > parent["max_uses"]:
        return False
    if "data_classes" in parent and not set(child.get("data_classes", ["<missing>"])) <= set(parent["data_classes"]):
        return False
    return True


def _right_narrows(parent_rights: list[dict], right: dict) -> bool:
    for parent in parent_rights:
        if parent["action"] == right["action"] and resource_covers(parent["resource"], right["resource"]) \
                and _constraints_narrow(parent.get("constraints", {}), right.get("constraints", {})):
            return True
    return False


def _budget_narrows(parent: dict | None, child: dict | None) -> bool:
    parent, child = parent or {}, child or {}
    for limit in ("messages", "compute_units"):
        if limit in parent and child.get(limit, parent[limit] + 1) > parent[limit]:
            return False
    if "money" in parent and ("money" not in child or not _money_le(child["money"], parent["money"])):
        return False
    return True


def _check_narrowing(parent: dict, child: dict) -> None:
    if child["iss"] != parent["sub"]:
        raise ValueError("(a) child iss must equal parent sub")
    if child["aud"] != parent["aud"]:
        raise ValueError("(b) child aud must equal parent aud")
    if parse_ts(child["exp"]) > parse_ts(parent["exp"]):
        raise ValueError("(c) child exp is later than parent exp")
    for right in child["rights"]:
        if not _right_narrows(parent["rights"], right):
            raise ValueError(f"(d)/(e) right {right['action']} on {right['resource']} is not covered by the parent")
    if not _budget_narrows(parent.get("budget"), child.get("budget")):
        raise ValueError("(e) budget is missing a parent limit or exceeds it")


# ------------------------------------------------------------- verification


@dataclass
class VerifiedToken:
    token: dict
    root_issuer: str
    links: int
    right: dict | None = None


def _check_cnf(link: dict) -> None:
    cnf = link.get("cnf", {})
    holder_public = public_from_did(link["sub"])
    if "jkt" in cnf and cnf["jkt"] != jwk_thumbprint(holder_public):
        raise Refused("unauthorized", "cnf.jkt does not match the holder key")
    if "kid" in cnf and cnf["kid"].split("#", 1)[0] != link["sub"]:
        raise Refused("unauthorized", "cnf.kid does not name the holder key")
    if "jkt" not in cnf and "kid" not in cnf:
        raise Refused("unauthorized", "no supported proof-of-possession binding in cnf")


def verify_chain(token: dict, *, now: datetime | None = None, trusted_roots: set[str],
                 max_lifetime: timedelta = MAX_LIFETIME) -> VerifiedToken:
    """Verify a token and its chain. Raises ``Refused``.

    ``trusted_roots`` are identities allowed to issue root tokens for this
    audience (the audience agent and its owner).
    """
    now = now or utcnow()
    chain = token.get("chain")
    if not isinstance(chain, list):
        raise Refused("malformed", "token has no chain member")
    if len(chain) > MAX_CHAIN:
        raise Refused("unauthorized", f"chain has {len(chain)} links, at most {MAX_CHAIN} allowed")
    sequence = [dict(link, chain=copy.deepcopy(chain[:i])) for i, link in enumerate(chain)] + [token]
    for index, link in enumerate(sequence):
        try:
            verify_object(link, expected_signer=link["iss"])
        except Refused as exc:
            raise Refused("unauthorized", f"link {index}: {exc.detail}") from None
        iat, exp = parse_ts(link["iat"]), parse_ts(link["exp"])
        if exp - iat > max_lifetime:
            raise Refused("unauthorized", f"link {index}: lifetime exceeds {max_lifetime}")
        if exp <= now:
            raise Refused("expired", f"link {index} expired")
        if "nbf" in link and parse_ts(link["nbf"]) > now:
            raise Refused("unauthorized", f"link {index} not yet valid")
        _check_cnf(link)
        if index == 0:
            if link["iss"] not in trusted_roots:
                raise Refused("unauthorized", "root issuer is not the audience or its owner")
        else:
            try:
                _check_narrowing(sequence[index - 1], link)
            except ValueError as exc:
                raise Refused("unauthorized", f"link {index} widens its parent: {exc}") from None
    return VerifiedToken(token=token, root_issuer=sequence[0]["iss"], links=len(chain))


def find_right(token: dict, action: str, resource: str | None) -> dict:
    """Return the right that covers ``action`` on ``resource`` or raise ``Refused``."""
    if resource is None:
        raise Refused("unauthorized", "instructions without resource are not covered")
    for right in token["rights"]:
        if right["action"] == action and resource_covers(right["resource"], resource):
            return right
    raise Refused("unauthorized", f"no right covers {action} on {resource}")
