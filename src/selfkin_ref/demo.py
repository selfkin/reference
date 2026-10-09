# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Selfkin reference contributors
"""End-to-end demo: ``python -m selfkin_ref.demo``.

Two of Alice's devices pair. An agent on the phone sends a signed, encrypted
instruction with a delegated capability to the home server, which verifies
it and runs a toy action. Then the demo shows what gets rejected: a replayed
frame, a replayed envelope, a tampered ciphertext, an instruction changed
after signing, and an over-broad delegation. The toy action makes one cloud
call through the Privacy Gateway, which emits a privacy report.

Everything runs in one process with no network access.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path

from . import capability, dcbor, envelope, schemas
from .identity import Owner
from .keys import short
from .privacy import ContextItem, PrivacyGateway, Provider
from .runtime import Runtime
from .util import new_id, utcnow

ACTION = "calendar.propose_meeting"
WORK = "urn:selfkin:calendar:alice/work"
ALL = "urn:selfkin:calendar:alice/*"


class Printer:
    def __init__(self, out) -> None:
        self.out = out
        self.step = 0

    def section(self, title: str) -> None:
        self.step += 1
        print(f"\n[{self.step}] {title}", file=self.out)

    def line(self, who: str, text: str) -> None:
        print(f"    {who:<9} {text}", file=self.out)

    def result(self, ok: bool, text: str) -> None:
        print(f"    {'PASS' if ok else 'FAIL':<9} {text}", file=self.out)


def run(out=sys.stdout, show_report: bool = True) -> dict:
    p = Printer(out)
    now = utcnow()
    results: dict = {"checks": []}

    def check(name: str, ok: bool, text: str) -> None:
        results["checks"].append((name, ok))
        p.result(ok, text)

    print("Selfkin reference demo (Draft, not for production; simplified E2E, not Noise or MLS)", file=out)

    # ------------------------------------------------------------ identities
    p.section("Identities: one owner, two devices, one key per agent")
    alice = Owner.create("alice")
    phone = alice.add_device("phone", region="CH", now=now)
    home = alice.add_device("homebox", region="CH", now=now)
    a = Runtime(alice, phone, now=now)
    b = Runtime(alice, home, now=now)
    planner = a.add_agent("planner", now=now)
    assistant = a.add_agent("assistant", now=now)
    helper = a.add_agent("helper", now=now)

    gateway = PrivacyGateway(agent="", relay=None)
    provider = Provider(id="urn:selfkin:provider:example-cloud", name="Example Cloud LLM", claimed="P2",
                        verified=False, verification_failure="signature-invalid", region="CH", retention="P30D")
    reports: list[dict] = []

    def propose_meeting(env: dict) -> dict:
        params = env["instructions"].get("params", {})
        call = gateway.prepare(provider, [
            ContextItem("request.title", "query.general", params.get("title", "")),
            ContextItem("calendar.free_slots", "calendar.availability", ["Tue 10:00", "Thu 14:00"]),
            ContextItem("attendee.email", "contacts.email", params.get("attendee", "")),
            ContextItem("owner.health_note", "health.records", "physio on Tuesday"),
            ContextItem("owner.location", "location.precise", "46.948,7.447"),
            ContextItem("calendar.all_events", "calendar.events", ["(full calendar)"], needed=False),
        ], residency_tags=["CH-EU"], model={"name": "example-model", "version": "2026-09"}, now=now)
        reports.append(call.report)
        for warning in call.warnings:
            p.line("gateway", "WARNING " + warning)
        return {"status": "proposed", "slots": ["Tue 10:00", "Thu 14:00"]}

    calendar = b.add_agent("calendar", handlers={ACTION: propose_meeting}, now=now)
    gateway.agent = calendar.did
    names = {alice.did: "alice", phone.did: "phone", home.did: "homebox", a.core.did: "core@phone",
             b.core.did: "core@homebox", planner.did: "planner@phone", assistant.did: "assistant@phone",
             helper.did: "helper@phone", calendar.did: "calendar@homebox"}
    for rt in (a, b):
        rt.trust.labels.update(names)
    p.line("owner", f"alice      {short(alice.did)}")
    for agent in (a.core, planner, assistant, helper, b.core, calendar):
        p.line("agent", f"{names[agent.did]:<17} {short(agent.did)}  (owner statement signed by alice)")

    # --------------------------------------------------------------- pairing
    p.section("Pairing: owner consent on both devices, X25519 + HKDF, 6-digit SAS")
    request = a.pairing_request(b.core.did, forms=["F1", "F6"], tags=["CH-EU"], actions=[ACTION], now=now)
    p.line("phone", f"-> sk.pairing.request  session={request['session']}")
    response, sas_b = b.accept_pairing(request, now=now)
    p.line("homebox", "-> sk.pairing.response (signed, with ephemeral X25519 key)")
    confirm, sas_a = a.complete_pairing(response, now=now)
    record = b.finish_pairing(confirm, now=now)
    session = request["session"]
    p.line("phone", f"SAS {sas_a}")
    p.line("homebox", f"SAS {sas_b}")
    check("sas", sas_a == sas_b, "both screens show the same SAS; alice confirms on both devices")
    p.line("record", f"forms={record['forms']} residency={record['residency']} capabilities={record['capabilities']}")

    # -------------------------------------------------------------- tokens
    p.section("Capability tokens: alice -> planner (root), planner -> assistant (narrowed)")
    root = capability.issue(alice.key, sub=planner.did, aud=calendar.did, lifetime=timedelta(minutes=50), now=now,
                            rights=[{"action": ACTION, "resource": ALL,
                                     "constraints": {"data_classes": ["calendar.availability", "calendar.events"],
                                                     "max_uses": 5}}],
                            budget={"messages": 10})
    delegated = capability.delegate(root, planner.key, sub=assistant.did, lifetime=timedelta(minutes=30), now=now,
                                    rights=[{"action": ACTION, "resource": WORK,
                                             "constraints": {"data_classes": ["calendar.availability"], "max_uses": 2}}],
                                    budget={"messages": 3})
    for token in (root, delegated):
        schemas.validate("capability-token", token)
    p.line("root", f"{ACTION} on {ALL}, max_uses 5, budget 10 messages, 50 min")
    p.line("delegated", f"{ACTION} on {WORK}, max_uses 2, budget 3 messages, 30 min, chain of {len(delegated['chain'])}")
    check("tokens-schema", True, "both tokens match capability-token.schema.json")

    def instruction(sender, token, *, resource=WORK, idem=None, title="Project sync"):
        return envelope.make(sender, aud=calendar.did, session=session, seq=a.next_seq(session, sender),
                             form="F6", intent="scheduling.propose", cap_token=token,
                             instructions={"action": ACTION, "resource": resource, "consequential": False,
                                           "params": {"title": title, "duration": "PT30M",
                                                      "attendee": "bob@example.org"}},
                             idem_key=idem or new_id("idem-key"),
                             residency_tags=["CH-EU"], data_classes=["calendar.availability"],
                             provenance=[{"role": "delegator", "id": planner.did, "device": phone.did}], now=now)

    # ------------------------------------------------------------- happy path
    p.section("assistant@phone -> calendar@homebox: signed, encrypted instruction")
    env = instruction(assistant, delegated)
    frame = a.seal(session, env)
    p.line("phone", f"-> envelope seq={env['seq']} intent={env['intent']} action={ACTION}")
    p.line("phone", f"   frame of {len(frame)} bytes (ChaCha20-Poly1305), envelope signed with dcbor")
    p.line("homebox", "checks: version, schema, aud, owner statements, signature, freshness, nonce, seq,")
    p.line("", "        residency CH-EU vs region CH, chain root -> delegated, binding, rights, budget")
    delivery = b.deliver(session, frame, now=now)
    ok = delivery.status == "executed"
    check("execute", ok, f"executed {ACTION} -> {delivery.outcome.result if ok else delivery.reason}")
    results["report"] = reports[-1] if reports else None

    # ---------------------------------------------------------------- replays
    p.section("Replay: the same frame is injected again")
    d = b.deliver(session, frame, now=now)
    check("replay-frame", d.status == "dropped" and d.reason == "replayed-frame",
          f"dropped at the transport layer ({d.reason}); counter already used")

    p.section("Replay: the same signed envelope in a fresh frame")
    d = b.deliver(session, a.seal(session, env), now=now)
    check("replay-envelope", d.status == "refused" and d.reason == "replayed",
          f"refused with reason '{d.reason}'; nonce already seen")
    refusal_env = d.envelope
    back = a.deliver(session, d.reply, now=now)
    p.line("phone", f"<- sk.refused {json.dumps(d.envelope['data'], sort_keys=True)}")
    check("refusal-schema", back.status == "executed" and not schemas.errors("envelope", d.envelope),
          "refusal envelope is signed, schema-valid, and carries no free text")

    # ---------------------------------------------------------------- tamper
    p.section("Tamper: one bit of ciphertext flipped in transit")
    sealed = dcbor.decode(a.seal(session, instruction(assistant, delegated)))
    sealed["ct"] = sealed["ct"][:10] + bytes([sealed["ct"][10] ^ 0x01]) + sealed["ct"][11:]
    d = b.deliver(session, dcbor.encode(sealed), now=now)
    check("tamper-frame", d.status == "dropped" and d.reason == "decrypt-failed",
          f"dropped ({d.reason}); AEAD tag does not verify")

    p.section("Tamper: resource changed after signing (alice/work -> alice/private)")
    forged = instruction(assistant, delegated)
    forged["instructions"]["resource"] = "urn:selfkin:calendar:alice/private"
    d = b.deliver(session, a.seal(session, forged), now=now)
    check("tamper-envelope", d.reason == "bad-signature", f"refused with reason '{d.reason}'")

    # ------------------------------------------------------------ delegation
    p.section("Over-broad delegation: assistant -> helper widens alice/work to alice/*")
    try:
        capability.delegate(delegated, assistant.key, sub=helper.did, now=now,
                            rights=[{"action": ACTION, "resource": ALL,
                                     "constraints": {"data_classes": ["calendar.availability"], "max_uses": 2}}],
                            budget={"messages": 3})
        refused_locally = False
    except ValueError as exc:
        refused_locally = True
        p.line("phone", f"delegate() refuses locally: {exc}")
    wide = capability.delegate(delegated, assistant.key, sub=helper.did, now=now, check=False,
                               rights=[{"action": ACTION, "resource": ALL,
                                        "constraints": {"data_classes": ["calendar.availability"], "max_uses": 2}}],
                               budget={"messages": 3})
    p.line("phone", "a misbehaving agent builds it anyway (check=False) and sends it")
    d = b.deliver(session, a.seal(session, instruction(helper, wide)), now=now)
    p.line("homebox", f"detail (local log only): {d.detail}")
    check("over-broad", refused_locally and d.reason == "unauthorized", f"refused with reason '{d.reason}'")

    # ------------------------------------------------------------ idempotency
    p.section("Retry with the same idem_key (new nonce and seq)")
    retry = instruction(assistant, delegated, idem=env["idem_key"])
    d = b.deliver(session, a.seal(session, retry), now=now)
    check("idempotent", d.status == "duplicate" and len(reports) == 1,
          "not executed again; the stored result is returned (SK-COM A9)")

    # ---------------------------------------------------------------- report
    p.section("Privacy report for the one cloud call (field names only, no values)")
    report = reports[0]
    schemas.validate("privacy-report", report)
    if show_report:
        for text in json.dumps(report, indent=2, sort_keys=True).splitlines():
            print("    " + text, file=out)
    leaked = [v for v in ("bob@example.org", "physio", "46.948") if v in json.dumps(report)]
    check("privacy-report", not leaked, "valid against privacy-report.schema.json; no values in the report")

    p.section("Local log on homebox (SK-COM A10: form, peer, intent, decision)")
    for entry in b.log:
        p.line(entry.direction, f"{entry.form:<3} {entry.peer:<17} {entry.intent:<20} {entry.decision}")

    passed = sum(1 for _, ok in results["checks"] if ok)
    total = len(results["checks"])
    print(f"\n{passed}/{total} checks passed", file=out)
    results["ok"] = passed == total
    results["log"] = b.log
    results["artifacts"] = {
        "envelope.pairing-request": request,
        "envelope.instruction": env,
        "envelope.refusal": refusal_env,
        "refusal.replayed": refusal_env["data"],
        "capability-token.root": root,
        "capability-token.delegated": delegated,
        "privacy-report.cloud-call": report,
    }
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m selfkin_ref.demo", description=__doc__.splitlines()[0])
    parser.add_argument("--no-report", action="store_true", help="do not print the full privacy report")
    parser.add_argument("--export", metavar="DIR", help="write the produced envelopes, tokens, and report as JSON")
    args = parser.parse_args(argv)
    results = run(show_report=not args.no_report)
    if args.export:
        target = Path(args.export)
        target.mkdir(parents=True, exist_ok=True)
        for name, obj in results["artifacts"].items():
            (target / f"{name}.json").write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", "utf-8")
        print(f"exported {len(results['artifacts'])} documents to {target}")
    return 0 if results["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
