"""Every check the harness answers: what each one proves, and the rows it still needs.

The names are the rack audit's (lane-hosts-keys PLAN.md:110-120) for the
shell uses of pass 34 section 13, and `kind-<n>-...` for the job kinds of
15.2. A check whose rows are not merged has no `run`: it answers WAITS with
those rows, never a skip and never a PASS. A later row's PR gives its check a
`run` (one canary rides each row it proves).
"""

from __future__ import annotations

import http.client
from dataclasses import dataclass, field
from typing import Callable

from rack.addresses import AddressError, Target, pinned_status, resolve_target
from rack.evidence import Evidence
from rack.rack_config import RackConfig


@dataclass
class Outcome:
    passed: bool
    reason: str = ""


@dataclass
class Context:
    config: RackConfig
    host: str
    phase: str
    run_id: str
    evidence: Evidence


@dataclass
class Check:
    name: str
    proves: str
    needs: list[str] = field(default_factory=list)
    run: Callable[[Context], Outcome] | None = None


def drained(ctx: Context) -> Outcome:
    """old-channels-drained: nothing of the tool or the old transports is left."""
    from rack.readback.drain import read_drain

    reading = read_drain(ctx.config.section("drain"), ctx.config.proc_root, ctx.config.command_timeout_secs)
    ctx.evidence.add("drain", reading.__dict__)
    summary = reading.summary()
    return Outcome(not summary, f"live: {summary}" if summary else "")


def transfers_drained(ctx: Context) -> Outcome:
    """other-rsync: no file transfer program runs, and every source was read."""
    from rack.readback.drain import read_drain

    reading = read_drain(ctx.config.section("drain"), ctx.config.proc_root, ctx.config.command_timeout_secs)
    ctx.evidence.add("transfers", reading.transfers)
    ctx.evidence.add("unread", reading.unread)
    summary = reading.summary(("transfers", "sources not read"))
    return Outcome(not summary, f"live: {summary}" if summary else "")


def keys_unused(ctx: Context) -> Outcome:
    """identity-scope and pivot-audit: no rack key logs in here, or is live."""
    from rack.readback.keys import judge, read_keys

    section = ctx.config.section("keys")
    reading = read_keys(section, ctx.config.proc_root, ctx.config.command_timeout_secs)
    passed, reason, facts = judge(reading, section, ctx.phase)
    ctx.evidence.add("keys", facts)
    ctx.evidence.add("unread", reading.unread + reading.unread_files)
    return Outcome(passed, reason)


def forward_policy(ctx: Context) -> Outcome:
    """forward-policy: no ssh forward is live, and the model gateway answers on its own route.

    It asks the gateway's model list and spends nothing: any HTTP answer
    below 300, or a 4xx (401 included), shows the route works without a
    forward. A URL that connects to this box (loopback, unspecified or its own
    address, in any spelling) is refused, because on a lane box it would be a
    forward. The request connects only to the addresses that judgement saw
    (rack.addresses), and no redirect is followed: a 3xx fails, since its
    next hop was never judged. A forward source that could not be read is no
    proof of absence.
    """
    from rack.readback.drain import FORWARD_SOURCES, read_drain

    url = ctx.config.section("canary")["model_list_url"]
    if not url:
        return Outcome(False, "no canary.model_list_url")
    try:
        target = resolve_target(url)
    except AddressError as error:
        return Outcome(False, f"canary.model_list_url: {error}")
    if target.local:
        return Outcome(False, "canary.model_list_url is a loopback or local address")
    if target.scheme not in ("http", "https"):
        return Outcome(False, "canary.model_list_url is not http or https")
    reading = read_drain(ctx.config.section("drain"), ctx.config.proc_root, ctx.config.command_timeout_secs)
    ctx.evidence.add("forwards", reading.forwards)
    if reading.forwards:
        return Outcome(False, f"live: {len(reading.forwards)} ssh forwards")
    missing = [source for source in reading.unread if source in FORWARD_SOURCES]
    if missing:
        return Outcome(False, "not read: " + ", ".join(missing))
    return gateway_outcome(ctx, target)


def gateway_outcome(ctx: Context, target: Target) -> Outcome:
    """The model list's answer over the judged address, as forward-policy reads it."""
    try:
        status = pinned_status(target, ctx.config.command_timeout_secs)
    except (OSError, http.client.HTTPException) as error:
        return Outcome(False, f"the model gateway did not answer: {type(error).__name__}")
    ctx.evidence.add("model_list_status", status)
    if 300 <= status < 400:
        return Outcome(False, f"the model gateway answered a redirect ({status}), which is not followed")
    if status >= 500:
        return Outcome(False, f"the model gateway answered {status}")
    return Outcome(True)


def _canary(module: str, function: str) -> Callable[[Context], Outcome]:
    def run(ctx: Context) -> Outcome:
        import importlib

        return getattr(importlib.import_module(f"rack.canary.{module}"), function)(ctx)

    return run


_ORCHESTRATOR_MEL = "mel's window (R6); run by the Orchestrator only, as evidence"
_PUBLISH = "a disposable repository and the owner's mirror-push grant (an outward act; ASK first)"

CHECKS: dict[str, Check] = {
    check.name: check
    for check in (
        # Section 13: the shell uses, under the audit's names.
        Check("identity-scope", "13: no machine logs in to this box with another's key (gate C)", run=keys_unused),
        Check("pivot-audit", "13: no live session on a rack key reaches this box (gate C)", run=keys_unused),
        Check("export-safety", "the audit's SFTP jails", needs=["the Orchestrator's SFTP jails (audit PLAN.md:52-75)"]),
        Check("mesh-probe", "13 row 1: probes and status through vault.machines.execution.get", run=_canary("machines", "run_mesh_probe")),
        Check("fleet-exec", "13 row 2: a pinned job launched and ended through an order (its log follow rides Q3 #10466)", run=_canary("fleet_exec", "run")),
        Check("fleet-sync", "13 rows 6 and 8: code and inputs by digest, work trees through repo custody", needs=["R10", "P2"]),
        Check("okc-delegation", "13 row 3: the booking coordinator as orders on a line", needs=["F1", "Q5 #10467", "G2", "R10", "P2"]),
        Check(
            "inbox-append",
            "13 row 9: notes as vault writes, each seen once",
            needs=["a write a Grant can bound to one destination, with its list read (none at 14c82900)", "the lanes as Oneiron agents"],
        ),
        Check("sol-lock", "13 row 4: a named running cap", needs=["Q5 #10467"]),
        Check("astra-launch", "13 row 5: a session as a work order", needs=["W1 PR 3 (issuer side)"]),
        Check("session-ops", "13 row 5: a session's status and stop by attempt key", needs=["W1 PR 3 (issuer side)"]),
        Check("signed-publish", "13 row 7 and 15.3: publishing through repo custody's doors", needs=[_PUBLISH]),
        Check("git-remote", "13 row 7: fetch and push through the approved route", needs=[_PUBLISH]),
        Check("other-rsync", "13 row 6: no tree copied through a shell", run=transfers_drained),
        Check("forward-policy", "13 row 10: the model gateway reached without a forward", run=forward_policy),
        Check("old-channels-drained", "15.1 gate B: the drain readback at the box", run=drained),
        # Section 15.2: the job kinds.
        Check("kind-1-gpu-arms", "15.2 kind 1", needs=[_ORCHESTRATOR_MEL]),
        Check("kind-2-house-nightly", "15.2 kind 2", needs=[_ORCHESTRATOR_MEL]),
        Check("kind-3-machine-switch", "15.2 kind 3, read side: each machine's enabled and paused state read through Oneiron", run=_canary("machines", "run_switch_read")),
        Check("kind-4-storage", "15.2 kind 4", needs=["R3b S2 #10512"]),
        Check("kind-5-drain-guard", "15.2 kind 5, read side: each machine's drain read through Oneiron", run=_canary("machines", "run_drain_read")),
        Check("kind-6-logs", "15.2 kind 6", needs=["Q3 #10466"]),
        Check("kind-7-builds", "15.2 kind 7", needs=["F1", "kind 7 parity runs"]),
        Check("kind-8-rented", "15.2 kind 8", needs=["V1"]),
        Check("kind-9-lane-units", "15.2 kind 9", needs=["W2", "the lanes' templates"]),
    )
}
