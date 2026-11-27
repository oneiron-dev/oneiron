"""Machine reads through Oneiron: `mesh-probe`, and the read sides of kinds 3 and 5.

One verb serves all three: `vault.machines.execution.get` (door 11). An
agent's Grant can list it; `vault.machines.status` and `vault.machines.list`
answer the owner only. The issuer asks each job-granted machine itself and
answers what the machine said: whether it is enabled, paused or drained, and
what it offers. A canary passes when every machine of
`canary.target_machines` is listed and its node answered.

- mesh-probe replaces the tool's probes and status (section 13 row 1).
- kind-3-machine-switch reads each machine's enabled and paused state, which
  `fleet status` shows today. Its write side (pause, see the order's blocker,
  resume) changes a machine and is not here.
- kind-5-drain-guard reads each machine's drain as the node and its device
  table report it. Its write side (the clear, door 12) is not here.
"""

from __future__ import annotations

from rack.checks import Context, Outcome
from rack.oneiron_api import ApiError, call

VERB = "vault.machines.execution.get"


def _answers(ctx: Context) -> tuple[dict[str, dict] | None, Outcome | None]:
    """machine id -> its execution view, for every target machine; or the failing outcome."""
    targets = ctx.config.section("canary")["target_machines"]
    if not targets:
        return None, Outcome(False, "no canary.target_machines")
    try:
        reply = call(ctx.config, ctx.host, VERB, {})
    except ApiError as error:
        return None, Outcome(False, str(error))
    listed = {}
    for item in reply.get("machines", []) if isinstance(reply, dict) else []:
        if isinstance(item, dict) and isinstance(item.get("machine"), str):
            listed[item["machine"]] = item
    missing = [m for m in targets if m not in listed]
    ctx.evidence.add("listed_machines", sorted(listed))
    if missing:
        return None, Outcome(False, f"{len(missing)} target machines not listed: {', '.join(missing)}")
    not_answered = {
        m: (listed[m].get("node") or {}).get("state", "absent")
        for m in targets
        if (listed[m].get("node") or {}).get("state") != "answered"
    }
    if not_answered:
        states = ", ".join(f"{m} {state}" for m, state in sorted(not_answered.items()))
        return None, Outcome(False, f"node not answered: {states}")
    return {m: listed[m] for m in targets}, None


def run_mesh_probe(ctx: Context) -> Outcome:
    views, failed = _answers(ctx)
    if failed:
        return failed
    ctx.evidence.add(
        "machines",
        {
            m: {
                "enabled": view["node"]["answer"].get("enabled"),
                "templates": [t.get("name") for t in view["node"]["answer"].get("templates", [])],
                "engine_version": view["node"]["answer"].get("engine_version"),
                "asked_at_ms": view["node"].get("asked_at_ms"),
            }
            for m, view in views.items()
        },
    )
    return Outcome(True)


def run_switch_read(ctx: Context) -> Outcome:
    views, failed = _answers(ctx)
    if failed:
        return failed
    states = {}
    for m, view in views.items():
        answer = view["node"]["answer"]
        if "enabled" not in answer or "paused" not in answer:
            return Outcome(False, f"{m}: the node's answer has no enabled or paused field")
        states[m] = {"enabled": answer["enabled"], "paused": answer["paused"]}
    ctx.evidence.add("switches", states)
    return Outcome(True)


def run_drain_read(ctx: Context) -> Outcome:
    views, failed = _answers(ctx)
    if failed:
        return failed
    drains = {}
    for m, view in views.items():
        answer = view["node"]["answer"]
        if "drained" not in answer:
            return Outcome(False, f"{m}: the node's answer has no drained field")
        availability = view.get("availability") or {}
        devices = (availability.get("answer") or {}) if availability.get("state") == "answered" else {}
        drains[m] = {"node": answer["drained"], "devices": devices.get("drained")}
    ctx.evidence.add("drains", drains)
    return Outcome(True)
