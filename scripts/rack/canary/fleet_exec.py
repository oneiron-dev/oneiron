"""fleet-exec: one pinned probe job ordered, placed, run and ended through Oneiron alone.

It replaces the tool's job launch with a caller's argument vector and its
detached follow (pass 34 section 13 row 2; 15.5's probe example):

1. `vault.machines.execution.get` for `canary.exec_machine`: the probe
   template's digest as that machine offers it.
2. `vault.jobs.workloads.pin`: the probe at the configured commit, one
   thread, no network, no device. A pin that waits for the owner's
   check-in fails here with the check-in's id; once the owner has answered,
   `canary.probe.check_in_ref` names it and the pin goes.
3. `vault.jobs.order`: class interactive, limited to the exec machine,
   charged to `canary.offer`, waiting at most `canary.order_deadline_secs`
   to be placed, keyed by the run (a second run makes its own order).
4. `vault.jobs.orders.wait` until terminal, asked every `canary.poll_secs`
   (over HTTP the call answers at once and never parks).

It passes when the order is done, its last attempt ran on the exec machine,
started, and exited 0, and the order holds that attempt's signed receipt.
Following the job's log by offset rides row Q3 (#10466).

The Grant it calls with lists vault.machines.execution.get,
vault.jobs.workloads.pin, vault.jobs.order, vault.jobs.orders.wait and
vault.gpu.jobs.start (an offer's order needs it), with the owner's per-job
maximum.
"""

from __future__ import annotations

import time

from rack.checks import Context, Outcome
from rack.oneiron_api import ApiError, call

GOING_STANDINGS = ("pinned", "cleared", "approved")


class Failed(Exception):
    """A step that did not pass; its message is the reason."""


def _offered_digest(ctx: Context, machine: str, template: str) -> str:
    reply = call(ctx.config, ctx.host, "vault.machines.execution.get", {"machine": machine})
    items = [i for i in reply.get("machines", []) if isinstance(i, dict) and i.get("machine") == machine]
    if not items:
        raise Failed(f"the exec machine {machine} is not listed")
    node = items[0].get("node") or {}
    if node.get("state") != "answered":
        raise Failed(f"the exec machine's node did not answer ({node.get('state', 'absent')})")
    for offer in node["answer"].get("templates", []):
        if offer.get("name") == template:
            return str(offer.get("digest", ""))
    raise Failed(f"the exec machine does not offer the template {template}")


def _pin(ctx: Context, template_digest: str) -> str:
    probe = ctx.config.section("canary")["probe"]
    for key in ("commit", "contract_path", "contract_sha256", "entry"):
        if not probe[key]:
            raise Failed(f"no canary.probe.{key}")
    pin = {
        "template": probe["template"],
        "template_digest": template_digest,
        "commit": probe["commit"],
        "contract_sha256": probe["contract_sha256"],
        "contract_path": probe["contract_path"],
        "entry": probe["entry"],
        "args": probe["args"],
        "request": {
            "cpu_threads": probe["cpu_threads"],
            "memory_mib": probe["memory_mib"],
            "disk_mib": probe["disk_mib"],
            "devices": [],
            "maximum_secs": probe["maximum_secs"],
        },
        "scope": "host",
        "network": "none",
        "outputs": [],
    }
    body: dict = {"pin": pin}
    if probe["project"]:
        body["project"] = probe["project"]
    if probe["check_in_ref"]:
        body["check_in_ref"] = probe["check_in_ref"]
    try:
        change = call(ctx.config, ctx.host, "vault.jobs.workloads.pin", body)
    except ApiError as error:
        if error.code == "CHECK_IN_PENDING":
            pending = error.error.get("pending") or {}
            raise Failed(
                f"the probe pin waits for the owner's check-in {pending.get('check_in', '')}; "
                "name it in canary.probe.check_in_ref once the owner has answered"
            ) from None
        raise
    workload = change.get("workload") or {}
    ctx.evidence.add("pin", {"digest": workload.get("digest"), "standing": workload.get("standing")})
    if workload.get("standing") not in GOING_STANDINGS:
        raise Failed(f"the probe pin stands {workload.get('standing')}")
    return str(workload.get("digest", ""))


def _state_words(order: dict) -> str:
    state = order.get("state") or {}
    kind = state.get("kind", "absent")
    blocked = state.get("blocked") or (state.get("why") or {}).get("blocked") or []
    why = state.get("why") or {}
    words = kind
    if why.get("kind"):
        words += f" {why['kind']}"
        end = why.get("end") or {}
        if end.get("kind"):
            words += f" {end['kind']}"
    codes = [str((b.get("blocker") or {}).get("code")) for b in blocked if isinstance(b, dict)]
    if codes:
        words += f" ({', '.join(codes)})"
    return words


def _judge(view: dict, machine: str) -> None:
    order = view.get("order") or {}
    if (order.get("state") or {}).get("kind") != "done":
        raise Failed(f"the order ended {_state_words(order)}")
    attempts = [a for a in order.get("attempts", []) if isinstance(a, dict)]
    if not attempts:
        raise Failed("the order is done with no attempt")
    last = max(attempts, key=lambda a: a.get("n", 0))
    if last.get("machine") != machine:
        raise Failed(f"the last attempt ran on {last.get('machine')}, not the exec machine")
    if last.get("started_at_ms") is None:
        raise Failed("the last attempt has no start")
    end = (last.get("end") or {}).get("kind") or {}
    if end != {"kind": "exited", "code": 0}:
        code = f" {end['code']}" if "code" in end else ""
        raise Failed(f"the last attempt ended {end.get('kind', 'without an end')}{code}")
    receipt = view.get("receipt") or {}
    if receipt.get("attempt") != last.get("n") or not receipt.get("signed"):
        raise Failed("the order holds no signed receipt for its last attempt")
    if receipt.get("machine") != machine:
        raise Failed("the receipt names another machine")


def run(ctx: Context) -> Outcome:
    canary = ctx.config.section("canary")
    machine = canary["exec_machine"]
    if not machine:
        return Outcome(False, "no canary.exec_machine")
    if not canary["offer"]:
        return Outcome(False, "no canary.offer")
    deadline = canary["order_deadline_secs"]
    poll = canary["poll_secs"]
    try:
        workload = _pin(ctx, _offered_digest(ctx, machine, canary["probe"]["template"]))
        now_ms = int(time.time() * 1000)
        body = {
            "workload": workload,
            "charge": {"kind": "offer", "name": canary["offer"]},
            "limits": {"machines": [machine]},
            "class": "interactive",
            "wait": {"kind": "until", "ms": now_ms + deadline * 1000},
            "intent_key": f"rack-{ctx.host}-fleet-exec-{ctx.run_id}",
        }
        made = call(ctx.config, ctx.host, "vault.jobs.order", body)
        order_id = str((made.get("order") or {}).get("id", ""))
        if not order_id:
            raise Failed("the order answer has no order id")
        ctx.evidence.add("order", order_id)

        end_by = time.monotonic() + deadline + canary["probe"]["maximum_secs"] + 2 * poll
        while True:
            answer = call(
                ctx.config, ctx.host, "vault.jobs.orders.wait", {"order": order_id, "until": "terminal"}
            )
            view = answer.get("view") or {}
            if answer.get("reached"):
                break
            if time.monotonic() >= end_by:
                raise Failed(f"the order did not end in time; it is {_state_words(view.get('order') or {})}")
            time.sleep(poll)
        ctx.evidence.add(
            "attempts",
            [
                {k: a.get(k) for k in ("n", "machine", "started_at_ms", "end")}
                for a in (view.get("order") or {}).get("attempts", [])
                if isinstance(a, dict)
            ],
        )
        ctx.evidence.add("receipt_key", (view.get("receipt") or {}).get("key"))
        _judge(view, machine)
    except Failed as failed:
        return Outcome(False, str(failed))
    except ApiError as error:
        return Outcome(False, str(error))
    return Outcome(True)
