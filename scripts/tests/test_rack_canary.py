"""scripts/rack canaries (pass 34 row K1): mesh-probe, the kind-3 and kind-5 reads, fleet-exec.

`oneiron` is a stand-in that answers each verb from fixtures shaped as the
facade answers at main 14c82900 (the verbs' Rust wire types; the bodies go
bare, a refusal is {"error": {"code": ...}}). Each call is logged, so a test
reads the exact request bodies and the environment the client passed on.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

import pytest

from rack_fixture import HOST, Box

from rack.addresses import Target, local_target, resolve_target
from rack.oneiron_api import PIN_MARK, _write_curl_pin

M1 = "a1" * 16
M2 = "b2" * 16
TEMPLATE_DIGEST = "c3" * 32
WORKLOAD = "d4" * 32
ORDER = "e5" * 16
CHECK_IN = "f6" * 16
SECRET = "s3cret-bearer-value"


def node(state="answered", paused=None, drained=None):
    view = {"state": state, "not_asked": None, "asked_at_ms": 1000, "answer": None, "refusal": None, "error": None}
    if state == "answered":
        view["answer"] = {
            "enabled": True,
            "paused": paused,
            "drained": drained,
            "templates": [{"name": "probe", "digest": TEMPLATE_DIGEST, "scopes": ["host"], "network": ["none"], "returnable": [], "require": []}],
            "scopes": [],
            "disk_free_bytes": 1,
            "disk_reserved_bytes": 0,
            "disk_reserve_bytes": 0,
            "epoch": None,
            "swept": True,
            "boot_id": "boot",
            "engine_version": "test",
        }
    elif state == "refused":
        view["refusal"] = "not_issuer"
    else:
        view["error"] = "no answer"
    return view


def machine(machine_id, **node_args):
    return {
        "machine": machine_id,
        "name": None,
        "this_install": False,
        "job_grant": True,
        "job_status_grant": True,
        "node": node(**node_args),
        "availability": {"state": "not_asked", "not_asked": "cpu_only", "asked_at_ms": None, "answer": None, "refusal": None, "error": None},
        "live_keys": {"state": "answered", "not_asked": None, "asked_at_ms": 1000, "answer": [], "refusal": None, "error": None},
    }


def execution(*machines):
    return {"body": {"machines": list(machines)}}


def view(state, attempts=(), receipt=None):
    return {"order": {"id": ORDER, "state": state, "attempts": list(attempts)}, "replayed": False, "receipt": receipt}


def attempt(end, started=2000):
    return {"n": 1, "job": "0" * 32, "machine": M1, "made_at_ms": 1500, "started_at_ms": started, "end": end}


def exited(code):
    return {"kind": {"kind": "exited", "code": code}, "at_ms": 3000, "after": {}}


RECEIPT = {"attempt": 1, "key": "k-1", "machine": M1, "signed": "c2lnbmVk", "observed_at_ms": 3100}
PIN_WENT = {"body": {"changed": True, "workload": {"digest": WORKLOAD, "standing": "cleared", "pin": {}}}}
ORDER_OPEN = {"body": view({"kind": "open", "blocked": [], "looked_at_ms": 1, "earliest_ms": None})}


def waited(order_view, reached):
    return {"body": {"view": order_view, "reached": reached}}


@pytest.fixture
def box(tmp_path):
    box = Box(tmp_path)
    box.config["issuer"] = {"base_url": "https://198.51.100.7"}
    box.config["canary"] = {
        "target_machines": [M1, M2],
        "exec_machine": M1,
        "offer": "rack-offer",
        "probe": {
            "commit": "1" * 40,
            "contract_path": "contract.json",
            "contract_sha256": "2" * 64,
            "entry": "probes/cpu_one_thread.sh",
            "args": ["--secs", "20"],
        },
        "order_deadline_secs": 60,
        "poll_secs": 0,
    }
    return box


def run(box, check):
    return box.run(HOST, "before", check, env={"ONEIRON_SECRET": SECRET, "SSH_AUTH_SOCK": "/tmp/agent.sock"})


def test_mesh_probe_passes_when_every_target_machine_answered(box):
    box.oneiron({"vault.machines.execution.get": [execution(machine(M1), machine(M2))]})
    done = run(box, "mesh-probe")
    assert done.returncode == 0, done.stderr
    assert done.stdout == f"PASS {HOST} before mesh-probe\n"
    (call,) = box.calls()
    assert call["verb"] == "vault.machines.execution.get"
    assert call["body"] == {}
    assert call["argv"][:3] == ["api", "--base-url", "https://198.51.100.7"]
    assert call["argv"][-4:] == ["call", "vault.machines.execution.get", "--data", "-"]
    assert all(SECRET not in word for word in call["argv"])
    assert set(call["env"]) <= {"PATH", "HOME", "LC_ALL", "ONEIRON_SECRET", "ONEIRON_BINDING_KEY", "TMPDIR"}
    assert "ONEIRON_SECRET" in call["env"] and "TMPDIR" in call["env"]


@pytest.mark.parametrize(
    ("listed", "reason"),
    [
        ([machine(M1)], "1 target machines not listed"),
        ([machine(M1), machine(M2, state="refused")], f"node not answered: {M2} refused"),
        ([machine(M1, state="unknown"), machine(M2)], f"node not answered: {M1} unknown"),
    ],
)
def test_mesh_probe_fails_on_a_missing_or_silent_machine(box, listed, reason):
    box.oneiron({"vault.machines.execution.get": [execution(*listed)]})
    done = run(box, "mesh-probe")
    assert done.returncode == 1
    assert done.stdout == ""
    assert reason in done.stderr


def test_a_refused_call_fails_with_the_facades_code(box):
    box.oneiron(
        {"vault.machines.execution.get": [{"rc": 22, "body": {"error": {"code": "FORBIDDEN", "message": "no grant lists this verb", "requestId": "r", "suggestions": []}}}]}
    )
    done = run(box, "mesh-probe")
    assert done.returncode == 1
    assert "exit 22 FORBIDDEN: no grant lists this verb" in done.stderr


@pytest.mark.parametrize("url", ["http://127.0.0.1:9090", "http://127.1:9090", "http://0x7f.1:9090", "http://[::1]:9090"])
def test_a_loopback_issuer_is_refused_before_any_call(box, url):
    box.config["issuer"] = {"base_url": url}
    box.oneiron({"vault.machines.execution.get": [execution(machine(M1), machine(M2))]})
    done = run(box, "mesh-probe")
    assert done.returncode == 1
    assert "loopback or local address" in done.stderr
    assert box.calls() == []


@pytest.mark.parametrize(
    ("url", "local"),
    [
        ("http://127.1:9090", True),
        ("http://2130706433:9090", True),
        ("http://0.0.0.0:9090", True),
        ("http://[::]:9090", True),
        ("http://[::ffff:127.0.0.1]:9090", True),
        ("http://localhost:9090", True),
        ("https://issuer.localhost", True),
        ("https://198.51.100.7", False),
    ],
)
def test_a_url_is_local_by_the_address_it_connects_to_not_its_spelling(url, local):
    assert local_target(url) is local


def gone(pid: int) -> bool:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    except FileNotFoundError:
        return True
    return fields[0] in ("Z", "X")


def test_an_issuer_that_never_answers_ends_with_its_curl_and_its_staged_body(box):
    box.config["command_timeout_secs"] = 2
    box.oneiron({"vault.machines.execution.get": [{"hang": True, "body": {}}]})
    done = run(box, "mesh-probe")
    assert done.returncode == 1
    assert "no answer in 2 s" in done.stderr
    hang = json.loads((box.out / "oneiron.hang.json").read_text())
    assert not Path(hang["tmpdir"]).exists()
    deadline = time.monotonic() + 5
    while not gone(hang["helper"]) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert gone(hang["helper"])


def test_the_kind_3_and_kind_5_reads_record_the_switch_and_the_drain(box):
    box.oneiron({"vault.machines.execution.get": [execution(machine(M1, paused="owner"), machine(M2, drained="three failures"))]})
    for check in ("kind-3-machine-switch", "kind-5-drain-guard"):
        done = box.run(HOST, "before", check, env={"ONEIRON_RUN_ID_UNUSED": "1", "ONEIRON_SECRET": SECRET})
        assert done.returncode == 0, (check, done.stderr)
    records = {json.loads(p.read_text())["check"]: json.loads(p.read_text()) for p in box.evidence_files()}
    assert records["kind-3-machine-switch"]["switches"][M1] == {"enabled": True, "paused": "owner"}
    assert records["kind-5-drain-guard"]["drains"][M2]["node"] == "three failures"


def exec_answers(wait_answers, pin=PIN_WENT, order=ORDER_OPEN):
    return {
        "vault.machines.execution.get": [execution(machine(M1))],
        "vault.jobs.workloads.pin": [pin],
        "vault.jobs.order": [order],
        "vault.jobs.orders.wait": wait_answers,
    }


DONE_EXIT_0 = waited(view({"kind": "done"}, [attempt(exited(0))], RECEIPT), True)


def test_fleet_exec_orders_the_probe_and_passes_on_a_signed_exit_0(box):
    running = waited(view({"kind": "running", "attempt": 1}, [attempt(None)]), False)
    box.oneiron(exec_answers([running, DONE_EXIT_0]))
    done = run(box, "fleet-exec")
    assert done.returncode == 0, done.stderr
    assert done.stdout == f"PASS {HOST} before fleet-exec\n"
    calls = box.calls()
    assert [c["verb"] for c in calls] == [
        "vault.machines.execution.get",
        "vault.jobs.workloads.pin",
        "vault.jobs.order",
        "vault.jobs.orders.wait",
        "vault.jobs.orders.wait",
    ]
    assert calls[0]["body"] == {"machine": M1}
    pin = calls[1]["body"]["pin"]
    assert pin["template_digest"] == TEMPLATE_DIGEST
    assert pin["request"] == {"cpu_threads": 1, "memory_mib": 512, "disk_mib": 64, "devices": [], "maximum_secs": 300}
    assert (pin["scope"], pin["network"], pin["outputs"]) == ("host", "none", [])
    assert "check_in_ref" not in calls[1]["body"] and "project" not in calls[1]["body"]
    order = calls[2]["body"]
    assert order["workload"] == WORKLOAD
    assert order["charge"] == {"kind": "offer", "name": "rack-offer"}
    assert order["limits"] == {"machines": [M1]}
    assert order["class"] == "interactive"
    assert order["wait"]["kind"] == "until" and order["wait"]["ms"] > 0
    assert order["intent_key"].startswith(f"rack-{HOST}-fleet-exec-")
    assert calls[3]["body"] == {"order": ORDER, "until": "terminal"}


def test_fleet_exec_fails_while_the_pin_waits_for_the_owners_check_in(box):
    waits = {"body": {"error": {"code": "CHECK_IN_PENDING", "message": "asks the owner", "reasonCodes": [f"check_in:{CHECK_IN}"], "pending": {"kind": "check_in", "check_in": CHECK_IN}}}}
    box.oneiron(exec_answers([DONE_EXIT_0], pin=waits))
    done = run(box, "fleet-exec")
    assert done.returncode == 1
    assert f"waits for the owner's check-in {CHECK_IN}" in done.stderr
    assert [c["verb"] for c in box.calls()][-1] == "vault.jobs.workloads.pin"


def test_fleet_exec_names_the_answered_check_in_and_the_project(box):
    box.config["canary"]["probe"].update({"check_in_ref": CHECK_IN, "project": "9a" * 16})
    box.oneiron(exec_answers([DONE_EXIT_0]))
    assert run(box, "fleet-exec").returncode == 0
    pin_body = box.calls()[1]["body"]
    assert pin_body["check_in_ref"] == CHECK_IN and pin_body["project"] == "9a" * 16


@pytest.mark.parametrize(
    ("final", "reason"),
    [
        (view({"kind": "done"}, [attempt(exited(3))], RECEIPT), "the last attempt ended exited 3"),
        (view({"kind": "done"}, [attempt(exited(0))], None), "no signed receipt"),
        (view({"kind": "done"}, [attempt(exited(0), started=None)], RECEIPT), "no start"),
        (
            view({"kind": "given_up", "why": {"kind": "never_fits", "blocked": [{"blocker": {"code": "no_machine"}}]}}),
            "the order ended given_up never_fits (no_machine)",
        ),
        (view({"kind": "cancelled", "why": {"kind": "authority_ended"}}), "the order ended cancelled authority_ended"),
    ],
)
def test_fleet_exec_fails_on_every_end_but_a_signed_exit_0(box, final, reason):
    box.oneiron(exec_answers([waited(final, True)]))
    done = run(box, "fleet-exec")
    assert done.returncode == 1
    assert reason in done.stderr


def test_fleet_exec_fails_when_the_order_does_not_end_in_time(box):
    box.config["canary"].update({"order_deadline_secs": 1, "poll_secs": 1})
    box.config["canary"]["probe"]["maximum_secs"] = 1
    stuck = waited(view({"kind": "open", "blocked": [{"machine": M1, "blocker": {"code": "machine_unreachable", "since_ms": 5}}], "looked_at_ms": 9, "earliest_ms": None}), False)
    box.oneiron(exec_answers([stuck]))
    done = run(box, "fleet-exec")
    assert done.returncode == 1
    assert "did not end in time; it is open (machine_unreachable)" in done.stderr


def test_fleet_exec_fails_when_the_exec_machine_does_not_offer_the_probe(box):
    box.config["canary"]["probe"]["template"] = "not-offered"
    box.oneiron(exec_answers([DONE_EXIT_0]))
    done = run(box, "fleet-exec")
    assert done.returncode == 1
    assert "does not offer the template not-offered" in done.stderr


def test_fleet_exec_fails_on_a_refused_order(box):
    refused = {"rc": 22, "body": {"error": {"code": "INVALID_STATE", "message": "never fits", "reasonCodes": ["never_fits"]}}}
    box.oneiron(exec_answers([DONE_EXIT_0], order=refused))
    done = run(box, "fleet-exec")
    assert done.returncode == 1
    assert "vault.jobs.order: exit 22 INVALID_STATE: never fits" in done.stderr


def test_inbox_append_waits_for_a_bounded_write_verb(box):
    done = run(box, "inbox-append")
    assert done.returncode == 3
    assert done.stderr.startswith(f"WAITS {HOST} before inbox-append: needs a write a Grant can bound")


# A host curl looks up (not an address literal) that resolves with no DNS: 3325256711 is 198.51.100.7.
NAMED_ISSUER = "http://3325256711:9090"


def test_the_issuer_call_is_held_to_the_address_the_check_judged(box):
    box.config["issuer"] = {"base_url": NAMED_ISSUER}
    box.curl()
    box.oneiron({"vault.machines.execution.get": [execution(machine(M1), machine(M2))]}, runs_curl=True)
    done = run(box, "mesh-probe")
    assert done.returncode == 0, done.stderr
    (argv,) = box.curl_calls()
    assert argv[:3] == ["-q", "--resolve", "3325256711:9090:198.51.100.7"]
    assert argv[3:] == ["--silent", "--url", f"{NAMED_ISSUER}/api/verbs/vault.machines.execution.get"]


def test_a_call_that_does_not_go_through_the_harness_curl_fails(box):
    box.config["issuer"] = {"base_url": NAMED_ISSUER}
    box.curl()
    box.oneiron({"vault.machines.execution.get": [execution(machine(M1), machine(M2))]})
    done = run(box, "mesh-probe")
    assert done.returncode == 1
    assert "not held to the checked address" in done.stderr


def test_an_address_literal_issuer_needs_no_pin():
    assert resolve_target("https://198.51.100.7").literal
    named = resolve_target(NAMED_ISSUER)
    assert not named.literal and named.addresses == ("198.51.100.7",) and not named.local


def test_the_resolve_entry_names_every_judged_address_with_v6_in_brackets():
    target = Target("https", "issuer.example", 443, ("2001:db8::7", "198.51.100.7"), False, False, "/")
    assert target.curl_resolve() == "issuer.example:443:[2001:db8::7],198.51.100.7"


def test_the_harness_curl_refuses_a_call_without_q_first(tmp_path):
    real = tmp_path / "real-curl"
    real.write_text("#!/bin/sh\nexit 0\n")
    real.chmod(0o755)
    target = Target("https", "issuer.example", 443, ("198.51.100.7",), False, False, "/")
    bin_dir = _write_curl_pin(tmp_path, str(real), target)
    done = subprocess.run([str(bin_dir / "curl"), "--silent"], capture_output=True, text=True, timeout=30)
    assert done.returncode == 2
    assert "-q first" in done.stderr
    assert not (tmp_path / PIN_MARK).exists()
