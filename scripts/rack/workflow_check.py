#!/usr/bin/env -S python3 -I
"""The rack harness's one entry (pass 34 row K1), in the rack audit's check contract.

    workflow_check.py [--config FILE] HOST PHASE CHECK
    workflow_check.py [--config FILE] --list
    workflow_check.py [--config FILE] --export-client-keys HOST

HOST PHASE CHECK runs one check on this box and answers in the contract of
the audit's approved workflow checks (lane-hosts-keys PLAN.md:106-120):
exactly `PASS HOST PHASE CHECK` on stdout and exit 0 only when the check
passed. Otherwise nothing goes to stdout and one line goes to stderr:

    exit 1  FAIL HOST PHASE CHECK: <reason>
    exit 3  WAITS HOST PHASE CHECK: needs <rows>   (its rows are not merged)
    exit 2  a usage, configuration or evidence error

HOST must name this box (its hostname is one of the host's `box_names`), so
one box never answers for another. Each run writes its private, redacted
evidence before it answers; without evidence there is no PASS. The run id is
$ONEIRON_RACK_RUN_ID when set, else the time and the process id.

--list prints each check, built or waiting, the rows it needs and what it
proves. --export-client-keys writes this box's client key fingerprints for
the key readback's rack list (see readback/keys.py).

The configuration is --config, else $ONEIRON_RACK_CONFIG, else
~/.config/oneiron-rack/rack.json. The file is executable, as the audit calls
it by its absolute path; its first line runs it as `python3 -I`, so no
PYTHON* variable or user site directory loads code into it.
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import sys
import time
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent.parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from rack.checks import CHECKS, Context, Outcome  # noqa: E402
from rack.evidence import Evidence, EvidenceError, redact  # noqa: E402
from rack.rack_config import PHASES, ConfigError, RackConfig  # noqa: E402

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_WAITS = 3

RUN_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class UsageError(Exception):
    """A request the harness does not answer; exit 2."""


def config_path(named: str | None) -> Path:
    if named:
        return Path(named)
    if os.environ.get("ONEIRON_RACK_CONFIG"):
        return Path(os.environ["ONEIRON_RACK_CONFIG"])
    return Path.home() / ".config" / "oneiron-rack" / "rack.json"


def run_id() -> str:
    named = os.environ.get("ONEIRON_RACK_RUN_ID", "")
    if named:
        if not RUN_ID.match(named):
            raise UsageError("ONEIRON_RACK_RUN_ID must be 1-64 of A-Z a-z 0-9 . _ -")
        return named
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"-{os.getpid()}"


def this_box() -> str:
    return socket.gethostname().split(".", 1)[0]


def require_box(config: RackConfig, host: str) -> None:
    if host not in config.hosts():
        raise UsageError(f"unknown host {host!r}")
    box = this_box()
    if box not in config.box_names(host):
        raise UsageError(f"this box is not {host}")


def list_checks() -> int:
    for check in CHECKS.values():
        state = "built" if check.run else "waits"
        needs = ", ".join(check.needs) if check.needs else "-"
        print(f"{check.name}\t{state}\t{needs}\t{check.proves}")
    return EXIT_PASS


def export_keys(config: RackConfig, host: str) -> int:
    from rack.readback.keys import export_client_keys

    require_box(config, host)
    target = export_client_keys(config.section("keys"), host, config.evidence_root() / "client-keys")
    count = sum(1 for _ in target.open(encoding="utf-8"))
    print(f"wrote {count} client key fingerprints for {host}", file=sys.stderr)
    return EXIT_PASS


def run_check(config: RackConfig, host: str, phase: str, name: str) -> int:
    if phase not in PHASES:
        raise UsageError(f"unknown phase {phase!r}")
    check = CHECKS.get(name)
    if check is None:
        raise UsageError(f"unknown check {name!r}")
    require_box(config, host)
    evidence = Evidence(config.evidence_root(), run_id(), host, phase, name)
    label = f"{host} {phase} {name}"

    if check.run is None:
        reason = "needs " + ", ".join(check.needs)
        evidence.write("waits", reason)
        print(f"WAITS {label}: {redact(reason)}", file=sys.stderr)
        return EXIT_WAITS

    ctx = Context(config=config, host=host, phase=phase, run_id=evidence.run_id, evidence=evidence)
    try:
        outcome = check.run(ctx)
    except Exception as error:  # A check that broke is a FAIL, never a PASS.
        outcome = Outcome(False, f"the check broke: {type(error).__name__}: {error}")
    if not isinstance(outcome, Outcome):
        outcome = Outcome(False, "the check gave no outcome")

    evidence.write("pass" if outcome.passed else "fail", outcome.reason)
    if outcome.passed:
        print(f"PASS {label}")
        return EXIT_PASS
    print(f"FAIL {label}: {redact(outcome.reason) or 'no reason given'}", file=sys.stderr)
    return EXIT_FAIL


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="workflow_check.py", add_help=True)
    parser.add_argument("--config")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--export-client-keys", metavar="HOST")
    parser.add_argument("words", nargs="*")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return EXIT_USAGE
    try:
        if args.list:
            if args.words or args.export_client_keys:
                raise UsageError("--list takes no other argument")
            return list_checks()
        config = RackConfig.load(config_path(args.config))
        if args.export_client_keys:
            if args.words:
                raise UsageError("--export-client-keys takes no other argument")
            return export_keys(config, args.export_client_keys)
        if len(args.words) != 3:
            raise UsageError("give HOST PHASE CHECK")
        host, phase, name = args.words
        return run_check(config, host, phase, name)
    except (UsageError, ConfigError, EvidenceError, OSError) as error:
        print(f"workflow_check: {redact(str(error))}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
