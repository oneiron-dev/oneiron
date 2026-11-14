#!/usr/bin/env python3
"""Deck creation receipts (deck-create-v1), Office half.

PowerPoint itself measures, per text unit, whether the laid-out text fits the
frame of six decks the docedit emitter writes; the receipts are committed and
a test keeps them bound to the emitter. The engine half (`deck-create-cases`,
crates/oneiron-docedit) writes a run directory: the case manifest's bytes,
each candidate pinned by SHA-256 with the units PowerPoint owes it, and a copy
of this script with its siblings. This script opens every candidate in the
pinned PowerPoint (deck_oracle's custody, staging, environment pin and refusal
rules, under the shared Office lock), measures each unit's fit between `open`
and `pdf`, and writes run.json. docs/ops/deck-gate.md has the commands.

  plan RUN             verify a run directory and say what `office` would open
  office RUN           Mac mini only: open everything serially, then write run.json

Both run from the run directory's pinned copy
(`python3 -B office/deck_create_gate.py ...`), on the Mac mini only, never the
owner's MacBook. These candidates are the emitter's own output, so there is no
isolated account: the one pass opens everything.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import deck_gate  # noqa: E402  (beside this file, in the repo and in a run)
import deck_oracle as oracle_mod  # noqa: E402
import deck_session  # noqa: E402

RUN_SCHEMA = 'oneiron.deck-create-run/1'
OFFICE_SCHEMA = 'oneiron.deck-create-office/1'
CASE_SET = 'deck-create-v1'
LOCK = deck_session.LOCK
UNIT_KINDS = ('text', 'table', 'chart')


def load_run(run: Path) -> dict:
    """The run manifest; a run without a readable one is refused."""
    try:
        manifest = json.loads((run / 'manifest.json').read_text())
    except (OSError, ValueError) as exc:
        print(f'REFUSED: {run} holds no readable manifest.json: {exc}', file=sys.stderr)
        raise SystemExit(2)
    if not isinstance(manifest, dict):
        print(f'REFUSED: {run / "manifest.json"} is not a JSON object', file=sys.stderr)
        raise SystemExit(2)
    return manifest


def _pinned(run: Path, entry: dict, what: str) -> list[str]:
    """The pinned file is present with its bytes; its pin, else."""
    rel = entry.get('path', entry.get('file'))
    if not isinstance(rel, str) or not rel:
        return [f'{what} names no file']
    path = run / rel
    if not path.is_file():
        return [f'{what}: {rel} is missing']
    if path.stat().st_size != entry.get('bytes') or oracle_mod.digest(path) != entry.get('sha256'):
        return [f'{what}: {rel} does not match its pin']
    return []


def _unit(case: str, unit) -> list[str]:
    """One fit unit has the run manifest's keys with the right types."""
    if not isinstance(unit, dict):
        return [f'{case}: a unit is not an object: {unit!r}']
    problems = []
    block = unit.get('block')
    for key in ('slide', 'shape_index', 'shape_id'):
        if not isinstance(unit.get(key), int) or isinstance(unit.get(key), bool):
            problems.append(f'{case}: unit {block!r} {key} is not an integer')
    for key in ('part', 'name', 'block', 'kind'):
        if not isinstance(unit.get(key), str):
            problems.append(f'{case}: unit {block!r} {key} is not a string')
    if unit.get('kind') not in UNIT_KINDS:
        problems.append(f"{case}: unit {block!r} kind {unit.get('kind')!r} is not one of "
                        f'{", ".join(UNIT_KINDS)}')
    planned = unit.get('planned_emu')
    if (not isinstance(planned, list) or len(planned) != 4
            or any(not isinstance(value, int) or isinstance(value, bool) for value in planned)):
        problems.append(f'{case}: unit {block!r} planned_emu is not four integers')
    return problems


def verify(run: Path, manifest: dict) -> list[str]:
    """Every pinned file of the run is present with its bytes; nothing is opened."""
    problems = []
    if manifest.get('schema') != RUN_SCHEMA:
        problems.append(f"schema {manifest.get('schema')!r} is not {RUN_SCHEMA}")
    if manifest.get('case_set') != CASE_SET:
        problems.append(f"case_set {manifest.get('case_set')!r} is not {CASE_SET}")
    case_manifest = manifest.get('case_manifest')
    if not isinstance(case_manifest, dict):
        problems.append('the manifest names no case-manifest pin')
    else:
        problems.extend(_pinned(run, case_manifest, 'case manifest'))
    candidates = manifest.get('candidates')
    if not isinstance(candidates, list):
        problems.append('the manifest names no candidates')
        candidates = []
    ids = []
    for entry in candidates:
        if not isinstance(entry, dict):
            problems.append(f'a candidate entry is not an object: {entry!r}')
            continue
        if not isinstance(entry.get('id'), str) or not entry.get('id'):
            problems.append(f'a candidate has no id: {entry!r}')
        ids.append(entry.get('id'))
        problems.extend(_pinned(run, entry, f"candidate {entry.get('id')!r}"))
        units = entry.get('units')
        if not isinstance(units, list):
            problems.append(f"{entry.get('id')}: units is not a list")
            continue
        for unit in units:
            problems.extend(_unit(entry.get('id'), unit))
    if len(ids) != len(set(ids)):
        problems.append('candidate ids repeat')
    office = manifest.get('office')
    scripts = office.get('scripts') if isinstance(office, dict) else None
    if not isinstance(scripts, list):
        problems.append('the manifest names no office scripts')
    else:
        for script in scripts:
            if not isinstance(script, dict):
                problems.append(f'an office script entry is not an object: {script!r}')
                continue
            problems.extend(_pinned(run, script, f"office script {script.get('path')!r}"))
    return problems


def cmd_plan(args) -> int:
    run = args.run.resolve()
    manifest = load_run(run)
    problems = verify(run, manifest)
    case_manifest = manifest.get('case_manifest') or {}
    print(f"run {run}: case set {manifest.get('case_set')}, source {manifest.get('source')}")
    print(f"case manifest sha256 {case_manifest.get('sha256')} ({case_manifest.get('bytes')} bytes)")
    candidates = manifest.get('candidates')
    if isinstance(candidates, list):
        for entry in candidates:
            if not isinstance(entry, dict):
                continue
            kinds = {}
            units = entry.get('units')
            if isinstance(units, list):
                for unit in units:
                    if isinstance(unit, dict):
                        kinds[unit.get('kind')] = kinds.get(unit.get('kind'), 0) + 1
            by_kind = ' '.join(f'{kind}={kinds.get(kind, 0)}' for kind in UNIT_KINDS)
            print(f"{entry.get('id')} {(entry.get('sha256') or '')[:12]} "
                  f"slides={entry.get('slides')} units {by_kind}")
    refused = manifest.get('refused')
    if isinstance(refused, list):
        for entry in refused:
            if isinstance(entry, dict):
                print(f"refused {entry.get('id')}: {entry.get('reason')}")
    for problem in problems:
        print(f'PROBLEM {problem}')
    return 1 if problems else 0


def write_run_json(run: Path, manifest: dict, results: Path, environment: dict,
                   started: float, finished: float, stopped: str | None):
    """run.json from each receipt.json, read back; the clean and fit totals beside it."""
    candidates = {}
    clean = fits = overflows = inconclusive = 0
    for entry in manifest['candidates']:
        path = results / entry['id'] / 'receipt.json'
        if path.exists():
            receipt = json.loads(path.read_text())
            status = receipt.get('status', 'unsupported')
            detail = receipt.get('detail', '')
            rows = receipt.get('fit')
            rows = rows if isinstance(rows, list) else []
        else:
            status, detail, rows = 'not_run', f'not run: {stopped}' if stopped else 'not run', []
        counted = sum(1 for row in rows if isinstance(row, dict) and row.get('verdict') == 'fits')
        overflowed = sum(1 for row in rows
                         if isinstance(row, dict) and row.get('verdict') == 'overflows')
        candidates[entry['id']] = {'sha256': entry['sha256'], 'status': status, 'detail': detail,
                                   'fits': counted, 'overflows': overflowed,
                                   'inconclusive': len(rows) - counted - overflowed}
        clean += status == 'clean'
        fits += counted
        overflows += overflowed
        inconclusive += len(rows) - counted - overflowed
    (results / 'run.json').write_text(json.dumps(
        {'schema': OFFICE_SCHEMA, 'case_set': manifest['case_set'], 'run': run.name,
         'source': manifest['source'], 'case_manifest_sha256': manifest['case_manifest']['sha256'],
         'seat': socket.gethostname().split('.')[0], 'account_role': environment['font_role'],
         'environment': environment, 'font_inventory_sha256': environment['font_inventory_sha256'],
         'started_at': started, 'finished_at': finished, 'stopped': stopped,
         'candidates': candidates}, indent=2) + '\n')
    return clean, fits, overflows, inconclusive


def cmd_office(args) -> int:
    run = args.run.resolve()
    manifest = load_run(run)
    problems = verify(run, manifest)
    if problems:
        print('REFUSED: the run directory does not match its manifest', file=sys.stderr)
        for problem in problems:
            print(f'  {problem}', file=sys.stderr)
        return 2
    if sys.platform != 'darwin' or not oracle_mod.APP.exists():
        print('REFUSED: PowerPoint for Mac is not installed here; the Office half runs on the Mac mini',
              file=sys.stderr)
        return 2
    office = manifest['office']
    observer = args.observer or office['observer']
    timeout = args.timeout or office['timeout_seconds']
    # The approved pin's locale is empty, as the recorded Mac mini runs were.
    for name in list(os.environ):
        if name == 'LANG' or name.startswith('LC_'):
            del os.environ[name]
    reason = oracle_mod.observer_status(observer)
    environment = oracle_mod.env_pin(observer) if not reason else None
    reason = reason or oracle_mod.environment_mismatch(environment)
    if reason:
        print(f'REFUSED: {reason}', file=sys.stderr)
        return 2
    if oracle_mod.app_pid() and oracle_mod.presentations():
        print('REFUSED: PowerPoint has open presentations; close them first, never ours to close',
              file=sys.stderr)
        return 2
    results = (args.results or run / 'office-results').resolve()
    results.mkdir(parents=True, exist_ok=True)
    account, inventory, rows = oracle_mod.font_inventory()
    (results / 'font-inventory.json').write_text(json.dumps(
        {'font_account': account, 'font_inventory_sha256': inventory, 'rows': list(rows)}, indent=2) + '\n')
    stopped = quit_error = None
    started = time.time()
    custody, dialogs = [0], deck_session.FirstRun()
    # SIGTERM and SIGHUP unwind through the finally below, as SIGINT does.
    previous = {sig: signal.signal(sig, deck_gate._stop) for sig in deck_gate.STOP_SIGNALS}
    try:
        deck_session.take_lock(f'deck-create {manifest.get("source")} {run}')
        already_running = oracle_mod.app_pid() is not None
        try:
            for entry in manifest['candidates']:
                stopped = deck_gate.run_one(
                    run / entry['file'], results / entry['id'], observer, timeout, custody, dialogs,
                    fit=entry['units'],
                    binding={'case_set': manifest['case_set'], 'case': entry['id'],
                             'case_manifest_sha256': manifest['case_manifest']['sha256'],
                             'source': manifest['source']})
                if stopped:
                    break
        finally:
            if not already_running:
                try:
                    oracle_mod.quit_if_empty()
                except (RuntimeError, subprocess.TimeoutExpired) as exc:
                    quit_error = str(exc)
    except deck_gate.Stopped as exc:
        stopped = f'stopped by {exc}'
    finally:
        try:
            lock_error = deck_session.release_lock()
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    if (stopped and stopped.startswith('cleanup')) or quit_error is not None:
        # Never closed here: the next pass refuses while PowerPoint holds a presentation.
        print(f'PowerPoint custody is uncertain ({stopped or quit_error}); check the Mac mini '
              'before the next pass', file=sys.stderr)
    if lock_error:
        print(f'LOCK NOT RELEASED at {LOCK}: {lock_error}; remove it by hand', file=sys.stderr)
    finished = time.time()
    clean, fits, overflows, inconclusive = write_run_json(run, manifest, results, environment,
                                                          started, finished, stopped)
    total = len(manifest['candidates'])
    if stopped:
        print(f'STOPPED: {stopped}', file=sys.stderr)
    print(f'## DECK-CREATE-OFFICE run={run.name} clean={clean}/{total} fits={fits} '
          f'overflows={overflows} inconclusive={inconclusive} results={results}')
    return 0 if total and clean == total else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    plan = sub.add_parser('plan', help='verify a run directory; no Office')
    plan.add_argument('run', type=Path)
    office = sub.add_parser('office', help='Mac mini only: open every candidate serially, then write run.json')
    office.add_argument('run', type=Path)
    office.add_argument('--results', type=Path, help='Office results (default: RUN/office-results)')
    office.add_argument('--observer', choices=('cua', 'system-events'))
    office.add_argument('--timeout', type=int, help='seconds per candidate (default: the run manifest)')
    args = parser.parse_args()
    return {'plan': cmd_plan, 'office': cmd_office}[args.command](args)


if __name__ == '__main__':
    sys.exit(main())
