#!/usr/bin/env python3
"""Resume an identity-pinned Excel corpus after verified owned-input timeouts.

This supervisor never changes the driver, its identity, or an existing row.
It does not kill or restart Excel. Foreign or recovered workbook custody refuses
recovery. All Office paths remain those staged by the original driver.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify(args):
    identity = json.loads((args.output / "identity.json").read_text())
    actual = dict(manifest_sha256=sha(args.manifest), script_sha256=sha(args.script),
                  driver_sha256=sha(args.driver))
    if identity != actual:
        raise ValueError("oracle identity changed; use a new output folder")
    entries = [json.loads(line) for line in args.manifest.read_text().splitlines()]
    manifest = {entry["sha256"]: entry for entry in entries}
    if len(entries) != len(manifest):
        raise ValueError("duplicate manifest input")
    rows = [json.loads(line) for line in (args.output / "rows.jsonl").read_text().splitlines()]
    seen = set()
    versions = set()
    for row in rows:
        key = row["sha256"]
        if key in seen or key not in manifest or row["path"] != manifest[key]["path"]:
            raise ValueError("duplicate or non-manifest oracle row")
        seen.add(key)
        if row["status"] == "completed":
            if row.get("calculation") != "calculate full rebuild" or row.get("final_workbooks") != 0:
                raise ValueError("unproved recalculation or custody")
            if sha(args.output / (key + ".xlsx")) != row["output_sha256"]:
                raise ValueError("prior output hash changed")
            versions.add(row["app_version"])
        elif row["status"] not in {"preflight-rejected", "excel-rejected", "timed-out"}:
            raise ValueError("non-recoverable oracle row")
    if len(versions) > 1:
        raise ValueError("Excel version changed within the corpus")
    return identity, manifest, rows


def app_call(script, arguments, runner):
    return runner(["/usr/bin/perl", "-e", "alarm 120; exec @ARGV", "/usr/bin/osascript",
                   str(script), *map(str, arguments)], capture_output=True, text=True, timeout=130)


def activate_existing(args, runner, expected_owner):
    script = getattr(args, "activate_existing", None)
    if script is None:
        return
    pid = args.activate_pid
    if type(pid) is not int or not 0 < pid <= 2147483647:
        raise ValueError("invalid existing Excel PID")
    if (args.lock / "owner").read_text().strip() != expected_owner:
        raise ValueError("Office lock changed before activation")
    command = ["/usr/bin/perl", "-e", "alarm 30; exec @ARGV", "/usr/bin/osascript",
               "-l", "JavaScript", str(script), str(pid)]
    receipt = dict(pid=pid, script_sha256=sha(script), lock_retained=True)
    try:
        result = runner(command, capture_output=True, text=True, timeout=40)
        receipt.update(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)
    except subprocess.TimeoutExpired:
        receipt.update(exit_code=None, stdout="", stderr="activation timed out")
    try:
        activated = json.loads(receipt["stdout"])
    except (ValueError, TypeError):
        activated = {}
    valid = (receipt["exit_code"] == 0 and isinstance(activated, dict)
             and type(activated.get("pid")) is int and activated["pid"] == pid
             and activated.get("bundle") == "com.microsoft.Excel"
             and activated.get("activated") is True)
    receipt["status"] = "activated-existing" if valid else "activation-refused"
    path = args.output / f"activation-{time.time_ns()}.json"
    with path.open("x") as stream:
        stream.write(json.dumps(receipt, indent=2) + "\n")
    if (args.lock / "owner").read_text().strip() != expected_owner:
        raise ValueError("Office lock changed during activation")
    if not valid:
        raise RuntimeError("existing Excel activation failed; preserve custody")
    # Activation is not ownership proof. The next bounded inventory must succeed.


def inventory(args, runner):
    # Inventory is read-only. One extra bounded read can let a busy Excel finish
    # after the input deadline; it never authorizes closing an unidentified book.
    expected_owner = f"W7-C14 real workbook oracle {args.output}"
    for attempt in (1, 2):
        if (args.lock / "owner").read_text().strip() != expected_owner:
            raise ValueError("Office lock changed during recovery")
        try:
            result = app_call(args.inventory, [], runner)
            if result.returncode == 0:
                if (args.lock / "owner").read_text().strip() != expected_owner:
                    raise ValueError("Office lock changed during recovery")
                break
            exit_code = result.returncode
            timed_out = exit_code in (-14, 142)
            output = dict(stdout=result.stdout, stderr=result.stderr)
        except subprocess.TimeoutExpired as error:
            exit_code = None
            timed_out = True
            output = dict(stdout=error.stdout, stderr=error.stderr)
        failure = dict(status="inventory-timeout" if timed_out else "inventory-error",
                       attempt=attempt, exit_code=exit_code,
                       script_sha256=sha(args.inventory), lock_retained=True,
                       **{key: value.decode(errors="replace") if isinstance(value, bytes)
                          else value or "" for key, value in output.items()})
        path = args.output / f"inventory-failure-{time.time_ns()}.json"
        with path.open("x") as stream:
            stream.write(json.dumps(failure, indent=2) + "\n")
        if not timed_out or attempt == 2:
            raise RuntimeError("Excel inventory failed; preserve custody")
        activate_existing(args, runner, expected_owner)
    lines = result.stdout.strip().splitlines()
    if not lines or not lines[0].isdigit():
        raise ValueError("invalid workbook inventory")
    books = []
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) != 3:
            raise ValueError("invalid workbook identity")
        books.append(tuple(fields))
    if len(books) != int(lines[0]):
        raise ValueError("incomplete workbook inventory")
    return books, result.stdout


def recover(args, runner=subprocess.run):
    identity, manifest, rows = verify(args)
    if not rows or rows[-1]["status"] != "timed-out":
        raise ValueError("only a recorded input timeout can be recovered")
    row = rows[-1]
    owner = f"W7-C14 real workbook oracle {args.output}"
    if (args.lock / "owner").read_text().strip() != owner:
        raise ValueError("Office lock has another owner")
    custody = json.loads((args.output / "custody.json").read_text())
    if custody["owner"] != owner or not custody["lock_retained"]:
        raise ValueError("timeout custody is not retained by this run")
    stage = Path(custody["stage"])
    container = args.container.resolve()
    if stage.is_symlink() or stage.resolve().parent != container:
        raise ValueError("staging folder is outside the owned container root")
    case = stage / row["sha256"]
    if case.is_symlink() or case.resolve().parent != stage.resolve():
        raise ValueError("case folder is outside the owned staging root")
    source_name = Path(manifest[row["sha256"]]["path"]).name
    staged_input = case / source_name
    if staged_input.is_symlink() or sha(staged_input) != row["sha256"]:
        raise ValueError("staged input identity changed")
    books, before = inventory(args, runner)
    if books:
        if len(books) != 1 or books[0][:2] != (source_name, str(case)):
            raise ValueError("foreign or recovered workbook is present; preserve custody")
        closed = app_call(args.close_owned, [source_name, case], runner)
        if closed.returncode or closed.stdout.strip() != "0":
            raise RuntimeError("owned workbook did not close; preserve custody")
    remaining, after = inventory(args, runner)
    if remaining:
        raise ValueError("workbook appeared during recovery; preserve custody")
    if (args.lock / "owner").read_text().strip() != owner:
        raise ValueError("Office lock changed during recovery")
    archive = args.output / ("recovery-" + str(time.time_ns()))
    archive.mkdir()
    for name in ("identity.json", "custody.json"):
        shutil.copyfile(args.output / name, archive / name)
    (archive / "inventory-before.txt").write_text(before)
    (archive / "inventory-after.txt").write_text(after)
    receipt = dict(status="custody-restored", timeout_row_preserved=row,
                   final_workbooks=0, foreign_workbooks_touched=False,
                   identity_unchanged=identity, supervisor_sha256=sha(Path(__file__)),
                   completed_rows_reused=sum(r["status"] == "completed" for r in rows),
                   owned_workbook_closed_without_saving=bool(books))
    (archive / "receipt.json").write_text(json.dumps(receipt, indent=2))
    shutil.rmtree(stage)
    (args.lock / "owner").unlink()
    args.lock.rmdir()
    return len(rows)


def run(args):
    if sys.platform != "darwin":
        raise RuntimeError("Excel must run on the MacBook")
    last_count = -1
    while True:
        if not (args.output / "identity.json").exists():
            if args.lock.exists():
                raise ValueError("Office is already owned; do not start another session")
            if args.output.exists() and any(args.output.iterdir()):
                raise ValueError("unrecognized output folder; preserve its contents")
        else:
            identity, manifest, rows = verify(args)
            if args.lock.exists():
                if len(rows) <= last_count:
                    raise RuntimeError("oracle made no progress; preserve custody")
                last_count = recover(args)
        command = [sys.executable, str(args.driver), "--corpus", str(args.corpus),
                   "--manifest", str(args.manifest), "--output", str(args.output),
                   "--script", str(args.script), "--lock", str(args.lock)]
        result = subprocess.run(command)
        identity, manifest, rows = verify(args)
        if result.returncode == 0:
            custody = json.loads((args.output / "custody.json").read_text())
            if len(rows) != len(manifest) or custody["lock_retained"]:
                raise RuntimeError("incomplete corpus or custody")
            return
        if not args.lock.exists() or len(rows) <= last_count:
            raise RuntimeError("driver failed without a recoverable timeout")
        # The next iteration re-proves hashes, ownership and real workbook identities.


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("driver", "corpus", "manifest", "output", "script", "lock", "inventory", "close-owned", "container"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--activate-existing", type=Path,
                        help="Optional bounded JXA activation of an already-running Excel PID")
    parser.add_argument("--activate-pid", type=int)
    args = parser.parse_args()
    if (args.activate_existing is None) != (args.activate_pid is None):
        parser.error("--activate-existing and --activate-pid must be supplied together")
    run(args)
