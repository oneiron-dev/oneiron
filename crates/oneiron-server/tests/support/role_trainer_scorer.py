"""A tiny pinned role scorer for the served tests (ROLE-TRAINING-RUN, RULING
TRAIN-ROLE-EVALUATOR = A).

It speaks the role score wire (`oneiron.training-pack.role-score/1` and its receipt, as
scripts/training_pack/README.md gives them) in place of a real scorer. It loads no model
and claims no model quality: no network, no spend, and only the Python standard library.
It reads the staged checkpoint files and the splits, checks each against the request's
pins, and writes one margin per pair, (len(chosen) - len(rejected)) / 8 over the pair's
texts, so a test can recompute every margin from the split it holds. The host computes
every measurement from those margins. A split arrives on stdin, held-out first, framed by
its `bytes`; a request whose split names a `path` (an older host's staged file) is read
from that file instead, so a red run of the new tests reaches the old host's behaviour.

The plan setting `fixture_scorer_fault` picks one fault:
- `drop_held_out_margin` leaves the last held-out pair without a margin, so a test can
  watch the host refuse a short receipt;
- `copy_held_out_rows` copies every held-out row into its error stream, into
  `output/rows.jsonl` and into an extra receipt field, so a test can watch the host keep
  none of them;
- `probe_jobs_root` searches every file under the trainers' jobs root (the parent of its
  score directory) for a held-out row while it runs, and refuses if one holds it.
Any failed check writes a refused receipt.

Run as the host runs a scorer: `<python> -I role_trainer_scorer.py --request <score
json> --output <new dir>`.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

JOB_FORMAT = "oneiron.training-pack.role-score/1"
RECEIPT_FORMAT = "oneiron.training-pack.role-score-receipt/1"
PAIR_FORMAT = "oneiron.reservoir-pair/1"
DROP_HELD_OUT_MARGIN = "drop_held_out_margin"
COPY_HELD_OUT_ROWS = "copy_held_out_rows"
PROBE_JOBS_ROOT = "probe_jobs_root"


class Refused(Exception):
    pass


def _need(condition: bool, reason: str):
    if not condition:
        raise Refused(reason)


def _text(value) -> str:
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True)


def split_bytes(split: dict) -> bytes:
    """A split's bytes: its staged file when the request names one, else exactly its
    `bytes` from stdin."""
    if "path" in split:
        return Path(split["path"]).read_bytes()
    wanted = split["bytes"]
    data = b""
    while len(data) < wanted:
        chunk = sys.stdin.buffer.read(wanted - len(data))
        _need(bool(chunk), "stdin ended inside a split")
        data += chunk
    return data


def lines_of(rows: bytes) -> list:
    return [line for line in rows.split(b"\n") if line]


def margins(split: dict, rows: bytes) -> dict:
    """One margin per pair of a split, in its row order."""
    _need(split["format"] == PAIR_FORMAT, "not a reservoir pair split")
    sha256 = hashlib.sha256(rows).hexdigest()
    _need(sha256 == split["sha256"], "split sha256 differs")
    _need(len(rows) == split["bytes"], "split size differs")
    lines = lines_of(rows)
    _need(len(lines) == split["rows"] and lines, "split row count differs")
    scored = []
    for line in lines:
        pair = json.loads(line)
        _need("chosen" in pair and "rejected" in pair, "a split row is no pair")
        margin = (len(_text(pair["chosen"])) - len(_text(pair["rejected"]))) / 8
        scored.append({"row_sha256": hashlib.sha256(line).hexdigest(), "margin": margin})
    return {"sha256": sha256, "margins": scored}


def holders(root: Path, lines: list) -> list:
    """Every file under `root` whose bytes hold one of `lines`."""
    found = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            data = path.read_bytes()
            if any(line in data for line in lines):
                found.append(str(path))
    return found


def score(request_bytes: bytes, output: Path) -> dict:
    job = json.loads(request_bytes)
    fault = job["settings"].get("fixture_scorer_fault")
    _need(job.get("format") == JOB_FORMAT, "not a role score job")
    _need(job["target"]["kind"] == "role", "not a role target")
    checkpoint = job["checkpoint"]
    files = []
    for row in checkpoint["files"]:
        data = (Path(checkpoint["dir"]) / row["name"]).read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        _need(sha256 == row["sha256"], f"{row['name']} differs")
        files.append({"name": row["name"], "sha256": sha256})

    held_out_bytes = split_bytes(job["held_out"])
    training_bytes = split_bytes(job["training"]) if job.get("training") is not None else None
    held_out_lines = lines_of(held_out_bytes)
    if fault == PROBE_JOBS_ROOT:
        found = holders(output.parent.parent, held_out_lines)
        _need(not found, f"a held-out row sits in {found}")
    held_out = margins(job["held_out"], held_out_bytes)
    if fault == DROP_HELD_OUT_MARGIN:
        held_out["margins"] = held_out["margins"][:-1]
    receipt = {
        "format": RECEIPT_FORMAT,
        "status": "scored",
        "run": job["run"],
        "spec_blake3": job["spec_blake3"],
        "exposure": job["exposure"],
        "request": {"sha256": hashlib.sha256(request_bytes).hexdigest(), "bytes": len(request_bytes)},
        "checkpoint": {"load_set_blake3": checkpoint["load_set_blake3"], "files": files},
        "held_out": held_out,
    }
    if training_bytes is not None:
        receipt["training"] = margins(job["training"], training_bytes)
    if fault == COPY_HELD_OUT_ROWS:
        for line in held_out_lines:
            sys.stderr.buffer.write(line + b"\n")
        sys.stderr.flush()
        (output / "rows.jsonl").write_bytes(b"\n".join(held_out_lines) + b"\n")
        receipt["held_out_rows"] = [line.decode() for line in held_out_lines]
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    out = Path(args.output)
    out.mkdir(mode=0o700)
    request_bytes = Path(args.request).read_bytes()
    try:
        receipt = score(request_bytes, out)
    except (Refused, KeyError, ValueError, OSError) as error:
        receipt = {"format": RECEIPT_FORMAT, "status": "refused", "reason": str(error)}
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return 0 if receipt["status"] == "scored" else 1


if __name__ == "__main__":
    sys.exit(main())
