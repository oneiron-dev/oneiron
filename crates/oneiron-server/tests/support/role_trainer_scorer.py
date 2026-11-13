"""A tiny pinned role scorer for the served tests (ROLE-TRAINING-RUN, RULING
TRAIN-ROLE-EVALUATOR = A).

It speaks the role score wire (`oneiron.training-pack.role-score/1` and its receipt, as
scripts/training_pack/README.md gives them) in place of a real scorer. It loads no model
and claims no model quality: no network, no spend, and only the Python standard library.
It reads the staged checkpoint files and split files, checks each against the request's
pins, and writes one margin per pair, (len(chosen) - len(rejected)) / 8 over the pair's
texts, so a test can recompute every margin from the split it holds. The host computes
every measurement from those margins.

The plan setting `fixture_scorer_fault = "drop_held_out_margin"` leaves the last
held-out pair without a margin, so a test can watch the host refuse a short receipt.
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


class Refused(Exception):
    pass


def _need(condition: bool, reason: str):
    if not condition:
        raise Refused(reason)


def _text(value) -> str:
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True)


def margins(split: dict) -> dict:
    """One margin per pair of a staged split, in its row order."""
    _need(split["format"] == PAIR_FORMAT, "not a reservoir pair split")
    rows = Path(split["path"]).read_bytes()
    sha256 = hashlib.sha256(rows).hexdigest()
    _need(sha256 == split["sha256"], "split sha256 differs")
    _need(len(rows) == split["bytes"], "split size differs")
    lines = [line for line in rows.split(b"\n") if line]
    _need(len(lines) == split["rows"] and lines, "split row count differs")
    scored = []
    for line in lines:
        pair = json.loads(line)
        _need("chosen" in pair and "rejected" in pair, "a split row is no pair")
        margin = (len(_text(pair["chosen"])) - len(_text(pair["rejected"]))) / 8
        scored.append({"row_sha256": hashlib.sha256(line).hexdigest(), "margin": margin})
    return {"sha256": sha256, "margins": scored}


def score(request_bytes: bytes) -> dict:
    job = json.loads(request_bytes)
    _need(job.get("format") == JOB_FORMAT, "not a role score job")
    _need(job["target"]["kind"] == "role", "not a role target")
    checkpoint = job["checkpoint"]
    files = []
    for row in checkpoint["files"]:
        data = (Path(checkpoint["dir"]) / row["name"]).read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        _need(sha256 == row["sha256"], f"{row['name']} differs")
        files.append({"name": row["name"], "sha256": sha256})

    held_out = margins(job["held_out"])
    if job["settings"].get("fixture_scorer_fault") == DROP_HELD_OUT_MARGIN:
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
    if job.get("training") is not None:
        receipt["training"] = margins(job["training"])
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
        receipt = score(request_bytes)
    except (Refused, KeyError, ValueError, OSError) as error:
        receipt = {"format": RECEIPT_FORMAT, "status": "refused", "reason": str(error)}
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return 0 if receipt["status"] == "scored" else 1


if __name__ == "__main__":
    sys.exit(main())
