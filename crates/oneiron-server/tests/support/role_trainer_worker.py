"""A tiny pinned role trainer for the served tests (ROLE-TRAINING-RUN, LEARN-TRAIN Q2).

It speaks the role job wire (`oneiron.training-pack.role-job/1` and its receipt, as
scripts/training_pack/README.md gives them) in place of a real role worker. It trains
nothing: no optimisation, no network, no spend, and only the Python standard library.
It reads the staged training rows and the staged starting files, checks each against the
request's pins, and returns two fixed load sets whose weights file records the SHA-256 of
the rows it read, so a test can tell that the actual staged corpus reached it. Its probe
logits are fixed, the same on both sides, unless the plan's settings name an
`export_logit_skew`: that is added to the last export logit while the receipt still states
a largest difference of 0, so a test can tell which difference the engine keeps. Any
failed check writes a refused receipt.

Run as the host runs a worker: `<python> -I role_trainer_worker.py --request <job json>
--output <new dir>`.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

JOB_FORMAT = "oneiron.training-pack.role-job/1"
RECEIPT_FORMAT = "oneiron.training-pack.role-receipt/1"
SERVICE_UNIT = "gpu_wall_second"
WEIGHTS_NAME = "adapter.safetensors"
FIXED_LOGITS = [0.25, -0.25]

# BLAKE3 in hash mode, after the reference implementation
# (github.com/BLAKE3-team/BLAKE3, reference_impl): the engine pins every file by it, and
# this worker may use only the standard library.
_MASK = 0xFFFFFFFF
_BLOCK_LEN = 64
_CHUNK_LEN = 1024
_CHUNK_START = 1 << 0
_CHUNK_END = 1 << 1
_PARENT = 1 << 2
_ROOT = 1 << 3
_IV = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)


def _g(state, a, b, c, d, x, y):
    state[a] = (state[a] + state[b] + x) & _MASK
    state[d] = _rotr(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & _MASK
    state[b] = _rotr(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + y) & _MASK
    state[d] = _rotr(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & _MASK
    state[b] = _rotr(state[b] ^ state[c], 7)


def _rotr(value, bits):
    return ((value >> bits) | (value << (32 - bits))) & _MASK


def _compress(cv, words, counter, block_len, flags):
    state = list(cv) + list(_IV[:4]) + [counter & _MASK, (counter >> 32) & _MASK, block_len, flags]
    m = list(words)
    for round_index in range(7):
        _g(state, 0, 4, 8, 12, m[0], m[1])
        _g(state, 1, 5, 9, 13, m[2], m[3])
        _g(state, 2, 6, 10, 14, m[4], m[5])
        _g(state, 3, 7, 11, 15, m[6], m[7])
        _g(state, 0, 5, 10, 15, m[8], m[9])
        _g(state, 1, 6, 11, 12, m[10], m[11])
        _g(state, 2, 7, 8, 13, m[12], m[13])
        _g(state, 3, 4, 9, 14, m[14], m[15])
        if round_index < 6:
            m = [m[i] for i in _PERMUTATION]
    return [state[i] ^ state[i + 8] for i in range(8)]


def _words(block):
    return struct.unpack("<16I", block.ljust(_BLOCK_LEN, b"\0"))


def _chunk_output(chunk, counter):
    """A chunk's last block, still to compress: (cv, words, counter, len, flags)."""
    cv = _IV
    blocks = [chunk[i : i + _BLOCK_LEN] for i in range(0, len(chunk), _BLOCK_LEN)] or [b""]
    for index, block in enumerate(blocks[:-1]):
        flags = _CHUNK_START if index == 0 else 0
        cv = _compress(cv, _words(block), counter, _BLOCK_LEN, flags)
    last = blocks[-1]
    flags = (_CHUNK_START if len(blocks) == 1 else 0) | _CHUNK_END
    return (cv, _words(last), counter, len(last), flags)


def _parent_output(left, right):
    return (_IV, tuple(left) + tuple(right), 0, _BLOCK_LEN, _PARENT)


def _chaining_value(output):
    cv, words, counter, block_len, flags = output
    return _compress(cv, words, counter, block_len, flags)


def blake3_hex(data: bytes) -> str:
    """BLAKE3 of `data`, 32 bytes, as lowercase hex."""
    chunks = [data[i : i + _CHUNK_LEN] for i in range(0, len(data), _CHUNK_LEN)] or [b""]
    stack = []
    for counter, chunk in enumerate(chunks[:-1]):
        cv = _chaining_value(_chunk_output(chunk, counter))
        total = counter + 1
        while total & 1 == 0:
            cv = _chaining_value(_parent_output(stack.pop(), cv))
            total >>= 1
        stack.append(cv)
    output = _chunk_output(chunks[-1], len(chunks) - 1)
    while stack:
        output = _parent_output(stack.pop(), _chaining_value(output))
    cv, words, counter, block_len, flags = output
    root = _compress(cv, words, counter, block_len, flags | _ROOT)
    return struct.pack("<8I", *root).hex()


def canonical_json(value) -> bytes:
    """`oneiron_model::llm::canonical_json_bytes` for the values hashed here (no floats):
    sorted keys, no whitespace."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def load_set_blake3(model: str, rows: list) -> str:
    """`PinnedCheckpoint::content_hash`: BLAKE3 of canonical [model, files by name], each
    file [name, kind, source, its BLAKE3 as 32 byte values, bytes]."""
    files = [
        [row["name"], row["kind"], row["source"], list(bytes.fromhex(row["blake3"])), row["bytes"]]
        for row in sorted(rows, key=lambda row: row["name"])
    ]
    return blake3_hex(canonical_json([model, files]))


class Refused(Exception):
    """A job this worker does not run: the receipt names why."""


def _need(condition: bool, reason: str):
    if not condition:
        raise Refused(reason)


def _write_file(out: Path, relative: str, kind: str, data: bytes, source: dict) -> dict:
    path = out / relative
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(data)
    return {
        "name": Path(relative).name,
        "kind": kind,
        "source": source,
        "path": relative,
        "blake3": blake3_hex(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }


def train(request_bytes: bytes, out: Path) -> dict:
    job = json.loads(request_bytes)
    _need(job.get("format") == JOB_FORMAT, "not a role job")
    _need(job["target"]["kind"] == "role", "not a role target")
    training = job["training"]
    rows = Path(training["path"]).read_bytes()
    _need(hashlib.sha256(rows).hexdigest() == training["sha256"], "training sha256 differs")
    _need(blake3_hex(rows) == training["blake3"], "training blake3 differs")
    _need(len(rows) == training["bytes"], "training size differs")
    count = sum(1 for line in rows.split(b"\n") if line)
    _need(count == training["rows"] and count > 0, "training row count differs")
    for line in rows.split(b"\n"):
        if line:
            pair = json.loads(line)
            _need("chosen" in pair and "rejected" in pair, "a training row is no pair")

    base = job["base"]
    base_rows = []
    for row in base["files"]:
        data = (Path(base["dir"]) / row["name"]).read_bytes()
        _need(hashlib.sha256(data).hexdigest() == row["sha256"], f"{row['name']} differs")
        base_rows.append({**row, "blake3": blake3_hex(data), "bytes": len(data)})
    base_set = load_set_blake3(base["model"], base_rows)
    _need(base_set == base["load_set_blake3"], "the starting load set differs")

    model = job["target"]["output_model"]
    source = job["harness"]
    weights = (
        f"fixture role adapter\nrecipe {job['recipe']}\n"
        f"training sha256 {training['sha256']}\nbase {base_set}\n"
    ).encode()
    sets = {}
    for side in ("training", "export"):
        row = _write_file(out, f"{side}/{WEIGHTS_NAME}", "weights", weights, source)
        sets[side] = {"model": model, "files": [row], "load_set_blake3": load_set_blake3(model, [row])}
    skew = float(job["settings"].get("export_logit_skew", 0.0))
    export_logits = FIXED_LOGITS[:-1] + [FIXED_LOGITS[-1] + skew]
    probes = [
        {
            "probe_id": probe["id"],
            "input_blake3": blake3_hex(canonical_json(probe["input"])),
            "training_logits": FIXED_LOGITS,
            "export_logits": export_logits,
            "training_argmax": 0,
            "export_argmax": 0,
            "max_logit_difference": 0.0,
        }
        for probe in job["probes"]
    ]
    return {
        "format": RECEIPT_FORMAT,
        "status": "trained",
        "run": job["run"],
        "spec_blake3": job["spec_blake3"],
        "settings": job["settings"],
        "harness": job["harness"],
        "authorization": {"kind": job["compute"]["kind"], "reference": job["compute"]["reference"]},
        "request": {"sha256": hashlib.sha256(request_bytes).hexdigest(), "bytes": len(request_bytes)},
        "recipe": {
            "recipe": job["recipe"],
            "target": {"kind": "role", "role": job["target"]["role"], "output_model": model},
            "base": {"model": base["model"], "load_set_blake3": base_set},
        },
        "training": {"sha256": training["sha256"], "rows": count},
        "load_sets": sets,
        "probes": probes,
        "service_units": {"unit": SERVICE_UNIT, "quantity": 1},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    out = Path(args.output)
    out.mkdir(mode=0o700)
    request_bytes = Path(args.request).read_bytes()
    try:
        receipt = train(request_bytes, out)
    except (Refused, KeyError, ValueError, OSError) as error:
        receipt = {"format": RECEIPT_FORMAT, "status": "refused", "reason": str(error)}
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return 0 if receipt["status"] == "trained" else 1


if __name__ == "__main__":
    sys.exit(main())
