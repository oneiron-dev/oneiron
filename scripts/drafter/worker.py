#!/usr/bin/env python3
"""FIX 14974: train one vault's own drafter version for its target, on this host's GPU.

`<python> -I worker.py --request <abs job json> --output <abs new dir>`, run by the engine's
drafter trainer adapter (`crates/oneiron-server/src/ai_host/drafter.rs`), never through a shell.
It checks every pin, renders the job's training examples with the served target's own chat
template and tokenizer, reads the target's hidden taps from the target checkpoint, trains the
DFlash drafter from its parent (the stock drafter or the version it continues) with the recipe's
settings, exports the serving format through the operator's converter, and writes
`receipt.json`. It reads no held-out example, picks no held-out sample, calls no model service or
network, downloads nothing, runs no remote code and sets no binding. README.md is the contract.

Provenance: see `dflash_recipe.py` (DFlash as its authors describe it, the EAGLE-3 tap
convention, and the in-house step-A prototype).
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.metadata
import importlib.util
import json
import math
import os
import platform
import re
import shutil
import sys
import time
import traceback
from pathlib import Path

import blake3
import torch


def _sibling(name: str):
    """A module from beside this file, never from the working directory or sys.path."""
    path = Path(__file__).with_name(f"{name}.py")
    spec = importlib.util.spec_from_file_location(f"drafter_{name}", path)
    module = sys.modules[spec.name] = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


recipe = _sibling("dflash_recipe")
Refusal, Failure, need = recipe.Refusal, recipe.Failure, recipe.need

JOB_FORMAT = "oneiron.drafter.train-job/1"
RECEIPT_FORMAT = "oneiron.drafter.train-receipt/1"
JOB_KEYS = {"format", "version", "spec_blake3", "generation", "admission", "recipe", "target",
            "served_target", "tap_model", "converter", "parent", "training"}
RECIPE_KEYS = {"id", "revision", "settings", "gpu_seconds", "device_memory_mib"}
TARGET_KEYS = {"model", "tokenizer", "runtime"}
TRAINING_KEYS = {"path", "bytes", "blake3", "examples", "form"}
FILE_KEYS = {"name", "bytes", "blake3"}
CODE = ("worker.py", "dflash_recipe.py")
# The worker's lock, held for its whole life: a host that finds it free and no receipt knows the
# job is gone.
LOCK_FILE = "worker.lock"
RECEIPT_FILE = "receipt.json"
LOAD_SET_DIR = "load-set"
WORK_DIR = "work"
NOT_MEASURED = ("held_out_quality", "serving_speed", "token_identity", "cost")
IS_NOT = ("qualification", "activation", "binding", "held-out evaluation")
# The last frames a redacted traceback keeps: file, line and function only.
TRACEBACK_FRAMES = 20
# How much of a file one BLAKE3 update reads.
HASH_CHUNK_BYTES = 1 << 24


def _closed(value: object, keys: set[str], where: str) -> dict:
    need(isinstance(value, dict) and set(value) == keys, f"{where} needs keys {sorted(keys)}")
    return value


def _hex(value: object, width: int, where: str) -> str:
    need(isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{width}}}", value), f"{where}: {width} hex")
    return value


def _count(value: object, where: str) -> int:
    need(type(value) is int and value >= 0, f"{where} must be a nonnegative integer")
    return value


def _absolute(value: object, where: str) -> Path:
    need(isinstance(value, str) and Path(value).is_absolute(), f"{where} must be an absolute path")
    return Path(value)


def file_blake3(path: Path) -> tuple[int, str]:
    hasher, size = blake3.blake3(max_threads=blake3.blake3.AUTO), 0
    with open(path, "rb") as handle:
        while chunk := handle.read(HASH_CHUNK_BYTES):
            hasher.update(chunk)
            size += len(chunk)
    return size, hasher.hexdigest()


def directory_pins(directory: Path) -> dict:
    """Every regular file of `directory`, sorted by name, with its length and BLAKE3, and the
    BLAKE3 of that list's JSON: the pin of a checkpoint the job names by path."""
    need(directory.is_dir(), f"{directory.name} is not a directory")
    files = []
    for path in sorted(directory.iterdir()):
        if path.is_file() and not path.is_symlink():
            size, digest = file_blake3(path)
            files.append({"name": path.name, "bytes": size, "blake3": digest})
    listing = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"files": files, "files_blake3": blake3.blake3(listing).hexdigest()}


def parse_job(data: bytes) -> dict:
    """The request, closed at every level: anything unknown or missing refuses."""
    try:
        job = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise Refusal("the request is not UTF-8 JSON") from None
    _closed(job, JOB_KEYS, "request")
    need(job["format"] == JOB_FORMAT, f"request.format must be {JOB_FORMAT}")
    _hex(job["version"], 32, "request.version")
    _hex(job["spec_blake3"], 64, "request.spec_blake3")
    _count(job["generation"], "request.generation")
    need(isinstance(job["admission"], str) and job["admission"], "request.admission: nonempty")
    spec = _closed(job["recipe"], RECIPE_KEYS, "recipe")
    need(spec["id"] == recipe.FAMILY, f"recipe.id must be {recipe.FAMILY}")
    revision = _closed(spec["revision"], {"repository", "revision"}, "recipe.revision")
    need(revision["revision"] not in ("main", "master", "latest", "HEAD"), "recipe.revision moves")
    recipe.parse_settings(spec["settings"])
    target = _closed(job["target"], TARGET_KEYS, "target")
    need(target["runtime"] == recipe.RUNTIME, f"this recipe exports for {recipe.RUNTIME} only")
    for key in ("served_target", "tap_model", "converter"):
        _absolute(job[key], key)
    parent = job["parent"]
    need(isinstance(parent, dict) and parent.get("kind") in ("stock", "version"), "parent.kind")
    if parent["kind"] == "stock":
        _closed(parent, {"kind", "dir"}, "parent")
    else:
        _closed(parent, {"kind", "version", "dir", "files"}, "parent")
        _hex(parent["version"], 32, "parent.version")
        need(isinstance(parent["files"], list) and parent["files"], "parent.files: nonempty")
        names = {_closed(f, FILE_KEYS, "parent.files[]")["name"] for f in parent["files"]}
        need({recipe.TRAINABLE_CONFIG, recipe.TRAINABLE_WEIGHTS} <= names,
             "the parent version keeps no trainable config and weights")
    _absolute(parent["dir"], "parent.dir")
    training = _closed(job["training"], TRAINING_KEYS, "training")
    _absolute(training["path"], "training.path")
    _count(training["bytes"], "training.bytes")
    _count(training["examples"], "training.examples")
    _hex(training["blake3"], 64, "training.blake3")
    need(training["form"] == recipe.CORPUS_FORM, f"training.form must be {recipe.CORPUS_FORM}")
    return job


def parent_pins(parent: dict) -> dict:
    """The parent's pin: the stock directory's files hashed here, or each kept version's
    trainable file checked against the BLAKE3 the job names."""
    directory = Path(parent["dir"])
    if parent["kind"] == "stock":
        return {"kind": "stock"} | directory_pins(directory)
    for pin in parent["files"]:
        size, digest = file_blake3(directory / pin["name"])
        need((size, digest) == (pin["bytes"], pin["blake3"]), "a parent trainable file differs from its pin")
    return {"kind": "version", "version": parent["version"], "files": parent["files"]}


def read_training(training: dict) -> list[dict]:
    """The job's training examples, checked against their pin: one JSON object per line, each
    of the corpus form. Held-out examples never reach this worker."""
    path = Path(training["path"])
    data = path.read_bytes()
    need(len(data) == training["bytes"] and blake3.blake3(data).hexdigest() == training["blake3"],
         "the training examples differ from their pin")
    lines = [line for line in data.split(b"\n") if line.strip()]
    need(len(lines) == training["examples"], "the training examples' count differs from their pin")
    examples = []
    for number, line in enumerate(lines, 1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            raise Refusal(f"training line {number} is not JSON") from None
        need(isinstance(value, dict) and value.get("form") == recipe.CORPUS_FORM,
             f"training line {number} is not of the corpus form")
        examples.append(value)
    need(examples, "the job holds no training example")
    return examples


def environment() -> dict:
    """This run's interpreter, packages and device; no CUDA device refuses the job."""
    here = Path(__file__).parent
    need(torch.cuda.is_available(), "no CUDA device: this recipe trains on this host's GPU only")
    gpu = torch.cuda.get_device_properties(0)
    record = {"python": platform.python_version(), "torch": torch.__version__,
              "cuda": torch.version.cuda, "device": gpu.name,
              "capability": f"{gpu.major}.{gpu.minor}", "device_memory_mib": gpu.total_memory // 2**20}
    record["code_sha256"] = {name: hashlib.sha256((here / name).read_bytes()).hexdigest() for name in CODE}
    record["distributions"] = sorted(f"{d.metadata['Name']}=={d.version}"
                                     for d in importlib.metadata.distributions())
    driver = Path("/proc/driver/nvidia/version")
    if driver.is_file():
        record["nvidia_driver"] = driver.read_text().splitlines()[0]
    return record


def _write_new(path: Path, data: bytes) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
        handle.write(data)


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _plain(value: object) -> object:
    """JSON values only: a non-finite float becomes its name, so the receipt still parses."""
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return str(value) if isinstance(value, float) and not math.isfinite(value) else value


def prepare_examples(job: dict, served, tap, work: Path, settings: dict, shape, receipt: dict) -> list:
    """Renders each training example, reads its taps once and keeps them on disk under `work`:
    for each span, the taps of the positions its blocks may see."""
    examples, skipped, tokens, generated = [], {}, 0, 0
    window = settings["context_window"] if settings["context_window"] is not None else shape.window
    taps_dir = work / "taps"
    taps_dir.mkdir(mode=0o700)
    for line in read_training(job["training"]):
        rendered = recipe.render_example(served, line)
        if isinstance(rendered, str):
            skipped[rendered] = skipped.get(rendered, 0) + 1
            continue
        ids, start, end = rendered
        taps_from = 0 if window is None else max(0, start - window)
        taps = recipe.extract_taps(tap, ids, taps_from, end - 1)
        path = taps_dir / f"{len(examples)}.pt"
        torch.save(taps, path)
        examples.append(recipe.Example(torch.tensor(ids, dtype=torch.long), start, end, taps_from, path))
        tokens, generated = tokens + len(ids), generated + end - start
    receipt["corpus"] = {"examples": job["training"]["examples"], "used": len(examples),
                         "skipped": skipped, "sequence_tokens": tokens, "generated_tokens": generated,
                         "render": recipe.RENDER, "held_out_read": False}
    if not examples:
        raise Failure("no training example rendered as the served target renders it")
    return examples


def run(job: dict, out: Path, receipt: dict, marks: dict) -> list[dict]:
    """The job: pins, examples, taps, training, export. Returns the load set's files."""
    settings = job["recipe"]["settings"]
    served = recipe.load_served_target(Path(job["served_target"]), job["target"]["tokenizer"])
    receipt["pins"] = {"served_target": served.record, "parent": parent_pins(job["parent"])}
    config, tensors = recipe.read_parent(job["parent"])
    shape = recipe.drafter_shape(config)
    receipt["pins"]["tap_model"] = directory_pins(Path(job["tap_model"]))
    converter = Path(job["converter"])
    need(converter.is_file(), "the serving-format converter is not a file")
    size, digest = file_blake3(converter)
    receipt["pins"]["converter"] = {"name": converter.name, "bytes": size, "blake3": digest}
    torch.manual_seed(settings["seed"])
    work = out / WORK_DIR
    work.mkdir(mode=0o700)
    device = torch.device("cuda", 0)
    marks["gpu_start"] = time.monotonic()
    tap = recipe.load_tap_model(Path(job["tap_model"]), shape.tap_layers,
                                served.tokenizer.get_vocab_size(), settings)
    receipt["pins"]["tap_model"] |= tap.record
    examples = prepare_examples(job, served, tap, work, settings, shape, receipt)
    embed, lm_head = tap.embed, tap.lm_head
    del tap
    torch.cuda.empty_cache()
    marks["taps"] = time.monotonic()
    model, prefix = recipe.load_drafter(config, tensors, device)
    del tensors
    trainer = recipe.Trainer(model, embed, lm_head, settings, device)
    receipt["training"] = trainer.train(examples)
    receipt["training"]["peak_device_memory_mib"] = torch.cuda.max_memory_allocated() // 2**20
    marks["trained"] = time.monotonic()
    trained = recipe.trained_tensors(model, prefix)
    del trainer, model
    torch.cuda.empty_cache()
    trained_dir, serving_dir, scratch = work / "trained", work / "serving", work / "convert"
    recipe.converter_input(trained_dir, config, trained, served)
    serving_dir.mkdir(mode=0o700)
    scratch.mkdir(mode=0o700)
    served_files = recipe.export(converter, trained_dir, serving_dir, scratch, settings["export_args"],
                                 work / "convert.log")
    marks["exported"] = time.monotonic()
    load_set = out / LOAD_SET_DIR
    load_set.mkdir(mode=0o700)
    rows = []
    for path in served_files:
        need(not path.name.startswith(recipe.TRAINABLE_PREFIX), "the converter wrote a trainable-state name")
        shutil.copyfile(path, load_set / path.name)
        rows.append(("serving", load_set / path.name))
    (load_set / recipe.TRAINABLE_CONFIG).write_text(json.dumps(config, indent=2, sort_keys=True),
                                                     encoding="utf-8")
    shutil.copyfile(trained_dir / "model.safetensors", load_set / recipe.TRAINABLE_WEIGHTS)
    rows += [("trainable", load_set / recipe.TRAINABLE_CONFIG), ("trainable", load_set / recipe.TRAINABLE_WEIGHTS)]
    files = []
    for role, path in rows:
        os.chmod(path, 0o600)
        size, digest = file_blake3(path)
        files.append({"name": path.name, "bytes": size, "blake3": digest, "role": role})
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="FIX 14974: one vault drafter version.")
    parser.add_argument("--request", type=Path, required=True, help="absolute job JSON path")
    parser.add_argument("--output", type=Path, required=True, help="absolute new directory")
    args = parser.parse_args(argv)
    out = args.output
    if not (args.request.is_absolute() and out.is_absolute()) or out.exists() and (
        not out.is_dir() or any(out.iterdir())
    ):
        parser.error("--request and --output must be absolute; --output new or empty")
    out.mkdir(mode=0o700, exist_ok=True)
    out.chmod(0o700)
    lock = os.open(out / LOCK_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX)
    receipt: dict = {"format": RECEIPT_FORMAT, "not_measured": NOT_MEASURED, "is_not": IS_NOT}
    clock, marks = time.monotonic(), {}
    try:
        receipt["environment"] = environment()
        request = args.request.read_bytes()
        job = parse_job(request)
        for key in ("version", "spec_blake3", "generation", "admission", "recipe", "target"):
            receipt[key] = job[key]
        receipt["request"] = {"blake3": blake3.blake3(request).hexdigest(), "bytes": len(request)}
        files = run(job, out, receipt, marks)
        receipt["output"] = {"runtime": recipe.RUNTIME, "dir": LOAD_SET_DIR, "files": files}
        status = "trained"
    except Refusal as error:
        status, receipt["reason"] = "refused", str(error)
    except Failure as error:
        status, receipt["reason"] = "failed", str(error)
    except Exception as error:  # noqa: BLE001 - class and frames only: a message may quote input
        status, receipt["reason"] = "failed", f"unexpected {type(error).__name__}"
        frames = traceback.extract_tb(error.__traceback__)
        receipt["traceback"] = [
            {"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
            for frame in frames[-TRACEBACK_FRAMES:]
        ]
    marks["end"] = time.monotonic()
    if "gpu_start" in marks:
        seconds = math.ceil(marks["end"] - marks["gpu_start"])
        receipt["service_units"] = {"unit": "gpu_wall_second", "quantity": seconds}
    receipt["status"] = status
    receipt["elapsed_seconds"] = {name: round(at - clock, 3) for name, at in marks.items()}
    # The scratch (rendered taps, the trained HF copy, the converter's scratch) goes now; the
    # host removes the whole job directory once it has read the receipt and sealed the load set.
    shutil.rmtree(out / WORK_DIR, ignore_errors=True)
    # Written beside its name and renamed in: a reader sees the whole receipt or none.
    staging = out / (RECEIPT_FILE + ".part")
    _write_new(staging, _json_bytes(_plain(receipt)))
    os.replace(staging, out / RECEIPT_FILE)
    print(json.dumps({"status": status, "receipt": str(out / RECEIPT_FILE)}))
    return {"trained": 0, "refused": 2}.get(status, 1)


if __name__ == "__main__":
    sys.exit(main())
