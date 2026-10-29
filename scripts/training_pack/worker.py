#!/usr/bin/env python3
"""FIX 7263 (OF-418 L1): train one question-scoped binary head on the frozen Oneironer encoder.

`worker.py --request <abs job json> --output <abs new dir>` verifies every pin, trains a new
two-logit head on the frozen encoder's pooled states of consented per-target rows, exports
both load sets, reloads the export to measure fixed probes and writes receipt.json. It calls
no model service, teacher or network, uploads or installs nothing, and its receipt is not a
held-out result, a TrainingRun, a swap or serving readiness. README.md is the contract.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import math
import os
import platform
import re
import sys
import time
import traceback
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

import blake3
import safetensors.torch
import torch
import torch.nn.functional as F


def _sibling(name: str):
    """encoder.py from beside this file, never from the working directory or sys.path."""
    path = Path(__file__).with_name(f"{name}.py")
    spec = importlib.util.spec_from_file_location(f"training_pack_{name}", path)
    module = sys.modules[spec.name] = importlib.util.module_from_spec(spec)  # dataclasses
    spec.loader.exec_module(module)
    return module


encoder = _sibling("encoder")
Refusal, FilePin = encoder.Refusal, encoder.FilePin

JOB_FORMAT, ROW_FORMAT = "oneiron.training-pack.job/1", "oneiron.detector-target-row/1"
RECEIPT_FORMAT = "oneiron.training-pack.receipt/1"
RECIPE_FORMAT, CLASSIFIER_FORMAT = "oneiron.question-head-recipe/1", "oneiron.question-classifier/1"
RECIPE, RENDERER = "oneiron.frozen-encoder-binary-head/1", "oneiron.detector-target-text/1"
LABEL_SCHEMA, LABEL_ORDER = "oneiron.per-target-binary/1", ("no", "yes")
BETAS, EPS, OBJECTIVE = (0.9, 0.999), 1e-8, "cross_entropy/mean/unweighted"
# (job pin role, load-set name, CheckpointFileKind) of the base files both load sets hold.
BASE_LOAD = (("config", "config.json", "config"), ("tokenizer", "tokenizer.json", "tokenizer"))
BASE_LOAD += (("trunk", "trunk.safetensors", "weights"),)
JOB_KEYS = {"format", "run", "spec_blake3", "compute", "target", "base", "training"}
JOB_KEYS |= {"provenance", "settings", "harness", "probes", "export_logit_tolerance"}
# (setting, integral, positive) of every numeric setting; `recipe` must equal RECIPE.
BOUNDS = (("seed", True, False), ("epochs", True, True), ("batch_size", True, True))
BOUNDS += (("learning_rate", False, True), ("weight_decay", False, False))
SETTINGS = {"recipe"} | {key for key, _, _ in BOUNDS}
ROW_PINS = ("question_id", "question_version", "corpus_revision", "feature_schema", "label_schema")
ROW_KEYS = {"format", "row", "split", "source_family", "consent", "label", "input", *ROW_PINS}
NOT_MEASURED = ("cost", "serving_latency", "calibration", "held_out_quality", "comparison")
IS_NOT = ("HeldOutResult", "TrainingRun", "owner swap", "serving readiness")
CODE, PROVENANCE = ("worker.py", "encoder.py"), {"split_receipt", "consent_receipt"}
MODEL_ID = re.compile(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+@[A-Za-z0-9._-]+")
# The last frames a redacted traceback keeps: file, line and function only.
TRACEBACK_FRAMES = 20


class Failure(Exception):
    """A started run that produced no trained head: the receipt keeps what it measured."""


def canonical_json(value: object) -> bytes:
    """`oneiron_model::llm::canonical_json_bytes`: serde_json, sorted keys, no whitespace,
    ryu floats. The engine's probe-input and load-set hashes are BLAKE3 of these bytes."""
    return _canon(value).encode("utf-8")  # a lone surrogate raises: no JSON form


def _digest(value: object) -> str:
    return blake3.blake3(canonical_json(value)).hexdigest()


def _canon(value: object) -> str:
    if isinstance(value, float):
        return _float_text(value)
    if isinstance(value, list):
        return "[" + ",".join(map(_canon, value)) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(f"{_canon(k)}:{_canon(v)}" for k, v in sorted(value.items())) + "}"
    if type(value) is int:
        _need(-(2**63) <= value < 2**64, "an integer outside i64/u64 has no serde_json form")
    return json.dumps(value, ensure_ascii=False)  # null, true, false, an integer or a string


def _float_text(value: float) -> str:
    """ryu's `format_finite`, as serde_json writes an f64, from Python's shortest digits."""
    _need(math.isfinite(value), "a non-finite number has no JSON form")
    if value == 0:
        return "-0.0" if math.copysign(1.0, value) < 0 else "0.0"
    sign, digits, exponent = Decimal(repr(value)).as_tuple()
    text = "".join(map(str, digits)).rstrip("0")
    exponent += len(digits) - len(text)
    point = len(text) + exponent
    if exponent >= 0 and point <= 16:
        body = text + "0" * exponent + ".0"
    elif 0 < point <= 16:
        body = f"{text[:point]}.{text[point:]}"
    elif -5 < point <= 0:
        body = "0." + "0" * -point + text
    else:
        body = (text if len(text) == 1 else f"{text[0]}.{text[1:]}") + f"e{point - 1}"
    return ("-" if sign else "") + body


def _load_json(data: bytes, where: str) -> object:
    """Strict JSON: UTF-8 and no repeated key. A non-finite number refuses where it is used."""

    def pairs(items: list) -> dict:
        _need(len(dict(items)) == len(items), f"{where} repeats an object key")
        return dict(items)

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Refusal(f"{where} is not UTF-8 JSON ({type(error).__name__})") from None


def _need(condition: object, reason: str) -> None:
    if not condition:
        raise Refusal(reason)


def _closed(value: object, keys: set[str], where: str) -> dict:
    _need(isinstance(value, dict) and set(value) == keys, f"{where} needs keys {sorted(keys)}")
    return value


def _text(value: object, where: str) -> str:
    _need(isinstance(value, str) and value.strip(), f"{where} must be a nonempty string")
    return value


def _number(value: object, where: str, integral: bool, positive: bool) -> float:
    """An integer (or a real) of magnitude below 2^63, positive or nonnegative; never NaN."""
    kinds = (int,) if integral else (int, float)
    ok = type(value) in kinds and abs(value) < 2**63 and (value > 0 if positive else value >= 0)
    _need(ok, f"{where} must be a {'positive' if positive else 'nonnegative'} number")
    return value


def _source(value: object, where: str) -> dict:
    """A SourcePin: a repository and an immutable revision, never a moving branch."""
    pin = _closed(value, {"repository", "revision"}, where)
    _text(pin["repository"], f"{where}.repository")
    revision = _text(pin["revision"], f"{where}.revision")
    _need(revision not in ("main", "master", "latest", "HEAD"), f"{where} must be immutable")
    return pin


def _input(value: object, where: str) -> dict:
    """One model input: the exact target and its declared context, nothing else."""
    body = _closed(value, {"target", "context"}, where)
    _need(body["target"] is not None and isinstance(body["context"], list), f"{where} malformed")
    return body


@dataclass(frozen=True)
class QuestionTarget:
    """The one exact question a head answers, and the model id its checkpoint carries."""

    question_id: str
    question_version: int
    definition: object
    definition_blake3: str
    family: str
    corpus_revision: str
    feature_schema: str
    label_schema: str
    renderer: str
    output_model: str


@dataclass(frozen=True)
class TrainingTarget:
    """The worker format's tagged target, Role or Question; this recipe trains Question only."""

    kind: str
    question: QuestionTarget

    @staticmethod
    def parse(value: object) -> TrainingTarget:
        kind = value.get("kind") if isinstance(value, dict) else None
        _need(kind != "role", "target.kind is role: this recipe trains a question, never a role")
        _need(kind == "question", "target.kind must be question (role is named, and refused)")
        t = _closed(value, {"kind"} | set(QuestionTarget.__dataclass_fields__), "target")
        digest = _digest(t["definition"])
        ok = t["definition"] is not None and t["definition_blake3"] == digest
        _need(ok, "target.definition_blake3 must be BLAKE3 of the canonical definition")
        ok = t["label_schema"] == LABEL_SCHEMA and t["renderer"] == RENDERER
        _need(ok, f"this recipe takes label schema {LABEL_SCHEMA} and renderer {RENDERER}")
        for key in ("question_id", "family", "corpus_revision", "feature_schema"):
            _text(t[key], f"target.{key}")
        _number(t["question_version"], "target.question_version", True, False)
        model = t["output_model"]
        _need(isinstance(model, str) and MODEL_ID.fullmatch(model), "target.output_model: id")
        return TrainingTarget("question", QuestionTarget(**{k: t[k] for k in t if k != "kind"}))


@dataclass(frozen=True)
class TrainingJob:
    """A checked request; `body` keeps run, spec and every value verbatim (never recomputed)."""

    body: dict
    target: TrainingTarget
    base_dir: Path
    base_pins: dict
    training_dir: Path
    training_pin: FilePin


def parse_job(data: bytes) -> TrainingJob:
    """The whole request, closed at every level: anything unknown or missing refuses."""
    job = _closed(_load_json(data, "request"), JOB_KEYS, "request")
    _need(job["format"] == JOB_FORMAT, f"request.format must be {JOB_FORMAT}")
    _text(job["run"], "request.run")
    spec = job["spec_blake3"]
    _need(isinstance(spec, str) and re.fullmatch("[0-9a-f]{64}", spec), "spec_blake3: 64 hex")
    compute = _closed(job["compute"], {"kind", "reference"}, "compute")
    _need(compute["kind"] in ("engine_run", "development"), "compute.kind is not a known kind")
    _text(compute["reference"], "compute.reference")
    target = TrainingTarget.parse(job["target"])
    base = _closed(job["base"], {"model", "source", "dir", "files"}, "base")
    _source(base["source"], "base.source")
    _need(isinstance(base["model"], str) and MODEL_ID.fullmatch(base["model"]), "base.model: id")
    _need(base["model"] != target.question.output_model, "output_model must name a new model")
    roles = {"manifest"} | {role for role, _, _ in BASE_LOAD}
    files = _closed(base["files"], roles, "base.files")
    training = _closed(job["training"], {"path", "sha256", "blake3", "bytes"}, "training")
    path, base_dir = Path(_text(training["path"], "path")), Path(_text(base["dir"], "dir"))
    _need(path.is_absolute() and base_dir.is_absolute(), "training.path, base.dir: absolute")
    for key, value in _closed(job["provenance"], PROVENANCE, "provenance").items():
        _text(value, f"provenance.{key}")
    settings = _closed(job["settings"], SETTINGS, "settings")
    _need(settings["recipe"] == RECIPE, f"settings.recipe must be {RECIPE}")
    for key, integral, positive in BOUNDS:
        _number(settings[key], f"settings.{key}", integral, positive)
    _number(job["export_logit_tolerance"], "export_logit_tolerance", False, False)
    _source(job["harness"], "harness")
    probes = job["probes"]
    _need(isinstance(probes, list) and probes, "probes must be a nonempty list")
    for index, probe in enumerate(probes):
        _text(_closed(probe, {"id", "input"}, f"probes[{index}]")["id"], f"probes[{index}].id")
        _input(probe["input"], f"probes[{index}].input")
    _need(len({probe["id"] for probe in probes}) == len(probes), "probe ids must be unique")
    pin = {key: training[key] for key in ("sha256", "blake3", "bytes")} | {"file": path.name}
    pins = {role: FilePin.parse(files[role], f"base.files.{role}") for role in roles}
    return TrainingJob(job, target, base_dir, pins, path.parent, FilePin.parse(pin, "training"))


def render_target(definition: object, value: dict) -> str:
    """`oneiron.detector-target-text/1`: canonical-JSON lines for the question, the target and
    each declared context item. Labels, reviewers, consent and ids never reach the model."""
    lines = ["question: " + _canon(definition), "target: " + _canon(value["target"])]
    return "\n".join(lines + ["context: " + _canon(item) for item in value["context"]])


def read_rows(job: TrainingJob) -> tuple[list[tuple[str, str, int]], dict]:
    """The pinned JSONL as (row id, rendered text, label): consented, adjudicated, per-target
    training-side rows of this exact question, corpus and schema; none sampled or relabeled."""
    q, pin = job.target.question, job.training_pin
    lines = encoder.read_pinned(job.training_dir, pin).split(b"\n")
    rows, families = {}, set()
    for number, line in enumerate(lines[:-1] if lines[-1] == b"" else lines, 1):
        row = _closed(_load_json(line, f"line {number}"), ROW_KEYS, f"training line {number}")
        where = "training row " + _text(row["row"], f"training line {number}.row")
        _need(row["format"] == ROW_FORMAT and row["row"] not in rows, f"{where}: format or id")
        mixed = [k for k in ROW_PINS if (type(row[k]), row[k]) != (type(v := getattr(q, k)), v)]
        _need(not mixed, f"{where} differs from the job's target in {', '.join(mixed)}")
        _need(row["split"] == "training", f"{where} is not on the training side of the split")
        families.add(_text(row["source_family"], f"{where}.source_family"))
        consent = _closed(row["consent"], {"basis", "receipt"}, f"{where}.consent")
        label = _closed(row["label"], {"answer", "unit", "adjudication"}, f"{where}.label")
        for name, value in (*consent.items(), ("adjudication", label["adjudication"])):
            _text(value, f"{where}.{name}")
        _need(label["unit"] == "target", f"{where}: a window label never becomes a target label")
        _need(label["answer"] in LABEL_ORDER, f"{where}.label.answer must be no or yes")
        text = render_target(q.definition, _input(row["input"], f"{where}.input"))
        rows[row["row"]] = (text, LABEL_ORDER.index(label["answer"]))
    counts = {name: sum(y == i for _, y in rows.values()) for i, name in enumerate(LABEL_ORDER)}
    _need(rows and 0 not in counts.values(), f"training needs both classes; it has {counts}")
    corpus = {"training": vars(pin), "rows": len(rows), "labels": counts}
    corpus["families"] = {"count": len(families), "blake3": _digest(sorted(families))}
    corpus |= {"provenance": job.body["provenance"], "split_certified_by_worker": False}
    return [(key, text, label) for key, (text, label) in rows.items()], corpus


def _head_bytes(head: torch.nn.Linear, prefix: str) -> bytes:
    pairs = (("weight", head.weight), ("bias", head.bias))
    tensors = {prefix + name: t.detach().to("cpu", torch.float32).contiguous() for name, t in pairs}
    return safetensors.torch.save(tensors)


def train_head(model, sequences: list, labels: list[int], settings: dict):
    """Pools rows through the frozen encoder (eval, no encoder gradient), then makes real AdamW
    updates on a new Linear(hidden, 2) head; no update or change, or a non-finite loss, fails."""
    model.requires_grad_(False)
    if any(tensor.requires_grad for tensor in model.weights.values()):
        raise Failure("an encoder tensor requires a gradient")
    features = encoder.encode_targets(model, sequences)
    # One-hot targets keep the loss to deterministic CUDA kernels (no nll_loss scatter).
    targets = torch.eye(len(LABEL_ORDER))[torch.tensor(labels)].to(features.device)
    torch.manual_seed(settings["seed"])
    shuffle = torch.Generator().manual_seed(settings["seed"])
    head = torch.nn.Linear(features.shape[1], len(LABEL_ORDER)).to(features.device)
    before = hashlib.sha256(_head_bytes(head, "")).hexdigest()
    adamw = {"lr": settings["learning_rate"], "betas": BETAS, "eps": EPS}
    optimizer = torch.optim.AdamW(head.parameters(), **adamw, weight_decay=settings["weight_decay"])
    steps, trace = 0, []
    for _ in range(settings["epochs"]):
        total = 0.0
        for batch in torch.randperm(len(labels), generator=shuffle).split(settings["batch_size"]):
            batch = batch.to(features.device)
            logits = F.log_softmax(head(features[batch]), dim=-1)
            loss = -(targets[batch] * logits).sum(dim=-1).mean()  # mean cross-entropy
            optimizer.zero_grad(set_to_none=True)
            loss.backward()
            optimizer.step()
            steps, total = steps + 1, total + loss.item() * len(batch)
        trace.append(total / len(labels))
    after = hashlib.sha256(_head_bytes(head, "")).hexdigest()
    finite = all(map(math.isfinite, trace)) and all(p.isfinite().all() for p in head.parameters())
    if steps == 0 or after == before or not finite:
        raise Failure("the head did not train: no update, no change or a non-finite loss")
    record = {"optimizer_steps": steps, "epoch_mean_loss": trace, "encoder_trainable_tensors": 0}
    return head, record | {"head_sha256_before": before, "head_sha256_after": after}


def _recipe(job: TrainingJob) -> dict:
    """What recipe.json and classifier.json both pin: the recipe, the target and the base."""
    question = {k: v for k, v in vars(job.target.question).items() if k != "definition"}
    base = {k: job.body["base"][k] for k in ("model", "source")}
    recipe = {"recipe": RECIPE, "renderer": RENDERER, "pooling": encoder.POOLING}
    recipe |= {"label_order": list(LABEL_ORDER), "objective": OBJECTIVE, "dtype": "float32"}
    recipe["optimizer"] = {"name": "adamw", "betas": list(BETAS), "eps": EPS}
    recipe["target"] = {"kind": job.target.kind, **question}
    return recipe | {"base": base | {"manifest_sha256": job.base_pins["manifest"].sha256}}


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def _write(out: Path, relative: str, kind: str, data: bytes, source: object) -> dict:
    """Writes one new private file, never over another, and pins it as a load-set row."""
    path = out / relative
    path.parent.mkdir(mode=0o700, exist_ok=True)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
        handle.write(data)
    row = {"name": path.name, "kind": kind, "path": relative, "source": source}
    digests = {"sha256": hashlib.sha256(data), "blake3": blake3.blake3(data)}
    return row | {"bytes": len(data)} | {k: v.hexdigest() for k, v in digests.items()}


def load_set_blake3(model: str, rows: list[dict]) -> str:
    """`PinnedCheckpoint::content_hash`: BLAKE3 of canonical [model, files by name], each file
    [name, kind, source, its BLAKE3 as 32 byte values, bytes]."""
    files = [
        [row["name"], row["kind"], row["source"], [*bytes.fromhex(row["blake3"])], row["bytes"]]
        for row in sorted(rows, key=lambda row: row["name"])
    ]
    return _digest([model, files])


def export_checkpoint(out: Path, job: TrainingJob, loaded, head: torch.nn.Linear) -> dict:
    """Base files once under base/; the training set adds the head as trained and recipe.json,
    the exported set the serving head and classifier.json (separate from oneironer.json)."""
    model, harness = job.target.question.output_model, job.body["harness"]
    source = job.body["base"]["source"]
    base = [_write(out, f"base/{n}", k, loaded.files[r], source) for r, n, k in BASE_LOAD]
    shape = {"weight": [len(LABEL_ORDER), head.in_features], "bias": [len(LABEL_ORDER)]}
    trained = _write(out, "training/head.safetensors", "weights", _head_bytes(head, ""), harness)
    recipe = {"format": RECIPE_FORMAT, "settings": job.body["settings"], "tensors": shape}
    recipe = _json_bytes(_recipe(job) | recipe)
    recipe = _write(out, "training/recipe.json", "config", recipe, harness)
    served = _write(out, "export/head.safetensors", "weights", _head_bytes(head, "head."), harness)
    classifier = _recipe(job) | {"format": CLASSIFIER_FORMAT, "model": model}
    classifier |= {"output": "raw_logits", "max_positions": loaded.record["max_positions"]}
    classifier["tensors"] = {f"head.{name}": dims for name, dims in shape.items()}
    pins = [{k: row[k] for k in ("name", "sha256", "bytes")} for row in base + [served]]
    classifier = _json_bytes(classifier | {"files": pins})
    classifier = _write(out, "export/classifier.json", "config", classifier, harness)
    sets = {"training": base + [trained, recipe], "export": base + [served, classifier]}
    return {side: {"model": model, "files": rows, "load_set_blake3": load_set_blake3(model, rows)}
            for side, rows in sets.items()}


def compare_export(out: Path, job: TrainingJob, export: dict, texts, trained_ids, trained, device):
    """Reloads the export by its pins (fresh encoder, tokenizer, head); measures each probe
    against the in-memory trained head's logits."""
    rows = {row["name"]: row for row in export["files"]}
    pin = lambda n: FilePin(*map(rows[n].get, ("path", "sha256", "blake3", "bytes")))
    loaded = encoder.load_pinned_encoder(out, {r: pin(n) for r, n, _ in BASE_LOAD}, device)
    tensors = safetensors.torch.load(encoder.read_pinned(out, pin("head.safetensors")))
    weight, bias = tensors["head.weight"].to(device), tensors["head.bias"].to(device)
    again = encoder.tokenize_targets(loaded.tokenizer, texts, loaded.model.config.positions)
    with torch.no_grad():
        exported = F.linear(encoder.encode_targets(loaded.model, again), weight, bias).tolist()
    probes, cases = [], zip(job.body["probes"], trained_ids, trained, exported, again)
    for probe, ids, before, after, reloaded in cases:
        digests = {"input": probe["input"], "tokens": ids}
        measured = {f"{k}_blake3": _digest(v) for k, v in digests.items()}
        measured |= {"probe_id": probe["id"], "windows": len(ids), "tokens_match": ids == reloaded}
        measured |= {"training_logits": before, "export_logits": after}
        measured |= {"training_argmax": _argmax(before), "export_argmax": _argmax(after)}
        measured["max_logit_difference"] = max(abs(a - b) for a, b in zip(before, after))
        probes.append(measured)
    flips = sum(p["training_argmax"] != p["export_argmax"] for p in probes)
    worst = max(p["max_logit_difference"] for p in probes)
    logits = [x for p in probes for x in p["training_logits"] + p["export_logits"]]
    finite, tokens = all(map(math.isfinite, logits)), all(p["tokens_match"] for p in probes)
    tolerance = job.body["export_logit_tolerance"]
    check = {"argmax_flips": flips, "max_logit_difference": worst, "tolerance": tolerance}
    passed = finite and tokens and flips == 0 and worst <= tolerance
    return probes, check | {"finite": finite, "tokens_match": tokens, "passed": passed}


def _argmax(logits: list[float]) -> int:
    return max(range(len(logits)), key=logits.__getitem__)


def environment() -> dict:
    """This run's interpreter, packages and device; drift from requirements.txt, or no CUDA
    device, refuses the job, so the receipt names only what was pinned and checked."""
    here = Path(__file__).parent
    pinned = (here / "requirements.txt").read_bytes()
    text = pinned.decode("utf-8")
    python = re.search(r"^# python==(\S+)$", text, re.M)
    _need(python and platform.python_version() == python[1], "python is not the pinned one")
    norm = lambda name: re.sub(r"[-_.]+", "-", name).lower()  # noqa: E731 - PEP 503 names
    found = {norm(d.metadata["Name"]): d.version for d in importlib.metadata.distributions()}
    pins = re.findall(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?==(\S+)", text, re.M)
    drift = [name for name, version in pins if found.get(norm(name)) != version]
    _need(not drift, "installed packages differ from requirements.txt: " + ", ".join(drift))
    _need(torch.cuda.is_available(), "no CUDA device: this recipe runs on a booked CUDA GPU only")
    gpu = torch.cuda.get_device_properties(0)
    record = {"python": platform.python_version(), "torch": torch.__version__}
    record |= {"cuda": torch.version.cuda, "cudnn": torch.backends.cudnn.version()}
    record |= {"device": gpu.name, "capability": f"{gpu.major}.{gpu.minor}"}
    code = {name: hashlib.sha256((here / name).read_bytes()).hexdigest() for name in CODE}
    record |= {"code_sha256": code, "requirements_sha256": hashlib.sha256(pinned).hexdigest()}
    record["distributions"] = sorted(f"{name}=={version}" for name, version in found.items())
    driver = Path("/proc/driver/nvidia/version")
    if driver.is_file():
        record["nvidia_driver"] = driver.read_text().splitlines()[0]
    return record


def _plain(value: object) -> object:
    """JSON values only: a non-finite float becomes its name, so the receipt still parses."""
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return str(value) if isinstance(value, float) and not math.isfinite(value) else value


def write_receipt(out: Path, receipt: dict) -> dict:
    """receipt.json for every outcome: measurements, pins and ids, never row text."""
    return _write(out, "receipt.json", "receipt", _json_bytes(_plain(receipt)), None)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="FIX 7263: one question head, frozen encoder.")
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
    # Deterministic cuBLAS: set before the first CUDA kernel creates a cuBLAS handle.
    os.environ["CUBLAS_WORKSPACE_CONFIG"] = ":4096:8"
    receipt: dict = {"format": RECEIPT_FORMAT, "not_measured": NOT_MEASURED, "is_not": IS_NOT}
    clock, marks, device = time.monotonic(), {}, torch.device("cuda", 0)
    try:
        receipt["environment"] = environment()
        request = args.request.read_bytes()
        job = parse_job(request)
        body = job.body
        receipt |= {key: body[key] for key in ("run", "spec_blake3", "settings", "harness")}
        receipt["authorization"] = body["compute"] | {"verified_by_worker": False}
        receipt["request"] = {"sha256": hashlib.sha256(request).hexdigest(), "bytes": len(request)}
        receipt["recipe"] = _recipe(job)
        rows, receipt["corpus"] = read_rows(job)
        torch.use_deterministic_algorithms(True)
        torch.backends.cudnn.benchmark = False
        torch.set_float32_matmul_precision("highest")
        marks["gpu_start"] = time.monotonic()
        loaded = encoder.load_pinned_encoder(job.base_dir, job.base_pins, device)
        receipt["encoder"] = loaded.record
        probes = [render_target(job.target.question.definition, p["input"]) for p in body["probes"]]
        texts, count = [text for _, text, _ in rows] + probes, len(rows)
        windows = encoder.tokenize_targets(loaded.tokenizer, texts, loaded.model.config.positions)
        row_ids, probe_ids = windows[:count], windows[count:]
        receipt["corpus"]["multi_window_rows"] = sum(len(ids) > 1 for ids in row_ids)
        marks["loaded"] = time.monotonic()
        labels = [label for _, _, label in rows]
        head, training = train_head(loaded.model, row_ids, labels, body["settings"])
        receipt["training"] = training | {"encoder_passes": sum(map(len, row_ids))}
        with torch.no_grad():
            trained = head(encoder.encode_targets(loaded.model, probe_ids)).tolist()
        marks["trained"] = time.monotonic()
        receipt["load_sets"] = sets = export_checkpoint(out, job, loaded, head)
        del loaded
        torch.cuda.empty_cache()
        marks["exported"] = time.monotonic()
        measured = compare_export(out, job, sets["export"], probes, probe_ids, trained, device)
        receipt["probes"], receipt["export_check"] = measured
        marks["compared"] = time.monotonic()
        seconds = math.ceil(marks["compared"] - marks["gpu_start"])
        receipt["service_units"] = {"unit": "gpu_wall_second", "quantity": seconds}
        status = "trained" if receipt["export_check"]["passed"] else "export_parity_failed"
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
    receipt["status"] = status
    marks["end"] = time.monotonic()
    receipt["elapsed_seconds"] = {name: round(at - clock, 3) for name, at in marks.items()}
    row = write_receipt(out, receipt)
    summary = {"status": status, "receipt": str(out / row["path"]), "sha256": row["sha256"]}
    print(json.dumps(summary))
    return {"trained": 0, "refused": 2}.get(status, 1)


if __name__ == "__main__":
    sys.exit(main())
