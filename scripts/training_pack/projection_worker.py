#!/usr/bin/env python3
"""Train one retrieval projection on native frozen features, without seeing held-out rows.

This worker uses the pinned question-worker environment, not its question algorithm.
Each consented reservoir artifact supplies two text views. Only the new ST Dense matrix
trains; the frozen native base, tokenizer, prompts and prior module chain are kept.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import sys
import time
import traceback

import blake3
import safetensors.torch
import torch
import torch.nn.functional as F


def sibling(name):
    path = Path(__file__).with_name(name + ".py")
    spec = importlib.util.spec_from_file_location("projection_" + name, path)
    module = sys.modules[spec.name] = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


common = sibling("worker")
RECIPE = "oneiron.reservoir-pair-projection/1"
FORMAT = "oneiron.embedding-projection.receipt/1"


def need(value, reason):
    common._need(value, reason)


def safe_name(name):
    need(isinstance(name, str) and name and not name.startswith("/") and "\\" not in name,
         "checkpoint name is not relative")
    need(all(p not in ("", ".", "..") for p in name.split("/")), "invalid checkpoint name")
    return name


def pinned(path, pin):
    data = path.read_bytes()
    need(len(data) == pin["bytes"] and hashlib.sha256(data).hexdigest() == pin["sha256"]
         and blake3.blake3(data).hexdigest() == pin["blake3"], "staged file differs from pin")
    return data


def parse(data):
    job = common._closed(common._load_json(data, "request"), {
        "format", "run", "spec_blake3", "compute", "model", "settings", "harness", "base",
        "features", "training_blake3", "probes", "export_logit_tolerance", "preparation_seconds"}, "request")
    need(job["format"] == "oneiron.embedding-projection.job/1", "unknown projection job")
    need(common.MODEL_ID.fullmatch(job["model"]), "output model id is malformed")
    need(job["compute"] == {"kind": "engine_run", "reference": "training_pack:" + job["run"]},
         "projection requires its own engine run")
    common._source(job["harness"], "harness")
    settings = job["settings"]
    optional = {"evaluation"} if isinstance(settings, dict) and "evaluation" in settings else set()
    fields = {"recipe", "epochs", "batch_size", "learning_rate", "weight_decay", "temperature",
              "seed", "max_input_tokens"}
    common._closed(settings, fields | optional, "settings")
    need(settings["recipe"] == RECIPE, "unknown projection recipe")
    for field, integral, positive in (*common.BOUNDS, ("temperature", False, True),
                                       ("max_input_tokens", True, True)):
        common._number(settings[field], field, integral, positive)
    need(settings["batch_size"] >= 2, "contrastive batches need at least two pairs")
    if "evaluation" in settings:
        evaluation = settings["evaluation"]
        need(isinstance(evaluation, dict), "evaluation must be an object")
        common._closed(evaluation, set(evaluation) & {"minimum_mrr"}, "evaluation")
        if "minimum_mrr" in evaluation:
            value = common._number(evaluation["minimum_mrr"], "minimum_mrr", False, False)
            need(value <= 1, "minimum_mrr must be in 0..=1")
    common._number(job["export_logit_tolerance"], "export_logit_tolerance", False, False)
    common._number(job["preparation_seconds"], "preparation_seconds", False, False)
    features = common._closed(job["features"], {"path", "sha256", "blake3", "bytes"}, "features")
    path = Path(features["path"])
    need(path.is_absolute(), "feature path must be absolute")
    matrices = common._load_json(pinned(path, features), "features")
    common._closed(matrices, {"pairs", "probes"}, "features")
    pairs = torch.tensor(matrices["pairs"], dtype=torch.float32)
    probes = torch.tensor(matrices["probes"], dtype=torch.float32)
    need(pairs.ndim == 3 and pairs.shape[0] >= 2 and pairs.shape[1] == 2 and pairs.shape[2] > 0,
         "contrastive training needs at least two paired feature rows")
    need(probes.ndim == 2 and len(probes) == len(job["probes"]) and len(probes) > 0
         and probes.shape[1] == pairs.shape[2], "probe feature dimensions differ")
    need(pairs.isfinite().all() and probes.isfinite().all(), "features are nonfinite")
    return job, pairs, probes


def normalize(value):
    norm = value.square().sum(dim=-1, keepdim=True).sqrt()
    if not torch.isfinite(norm).all() or (norm == 0).any():
        raise common.Failure("projection has a zero or nonfinite vector")
    return value / norm


def weight_bytes(head):
    return safetensors.torch.save({"linear.weight": head.weight.detach().cpu().contiguous()})


def train(pairs, settings):
    width = pairs.shape[-1]
    head = torch.nn.Linear(width, width, bias=False, device=pairs.device)
    with torch.no_grad():
        head.weight.copy_(torch.eye(width, device=pairs.device))
    before = hashlib.sha256(weight_bytes(head)).hexdigest()
    optimizer = torch.optim.AdamW(head.parameters(), lr=settings["learning_rate"],
                                 weight_decay=settings["weight_decay"], betas=common.BETAS, eps=common.EPS)
    shuffle = torch.Generator().manual_seed(settings["seed"])
    trace, steps = [], 0
    for _ in range(settings["epochs"]):
        total = 0.0
        for ids in torch.randperm(len(pairs), generator=shuffle).split(settings["batch_size"]):
            views = normalize(head(pairs[ids.to(pairs.device)]))
            scores = views[:, 0] @ views[:, 1].T / settings["temperature"]
            labels = torch.eye(len(ids), device=pairs.device)
            loss = -((F.log_softmax(scores, dim=1) * labels).sum(dim=1).mean()
                     + (F.log_softmax(scores.T, dim=1) * labels).sum(dim=1).mean()) / 2
            if not torch.isfinite(loss):
                raise common.Failure("projection loss is nonfinite")
            optimizer.zero_grad(set_to_none=True)
            loss.backward()
            optimizer.step()
            steps += 1
            total += loss.item() * len(ids)
        trace.append(total / len(pairs))
    after = hashlib.sha256(weight_bytes(head)).hexdigest()
    if before == after or not head.weight.isfinite().all():
        raise common.Failure("projection made no finite weight change")
    return head, {"optimizer_steps": steps, "epoch_mean_loss": trace,
                  "weight_sha256_before": before, "weight_sha256_after": after,
                  "optimizer": {"name": "adamw", "betas": list(common.BETAS), "eps": common.EPS}}


def write_file(out, name, kind, data, source):
    path = out / safe_name(name)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
        handle.write(data)
    return {"name": name, "path": name, "kind": kind, "source": source, "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), "blake3": blake3.blake3(data).hexdigest()}


def export(out, job, head):
    base = job["base"]
    directory = Path(base["dir"])
    need(directory.is_absolute(), "base directory is not absolute")
    files = base["files"]
    names = [safe_name(row["name"]) for row in files]
    need(len(set(names)) == len(names) and "modules.json" in names, "invalid base file names")
    original = {row["name"]: pinned(directory / row["name"], row) for row in files}
    modules = common._load_json(original["modules.json"], "modules.json")
    need(isinstance(modules, list), "module chain is not a list")
    module = "projection-" + job["run"]
    need(all(not name.startswith(module + "/") for name in names), "projection module already exists")
    modules = modules + [
        {"idx": len(modules), "name": module, "path": module, "type": "sentence_transformers.models.Dense"},
        {"idx": len(modules) + 1, "name": module + "-normalize", "path": "",
         "type": "sentence_transformers.models.Normalize"}]
    rows = []
    for file in files:
        name = file["name"]
        changed = name == "modules.json"
        data = common._json_bytes(modules) if changed else original[name]
        source = job["harness"] if changed else file["source"]
        rows.append(write_file(out, name, file["kind"], data, source))
    config = {"in_features": head.in_features, "out_features": head.out_features, "bias": False,
              "activation_function": "torch.nn.modules.linear.Identity"}
    rows.append(write_file(out, module + "/config.json", "config", common._json_bytes(config), job["harness"]))
    weights = write_file(out, module + "/model.safetensors", "weights", weight_bytes(head), job["harness"])
    rows.append(weights)
    checkpoint = {"model": job["model"], "files": rows,
                  "load_set_blake3": common.load_set_blake3(job["model"], rows)}
    return {"training": checkpoint, "export": checkpoint}, weights


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    need(args.request.is_absolute() and args.output.is_absolute(), "job paths must be absolute")
    out = args.output
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.environ["CUBLAS_WORKSPACE_CONFIG"] = ":4096:8"
    receipt = {"format": FORMAT}
    clock = time.monotonic()
    try:
        receipt["environment"] = common.environment()
        receipt["environment"]["code_sha256"][Path(__file__).name] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        body = args.request.read_bytes()
        job, pairs, probes = parse(body)
        receipt |= {key: job[key] for key in ("run", "spec_blake3", "settings", "harness", "training_blake3")}
        receipt["authorization"] = job["compute"]
        receipt["request_sha256"] = hashlib.sha256(body).hexdigest()
        torch.use_deterministic_algorithms(True)
        torch.set_float32_matmul_precision("highest")
        torch.manual_seed(job["settings"]["seed"])
        device = torch.device("cuda", 0)
        start = time.monotonic()
        pairs, probes = pairs.to(device), probes.to(device)
        head, receipt["training"] = train(pairs, job["settings"])
        with torch.no_grad():
            trained = normalize(head(probes)).cpu().tolist()
        receipt["load_sets"], weights = export(out, job, head)
        reloaded = safetensors.torch.load(pinned(out / weights["path"], weights))["linear.weight"].to(device)
        with torch.no_grad():
            exported = normalize(F.linear(probes, reloaded)).cpu().tolist()
        receipt["probes"] = [dict(probe, probe_id=probe["id"], training=a, export=b)
                             for probe, a, b in zip(job["probes"], trained, exported)]
        torch.cuda.synchronize()
        receipt["service_units"] = {"unit": "gpu_wall_second", "quantity": math.ceil(job["preparation_seconds"] + time.monotonic() - start)}
        receipt["status"] = "trained"
    except common.Refusal as error:
        receipt |= {"status": "refused", "reason": str(error)}
    except common.Failure as error:
        receipt |= {"status": "failed", "reason": str(error)}
    except Exception as error:
        frames = traceback.extract_tb(error.__traceback__)
        receipt |= {"status": "failed", "reason": type(error).__name__,
                    "traceback": [{"file": Path(f.filename).name, "line": f.lineno, "function": f.name}
                                  for f in frames[-common.TRACEBACK_FRAMES:]]}
    receipt["elapsed_seconds"] = time.monotonic() - clock
    write_file(out, "receipt.json", "config", common._json_bytes(common._plain(receipt)), None)
    return 0 if receipt["status"] == "trained" else 1


if __name__ == "__main__":
    sys.exit(main())
