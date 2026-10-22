#!/usr/bin/env python3
"""Transport-free EXL3 bench over exported requests, or an observed worker.

The optional observer reads actual Job sequence IDs at the end of each pass.
It changes no prompt, sampler, scheduler or generator operation. Token IDs
are never reconstructed from text. Exports and rows must stay outside source.
Use --serve to run the unchanged HTTP/native server with the same observer.
"""
import argparse
import hashlib
import json
import os
import sys
import time
import uuid
from pathlib import Path

import exl3_server as worker
import exl3_tools


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def append(path, row):
    with Path(path).open("a") as stream:
        stream.write(json.dumps(row, ensure_ascii=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def outside(path):
    path = Path(path).resolve()
    source = Path(__file__).resolve().parents[2]
    if path.is_relative_to(source):
        raise ValueError("bench artifacts must stay outside the source tree")
    return path


def observe(exports=None):
    """Install once per process, before load starts the scheduler thread."""
    original_prepare = worker.Server.prepare
    original_end = worker.Scheduler._end_phase
    original_usage = worker.Scheduler._usage

    def prepare(self, body, request_id, accepted_ns=None):
        req = original_prepare(self, body, request_id, accepted_ns)
        # The worker ignores the carrier-only stream controls in prepare.
        semantic = {k: v for k, v in body.items() if k not in ("stream", "stream_options")}
        data = canonical(semantic)
        req.bench_request_sha256 = digest(data)
        req.bench_token_ids = []
        if exports is not None:
            (exports / (req.bench_request_sha256 + ".json")).write_bytes(data)
        return req

    def end(self, req, final):
        job = final.get("job")
        if job is not None:
            ids = job.sequences[0].sequence_ids.torch().flatten().tolist()
            req.bench_token_ids.extend(int(i) for i in ids[int(final["prompt_tokens"]):])
        return original_end(self, req, final)

    def usage(self, req, end):
        value = original_usage(self, req, end)
        value["bench_token_ids"] = list(req.bench_token_ids)
        value["bench_request_sha256"] = req.bench_request_sha256
        return value

    worker.Server.prepare = prepare
    worker.Scheduler._end_phase = end
    worker.Scheduler._usage = usage


def rejection(usage, ids, terminal):
    calls = usage.get("inference_calls", [])
    if not terminal or len(calls) != 1:
        return "missing terminal or single physical-call receipt"
    call = calls[0]
    counts = [call.get(k) for k in ("ttft_us", "output_tokens", "drafts_proposed", "drafts_accepted")]
    if any(type(n) is not int or n < 0 for n in counts):
        return "missing or invalid native counters"
    if counts[3] > counts[2] or counts[1] != len(ids) or counts[1] != usage.get("completion_tokens"):
        return "native counters disagree with observed token ids"
    if call.get("end_reason") not in ("stop", "length", "tool_calls"):
        return "invalid native end"
    waits = call.get("queue_wait", {})
    if any(type(waits.get(k)) is not int or waits[k] < 0 for k in ("worker_us", "engine_us")):
        return "missing queue counters"
    passes = call.get("passes", [])
    if not passes:
        return "missing native passes"
    for p in passes:
        if (p.get("counter_source") != "exl3_job" or p.get("outcome") not in ("hit", "recompute")
                or any(type(p.get(k)) is not int or p[k] < 0 for k in
                       ("input_tokens", "cache_read_tokens", "computed_input_tokens", "prefill_us", "generate_us"))
                or p["input_tokens"] != p["cache_read_tokens"] + p["computed_input_tokens"]):
            return "invalid native pass"
    return None


def drive(state, body, case_id, warmup=False):
    start = time.perf_counter_ns()
    first = [None, None]
    last = [None]
    reasoning, content = [], []

    def piece(index, sink):
        def emit(text):
            now = time.perf_counter_ns()
            if text:
                first[0] = first[0] or now
                if index == 1:
                    first[1] = first[1] or now
                last[0] = now
            sink.append(text)
        return emit

    scheduler = state.scheduler
    req = None
    counted = scheduler.accept()
    if not counted:
        raise RuntimeError("scheduler is draining")
    try:
        req = state.prepare(body, "executor-" + uuid.uuid4().hex, time.monotonic_ns())
        scheduler.submit(req, lambda: False)
        result = scheduler.wait(req, lambda: False, piece(0, reasoning), piece(1, content))
        end = time.perf_counter_ns()
        message, finish = exl3_tools.answer_message(reasoning, content, req.tools, result["finish_reason"])
        text = message["content"]
        usage = result["usage"]
        ids = usage.get("bench_token_ids", [])
        error = rejection(usage, ids, True)
        millis = lambda mark: None if mark is None else (mark - start) / 1e6
        return {
            "schema": "oneiron.infer-bench.row.v1", "arm_id": "executor", "transport": "executor",
            "case_id": case_id, "rep": 0, "warmup": warmup,
            "status": "rejected" if error else "ok", "error": error,
            "ttft_any_ms": millis(first[0]), "ttft_text_ms": millis(first[1]),
            "t_last_ms": millis(last[0]), "wall_ms": millis(end),
            "input_tokens": usage["prompt_tokens"], "output_tokens": usage["completion_tokens"],
            "finish_reason": finish, "native": result["timings"],
            "inference_calls": usage.get("inference_calls", []),
            "token_ids": ids, "token_ids_sha256": digest(json.dumps(ids, separators=(",", ":")).encode()),
            "text_sha256": digest(text.encode()), "output_chars": len(text),
            "request_sha256": usage.get("bench_request_sha256"), "native_stats": req.final_stats,
        }
    except Exception as error:
        return {"schema": "oneiron.infer-bench.row.v1", "arm_id": "executor", "case_id": case_id,
                "status": "rejected", "error": f"{type(error).__name__}: {error}", "warmup": warmup,
                "wall_ms": (time.perf_counter_ns() - start) / 1e6}
    finally:
        if req is not None and not req.ended:
            scheduler.cancel(req)
        scheduler.settle()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target-dir", required=True)
    p.add_argument("--draft-dir", required=True)
    p.add_argument("--requests", type=outside, help="JSONL: case_id, request_file; first entry is warmup")
    p.add_argument("--out", type=outside)
    p.add_argument("--export-dir", type=outside)
    p.add_argument("--serve", action="store_true")
    p.add_argument("--native-socket")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=18991)
    p.add_argument("--context", type=int, default=32768)
    p.add_argument("--draft-tokens", type=int, default=7)
    p.add_argument("--cache-tokens", type=int, default=40192)
    p.add_argument("--max-in-flight", type=int, default=4)
    p.add_argument("--recurrent-cache-gib", type=int, default=4)
    p.add_argument("--default-max-tokens", type=int, default=4096)
    p.add_argument("--model-id", default="qwen3.8-27b")
    p.add_argument("--weights-manifest")
    p.add_argument("--launch-manifest")
    args = p.parse_args()
    if not args.serve and (args.requests is None or args.out is None):
        p.error("executor needs --requests and --out")
    if args.export_dir is not None:
        args.export_dir.mkdir(parents=True, exist_ok=True)
    observe(args.export_dir)
    state = worker.load(args)
    if args.serve:
        worker.serve(args, state)
        return
    try:
        for number, line in enumerate(args.requests.read_text().splitlines()):
            item = json.loads(line)
            data = outside(item["request_file"]).read_bytes()
            body = json.loads(data)
            if data != canonical(body):
                raise ValueError("request export is not canonical or byte-identical")
            row = drive(state, body, item["case_id"], warmup=number == 0)
            append(args.out, row)
            print("EXECUTOR_ROW", row["case_id"], row["status"], flush=True)
    finally:
        state.scheduler.close()


if __name__ == "__main__":
    main()
