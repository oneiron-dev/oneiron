#!/usr/bin/env python3
"""The house model's generation server: Qwen3.8-27B as EXL3 4 bpw with the
DFlash2 draft, behind an OpenAI-compatible `/v1/chat/completions`.

This is the server RESEARCH-1232 measured, made a service. The draft depth is
the owner's ruling of 2026-10-16: 7 drafted tokens for every workload, until
new evidence moves it (`--draft-tokens`). Caches are Q8 for target and draft,
batch 1; requests take turns.

A thinking reply is split as llama.cpp's `--reasoning-format deepseek` splits
it: the text before `</think>` comes back as `reasoning_content`, the answer as
`content`. `reasoning_budget_tokens` caps the thinking part; at the cap the
server closes the thought itself and the answer gets the rest of `max_tokens`.
A `response_format` schema constrains the answer only, never the thought.

A request body may come gzip- or zstd-encoded (`body_codec.py`); one in a
codec this server cannot read is answered 415.
"""
import argparse
import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from body_codec import UnsupportedEncoding, decode_body
from jinja2 import Environment
from exllamav3 import Cache, CacheLayer_quant, Config, Generator, Job, LLGuidanceFilter, Model, Tokenizer
from exllamav3.generator.sampler import ComboSampler

THINK_OPEN = "<think>"
THINK_CLOSE = "</think>"
# What the server writes when the thinking budget runs out, as the template
# itself frames a closed thought.
FORCED_CLOSE = "\n" + THINK_CLOSE + "\n\n"
PAGE = 256


class RequestError(ValueError):
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


def raise_template_error(message):
    raise ValueError(message)


def check_placement(name, model):
    placement = [(str(module.key), str(getattr(module, "device", None)), bool(module.caps.get("prefer_cpu")))
                 for module in model.modules]
    unexpected = [(key, device) for key, device, prefer_cpu in placement
                  if device != "cuda:0" and not (device == "cpu" and prefer_cpu)]
    if unexpected:
        raise RuntimeError(f"{name} has non-CUDA modules not marked prefer_cpu: {unexpected[:12]}")
    if getattr(model.config, "moe_cpu_hosts", {}):
        raise RuntimeError(f"{name} enabled CPU-offloaded experts")
    devices = sorted({device for _, device, _ in placement})
    print(f"MODEL_DEVICE {name} {devices}", flush=True)


def load(args):
    if args.context % PAGE:
        raise ValueError(f"--context must be a multiple of the cache page, {PAGE}")
    if args.draft_tokens < 1:
        raise ValueError("--draft-tokens must be at least 1")

    target_config = Config.from_directory(args.target_dir)
    target = Model.from_config(target_config, component="text")
    tokenizer = Tokenizer(target_config)
    template_path = Path(args.target_dir) / "chat_template.jinja"
    template = Environment().from_string(template_path.read_text(encoding="utf-8"))
    template.environment.globals["raise_exception"] = raise_template_error

    draft = draft_cache = None
    depth = 0
    if args.draft_dir:
        draft_config = Config.from_directory(args.draft_dir)
        draft = Model.from_config(draft_config, component="text")
        block = int(draft.caps.get("default_draft_size", 0))
        if block <= 0:
            raise RuntimeError("the DFlash2 draft exposes no draft block size")
        if args.draft_tokens > block:
            raise RuntimeError(f"--draft-tokens {args.draft_tokens} is deeper than the draft's block, {block}")
        depth = args.draft_tokens

    target_cache = Cache(target, max_num_tokens=args.context, layer_type=CacheLayer_quant,
                         k_bits=8, v_bits=8, max_batch_size=1, max_history=depth)
    if draft is not None:
        draft_cache = Cache(draft, max_num_tokens=args.context, layer_type=CacheLayer_quant,
                            k_bits=8, v_bits=8, max_batch_size=1, max_history=depth)

    print(f"MODEL_LOAD_START target={args.target_dir} draft={args.draft_dir or 'none'} "
          f"context={args.context} depth={depth}", flush=True)
    target.load(device="cuda:0", max_batch_size=1, progressbar=False)
    check_placement("target", target)
    if draft is not None:
        draft.load(device="cuda:0", max_batch_size=1, progressbar=False)
        check_placement("draft", draft)

    generator = Generator(target, target_cache, tokenizer, max_batch_size=1,
                          draft_model=draft, draft_cache=draft_cache,
                          num_draft_tokens=depth or None,
                          cpu_cache_size=0, recurrent_cache_size=args.recurrent_cache_gib * 1024**3,
                          record_draft_stats=True)
    stop_ids = set()
    eos = getattr(target_config, "eos_token_id", None)
    for token in eos if isinstance(eos, list) else [eos]:
        if token is not None:
            stop_ids.add(int(token))
    for spelling in ("<|im_end|>", "<|endoftext|>"):
        ids = tokenizer.encode(spelling, encode_special_tokens=True).flatten().tolist()
        if len(ids) == 1:
            stop_ids.add(int(ids[0]))
    print(f"SERVER_READY model={args.model_id} context={args.context} depth={depth} "
          f"stop_ids={sorted(stop_ids)}", flush=True)
    return Server(args, tokenizer, template, generator, sorted(stop_ids))


def make_sampler(body):
    return ComboSampler(
        rep_p=float(body.get("repetition_penalty", 1.0)),
        freq_p=float(body.get("frequency_penalty", 0.0)),
        pres_p=float(body.get("presence_penalty", 0.0)),
        rep_sustain_range=64,
        rep_decay_range=0,
        temperature=float(body.get("temperature", 1.0)),
        min_p=float(body.get("min_p", 0.0)),
        top_k=int(body.get("top_k", 0)),
        top_p=float(body.get("top_p", 1.0)),
    )


def optional_int(body, key):
    value = body.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or int(value) != value:
        raise RequestError(f"{key} must be an integer")
    return int(value)


def answer_schema(body):
    response_format = body.get("response_format")
    if response_format is None:
        return None
    kind = response_format.get("type")
    if kind == "text":
        return None
    if kind == "json_object":
        return {"type": "object"}
    if kind != "json_schema":
        raise RequestError("response_format.type must be text, json_object or json_schema")
    schema = (response_format.get("json_schema") or {}).get("schema")
    if not isinstance(schema, dict):
        raise RequestError("response_format.json_schema.schema must be an object")
    return schema


def stop_strings(body):
    stop = body.get("stop")
    if stop is None:
        return []
    if isinstance(stop, str):
        return [stop]
    if isinstance(stop, list) and all(isinstance(s, str) for s in stop):
        return stop
    raise RequestError("stop must be a string or a list of strings")


def opens_thought(prompt):
    """True when the rendered prompt ends inside an open thought, as the
    template leaves it when thinking is on."""
    return prompt.rfind(THINK_OPEN) > prompt.rfind(THINK_CLOSE)


class Server:
    def __init__(self, args, tokenizer, template, generator, stop_ids):
        self.model_id = args.model_id
        self.context = args.context
        self.default_max_tokens = args.default_max_tokens
        self.tokenizer = tokenizer
        self.template = template
        self.generator = generator
        self.stop_ids = stop_ids
        self.lock = threading.Lock()

    def encode(self, text):
        return self.tokenizer.encode(text, encode_special_tokens=True, add_bos=False).cpu()

    def run(self, ids, max_new_tokens, body, stops, filters, emit):
        """Runs one job to its end and returns its final event."""
        job = Job(
            input_ids=ids,
            max_new_tokens=max_new_tokens,
            seed=optional_int(body, "seed"),
            sampler=make_sampler(body),
            stop_conditions=self.stop_ids + stops,
            decode_special_tokens=False,
            filters=filters,
        )
        serial = self.generator.enqueue(job)
        final = None
        while self.generator.num_remaining_jobs():
            for result in self.generator.iterate():
                if result.get("serial") != serial:
                    continue
                if result.get("stage") == "error":
                    raise result["error"]
                if result.get("stage") != "streaming":
                    continue
                text = result.get("text") or ""
                if text:
                    emit(text)
                if result.get("eos"):
                    final = result
        if final is None:
            raise RuntimeError("the generator drained without a final event")
        return final

    def generate(self, body, emit_reasoning, emit_content):
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            raise RequestError("messages must be a non-empty list")
        template_kwargs = body.get("chat_template_kwargs") or {}
        if not isinstance(template_kwargs, dict):
            raise RequestError("chat_template_kwargs must be an object")
        prompt = self.template.render(
            messages=messages,
            add_generation_prompt=True,
            add_vision_id=False,
            tools=[],
            **template_kwargs,
        )
        ids = self.encode(prompt)
        prompt_tokens = int(ids.numel())
        room = self.context - prompt_tokens
        if room < 1:
            raise RequestError(f"the prompt's {prompt_tokens} tokens fill the {self.context}-token context",
                               code="context_length_exceeded")
        max_tokens = optional_int(body, "max_completion_tokens") or optional_int(body, "max_tokens") \
            or self.default_max_tokens
        if max_tokens < 1:
            raise RequestError("max_tokens must be positive")
        max_tokens = min(max_tokens, room)
        budget = optional_int(body, "reasoning_budget_tokens")
        if budget is not None and budget < 0:
            raise RequestError("reasoning_budget_tokens must not be negative")
        schema = answer_schema(body)
        stops = stop_strings(body)

        timings = {"prefill": 0.0, "generate": 0.0, "accepted": 0, "rejected": 0}
        spent = 0
        reasoning = []

        def account(final):
            nonlocal spent
            spent += int(final.get("new_tokens", 0))
            timings["prefill"] += float(final.get("time_prefill", 0.0))
            timings["generate"] += float(final.get("time_generate", 0.0))
            timings["accepted"] += int(final.get("accepted_draft_tokens", 0))
            timings["rejected"] += int(final.get("rejected_draft_tokens", 0))

        def keep_reasoning(piece):
            reasoning.append(piece)
            emit_reasoning(piece)

        answer_prompt = prompt
        finish = None
        with self.lock:
            if opens_thought(prompt):
                cap = max_tokens if budget is None else min(budget, max_tokens)
                if cap > 0:
                    final = self.run(ids, cap, body, [THINK_CLOSE], [], keep_reasoning)
                    account(final)
                    reason = final.get("eos_reason")
                    if reason == "stop_string":
                        answer_prompt = prompt + "".join(reasoning) + THINK_CLOSE
                    elif reason == "max_new_tokens" and cap < max_tokens:
                        answer_prompt = prompt + "".join(reasoning) + FORCED_CLOSE
                    else:
                        # The model stopped inside its thought, or the thought
                        # took every token the call allowed.
                        finish = "length" if reason == "max_new_tokens" else "stop"
                else:
                    answer_prompt = prompt + FORCED_CLOSE

            if finish is None:
                left = max_tokens - spent
                if left < 1:
                    finish = "length"
                else:
                    leading = [True]

                    def keep_content(piece):
                        # The answer's first bytes after a thought are the
                        # template's blank line, not the answer.
                        if leading[0]:
                            piece = piece.lstrip("\n")
                            if not piece:
                                return
                            leading[0] = False
                        emit_content(piece)

                    filters = []
                    if schema is not None:
                        filters.append(LLGuidanceFilter(self.tokenizer, json_schema=schema,
                                                        eos_after_completed=True))
                    answer_ids = ids if answer_prompt is prompt else self.encode(answer_prompt)
                    final = self.run(answer_ids, left, body, stops, filters, keep_content)
                    account(final)
                    finish = "length" if final.get("eos_reason") == "max_new_tokens" else "stop"

        usage = {"prompt_tokens": prompt_tokens, "completion_tokens": spent,
                 "total_tokens": prompt_tokens + spent}
        stats = {
            "prompt_n": prompt_tokens,
            "prompt_per_second": prompt_tokens / timings["prefill"] if timings["prefill"] > 0 else None,
            "predicted_n": spent,
            "predicted_per_second": spent / timings["generate"] if timings["generate"] > 0 else None,
            "draft_n": timings["accepted"] + timings["rejected"],
            "draft_n_accepted": timings["accepted"],
        }
        return {"usage": usage, "timings": stats, "finish_reason": finish}


def serve(args, state):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *log_args):
            print("HTTP", self.address_string(), fmt % log_args, flush=True)

        def _json(self, status, payload):
            raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _chunk(self, payload):
            self.wfile.write(f"{len(payload):X}\r\n".encode("ascii") + payload + b"\r\n")
            self.wfile.flush()

        def _sse(self, payload):
            self._chunk(("data: " + json.dumps(payload, ensure_ascii=False) + "\n\n").encode("utf-8"))

        def do_GET(self):
            if self.path == "/health":
                self._json(200, {"status": "ok"})
            elif self.path in ("/v1/models", "/models"):
                self._json(200, {"object": "list", "data": [{"id": state.model_id, "object": "model"}]})
            else:
                self._json(404, {"error": {"message": "not found"}})

        def do_POST(self):
            if self.path not in ("/v1/chat/completions", "/chat/completions"):
                self._json(404, {"error": {"message": "not found"}})
                return
            headers_sent = False
            try:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(decode_body(self.headers.get("Content-Encoding"),
                                              self.rfile.read(length)))
                if not isinstance(body, dict):
                    raise RequestError("the body must be a JSON object")
                streaming = bool(body.get("stream", False))
                request_id = "chatcmpl-" + uuid.uuid4().hex
                created = int(time.time())
                model = body.get("model") or state.model_id
                reasoning, content = [], []
                if streaming:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "close")
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    headers_sent = True

                def delta(field, sink):
                    def emit(piece):
                        sink.append(piece)
                        if streaming:
                            self._sse({"id": request_id, "object": "chat.completion.chunk", "created": created,
                                       "model": model,
                                       "choices": [{"index": 0, "delta": {field: piece}, "finish_reason": None}]})
                    return emit

                result = state.generate(body, delta("reasoning_content", reasoning), delta("content", content))
                if streaming:
                    self._sse({"id": request_id, "object": "chat.completion.chunk", "created": created,
                               "model": model,
                               "choices": [{"index": 0, "delta": {}, "finish_reason": result["finish_reason"]}],
                               "usage": result["usage"], "timings": result["timings"]})
                    self._chunk(b"data: [DONE]\n\n")
                    self.wfile.write(b"0\r\n\r\n")
                    self.wfile.flush()
                    self.close_connection = True
                else:
                    message = {"role": "assistant", "content": "".join(content)}
                    if reasoning:
                        message["reasoning_content"] = "".join(reasoning)
                    self._json(200, {"id": request_id, "object": "chat.completion", "created": created,
                                     "model": model,
                                     "choices": [{"index": 0, "message": message,
                                                  "finish_reason": result["finish_reason"]}],
                                     "usage": result["usage"], "timings": result["timings"]})
            except UnsupportedEncoding as e:
                self._json(415, {"error": {"message": f"Content-Encoding {e} is not supported",
                                           "type": "invalid_request_error"}})
            except (RequestError, ValueError, KeyError, TypeError) as e:
                print(f"REQUEST_ERROR {type(e).__name__}: {e}", flush=True)
                if headers_sent:
                    self.close_connection = True
                else:
                    error = {"message": str(e), "type": "invalid_request_error"}
                    if getattr(e, "code", None):
                        error["code"] = e.code
                    self._json(400, {"error": error})
            except BrokenPipeError:
                self.close_connection = True
            except Exception as e:
                print(f"REQUEST_ERROR {type(e).__name__}: {e}", flush=True)
                if headers_sent:
                    self.close_connection = True
                else:
                    self._json(500, {"error": {"message": f"{type(e).__name__}: {e}"}})

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    server.serve_forever()


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--target-dir", required=True, help="the EXL3 4 bpw target model directory")
    p.add_argument("--draft-dir", default="", help="the DFlash2 draft model directory; empty serves without a draft")
    p.add_argument("--draft-tokens", type=int, default=7,
                   help="the draft depth: drafted tokens the target checks per step (owner ruling 2026-10-16: 7)")
    p.add_argument("--context", type=int, default=32768, help="the context, in tokens; a multiple of 256")
    p.add_argument("--recurrent-cache-gib", type=int, default=4)
    p.add_argument("--default-max-tokens", type=int, default=4096,
                   help="the reply cap when a request names none")
    p.add_argument("--model-id", default="qwen3.8-27b", help="the id /v1/models reports")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=18091)
    args = p.parse_args()
    serve(args, load(args))


if __name__ == "__main__":
    main()
