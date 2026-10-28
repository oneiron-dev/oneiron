#!/usr/bin/env python3
"""The house model's generation server: Qwen3.8-27B as EXL3 4 bpw with the
DFlash2 draft, behind an OpenAI-compatible `/v1/chat/completions`.

This is the server RESEARCH-1232 measured, made a service. The draft depth is
the owner's ruling of 2026-10-16: 7 drafted tokens for every workload, until
new evidence moves it (`--draft-tokens`). Caches are Q8 for target and draft.

One scheduler thread owns the generator (INF 1, FIX 6566). HTTP handlers
render and tokenize their request, hand it to the scheduler and stream from
their own queue; they never call the generator. The scheduler admits up to
`--max-in-flight` requests at once (4 by default, never more), each only when
its pages fit in the shared cache beside the pages the admitted ones hold. A
request that does not fit waits; none is refused for its size, cut short or
evicted. A request whose body sets `"oneiron_solo": true` runs alone: it
waits its turn in arrival order, the scheduler lets what is in flight finish,
runs it by itself, then admits again.

A thinking reply is split as llama.cpp's `--reasoning-format deepseek` splits
it: the text before `</think>` comes back as `reasoning_content`, the answer as
`content`. `reasoning_budget_tokens` caps the thinking part; at the cap the
server closes the thought itself and the answer gets the rest of `max_tokens`.
A `response_format` schema constrains the answer only, never the thought.

A request body may come gzip- or zstd-encoded (`body_codec.py`); one in a
codec this server cannot read is answered 415.

Each reply's `usage` carries its inference receipt: the prompt-cache evidence
of every Job the request ran, read from each Job's final event, with the
server's identity, the Generator's epoch and the request's measured queue
waits (`cache_usage.py`, FIX 6567, 8314). The identity's `model` is
the target's weights manifest digest, when the installed shards match it
before they load (`--weights-manifest`, FIX 7895); the server starts either
way. The `model` it returns and lists stays `--model-id`. Started by the
model worker supervisor, it is given `--launch-manifest`: each receipt then
echoes that manifest's digest beside the Generator's epoch, names the build
the supervisor verified as its runtime, and says verified artifacts
(FIX 8315). Without one the build stays reported.

Each receipt also carries the R3 counters (FIX 8317): the request's
first-token time, from its acceptance (before it is rendered) to the first
token the Generator samples for it, reasoning or answer; its native end; its
native output count; and its drafts proposed and accepted, a total only when
every pass reported both. A count a Job's final leaves out stays out of the
receipt, never zero (FIX 8896).

A request's `tools` reach the chat template, and a tool call the model
writes comes back as OpenAI `tool_calls`, buffered or streamed
(`exl3_tools.py`, FIX 8328). A reply with no tool call is unchanged.

Started with `--native-socket`, the server also answers the host over a Unix
socket (`exl3_ipc.py`, DESIGN-V2 R1): the same scheduler, with streamed
events, an acknowledged cancel, allocator stats (`exl3_stats.py`), drain and
shutdown. The HTTP routes stay as they are.

On a target with recurrent state, the native socket also serves exact
conversation sessions (`exl3_session/`, DESIGN-V2 R2): canonical checkpoints
retained on the device, working branches forked from them copy-on-write,
and the suffix commit that advances them. Their pages count against the
same pool: the scheduler admits work against the pool less the pages
sessions hold, and evicts sessions nothing runs on, least recently used
first, when a request or a commit needs the room. A session-less call runs
exactly as before. `--no-sessions` turns the layer off.

Where the layer can write and rebuild snapshots (R3: a quantized KV layout,
a portable recurrent state, a known build identity, a sealed memfd), it also
exports a published checkpoint to the host and imports one onto a new
session (`exl3_session/snapshot.py`). An import's pages are taken only when
they fit beside what is reserved and what sessions hold, idle sessions
evicted first; otherwise it is refused `snapshot_busy`. Exports and imports
count as calls for a drain, and the regions they keep close at shutdown.
"""
import argparse
import collections
import json
import queue
import socket
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import cache_usage
import exl3_ipc
import exl3_stats
import exl3_tools
import weights_manifest
from body_codec import UnsupportedEncoding, decode_body
from jinja2 import Environment
from exllamav3 import Cache, CacheLayer_quant, Config, Generator, Job, LLGuidanceFilter, Model, Tokenizer
from exllamav3.generator.sampler import ComboSampler

try:
    import exl3_session
except Exception as session_import_error:  # without the layer, no session op is advertised
    exl3_session = None
    print(f"WARN SESSIONS_UNAVAILABLE {type(session_import_error).__name__}: {session_import_error}", flush=True)

THINK_OPEN = "<think>"
THINK_CLOSE = "</think>"
# What the server writes when the thinking budget runs out, as the template
# itself frames a closed thought.
FORCED_CLOSE = "\n" + THINK_CLOSE + "\n\n"
# The cache page, in tokens: exllamav3's PAGE_SIZE.
PAGE = 256

# The most requests in flight at once, whatever `--max-in-flight` asks for.
MAX_IN_FLIGHT = 4
# Requests in flight by default (Engine ruling 10-21, INF 1). Batch invariance
# does not hold at 4 for a long or multi-turn request, so a call whose answer
# is compared with another's asks to run alone (`SOLO_FIELD`).
DEFAULT_IN_FLIGHT = 4
# The request body's field that asks for solo admission: true runs the request
# with nothing else in flight.
SOLO_FIELD = "oneiron_solo"
# The shared KV pool, in tokens, when the launcher names none; never less than
# one full request (`full_request_pool`).
# INF 1 (FIX 6974): the largest pool measured at four in flight whose peak
# leaves 2 GiB of the card's 24564 MiB, at a 22488 MiB peak.
DEFAULT_CACHE_TOKENS = 40192
# Submitted requests that wait for admission. Past it a request waits in its
# own handler for a place; it is never refused.
INGRESS_CAPACITY = 4
# Tokens a thinking request holds beyond its prompt and output, for the closed
# thought and the answer pass's re-encoding of prompt and thought.
CLOSE_ROOM_TOKENS = 16
# How often a waiting handler checks that its client is still there, seconds.
DISCONNECT_POLL_S = 0.25
# How long the scheduler pauses when the generator holds a job it cannot start
# (admission makes every job fit, so this guards a loop that should not occur).
STALL_WAIT_S = 0.05


class RequestError(ValueError):
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


class ClientGone(Exception):
    """The client closed its connection before its reply was complete."""


class Draining(RuntimeError):
    """The server takes no new call: it drains or shuts down."""


class TimedJob(Job):
    """A Job that tells its request when it samples its first token (R3):
    after the first increment of its generated count, on the plain and the
    speculative decode paths alike, which both sample through
    `receive_sample`. A requeue runs `__init__` again on the same object, so
    the hook is kept, never reset; it fires once."""

    def __init__(self, *args, on_first_token=None, **kwargs):
        hook = on_first_token if on_first_token is not None else getattr(self, "on_first_token", None)
        super().__init__(*args, **kwargs)
        self.on_first_token = hook

    def receive_sample(self, *args, **kwargs):
        result = super().receive_sample(*args, **kwargs)
        hook = self.on_first_token
        if hook is not None and self.new_tokens >= 1:
            self.on_first_token = None
            hook()
        return result


if exl3_session is not None:
    class FrontierJob(exl3_session.FrontierMixin, TimedJob):
        """A session working branch's Job (`exl3_session/jobs.py`): attached
        at its plan's frontier, with the first-token hook."""


def cuda_devices(*models):
    """The CUDA devices the models' modules were placed on, by name."""
    devices = set()
    for model in models:
        if model is None:
            continue
        for module in model.modules:
            device = str(getattr(module, "device", None))
            if device.startswith("cuda"):
                devices.add(device)
    return sorted(devices)


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


def full_request_pool(context, depth):
    """The pool one full-context request needs alone: the context, the
    backend's one extra token and its draft depth, and a thinking request's
    close room, rounded up to whole pages (Engine ruling 10-20, FIX 6723)."""
    return -(-(context + 1 + depth + CLOSE_ROOM_TOKENS) // PAGE) * PAGE


def weights_digest(target_dir, manifest_path):
    """The target's weights digest: its manifest's, when the installed shards
    match it. A missing or mismatched manifest leaves the identity without a
    model digest, with one warning; the server still starts."""
    if not manifest_path:
        return None
    try:
        return weights_manifest.verify(target_dir, manifest_path)
    except Exception as error:  # identity never stops the server
        print(f"WARN WEIGHTS_UNVERIFIED {error}; the cache identity names no model",
              file=sys.stderr, flush=True)
        return None


def launch_identity(manifest_path):
    """The supervisor's launch manifest (FIX 8315) as `(digest, runtime)`:
    the SHA-256 of its exact bytes, and the build digest it names. None
    without one; a manifest that cannot be read leaves the server on its
    reported versions, with one warning, and the server still starts."""
    if not manifest_path:
        return None
    try:
        data = Path(manifest_path).read_bytes()
        runtime = json.loads(data).get("runtime")
        if not (isinstance(runtime, str) and len(runtime) == 64
                and all(c in "0123456789abcdef" for c in runtime)):
            raise ValueError("it names no 64-hex runtime")
    except Exception as error:  # identity never stops the server
        print(f"WARN LAUNCH_MANIFEST_UNREAD {error}; the build stays reported, not verified",
              file=sys.stderr, flush=True)
        return None
    return cache_usage.sha256_hex(data), runtime


def load(args):
    if args.context % PAGE:
        raise ValueError(f"--context must be a multiple of the cache page, {PAGE}")
    if args.draft_tokens < 1:
        raise ValueError("--draft-tokens must be at least 1")
    if not 1 <= args.max_in_flight <= MAX_IN_FLIGHT:
        raise ValueError(f"--max-in-flight must be 1 to {MAX_IN_FLIGHT}")
    # The shared pool every request in flight draws on: DEFAULT_CACHE_TOKENS
    # unless the launcher names one, and never less than one full request (the
    # context plus its draft and close room, page-rounded).
    floor = full_request_pool(args.context, args.draft_tokens if args.draft_dir else 0)
    cache_tokens = max(DEFAULT_CACHE_TOKENS, floor) if args.cache_tokens is None else args.cache_tokens
    if cache_tokens % PAGE:
        raise ValueError(f"--cache-tokens must be a multiple of the cache page, {PAGE}")
    if cache_tokens < floor:
        raise ValueError(f"--cache-tokens must be at least {floor}, so a request the context admits fits alone")

    # The shards are checked before anything loads them.
    model_digest = weights_digest(args.target_dir, args.weights_manifest)
    launch = launch_identity(args.launch_manifest)
    target_config = Config.from_directory(args.target_dir)
    target = Model.from_config(target_config, component="text")
    tokenizer = Tokenizer(target_config)
    template_path = Path(args.target_dir) / "chat_template.jinja"
    template_source = template_path.read_text(encoding="utf-8")
    template = Environment().from_string(template_source)
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

    # One recurrent slot per request in flight; the caches come before the
    # model loads, which allocate them.
    batch = args.max_in_flight
    target_cache = Cache(target, max_num_tokens=cache_tokens, layer_type=CacheLayer_quant,
                         k_bits=8, v_bits=8, max_batch_size=batch, max_history=depth)
    if draft is not None:
        draft_cache = Cache(draft, max_num_tokens=cache_tokens, layer_type=CacheLayer_quant,
                            k_bits=8, v_bits=8, max_batch_size=batch, max_history=depth)

    print(f"MODEL_LOAD_START target={args.target_dir} draft={args.draft_dir or 'none'} "
          f"context={args.context} cache_tokens={cache_tokens} in_flight={batch} depth={depth}", flush=True)
    target.load(device="cuda:0", max_batch_size=batch, progressbar=False)
    check_placement("target", target)
    if draft is not None:
        draft.load(device="cuda:0", max_batch_size=batch, progressbar=False)
        check_placement("draft", draft)

    # Sessions run on the stock Generator over the session page table; where
    # the layer cannot serve them, the Generator is the stock one.
    generator_class = Generator
    # The bench (exl3_executor_bench.py) builds its own args, without the flag.
    if getattr(args, "no_sessions", False):
        print("SESSIONS_OFF reason=--no-sessions", flush=True)
    elif exl3_session is not None:
        refused = exl3_session.unsupported(target, draft)
        if refused is None:
            generator_class = exl3_session.SessionGenerator
        else:
            print(f"SESSIONS_OFF reason={refused!r}", flush=True)
    generator = generator_class(target, target_cache, tokenizer, max_batch_size=batch,
                                draft_model=draft, draft_cache=draft_cache,
                                num_draft_tokens=depth or None,
                                cpu_cache_size=0, recurrent_cache_size=args.recurrent_cache_gib * 1024**3,
                                record_draft_stats=True)
    # What answers every request from here on, its epoch minted with the
    # Generator: the caches and Generator as built above, and the server's
    # settings (FIX 6567).
    identity = cache_usage.BackendIdentity(
        args.target_dir, template_source,
        cache_settings={"layer": "quant", "k_bits": 8, "v_bits": 8, "page_tokens": PAGE,
                        "cache_tokens": cache_tokens, "max_batch_size": batch, "max_history": depth,
                        "draft_cache": draft is not None, "cpu_cache_size": 0,
                        "recurrent_cache_size": args.recurrent_cache_gib * 1024**3},
        server_settings={"context": args.context, "draft": draft is not None, "draft_tokens": depth,
                         "max_in_flight": batch},
        model_digest=model_digest, launch=launch)
    stop_ids = set()
    eos = getattr(target_config, "eos_token_id", None)
    for token in eos if isinstance(eos, list) else [eos]:
        if token is not None:
            stop_ids.add(int(token))
    for spelling in ("<|im_end|>", "<|endoftext|>"):
        ids = tokenizer.encode(spelling, encode_special_tokens=True).flatten().tolist()
        if len(ids) == 1:
            stop_ids.add(int(ids[0]))
    # The allocator's peaks start again here: from now on they are serving
    # peaks, and the load's are kept apart (exl3_stats.py).
    memory = exl3_stats.Memory(target, target_cache, generator, cuda_devices(target, draft))
    memory.reset_peaks()
    print(f"SERVER_READY model={args.model_id} context={args.context} cache_tokens={cache_tokens} "
          f"in_flight={batch} depth={depth} stop_ids={sorted(stop_ids)}", flush=True)
    return Server(args, tokenizer, template, generator, sorted(stop_ids), identity, memory)


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


def pages_for(input_tokens, max_new_tokens, depth):
    """The cache pages one job holds, counted as the generator counts them:
    `Job.prepare_for_queue` reserves the output cap plus 1 plus the draft depth
    (exllamav3 generator/job.py, its default `max_rq_tokens`), and
    `Sequence.prepare` rounds prompt plus that reservation up to whole pages
    (generator/pagetable.py). A prefix page the job could share with another
    counts again here, so this never undercounts."""
    tokens = input_tokens + max_new_tokens + 1 + depth
    return -(-tokens // PAGE)


def peer_gone(connection):
    """True once the client has closed its end of `connection`: a peek reads
    end-of-file, or the socket has failed. The request's whole body is read
    before this is asked, so a byte waiting here belongs to a next request."""
    try:
        return connection.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT) == b""
    except (BlockingIOError, InterruptedError, TimeoutError):
        return False
    except OSError:
        return True


class Request:
    """One chat call between its HTTP handler and the scheduler.

    The handler fills the inputs before `Scheduler.submit` and never changes
    them; from then on only the scheduler thread touches the phase and
    accounting fields. The two sides meet in `events` (scheduler to handler:
    reasoning and content pieces and the first-token mark, then one of done,
    error or cancelled) and in `cancelled` (handler to scheduler). `ended` is
    the handler's own: it saw the terminal event. A request that ends in
    error or cancelled carries the receipt of what it completed in
    `partial_usage`, and the scheduler's cheap stats at its end in
    `final_stats`, both set before its terminal event."""

    def __init__(self, request_id, prompt, ids, max_tokens, budget, schema, stops, seed, samplers, solo,
                 accepted_ns=None, tools=None):
        # Inputs.
        self.request_id = request_id
        # When the worker accepted the request, before it was rendered
        # (monotonic ns): the start of its first-token time (R3).
        self.accepted_ns = accepted_ns
        # The request's tool specs, which its reply is read for (FIX 8328).
        self.tools = tools or []
        # Runs alone: admitted once nothing else is in flight, with nothing
        # admitted beside it until it ends.
        self.solo = solo
        self.prompt = prompt
        self.ids = ids
        self.prompt_tokens = int(ids.numel())
        self.max_tokens = max_tokens
        self.thinking = opens_thought(prompt)
        # The thought's own cap, for a prompt that opens one.
        self.cap = max_tokens if budget is None else min(budget, max_tokens)
        self.schema = schema
        self.stops = stops
        self.seed = seed
        # A fresh sampler for each pass, as each pass always had.
        self.samplers = samplers
        # The pages the request holds from admission to its end, both passes.
        self.need = 0
        # The pass it starts with, and the answer's prompt when that is known
        # before any token: the prompt itself, or the prompt with the thought
        # closed at once for a zero thinking budget.
        self.first = "reason" if self.thinking and self.cap > 0 else "answer"
        self.answer_prompt = None
        self.answer_ids = None
        # The digest of its effective execution, for its cache record.
        self.execution_mode = None
        self.events = queue.SimpleQueue()
        self.cancelled = threading.Event()
        self.ended = False
        # The scheduler's.
        self.submitted = None
        self.admitted = False
        self.admission_wait = 0.0
        self.phase = None
        self.job = None
        self.pages = 0
        self.grow = 0
        self.grow_since = None
        self.page_wait = 0.0
        self.left = 0
        self.spent = 0
        self.reasoning = []
        self.leading = True
        self.peak = 0
        self.released = False
        # Each ended Job's native measurements, totalled while every pass
        # reports them (cache_usage.pass_totals); None before the first.
        self.totals = None
        # The last ended Job's native end.
        self.eos_reason = None
        # When the first generated token was sampled (monotonic ns).
        self.first_token_ns = None
        self.partial_usage = None
        self.final_stats = None
        # Each ended Job's pass, from its final event, in order (FIX 6567).
        self.passes = []
        # A `session.generate`'s working branch (exl3_session), the pages
        # its first Job shares with what the session holds, and whether the
        # scheduler has it (which then ends the branch with it).
        self.branch = None
        self.shared = 0
        self.queued = False

    def mark_first_token(self):
        """Notes the request's first sampled token, once, from the scheduler
        thread, and tells the handler."""
        if self.first_token_ns is not None:
            return
        self.first_token_ns = time.monotonic_ns()
        phase = "reasoning" if self.phase == "reason" else "content"
        self.events.put(("first_token", {"ttft_us": self.ttft_us(), "phase": phase}))

    def ttft_us(self):
        """Acceptance to the first sampled token, in whole microseconds; None
        before a token, or without an acceptance time."""
        if self.accepted_ns is None or self.first_token_ns is None:
            return None
        return max(0, self.first_token_ns - self.accepted_ns) // 1000


class Scheduler:
    """The one thread that owns the Generator (INF 1, FIX 6566).

    A handler submits a prepared Request into a bounded ingress queue and
    reads its own event queue. The owner thread admits requests in arrival
    order while fewer than `max_in_flight` are in flight and the head
    request's pages fit beside the pages the admitted ones hold, enqueues each
    request's jobs, calls `iterate()` once per pass and routes every event to
    its request. It sleeps only when it has nothing to iterate, admit or
    start. A thinking request keeps its one place and its pages through both
    passes: the answer job is enqueued when the reasoning job ends, never
    beside it, and no new request is admitted while an answer waits. A solo
    request at the head of the queue stops admission until what is in flight
    has ended, then goes in alone; the requests behind it wait for it.

    Both transports feed it: an HTTP handler and a native call alike count
    their call from acceptance to its end (`accept`, `settle`), which is what
    a drain waits on, and ask the owner thread for its stats (`snapshot`)."""

    def __init__(self, generator, tokenizer, encode, stop_ids, max_in_flight, identity, memory=None):
        self.generator = generator
        self.tokenizer = tokenizer
        self.encode = encode
        self.stop_ids = stop_ids
        self.max_in_flight = max_in_flight
        self.identity = identity
        self.memory = memory
        self.depth = int(generator.num_draft_tokens)
        self.pool_pages = int(generator.pagetable.max_pages)
        # Shared with the handlers, under `cond`.
        self.cond = threading.Condition()
        self.ingress = collections.deque()
        self.pokes = 0
        self.closing = False
        # Submits waiting for an ingress place; calls accepted and not yet
        # ended; whether the worker drains; snapshots asked of the owner.
        self.blocked = 0
        self.open_calls = 0
        self.draining = False
        self.asks = collections.deque()
        # Work other threads hand the owner thread (the session layer's page
        # work), run between passes.
        self.chores = collections.deque()
        # The session layer, when the server has one (exl3_session); its
        # pages count against the pool.
        self.sessions = None
        # The owner thread's alone.
        self.active = []
        self.by_serial = {}
        self.reserved = 0
        self.thread = threading.Thread(target=self._loop, name="exl3-scheduler", daemon=True)
        self.thread.start()

    # The handlers' side.

    def submit(self, req, gone):
        """Queues `req` for admission. While the ingress queue is full it
        waits, and raises ClientGone if the client leaves meanwhile."""
        need = req.prompt_tokens + (CLOSE_ROOM_TOKENS if req.thinking else 0)
        # A request bigger than the whole pool waits until it is alone; the
        # generator's own check then decides it, as it did before. A
        # session branch's first Job shares the pages its session holds.
        req.need = max(0, min(pages_for(need, req.max_tokens, self.depth), self.pool_pages) - req.shared)
        req.submitted = time.monotonic()
        with self.cond:
            # Counted while it waits for a place: part of the queue depth.
            self.blocked += 1
            try:
                while len(self.ingress) >= INGRESS_CAPACITY and not self.closing:
                    self.cond.wait(DISCONNECT_POLL_S)
                    if len(self.ingress) >= INGRESS_CAPACITY and gone():
                        raise ClientGone()
            finally:
                self.blocked -= 1
            if self.closing:
                raise RuntimeError("the server is shutting down")
            self.ingress.append(req)
            req.queued = True
            self.pokes += 1
            self.cond.notify_all()

    def wait(self, req, gone, on_reasoning, on_content, on_first_token=None):
        """Hands `req`'s pieces to the callbacks as they come and returns its
        result. Raises the request's error, or ClientGone once the client has
        left."""
        check_at = time.monotonic() + DISCONNECT_POLL_S
        while True:
            try:
                kind, value = req.events.get(timeout=DISCONNECT_POLL_S)
            except queue.Empty:
                kind, value = None, None
            if kind == "reasoning":
                on_reasoning(value)
            elif kind == "content":
                on_content(value)
            elif kind == "first_token":
                if on_first_token is not None:
                    on_first_token(value)
            elif kind is not None:
                req.ended = True
                if kind == "done":
                    return value
                if kind == "error":
                    raise value
                raise ClientGone()
            if time.monotonic() >= check_at:
                if gone():
                    raise ClientGone()
                check_at = time.monotonic() + DISCONNECT_POLL_S

    def cancel(self, req):
        """Stops `req` wherever it is: waiting, or in flight."""
        req.cancelled.set()
        with self.cond:
            self.pokes += 1
            self.cond.notify_all()

    def accept(self):
        """Counts one call from its acceptance to its `settle`; False, and
        nothing counted, once the worker drains or shuts down."""
        with self.cond:
            if self.draining or self.closing:
                return False
            self.open_calls += 1
            return True

    def settle(self):
        """Ends one counted call."""
        with self.cond:
            self.open_calls -= 1
            self.cond.notify_all()

    def drain(self):
        """Takes no new call, and returns once every call accepted before
        has ended: queued and in-flight work finishes, with no deadline.
        True when drained, False when the server shut down first."""
        with self.cond:
            self.draining = True
            self.cond.notify_all()
            while self.open_calls > 0 and not self.closing:
                self.cond.wait()
            return not self.closing

    def queue_counts(self):
        """The queue as the scheduler counts it: its depth is the submits
        waiting for a place plus the ingress queue."""
        with self.cond:
            ingress, blocked = len(self.ingress), self.blocked
            open_calls, draining = self.open_calls, self.draining
        return {"queue_depth": ingress + blocked, "ingress": ingress, "blocked_submits": blocked,
                "in_flight": len(self.active), "open_calls": open_calls, "draining": draining}

    def snapshot(self, full):
        """A stats snapshot the owner thread takes between passes, full
        (with exllamav3's category walk) or cheap; None once the scheduler
        is closing or the snapshot failed."""
        ask = {"full": bool(full), "done": threading.Event(), "value": None}
        with self.cond:
            if self.closing:
                return None
            self.asks.append(ask)
            self.pokes += 1
            self.cond.notify_all()
        ask["done"].wait()
        return ask["value"]

    def close(self, timeout=10.0):
        with self.cond:
            self.closing = True
            self.cond.notify_all()
        self.thread.join(timeout)

    def poke(self):
        """Wakes the owner thread for a pass."""
        with self.cond:
            self.pokes += 1
            self.cond.notify_all()

    def post(self, chore):
        """Runs `chore` on the owner thread between passes; False, and never
        run, once the scheduler is closing."""
        with self.cond:
            if self.closing:
                return False
            self.chores.append(chore)
            self.pokes += 1
            self.cond.notify_all()
        return True

    def run_owned(self, work):
        """Runs `work` on the owner thread between passes and returns what it
        returns, or raises what it raised. No deadline: it waits its pass."""
        box = {"done": threading.Event(), "value": None, "error": None}

        def chore():
            try:
                box["value"] = work()
            except BaseException as error:
                box["error"] = error
            finally:
                box["done"].set()

        if not self.post(chore):
            raise Draining("the server is shutting down")
        box["done"].wait()
        if box["error"] is not None:
            raise box["error"]
        return box["value"]

    # The owner thread's side.

    def unreserve(self, pages):
        """Gives back pages a session commit reserved."""
        self.reserved -= pages

    def room_for(self, pages):
        """True once `pages` more fit the pool beside what is reserved and
        what sessions hold, evicting sessions nothing runs on, least recently
        used first, to make it; False when they cannot. A snapshot import's
        pages, on the owner thread."""
        sessions = self.sessions

        def fits():
            return self.reserved + sessions.held_pages() + pages <= self.pool_pages

        sessions.evict_until(fits)
        return fits()

    def _pinned(self):
        """The pages sessions hold that eviction may not take now."""
        return self.sessions.pinned_pages() if self.sessions is not None else 0

    def _make_room(self):
        """Evicts sessions nothing runs on, least recently used first, until
        what is reserved and what sessions hold fit the pool."""
        sessions = self.sessions
        if sessions is not None:
            sessions.evict_until(lambda: self.reserved + sessions.held_pages() <= self.pool_pages)

    def _commit_room_locked(self, commit):
        """True when session commit `commit` may start now: a place is free,
        no answer pass waits to grow, no solo request runs, and its pages fit
        beside what is reserved and pinned. Called under `cond`."""
        if any(req.grow or req.solo for req in self.active):
            return False
        if len(self.active) + self.sessions.running_commits() >= self.max_in_flight:
            return False
        return self.reserved + commit.need + self._pinned() <= self.pool_pages

    def _commit_startable_locked(self):
        if self.sessions is None:
            return False
        commit = self.sessions.next_commit()
        return commit is not None and self._commit_room_locked(commit)

    def _start_commits(self):
        """Starts the session commits that fit, in the order they came. A
        commit is background work: it takes a place and its pages only when
        they are free, and no request waits for it."""
        sessions = self.sessions
        if sessions is None:
            return
        while True:
            commit = sessions.next_commit()
            if commit is None:
                return
            with self.cond:
                if not self._commit_room_locked(commit):
                    return
            self.reserved += commit.need
            commit.reserved = True
            self._make_room()
            sessions.start_commit(commit)

    def _end_branch(self, req):
        if req.branch is not None and self.sessions is not None:
            self.sessions.end_branch(req.branch)

    def _admissible_locked(self, admitted):
        """True when the head of ingress may be admitted now, beside the
        requests in flight and `admitted`, the ones this pass has taken so
        far: a place is free, no answer pass waits to grow, its pages fit,
        and no solo request stands in the way. A solo request is admitted only
        once nothing else is in flight, and nothing is admitted beside it.
        Called under `cond`, from the owner thread."""
        if not self.ingress or any(req.grow for req in self.active):
            return False
        in_flight = self.active + admitted
        # A running session commit holds a place too.
        commits = self.sessions.running_commits() if self.sessions is not None else 0
        if len(in_flight) + commits >= self.max_in_flight:
            return False
        head = self.ingress[0]
        if any(req.solo for req in in_flight) or (head.solo and (in_flight or commits)):
            return False
        # Pages sessions hold count, less what eviction may give back.
        return self.reserved + head.need + self._pinned() <= self.pool_pages

    def _idle_locked(self):
        """True when a pass would do nothing: no job to iterate, no answer
        pass waiting for pages, and no request the head of ingress could
        admit. While the scheduler drains for a solo request it is busy with
        the jobs it waits on, and the pass after the last one ends admits it.
        Called under `cond`, from the owner thread."""
        if self.generator.num_remaining_jobs() or any(req.grow for req in self.active):
            return False
        if self.chores or self._commit_startable_locked():
            return False
        return not self._admissible_locked([])

    def _loop(self):
        seen = -1
        while True:
            with self.cond:
                while self.pokes == seen and not self.closing and self._idle_locked():
                    self.cond.wait()
                seen = self.pokes
                if self.closing:
                    break
                dropped = [req for req in self.ingress if req.cancelled.is_set()]
                for req in dropped:
                    self.ingress.remove(req)
                if dropped:
                    self.cond.notify_all()
                asks = list(self.asks)
                self.asks.clear()
                chores = list(self.chores)
                self.chores.clear()
            try:
                for ask in asks:
                    self._answer(ask)
                self._run_chores(chores)
                for req in dropped:
                    self._end_branch(req)
                    self._settle_partial(req, "cancelled")
                    req.events.put(("cancelled", None))
                self._pass()
            except Exception as e:
                # A fault in this loop rather than in one job: fail what is in
                # flight, never leave it parked.
                print(f"SCHEDULER_ERROR {type(e).__name__}: {e}", flush=True)
                for req in list(self.active):
                    self._fail(req, e)
        self._shutdown()

    def _run_chores(self, chores):
        for chore in chores:
            try:
                chore()
            except Exception as e:  # a chore never stops the scheduler
                print(f"SCHEDULER_CHORE_ERROR {type(e).__name__}: {e}", flush=True)

    def _pass(self):
        self._reap_cancelled()
        for req in list(self.active):
            if req.grow:
                self._try_answer(req)
        if not self.generator.num_remaining_jobs():
            # Answer passes that wait on each other's reservations, with no
            # job running: every page is free, so the oldest goes now.
            waiting = next((req for req in self.active if req.grow), None)
            if waiting is not None:
                self._try_answer(waiting, force=True)
        self._admit()
        self._start_commits()
        if not self.generator.num_remaining_jobs():
            return
        try:
            results = self.generator.iterate()
        except Exception as e:
            # Not one job's error: every request with a job fails, and every
            # session commit.
            print(f"GENERATOR_ERROR {type(e).__name__}: {e}", flush=True)
            for req in [req for req in self.active if req.job is not None]:
                self._fail(req, e)
            if self.sessions is not None:
                self.sessions.fail_commits(e)
            return
        self._route(results)
        if self.sessions is not None:
            self.sessions.after_pass()
        if not results and not self.generator.num_active_jobs() and self.generator.num_pending_jobs():
            with self.cond:
                self.cond.wait(STALL_WAIT_S)

    def _reap_cancelled(self):
        for req in [req for req in self.active if req.cancelled.is_set()]:
            # The Generator's own cancel releases the job's pages and its
            # recurrent slot; the request's place and reservation go next.
            # Only then is the cancel told: a native caller's `released`.
            self._drop_job(req)
            self._release(req)
            self._settle_partial(req, "cancelled")
            # Cancelling a job emits no end event: wake the handler here.
            req.events.put(("cancelled", None))

    def _snapshot(self, full):
        """A stats snapshot, with what each session holds (its unique bytes)
        when the server serves sessions."""
        out = exl3_stats.snapshot(self.memory, self.queue_counts(), self.identity.epoch, full)
        if self.sessions is not None:
            out["sessions"] = self.sessions.stats()
        return out

    def _answer(self, ask):
        """Takes one asked-for snapshot, here on the owner thread."""
        try:
            ask["value"] = self._snapshot(ask["full"])
        except Exception as e:  # stats never stop the scheduler
            print(f"SCHEDULER_STATS_ERROR {type(e).__name__}: {e}", flush=True)
        finally:
            ask["done"].set()

    def _cheap_stats(self):
        try:
            return self._snapshot(False)
        except Exception as e:  # stats never stop the scheduler
            print(f"SCHEDULER_STATS_ERROR {type(e).__name__}: {e}", flush=True)
            return None

    def _settle_partial(self, req, end):
        """Keeps the receipt of what `req` completed before it ended in error
        or was cancelled, and the stats at its end. A receipt that cannot be
        built is left out; it never stops the end."""
        try:
            req.partial_usage = self._usage(req, end)
        except Exception as e:
            print(f"SCHEDULER_RECEIPT_ERROR {type(e).__name__}: {e}", flush=True)
        req.final_stats = self._cheap_stats()

    def _admit(self):
        """Admits requests from the head of the ingress queue, in order, while
        places and pages allow. A waiting answer pass goes first: no request
        is admitted while one waits to grow. A solo request goes in alone."""
        admitted = []
        with self.cond:
            while self._admissible_locked(admitted):
                head = self.ingress.popleft()
                self.reserved += head.need
                head.pages = head.need
                admitted.append(head)
            if admitted:
                self.cond.notify_all()
        if admitted:
            self._make_room()
        now = time.monotonic()
        for req in admitted:
            req.admission_wait = now - req.submitted
            req.admitted = True
            self.active.append(req)
            if req.solo:
                # The id and the wait only: never the prompt.
                print(f"SOLO_ADMIT {req.request_id} waited_ms={req.admission_wait * 1000.0:.0f}", flush=True)
        in_flight = len(self.active)
        for req in self.active:
            req.peak = max(req.peak, in_flight)
        for req in admitted:
            try:
                if req.first == "reason":
                    self._enqueue(req, "reason", req.ids, req.cap, [THINK_CLOSE], [])
                else:
                    self._begin_answer(req)
            except Exception as e:
                self._fail(req, e)

    def _enqueue(self, req, phase, ids, max_new_tokens, stops, filters):
        req.phase = phase
        try:
            fields = dict(
                input_ids=ids,
                max_new_tokens=max_new_tokens,
                seed=req.seed,
                sampler=req.samplers[phase],
                stop_conditions=self.stop_ids + stops,
                decode_special_tokens=False,
                filters=filters,
                identifier=(req.request_id, phase),
                on_first_token=req.mark_first_token,
            )
            if req.branch is not None and self.sessions is not None:
                # A working branch's Job, attached where its session's state
                # matches these ids; a thinking call's reasoning pass leaves
                # its answer pass a carry.
                plan = self.sessions.plan(req.branch, ids, carry=phase == "reason")
                job = FrontierJob(plan=plan, **fields)
            else:
                job = TimedJob(**fields)
            serial = self.generator.enqueue(job)
        except Exception as e:
            self._fail(req, e)
            return
        req.job = job
        self.by_serial[serial] = req

    def _begin_answer(self, req):
        left = req.max_tokens - req.spent
        if left < 1:
            # The thought closed on its own with no token left for an answer.
            self._finish(req, "length", end="length")
            return
        if req.answer_ids is None:
            req.answer_ids = self.encode(req.answer_prompt)
        req.left = left
        need = min(pages_for(int(req.answer_ids.numel()), left, self.depth), self.pool_pages)
        if req.branch is not None and self.sessions is not None:
            need = max(0, need - self.sessions.shared_pages(req.branch, req.answer_ids))
        req.grow = max(0, need - req.pages)
        req.grow_since = time.monotonic()
        self._try_answer(req)

    def _try_answer(self, req, force=False):
        """Enqueues `req`'s answer job once its pages fit; until then it waits,
        holding its place. `force` enqueues it past the reservations when no
        job holds a page."""
        if req.grow:
            if self.reserved + req.grow + self._pinned() > self.pool_pages and not force:
                return
            self.reserved += req.grow
            req.pages += req.grow
            req.grow = 0
            self._make_room()
        req.page_wait += time.monotonic() - req.grow_since
        try:
            filters = []
            if req.schema is not None:
                filters.append(LLGuidanceFilter(self.tokenizer, json_schema=req.schema, eos_after_completed=True))
        except Exception as e:
            self._fail(req, e)
            return
        self._enqueue(req, "answer", req.answer_ids, req.left, req.stops, filters)

    def _route(self, results):
        for result in results:
            serial = result.get("serial")
            req = self.by_serial.get(serial)
            if req is None:
                # A session commit's, or a job already gone.
                if self.sessions is not None:
                    self.sessions.on_result(result)
                continue
            if result.get("job") is not None:
                req.job = result["job"]
            stage = result.get("stage")
            if stage == "error":
                # The generator has already released the job.
                self.by_serial.pop(serial, None)
                req.job = None
                self._fail(req, result.get("error") or RuntimeError("the generator failed the job"))
                continue
            if stage != "streaming":
                continue
            text = result.get("text") or ""
            if text:
                self._deliver(req, text)
            if result.get("eos"):
                self.by_serial.pop(serial, None)
                req.job = None
                self._end_phase(req, result)

    def _deliver(self, req, text):
        if req.phase == "reason":
            req.reasoning.append(text)
            req.events.put(("reasoning", text))
            return
        # The answer's first bytes after a thought are the template's blank
        # line, not the answer.
        if req.leading:
            text = text.lstrip("\n")
            if not text:
                return
            req.leading = False
        req.events.put(("content", text))

    def _end_phase(self, req, final):
        req.passes.append(cache_usage.job_pass(req.phase, req.thinking, final))
        req.totals = cache_usage.pass_totals(req.totals, final)
        # What the request has spent of its cap, for scheduling alone: a pass
        # whose final names no count is taken to have spent all it was
        # allowed, never nothing. The receipt reads only native counts.
        spent = cache_usage.native_count(final, "new_tokens")
        if spent is None:
            spent = req.cap if req.phase == "reason" else req.left
        req.spent += spent
        reason = final.get("eos_reason")
        req.eos_reason = reason if isinstance(reason, str) else None
        if req.phase == "reason":
            if reason == "stop_string":
                req.answer_prompt = req.prompt + "".join(req.reasoning) + THINK_CLOSE
            elif reason == "max_new_tokens" and req.cap < req.max_tokens:
                req.answer_prompt = req.prompt + "".join(req.reasoning) + FORCED_CLOSE
            else:
                # The model stopped inside its thought, or the thought took
                # every token the call allowed.
                self._finish(req, "length" if reason == "max_new_tokens" else "stop")
                return
            self._begin_answer(req)
            return
        self._finish(req, "length" if reason == "max_new_tokens" else "stop")

    def _usage(self, req, end):
        """`req`'s usage with its receipt (cache_usage.py), from the passes it
        completed; `end` is its end in the receipt's closed set, or None."""
        prompt_tokens = req.prompt_tokens
        spent = req.spent
        usage = {"prompt_tokens": prompt_tokens, "completion_tokens": spent,
                 "total_tokens": prompt_tokens + spent}
        totals = req.totals
        enqueued = totals["time_enqueued"] if totals is not None else None
        proposed, accepted = cache_usage.drafts(totals)
        cache_usage.add_evidence(usage, prompt_tokens, req.passes, self.identity.record(req.execution_mode),
                                 worker_wait_s=req.admission_wait if req.admitted else None,
                                 engine_wait_s=None if enqueued is None else enqueued + req.page_wait,
                                 build_evidence=self.identity.build_evidence,
                                 launch_manifest=self.identity.launch_manifest,
                                 ttft_us=req.ttft_us(), end=end,
                                 output_tokens=totals["new_tokens"] if totals is not None else None,
                                 drafts_proposed=proposed, drafts_accepted=accepted)
        return usage

    def _finish(self, req, finish, end=None):
        """Ends `req` with its answer. `end` is the receipt's end when the
        scheduler itself ended it; otherwise its last Job's native end."""
        if end is None:
            end = cache_usage.end_reason(req.eos_reason)
        usage = self._usage(req, end)
        prompt_tokens = req.prompt_tokens
        totals = req.totals or {}
        prefill, generate = totals.get("time_prefill"), totals.get("time_generate")
        enqueued = totals.get("time_enqueued")
        output = totals.get("new_tokens")
        proposed, accepted = cache_usage.drafts(req.totals)
        stats = {
            "prompt_n": prompt_tokens,
            "prompt_per_second": prompt_tokens / prefill if prefill else None,
            "predicted_n": output,
            "predicted_per_second": output / generate if output is not None and generate else None,
            "draft_n": proposed,
            "draft_n_accepted": accepted,
            # Submitted to admitted, including any wait for an ingress place.
            "admission_wait_ms": req.admission_wait * 1000.0,
            # Each job's own enqueue-to-start, and the answer's wait for pages.
            "enqueue_wait_ms": None if enqueued is None else (enqueued + req.page_wait) * 1000.0,
            "draft_depth": self.depth,
            "max_in_flight": self.max_in_flight,
            # The most requests in flight at once while this one was.
            "peak_in_flight": req.peak,
        }
        # A measure no final gave is left out, never zero (FIX 8896).
        stats = {key: value for key, value in stats.items() if value is not None}
        self._release(req)
        req.final_stats = self._cheap_stats()
        req.events.put(("done", {"usage": usage, "timings": stats, "finish_reason": finish}))

    def _fail(self, req, error):
        self._drop_job(req)
        self._release(req)
        self._settle_partial(req, "error")
        req.events.put(("error", error))

    def _drop_job(self, req):
        job = req.job
        if job is None:
            return
        req.job = None
        self.by_serial.pop(job.serial_number, None)
        try:
            self.generator.cancel(job)
        except Exception as e:
            print(f"SCHEDULER_CANCEL_ERROR {type(e).__name__}: {e}", flush=True)

    def _release(self, req):
        """Gives back `req`'s place and pages, once."""
        if req.released:
            return
        req.released = True
        self.reserved -= req.pages
        req.pages = 0
        req.grow = 0
        if req in self.active:
            self.active.remove(req)
        # Its jobs have ended: a session branch ends with it.
        self._end_branch(req)

    def _shutdown(self):
        error = RuntimeError("the server is shutting down")
        for req in list(self.active):
            self._fail(req, error)
        with self.cond:
            waiting = list(self.ingress)
            self.ingress.clear()
            asks = list(self.asks)
            self.asks.clear()
            chores = list(self.chores)
            self.chores.clear()
        for ask in asks:
            ask["done"].set()
        # What other threads wait on runs once more, so none waits forever.
        self._run_chores(chores)
        if self.sessions is not None:
            self.sessions.close(error)
        for req in waiting:
            self._end_branch(req)
            self._settle_partial(req, "error")
            req.events.put(("error", error))
        try:
            self.generator.close()
        except Exception as e:
            print(f"SCHEDULER_CLOSE_ERROR {type(e).__name__}: {e}", flush=True)


class Server:
    def __init__(self, args, tokenizer, template, generator, stop_ids, identity, memory=None):
        self.model_id = args.model_id
        self.context = args.context
        self.default_max_tokens = args.default_max_tokens
        self.tokenizer = tokenizer
        self.template = template
        self.identity = identity
        self.scheduler = Scheduler(generator, tokenizer, self.encode, stop_ids, args.max_in_flight, identity,
                                   memory)
        # Stops the HTTP server, when it runs: the native shutdown's way out.
        self.stop_serving = None
        # What a cancelled wait raises, for the native calls (exl3_ipc.py),
        # which cannot import this module: it runs as `__main__`.
        self.client_gone = ClientGone
        # The session layer, on a Generator built for it (load); None
        # otherwise, and then no session op is advertised.
        self.sessions = None
        if exl3_session is not None and isinstance(generator, exl3_session.SessionGenerator):
            self.sessions = exl3_session.SessionLayer(generator, self.render, self.encode, identity)
            self.sessions.scheduler = self.scheduler
            generator.sessions = self.sessions
            self.scheduler.sessions = self.sessions
            snapshots = self.sessions.compatibility
            print(f"SESSIONS_ON page_bytes={self.sessions.page_bytes} "
                  f"snapshots={snapshots['state'] if snapshots is not None else 'off'}", flush=True)

    def encode(self, text):
        return self.tokenizer.encode(text, encode_special_tokens=True, add_bos=False).cpu()

    def render(self, messages, tools, generation_prompt, template_kwargs=None):
        """The template's rendering of `messages` with `tools`, as every call
        is rendered: a replayed tool round's arguments as the object the
        template iterates (FIX 8328)."""
        return self.template.render(
            messages=exl3_tools.normalize_history(messages),
            add_generation_prompt=generation_prompt,
            add_vision_id=False,
            tools=tools,
            **(template_kwargs or {}),
        )

    def prepare(self, body, request_id, accepted_ns=None):
        """Renders, tokenizes and checks one request, in its handler's thread.
        `accepted_ns` is when the worker accepted it (monotonic ns)."""
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            raise RequestError("messages must be a non-empty list")
        template_kwargs = body.get("chat_template_kwargs") or {}
        if not isinstance(template_kwargs, dict):
            raise RequestError("chat_template_kwargs must be an object")
        try:
            tools = exl3_tools.tool_specs(body)
        except ValueError as e:
            raise RequestError(str(e)) from None
        # A replayed tool round's arguments go in as the object the template
        # iterates, and the request's own tools reach it (FIX 8328).
        prompt = self.render(messages, tools, True, template_kwargs)
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
        seed = optional_int(body, "seed")
        solo = body.get(SOLO_FIELD, False)
        if not isinstance(solo, bool):
            raise RequestError(f"{SOLO_FIELD} must be true or false")
        samplers = {"reason": make_sampler(body), "answer": make_sampler(body)}
        req = Request(request_id, prompt, ids, max_tokens, budget, schema, stops, seed, samplers, solo,
                      accepted_ns=accepted_ns, tools=tools)
        req.execution_mode = self.identity.execution_mode(template_kwargs, solo)
        if not req.thinking:
            req.answer_prompt = prompt
            req.answer_ids = ids
        elif req.first == "answer":
            req.answer_prompt = prompt + FORCED_CLOSE
            req.answer_ids = self.encode(req.answer_prompt)
        return req

    def shutdown(self):
        """Stops serving: the HTTP server's loop ends, and with it the
        scheduler, which fails what is left. Returns at once."""
        stop = self.stop_serving
        if stop is not None:
            threading.Thread(target=stop, name="exl3-shutdown", daemon=True).start()


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

        def _gone(self):
            return peer_gone(self.connection)

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
            req = None
            counted = False
            try:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(decode_body(self.headers.get("Content-Encoding"),
                                              self.rfile.read(length)))
                if not isinstance(body, dict):
                    raise RequestError("the body must be a JSON object")
                # Accepted: the first-token time starts here, before the
                # request is rendered, and a drain waits for it from here.
                accepted_ns = time.monotonic_ns()
                counted = state.scheduler.accept()
                if not counted:
                    raise Draining("the server is draining")
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

                def chunk(delta, finish=None):
                    return {"id": request_id, "object": "chat.completion.chunk", "created": created,
                            "model": model, "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}

                req = state.prepare(body, request_id, accepted_ns)
                # A streamed answer to a request with tools is held from its
                # first tool-call marker on (FIX 8328).
                splitter = exl3_tools.StreamSplitter(req.tools) if streaming and req.tools else None

                def delta(field, sink, split=None):
                    def emit(piece):
                        sink.append(piece)
                        if streaming:
                            out = piece if split is None else split.feed(piece)
                            if out:
                                self._sse(chunk({field: out}))
                    return emit

                state.scheduler.submit(req, self._gone)
                result = state.scheduler.wait(req, self._gone, delta("reasoning_content", reasoning),
                                              delta("content", content, splitter))
                finish = result["finish_reason"]
                if streaming:
                    if splitter is not None:
                        tail, calls = splitter.finish(finish == "stop")
                        if tail:
                            self._sse(chunk({"content": tail}))
                        if calls:
                            self._sse(chunk({"tool_calls": exl3_tools.stream_deltas(calls)}))
                            finish = "tool_calls"
                            cache_usage.mark_tool_calls(result["usage"])
                    final = chunk({}, finish)
                    final["usage"] = result["usage"]
                    final["timings"] = result["timings"]
                    self._sse(final)
                    self._chunk(b"data: [DONE]\n\n")
                    self.wfile.write(b"0\r\n\r\n")
                    self.wfile.flush()
                    self.close_connection = True
                else:
                    message, finish = exl3_tools.answer_message(reasoning, content, req.tools, finish)
                    if message.get("tool_calls"):
                        cache_usage.mark_tool_calls(result["usage"])
                    self._json(200, {"id": request_id, "object": "chat.completion", "created": created,
                                     "model": model,
                                     "choices": [{"index": 0, "message": message, "finish_reason": finish}],
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
            except (BrokenPipeError, ConnectionResetError, ClientGone):
                self.close_connection = True
            except Exception as e:
                print(f"REQUEST_ERROR {type(e).__name__}: {e}", flush=True)
                if headers_sent:
                    self.close_connection = True
                else:
                    self._json(500, {"error": {"message": f"{type(e).__name__}: {e}"}})
            finally:
                # A handler that leaves before its request's end, for any
                # reason, takes the request out of the scheduler.
                if req is not None and not req.ended:
                    state.scheduler.cancel(req)
                if counted:
                    state.scheduler.settle()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    state.stop_serving = server.shutdown
    native = None
    try:
        if args.native_socket:
            native = exl3_ipc.NativeServer(args.native_socket, state)
            native.start()
        server.serve_forever()
    finally:
        server.server_close()
        if native is not None:
            native.close()
        state.scheduler.close()


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--target-dir", required=True, help="the EXL3 4 bpw target model directory")
    p.add_argument("--weights-manifest", default=None,
                   help="the target's weights manifest (weights_manifest.py prepare); its digest is the "
                        "cache identity's model when the installed shards match it")
    p.add_argument("--draft-dir", default="", help="the DFlash2 draft model directory; empty serves without a draft")
    p.add_argument("--draft-tokens", type=int, default=7,
                   help="the draft depth: drafted tokens the target checks per step (owner ruling 2026-10-16: 7)")
    p.add_argument("--context", type=int, default=32768,
                   help="each request's context, in tokens; a multiple of 256")
    p.add_argument("--cache-tokens", type=int, default=None,
                   help="the KV pool every request in flight shares, in tokens; a multiple of 256, at least "
                        f"one full request (default: {DEFAULT_CACHE_TOKENS}, or that floor when it is larger: "
                        "--context + 1 + the draft depth + 16, rounded up to 256)")
    p.add_argument("--max-in-flight", type=int, default=DEFAULT_IN_FLIGHT,
                   help=f"requests the scheduler runs at once, 1 to {MAX_IN_FLIGHT} (default {DEFAULT_IN_FLIGHT}); "
                        f"a request that sets {SOLO_FIELD} runs alone")
    p.add_argument("--recurrent-cache-gib", type=int, default=4)
    p.add_argument("--default-max-tokens", type=int, default=4096,
                   help="the reply cap when a request names none")
    p.add_argument("--model-id", default="qwen3.8-27b", help="the id /v1/models reports")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=18091)
    p.add_argument("--launch-manifest", default=None,
                   help="the supervisor's launch manifest (FIX 8315); its digest is echoed in every receipt "
                        "and its runtime is the build, verified, when it reads")
    p.add_argument("--native-socket", default=None,
                   help="a Unix socket path the host's native calls come in on (exl3_ipc.py): its folder is "
                        "made this user's alone, the socket 0600, and only this user's processes are answered; "
                        "the HTTP routes stay")
    p.add_argument("--no-sessions", action="store_true",
                   help="serve no exact conversation sessions on the native socket (exl3_session/); by default "
                        "a target with recurrent state serves them")
    args = p.parse_args()
    serve(args, load(args))


if __name__ == "__main__":
    main()
