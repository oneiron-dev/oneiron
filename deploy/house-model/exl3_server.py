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
import weights_manifest
from body_codec import UnsupportedEncoding, decode_body
from jinja2 import Environment
from exllamav3 import Cache, CacheLayer_quant, Config, Generator, Job, LLGuidanceFilter, Model, Tokenizer
from exllamav3.generator.sampler import ComboSampler

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

    generator = Generator(target, target_cache, tokenizer, max_batch_size=batch,
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
    print(f"SERVER_READY model={args.model_id} context={args.context} cache_tokens={cache_tokens} "
          f"in_flight={batch} depth={depth} stop_ids={sorted(stop_ids)}", flush=True)
    return Server(args, tokenizer, template, generator, sorted(stop_ids), identity)


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
    reasoning and content pieces, then one of done, error or cancelled) and in
    `cancelled` (handler to scheduler). `ended` is the handler's own: it saw
    the terminal event."""

    def __init__(self, request_id, prompt, ids, max_tokens, budget, schema, stops, seed, samplers, solo):
        # Inputs.
        self.request_id = request_id
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
        self.timings = {"prefill": 0.0, "generate": 0.0, "enqueued": 0.0, "accepted": 0, "rejected": 0}
        # Each ended Job's pass, from its final event, in order (FIX 6567).
        self.passes = []


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
    has ended, then goes in alone; the requests behind it wait for it."""

    def __init__(self, generator, tokenizer, encode, stop_ids, max_in_flight, identity):
        self.generator = generator
        self.tokenizer = tokenizer
        self.encode = encode
        self.stop_ids = stop_ids
        self.max_in_flight = max_in_flight
        self.identity = identity
        self.depth = int(generator.num_draft_tokens)
        self.pool_pages = int(generator.pagetable.max_pages)
        # Shared with the handlers, under `cond`.
        self.cond = threading.Condition()
        self.ingress = collections.deque()
        self.pokes = 0
        self.closing = False
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
        # generator's own check then decides it, as it did before.
        req.need = min(pages_for(need, req.max_tokens, self.depth), self.pool_pages)
        req.submitted = time.monotonic()
        with self.cond:
            while len(self.ingress) >= INGRESS_CAPACITY and not self.closing:
                self.cond.wait(DISCONNECT_POLL_S)
                if len(self.ingress) >= INGRESS_CAPACITY and gone():
                    raise ClientGone()
            if self.closing:
                raise RuntimeError("the server is shutting down")
            self.ingress.append(req)
            self.pokes += 1
            self.cond.notify_all()

    def wait(self, req, gone, on_reasoning, on_content):
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

    def close(self, timeout=10.0):
        with self.cond:
            self.closing = True
            self.cond.notify_all()
        self.thread.join(timeout)

    # The owner thread's side.

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
        if len(in_flight) >= self.max_in_flight:
            return False
        head = self.ingress[0]
        if any(req.solo for req in in_flight) or (head.solo and in_flight):
            return False
        return self.reserved + head.need <= self.pool_pages

    def _idle_locked(self):
        """True when a pass would do nothing: no job to iterate, no answer
        pass waiting for pages, and no request the head of ingress could
        admit. While the scheduler drains for a solo request it is busy with
        the jobs it waits on, and the pass after the last one ends admits it.
        Called under `cond`, from the owner thread."""
        if self.generator.num_remaining_jobs() or any(req.grow for req in self.active):
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
            try:
                for req in dropped:
                    req.events.put(("cancelled", None))
                self._pass()
            except Exception as e:
                # A fault in this loop rather than in one job: fail what is in
                # flight, never leave it parked.
                print(f"SCHEDULER_ERROR {type(e).__name__}: {e}", flush=True)
                for req in list(self.active):
                    self._fail(req, e)
        self._shutdown()

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
        if not self.generator.num_remaining_jobs():
            return
        try:
            results = self.generator.iterate()
        except Exception as e:
            # Not one job's error: every request with a job fails.
            print(f"GENERATOR_ERROR {type(e).__name__}: {e}", flush=True)
            for req in [req for req in self.active if req.job is not None]:
                self._fail(req, e)
            return
        self._route(results)
        if not results and not self.generator.num_active_jobs() and self.generator.num_pending_jobs():
            with self.cond:
                self.cond.wait(STALL_WAIT_S)

    def _reap_cancelled(self):
        for req in [req for req in self.active if req.cancelled.is_set()]:
            self._drop_job(req)
            self._release(req)
            # Cancelling a job emits no end event: wake the handler here.
            req.events.put(("cancelled", None))

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
        now = time.monotonic()
        for req in admitted:
            req.admission_wait = now - req.submitted
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
            job = Job(
                input_ids=ids,
                max_new_tokens=max_new_tokens,
                seed=req.seed,
                sampler=req.samplers[phase],
                stop_conditions=self.stop_ids + stops,
                decode_special_tokens=False,
                filters=filters,
                identifier=(req.request_id, phase),
            )
            serial = self.generator.enqueue(job)
        except Exception as e:
            self._fail(req, e)
            return
        req.job = job
        self.by_serial[serial] = req

    def _begin_answer(self, req):
        left = req.max_tokens - req.spent
        if left < 1:
            self._finish(req, "length")
            return
        if req.answer_ids is None:
            req.answer_ids = self.encode(req.answer_prompt)
        req.left = left
        need = min(pages_for(int(req.answer_ids.numel()), left, self.depth), self.pool_pages)
        req.grow = max(0, need - req.pages)
        req.grow_since = time.monotonic()
        self._try_answer(req)

    def _try_answer(self, req, force=False):
        """Enqueues `req`'s answer job once its pages fit; until then it waits,
        holding its place. `force` enqueues it past the reservations when no
        job holds a page."""
        if req.grow:
            if self.reserved + req.grow > self.pool_pages and not force:
                return
            self.reserved += req.grow
            req.pages += req.grow
            req.grow = 0
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
        req.spent += int(final.get("new_tokens", 0))
        timings = req.timings
        timings["prefill"] += float(final.get("time_prefill", 0.0))
        timings["generate"] += float(final.get("time_generate", 0.0))
        timings["enqueued"] += float(final.get("time_enqueued", 0.0))
        timings["accepted"] += int(final.get("accepted_draft_tokens", 0))
        timings["rejected"] += int(final.get("rejected_draft_tokens", 0))
        reason = final.get("eos_reason")
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

    def _finish(self, req, finish):
        timings = req.timings
        prompt_tokens = req.prompt_tokens
        spent = req.spent
        usage = {"prompt_tokens": prompt_tokens, "completion_tokens": spent,
                 "total_tokens": prompt_tokens + spent}
        cache_usage.add_evidence(usage, prompt_tokens, req.passes, self.identity.record(req.execution_mode),
                                 worker_wait_s=req.admission_wait,
                                 engine_wait_s=timings["enqueued"] + req.page_wait,
                                 build_evidence=self.identity.build_evidence,
                                 launch_manifest=self.identity.launch_manifest)
        stats = {
            "prompt_n": prompt_tokens,
            "prompt_per_second": prompt_tokens / timings["prefill"] if timings["prefill"] > 0 else None,
            "predicted_n": spent,
            "predicted_per_second": spent / timings["generate"] if timings["generate"] > 0 else None,
            "draft_n": timings["accepted"] + timings["rejected"],
            "draft_n_accepted": timings["accepted"],
            # Submitted to admitted, including any wait for an ingress place.
            "admission_wait_ms": req.admission_wait * 1000.0,
            # Each job's own enqueue-to-start, and the answer's wait for pages.
            "enqueue_wait_ms": (timings["enqueued"] + req.page_wait) * 1000.0,
            "draft_depth": self.depth,
            "max_in_flight": self.max_in_flight,
            # The most requests in flight at once while this one was.
            "peak_in_flight": req.peak,
        }
        self._release(req)
        req.events.put(("done", {"usage": usage, "timings": stats, "finish_reason": finish}))

    def _fail(self, req, error):
        self._drop_job(req)
        self._release(req)
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

    def _shutdown(self):
        error = RuntimeError("the server is shutting down")
        for req in list(self.active):
            self._fail(req, error)
        with self.cond:
            waiting = list(self.ingress)
            self.ingress.clear()
        for req in waiting:
            req.events.put(("error", error))
        try:
            self.generator.close()
        except Exception as e:
            print(f"SCHEDULER_CLOSE_ERROR {type(e).__name__}: {e}", flush=True)


class Server:
    def __init__(self, args, tokenizer, template, generator, stop_ids, identity):
        self.model_id = args.model_id
        self.context = args.context
        self.default_max_tokens = args.default_max_tokens
        self.tokenizer = tokenizer
        self.template = template
        self.identity = identity
        self.scheduler = Scheduler(generator, tokenizer, self.encode, stop_ids, args.max_in_flight, identity)

    def encode(self, text):
        return self.tokenizer.encode(text, encode_special_tokens=True, add_bos=False).cpu()

    def prepare(self, body, request_id):
        """Renders, tokenizes and checks one request, in its handler's thread."""
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
        seed = optional_int(body, "seed")
        solo = body.get(SOLO_FIELD, False)
        if not isinstance(solo, bool):
            raise RequestError(f"{SOLO_FIELD} must be true or false")
        samplers = {"reason": make_sampler(body), "answer": make_sampler(body)}
        req = Request(request_id, prompt, ids, max_tokens, budget, schema, stops, seed, samplers, solo)
        req.execution_mode = self.identity.execution_mode(template_kwargs, solo)
        if not req.thinking:
            req.answer_prompt = prompt
            req.answer_ids = ids
        elif req.first == "answer":
            req.answer_prompt = prompt + FORCED_CLOSE
            req.answer_ids = self.encode(req.answer_prompt)
        return req


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

                req = state.prepare(body, request_id)
                state.scheduler.submit(req, self._gone)
                result = state.scheduler.wait(req, self._gone, delta("reasoning_content", reasoning),
                                              delta("content", content))
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

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    try:
        server.serve_forever()
    finally:
        server.server_close()
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
    args = p.parse_args()
    serve(args, load(args))


if __name__ == "__main__":
    main()
