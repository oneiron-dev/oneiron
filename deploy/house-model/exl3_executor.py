"""The house EXL3 worker's priority-aware executor (DESIGN-V2 R4, scheduling
v1.3): which of the Jobs the scheduler admitted run in each engine round.

The owner thread admits requests as before (exl3_server.py): up to four in
flight, paused ones and session commits included, each only when its pages
fit, a solo request alone. Under the `class_deadline_v1` policy it then
chooses, every engine round, the Jobs the round runs (prefill, decode and
verify alike) by work class, foreground before background, then priority,
then the earliest deadline, then arrival. While foreground work is present,
waiting or in flight, at most BACKGROUND_ACTIVE_LIMIT background Jobs run in
a round, round-robin among the equally ranked, and no more background work
is admitted than that; with no foreground work present, background work
uses every place, as before. While foreground work is present, a background
Job's prefill runs at most PREFILL_CHUNK_TOKENS in a round; otherwise, and for
a foreground Job always, prefill runs the Generator's own chunk, as before. After EXECUTION_ROUNDS_PER_GRANT rounds the executor
chooses again.

The hook is the pinned exllamav3 1.6.0 `Generator.iterate`
(generator/generator.py:459-579): it starts pending Jobs
(`iterate_start_jobs`, 540), runs one prefill chunk for each active Job
(543-547), then one decode or verify pass over every active Job whose
prefill is done (553-572). ExecutorMixin runs the stock start with every
active Job in view, so the batch and recurrent-slot limits count them all,
then leaves the Jobs it did not choose out of `active_jobs` for the rest of
that one iterate, and puts them back in their order when it returns. A Job
left out is paused: it keeps its pages, its recurrent slot, its RNG, its
serial, its filters and its copy-on-write pages, is never cancelled or
enqueued again, and runs again in the round it is chosen. `num_remaining_jobs`
still counts it, so the stock idle housekeeping (`on_queue_drained`, whose
defragmentation asserts no referenced page, pagetable.py:835) never runs
under it. Nothing is preempted inside a round: a round runs to its end.

A prefill chunk's bound is the Generator's `max_chunk_size`, which the
stock `Job.prefill` reads for the chunk's end and floors to a page
(job.py:1367-1368): ScheduledJob sets it for its own prefill only. A session
frontier between page boundaries already runs at most one page
(`exl3_session/jobs.py`).

The host's `schedule` op pauses a call (`yield`) until it `resume`s, or
changes its class, priority or deadline (`reprioritize`); the owner thread
applies it between rounds, and the acknowledgement says so. A paused call
keeps its place and pages: a pause frees execution, never memory
(PAUSE_EVICTS_STATE).

Under the `fifo` policy (`--scheduling-policy fifo`) the Generator is the
stock one and every active Job runs every round, as before R4; the fields
are still read, checked and reported, and change nothing.
"""
import itertools
import math
import threading
import time

# The scheduling codec minor this worker speaks (`capabilities.scheduling`).
SCHEDULING_MINOR = 3
# The policies, by the name the hello advertises.
CLASS_DEADLINE_POLICY = "class_deadline_v1"
FIFO_POLICY = "fifo"
POLICIES = (CLASS_DEADLINE_POLICY, FIFO_POLICY)
DEFAULT_POLICY = CLASS_DEADLINE_POLICY
# The most prompt tokens a background Job's prefill runs in one round while
# foreground work is present: one cache page, a prompt's last chunk shorter.
# Unmeasured start.
PREFILL_CHUNK_TOKENS = 256
# Engine rounds one choice of Jobs runs before the executor chooses again.
EXECUTION_ROUNDS_PER_GRANT = 1
# Background units (Jobs, commits) that run in a round, and that are
# admitted, while foreground work is present. Unmeasured start.
BACKGROUND_ACTIVE_LIMIT = 1
# Pages a snapshot transfer copies on the owner thread at a time while
# foreground work is present; with none, it copies at once, as before.
TRANSFER_CHUNK_PAGES = 1
# The work classes, by their wire names.
FOREGROUND = "foreground"
BACKGROUND = "background"
WORK_CLASSES = (FOREGROUND, BACKGROUND)
# A call that names no class keeps the standing every call had before R4.
DEFAULT_WORK_CLASS = FOREGROUND
PRIORITIES = (0, 1)
DEFAULT_PRIORITY = 0
DEFAULT_DEADLINE = None
# The HTTP route takes no scheduling field: an HTTP call runs at the
# defaults, so no caller promotes itself.
HTTP_PRIORITY_OVERRIDE = False
# What a call with no admission grant gets: admitted, and counted.
ADMIT_AND_COUNT = "admit_and_count"
REFUSE = "refuse"
MISSING_SHARED_DEVICE_GRANT = ADMIT_AND_COUNT
# A pause keeps the Job's pages and state on the device.
PAUSE_EVICTS_STATE = False
# The resource classes a grant may name; this worker serves chat.
RESOURCE_CLASSES = ("chat", "encoder", "embedder", "asr", "tts")
RESOURCE_CLASS = "chat"
# The `schedule` op's actions.
YIELD = "yield"
RESUME = "resume"
REPRIORITIZE = "reprioritize"
ACTIONS = (YIELD, RESUME, REPRIORITIZE)
# An admission grant's fields, every one named.
GRANT_FIELDS = frozenset(("grant_id", "revision", "resource_class", "profile_id", "envelope_mib"))
# Where a change takes effect: the next engine round.
BOUNDARY = "engine_round"
U64_MAX = (1 << 64) - 1

# Arrival order, across every call this process takes.
_ARRIVALS = itertools.count()


class SchedulingError(ValueError):
    """A scheduling field this worker refuses before any work, with its
    refusal code."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class ReleaseFailed(RuntimeError):
    """A call whose Job the Generator could not cancel: its pages, place and
    reservation stay charged until the Generator ends the Job itself, or the
    process is reaped. Its call ends with this error, never `released`."""

    code = "release_failed"


def _is_u64(value):
    return type(value) is int and 0 <= value <= U64_MAX


def _invalid(message):
    return SchedulingError("invalid_request", message)


def work_fields(body, now_ns):
    """The class, priority and deadline `body` names, each only when present:
    a `deadline` is the microseconds left at send, converted once to this
    process's monotonic clock; a null one is none."""
    fields = {}
    work_class = body.get("work_class")
    if work_class is not None:
        if work_class not in WORK_CLASSES:
            raise _invalid("work_class must be foreground or background")
        fields["work_class"] = work_class
    priority = body.get("priority")
    if priority is not None:
        if type(priority) is not int or priority not in PRIORITIES:
            raise _invalid("priority must be 0 or 1")
        fields["priority"] = priority
    if "deadline" in body:
        deadline = body["deadline"]
        if deadline is None:
            fields["deadline_ns"] = None
        elif _is_u64(deadline):
            fields["deadline_ns"] = now_ns + deadline * 1000
        else:
            raise _invalid("deadline must be null or the microseconds left, a u64")
    return fields


def parse_grant(value):
    """A call's `admission` grant, checked: `{grant_id, revision,
    resource_class, profile_id, envelope_mib}`, for this worker's class.
    None when the call carries none."""
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != GRANT_FIELDS:
        raise SchedulingError("invalid_grant",
                              "admission must be {grant_id, revision, resource_class, profile_id, envelope_mib}")
    if not _is_u64(value["grant_id"]) or not _is_u64(value["revision"]):
        raise SchedulingError("invalid_grant", "a grant's id and revision are u64s")
    if value["resource_class"] not in RESOURCE_CLASSES:
        raise SchedulingError("invalid_grant", f"resource_class must be one of {', '.join(RESOURCE_CLASSES)}")
    if value["resource_class"] != RESOURCE_CLASS:
        raise SchedulingError("invalid_grant", f"this worker serves {RESOURCE_CLASS}")
    if not isinstance(value["profile_id"], str) or not value["profile_id"]:
        raise SchedulingError("invalid_grant", "a grant names its profile")
    if not _is_u64(value["envelope_mib"]) or value["envelope_mib"] < 1:
        raise SchedulingError("invalid_grant", "a grant's envelope is a positive MiB count")
    return dict(value)


class WorkContext:
    """One call's place in the executor's order: its class, priority,
    deadline (monotonic ns, or None), grant, revision, and whether the host
    paused it. Made where the call is accepted; from then on only the owner
    thread changes it."""

    def __init__(self, work_class=DEFAULT_WORK_CLASS, priority=DEFAULT_PRIORITY, deadline_ns=DEFAULT_DEADLINE,
                 grant=None):
        self.work_class = work_class
        self.priority = priority
        self.deadline_ns = deadline_ns
        self.grant = grant
        self.revision = grant["revision"] if grant is not None else 0
        self.yielded = False
        self.yields = 0
        self.arrival = next(_ARRIVALS)

    @classmethod
    def from_body(cls, body, now_ns):
        """The context a native call's body names; SchedulingError for a
        field this worker refuses."""
        return cls(grant=parse_grant(body.get("admission")), **work_fields(body, now_ns))

    def arrive(self):
        """Takes the call's place in arrival order: where it enters the
        scheduler's queue, as the queue always ordered calls."""
        self.arrival = next(_ARRIVALS)

    def foreground(self):
        return self.work_class == FOREGROUND

    def rank(self):
        """The order key: class, then priority, then the earliest deadline
        (none last), then arrival."""
        deadline = self.deadline_ns if self.deadline_ns is not None else math.inf
        return (0 if self.foreground() else 1, -self.priority, deadline, self.arrival)

    def evidence(self, now_ns):
        """What a receipt says of the context now; a deadline as the
        microseconds left, negative once it has passed."""
        out = {"work_class": self.work_class, "priority": self.priority, "revision": self.revision,
               "paused": self.yielded}
        if self.deadline_ns is not None:
            out["deadline_remaining_us"] = (self.deadline_ns - now_ns) // 1000
        if self.grant is not None:
            out["grant_id"] = self.grant["grant_id"]
            out["profile_id"] = self.grant["profile_id"]
            out["envelope_mib"] = self.grant["envelope_mib"]
        return out


def http_context(body, now_ns):
    """An HTTP call's context: the defaults, unless HTTP_PRIORITY_OVERRIDE
    lets its body name one."""
    return WorkContext.from_body(body, now_ns) if HTTP_PRIORITY_OVERRIDE else WorkContext()


class ScheduleUpdate:
    """One `schedule` op's change, checked: its revision, action and, for
    `reprioritize`, the fields it names."""

    __slots__ = ("revision", "action", "fields")

    def __init__(self, body, now_ns):
        if not _is_u64(body.get("revision")):
            raise _invalid("revision must be a u64")
        if body.get("action") not in ACTIONS:
            raise _invalid("action must be yield, resume or reprioritize")
        self.revision = body["revision"]
        self.action = body["action"]
        self.fields = work_fields(body, now_ns)
        if self.action != REPRIORITIZE and self.fields:
            raise _invalid("only reprioritize changes the class, priority or deadline")
        if self.action == REPRIORITIZE and not self.fields:
            raise _invalid("reprioritize names a class, a priority or a deadline")


class ExecutionRecord:
    """What the executor did with one call's Jobs (a request's passes share
    one, as they never run at once): the rounds they ran, the rounds they
    were left out by the policy or paused by the host, how long they were
    paused, and their prefill chunks."""

    def __init__(self):
        self.rounds_run = 0
        self.rounds_withheld = 0
        self.rounds_yielded = 0
        self.last_round = -1
        self.paused_since = None
        self.paused_ns = 0
        self.prefill_chunks = 0
        self.prefill_tokens_max = 0

    def ran(self, round_number, now_ns):
        self.rounds_run += 1
        self.last_round = round_number
        if self.paused_since is not None:
            self.paused_ns += now_ns - self.paused_since
            self.paused_since = None

    def paused(self, now_ns, yielded):
        if yielded:
            self.rounds_yielded += 1
        else:
            self.rounds_withheld += 1
        if self.paused_since is None:
            self.paused_since = now_ns

    def prefilled(self, tokens):
        if tokens > 0:
            self.prefill_chunks += 1
            self.prefill_tokens_max = max(self.prefill_tokens_max, tokens)

    def receipt(self, now_ns):
        paused = self.paused_ns + (now_ns - self.paused_since if self.paused_since is not None else 0)
        return {"rounds_run": self.rounds_run, "rounds_withheld": self.rounds_withheld,
                "rounds_yielded": self.rounds_yielded, "paused_us": paused // 1000,
                "prefill_chunks": self.prefill_chunks, "prefill_chunk_tokens_max": self.prefill_tokens_max}


class ScheduledJob:
    """The executor's Job mixin: put it first, before a session mixin and the
    stock Job. It carries the call's context and execution record, and
    bounds its own prefill to the round's chunk."""

    def __init__(self, *args, work=None, execution=None, **kwargs):
        # A requeue runs __init__ again on the same object: both are kept.
        kept_work = work if work is not None else getattr(self, "work", None)
        kept_execution = execution if execution is not None else getattr(self, "execution", None)
        stranded = getattr(self, "stranded", False)
        super().__init__(*args, **kwargs)
        self.work = kept_work
        self.execution = kept_execution if kept_execution is not None else ExecutionRecord()
        # This round's prefill bound in tokens, or None for the Generator's.
        self.prefill_bound = None
        # A Job the Generator could not cancel: it runs out at the lowest
        # rank, and its call's charges stay until it ends (ReleaseFailed).
        self.stranded = stranded

    def prefill(self, results):
        before = sum(seq.kv_position for seq in self.sequences)
        bound = self.prefill_bound
        if bound is None:
            super().prefill(results)
        else:
            generator = self.generator
            chunk = generator.max_chunk_size
            generator.max_chunk_size = min(chunk, bound)
            try:
                super().prefill(results)
            finally:
                generator.max_chunk_size = chunk
        self.execution.prefilled(sum(seq.kv_position for seq in self.sequences) - before)


def job_foreground(job):
    """Whether `job` runs as foreground work: its context's class, the
    default for a Job with none, and never once it is stranded."""
    if getattr(job, "stranded", False):
        return False
    work = getattr(job, "work", None)
    return work is None or work.foreground()


def job_yielded(job):
    work = getattr(job, "work", None)
    return work is not None and work.yielded and not getattr(job, "stranded", False)


def _background_order(job):
    """Background Jobs' order for the round's places: stranded last, then
    priority and deadline, then the one that ran least recently."""
    work = getattr(job, "work", None)
    execution = getattr(job, "execution", None)
    priority = work.priority if work is not None else DEFAULT_PRIORITY
    deadline = work.deadline_ns if work is not None and work.deadline_ns is not None else math.inf
    last = execution.last_round if execution is not None else -1
    arrival = work.arrival if work is not None else 0
    return (getattr(job, "stranded", False), -priority, deadline, last, arrival)


class Executor:
    """The policy and its counts. The owner thread chooses each round's
    Jobs and applies the host's updates; the native channel's threads check
    and count grants, under `lock`."""

    def __init__(self, policy=DEFAULT_POLICY):
        if policy not in POLICIES:
            raise ValueError(f"the scheduling policy must be one of {', '.join(POLICIES)}")
        self.policy = policy
        self.prioritized = policy == CLASS_DEADLINE_POLICY
        self.lock = threading.Lock()
        # The grants of calls still open: id -> [highest revision, calls].
        self.grants = {}
        self.counts = {"granted_calls": 0, "ungranted_calls": 0, "refused_grants": 0, "applied_updates": 0,
                       "refused_updates": 0}
        # The owner thread's.
        self.round = 0
        self.revision = 0
        self.foreground_present = False
        # The last round's Jobs: run, left out by the policy, paused.
        self.ran = 0
        self.withheld = 0
        self.yielded = 0
        self.choice = None
        self.choice_key = None
        self.chosen_round = 0

    def capability(self):
        """`capabilities.scheduling`: only what this policy does."""
        return {"minor": SCHEDULING_MINOR, "policy": self.policy, "chunked_prefill": self.prioritized,
                "update": self.prioritized}

    # Grants, on the native channel's threads.

    def open_grant(self, work):
        """Counts one call's grant from its acceptance to `close_grant`;
        SchedulingError `stale_grant` for a revision below one this worker
        has seen for that grant while a call holds it. A call with none is
        admitted and counted (MISSING_SHARED_DEVICE_GRANT)."""
        grant = work.grant
        with self.lock:
            if grant is None:
                if MISSING_SHARED_DEVICE_GRANT == REFUSE:
                    raise SchedulingError("missing_grant", "this worker takes only granted calls")
                self.counts["ungranted_calls"] += 1
                return
            held = self.grants.get(grant["grant_id"])
            if held is not None and work.revision < held[0]:
                self.counts["refused_grants"] += 1
                raise SchedulingError("stale_grant", f"grant {grant['grant_id']} is at revision {held[0]}")
            if held is None:
                self.grants[grant["grant_id"]] = [work.revision, 1]
            else:
                held[1] += 1
            self.counts["granted_calls"] += 1

    def close_grant(self, work):
        grant = work.grant
        if grant is None:
            return
        with self.lock:
            held = self.grants.get(grant["grant_id"])
            if held is not None:
                held[1] -= 1
                if held[1] <= 0:
                    del self.grants[grant["grant_id"]]

    # The owner thread's side.

    def apply(self, work, update):
        """Applies `update` to `work` between rounds: True, or False when its
        revision is not above the call's."""
        if update.revision <= work.revision:
            self.counts["refused_updates"] += 1
            return False
        work.revision = update.revision
        if update.action == YIELD:
            work.yielded = True
            work.yields += 1
        elif update.action == RESUME:
            work.yielded = False
        else:
            for name, value in update.fields.items():
                setattr(work, name, value)
        self.revision = max(self.revision, update.revision)
        self.counts["applied_updates"] += 1
        self.choice = None
        if work.grant is not None:
            with self.lock:
                held = self.grants.get(work.grant["grant_id"])
                if held is not None:
                    held[0] = max(held[0], update.revision)
        return True

    def runnable(self, job):
        """Whether the policy may run `job` at all: every Job under FIFO;
        under the class policy, every one the host has not paused."""
        return not self.prioritized or not job_yielded(job)

    def runnable_jobs(self, generator):
        """The Jobs a round could run: pending, and active ones not paused."""
        return generator.num_pending_jobs() + sum(1 for job in generator.active_jobs if self.runnable(job))

    def choose(self, jobs):
        """The Jobs of active `jobs` this round runs, in their order: every
        foreground one, and the background ones the policy lets in. Sets
        each chosen Job's prefill bound, and records every Job's round."""
        self.round += 1
        now = time.monotonic_ns()
        # A choice holds for its rounds while the Jobs and the foreground's
        # presence stay as they were.
        key = (frozenset(id(job) for job in jobs), self.foreground_present)
        if self.choice is None or self.round - self.chosen_round >= EXECUTION_ROUNDS_PER_GRANT \
                or key != self.choice_key:
            runnable = [job for job in jobs if self.runnable(job)]
            background = [job for job in runnable if not job_foreground(job)]
            if self.foreground_present and len(background) > BACKGROUND_ACTIVE_LIMIT:
                background = sorted(background, key=_background_order)[:BACKGROUND_ACTIVE_LIMIT]
            self.choice = {id(job) for job in runnable if job_foreground(job)} | {id(job) for job in background}
            self.choice_key = key
            self.chosen_round = self.round
        chosen = []
        self.withheld = self.yielded = 0
        self.ran = len(self.choice & key[0])
        for job in jobs:
            execution = getattr(job, "execution", None)
            if id(job) in self.choice:
                if hasattr(job, "prefill_bound"):
                    yields = self.foreground_present and not job_foreground(job)
                    job.prefill_bound = PREFILL_CHUNK_TOKENS if yields else None
                if execution is not None:
                    execution.ran(self.round, now)
                chosen.append(job)
                continue
            yielded = job_yielded(job)
            if yielded:
                self.yielded += 1
            else:
                self.withheld += 1
            if execution is not None:
                execution.paused(now, yielded)
        return chosen

    def transfer_chunk(self, work):
        """The pages a snapshot transfer of `work`'s class copies on the
        owner thread at a time now: TRANSFER_CHUNK_PAGES for background work
        while foreground work is present under the class policy; None, all
        at once, as before, otherwise."""
        if self.prioritized and self.foreground_present and not work.foreground():
            return TRANSFER_CHUNK_PAGES
        return None

    def stats(self):
        """The policy's state for a stats snapshot, on the owner thread."""
        with self.lock:
            counts = dict(self.counts)
            open_grants = len(self.grants)
        return dict(counts, policy=self.policy, minor=SCHEDULING_MINOR, round=self.round,
                    next_boundary={"kind": BOUNDARY, "round": self.round + 1}, revision=self.revision,
                    foreground_present=self.foreground_present, jobs_withheld=self.withheld,
                    jobs_yielded=self.yielded, open_grants=open_grants,
                    prefill_chunk_tokens=PREFILL_CHUNK_TOKENS if self.prioritized else None,
                    background_active_limit=BACKGROUND_ACTIVE_LIMIT if self.prioritized else None,
                    transfer_chunk_pages=TRANSFER_CHUNK_PAGES if self.prioritized else None,
                    pause_evicts_state=PAUSE_EVICTS_STATE)


class ExecutorMixin:
    """The Generator mixin: put it before the stock Generator or the session
    layer's. With `executor` set, each iterate runs only the Jobs it
    chooses; with None, the Generator is stock."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executor = None
        # The Jobs left out of the iterate in progress, and every active Job
        # in its order before it; empty and None between iterates.
        self.withheld_jobs = []
        self.round_order = None

    def num_remaining_jobs(self):
        return super().num_remaining_jobs() + len(self.withheld_jobs)

    def iterate_start_jobs(self, results):
        super().iterate_start_jobs(results)
        executor = self.executor
        if executor is None:
            return
        jobs = self.active_jobs
        chosen = executor.choose(jobs)
        if len(chosen) == len(jobs):
            return
        picked = {id(job) for job in chosen}
        self.round_order = list(jobs)
        self.withheld_jobs = [job for job in jobs if id(job) not in picked]
        self.active_jobs = chosen

    def iterate(self):
        try:
            return super().iterate()
        finally:
            order = self.round_order
            if order is not None:
                kept = {id(job) for job in self.active_jobs} | {id(job) for job in self.withheld_jobs}
                self.active_jobs = [job for job in order if id(job) in kept]
                self.withheld_jobs = []
                self.round_order = None


def scheduled_generator(base):
    """`base`, the stock Generator or the session layer's, with the
    executor's mixin before it."""
    return type("Scheduled" + base.__name__, (ExecutorMixin, base), {})
