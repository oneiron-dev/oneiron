"""The house EXL3 worker's evaluator-only output (FIX 14975): what the host's
drafter evaluator replays a vault's held-out turns with, to judge a trained
drafter against the target alone. No serving path sends it.

One op on the native socket, `eval.generate`, advertised in the hello as
`capabilities.evaluator` (`capability`). Its frame is a `generate`'s: one
`chat_json` input region, `params` as the HTTP route takes them, and the
scheduling fields at the body's top level. Two fields are its own:

- `forced`: `{"reason"?: [ids], "answer"?: [ids]}`, token ids the pass emits
  first, as its own output, before it samples on (exllamav3's
  `constrain_output_now`): the target's continuation under a drafted arm's
  actual prefix. A pass that is forced loses its filters, as exllamav3 says.
- `evidence`: true to keep, at every generated position, the top two raw
  logits (before any sampler or mask) the position's token was taken from,
  with their token ids: on a target-only incarnation, the target alone's.

The call runs through the scheduler as any chat call does, on the
incarnation's own Generator, draft and depth, with the same rendering,
template and settings; the host asks it solo. Every generated token id is
kept pass by pass, reasoning, tool calls, answer and terminators alike, as
each Job takes it. The evidence stays on the device while the call runs and
is copied out once at its end, so it never syncs a decode step.

It is answered by ONE frame of its own name, `{outcome: "done",
finish_reason, passes: [{phase, ids, top2?}], usage, timings, elapsed_us}`,
`top2` one `[id1, logit1, id2, logit2]` per generated position; or
`{outcome: "error", error: {type, code}}`; or `refused` before anything ran.
"""
import time
import uuid

import torch

# The op this module answers.
OP = "eval.generate"
# The evaluator capability's minor.
EVALUATOR_MINOR = 1
# A thinking call's passes, in the order they run.
PHASES = ("reason", "answer")
# What `evidence` keeps at each generated position.
EVIDENCE = "top2_raw_logits"
# How many of the target's best logits the evidence keeps: the top two.
EVIDENCE_WIDTH = 2


def capability():
    """`capabilities.evaluator`: the op, and what its evidence holds."""
    return {"minor": EVALUATOR_MINOR, "ops": [OP], "evidence": EVIDENCE, "forced": list(PHASES)}


class EvaluationRefused(Exception):
    """An evaluation field this worker cannot read: refused before anything
    ran."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def parse(body):
    """The call's forced ids by pass, and whether it keeps evidence;
    EvaluationRefused for a field that does not read."""
    forced = body.get("forced") or {}
    if not isinstance(forced, dict) or set(forced) - set(PHASES):
        raise EvaluationRefused("invalid_request", "forced names reason or answer ids only")
    for ids in forced.values():
        if not isinstance(ids, list) or not ids or not all(type(i) is int and i >= 0 for i in ids):
            raise EvaluationRefused("invalid_request", "forced ids are a non-empty list of token ids")
    evidence = body.get("evidence", False)
    if not isinstance(evidence, bool):
        raise EvaluationRefused("invalid_request", "evidence must be true or false")
    return {phase: list(ids) for phase, ids in forced.items()}, evidence


def materialize(top2):
    """A pass's evidence on the host, copied out in one go: one
    `[id1, logit1, id2, logit2]` per position, None where a position kept
    none."""
    present = [entry for entry in top2 if entry is not None]
    if not present:
        return [None] * len(top2)
    ids = torch.stack([entry[0] for entry in present]).cpu().tolist()
    values = torch.stack([entry[1] for entry in present]).float().cpu().tolist()
    rows = iter(zip(ids, values))
    out = []
    for entry in top2:
        if entry is None:
            out.append(None)
            continue
        pair, logits = next(rows)
        out.append([int(pair[0]), float(logits[0]), int(pair[1]), float(logits[1])])
    return out


class Recording:
    """What one evaluation call's Jobs generated, pass by pass: every token
    id each took, and with `evidence` the top two raw logits it was taken
    from. The owner thread alone writes it."""

    def __init__(self, evidence):
        self.evidence = evidence
        self.phase = None
        self.ids = {}
        self.top2 = {}

    def begin(self, phase):
        self.phase = phase
        self.ids[phase] = []
        self.top2[phase] = []

    def take(self, token, top2):
        if self.phase is None:
            return
        self.ids[self.phase].append(token)
        if self.evidence:
            self.top2[self.phase].append(top2)

    def passes(self):
        out = []
        for phase in PHASES:
            if phase not in self.ids:
                continue
            row = {"phase": phase, "ids": self.ids[phase]}
            if self.evidence:
                row["top2"] = materialize(self.top2[phase])
            out.append(row)
        return out


class RecordingMixin:
    """A Job mixin, put first: it keeps the token each position takes and,
    with evidence, the top two raw logits of that position, in the call's
    Recording. A requeue runs `__init__` again on the same object; the
    recording is kept."""

    def __init__(self, *args, recording=None, **kwargs):
        kept = recording if recording is not None else getattr(self, "recording", None)
        super().__init__(*args, **kwargs)
        self.recording = kept
        self.pending_top2 = None

    def receive_logits(self, logits):
        recording = self.recording
        if recording is not None and recording.evidence:
            values, ids = torch.topk(logits.flatten().float(), EVIDENCE_WIDTH)
            self.pending_top2 = (ids, values)
        return super().receive_logits(logits)

    def receive_sample(self, *args, **kwargs):
        recording = self.recording
        token = args[1] if len(args) > 1 else kwargs.get("next_token")
        if recording is not None and token is not None and self.new_tokens >= 0:
            recording.take(int(token.flatten()[0].item()), self.pending_top2)
        self.pending_top2 = None
        return super().receive_sample(*args, **kwargs)


# The evaluator Job class of each base the scheduler builds Jobs from.
_JOB_CLASSES = {}


class EvaluationHook:
    """A request's evaluator side, as the scheduler sees it (`req.evaluation`):
    the Job class each pass is built from, the ids each pass is forced to
    first, and the recording."""

    def __init__(self, forced, evidence):
        self.forced = forced
        self.recording = Recording(evidence)

    def job(self, base, fields, phase):
        """`phase`'s Job: the base the scheduler would build, recording."""
        cls = _JOB_CLASSES.get(base)
        if cls is None:
            cls = type("Evaluator" + base.__name__, (RecordingMixin, base), {})
            _JOB_CLASSES[base] = cls
        self.recording.begin(phase)
        return cls(recording=self.recording, **fields)

    def enqueued(self, job, phase):
        """Forces `phase`'s ids once its Job is enqueued."""
        ids = self.forced.get(phase)
        if ids:
            job.constrain_output_now(torch.tensor([ids], dtype=torch.long))


def ignore(_piece):
    return None


def run(state, params, conversation, forced, evidence, work, gone):
    """Runs one evaluation call through the scheduler to its end, and
    returns its answer frame's body. Raises what the scheduler raised;
    `gone` says the host has left."""
    scheduler = state.scheduler
    body = dict(params)
    body["messages"] = conversation["messages"]
    if "tools" in conversation:
        body["tools"] = conversation["tools"]
    accepted_ns = time.monotonic_ns()
    req = state.prepare(body, "eval-" + uuid.uuid4().hex, accepted_ns, work=work)
    hook = EvaluationHook(forced, evidence)
    req.evaluation = hook
    try:
        scheduler.submit(req, gone)
        result = scheduler.wait(req, gone, ignore, ignore)
    finally:
        if not req.ended:
            scheduler.cancel(req)
    return {
        "outcome": "done",
        "finish_reason": result["finish_reason"],
        "passes": hook.recording.passes(),
        "usage": result["usage"],
        "timings": result["timings"],
        "elapsed_us": (time.monotonic_ns() - accepted_ns) // 1000,
    }
