"""The inference receipt the house EXL3 server returns in each reply's
`usage` (FIX 6567, INF 2 step 1; FIX 8314, INFERENCE R1).

Every Job the scheduler runs for a request is one pass over an input: a
thinking request's reasoning pass over its prompt, then its answer pass over
the prompt with the thought closed (re-encoded); any other request's one pass
over its prompt. exllamav3's final event of each Job reports that input
(`prompt_tokens`), the part of it read from the cache (`cached_tokens`, whole
pages included: never add `cached_pages` * 256 to it), the whole pages read,
and the Job's prefill and generate times. This module turns those finals into
one receipt in the form the engine reads (`oneiron::llm::InferenceCallReceipt`),
under `usage.inference_calls`, beside the standard counts:

- `usage.prompt_tokens` stays the request's own prompt length;
- `usage.prompt_tokens_details.cached_tokens` is the FIRST Job's cache read,
  given only when that Job ran over the request's own prompt and its counts
  agree, so prompt tokens less cached tokens is what that pass computed;
- an answer pass's re-encode appears only among the record's passes.

A count the final does not carry is left out, never written as zero, and a
pass whose counts are missing or disagree is `unknown`, never a guessed hit.
A pass's computed input is its input less its cache read: logical input work,
not the tensors a kernel saw. Its times are per-Job intervals, which hold
other jobs' work when several run at once.

The identity is fixed when the Generator is built: an epoch minted then, and
SHA-256 digests of what the server loaded and runs with. Its `model` is the
digest of the target's weights manifest, given only when the installed shards
matched it before they loaded (`weights_manifest.py`, FIX 7895); without one
the record names no model. It never reads the model a request body names.
Nothing here holds prompt text.

The receipt names its worker: kind `exl3`, that identity, and its build as
`reported_version`, since the runtime digest hashes the versions the packages
report, not the binaries. Its queue waits are the two the scheduler already
measures, in whole microseconds: `worker_us` from submission to admission,
`engine_us` each Job's enqueue-to-start with the answer pass's wait for
pages. The R3 counters ride in the same record (FIX 8317): `ttft_us`, the
request's acceptance to its first generated token, measured at the worker;
`end_reason`, its native end in the closed set; `output_tokens`, the native
count of generated tokens; and `drafts_proposed` / `drafts_accepted`. A
count is a total over the request's passes only when every pass reported
it (`pass_totals`); one any pass left out is absent, never zero. The engine
model the call was admitted for is the engine's to stamp.
"""
import hashlib
import json
import math
import operator
import platform
import uuid
from importlib import metadata
from pathlib import Path

# The usage key the engine reads the receipts under (`INFERENCE_CALLS_KEY`).
INFERENCE_CALLS_KEY = "inference_calls"
# The usage key a supervised launch's answers echo its launch manifest's
# digest under (the worker probe's `LAUNCH_MANIFEST_KEY`).
LAUNCH_MANIFEST_KEY = "launch_manifest"
# The target directory's files the tokenizer is built from, with the model
# config that names its special tokens; the digest covers each one present,
# by name. Without `tokenizer.json` there is no tokenizer digest.
TOKENIZER_FILES = ("tokenizer.json", "tokenizer_config.json", "special_tokens_map.json",
                   "added_tokens.json", "config.json")
# The installed distributions whose versions the runtime digest reports.
RUNTIME_DISTRIBUTIONS = ("exllamav3", "torch")
# The scheduler's name for a thinking request's reasoning phase.
PHASE_REASON = "reason"


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def settings_digest(settings):
    """The digest of a settings object, keys sorted, so equal settings hash
    equal."""
    text = json.dumps(settings, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256_hex(text.encode("utf-8"))


def tokenizer_digest(target_dir):
    """The digest of the tokenizer files in the target directory, read as
    the server loads; None when there is no `tokenizer.json` or a file cannot
    be read."""
    directory = Path(target_dir)
    if not (directory / TOKENIZER_FILES[0]).is_file():
        return None
    digest = hashlib.sha256()
    try:
        for name in TOKENIZER_FILES:
            path = directory / name
            if path.is_file():
                data = path.read_bytes()
                digest.update(f"{name}\0{len(data)}\0".encode("utf-8"))
                digest.update(data)
    except OSError:
        return None
    return digest.hexdigest()


def runtime_digest():
    """The installed exllamav3 and torch, as their packages report their
    versions, with the Python that runs them: reported identity, not a check
    of the binaries. None when a version is not to be found."""
    try:
        versions = {name: metadata.version(name) for name in RUNTIME_DISTRIBUTIONS}
    except metadata.PackageNotFoundError:
        return None
    versions["python"] = platform.python_version()
    return settings_digest(versions)


class BackendIdentity:
    """What answers every request of this server's life: built once, beside
    the Generator, whose incarnation `epoch` names. `model_digest` is the
    verified weights manifest's digest, or None. Each digest that cannot be
    taken is left out.

    `launch` is the supervisor's launch manifest, as `(digest, runtime)`,
    when one was given (FIX 8315): the runtime is then the build the
    supervisor verified before the launch, the build evidence is verified
    artifacts, and every receipt echoes the manifest's digest. Without one,
    the runtime is the installed versions as reported."""

    def __init__(self, target_dir, template_source, cache_settings, server_settings,
                 model_digest=None, launch=None):
        self.epoch = uuid.uuid4().hex
        self.model = model_digest
        self.template = sha256_hex(template_source.encode("utf-8"))
        self.tokenizer = tokenizer_digest(target_dir)
        if launch is None:
            self.launch_manifest = None
            self.runtime = runtime_digest()
            self.build_evidence = "reported_version"
        else:
            self.launch_manifest, self.runtime = launch
            self.build_evidence = "verified_artifacts"
        self.cache_mode = settings_digest(cache_settings)
        self.server_settings = server_settings

    def execution_mode(self, template_kwargs, solo):
        """The digest of one request's effective execution: the server's
        settings, the template arguments it rendered with, and solo
        admission."""
        return settings_digest({"server": self.server_settings, "template_kwargs": template_kwargs,
                                "solo": solo})

    def record(self, execution_mode):
        identity = {
            "model": self.model,
            "tokenizer": self.tokenizer,
            "runtime": self.runtime,
            "template": self.template,
            "execution_mode": execution_mode,
            "cache_mode": self.cache_mode,
            "backend_epoch": self.epoch,
        }
        return {key: value for key, value in identity.items() if value is not None}


def native_count(final, key):
    """A non-negative whole count the final event carries, else None."""
    value = final.get(key)
    if value is None or isinstance(value, bool):
        return None
    try:
        value = operator.index(value)
    except TypeError:
        return None
    return value if value >= 0 else None


def micros(seconds):
    """A Job's time in seconds as whole microseconds, else None."""
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
        return None
    if not math.isfinite(seconds) or seconds < 0:
        return None
    return int(round(seconds * 1_000_000))


def native_seconds(final, key):
    """A non-negative finite time in seconds the final event carries, else
    None."""
    value = final.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) and value >= 0 else None


# Each Job final's measurements a request totals, with how each is read.
PASS_TOTALS = (
    ("new_tokens", native_count),
    ("accepted_draft_tokens", native_count),
    ("rejected_draft_tokens", native_count),
    ("time_prefill", native_seconds),
    ("time_enqueued", native_seconds),
    ("time_generate", native_seconds),
)


def pass_totals(totals, final):
    """`totals` with one more Job final added: a measure stays a sum only
    while every pass so far reported it, and is None from the first pass
    that did not. `totals` None starts the request's first pass."""
    values = {key: read(final, key) for key, read in PASS_TOTALS}
    if totals is None:
        return values
    return {key: None if totals[key] is None or values[key] is None else totals[key] + values[key]
            for key, _ in PASS_TOTALS}


# The request's end, by the native `eos_reason` of its last Job (R1: absent
# is unknown; a closed category keeps no provider text).
END_REASONS = {
    "stop_token": "stop",
    "stop_string": "stop",
    "end_filter": "stop",
    "max_new_tokens": "length",
}


def end_reason(eos_reason):
    """A native `eos_reason` as the receipt's `end_reason`: stop, length, or
    other for any other reason given; None when none was given."""
    if eos_reason is None:
        return None
    return END_REASONS.get(eos_reason, "other")


def drafts(totals):
    """`(proposed, accepted)` over the request's passes: accepted plus
    rejected, and accepted, only when every pass reported both; else
    `(None, None)`. Never inferred from speed or depth."""
    if totals is None:
        return None, None
    accepted, rejected = totals["accepted_draft_tokens"], totals["rejected_draft_tokens"]
    if accepted is None or rejected is None:
        return None, None
    return accepted + rejected, accepted


def job_pass(phase, thinking, final):
    """One Job's pass, from its final event: the scheduler's `phase`, read as
    the reasoning pass, the answer pass that re-encodes a closed thought, or
    the one pass over a prompt that opens no thought. The outcome is a hit or
    a recompute only when the input and the cache read are both reported and
    the read is no more than the input; the computed input is then their
    difference. Anything else is unknown."""
    if phase == PHASE_REASON:
        name = "reasoning"
    else:
        name = "answer" if thinking else "prompt"
    entry = {
        "phase": name,
        "input_tokens": native_count(final, "prompt_tokens"),
        "cache_read_tokens": native_count(final, "cached_tokens"),
        "cached_pages": native_count(final, "cached_pages"),
        "prefill_us": micros(final.get("time_prefill")),
        "generate_us": micros(final.get("time_generate")),
        "counter_source": "exl3_job",
        "outcome": "unknown",
    }
    taken, read = entry["input_tokens"], entry["cache_read_tokens"]
    if taken is not None and read is not None and read <= taken:
        entry["computed_input_tokens"] = taken - read
        entry["outcome"] = "hit" if read > 0 else "recompute"
    return {key: value for key, value in entry.items() if value is not None}


def add_evidence(usage, prompt_tokens, passes, identity, worker_wait_s=None, engine_wait_s=None,
                 build_evidence="reported_version", launch_manifest=None, ttft_us=None,
                 end=None, output_tokens=None, drafts_proposed=None, drafts_accepted=None):
    """Writes the request's receipt into `usage`, and the standard cached count
    when its first pass ran over its own prompt with counts that agree.
    `worker_wait_s` and `engine_wait_s` are the scheduler's own waits, in
    seconds; one it did not measure is None and left out. `launch_manifest`,
    the digest of the supervisor's launch manifest, is echoed under
    `LAUNCH_MANIFEST_KEY` when the server was given one. The R3 counters
    (`ttft_us`, `end`, `output_tokens`, the drafts) go in as given; None is
    left out."""
    first = passes[0] if passes else None
    if (first is not None and first["phase"] in ("prompt", "reasoning")
            and first.get("input_tokens") == prompt_tokens and first["outcome"] != "unknown"):
        usage["prompt_tokens_details"] = {"cached_tokens": first["cache_read_tokens"]}
    receipt = {
        "worker": {"kind": "exl3", "identity": identity, "build_evidence": build_evidence},
        "logical_prompt_tokens": prompt_tokens,
        "passes": passes,
    }
    queue_wait = {key: value for key, value in (("worker_us", micros(worker_wait_s)),
                                                 ("engine_us", micros(engine_wait_s)))
                  if value is not None}
    if queue_wait:
        receipt["queue_wait"] = queue_wait
    for key, value in (("ttft_us", ttft_us), ("end_reason", end), ("output_tokens", output_tokens),
                       ("drafts_proposed", drafts_proposed), ("drafts_accepted", drafts_accepted)):
        if value is not None:
            receipt[key] = value
    usage[INFERENCE_CALLS_KEY] = [receipt]
    if launch_manifest is not None:
        usage[LAUNCH_MANIFEST_KEY] = launch_manifest
