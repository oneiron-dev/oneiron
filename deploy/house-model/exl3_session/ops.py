"""The session ops of codec v1.1 (DESIGN-V2 R2), worker side. The wire is the
host's (crates/oneiron-model/src/llm/session.rs, models/native_exl3/
session_ops.rs): every body names `handle` (32 hex) and `binding` (64 hex)
and an `op_id`, and, where it changes state, the session `generation` it
expects. Refusals: `unknown_session`, `binding_mismatch`, `stale_generation`,
`lost_residency`, and `invalid_request` / `invalid_input` for a body this
side cannot read.

Joint tokenization, never a guessed message boundary. `session.fork`
renders the whole turn as the call will run it, and the turn's canonical
messages with a probe user message after them: their token longest common
prefix is where the turn's canonical path ends (`cap`), whatever the
template does at that boundary. The branch attaches only where the turn's
tokens equal the checkpoint's, short of `cap` (Engine STEALS line 15, worker
half: differential renderings). `session.append` renders the successor path
alone (no generation prompt) and with the probe after it: the staged
canonical tokens are their common prefix, so a checkpoint never holds a
token a following message would render differently (a last assistant
message's thinking block, say). `session.generate` attaches again against
the ids its own call renders: the attach point is verified on the tokens
that run.

`session.prepare` (I1 = C) renders the path the host expects the next turn
to start with (the published path, then the state-only board), as
`session.append` stages a path, checks that it extends the published
checkpoint, and prefills its suffix on that checkpoint, as a suffix commit
does, under the class and priority its body names (background, from the
host). The result is the session's prepared tail, beside the published
checkpoint and never published. `session.fork` attaches the turn's branch to
it instead of the checkpoint only where the turn's own tokens equal the
tail's further than the checkpoint's attach reaches, and answers what the
tail held, computed and gave (`prepared`); the tail ends at that fork either
way, and a prepare still running stops. `session.generate` attaches again on
the ids its call renders, against whichever the branch holds.

Codec v1.2 (R3) adds the snapshot ops. `session.export` names the published
checkpoint exactly and answers `{checkpoint, snapshot_bytes,
snapshot_sha256, output, residency}`; its snapshot region rides on the
answer's frame (`exl3_ipc.py` passes it, and fills `output.buffer_id`).
`session.import` carries a `snapshot_v1` input region, binary, never a
`chat_json` conversation; it goes only to a session that holds nothing yet,
and answers `{staged, imported_bytes, snapshot_sha256, residency}` once the
snapshot is checked, its pages written and its checkpoint staged. Their own
refusals: `snapshot_incompatible` (a snapshot this worker does not rebuild
exactly) and `snapshot_busy` (no room for it now), both a cache miss to the
host, and `invalid_input` for a region that is not the snapshot the body
names.
"""
import hashlib
import threading
import time

import exl3_executor
import torch
from exllamav3.constants import PAGE_SIZE

from . import snapshot
from .anchor import common_prefix
from .jobs import Plan
from .registry import (INVALID_INPUT, INVALID_REQUEST, LOST_RESIDENCY, STALE_GENERATION, UNKNOWN_SESSION, Branch,
                       Commit, Refused, Retained, Staged, new_handle)

# A prepare that a later op of the session stops: the turn it prepared for
# arrived, or the session moved on.
SUPERSEDED = "superseded"
# A prepare whose prefill could never fit the page pool beside its pinned
# base: it would wait at the head of the commit queue for ever.
PREPARE_TOO_LARGE = "prepare_too_large"
# The same for a suffix commit: the session cannot hold its successor.
COMMIT_TOO_LARGE = "commit_too_large"


def _fits_pool(layer, commit, base):
    """Whether `commit`'s fresh pages, beside the pages of the checkpoint
    `base` it pins, could ever fit the page pool. Commits start in order, so
    one that cannot would hold back every commit behind it."""
    base_pages = -(-base.anchor.frontier // PAGE_SIZE) if base is not None else 0
    return commit.need + base_pages <= layer.scheduler.pool_pages

# The ephemeral tail a differential rendering puts after a canonical path.
PROBE = {"role": "user", "content": "oneiron session probe"}
HEX = frozenset("0123456789abcdef")
U64_MAX = (1 << 64) - 1
# A checkpoint ref's fields, every one named.
REF_FIELDS = ("digest", "head", "frontier_tokens", "parent")


def _u64(body, key):
    value = body.get(key)
    if type(value) is not int or not 0 <= value <= U64_MAX:
        raise Refused(INVALID_REQUEST, f"{key} must be a u64")
    return value


def _hex(body, key, nbytes):
    value = body.get(key)
    if not isinstance(value, str) or len(value) != 2 * nbytes or not set(value) <= HEX:
        raise Refused(INVALID_REQUEST, f"{key} must be {2 * nbytes} lowercase hex digits")
    return value


def _ref(body, key):
    """A checkpoint ref the host names, or None."""
    value = body.get(key)
    if value is None:
        return None
    if not isinstance(value, dict):
        raise Refused(INVALID_REQUEST, f"{key} must be a checkpoint ref or null")
    _hex(value, "digest", 32)
    return value


def _exact_ref(body, key):
    """A checkpoint ref the host names exactly: `{digest, head,
    frontier_tokens, parent}`."""
    value = body.get(key)
    if not isinstance(value, dict) or set(value) != set(REF_FIELDS):
        raise Refused(INVALID_REQUEST, f"{key} must be a checkpoint ref {{digest, head, frontier_tokens, parent}}")
    _hex(value, "digest", 32)
    _u64(value, "frontier_tokens")
    if value["parent"] is not None:
        _hex(value, "parent", 32)
    if value["head"] is not None and not isinstance(value["head"], str):
        raise Refused(INVALID_REQUEST, f"{key}.head must be a string or null")
    return {field: value[field] for field in REF_FIELDS}


def _target(body):
    return _hex(body, "handle", 16), _hex(body, "binding", 32)


def _conversation(conversation):
    if conversation is None:
        raise Refused("invalid_input", "the op carries no input region")
    tools = conversation.get("tools") or []
    if not isinstance(tools, list) or not all(isinstance(tool, dict) for tool in tools):
        raise Refused("invalid_input", "tools must be a list of objects")
    return conversation["messages"], tools


def _ids(layer, messages, tools, generation_prompt):
    """The ids of `messages` as the template renders them, jointly
    tokenized: 1-D."""
    try:
        text = layer.render(messages, tools, generation_prompt)
    except Exception as error:
        raise Refused("invalid_input", f"the template refused the conversation: {error}") from None
    return layer.encode(text)[0]


def _with_stats(layer, answer):
    stats = layer.scheduler.snapshot(False)
    if stats is not None:
        answer = dict(answer, stats=stats)
    return answer


def create(layer, body, _conversation_):
    binding, op_id = _hex(body, "binding", 32), _u64(body, "op_id")
    with layer.lock:
        return layer.create(binding, op_id)


def fork(layer, body, conversation):
    handle, binding = _target(body)
    op_id, generation = _u64(body, "op_id"), _u64(body, "generation")
    expected = _ref(body, "expected")
    canonical = _u64(body, "canonical_messages")
    messages, tools = _conversation(conversation)
    if canonical > len(messages):
        raise Refused(INVALID_REQUEST, "canonical_messages is past the turn's messages")
    with layer.lock:
        session = layer.find(handle, binding)
        kept = layer.replay(session, op_id)
        if kept is not None:
            return kept
        layer.check_generation(session, generation)
        checkpoint = layer.expected(session, expected)
        # The turn has arrived: a prepare still running for it stops, and
        # what it computes no longer serves.
        preparing, session.preparing = session.preparing, None
    if preparing is not None:
        layer.scheduler.post(lambda: layer.stop_commit(preparing, Refused(SUPERSEDED, "the turn arrived")))
    full = _ids(layer, messages, tools, True)
    cap = common_prefix(full, _ids(layer, messages[:canonical] + [PROBE], tools, True))
    lcp = position = 0
    if checkpoint is not None:
        lcp = common_prefix(full[:cap], checkpoint.anchor.tokens)
        position, _ = checkpoint.anchor.attach_point(full, cap)
    release = []
    with layer.lock:
        if session.dropping:
            raise Refused(UNKNOWN_SESSION, "the session was dropped")
        layer.check_generation(session, generation)
        if layer.expected(session, expected) is not checkpoint:
            raise Refused(STALE_GENERATION, "another checkpoint is published")
        # A branch no call claimed ends at the session's next fork.
        for branch in [branch for branch in session.branches.values() if not branch.claimed]:
            release += layer.close_branch(branch)
        # The prepared tail serves this fork or none: the send-time check is
        # the turn's own tokens against the tail's, past the checkpoint's
        # attach point; the branch takes whichever reaches further.
        prepared, used = session.prepared, None
        if prepared is not None and checkpoint is not None and prepared.base is checkpoint \
                and not prepared.checkpoint.anchor.released:
            reach, _ = prepared.checkpoint.anchor.attach_point(full, int(full.numel()))
            if reach > position:
                used = (prepared, reach)
        if used is not None:
            branch = Branch(new_handle(), session, prepared.checkpoint, int(full.numel()))
            branch.checkpoint.anchor.pins += 1
        else:
            branch = Branch(new_handle(), session, checkpoint, cap)
            if checkpoint is not None:
                checkpoint.anchor.pins += 1
        release += layer.unprepare(session)
        session.branches[branch.handle] = branch
        answer = {"branch": branch.handle, "frontier_tokens": used[1] if used is not None else position,
                  "canonical_lcp_tokens": lcp, "residency": layer.residency(session)}
        if prepared is not None:
            tail = prepared.checkpoint.anchor.frontier - prepared.base.anchor.frontier
            reused = max(0, min(used[1] - position, tail)) if used is not None else 0
            answer["prepared"] = {"attached": used is not None, "prepared_tokens": tail,
                                  "computed_tokens": prepared.computed_tokens, "reused_tokens": reused}
        elif preparing is not None:
            answer["prepared"] = {"attached": False, "prepared_tokens": 0, "computed_tokens": None,
                                  "reused_tokens": 0, "stopped": True}
        layer.remember(session, op_id, generation, answer)
    if release:
        layer.scheduler.post(lambda: layer.release(release))
    return answer


def append(layer, body, conversation):
    handle, binding = _target(body)
    op_id, generation = _u64(body, "op_id"), _u64(body, "generation")
    base = _ref(body, "base")
    head = body.get("head")
    messages, tools = _conversation(conversation)
    with layer.lock:
        session = layer.find(handle, binding)
        kept = layer.replay(session, op_id)
        if kept is not None:
            return kept
        layer.check_generation(session, generation)
        checkpoint = layer.expected(session, base)
    path = _ids(layer, messages, tools, False)
    staged = path[:common_prefix(path, _ids(layer, messages + [PROBE], tools, True))].clone()
    lcp = common_prefix(staged, checkpoint.anchor.tokens) if checkpoint is not None else 0
    with layer.lock:
        if session.dropping:
            raise Refused(UNKNOWN_SESSION, "the session was dropped")
        layer.check_generation(session, generation)
        if layer.expected(session, base) is not checkpoint:
            raise Refused(STALE_GENERATION, "another checkpoint is published")
        session.staged = Staged(staged, head, checkpoint, lcp, generation)
        answer = {"staged_tokens": int(staged.numel()), "lcp_tokens": lcp}
        layer.remember(session, op_id, generation, answer)
    return answer


def prepare(layer, body, conversation):
    """`session.prepare`: the path the input region carries, which must
    extend the published checkpoint `base` names, prefilled on it into the
    session's prepared tail; answers `{prepared_tokens, computed_tokens}`,
    the tail's tokens past the checkpoint and the tokens it computed. A tail
    whose pages could never fit the pool beside its base is refused
    `prepare_too_large` before it pins anything or joins the queue."""
    handle, binding = _target(body)
    op_id, generation = _u64(body, "op_id"), _u64(body, "generation")
    base = _ref(body, "base")
    if base is None:
        raise Refused(INVALID_REQUEST, "a prepare names the published checkpoint it extends")
    work = _work(body)
    messages, tools = _conversation(conversation)
    with layer.lock:
        session = layer.find(handle, binding)
        kept = layer.replay(session, op_id)
        if kept is None:
            layer.check_generation(session, generation)
            checkpoint = layer.expected(session, base)
    if kept is None:
        path = _ids(layer, messages, tools, False)
        tokens = path[:common_prefix(path, _ids(layer, messages + [PROBE], tools, True))].clone()
        frontier = checkpoint.anchor.frontier
        if int(tokens.numel()) <= frontier or common_prefix(tokens, checkpoint.anchor.tokens) < frontier:
            raise Refused(STALE_GENERATION, "the prepared path does not extend the published checkpoint")
        release = []
        with layer.lock:
            if session.dropping:
                raise Refused(UNKNOWN_SESSION, "the session was dropped")
            layer.check_generation(session, generation)
            if layer.expected(session, base) is not checkpoint:
                raise Refused(STALE_GENERATION, "another checkpoint is published")
            staged = Staged(tokens, checkpoint.head, checkpoint, frontier, generation)
            kept = _commit(layer, session, op_id, staged, work, prepare=True)
            # Refused before it pins its base or joins the queue.
            if not _fits_pool(layer, kept, checkpoint):
                raise Refused(PREPARE_TOO_LARGE, "the prepared tail does not fit the page pool")
            stopped = session.preparing
            release += layer.unprepare(session)
            checkpoint.anchor.pins += 1
            session.preparing = kept
            layer.waiting.append(kept)
            layer.remember(session, op_id, generation, kept)
        if stopped is not None:
            layer.scheduler.post(lambda: layer.stop_commit(stopped, Refused(SUPERSEDED, "another prepare runs")))
        if release:
            layer.scheduler.post(lambda: layer.release(release))
    if not isinstance(kept, Commit) or not kept.prepare:
        if not isinstance(kept, dict):
            raise Refused(INVALID_REQUEST, "this op id answered another op")
        return kept
    layer.scheduler.poke()
    # No deadline: the prepare runs when the scheduler has room for it, and
    # the turn's fork stops it.
    kept.done.wait()
    if kept.refusal is not None:
        raise kept.refusal
    return _with_stats(layer, kept.reply)


def _commit(layer, session, op_id, staged, work, prepare=False):
    """The commit of `staged`: its ids (the path and one pad id, which never
    runs), where it attaches on its base, the fresh pages it needs, and its
    scheduling."""
    ids = torch.cat([staged.tokens, staged.tokens[-1:]])
    anchor = staged.base.anchor if staged.base is not None else None
    position, snapshot = anchor.attach_point(ids, staged.lcp) if anchor is not None else (0, None)
    # The pages a one-token Job reserves (its default requeue budget:
    # output, one more, the draft depth), less the ones it shares.
    depth = int(layer.generator.num_draft_tokens)
    total = -(-(int(ids.numel()) + 2 + depth) // PAGE_SIZE)
    return Commit(session, op_id, staged, Plan(anchor, position, snapshot), ids, total - position // PAGE_SIZE,
                  work, prepare)


def _work(body):
    """The op's scheduling (exl3_executor): the class, priority and deadline
    its body names, each defaulted when absent; refused `invalid_request`
    for one this side cannot read."""
    try:
        return exl3_executor.WorkContext(**exl3_executor.work_fields(body, time.monotonic_ns()))
    except exl3_executor.SchedulingError as error:
        raise Refused(INVALID_REQUEST, str(error)) from None


def suffix_commit(layer, body, _conversation_):
    handle, binding = _target(body)
    op_id, generation = _u64(body, "op_id"), _u64(body, "generation")
    work = _work(body)
    with layer.lock:
        session = layer.find(handle, binding)
        kept = layer.replay(session, op_id)
        if kept is None:
            layer.check_generation(session, generation)
            staged = session.staged
            if staged is None or staged.generation != generation or not staged.tokens.numel():
                raise Refused(STALE_GENERATION, "nothing is staged at this generation")
            if session.commit is not None:
                raise Refused(STALE_GENERATION, "another commit runs on this session")
            if staged.base is not None and session.lost:
                raise Refused(LOST_RESIDENCY, "the session's checkpoint is no longer held")
            if staged.base is not session.published:
                raise Refused(STALE_GENERATION, "another checkpoint is published")
            kept = _commit(layer, session, op_id, staged, work)
            # Refused before it pins its base or joins the queue.
            if not _fits_pool(layer, kept, staged.base):
                raise Refused(COMMIT_TOO_LARGE, "the successor does not fit the page pool")
            if staged.base is not None:
                staged.base.anchor.pins += 1
            session.commit = kept
            layer.waiting.append(kept)
            layer.remember(session, op_id, generation, kept)
    if not isinstance(kept, Commit):
        return kept
    layer.scheduler.poke()
    # No deadline: the commit runs when the scheduler has room for it.
    kept.done.wait()
    if kept.refusal is not None:
        raise kept.refusal
    return _with_stats(layer, kept.reply)


def checkpoint(layer, body, _conversation_):
    handle, binding = _target(body)
    op_id, generation = _u64(body, "op_id"), _u64(body, "generation")
    digest = _hex(body, "staged", 32)
    publish = body.get("publish")
    if not isinstance(publish, bool):
        raise Refused(INVALID_REQUEST, "publish must be true or false")
    with layer.lock:
        session = layer.find(handle, binding)
        kept = layer.replay(session, op_id)
    if kept is not None:
        return kept
    answer = layer.scheduler.run_owned(lambda: layer.publish(session, op_id, generation, digest, publish))
    return _with_stats(layer, answer)


def drop(layer, body, _conversation_):
    handle, binding = _target(body)
    op_id = _u64(body, "op_id")
    reason = body.get("reason")
    session = None
    with layer.lock:
        gone = layer.dropped.get(handle)
        if gone is not None:
            if gone[0] != op_id:
                raise Refused(UNKNOWN_SESSION, "no session has this handle")
            done = gone[1]
        else:
            session = layer.find(handle, binding)
            del layer.sessions[handle]
            session.dropping = True
            layer.leaving.add(session)
            done = threading.Event()
            layer.dropped[handle] = (op_id, done)
            for key in [key for key, value in layer.created.items() if value == handle]:
                del layer.created[key]
            cancels = [branch.cancel for branch in session.branches.values()
                       if branch.claimed and branch.cancel is not None]
    if session is None:
        # A retry: answered once the first drop has released.
        done.wait()
        return {"released": True}
    print(f"SESSION_DROP session={session.label} reason={reason!r}", flush=True)
    # What depends on the session stops: its calls are cancelled, its open
    # branches end, its commit stops; then everything it held goes.
    try:
        for cancel in cancels:
            cancel()
        layer.scheduler.run_owned(lambda: layer.abandon(session))
        with layer.lock:
            # An export or import in flight sees the drop and stops.
            while session.branches or session.transfers:
                layer.lock.wait()
        layer.scheduler.run_owned(lambda: layer.release_session(session))
    finally:
        done.set()
    return _with_stats(layer, {"released": True})


def export(layer, body, _conversation_):
    """`session.export`: (answer, region). The published checkpoint the
    body names exactly, copied on the scheduler thread and written off it
    into a sealed region, which the answer's frame passes. The region is
    kept with the answer: a retry passes the same bytes again."""
    handle, binding = _target(body)
    op_id, generation = _u64(body, "op_id"), _u64(body, "generation")
    ref = _exact_ref(body, "checkpoint")
    work = _work(body)
    with layer.lock:
        session = layer.find(handle, binding)
        kept = layer.replay(session, op_id)
        if kept is None:
            layer.check_generation(session, generation)
            checkpoint = layer.published_exactly(session, ref)
            session.transfers += 1
    if kept is not None:
        if not isinstance(kept, Retained):
            raise Refused(INVALID_REQUEST, "this op id answered another op")
        return dict(kept.answer), kept.region
    try:
        fields, tensors = layer.export_checkpoint(session, checkpoint, work)
        region = snapshot.write_region(fields, tensors)
        tensors = None
        with layer.lock:
            if session.dropping:
                region.close()
                raise Refused(UNKNOWN_SESSION, "the session was dropped")
            answer = {"checkpoint": checkpoint.ref(), "snapshot_bytes": region.length,
                      "snapshot_sha256": region.sha256,
                      "output": {"fd_index": 0, "offset": 0, "length": region.length, "encoding": snapshot.ENCODING},
                      "residency": layer.residency(session)}
            layer.remember(session, op_id, generation, Retained(answer, region))
    finally:
        layer.end_transfer(session)
    return _with_stats(layer, answer), region


def import_(layer, body, payload):
    """`session.import`: the snapshot `payload` (the input region's bytes)
    checked against the body and this worker, then written into fresh pages
    on the scheduler thread and staged as the empty session's successor."""
    handle, binding = _target(body)
    op_id, generation = _u64(body, "op_id"), _u64(body, "generation")
    ref = _exact_ref(body, "checkpoint")
    size, sha256 = _u64(body, "snapshot_bytes"), _hex(body, "snapshot_sha256", 32)
    work = _work(body)
    with layer.lock:
        session = layer.find(handle, binding)
        kept = layer.replay(session, op_id)
        if kept is None:
            layer.import_target(session, generation)
            session.transfers += 1
    if kept is not None:
        if isinstance(kept, Retained):
            raise Refused(INVALID_REQUEST, "this op id answered another op")
        return kept
    try:
        if payload is None:
            raise Refused(INVALID_INPUT, "the op carries no input region")
        if len(payload) != size or hashlib.sha256(payload).hexdigest() != sha256:
            raise Refused(INVALID_INPUT, "the input region is not the snapshot the body names")
        rebuilt = layer.decode_import(payload, ref)
        answer = layer.import_checkpoint(session, op_id, generation, rebuilt, size, sha256, work)
    finally:
        layer.end_transfer(session)
    return _with_stats(layer, answer)


def claim(layer, field):
    """`session.generate`'s `session` field: `{handle, binding, branch,
    op_id}`; the branch it names, claimed."""
    if not isinstance(field, dict):
        raise Refused(INVALID_REQUEST, "session must be an object")
    handle, binding = _target(field)
    branch = _hex(field, "branch", 16)
    _u64(field, "op_id")
    return layer.claim(handle, binding, branch)


HANDLERS = {
    "session.create": create,
    "session.fork": fork,
    "session.append": append,
    "session.suffix_commit": suffix_commit,
    "session.prepare": prepare,
    "session.checkpoint": checkpoint,
    "session.drop": drop,
    "session.export": export,
    "session.import": import_,
}

# The ops that carry a `chat_json` input region.
WITH_INPUT = ("session.fork", "session.append", "session.prepare", "session.generate")
# The op that carries a `snapshot_v1` input region, and the op whose answer
# passes one: the handler gives (answer, region).
SNAPSHOT_INPUT = ("session.import",)
SNAPSHOT_OUTPUT = ("session.export",)


def answer(layer, op, body, conversation):
    """The answer body of session op `op` (for `session.export`, the answer
    and its region); Refused when it is refused. `conversation` is an op's
    input: a `chat_json` conversation, or an import's snapshot bytes."""
    return HANDLERS[op](layer, body, conversation)
