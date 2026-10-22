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
"""
import threading

import torch
from exllamav3.constants import PAGE_SIZE

from .anchor import common_prefix
from .jobs import Plan
from .registry import (INVALID_REQUEST, LOST_RESIDENCY, STALE_GENERATION, UNKNOWN_SESSION, Branch, Commit,
                       Refused, Staged, new_handle)

# The ephemeral tail a differential rendering puts after a canonical path.
PROBE = {"role": "user", "content": "oneiron session probe"}
HEX = frozenset("0123456789abcdef")
U64_MAX = (1 << 64) - 1


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
        branch = Branch(new_handle(), session, checkpoint, cap)
        if checkpoint is not None:
            checkpoint.anchor.pins += 1
        session.branches[branch.handle] = branch
        answer = {"branch": branch.handle, "frontier_tokens": position, "canonical_lcp_tokens": lcp,
                  "residency": layer.residency(session)}
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


def _commit(layer, session, op_id, staged):
    """The commit of `staged`: its ids (the path and one pad id, which never
    runs), where it attaches on its base, and the fresh pages it needs."""
    ids = torch.cat([staged.tokens, staged.tokens[-1:]])
    anchor = staged.base.anchor if staged.base is not None else None
    position, snapshot = anchor.attach_point(ids, staged.lcp) if anchor is not None else (0, None)
    # The pages a one-token Job reserves (its default requeue budget:
    # output, one more, the draft depth), less the ones it shares.
    depth = int(layer.generator.num_draft_tokens)
    total = -(-(int(ids.numel()) + 2 + depth) // PAGE_SIZE)
    return Commit(session, op_id, staged, Plan(anchor, position, snapshot), ids, total - position // PAGE_SIZE)


def suffix_commit(layer, body, _conversation_):
    handle, binding = _target(body)
    op_id, generation = _u64(body, "op_id"), _u64(body, "generation")
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
            kept = _commit(layer, session, op_id, staged)
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
            while session.branches:
                layer.lock.wait()
        layer.scheduler.run_owned(lambda: layer.release_session(session))
    finally:
        done.set()
    return _with_stats(layer, {"released": True})


HANDLERS = {
    "session.create": create,
    "session.fork": fork,
    "session.append": append,
    "session.suffix_commit": suffix_commit,
    "session.checkpoint": checkpoint,
    "session.drop": drop,
}

# The ops that carry an input region.
WITH_INPUT = ("session.fork", "session.append", "session.generate")


def answer(layer, op, body, conversation):
    """The answer body of session op `op`; Refused when it is refused."""
    return HANDLERS[op](layer, body, conversation)
