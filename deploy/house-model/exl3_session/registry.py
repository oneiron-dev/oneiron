"""The session registry: sessions, their checkpoints and working branches, by
handle (DESIGN-V2 §3.2, R2). Metadata only, under one lock; the page work
is `layer.py`'s, on the scheduler thread.

A session is bound to its host binding (the session key less its HEAD) on
this incarnation; its handle is 128 random bits. It holds at most one
published canonical checkpoint, one computed successor not yet published,
and the successor path `session.append` staged. Its generation moves by one
at each publish; an op naming another generation is refused
`stale_generation`. A working branch pins the checkpoint it forked from, and
a commit pins its base, so neither is released under them; a checkpoint that
stops serving while pinned is retired, and released when the last pin goes.

Each op's id is remembered with its answer for the session's current and
previous generation: a retry gets the same answer, never a second act.

Snapshots (R3). An export names the published checkpoint exactly, and its
answer is kept with the region it passed (`Retained`): a retry passes the
same bytes again, and the region closes when the answer is forgotten, the
session is dropped or the incarnation ends. An import goes only to a session
that holds nothing yet, at its generation, and stages its checkpoint as the
successor a `session.checkpoint` publishes. Each export or import in flight
counts on its session (`transfers`); a drop waits for them before it says
`released`.
"""
import hashlib
import secrets
import threading
import time

from .anchor import token_digest

STALE_GENERATION = "stale_generation"
UNKNOWN_SESSION = "unknown_session"
BINDING_MISMATCH = "binding_mismatch"
LOST_RESIDENCY = "lost_residency"
INVALID_REQUEST = "invalid_request"
INVALID_INPUT = "invalid_input"
SNAPSHOT_INCOMPATIBLE = "snapshot_incompatible"
SNAPSHOT_BUSY = "snapshot_busy"


class Refused(Exception):
    """A session op refused before it acted, with its wire code."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class Checkpoint:
    """A canonical checkpoint: an anchor over a canonical path's tokens, and
    the ref the host holds it by. `parent` is its base's digest."""

    def __init__(self, anchor, head, parent):
        self.anchor = anchor
        self.digest = token_digest(anchor.tokens)
        self.head = head
        self.parent = parent

    def ref(self):
        return {"digest": self.digest, "head": self.head, "frontier_tokens": self.anchor.frontier,
                "parent": self.parent}

    def same_point(self, ref):
        return ref.get("digest") == self.digest and ref.get("head") == self.head


class Retained:
    """An answer kept with the snapshot region its frame passes, for its
    op's replay; the region closes when the answer is forgotten."""

    __slots__ = ("answer", "region")

    def __init__(self, answer, region):
        self.answer = answer
        self.region = region

    def close(self):
        self.region.close()


def dispose(kept):
    """Lets go of what a forgotten answer holds: an export's region."""
    if isinstance(kept, Retained):
        kept.close()


class Staged:
    """A canonical successor path `session.append` staged."""

    __slots__ = ("tokens", "head", "base", "lcp", "generation")

    def __init__(self, tokens, head, base, lcp, generation):
        self.tokens = tokens
        self.head = head
        self.base = base
        self.lcp = lcp
        self.generation = generation


class Branch:
    """A working branch: the checkpoint it forked from (pinned; None for a
    cold one), how far its turn's canonical path reaches (`cap`), and the
    carry its call's reasoning pass left. It ends with the call that claims
    it, or at the session's next fork when no call did."""

    def __init__(self, handle, session, checkpoint, cap):
        self.handle = handle
        self.session = session
        self.checkpoint = checkpoint
        self.cap = cap
        self.carry = None
        self.claimed = False
        self.cancel = None
        self.ended = False


class Commit:
    """One `session.suffix_commit` in flight: its plan, ids (the staged path
    and a pad), the pages it reserves, and its answer."""

    def __init__(self, session, op_id, staged, plan, ids, need):
        self.session = session
        self.op_id = op_id
        self.staged = staged
        self.base = staged.base
        self.plan = plan
        self.ids = ids
        self.need = need
        self.job = None
        self.reserved = False
        self.done = threading.Event()
        self.reply = None
        self.refusal = None


class Session:

    def __init__(self, handle, binding):
        self.handle = handle
        self.binding = binding
        self.label = hashlib.blake2b(handle.encode(), digest_size=4).hexdigest()
        self.generation = 0
        self.published = None
        self.successor = None
        self.staged = None
        self.retired = []
        self.branches = {}
        self.commit = None
        self.answers = {}
        self.lost = False
        self.dropping = False
        # Exports and imports in flight on it.
        self.transfers = 0
        self.used = time.monotonic()

    def anchors(self):
        """Every anchor this session holds pages through."""
        held = [checkpoint.anchor for checkpoint in (self.published, self.successor) if checkpoint is not None]
        held += [checkpoint.anchor for checkpoint in self.retired]
        held += [branch.carry for branch in self.branches.values() if branch.carry is not None]
        return held

    def evictable(self):
        """True when nothing runs on it and it holds something: no claimed
        branch, no commit."""
        if self.commit is not None or any(branch.claimed for branch in self.branches.values()):
            return False
        return bool(self.anchors())


def new_handle():
    """A session or branch handle: 128 random bits, 32 hex."""
    return secrets.token_hex(16)


class Registry:
    """The sessions of this incarnation. Every method runs under `lock`."""

    def __init__(self):
        self.lock = threading.Condition()
        self.sessions = {}
        # Dropped sessions whose pages are not yet released.
        self.leaving = set()
        # (binding, op_id) -> handle, for a retried create.
        self.created = {}
        # handle -> (op_id, released event), for a retried drop.
        self.dropped = {}

    def find(self, handle, binding):
        session = self.sessions.get(handle)
        if session is None:
            raise Refused(UNKNOWN_SESSION, "no session has this handle")
        if session.binding != binding:
            raise Refused(BINDING_MISMATCH, "the session is bound to another binding")
        return session

    def create(self, binding, op_id):
        handle = self.created.get((binding, op_id))
        session = self.sessions.get(handle) if handle is not None else None
        if session is None:
            session = Session(new_handle(), binding)
            self.sessions[session.handle] = session
            self.created[(binding, op_id)] = session.handle
        return {"handle": session.handle, "generation": session.generation}

    @staticmethod
    def replay(session, op_id):
        """The answer an op with this id already got, or None."""
        kept = session.answers.get(op_id)
        return None if kept is None else kept[1]

    @staticmethod
    def remember(session, op_id, generation, answer):
        session.answers[op_id] = (generation, answer)
        session.used = time.monotonic()

    @staticmethod
    def prune(session):
        """Forgets answers older than the previous generation: an op naming
        one is refused stale before it could repeat."""
        floor = session.generation - 1
        for op_id in [op_id for op_id, (generation, _) in session.answers.items() if generation < floor]:
            dispose(session.answers.pop(op_id)[1])

    @staticmethod
    def forget_answers(session):
        """Forgets every answer `session` keeps, and lets go of what each
        holds."""
        answers, session.answers = session.answers, {}
        for _, kept in answers.values():
            dispose(kept)

    @staticmethod
    def retained_bytes(session):
        """The bytes of the snapshot regions `session`'s answers keep."""
        return sum(kept.region.length for _, kept in session.answers.values() if isinstance(kept, Retained))

    @staticmethod
    def check_generation(session, generation):
        if generation != session.generation:
            raise Refused(STALE_GENERATION, f"the session is at generation {session.generation}")

    @staticmethod
    def expected(session, ref):
        """The published checkpoint `ref` names, or None for a cold one."""
        if ref is None:
            if session.published is not None:
                raise Refused(STALE_GENERATION, "the session has a published checkpoint")
            return None
        if session.lost:
            raise Refused(LOST_RESIDENCY, "the session's checkpoint is no longer held")
        if session.published is None or not session.published.same_point(ref):
            raise Refused(STALE_GENERATION, "another checkpoint is published")
        return session.published

    @staticmethod
    def published_exactly(session, ref):
        """The published checkpoint whose ref is `ref` exactly: its digest,
        HEAD, frontier and parent."""
        if session.lost:
            raise Refused(LOST_RESIDENCY, "the session's checkpoint is no longer held")
        if session.published is None or session.published.ref() != ref:
            raise Refused(STALE_GENERATION, "another checkpoint is published")
        return session.published

    @staticmethod
    def import_target(session, generation):
        """Refused unless `session` is at `generation` and holds nothing yet:
        no checkpoint, successor, staged path, commit or branch."""
        if session.dropping:
            raise Refused(UNKNOWN_SESSION, "the session was dropped")
        if session.generation != generation:
            raise Refused(STALE_GENERATION, f"the session is at generation {session.generation}")
        if session.published is not None or session.successor is not None or session.staged is not None \
                or session.commit is not None or session.branches or session.lost:
            raise Refused(STALE_GENERATION, "the session already holds a checkpoint or work")

    def end_transfer(self, session):
        """One export or import on `session` has ended."""
        with self.lock:
            session.transfers -= 1
            self.lock.notify_all()

    @staticmethod
    def unpin(session, checkpoint):
        """Drops one pin on `checkpoint`; the anchors to release now."""
        if checkpoint is None:
            return []
        anchor = checkpoint.anchor
        anchor.pins -= 1
        if anchor.retired and anchor.pins <= 0 and checkpoint in session.retired:
            session.retired.remove(checkpoint)
            return [anchor]
        return []

    @staticmethod
    def retire(session, checkpoint):
        """`checkpoint` stops serving; the anchors to release now (none while
        something pins it)."""
        if checkpoint is None:
            return []
        checkpoint.anchor.retired = True
        if checkpoint.anchor.pins > 0:
            session.retired.append(checkpoint)
            return []
        return [checkpoint.anchor]

    def close_branch(self, branch):
        """Ends `branch`; the anchors to release now."""
        if branch.ended:
            return []
        branch.ended = True
        session = branch.session
        session.branches.pop(branch.handle, None)
        release = []
        if branch.carry is not None:
            release.append(branch.carry)
            branch.carry = None
        release += self.unpin(session, branch.checkpoint)
        branch.checkpoint = None
        self.lock.notify_all()
        return release

    def strip(self, session):
        """Everything `session` holds stops serving: its unclaimed branches
        end and its checkpoints go. The anchors to release now."""
        release = []
        for branch in list(session.branches.values()):
            if not branch.claimed:
                release += self.close_branch(branch)
        for checkpoint in (session.published, session.successor):
            release += self.retire(session, checkpoint)
        session.published = session.successor = session.staged = None
        return release
