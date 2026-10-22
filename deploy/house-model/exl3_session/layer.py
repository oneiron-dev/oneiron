"""The session layer's scheduler side: everything that touches pages, Jobs or
the Generator runs here, on the scheduler thread that owns them; the ops
(`ops.py`) reach it through the scheduler's chores.

Pages. Every page a session holds is an owner's (`pages.py`): its published
checkpoint, its computed successor, a retired checkpoint still pinned, a
branch's carry. The scheduler admits work against the pool less what owners
hold; when a request or a commit needs room, sessions nothing runs on are
evicted, least recently used first (`evict_until`), so a session never makes
a call wait or refuses one. An evicted session answers `lost_residency`
where an op names its checkpoint.

A branch's Job attaches where its plan says (`plan`): to its checkpoint, no
further than its turn's canonical path, or, for a thinking call's answer
pass, to the carry its reasoning pass left (the call's own prompt, board
included, which dies with the call). A commit runs a CommitJob against its
base and, once its prefill has reached the end of the staged path, takes
its pages and the recurrent state at that exact frontier as the successor.
Nothing computed for a working branch is ever promoted: a successor's pages
come from its own commit alone.

`released` only once pages are back in the pool and state slots freed:
`release_session` runs after every Job of the session has ended.
"""
import time

from exllamav3.constants import PAGE_SIZE

from . import state
from .anchor import Anchor
from .jobs import CommitJob, Plan
from .pages import Owner
from .registry import LOST_RESIDENCY, Checkpoint, Refused, Registry

# The capability a worker with this layer advertises in its hello.
SCHEMA_MINOR = 1
OPS = ("session.create", "session.fork", "session.generate", "session.append", "session.suffix_commit",
       "session.checkpoint", "session.drop")


class SessionLayer(Registry):

    def __init__(self, generator, render, encode):
        super().__init__()
        self.generator = generator
        self.pagetable = generator.pagetable
        # render(messages, tools, generation_prompt) -> text; encode(text) -> (1, n) ids.
        self.render = render
        self.encode = encode
        self.scheduler = None
        self.waiting = []
        self.running = {}
        self.page_bytes = self.pagetable.page_bytes()

    def capability(self):
        return {"minor": SCHEMA_MINOR, "ops": list(OPS)}

    # Any thread: metadata only.

    def plan(self, branch, ids, carry=False):
        """Where a Job over `ids` ((1, n)) on `branch` attaches: the anchor
        that gives the most. With `carry`, the Job's pages and its last
        prompt-page snapshot become the branch's carry when it ends."""
        ids = ids[0]
        best = Plan()
        with self.lock:
            candidates = []
            if branch.checkpoint is not None:
                candidates.append((branch.checkpoint.anchor, branch.cap))
            if branch.carry is not None:
                candidates.append((branch.carry, branch.carry.frontier))
            for anchor, cap in candidates:
                if anchor.released:
                    continue
                position, snapshot = anchor.attach_point(ids, cap)
                if position > best.position:
                    best = Plan(anchor, position, snapshot)
        if carry:
            best.carry = True
            best.on_release = lambda job, pages: self.keep_carry(branch, job, pages)
        return best

    def shared_pages(self, branch, ids):
        """The pages a Job over `ids` on `branch` shares, which its call's
        reservation leaves out: owners hold them already."""
        return self.plan(branch, ids).position // PAGE_SIZE

    def claim(self, handle, binding, branch_handle):
        """The working branch a `session.generate` runs on, now claimed."""
        with self.lock:
            session = self.find(handle, binding)
            branch = session.branches.get(branch_handle)
            if branch is None or branch.claimed or branch.ended:
                raise Refused("unknown_session", "the session has no open branch with this handle")
            branch.claimed = True
            session.used = time.monotonic()
            return branch

    def unclaim(self, branch):
        """A claim whose call never ran: the branch is open again."""
        with self.lock:
            if not branch.ended:
                branch.claimed = False
                branch.cancel = None

    def bind_call(self, branch, cancel):
        with self.lock:
            branch.cancel = cancel

    def end_branch_later(self, branch):
        """Ends `branch` on the scheduler thread, for a call that never
        reached the scheduler."""
        if not self.scheduler.post(lambda: self.end_branch(branch)):
            with self.lock:
                self.close_branch(branch)

    def residency(self, session):
        unique = self.unique_bytes(session)
        out = {"resident": not session.lost}
        if unique is not None:
            out["unique_bytes"] = unique
        return out

    def unique_bytes(self, session):
        """What `session` holds, each page and snapshot once: its pages'
        device bytes and its snapshots' host bytes."""
        if self.page_bytes is None:
            return None
        anchors = session.anchors()
        pages = {id(page) for anchor in anchors for page in list(anchor.owner.pages)}
        snapshots = {id(snapshot): snapshot.nbytes for anchor in anchors for snapshot in anchor.snapshots}
        return len(pages) * self.page_bytes + sum(snapshots.values())

    # The scheduler thread.

    def release(self, anchors):
        for anchor in anchors:
            if not anchor.released:
                anchor.released = True
                self.pagetable.release(anchor.owner)

    def end_branch(self, branch):
        if branch is None:
            return
        with self.lock:
            release = self.close_branch(branch)
        self.release(release)

    def keep_carry(self, branch, job, pages):
        """A reasoning pass's Job gives back its pages: the branch keeps the
        ones before its last prompt-page snapshot, for the answer pass."""
        snapshot = job.page_snapshot
        if snapshot is None:
            return
        tokens = job.sequences[0].sequence_ids.torch()[0, :snapshot.position].clone()
        release = []
        with self.lock:
            if branch.ended:
                return
            owner = Owner()
            self.pagetable.hold(owner, pages[:snapshot.position // PAGE_SIZE])
            if branch.carry is not None:
                release.append(branch.carry)
            branch.carry = Anchor(tokens, owner, [snapshot])
        self.release(release)

    def held_pages(self):
        return len(self.pagetable.held())

    def pinned_pages(self):
        """The pages held by sessions eviction may not take now."""
        with self.lock:
            owners = [anchor.owner
                      for session in list(self.sessions.values()) + list(self.leaving)
                      if session.dropping or not session.evictable()
                      for anchor in session.anchors()]
        return len(self.pagetable.held(owners))

    def evict_until(self, fits):
        """Evicts sessions nothing runs on, least recently used first, until
        `fits()`."""
        while not fits():
            with self.lock:
                candidates = [session for session in self.sessions.values() if session.evictable()]
                if not candidates:
                    return
                victim = min(candidates, key=lambda session: session.used)
                release = self.strip(victim)
                victim.lost = True
            self.release(release)
            print(f"SESSION_EVICTED session={victim.label} held_pages={self.held_pages()}", flush=True)

    def publish(self, session, op_id, generation, digest, publish):
        """`session.checkpoint`: publishes its successor named `digest`
        atomically (or discards it), and answers."""
        with self.lock:
            if session.dropping:
                raise Refused("unknown_session", "the session was dropped")
            self.check_generation(session, generation)
            successor = session.successor
            matches = successor is not None and successor.digest == digest
            release = []
            if publish and matches:
                release += self.retire(session, session.published)
                session.published, session.successor, session.staged = successor, None, None
                session.generation += 1
                session.lost = False
                ready = True
            elif publish and session.lost:
                raise Refused(LOST_RESIDENCY, "the session's successor is no longer held")
            else:
                if matches:
                    release += self.retire(session, successor)
                    session.successor = None
                ready = False
            published = session.published
            answer = {"ready": ready, "checkpoint": published.ref() if published is not None else None,
                      "generation": session.generation, "residency": self.residency(session)}
            self.remember(session, op_id, generation, answer)
            self.prune(session)
        self.release(release)
        return answer

    def abandon(self, session):
        """A dropped session: its open branches end and its commit stops."""
        with self.lock:
            release = []
            for branch in list(session.branches.values()):
                if not branch.claimed:
                    release += self.close_branch(branch)
            commit = session.commit
        self.release(release)
        if commit is not None:
            self.stop_commit(commit, Refused("unknown_session", "the session was dropped"))

    def release_session(self, session):
        """Gives back everything a dropped session held, once its calls have
        ended."""
        with self.lock:
            release = self.strip(session)
            release += [checkpoint.anchor for checkpoint in session.retired]
            session.retired = []
            self.leaving.discard(session)
        self.release(release)

    # Commits, on the scheduler thread.

    def next_commit(self):
        with self.lock:
            return self.waiting[0] if self.waiting else None

    def running_commits(self):
        return len(self.running)

    def start_commit(self, commit):
        """Enqueues the head commit's Job; False when it could not start (it
        has been answered)."""
        with self.lock:
            if not self.waiting or self.waiting[0] is not commit:
                return False
            self.waiting.pop(0)
        try:
            job = CommitJob(input_ids=commit.ids.unsqueeze(0), max_new_tokens=1,
                            identifier=("session-commit", commit.op_id), plan=commit.plan)
            serial = self.generator.enqueue(job)
        except Exception as error:
            self.finish_commit(commit, refusal=Refused(LOST_RESIDENCY, f"the commit could not start: {error}"))
            return False
        commit.job = job
        self.running[serial] = commit
        return True

    def after_pass(self):
        """Takes each commit whose prefill reached the end of its path."""
        for serial, commit in list(self.running.items()):
            if commit.job.prefilled():
                del self.running[serial]
                self.harvest(commit)

    def on_result(self, result):
        """A Generator result for no request: a commit's failure ends it."""
        commit = self.running.get(result.get("serial"))
        if commit is not None and result.get("stage") == "error":
            del self.running[result.get("serial")]
            error = result.get("error")
            self.finish_commit(commit, refusal=Refused(LOST_RESIDENCY, f"the commit failed: {error}"))

    def fail_commits(self, error):
        """The Generator failed a whole pass: every running commit ends."""
        for serial, commit in list(self.running.items()):
            del self.running[serial]
            self.cancel_job(commit.job)
            self.finish_commit(commit, refusal=Refused(LOST_RESIDENCY, f"the commit failed: {error}"))

    def stop_commit(self, commit, refusal):
        with self.lock:
            waiting = commit in self.waiting
            if waiting:
                self.waiting.remove(commit)
        for serial, running in list(self.running.items()):
            if running is commit:
                del self.running[serial]
                self.cancel_job(commit.job)
                waiting = True
        if waiting:
            self.finish_commit(commit, refusal=refusal)

    def close(self, error):
        """The scheduler is shutting down: every commit ends."""
        with self.lock:
            waiting, self.waiting = self.waiting, []
        for commit in waiting:
            self.finish_commit(commit, refusal=Refused(LOST_RESIDENCY, str(error)))
        self.fail_commits(error)

    def cancel_job(self, job):
        try:
            self.generator.cancel(job)
        except Exception as error:
            print(f"SESSION_CANCEL_ERROR {type(error).__name__}: {error}", flush=True)

    def harvest(self, commit):
        """The successor: the commit's pages through its frontier, the
        recurrent state at that exact frontier, and the latest snapshot below
        it to replay from."""
        job = commit.job
        seq = job.sequences[0]
        frontier = len(seq.sequence_ids) - 1
        exact = None
        if job.recurrent_state is not None and job.recurrent_state.position == frontier:
            exact = state.capture(self.generator.cache, job.recurrent_state)
        below = job.page_snapshot
        if below is not None and below.position == frontier:
            exact, below = exact or below, None
        if below is None:
            below = commit.plan.snapshot
        snapshots = [snapshot for snapshot in (below, exact) if snapshot is not None]
        owner = Owner()
        self.pagetable.hold(owner, seq.allocated_pages[:-(-frontier // PAGE_SIZE)])
        anchor = Anchor(commit.ids[:frontier].clone(), owner, snapshots)
        self.cancel_job(job)
        self.finish_commit(commit, anchor=anchor)

    def finish_commit(self, commit, anchor=None, refusal=None):
        if commit.reserved:
            commit.reserved = False
            self.scheduler.unreserve(commit.need)
        release = []
        with self.lock:
            session = commit.session
            if session.commit is commit:
                session.commit = None
            release += self.unpin(session, commit.base)
            if anchor is not None and (session.dropping or session.lost):
                release.append(anchor)
                anchor = None
                refusal = Refused(LOST_RESIDENCY, "the session stopped serving while its commit ran")
            if anchor is not None:
                checkpoint = Checkpoint(anchor, commit.staged.head,
                                        commit.base.digest if commit.base is not None else None)
                release += self.retire(session, session.successor)
                session.successor = checkpoint
                commit.reply = {"staged": checkpoint.ref(),
                                "computed_tokens": anchor.frontier - commit.plan.position}
            else:
                commit.refusal = refusal
                session.answers.pop(commit.op_id, None)
            self.lock.notify_all()
        self.release(release)
        commit.done.set()

    def stats(self):
        """Per-session unique bytes and residency, for the stats snapshot."""
        with self.lock:
            sessions = list(self.sessions.values())
            rows = []
            for session in sessions:
                published = session.published
                rows.append({"session": session.label, "resident": not session.lost,
                             "frontier_tokens": published.anchor.frontier if published is not None else 0,
                             "unique_bytes": self.unique_bytes(session)})
        total = None
        if self.page_bytes is not None:
            total = sum(row["unique_bytes"] for row in rows)
        return {"count": len(rows), "held_pages": self.held_pages(), "page_bytes": self.page_bytes,
                "unique_bytes": total, "commits_waiting": len(self.waiting), "commits_running": len(self.running),
                "per_session": rows}
