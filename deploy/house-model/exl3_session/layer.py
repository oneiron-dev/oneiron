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

Snapshots (R3). `export_checkpoint` copies a published checkpoint's tokens,
KV pages and recurrent snapshot to the host, here, where no page moves under
it; the op encodes them off this thread. `import_checkpoint` takes fresh
pages for one only when they fit beside what is reserved and held (idle
sessions are evicted for them as for a request, and otherwise the import is
refused `snapshot_busy`), writes them, and stages the result. The layer
advertises codec minor 2 and its snapshot format only where both work: a
quantized KV layout, a portable recurrent state, a known model, tokenizer,
template and runtime, and a sealed memfd to pass.

Scheduling (R4, `exl3_executor.py`). A commit, an export and an import
carry the class, priority and deadline their op names. A commit's Job is
the executor's, its prefill bounded by its class; a background commit
starts only where the class policy lets background work in. A background
transfer copies its pages TRANSFER_CHUNK_PAGES at a time while foreground
work is present, each chunk a scheduler chore with rounds between them, its
checkpoint or its pages checked again before each; any other copies at
once, as before. The snapshot format and the publication are the same
either way.
"""
import time

import torch
from exllamav3.constants import PAGE_SIZE

from . import ops, snapshot, state
from .anchor import Anchor, token_digest
from .jobs import CommitJob, Plan
from .pages import Owner
from .registry import (LOST_RESIDENCY, SNAPSHOT_BUSY, SNAPSHOT_INCOMPATIBLE, STALE_GENERATION, UNKNOWN_SESSION,
                       Checkpoint, Refused, Registry)

# The capability a worker with this layer advertises in its hello.
SCHEMA_MINOR = 1
OPS = ("session.create", "session.fork", "session.generate", "session.append", "session.suffix_commit",
       "session.checkpoint", "session.drop")
# What a worker that exports and imports snapshots advertises besides.
SNAPSHOT_MINOR = 2
SNAPSHOT_OPS = ("session.export", "session.import")
# The worker identity a snapshot is bound to: every field but its epoch and
# the per-call execution mode. Unknown, no snapshot is advertised.
IDENTITY_FIELDS = ("model", "tokenizer", "template", "runtime")
# A snapshot header's fields.
HEADER_FIELDS = frozenset(("checkpoint", "compatibility", "kv", "state", "tensors", "token_count"))


def compatibility(identity, generator):
    """What an imported snapshot must match on this worker, or None when it
    cannot write or rebuild one: the identity less its epoch, the KV layout
    and the recurrent state kind."""
    if identity is None or not snapshot.hostable():
        return None
    record = identity.record(None)
    kv, kind = snapshot.kv_layout(generator.cache), state.portable_kind(generator.cache)
    if kv is None or kind is None or any(record.get(field) is None for field in IDENTITY_FIELDS):
        return None
    return dict({field: record[field] for field in IDENTITY_FIELDS}, kv=kv, state=kind)


def kv_extent(frontier):
    """The pages a frontier spans, and the valid tokens of the last."""
    pages = -(-frontier // PAGE_SIZE)
    return {"pages": pages, "last_page_tokens": frontier - (pages - 1) * PAGE_SIZE}


class SessionLayer(Registry):

    # What the native channel (exl3_ipc.py) reads off the layer, so it
    # imports nothing of it.
    Refused = Refused
    WITH_INPUT = ops.WITH_INPUT
    SNAPSHOT_INPUT = ops.SNAPSHOT_INPUT
    SNAPSHOT_OUTPUT = ops.SNAPSHOT_OUTPUT
    SNAPSHOT_ENCODING = snapshot.ENCODING

    def __init__(self, generator, render, encode, identity=None):
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
        self.compatibility = compatibility(identity, generator)

    def capability(self):
        if self.compatibility is None:
            return {"minor": SCHEMA_MINOR, "ops": list(OPS)}
        return {"minor": SNAPSHOT_MINOR, "ops": list(OPS + SNAPSHOT_OPS),
                "snapshot": {"schema": snapshot.SCHEMA, "encoding": snapshot.ENCODING, "hash": snapshot.HASH,
                             "state_kinds": [self.compatibility["state"]]}}

    def answer(self, op, body, conversation):
        """The answer body of session op `op` (not `session.generate`; for
        `session.export`, the answer and its region); Refused when it is
        refused."""
        return ops.answer(self, op, body, conversation)

    def claim_call(self, field):
        """The working branch a `session.generate`'s `session` field names,
        claimed for that call."""
        return ops.claim(self, field)

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
        """Gives back everything a dropped session held, once its calls and
        transfers have ended: its pages and state, and the snapshot regions
        its answers keep."""
        with self.lock:
            release = self.strip(session)
            release += [checkpoint.anchor for checkpoint in session.retired]
            session.retired = []
            self.forget_answers(session)
            self.leaving.discard(session)
        self.release(release)

    # Snapshots: the copies run on the scheduler thread, at once or in
    # chunks of pages (exl3_executor.TRANSFER_CHUNK_PAGES), each chunk a
    # chore of its own with rounds between them.

    def export_checkpoint(self, session, checkpoint, work):
        """`session.export`'s copy, from the op's thread: the header fields
        and host tensors of `checkpoint`, for the op to encode. Copied on the
        scheduler thread at once, or, while the executor chunks a transfer
        of `work`'s class (`Executor.transfer_chunk`), a chunk of pages per
        chore, the checkpoint checked again before each: one that stops
        serving between them refuses the export, a cache miss to the host.
        The format is the same either way."""
        run = self.scheduler.run_owned
        progress = {"copy": None}

        def step():
            # One chore: the header, tokens and state first, then a chunk
            # of pages; True once every page is copied.
            copy = progress["copy"]
            if copy is None:
                copy = progress["copy"] = self._export_begin(session, checkpoint)
            self._export_pages(session, checkpoint, copy, self.scheduler.executor.transfer_chunk(work))
            return copy.next >= copy.count

        while not run(step):
            pass
        copy = progress["copy"]
        return copy.fields, copy.tensors()

    def _export_check(self, session, checkpoint):
        with self.lock:
            if session.dropping:
                raise Refused(UNKNOWN_SESSION, "the session was dropped")
            if session.lost or checkpoint.anchor.released:
                raise Refused(LOST_RESIDENCY, "the session's checkpoint is no longer held")
            if session.published is not checkpoint:
                raise Refused(STALE_GENERATION, "another checkpoint is published")

    def _export_begin(self, session, checkpoint):
        """The export's header fields, tokens and recurrent state, while
        `checkpoint` is still `session`'s published checkpoint. The
        recurrent state is the latest snapshot at or below its frontier:
        exact at the frontier for GDN, the page boundary below it for an SWA
        frontier between two."""
        self._export_check(session, checkpoint)
        anchor = checkpoint.anchor
        below = [held for held in anchor.snapshots if held.position <= anchor.frontier]
        if not below:
            raise Refused(SNAPSHOT_INCOMPATIBLE, "the checkpoint holds no recurrent state to carry")
        cache = self.generator.cache
        state_fields, state_tensors = state.capture_portable(cache, below[-1])
        tensors = [("tokens", anchor.tokens.to(torch.int64).contiguous())] + state_tensors
        fields = {"checkpoint": checkpoint.ref(), "compatibility": self.compatibility,
                  "token_count": anchor.frontier, "kv": kv_extent(anchor.frontier), "state": state_fields}
        return snapshot.KvCopy(fields, tensors, anchor.owner.pages, anchor.frontier)

    def _export_pages(self, session, checkpoint, copy, chunk):
        """The KV of the export's next `chunk` pages (all that are left for
        None), its checkpoint checked again first."""
        self._export_check(session, checkpoint)
        stop = copy.count if chunk is None else min(copy.count, copy.next + chunk)
        copy.add(snapshot.gather_kv(self.generator.cache, copy.pages, copy.frontier, copy.next, stop))
        copy.next = stop

    def decode_import(self, payload, ref):
        """The snapshot `payload` as this worker rebuilds it, on any thread:
        checked against the format, this worker's compatibility, the
        checkpoint `ref` the host names, its token digest, and this cache's
        geometry. Refused `snapshot_incompatible` otherwise."""
        header, tensors = snapshot.decode_snapshot(payload)
        if set(header) != HEADER_FIELDS:
            raise Refused(SNAPSHOT_INCOMPATIBLE, "the snapshot's header is not snapshot_v1's")
        if header["compatibility"] != self.compatibility:
            raise Refused(SNAPSHOT_INCOMPATIBLE, "the snapshot was taken on another model, build or layout")
        if header["checkpoint"] != ref:
            raise Refused(SNAPSHOT_INCOMPATIBLE, "the snapshot holds another checkpoint")
        frontier = header["token_count"]
        if type(frontier) is not int or frontier < 1 or frontier != ref["frontier_tokens"] \
                or header["kv"] != kv_extent(frontier):
            raise Refused(SNAPSHOT_INCOMPATIBLE, "the snapshot's extent is not its checkpoint's")
        tokens = snapshot.take(tensors, "tokens", (frontier,), torch.int64)
        if token_digest(tokens) != ref["digest"]:
            raise Refused(SNAPSHOT_INCOMPATIBLE, "the snapshot's tokens are not its checkpoint's")
        cache = self.generator.cache
        recurrent = state.rebuild_portable(cache, header["state"], tensors, frontier)
        kv = {name: snapshot.take(tensors, name, shape, dtype)
              for name, (shape, dtype) in snapshot.kv_shapes(cache, frontier).items()}
        if tensors:
            raise Refused(SNAPSHOT_INCOMPATIBLE, f"the snapshot holds tensors this worker does not: {sorted(tensors)}")
        return snapshot.Rebuilt(tokens, recurrent, kv, ref["head"], ref["parent"])

    def import_checkpoint(self, session, op_id, generation, rebuilt, size, sha256, work):
        """`session.import` here, from the op's thread: `rebuilt` written
        into fresh pages and staged as `session`'s successor, under the same
        checks the op made. Refused `snapshot_busy` when its pages do not
        fit beside what is reserved and held, idle sessions evicted first.
        The pages are written on the scheduler thread at once, or, while the
        executor chunks a transfer of `work`'s class, a chunk per chore; the
        session holds them meanwhile (`importing`), and an eviction or a
        drop between chunks refuses the import."""
        frontier = int(rebuilt.tokens.numel())
        count = -(-frontier // PAGE_SIZE)
        run = self.scheduler.run_owned
        progress = {"anchor": None, "written": 0}

        def step():
            # One chore: the pages first, then a chunk of KV, then the
            # stage once every page is written; None until then.
            anchor = progress["anchor"]
            if anchor is None:
                anchor = progress["anchor"] = self._import_begin(session, generation, rebuilt, count)
            progress["written"] = self._import_pages(session, anchor, rebuilt, progress["written"],
                                                     self.scheduler.executor.transfer_chunk(work))
            if progress["written"] < count:
                return None
            return self._import_stage(session, op_id, generation, anchor, rebuilt, size, sha256)

        try:
            while True:
                answer = run(step)
                if answer is not None:
                    return answer
        except BaseException:
            anchor = progress["anchor"]
            if anchor is not None and not self.scheduler.post(lambda: self._import_abandon(session, anchor)):
                with self.lock:
                    if session.importing is anchor:
                        session.importing = None
            raise

    def _import_begin(self, session, generation, rebuilt, count):
        """The import's fresh pages, held by `session` while they are
        written, with their tokens and zeroed draft KV."""
        with self.lock:
            self.import_target(session, generation)
            if session.importing is not None:
                raise Refused(STALE_GENERATION, "another import runs on this session")
        if not self.scheduler.room_for(count):
            raise Refused(SNAPSHOT_BUSY, f"the snapshot's {count} pages do not fit beside what runs")
        pages, _, _, _ = self.pagetable.allocate_pages([], count, None)
        owner = Owner()
        self.pagetable.adopt(owner, pages)
        anchor = Anchor(rebuilt.tokens, owner, [rebuilt.state])
        try:
            self.place(pages, rebuilt)
        except BaseException:
            self.release([anchor])
            raise
        with self.lock:
            session.importing = anchor
        return anchor

    def _import_pages(self, session, anchor, rebuilt, start, chunk):
        """Writes the KV of the import's next `chunk` pages from `start`
        (all that are left for None), once the session still holds them;
        returns where the next chunk starts."""
        with self.lock:
            if session.dropping:
                raise Refused(UNKNOWN_SESSION, "the session was dropped")
            if anchor.released or session.importing is not anchor:
                raise Refused(LOST_RESIDENCY, "the import's pages were evicted while it was written")
        pages = anchor.owner.pages
        stop = len(pages) if chunk is None else min(len(pages), start + chunk)
        snapshot.fill_kv(self.generator.cache, pages, int(rebuilt.tokens.numel()), rebuilt.kv, start, stop)
        return stop

    def _import_stage(self, session, op_id, generation, anchor, rebuilt, size, sha256):
        """Stages the written import as `session`'s successor and answers."""
        with self.lock:
            if anchor.released or session.importing is not anchor:
                raise Refused(LOST_RESIDENCY, "the import's pages were evicted while it was written")
            session.importing = None
            try:
                self.import_target(session, generation)
            except Refused:
                session.importing = anchor
                raise
            checkpoint = Checkpoint(anchor, rebuilt.head, rebuilt.parent)
            session.successor = checkpoint
            answer = {"staged": checkpoint.ref(), "imported_bytes": size, "snapshot_sha256": sha256,
                      "residency": self.residency(session)}
            self.remember(session, op_id, generation, answer)
        return answer

    def _import_abandon(self, session, anchor):
        """An import that stopped: the pages it held go."""
        with self.lock:
            if session.importing is anchor:
                session.importing = None
        self.release([anchor])

    def place(self, pages, rebuilt):
        """Writes `rebuilt`'s tokens into fresh `pages`, in sequence order,
        and zeroes their draft KV, which the draft rebuilds from the frontier
        on; their target KV is written next (`snapshot.fill_kv`). No page is
        a revert candidate once written to."""
        tokens = rebuilt.tokens
        for page in pages:
            page.can_revert = False
        for index, page in enumerate(pages):
            start = index * PAGE_SIZE
            valid = min(PAGE_SIZE, int(tokens.numel()) - start)
            page.sequence[:, :valid].copy_(tokens[start:start + valid].unsqueeze(0))
            page.kv_position = valid
            page.prev_hash = pages[index - 1].phash if index else None
        draft = getattr(self.generator, "draft_cache", None)
        if draft is not None:
            snapshot.clear_pages(draft, pages)

    # Commits, on the scheduler thread.

    def next_commit(self):
        with self.lock:
            return self.waiting[0] if self.waiting else None

    def running_commits(self):
        return len(self.running)

    def foreground_commits(self):
        """Commits of foreground work the host has not paused, waiting or
        running: foreground work the executor sees present."""
        with self.lock:
            commits = list(self.waiting) + list(self.running.values())
        return sum(1 for commit in commits if commit.work.foreground() and not commit.work.yielded)

    def background_commits(self):
        """Running commits of background work."""
        return sum(1 for commit in list(self.running.values()) if not commit.work.foreground())

    def start_commit(self, commit):
        """Enqueues the head commit's Job, with its scheduling; False when it
        could not start (it has been answered)."""
        with self.lock:
            if not self.waiting or self.waiting[0] is not commit:
                return False
            self.waiting.pop(0)
        try:
            job = CommitJob(input_ids=commit.ids.unsqueeze(0), max_new_tokens=1,
                            identifier=("session-commit", commit.op_id), plan=commit.plan, work=commit.work)
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
        """The scheduler is shutting down: every commit ends, and every
        snapshot region an answer keeps closes."""
        with self.lock:
            waiting, self.waiting = self.waiting, []
            for session in list(self.sessions.values()) + list(self.leaving):
                self.forget_answers(session)
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
                             "unique_bytes": self.unique_bytes(session),
                             "retained_snapshot_bytes": self.retained_bytes(session)})
        total = None
        if self.page_bytes is not None:
            total = sum(row["unique_bytes"] for row in rows)
        return {"count": len(rows), "held_pages": self.held_pages(), "page_bytes": self.page_bytes,
                "unique_bytes": total, "commits_waiting": len(self.waiting), "commits_running": len(self.running),
                "retained_snapshot_bytes": sum(row["retained_snapshot_bytes"] for row in rows),
                "per_session": rows}
