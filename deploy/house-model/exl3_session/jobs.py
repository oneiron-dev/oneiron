"""The Jobs a session runs: the stock Job with a session mixin before it.

A Plan says where a Job attaches: an anchor, a position, the snapshot there.
A session Job's pages never enter the page table's hash index: it looks
none up by content and gives none a content hash (`hash_completed_page`
only links pages), so no page it writes is ever a candidate for another
call, vault or read scope, and the only pages it shares are its anchor's.

It never writes a shared page. The pages before its attach point's page are
the anchor's, read only. A partial page at the attach point is copied into a
fresh page, target and draft caches alike, before the Job writes past it
(copy-on-write); every other page is fresh, a replay from an earlier
snapshot included. Its recurrent snapshot stays its own, never in the
shared, hash-keyed checkpoint cache.

A frontier between page boundaries is prefilled to the next boundary in one
chunk of its own (the stock prefill starts chunks on page boundaries), then
the stock prefill goes on.

FrontierMixin is a working branch's Job: the stock Job from its attach point
on. CommitMixin is `session.suffix_commit`'s: prefill only and final-token
inclusive, over the staged path plus one pad id that never runs, with no
sampling. It never joins a generation pass; the layer takes its state once
its prefill has reached the end of the path.

Both run behind the executor's ScheduledJob (`exl3_executor.py`), which
bounds the stock prefill's chunk by the Job's class; the chunk to the next
page boundary here is never longer than a page.
"""
import time

import torch
from exl3_executor import ScheduledJob
from exllamav3 import Job
from exllamav3.constants import PAGE_SIZE

from . import state


class Plan:
    """Where a session Job attaches, and what it keeps. `on_release` is
    called with the Job and its pages just before it gives them back."""

    __slots__ = ("anchor", "position", "snapshot", "carry", "on_release")

    def __init__(self, anchor=None, position=0, snapshot=None, carry=False, on_release=None):
        self.anchor = anchor if position else None
        self.position = position if anchor is not None else 0
        self.snapshot = snapshot if self.anchor is not None else None
        self.carry = carry
        self.on_release = on_release


class SessionJob:
    """The session mixin: put it before the server's Job class."""

    def __init__(self, *args, plan=None, **kwargs):
        # A requeue runs __init__ again on the same object: the plan is kept.
        kept = plan if plan is not None else getattr(self, "plan", None)
        super().__init__(*args, **kwargs)
        self.plan = kept if kept is not None else Plan()
        self.page_snapshot = None

    def keeps_page_snapshot(self):
        return self.plan.carry

    def _caches(self):
        generator = self.generator
        return [generator.cache] if not generator.draft_model else [generator.cache, generator.draft_cache]

    def prepare_for_queue(self, generator, serial_number, rq=False):
        super().prepare_for_queue(generator, serial_number, rq)
        if rq:
            # A requeued Job runs over its own sequence: no anchor.
            self.plan = Plan(carry=self.plan.carry, on_release=self.plan.on_release)
        seq = self.sequences[0]
        total = -(-(len(seq.sequence_ids) + self.max_rq_tokens + self.rq_headroom) // PAGE_SIZE)
        # No content hash to look up: every page past the shared ones is
        # fresh.
        seq.page_hashes = []
        seq.new_unique_pages = total - self.plan.position // PAGE_SIZE
        self.all_unique_hashes = []

    def allocate_pages(self):
        generator, pagetable, plan = self.generator, self.pagetable, self.plan
        seq = self.sequences[0]
        position = plan.position
        shared = position // PAGE_SIZE
        pages = []
        if plan.anchor is not None:
            for page in plan.anchor.owner.pages[:shared]:
                pagetable.access_serial += 1
                page.add_ref(pagetable.access_serial)
                pages.append(page)
        fresh, _, _, non_sequential = pagetable.allocate_pages([], seq.new_unique_pages, None)
        tail = position - shared * PAGE_SIZE
        if tail:
            # Copy-on-write: the anchor's partial page stays as it is; this
            # Job writes its own copy.
            source, copy = plan.anchor.owner.pages[shared], fresh[0]
            for cache in self._caches():
                cache.copy_page(cache, source.page_index, copy.page_index, tail)
            copy.sequence[:, :tail].copy_(plan.anchor.tokens[shared * PAGE_SIZE:position].unsqueeze(0))
            copy.kv_position = tail
            copy.prev_hash = pages[-1].phash if pages else None
            copy.can_revert = False
        seq.allocated_pages = pages + fresh
        seq.kv_position = position
        seq.build_block_index_tensor()
        self.free_recurrent_state()
        if generator.recurrent_cache is not None:
            if plan.snapshot is not None:
                self.recurrent_state = state.restore(generator.cache, plan.snapshot)
                self.last_recurrent_checkpoint_pos = position
            else:
                self.recurrent_state = generator.cache.get_new_state()
        # The receipt's cache read: what the anchor gave.
        self.cached_pages += shared
        self.cached_tokens += tail
        self.total_pages += len(seq.allocated_pages)
        self.non_sequential_pages += non_sequential

    def prefill(self, results):
        seq = self.sequences[0]
        if seq.prefill_complete or seq.kv_position % PAGE_SIZE == 0:
            super().prefill(results)
            return
        if self.time_first_prefill is None:
            self.time_first_prefill = time.time()
        self._prefill_to_boundary(seq, results)

    def _prefill_to_boundary(self, seq, results):
        """One chunk from a frontier between page boundaries to the next
        boundary, or to the prompt's last id: the stock chunk's forward,
        draft update and page bookkeeping."""
        generator = self.generator
        start = seq.kv_position
        end = min((start // PAGE_SIZE + 1) * PAGE_SIZE, len(seq.sequence_ids) - 1)
        if end <= start:
            seq.prefill_complete = True
            return
        ids = seq.sequence_ids.torch_slice(start, end)
        params = {
            "attn_mode": "flash_attn",
            "block_table": seq.block_index_tensor,
            "cache": generator.cache,
            "cache_seqlens": torch.tensor([start], dtype=torch.int32),
            "recurrent_states": [self.recurrent_state] if self.recurrent_state is not None else None,
            "indexed_embeddings": self.embeddings,
            "inv_freq": self.alt_rope_freqs,
            "mm_span_prefix": 0,
        }
        if generator.draft_model:
            params.update(generator.draft_model.draft_verifier_params)
        generator.model.prefill(input_ids=ids, params=params)
        if generator.dflash_draft:
            generator.draft_model.update_kv_from_target(
                target_hidden=params.get("export_states"),
                cache=generator.draft_cache,
                params={"block_table": seq.block_index_tensor, "cache_seqlens": params["cache_seqlens"]},
            )
        elif generator.draft_model:
            generator.draft_model.prefill(
                input_ids=ids,
                params={
                    "target_hidden": None,
                    "attn_mode": "flash_attn",
                    "block_table": seq.block_index_tensor,
                    "cache": generator.draft_cache,
                    "cache_seqlens": torch.tensor([start], dtype=torch.int32),
                    "indexed_embeddings": None,
                },
            )
        index = start // PAGE_SIZE
        page = seq.allocated_pages[index]
        offset = start - index * PAGE_SIZE
        page.sequence[:, offset:offset + (end - start)].copy_(ids)
        page.kv_position = end - index * PAGE_SIZE
        page.can_revert = False
        seq.kv_position = end
        if page.kv_position == PAGE_SIZE:
            self.hash_completed_page(seq, index)
        if end >= len(seq.sequence_ids) - 1:
            seq.prefill_complete = True
        result = {
            "job": self,
            "stage": "prefill",
            "eos": False,
            "curr_progress": seq.kv_position,
            "max_progress": len(seq.sequence_ids) - 1,
            "serial": self.serial_number,
        }
        if self.identifier is not None:
            result["identifier"] = self.identifier
        results.append(result)

    def hash_completed_page(self, seq, page_idx):
        # A session page keeps its random hash: only the link to it is
        # written.
        if page_idx + 1 < len(seq.allocated_pages):
            following = seq.allocated_pages[page_idx + 1]
            following.prev_hash = seq.allocated_pages[page_idx].phash
            following.can_revert = False

    def maybe_stash_recurrent(self, cache, interval=None):
        # Only the stock prefill's last-page pass (which names `interval`)
        # is kept, as this Job's own snapshot, and only where it is wanted.
        if interval is None or self.recurrent_state is None or not self.keeps_page_snapshot():
            return
        seq = self.sequences[0]
        position = seq.kv_position
        if position == 0 or position % PAGE_SIZE or self.recurrent_state.position != position:
            return
        self.page_snapshot = state.capture(self.generator.cache, self.recurrent_state)

    def deallocate_pages(self):
        seq = self.sequences[0]
        pages = list(seq.allocated_pages or [])
        hook, self.plan.on_release = self.plan.on_release, None
        if hook is not None and pages:
            try:
                hook(self, pages)
            except Exception as error:  # a carry never stops the release
                print(f"SESSION_CARRY_ERROR {type(error).__name__}: {error}", flush=True)
        super().deallocate_pages()
        self.pagetable.scrub(pages)


class FrontierMixin(SessionJob):
    """A working branch's Job: attached at its plan's frontier, the stock
    Job from there on."""


class CommitMixin(SessionJob):
    """`session.suffix_commit`'s Job: its last id is a pad that never runs."""

    def keeps_page_snapshot(self):
        return True

    def is_prefill_done(self):
        # Never sampled: no generation pass takes it.
        return False

    def prefilled(self):
        """True once every id of the staged path has run."""
        seq = self.sequences[0]
        return seq.kv_position >= len(seq.sequence_ids) - 1


class CommitJob(ScheduledJob, CommitMixin, Job):
    """A commit's Job: the executor's (`exl3_executor.py`), its prefill
    bounded by its class as a call's is."""
