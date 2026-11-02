//! Merge queue operations: enqueue, stage, requeue, land, settle slow batches and recover.
//! `Memory::merge_queue_enqueue_as` is its call surface.
//! `memory::merge_queue_doors::types` defines the records these take and return.

use super::*;
use crate::merge_queue::{MergeFile, MergeFileExpected, MergeProposal};
use crate::repo_mutation::mount::RepoMountRef;

impl Memory<'_> {
    /// `vault.code.merge_queue.enqueue`: queues stored repository proposals
    /// as one batch through the unchanged `MergeQueue::enqueue`, which keeps
    /// its size limit and green-base check and speculates six proposals at a
    /// time (FIX 9948). No proposal is reviewed, checked or landed here.
    pub fn merge_queue_enqueue_as(
        &self,
        owner: &AuthenticatedOwner,
        input: MergeQueueEnqueueRequest,
    ) -> MemoryResult<MergeQueueBatchView> {
        self.merge_queue_owner(owner)?;
        let repo = self.merge_queue_repo(input.repo)?;
        let queue = self.merge_queue_of(&repo)?;
        if queue.pointers()?.green != input.base_green {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "base_green is not the queue green commit",
                &["Observe the queue and name its current green_commit."],
            ));
        }
        let proposals = self.merge_queue_submitted(&repo, &input.proposals, &input.base_green)?;
        Ok(batch_view(queue.enqueue(proposals)?))
    }

    /// `vault.code.merge_queue.stage`: materializes every nonempty subset of
    /// a queued batch in its own journaled detached worktree through the
    /// unchanged `MergeQueue::stage`. Head and green do not move.
    pub fn merge_queue_stage_as(
        &self,
        owner: &AuthenticatedOwner,
        input: MergeQueueBatchRequest,
    ) -> MemoryResult<MergeQueueBatchView> {
        self.merge_queue_owner(owner)?;
        let repo = self.merge_queue_repo(input.repo)?;
        let queue = self.merge_queue_of(&repo)?;
        Ok(batch_view(queue.stage(&input.batch_ref)?))
    }

    /// `vault.code.merge_queue.requeue_survivors`: enqueues the proposals a
    /// diagnosed red batch did not quarantine as a new batch, through the
    /// unchanged `MergeQueue::requeue_survivors`. The red batch and its
    /// quarantine are kept. A moved head refuses; nothing rebases.
    pub fn merge_queue_requeue_survivors_as(
        &self,
        owner: &AuthenticatedOwner,
        input: MergeQueueBatchRequest,
    ) -> MemoryResult<MergeQueueRequeueView> {
        self.merge_queue_owner(owner)?;
        let repo = self.merge_queue_repo(input.repo)?;
        let queue = self.merge_queue_of(&repo)?;
        let batch = queue.requeue_survivors(&input.batch_ref)?.map(batch_view);
        Ok(MergeQueueRequeueView {
            source_batch_ref: input.batch_ref,
            batch,
        })
    }

    /// `vault.code.merge_queue.land_reviewed`: advances the fast-tested head
    /// by one ready batch through the unchanged `MergeQueue::land_reviewed`
    /// alone. Every member still needs its own unanimous multi-critic
    /// approval, the exact tested bytes and base, and a durable mutation
    /// receipt; the owner proof approves nothing.
    pub fn merge_queue_land_reviewed_as(
        &self,
        owner: &AuthenticatedOwner,
        input: MergeQueueBatchRequest,
    ) -> MemoryResult<MergeQueueBatchView> {
        self.merge_queue_owner(owner)?;
        let repo = self.merge_queue_repo(input.repo)?;
        let queue = self.merge_queue_of(&repo)?;
        Ok(batch_view(queue.land_reviewed(&input.batch_ref)?))
    }

    /// `vault.code.merge_queue.settle_slow`: consumes stored slow results in
    /// landing order through the unchanged `MergeQueue::settle_slow`. Green
    /// advances only past passing results; a red one rolls the ungreen
    /// suffix back. The caller names no commit and no result.
    pub fn merge_queue_settle_slow_as(
        &self,
        owner: &AuthenticatedOwner,
        input: MergeQueueRepoRequest,
    ) -> MemoryResult<MergeQueuePointersView> {
        self.merge_queue_owner(owner)?;
        let repo = self.merge_queue_repo(input.repo)?;
        let queue = self.merge_queue_of(&repo)?;
        Ok(pointers_view(repo.repo, queue.settle_slow()?))
    }

    /// `vault.code.merge_queue.recover`: reconciles an interrupted landing or
    /// rollback with its persisted mutation receipts through the unchanged
    /// `MergeQueue::recover`. Unreceipted divergence refuses.
    pub fn merge_queue_recover_as(
        &self,
        owner: &AuthenticatedOwner,
        input: MergeQueueRepoRequest,
    ) -> MemoryResult<MergeQueuePointersView> {
        self.merge_queue_owner(owner)?;
        let repo = self.merge_queue_repo(input.repo)?;
        // A served source's missing projection is put back first (FIX 6869).
        let queue = self
            .vault
            .open_queue_for_recovery(repo.repo, &repo.repo_ref)?;
        let pointers = queue.recover()?;
        // A no-op recovery wakes the queue driver too (FIX 6868).
        self.vault.store.notify_attempt_observers();
        Ok(pointers_view(repo.repo, pointers))
    }

    /// The CALL behind batch formation: one enqueue call is one batch, its
    /// proposals in request order, with no batching window, tick or policy.
    /// Each proposal is a stored one the caller reads, of this repository's
    /// object store and pinned at `base_green`.
    fn merge_queue_submitted(
        &self,
        repo: &QueuedRepo,
        proposals: &[EntityId],
        base_green: &str,
    ) -> MemoryResult<Vec<MergeProposal>> {
        proposals
            .iter()
            .map(|proposal| self.merge_queue_proposal(repo, *proposal, base_green))
            .collect()
    }

    /// The CALL behind a proposal ref: the engine input is built from the
    /// stored proposal alone. Its path and new bytes are the reviewed ones,
    /// and the expected bytes are read from its own retained base fork. No
    /// byte, vote, actor or verdict comes from the request.
    fn merge_queue_proposal(
        &self,
        repo: &QueuedRepo,
        id: EntityId,
        base_green: &str,
    ) -> MemoryResult<MergeProposal> {
        self.merge_queue_readable(id)?;
        let row = self
            .vault
            .repo_proposal(id)?
            .ok_or_else(|| MemoryError::not_found("repository proposal not found"))?;
        self.produced_from([row.session, row.provenance_claim]);
        let pointer = RepoRef::parse(&row.repo)?;
        if self.merge_queue_store(&pointer)? != repo.identity {
            return Err(MemoryError::bad_request(
                "the proposal belongs to another repository",
            ));
        }
        if pointer.commit_hash() != Some(base_green) {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "the proposal is not pinned at the queue green commit",
                &["Propose the change again from the current green commit."],
            ));
        }
        // A file bundle is ONE queue proposal carrying all its files, each
        // with its reviewed state change; the caller names none of it.
        if row.is_file_bundle() {
            return Ok(crate::repo_mutation::bundle_merge_proposal(
                self.vault, &row, base_green,
            )?);
        }
        let base = self
            .vault
            .mount_repo_ref(&pointer, RepoMountRef::Fork(row.pre_action_fork_hash))?;
        let (path, content) = row.ordinary_file()?;
        let expected = base
            .read_file(path)?
            .map(|bytes| MergeFileExpected::Bytes(bytes.to_vec()));
        Ok(MergeProposal {
            id: row.id.to_hex(),
            base_green: base_green.to_owned(),
            files: vec![MergeFile {
                path: path.to_owned(),
                expected,
                content: Some(content.to_vec()),
                metadata_edit: None,
            }],
        })
    }
}
