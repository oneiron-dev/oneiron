//! Typed speculative merge queue doors (DOOR-132): enqueue stored repository
//! proposals as one batch, stage it, read the pointers and named batches,
//! requeue the survivors of a diagnosed batch, land a reviewed batch, settle
//! slow results and recover an interrupted effect. Each one projects a
//! `MergeQueue` operation that exists, unchanged.
//!
//! None initializes or configures a queue, runs a check, diagnoses a red
//! batch, takes a verdict, a test result or a receipt from the caller, or
//! publishes a tested-tree record. The checker doors (`checker`, FIX 6868)
//! request those checks on the frozen plan; the server's drain runs them.
//! Landing keeps every engine gate: unanimous multi-critic admission, the
//! sealed queue permit, exact bytes and base, and durable mutation receipts.
//! The owner proof is not a critic approval and never stands in for one.
//!
//! Authority is the owner's live proof alone (`Memory::merge_queue_owner`),
//! checked before any id resolves, so a refusal is no existence oracle.

mod checker;
mod checker_types;
mod observation;
mod operations;
mod types;

pub use checker_types::*;
pub use types::*;

use std::path::Path;

use super::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::EntityId;
use crate::codebase::RepoRef;
use crate::consent::AuthenticatedOwner;
use crate::git_wire::{GitWire, GitWireRepoIdentity};
use crate::merge_queue::{MergeBatch, MergeQueue, MergeQueuePointers};
use crate::registry::ENTITY_TYPE_CODE_ARTIFACT;

/// One registered repository a merge queue door acts on: its stored pointer
/// and the object store that pointer names.
struct QueuedRepo {
    repo: EntityId,
    repo_ref: RepoRef,
    identity: GitWireRepoIdentity,
}

impl Memory<'_> {
    /// The CALL behind every DOOR-132 door: merge queue doors are owner-only,
    /// observe included (the caller's own owner proof). The proof must be
    /// live on this vault and name this handle's own human actor. An agent
    /// never borrows it, and no request field names an actor.
    fn merge_queue_owner(&self, owner: &AuthenticatedOwner) -> MemoryResult<EntityId> {
        let actor = owner.revalidate(self.vault)?;
        if actor != self.actor || self.actor_class != crate::EdgeActorClass::Human {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "merge queue doors act as the authenticated owner",
                &["Present the owner's own verified, unattenuated credential."],
            ));
        }
        Ok(actor)
    }

    /// A row the door reads or names, which the caller's credential must
    /// read. Absent and withheld read alike.
    fn merge_queue_readable(&self, id: EntityId) -> MemoryResult<()> {
        self.produced_from([id]);
        if self.get_entity(&id.to_hex())?.value.is_none() {
            return Err(MemoryError::not_found(
                "merge queue record is absent or withheld",
            ));
        }
        Ok(())
    }

    /// The CALL behind the public repository identity: `repo` is an existing
    /// CODE_ARTIFACT the caller reads, and the door uses the local folder
    /// pointer stored on it. A remote pointer refuses; no folder path is
    /// taken from the request.
    fn merge_queue_repo(&self, repo: EntityId) -> MemoryResult<QueuedRepo> {
        self.merge_queue_readable(repo)?;
        if self.vault.get_entity_type(&repo)? != Some(ENTITY_TYPE_CODE_ARTIFACT) {
            return Err(MemoryError::bad_request(
                "repo must name a CODE_ARTIFACT record",
            ));
        }
        let body = self
            .vault
            .get_code_artifact(&repo)?
            .ok_or_else(|| MemoryError::not_found("code artifact not found"))?;
        let repo_ref = RepoRef::parse(&body.repo_ref)?;
        let identity = self.merge_queue_store(&repo_ref)?;
        Ok(QueuedRepo {
            repo,
            repo_ref,
            identity,
        })
    }

    /// The object store a local folder pointer names. The merge queue keeps
    /// one queue per object store and has no remote one.
    fn merge_queue_store(&self, repo_ref: &RepoRef) -> MemoryResult<GitWireRepoIdentity> {
        let RepoRef::LocalFolder { path, .. } = repo_ref else {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "the merge queue serves a local repository only",
                &["Name a code artifact whose stored pointer is a local folder."],
            ));
        };
        Ok(GitWire::new(self.vault)?.repository_identity(Path::new(path))?)
    }

    /// The unchanged engine queue of one registered repository.
    fn merge_queue_of(&self, repo: &QueuedRepo) -> MemoryResult<MergeQueue<'_>> {
        Ok(MergeQueue::open(self.vault, repo.repo_ref.clone())?)
    }
}

/// A batch as the wire carries it: ids and Git commits only. Proposal bytes,
/// the retained snapshot and host worktree paths stay in the engine.
fn batch_view(batch: MergeBatch) -> MergeQueueBatchView {
    MergeQueueBatchView {
        batch_ref: batch.id,
        baseline_ref: batch.baseline_id,
        expected_head: batch.expected_head,
        base_green: batch.base_green,
        proposals: batch
            .proposals
            .into_iter()
            .map(|proposal| proposal.id)
            .collect(),
        state: batch.state,
        paths: batch
            .paths
            .into_iter()
            .map(|path| MergeQueuePathView {
                mask: path.mask,
                commit: path.commit,
                tree: path.tree,
                verdict_ref: path.verdict,
            })
            .collect(),
        landed_head: batch.landed_head,
        slow_verdict_ref: batch.slow_verdict,
        quarantine: batch.quarantine,
        selected_tests: batch.selected_tests,
    }
}

/// The CALL behind the pointer names: the queue head and green are raw Git
/// commits, named `head_commit` and `green_commit`. They are not relabeled
/// as tested-tree records.
fn pointers_view(repo: EntityId, pointers: MergeQueuePointers) -> MergeQueuePointersView {
    MergeQueuePointersView {
        repo,
        head_commit: pointers.head,
        green_commit: pointers.green,
        pending_slow_batch_refs: pointers.pending_slow,
    }
}
