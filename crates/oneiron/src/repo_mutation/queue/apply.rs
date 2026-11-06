//! The execution body of one queued repository mutation (moved from
//! `queue.rs`, FIX 4360): authorize, prepare, lower the document, execute
//! and finish. A composed reviewed-stack member is authorized on its
//! original request, then runs the effective request its sealed step
//! derives, the same one for Git preparation, the expected post-snapshot,
//! the document lowering and execution.

use std::path::Path;

use crate::Vault;
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::lock_repository;

use super::super::git::{
    admitted_repo_ref, git_common_dir, require_pinned_head, resolve_mutable_repo_root,
};
use super::super::oplog::{
    OPLOG, REPO_MUTATION_OPLOG_SCHEMA_VERSION, StoredPreparedCommit,
    StoredPreparedConflictResolution, StoredRepoMutationOplogEntry, repo_mutation_oplog_key,
    repo_mutation_repo_key_hash,
};
use super::super::reviewed_stack::StackStep;
use super::super::snapshot::{SnapshotCustody, capture_repo_snapshot, decode_snapshot};
use super::super::support::{now_millis, truncate_failure};
use super::super::trailer::validate_repo_provenance_request;
use super::super::types::{
    RepoForkHash, RepoMutationOperation, RepoMutationOutcome, RepoMutationRequest,
    RepoMutationStatus,
};
use super::super::worktree::prune_queue_owned_worktrees;
use super::operation::{operation_subject, writes_file};
use super::{
    PreparedRepoMutation, PreparedRepoMutationAction, PreparedRepoMutationExecution,
    allocate_next_repo_mutation_seq, execute_repo_mutation, expected_post_action_fork_hash,
    prepare_repo_mutation_execution, require_staged_objects_available, store_snapshot_if_absent,
    validate_operation,
};
#[cfg(test)]
use super::{RepoMutationCrashPoint, take_repo_mutation_crash};

impl Vault {
    pub(super) fn apply_repo_mutation_inner(
        &self,
        request: RepoMutationRequest,
        proposal: Option<EntityId>,
        stack: Option<&StackStep>,
    ) -> Result<RepoMutationOutcome> {
        validate_operation(&request.operation)?;
        validate_repo_provenance_request(self, &request)?;
        let repo_root = resolve_mutable_repo_root(&request.repo_ref)?;
        let repo_ref = admitted_repo_ref(&request.repo_ref, &repo_root)?;
        let common_dir = git_common_dir(&repo_root)?;
        let _guard = lock_repository(&common_dir)?;
        let _ = prune_queue_owned_worktrees(&repo_root);

        if !matches!(
            request.operation,
            RepoMutationOperation::RecoverSnapshot { .. }
        ) {
            self.recover_prepared_repo_mutations_locked(&repo_ref, &repo_root)?;
        }

        super::super::proposal::authorize(self, &request, proposal, &repo_root, stack)?;
        // A composed stack member was authorized on its original reviewed
        // request; its sealed step derives the one request it runs (FIX 4360).
        let (request, lowering) = match stack
            .map(|step| step.effective_application(&request, &repo_root))
            .transpose()?
            .flatten()
        {
            Some(application) => {
                validate_operation(&application.request.operation)?;
                (
                    application.request,
                    Some((application.staged, application.composed)),
                )
            }
            None => (request, None),
        };
        let prepared = self.prepare_repo_mutation_with_proposal(
            &repo_ref, &request, &repo_root, proposal, stack,
        )?;
        #[cfg(test)]
        if take_repo_mutation_crash(RepoMutationCrashPoint::AfterPreparedBeforeAction) {
            let _ = prepared.execution.cleanup(&repo_root);
            return Err(Error::InvariantViolation(
                "test: injected repo mutation crash after Prepared before action",
            ));
        }

        let execution = (|| {
            if let Some(id) = proposal {
                match &lowering {
                    Some((staged, composed)) => {
                        super::super::document::land_stacked_document(self, id, staged, composed)?;
                    }
                    None => super::super::document::land_reviewed_document(self, id)?,
                }
            }
            #[cfg(test)]
            if take_repo_mutation_crash(RepoMutationCrashPoint::AfterDocumentBeforeAction) {
                return Err(Error::InvariantViolation(
                    "test: interrupted after reviewed document before Git action",
                ));
            }
            execute_repo_mutation(self, &repo_ref, &repo_root, &request, &prepared.execution)
        })();
        let cleanup = prepared.execution.cleanup(&repo_root);
        let execution = match (execution, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(repo_conflict_claim_id), Ok(())) => Ok(repo_conflict_claim_id),
        };

        #[cfg(test)]
        if execution.is_ok()
            && take_repo_mutation_crash(RepoMutationCrashPoint::AfterActionBeforeApplied)
        {
            return Err(Error::InvariantViolation(
                "test: injected repo mutation crash after action before Applied",
            ));
        }

        match execution {
            Ok(repo_conflict_claim_id) => {
                let entry = self.finish_repo_mutation(
                    &prepared.oplog,
                    RepoMutationStatus::Applied,
                    None,
                    now_millis(),
                )?;
                Ok(RepoMutationOutcome {
                    entry,
                    repo_conflict_claim_id,
                })
            }
            Err(error) => {
                // An attributed write can fail after its document or Git effect.
                // Keep its intent Prepared so recovery proves pre/post state,
                // rather than recording a false terminal failure after a commit.
                if proposal.is_some() {
                    return Err(error);
                }
                let failure = truncate_failure(&error.to_string());
                let _ = self.finish_repo_mutation(
                    &prepared.oplog,
                    RepoMutationStatus::Failed,
                    Some(failure),
                    now_millis(),
                );
                Err(error)
            }
        }
    }

    pub(super) fn prepare_repo_mutation_with_proposal(
        &self,
        repo_ref: &RepoRef,
        request: &RepoMutationRequest,
        repo_root: &Path,
        proposal: Option<EntityId>,
        stack: Option<&StackStep>,
    ) -> Result<PreparedRepoMutationAction> {
        let (fork_hash, snapshot_bytes) = capture_repo_snapshot(self, repo_root)?;
        let pre_action_snapshot = decode_snapshot(&snapshot_bytes)?;
        // A reviewed write is bound to its reviewed snapshot instead; its pin
        // was checked against HEAD when it was proposed.
        if proposal.is_none() && writes_file(&request.operation) {
            require_pinned_head(repo_ref, pre_action_snapshot.head.as_deref())?;
        }
        let prepared_execution = match &request.operation {
            RepoMutationOperation::ReceivedFiles { .. }
            | RepoMutationOperation::CommitFiles { .. } => {
                self.prepare_bundle_execution(repo_root, request, proposal)
            }
            _ => prepare_repo_mutation_execution(&self.store.clock, repo_root, request),
        };
        let execution = match prepared_execution {
            Ok(execution) => execution,
            Err(error) => {
                self.record_failed_repo_mutation_preparation(
                    repo_ref,
                    request,
                    fork_hash,
                    &snapshot_bytes,
                    &error,
                )?;
                return Err(error);
            }
        };
        let prepared = (|| -> Result<PreparedRepoMutation> {
            require_staged_objects_available(repo_root, &execution)?;
            // A composed member's prepared tree is its staged next prefix,
            // checked before any intent is recorded (FIX 4360).
            if let Some(step) = stack {
                step.require_prepared_tree(repo_root, &execution)?;
            }
            let expected_post_action_fork_hash = expected_post_action_fork_hash(
                &SnapshotCustody::of(self, repo_root)?,
                &request.operation,
                &pre_action_snapshot,
                fork_hash,
                &execution,
            )?;
            let repo_key_hash = repo_mutation_repo_key_hash(repo_ref);
            let started_at_ms = now_millis();
            let mut wtxn = self.store.env.write_txn()?;
            store_snapshot_if_absent(self, &mut wtxn, fork_hash, &snapshot_bytes)?;
            let seq = allocate_next_repo_mutation_seq(self, &mut wtxn, &repo_key_hash)?;
            let stored = StoredRepoMutationOplogEntry {
                schema_version: REPO_MUTATION_OPLOG_SCHEMA_VERSION,
                repo_ref: repo_ref.canonical(),
                seq,
                operation_kind: request.operation.kind().to_owned(),
                operation_subject: Some(operation_subject(&request.operation)),
                actor_id: request.actor_id.map(|id| *id.as_bytes()),
                actor_class: request.actor_class.map(|class| class as u8),
                session_id: request.session_id.map(|id| *id.as_bytes()),
                started_at_ms,
                finished_at_ms: None,
                pre_action_fork_hash: fork_hash,
                expected_post_action_fork_hash: Some(expected_post_action_fork_hash),
                prepared_commit: match &execution {
                    PreparedRepoMutationExecution::Direct => None,
                    _ => {
                        let commit = execution.commit_file()?;
                        Some(StoredPreparedCommit {
                            base_head: commit.base_head.clone(),
                            new_head: commit.new_head.clone(),
                        })
                    }
                },
                prepared_conflict_resolution: match &execution {
                    PreparedRepoMutationExecution::ResolveConflictFile { recovery, .. } => {
                        Some(StoredPreparedConflictResolution::from(recovery))
                    }
                    PreparedRepoMutationExecution::Direct
                    | PreparedRepoMutationExecution::CommitFile(_)
                    | PreparedRepoMutationExecution::FileBundle { .. } => None,
                },
                status: RepoMutationStatus::Prepared.as_str().to_owned(),
                failure: None,
            };
            OPLOG.put(
                &self.store,
                &mut wtxn,
                &repo_mutation_oplog_key(&repo_key_hash, seq),
                &stored,
            )?;
            // An erase can end the stack between steps (FIX 5219).
            if let Some(step) = stack {
                step.require_open_in_txn(self, &wtxn)?;
            }
            super::super::proposal::bind_prepared(self, &mut wtxn, proposal, repo_ref, seq)?;
            wtxn.commit()?;
            Ok(PreparedRepoMutation { repo_key_hash, seq })
        })();
        match prepared {
            Ok(oplog) => Ok(PreparedRepoMutationAction { oplog, execution }),
            Err(error) => {
                let _ = execution.cleanup(repo_root);
                Err(error)
            }
        }
    }

    fn record_failed_repo_mutation_preparation(
        &self,
        repo_ref: &RepoRef,
        request: &RepoMutationRequest,
        fork_hash: RepoForkHash,
        snapshot_bytes: &[u8],
        error: &Error,
    ) -> Result<()> {
        let repo_key_hash = repo_mutation_repo_key_hash(repo_ref);
        let timestamp = now_millis();
        let mut wtxn = self.store.env.write_txn()?;
        store_snapshot_if_absent(self, &mut wtxn, fork_hash, snapshot_bytes)?;
        let seq = allocate_next_repo_mutation_seq(self, &mut wtxn, &repo_key_hash)?;
        let stored = StoredRepoMutationOplogEntry {
            schema_version: REPO_MUTATION_OPLOG_SCHEMA_VERSION,
            repo_ref: repo_ref.canonical(),
            seq,
            operation_kind: request.operation.kind().to_owned(),
            operation_subject: Some(operation_subject(&request.operation)),
            actor_id: request.actor_id.map(|id| *id.as_bytes()),
            actor_class: request.actor_class.map(|class| class as u8),
            session_id: request.session_id.map(|id| *id.as_bytes()),
            started_at_ms: timestamp,
            finished_at_ms: Some(timestamp),
            pre_action_fork_hash: fork_hash,
            expected_post_action_fork_hash: None,
            prepared_conflict_resolution: None,
            prepared_commit: None,
            status: RepoMutationStatus::Failed.as_str().to_owned(),
            failure: Some(truncate_failure(&error.to_string())),
        };
        OPLOG.put(
            &self.store,
            &mut wtxn,
            &repo_mutation_oplog_key(&repo_key_hash, seq),
            &stored,
        )?;
        wtxn.commit()?;
        Ok(())
    }
}
