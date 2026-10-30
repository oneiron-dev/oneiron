//! The checked repository conflict claim writer (moved from `conflict.rs`
//! unchanged in behavior) and the merge queue's one-writer overlap handoff
//! (FIX 6868, G2 PR2).
//!
//! Both share the source re-read and the claim write. The queue's handoff
//! takes no Git text-conflict detector: its sealed admission names shared
//! whole-file paths the queue proved, and the claim records their exact
//! base, ours and theirs trees. In one transaction it checks the admission
//! and every source, reuses a claim of the same value (a resolved one
//! included), mints the TASK or keeps it held through the reconciliation
//! index, and links every participating batch. It never selects the
//! embedded owner, never merges bytes and never closes the claim.
use std::sync::atomic::Ordering;

use crate::Vault;
use crate::affect::Vad;
use crate::batch::{BatchOp, apply_ops};
use crate::claim::{ClaimBody, ClaimLifecycleStatus, PREDICATE_CONFLICT_OPEN, encode_claim_body};
use crate::codebase::RepoRef;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{CodeError, Error, Result};
use crate::federation::QueueReconciliationAdmission;
use crate::merge_queue::{QueueConflictLink, QueueStageOverlap};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::repo_mutation::RepoConflictClaim;
use crate::scan_check::{EngineScan, ScanCount};
use crate::temporal::TimeRange;

use super::super::conflict_value::{
    RepoConflictOpenValue, decode_repo_conflict_open_value, normalize_repo_conflict_paths,
};
use super::super::git::validate_git_ref_label;
use super::super::proposal::{self, RepoProposal};
use super::super::support::now_secs;

pub(super) fn put_engine_repo_conflict_claim_checked(
    vault: &Vault,
    claim_id: EntityId,
    branch_subject: EntityId,
    body: &ClaimBody,
    learned_at: u64,
    owner: Option<(&crate::consent::AuthenticatedOwner, EntityId)>,
    proposals: &[RepoProposal],
) -> Result<EntityId> {
    let data = encode_claim_body(body)?;
    let reconciliation_owner = if body.predicate == PREDICATE_CONFLICT_OPEN && owner.is_none() {
        Some(
            vault
                .ensure_embedded_owner_actor()
                .map_err(|error| Error::Code(CodeError::RepoMutationFailed(error.to_string())))?,
        )
    } else {
        None
    };
    let mut wtxn = vault.store.env.write_txn()?;
    let reconciliation_owner = match owner {
        Some((owner, repository)) => {
            let value = decode_repo_conflict_open_value(&body.value)?;
            proposal::require_repo_artifact_in_txn(vault, &wtxn, repository, &value.repo_ref)?;
            Some(owner.revalidate_in_txn(vault, &wtxn)?)
        }
        None => reconciliation_owner,
    };
    require_sources_unchanged_in_txn(vault, &wtxn, proposals)?;
    if body.predicate == PREDICATE_CONFLICT_OPEN {
        for id in vault.claims_for_subject_in_txn(&wtxn, &branch_subject)? {
            if let Some(existing) = vault.get_claim_in_txn(&wtxn, &id)?
                && existing.predicate == body.predicate
                && existing.lifecycle == ClaimLifecycleStatus::Active
                && existing.value == body.value
            {
                // Recording a held conflict again asks again for its TASK,
                // under the owner's authority as it reads now (FIX 8830).
                if let Some(owner) = reconciliation_owner
                    && vault.repo_reconciliation_task_in_txn(&wtxn, id)?.is_none()
                    && reconciliation_task_in_txn(
                        vault,
                        &mut wtxn,
                        id,
                        branch_subject,
                        &body.value,
                        owner,
                        learned_at,
                    )?
                    .is_some()
                {
                    wtxn.commit()?;
                }
                return Ok(id);
            }
        }
    }
    put_claim_in_txn(vault, &mut wtxn, claim_id, branch_subject, data, learned_at)?;
    if let Some(owner) = reconciliation_owner {
        // Below the owner's Auto ceiling the claim is kept and its
        // reconciliation held, told to the owner; the ceiling is never
        // widened (FIX 8830).
        reconciliation_task_in_txn(
            vault,
            &mut wtxn,
            claim_id,
            branch_subject,
            &body.value,
            owner,
            learned_at,
        )?;
    }
    wtxn.commit()?;
    Ok(claim_id)
}

/// The reconciliation TASK of the open conflict `claim_id`, minted for
/// `owner` in this writer, or `None` while the owner's ceiling holds it.
fn reconciliation_task_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: EntityId,
    subject: EntityId,
    value: &rmpv::Value,
    owner: EntityId,
    now: u64,
) -> Result<Option<EntityId>> {
    let value = decode_repo_conflict_open_value(value)?;
    let conflict = RepoConflictClaim {
        claim_id,
        subject,
        repo_ref: value.repo_ref,
        branch: value.branch,
        base_tree: value.base_tree,
        ours_tree: value.ours_tree,
        theirs_tree: value.theirs_tree,
        conflicted_paths: value.conflicted_paths,
        proposals: value.proposals,
    };
    vault.create_repo_reconciliation_task_in_txn(wtxn, &conflict, owner, now)
}

/// Every source proposal, as the caller read it, is still stored unchanged.
fn require_sources_unchanged_in_txn(
    vault: &Vault,
    wtxn: &heed::RoTxn<'_>,
    proposals: &[RepoProposal],
) -> Result<()> {
    for expected in proposals {
        if !EntityStoreRead::port_entity_present(&vault.store, wtxn, &expected.id)? {
            return Err(Error::EntityNotFound);
        }
        let stored = proposal::PROPOSAL
            .get(&vault.store, wtxn, &expected.id)?
            .ok_or(Error::EntityNotFound)?;
        if stored.repo != expected.repo
            || stored.files != expected.files
            || stored.pre_action_fork_hash != expected.pre_action_fork_hash
            || stored.actor != expected.actor
            || stored.status != expected.status
        {
            return Err(proposal::invalid("conflict source proposal changed"));
        }
    }
    Ok(())
}

/// Writes one conflict CLAIM and its `ClaimOf` edge to its present subject.
fn put_claim_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: EntityId,
    branch_subject: EntityId,
    data: Vec<u8>,
    learned_at: u64,
) -> Result<()> {
    if vault
        .store
        .port_entity_record(&**wtxn, &branch_subject)?
        .is_none()
    {
        return Err(Error::EntityNotFound);
    }
    let claim_of_weight = EdgeKind::ClaimOf
        .default_weight()
        .ok_or(Error::InvariantViolation(
            "ClaimOf edge missing default weight",
        ))?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![
            BatchOp::Put {
                id: claim_id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: true,
                hub_sync_imported: false,
            },
            BatchOp::Edge {
                src: claim_id,
                kind: EdgeKind::ClaimOf,
                tgt: branch_subject,
                weight: claim_of_weight,
                vad: Vad::NEUTRAL,
            },
        ],
        vault.text_index_trusted.load(Ordering::Acquire),
        false,
        true,
    )?;
    Ok(())
}

/// The base, ours and theirs trees a queue handoff records.
pub(in crate::repo_mutation) struct QueueConflictTrees {
    pub(in crate::repo_mutation) base: String,
    pub(in crate::repo_mutation) ours: String,
    pub(in crate::repo_mutation) theirs: String,
}

/// The merge queue's overlap handoff in one writer: the sealed admission
/// and every source checked again, the claim of this exact value reused or
/// written, its TASK minted or held, and `attach` linking every batch.
pub(in crate::repo_mutation) fn record_queue_conflict_claim(
    vault: &Vault,
    repo_ref: &RepoRef,
    overlap: &QueueStageOverlap,
    admission: &QueueReconciliationAdmission,
    trees: QueueConflictTrees,
    proposals: &[RepoProposal],
    attach: impl FnOnce(&mut heed::RwTxn<'_>, &QueueConflictLink) -> Result<()>,
) -> Result<QueueConflictLink> {
    validate_git_ref_label(&overlap.target.branch)?;
    let subject = overlap.target.branch_subject;
    let value = RepoConflictOpenValue {
        repo_ref: repo_ref.clone(),
        branch: overlap.target.branch.clone(),
        base_tree: trees.base,
        ours_tree: trees.ours,
        theirs_tree: trees.theirs,
        conflicted_paths: normalize_repo_conflict_paths(overlap.paths.clone())?,
        proposals: overlap.sources.clone(),
    };
    let body = super::open_conflict_body(subject, &value)?;
    let data = encode_claim_body(&body)?;
    let learned_at = now_secs();
    let mut wtxn = vault.store.env.write_txn()?;
    // Every shared path is kept; past the threshold row the host is asked
    // whether everything is okay (rule 5, FIX 8831).
    let mut count = ScanCount::start(
        &vault.store,
        &wtxn,
        EngineScan::RepoConflictPaths,
        subject.as_bytes(),
    )?;
    count.rows(value.conflicted_paths.len());
    count.defer(&vault.store);
    if !admission.holds_in_txn(vault, &wtxn, overlap)? {
        return Err(Error::ConcurrentWrite(
            "the queue reconciliation admission no longer holds",
        ));
    }
    require_sources_unchanged_in_txn(vault, &wtxn, proposals)?;
    let mut existing = None;
    for id in vault.claims_for_subject_in_txn(&wtxn, &subject)? {
        if let Some(claim) = vault.get_claim_in_txn(&wtxn, &id)?
            && claim.predicate == PREDICATE_CONFLICT_OPEN
            && matches!(
                claim.lifecycle,
                ClaimLifecycleStatus::Active | ClaimLifecycleStatus::Superseded
            )
            && claim.value == body.value
        {
            existing = Some((id, claim.lifecycle == ClaimLifecycleStatus::Active));
            break;
        }
    }
    let (claim_id, open) = match existing {
        Some(found) => found,
        None => {
            let id = vault.store.clock.entity_id()?;
            put_claim_in_txn(vault, &mut wtxn, id, subject, data, learned_at)?;
            (id, true)
        }
    };
    let task = match vault.repo_reconciliation_task_in_txn(&wtxn, claim_id)? {
        Some(task) => Some(task),
        None if open => {
            let conflict = RepoConflictClaim {
                claim_id,
                subject,
                repo_ref: value.repo_ref,
                branch: value.branch,
                base_tree: value.base_tree,
                ours_tree: value.ours_tree,
                theirs_tree: value.theirs_tree,
                conflicted_paths: value.conflicted_paths,
                proposals: value.proposals,
            };
            vault.create_queue_reconciliation_task_in_txn(
                &mut wtxn, &conflict, admission, learned_at,
            )?
        }
        None => None,
    };
    let link = QueueConflictLink {
        conflict: claim_id,
        branch_subject: subject,
        held: (task.is_none() && open).then(|| QueueReconciliationAdmission::TASK_HELD.to_owned()),
        task,
        sources: overlap.sources.clone(),
        batches: overlap.batches.clone(),
        resolution_batch: None,
        superseded: false,
    };
    attach(&mut wtxn, &link)?;
    wtxn.commit()?;
    vault.store.notify_attempt_observers();
    Ok(link)
}

impl Vault {
    /// Asks again for the TASK of a held queue handoff, under its admission
    /// as current policy reads it now: the same open claim and the same
    /// index, never a second claim. Nothing is written while it stays held.
    ///
    /// # Errors
    /// A store failure or an admission that no longer answers the overlap.
    pub(crate) fn retry_queue_reconciliation_task(
        &self,
        overlap: &QueueStageOverlap,
        admission: &QueueReconciliationAdmission,
        link: &QueueConflictLink,
        attach: impl FnOnce(&mut heed::RwTxn<'_>, &QueueConflictLink) -> Result<()>,
    ) -> Result<QueueConflictLink> {
        let mut wtxn = self.store.env.write_txn()?;
        if link.task.is_some() || !admission.holds_in_txn(self, &wtxn, overlap)? {
            return Ok(link.clone());
        }
        let Some(claim) = self.get_claim_in_txn(&wtxn, &link.conflict)? else {
            return Ok(link.clone());
        };
        if claim.predicate != PREDICATE_CONFLICT_OPEN
            || claim.lifecycle != ClaimLifecycleStatus::Active
        {
            return Ok(link.clone());
        }
        let value = decode_repo_conflict_open_value(&claim.value)?;
        let conflict = RepoConflictClaim {
            claim_id: link.conflict,
            subject: link.branch_subject,
            repo_ref: value.repo_ref,
            branch: value.branch,
            base_tree: value.base_tree,
            ours_tree: value.ours_tree,
            theirs_tree: value.theirs_tree,
            conflicted_paths: value.conflicted_paths,
            proposals: value.proposals,
        };
        let Some(task) = self.create_queue_reconciliation_task_in_txn(
            &mut wtxn,
            &conflict,
            admission,
            now_secs(),
        )?
        else {
            return Ok(link.clone());
        };
        let mut retried = link.clone();
        retried.task = Some(task);
        retried.held = None;
        attach(&mut wtxn, &retried)?;
        wtxn.commit()?;
        self.store.notify_attempt_observers();
        Ok(retried)
    }
}
