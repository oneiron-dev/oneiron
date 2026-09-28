//! Atomic critic admission and exact-prefix replay for a tested proposal stack.
use super::git::{canonical_repo_ref_for_root, resolve_mutable_repo_root};
use super::oplog::{SNAPSHOT, repo_mutation_snapshot_key};
use super::proposal::{
    self, PROPOSAL, RepoProposal, RepoProposalOperation, RepoProposalStatus, invalid,
};
use super::snapshot::{StoredRepoSnapshot, StoredRepoSnapshotEntryKind, capture_repo_snapshot};
use super::types::{RepoForkHash, RepoMutationOplogEntry, RepoMutationOutcome, RepoMutationStatus};
use crate::{
    EntityId, Vault,
    codebase::RepoRef,
    error::{Error, Result},
    git_wire::{GitWire, GitWireRepo, lock_repository},
    merge_queue::{LandingPermit, MergeBatch, TestedBatch},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReviewedStack {
    repo_identity: String,
    batch: String,
    expected_head: String,
    pre_snapshot: RepoForkHash,
    tested_tree: String,
    proposals: Vec<String>,
}

/// Only this module can construct a step, after atomic stack admission and
/// verification of the entire persisted prefix. It never replaces a proposal's
/// reviewed base; it authorizes one derived snapshot in one tested stack.
pub(super) struct StackStep {
    stack: String,
    proposal: EntityId,
    expected: RepoForkHash,
}
impl StackStep {
    pub(super) fn authorize(&self, row: &RepoProposal, actual: RepoForkHash) -> Result<()> {
        if row.id != self.proposal || row.merge_stack.as_deref() != Some(self.stack.as_str()) {
            return Err(invalid("stack step does not authorize this proposal"));
        }
        if actual != self.expected {
            return Err(Error::ConcurrentWrite("reviewed stack prefix changed"));
        }
        Ok(())
    }
}

/// One admitted reviewed merge stack. Key: string (repo identity hex) + ":" +
/// string (batch id).
const REVIEWED_STACK: crate::side_table::SideTable<
    String,
    ReviewedStack,
    crate::side_table::Named,
> = crate::side_table::SideTable::new(&crate::side_table::REPO_MUTATION_REVIEWED_STACK);

fn key(identity: &str, batch: &str) -> String {
    format!("{identity}:{batch}")
}
fn read(vault: &Vault, identity: &str, batch: &str) -> Result<Option<ReviewedStack>> {
    let txn = vault.store.env.read_txn()?;
    REVIEWED_STACK.get(&vault.store, &txn, &key(identity, batch))
}

impl Vault {
    pub(crate) fn has_reviewed_merge_stack(
        &self,
        repo: &GitWireRepo,
        batch: &MergeBatch,
    ) -> Result<bool> {
        Ok(read(self, &repo.identity().as_hex(), &batch.id)?.is_some())
    }

    /// Both input capabilities are issued by the merge queue under its writer
    /// lock. No unsealed public operation can opt out of exact-base review.
    pub(crate) fn apply_tested_repo_proposals(
        &self,
        repo_ref: &RepoRef,
        permit: &LandingPermit,
        tested: &TestedBatch,
    ) -> Result<Vec<RepoMutationOutcome>> {
        let root = resolve_mutable_repo_root(repo_ref)?;
        let repo_ref = canonical_repo_ref_for_root(repo_ref, &root)?;
        let wire = GitWire::new(self)?;
        let repo = wire.open_repo(repo_ref.clone(), &root)?;
        let _guard = lock_repository(repo.common_dir())?;
        self.recover_prepared_repo_mutations_locked(&repo_ref, &root)?;
        let batch = tested.batch();
        let snapshot = batch
            .pre_snapshot
            .ok_or(invalid("tested snapshot missing"))?;
        if permit.repo_identity() != repo.identity().as_hex()
            || permit.expected_head() != batch.expected_head
            || permit.batch_id() != batch.id
        {
            return Err(invalid("tested stack capability scope differs"));
        }
        let expected = ReviewedStack {
            repo_identity: repo.identity().as_hex(),
            batch: batch.id.clone(),
            expected_head: batch.expected_head.clone(),
            pre_snapshot: snapshot,
            tested_tree: tested.tested_tree().to_owned(),
            proposals: batch.proposals.iter().map(|p| p.id.clone()).collect(),
        };
        match read(self, &expected.repo_identity, &expected.batch)? {
            Some(stored) if stored == expected => {}
            Some(_) => return Err(invalid("reviewed stack identity changed")),
            None => self.admit_reviewed_stack(&repo, tested, &expected)?,
        }
        let ids = expected
            .proposals
            .iter()
            .map(|id| EntityId::from_hex(id))
            .collect::<Result<Vec<_>>>()?;
        let rows = ids
            .iter()
            .map(|id| self.repo_proposal(*id)?.ok_or(Error::EntityNotFound))
            .collect::<Result<Vec<_>>>()?;
        let oplog = self.repo_mutation_oplog_for_canonical(&repo_ref)?;
        let mut outcomes = Vec::new();
        let mut hash = expected.pre_snapshot;
        let mut stopped = false;
        let mut sequence = 0;
        for row in &rows {
            if row.merge_stack.as_deref() != Some(expected.batch.as_str()) || !row.eligible()? {
                return Err(invalid("reviewed stack member binding changed"));
            }
            let entry = row
                .operation_seq
                .map(|seq| {
                    oplog
                        .iter()
                        .find(|entry| entry.seq == seq)
                        .ok_or(Error::CorruptedIndex("stack member oplog missing"))
                })
                .transpose()?;
            if let Some(entry) = entry {
                require_receipt(row, entry, hash)?;
                if entry.seq <= sequence {
                    return Err(invalid("reviewed stack receipt order changed"));
                }
                sequence = entry.seq;
                match entry.status {
                    RepoMutationStatus::Applied
                        if !stopped && row.status == RepoProposalStatus::Applied =>
                    {
                        hash = entry
                            .expected_post_action_fork_hash
                            .ok_or(invalid("stack postcondition missing"))?;
                        outcomes.push(RepoMutationOutcome {
                            entry: entry.clone(),
                            repo_conflict_claim_id: proposal::resolution_claim_id(self, row)?,
                        });
                        continue;
                    }
                    RepoMutationStatus::Failed if row.status == RepoProposalStatus::Failed => {}
                    _ => return Err(invalid("reviewed stack receipts are not an applied prefix")),
                }
            } else if row.status != RepoProposalStatus::Approved {
                return Err(invalid("reviewed stack member is not approved"));
            }
            stopped = true;
        }
        // Never reset failed approval state or retry a document edit until the
        // live repository proves exactly the prefix already authorized above.
        if capture_repo_snapshot(&root)?.0 != hash {
            return Err(Error::ConcurrentWrite("reviewed stack recovery diverged"));
        }
        for row in rows.into_iter().skip(outcomes.len()) {
            if row.operation_seq.is_some() {
                // Recovery proved this failed attempt had no repository effect.
                // Keep its old terminal receipt, but allocate a fresh sequence on
                // retry. The immutable edit ID makes the document step idempotent.
                let mut txn = self.store.env.write_txn()?;
                let mut current = PROPOSAL
                    .get(&self.store, &txn, &row.id)?
                    .ok_or(Error::EntityNotFound)?;
                if current.operation_seq != row.operation_seq
                    || current.status != RepoProposalStatus::Failed
                {
                    return Err(invalid("failed stack attempt changed"));
                }
                current.operation_seq = None;
                current.status = RepoProposalStatus::Approved;
                proposal::store(self, &mut txn, &current)?;
                txn.commit()?;
            }
            let step = StackStep {
                stack: expected.batch.clone(),
                proposal: row.id,
                expected: hash,
            };
            let outcome = self.apply_repo_mutation_stack(row.request()?, row.id, &step)?;
            require_receipt(&row, &outcome.entry, hash)?;
            if outcome.entry.status != RepoMutationStatus::Applied {
                return Err(invalid("reviewed stack operation did not apply"));
            }
            hash = outcome
                .entry
                .expected_post_action_fork_hash
                .ok_or(invalid("stack postcondition missing"))?;
            if capture_repo_snapshot(&root)?.0 != hash {
                return Err(Error::ConcurrentWrite(
                    "reviewed stack operation result differs",
                ));
            }
            outcomes.push(outcome);
            #[cfg(test)]
            if outcomes.len() == 1
                && super::queue::take_repo_mutation_crash(
                    super::queue::RepoMutationCrashPoint::AfterStackMember,
                )
            {
                return Err(Error::InvariantViolation(
                    "test: interrupted reviewed stack",
                ));
            }
        }
        if super::conflict::tree_hash_for_ref(&root, "HEAD")? != expected.tested_tree {
            return Err(Error::ConcurrentWrite(
                "reviewed stack differs from tested tree",
            ));
        }
        Ok(outcomes)
    }

    fn admit_reviewed_stack(
        &self,
        repo: &GitWireRepo,
        tested: &TestedBatch,
        stack: &ReviewedStack,
    ) -> Result<()> {
        if capture_repo_snapshot(repo.repo_root())?.0 != stack.pre_snapshot {
            return Err(Error::ConcurrentWrite("reviewed stack base changed"));
        }
        let snapshot = {
            let txn = self.store.env.read_txn()?;
            let snapshot = SNAPSHOT
                .get(
                    &self.store,
                    &txn,
                    &repo_mutation_snapshot_key(stack.pre_snapshot),
                )?
                .ok_or(Error::EntityNotFound)?;
            let raw = SNAPSHOT.encode_value(&snapshot)?;
            if blake3::hash(&raw).as_bytes() != &stack.pre_snapshot {
                return Err(Error::CorruptedIndex("reviewed stack snapshot hash"));
            }
            super::snapshot::require_snapshot_schema(snapshot)?
        };
        if snapshot.head.as_deref() != Some(stack.expected_head.as_str()) {
            return Err(invalid("reviewed stack snapshot HEAD differs"));
        }
        let mut paths = BTreeSet::new();
        let mut conflicts = BTreeSet::new();
        let mut ids = BTreeSet::new();
        let mut rows = Vec::new();
        for candidate in &tested.batch().proposals {
            let id = EntityId::from_hex(&candidate.id)?;
            let row = self.repo_proposal(id)?.ok_or(Error::EntityNotFound)?;
            if !ids.insert(id) || !paths.insert(row.path.clone()) {
                return Err(invalid("reviewed stack repeats a proposal or path"));
            }
            if let RepoProposalOperation::ResolveConflictFile {
                open_conflict_claim_id,
                ..
            } = &row.operation
                && !conflicts.insert(*open_conflict_claim_id)
            {
                return Err(invalid("reviewed stack resolves one conflict twice"));
            }
            require_candidate(&row, candidate, stack, repo.repo_ref(), &snapshot)?;
            require_document_base(self, &row, &snapshot)?;
            proposal::validate_conflict(self, &row, repo.repo_root())?;
            super::queue::validate_operation(&row.request()?.operation)?;
            super::trailer::validate_repo_provenance_request(self, &row.request()?)?;
            rows.push(row);
        }
        if rows.is_empty() || rows.len() > 6 {
            return Err(invalid("reviewed stack bound exceeded"));
        }
        let mut txn = self.store.env.write_txn()?;
        // Review can run concurrently. Re-read every vote in this ONE transaction;
        // an invalid late member aborts all approvals and the stack binding.
        for row in rows {
            let mut current = PROPOSAL
                .get(&self.store, &txn, &row.id)?
                .ok_or(Error::EntityNotFound)?;
            if current.merge_stack.is_some()
                || current.operation_seq.is_some()
                || !matches!(
                    current.status,
                    RepoProposalStatus::Proposed | RepoProposalStatus::Approved
                )
                || !current.eligible()?
            {
                return Err(invalid(
                    "every stack member needs unused unanimous critic approval",
                ));
            }
            current.merge_stack = Some(stack.batch.clone());
            current.status = RepoProposalStatus::Approved;
            proposal::store(self, &mut txn, &current)?;
        }
        REVIEWED_STACK.put(
            &self.store,
            &mut txn,
            &key(&stack.repo_identity, &stack.batch),
            stack,
        )?;
        txn.commit()?;
        Ok(())
    }
}

fn require_candidate(
    row: &RepoProposal,
    candidate: &crate::merge_queue::MergeProposal,
    stack: &ReviewedStack,
    repo: &RepoRef,
    snapshot: &StoredRepoSnapshot,
) -> Result<()> {
    let canonical = super::oplog::repo_mutation_repo_key_hash;
    if canonical(&RepoRef::parse(&row.repo)?) != canonical(repo)
        || row.pre_action_fork_hash != stack.pre_snapshot
        || row.id.to_hex() != candidate.id
        || candidate.files.len() != 1
    {
        return Err(invalid(
            "tested change is not exactly one reviewed proposal",
        ));
    }
    let file = &candidate.files[0];
    let old = snapshot.entries.iter().find(|entry| entry.path == row.path);
    if old.is_some_and(|entry| entry.kind != StoredRepoSnapshotEntryKind::File) {
        return Err(invalid("reviewed stack requires regular files"));
    }
    let expected = old.map(|entry| entry.content.as_slice());
    if file.path != row.path
        || file.content.as_deref() != Some(row.content.as_slice())
        || file.expected.as_deref() != expected
    {
        return Err(invalid(
            "tested bytes differ from immutable reviewed operation",
        ));
    }
    std::str::from_utf8(expected.unwrap_or(b""))
        .map_err(|_| invalid("reviewed code requires UTF-8"))?;
    std::str::from_utf8(&row.content).map_err(|_| invalid("reviewed code requires UTF-8"))?;
    Ok(())
}

fn require_receipt(
    row: &RepoProposal,
    entry: &RepoMutationOplogEntry,
    expected: RepoForkHash,
) -> Result<()> {
    let request = row.request()?;
    if entry.pre_action_fork_hash != expected
        || entry.repo_ref != request.repo_ref
        || entry.operation_kind != request.operation.kind()
        || entry.operation_subject.as_deref() != Some(row.path.as_str())
        || entry.actor_id != Some(row.actor)
        || entry.session_id != Some(row.session)
    {
        return Err(invalid("reviewed stack receipt binding differs"));
    }
    Ok(())
}

// Read-only preflight catches an already-stale later document before any member
// lands. The normal document door still rechecks at execution, then replays by ID.
fn require_document_base(
    vault: &Vault,
    row: &RepoProposal,
    snapshot: &StoredRepoSnapshot,
) -> Result<()> {
    let old = snapshot
        .entries
        .iter()
        .find(|entry| entry.path == row.path)
        .map_or(b"".as_slice(), |entry| entry.content.as_slice());
    let old = std::str::from_utf8(old).map_err(|_| invalid("reviewed code requires UTF-8"))?;
    let new =
        std::str::from_utf8(&row.content).map_err(|_| invalid("reviewed code requires UTF-8"))?;
    if old == new {
        return Ok(());
    }
    let repo = RepoRef::parse(&row.repo)?;
    let scope = super::oplog::repo_mutation_repo_key(&repo);
    let session = vault.open_code_document(&scope, &row.path, old, row.session)?;
    match vault.code_file_edit_receipt(row.id)? {
        None if session.text() != old => Err(Error::ConcurrentWrite(
            "document changed since stack review",
        )),
        Some(receipt)
            if receipt.document_id != session.document_id()
                || receipt.session_id != row.session
                || receipt.actor
                    != crate::write_envelope::WriteActor::new(
                        row.actor,
                        crate::edge::EdgeActorClass::Agent,
                    )
                || receipt.edit
                    != crate::code_document::CodeFileEdit::between(&row.path, old, new) =>
        {
            Err(invalid("stack document receipt identity differs"))
        }
        _ => Ok(()),
    }
}
