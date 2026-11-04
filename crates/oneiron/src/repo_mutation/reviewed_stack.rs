//! Atomic critic admission and exact-prefix replay for a tested proposal stack.
use super::git::{canonical_repo_ref_for_root, resolve_mutable_repo_root};
use super::oplog::{
    OPLOG, SNAPSHOT, repo_mutation_oplog_key, repo_mutation_repo_key_hash,
    repo_mutation_snapshot_key,
};
use super::proposal::{
    self, PROPOSAL, RepoProposal, RepoProposalOperation, RepoProposalStatus, invalid,
};
use super::snapshot::capture_repo_snapshot;
use super::types::{RepoForkHash, RepoMutationOutcome, RepoMutationStatus};
use crate::{
    EntityId, Vault,
    codebase::RepoRef,
    error::{Error, Result},
    git_wire::{GitWire, GitWireRepo, lock_repository},
    merge_queue::{LandingPermit, MergeBatch, SpeculativePath, TestedBatch},
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
    /// The admitted members in order. An erase turns a pending one into an
    /// erased slot in place (FIX 5219).
    members: Vec<StackMember>,
    end: StackEnd,
}

/// One position in a stack's history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum StackMember {
    /// The proposal's hex id, as the batch names it.
    Proposal(String),
    /// A member deleted with its erased actor before it ran. It names nothing.
    Erased,
}

impl StackMember {
    fn proposal(&self) -> Result<Option<EntityId>> {
        match self {
            Self::Proposal(id) => EntityId::from_hex(id).map(Some),
            Self::Erased => Ok(None),
        }
    }
}

/// Where a stack ends. Only an erase of a pending member, in a stack that
/// already ran one, moves it (FIX 5219).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum StackEnd {
    /// Every member lands.
    Open,
    /// The erase found a member Prepared. The repo writer reconciles it, then
    /// freezes the end.
    Requested,
    /// The stack ends after this many landed members.
    Landed(usize),
}

impl ReviewedStack {
    /// Whether this stored row is `admitted`'s admission: the same identity and
    /// the same members in order, each still itself or erased. The end and the
    /// erased slots are all an erase changes (FIX 5219).
    fn admits(&self, admitted: &Self) -> bool {
        self.repo_identity == admitted.repo_identity
            && self.batch == admitted.batch
            && self.expected_head == admitted.expected_head
            && self.pre_snapshot == admitted.pre_snapshot
            && self.tested_tree == admitted.tested_tree
            && self.members.len() == admitted.members.len()
            && self
                .members
                .iter()
                .zip(&admitted.members)
                .all(|(stored, member)| stored == member || *stored == StackMember::Erased)
    }
}

/// The staged path a batch lands, the one selector the tree check, the landing
/// and the slow check read (FIX 5219): its full path, or once an erase ended its
/// reviewed stack, the prefix path of the landed members. The batch keeps every
/// path, so the prefix is a path all-path agreement already tested.
fn landed_path<'a>(
    stack: Option<&ReviewedStack>,
    batch: &'a MergeBatch,
) -> Result<&'a SpeculativePath> {
    let landed = match stack.map(|stack| stack.end) {
        Some(StackEnd::Landed(landed)) => landed,
        _ => batch.proposals.len(),
    };
    let mask = (1_u64 << landed) - 1;
    batch
        .paths
        .iter()
        .find(|path| path.mask == mask)
        .ok_or(Error::CorruptedIndex("landing path missing"))
}

/// Only this module can construct a step, after atomic stack admission and
/// verification of the entire persisted prefix. It never replaces a proposal's
/// reviewed base; it authorizes one derived snapshot in one tested stack.
pub(super) struct StackStep {
    key: String,
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

    /// Re-reads the stack's end and this member's binding in the writer that
    /// prepares or resets the member, so an erase that ended the stack between
    /// steps stops the next one (FIX 5219).
    pub(super) fn require_open_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<()> {
        let open = REVIEWED_STACK
            .get(&vault.store, txn, &self.key)?
            .is_some_and(|stack| stack.end == StackEnd::Open);
        let bound = PROPOSAL
            .get(&vault.store, txn, &self.proposal)?
            .is_some_and(|row| row.merge_stack.as_deref() == Some(self.stack.as_str()));
        if !open || !bound {
            return Err(Error::ConcurrentWrite(
                "reviewed stack ended before this member",
            ));
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

/// The call for a member past an ended stack's end that never ran (FIX 5219):
/// unbound and back to Proposed, it lands alone under today's per-proposal
/// gate, its own critiques still counting.
const ENDED_STACK_SURVIVOR_STATUS: RepoProposalStatus = RepoProposalStatus::Proposed;

/// The call for what landed (FIX 5219): the contiguous prefix of members whose
/// proposal is Applied and whose oplog receipt applied on the prefix before
/// it. A sequence alone is no landing: Prepared allocates one and a failed
/// attempt keeps it. Recovery proves the full receipt binding again.
fn landed_prefix_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    stack: &ReviewedStack,
) -> Result<usize> {
    let mut hash = stack.pre_snapshot;
    let mut sequence = 0;
    let mut landed = 0;
    for member in &stack.members {
        let Some(id) = member.proposal()? else {
            break;
        };
        let Some(row) = PROPOSAL.get(&vault.store, txn, &id)? else {
            break;
        };
        let (Some(seq), RepoProposalStatus::Applied) = (row.operation_seq, row.status) else {
            break;
        };
        let repo = repo_mutation_repo_key_hash(&RepoRef::parse(&row.repo)?);
        let Some(entry) = OPLOG.get(&vault.store, txn, &repo_mutation_oplog_key(&repo, seq))?
        else {
            break;
        };
        let Some(post) = entry.expected_post_action_fork_hash else {
            break;
        };
        if entry.status != RepoMutationStatus::Applied.as_str()
            || entry.seq <= sequence
            || entry.pre_action_fork_hash != hash
            || entry.operation_subject.as_deref() != Some(row.operation_subject().as_str())
        {
            break;
        }
        hash = post;
        sequence = entry.seq;
        landed += 1;
    }
    Ok(landed)
}

/// The call for ending a stack (FIX 5219): while a member is Prepared the end
/// stays requested and every binding stays. Once none is, the stack ends at its
/// landed prefix. With none landed it goes, as a stack no member ran does.
/// Each later member that never ran is unbound and Proposed again; one that
/// ran keeps its terminal receipt. No reviewed base is rewritten.
fn end_stack_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &String,
    mut stack: ReviewedStack,
) -> Result<()> {
    let mut members = Vec::new();
    for (index, member) in stack.members.iter().enumerate() {
        if let Some(id) = member.proposal()?
            && let Some(row) = PROPOSAL.get(&vault.store, wtxn, &id)?
        {
            members.push((index, row));
        }
    }
    // Prepared binds a sequence and leaves the proposal Approved until it finishes.
    if stack.end != StackEnd::Requested
        || members.iter().any(|(_, row)| {
            row.operation_seq.is_some() && row.status == RepoProposalStatus::Approved
        })
    {
        return REVIEWED_STACK.put(&vault.store, wtxn, key, &stack);
    }
    let landed = landed_prefix_in_txn(vault, wtxn, &stack)?;
    if landed == 0 {
        REVIEWED_STACK.delete(&vault.store, wtxn, key)?;
    } else {
        stack.end = StackEnd::Landed(landed);
        REVIEWED_STACK.put(&vault.store, wtxn, key, &stack)?;
    }
    for (index, mut row) in members {
        if index < landed || row.merge_stack.as_deref() != Some(stack.batch.as_str()) {
            continue;
        }
        if row.operation_seq.is_none() {
            row.status = ENDED_STACK_SURVIVOR_STATUS;
        } else if landed > 0 {
            continue;
        }
        row.merge_stack = None;
        proposal::store(vault, wtxn, &row)?;
    }
    Ok(())
}

/// Drops each admitted stack that listed a proposal in `gone`, deleted with
/// its erased actor before it ran (FIX 4478), and unbinds the stack's other
/// members, so each lands alone or in a new stack under its own approval. A
/// stack that already ran a member keeps the erased one as an erased slot and
/// ends at its last landed member (FIX 5219); no receipt or outcome is
/// rewritten.
pub(super) fn drop_stacks_listing_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    gone: &BTreeSet<EntityId>,
) -> Result<()> {
    let mut listing = Vec::new();
    for row in REVIEWED_STACK.iter_from(&vault.store, wtxn, &[])? {
        let (key, stack) = row?;
        if stack.members.iter().any(|member| {
            member
                .proposal()
                .is_ok_and(|id| id.is_some_and(|id| gone.contains(&id)))
        }) {
            listing.push((key, stack));
        }
    }
    for (key, mut stack) in listing {
        let mut members = Vec::new();
        for member in &stack.members {
            if let Some(id) = member.proposal()?
                && let Some(row) = PROPOSAL.get(&vault.store, wtxn, &id)?
            {
                members.push(row);
            }
        }
        if members.iter().any(|row| row.operation_seq.is_some()) {
            for member in &mut stack.members {
                if member.proposal()?.is_some_and(|id| gone.contains(&id)) {
                    *member = StackMember::Erased;
                }
            }
            if stack.end == StackEnd::Open {
                stack.end = StackEnd::Requested;
            }
            end_stack_in_txn(vault, wtxn, &key, stack)?;
            continue;
        }
        REVIEWED_STACK.delete(&vault.store, wtxn, &key)?;
        for mut row in members {
            if row.merge_stack.as_deref() == Some(stack.batch.as_str()) {
                row.merge_stack = None;
                proposal::store(vault, wtxn, &row)?;
            }
        }
    }
    Ok(())
}

impl Vault {
    pub(crate) fn has_reviewed_merge_stack(
        &self,
        repo: &GitWireRepo,
        batch: &MergeBatch,
    ) -> Result<bool> {
        Ok(read(self, &repo.identity().as_hex(), &batch.id)?.is_some())
    }

    /// Freezes an erase's end request at the landed prefix (FIX 5219). The merge
    /// queue calls this under the repo writer after prepared recovery, so each
    /// member that was Prepared has finished or failed.
    pub(crate) fn end_reviewed_merge_stack(
        &self,
        repo: &GitWireRepo,
        batch: &MergeBatch,
    ) -> Result<()> {
        let key = key(&repo.identity().as_hex(), &batch.id);
        let mut wtxn = self.store.env.write_txn()?;
        if let Some(stack) = REVIEWED_STACK.get(&self.store, &wtxn, &key)?
            && stack.end == StackEnd::Requested
        {
            end_stack_in_txn(self, &mut wtxn, &key, stack)?;
            wtxn.commit()?;
        }
        Ok(())
    }

    /// Whether every member of `batch` is an open stored proposal that met
    /// the review the one policy point holds it to, read without writing:
    /// the queue driver lands only then (FIX 6868, G2 PR2). With no review
    /// policy and no catalog of its own that is none (FIX 8268). The
    /// admission still judges every member again.
    pub(crate) fn reviewed_stack_members_ready(
        &self,
        batch: &MergeBatch,
    ) -> Result<std::result::Result<(), String>> {
        for candidate in &batch.proposals {
            let Some(row) = EntityId::from_hex(&candidate.id)
                .ok()
                .map(|id| self.repo_proposal(id))
                .transpose()?
                .flatten()
            else {
                return Ok(Err(format!("{} is no stored proposal", candidate.id)));
            };
            // The admission's own member rule, one already bound to this
            // batch included (FIX 7309).
            let txn = self.store.env.read_txn()?;
            if let Err(held) =
                super::reviewed_file::stack_member_rule_in_txn(self, &txn, &row, &batch.id, true)?
            {
                return Ok(Err(held.hold));
            }
        }
        Ok(Ok(()))
    }

    /// The staged path `batch` lands; see [`landed_path`].
    pub(crate) fn reviewed_landed_path<'a>(
        &self,
        repo: &GitWireRepo,
        batch: &'a MergeBatch,
    ) -> Result<&'a SpeculativePath> {
        landed_path(
            read(self, &repo.identity().as_hex(), &batch.id)?.as_ref(),
            batch,
        )
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
            members: batch
                .proposals
                .iter()
                .map(|p| StackMember::Proposal(p.id.clone()))
                .collect(),
            end: StackEnd::Open,
        };
        let stack = match read(self, &expected.repo_identity, &expected.batch)? {
            Some(stored) if stored.admits(&expected) => stored,
            Some(_) => return Err(invalid("reviewed stack identity changed")),
            None => {
                self.admit_reviewed_stack(&repo, tested, &expected)?;
                expected
            }
        };
        // An ended stack is complete through its last landed member (FIX 5219).
        let landed = match stack.end {
            StackEnd::Open => stack.members.len(),
            StackEnd::Landed(landed) if landed <= stack.members.len() => landed,
            StackEnd::Landed(_) => return Err(Error::CorruptedIndex("reviewed stack end")),
            StackEnd::Requested => {
                return Err(Error::ConcurrentWrite("reviewed stack end awaits recovery"));
            }
        };
        let ids = stack
            .members
            .iter()
            .take(landed)
            .map(|member| {
                member
                    .proposal()?
                    .ok_or(Error::CorruptedIndex("landed member erased"))
            })
            .collect::<Result<Vec<_>>>()?;
        let rows = ids
            .iter()
            .map(|id| self.repo_proposal(*id)?.ok_or(Error::EntityNotFound))
            .collect::<Result<Vec<_>>>()?;
        let oplog = self.repo_mutation_oplog_for_canonical(&repo_ref)?;
        let mut outcomes = Vec::new();
        let mut hash = stack.pre_snapshot;
        let mut stopped = false;
        let mut sequence = 0;
        for row in &rows {
            // Replay reads the review the admission sealed, never a later
            // policy on effects it already accepted (FIX 8268).
            if row.merge_stack.as_deref() != Some(stack.batch.as_str())
                || !row.stack_review_admitted(&stack.batch)?
            {
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
                super::reviewed_file::require_receipt(row, entry, hash)?;
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
        if capture_repo_snapshot(self, &root)?.0 != hash {
            return Err(Error::ConcurrentWrite("reviewed stack recovery diverged"));
        }
        // An ended stack only proves its prefix; it writes no later member.
        if stack.end != StackEnd::Open && outcomes.len() != rows.len() {
            return Err(invalid("ended reviewed stack prefix is not applied"));
        }
        for row in rows.into_iter().skip(outcomes.len()) {
            // An erased actor's member never runs again, so its failed attempt stays failed.
            row.actor.live()?;
            // A not-yet-effected masked copy's member runs only cleared (FIX 7608).
            if let Some(cause) = {
                let txn = self.store.env.read_txn()?;
                super::received_file::projected_hold_in_txn(self, &txn, &row)?
            } {
                return Err(invalid(cause));
            }
            let step = StackStep {
                key: key(&stack.repo_identity, &stack.batch),
                stack: stack.batch.clone(),
                proposal: row.id,
                expected: hash,
            };
            if row.operation_seq.is_some() {
                // Recovery proved this failed attempt had no repository effect.
                // Keep its old terminal receipt, but allocate a fresh sequence on
                // retry. The immutable edit ID makes the document step idempotent.
                let mut txn = self.store.env.write_txn()?;
                step.require_open_in_txn(self, &txn)?;
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
            let outcome = self.apply_repo_mutation_stack(row.request()?, row.id, &step)?;
            super::reviewed_file::require_receipt(&row, &outcome.entry, hash)?;
            if outcome.entry.status != RepoMutationStatus::Applied {
                return Err(invalid("reviewed stack operation did not apply"));
            }
            hash = outcome
                .entry
                .expected_post_action_fork_hash
                .ok_or(invalid("stack postcondition missing"))?;
            if capture_repo_snapshot(self, &root)?.0 != hash {
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
        let tested_tree = &landed_path(Some(&stack), batch)?.tree;
        if &super::conflict::tree_hash_for_ref(&root, "HEAD")? != tested_tree {
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
        if capture_repo_snapshot(self, repo.repo_root())?.0 != stack.pre_snapshot {
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
            // Every path of every member, a received bundle's all of them.
            if !ids.insert(id)
                || !row
                    .paths()
                    .into_iter()
                    .all(|path| paths.insert(path.to_owned()))
            {
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
            super::reviewed_file::require_candidate(
                &row,
                candidate,
                stack.pre_snapshot,
                repo.repo_ref(),
                &snapshot,
            )?;
            super::reviewed_file::require_document_base(self, &row, &snapshot)?;
            proposal::validate_conflict(self, &row, repo.repo_root())?;
            super::queue::validate_operation(&row.request()?.operation)?;
            super::trailer::validate_repo_provenance_request(self, &row.request()?)?;
            rows.push(row);
        }
        // A batch past one speculation window lands whole (FIX 9948).
        if rows.is_empty() {
            return Err(invalid("reviewed stack bound exceeded"));
        }
        let mut txn = self.store.env.write_txn()?;
        // Review can run concurrently. Re-read every vote and the vault's review
        // policy in this ONE transaction, and seal the review each member met
        // (FIX 8268); an invalid late member aborts all approvals and the
        // stack binding.
        for row in rows {
            let mut current = PROPOSAL
                .get(&self.store, &txn, &row.id)?
                .ok_or(Error::EntityNotFound)?;
            // The member rule the driver's readiness shares (FIX 7309).
            let review = super::reviewed_file::stack_member_rule_in_txn(
                self,
                &txn,
                &current,
                &stack.batch,
                false,
            )?
            .map_err(|held| held.refusal)?;
            current.queue_review = Some(review);
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
