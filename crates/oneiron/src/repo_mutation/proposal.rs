//! Durable per-operation code proposals. Review never mutates the repository.
use std::collections::BTreeSet;

use super::git::{
    admitted_repo_ref, git_common_dir, require_pinned_head, resolve_mutable_repo_root,
};
use super::oplog::{SNAPSHOT, repo_mutation_repo_key_hash, repo_mutation_snapshot_key};
use super::queue::validate_operation;
use super::snapshot::{
    SnapshotCustody, StoredRepoSnapshot, StoredRepoSnapshotEntryKind, capture_repo_snapshot,
};
use super::support::now_millis;
use super::types::{
    RepoForkHash, RepoMutationOperation, RepoMutationOutcome, RepoMutationRequest,
    RepoMutationStatus,
};
use crate::Vault;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::codebase::RepoRef;
use crate::critic::{
    CritiqueArtifact, CritiqueTriage, CritiqueVerdict, LensCatalog, triage_critiques,
};
use crate::entity_id::EntityId;
use crate::error::{CodeError, Error, Result};
use crate::git_wire::lock_repository;
use crate::secret_snapshot::SnapshotWithhold;
use crate::side_table::{self, Raw, SideKey, SideTable};
use rmpv::Value;
use serde::{Deserialize, Serialize};

pub(super) mod actor_erase;
mod files;
mod guards;
pub(super) mod persist;
mod queue_review;
mod review;
mod run;
pub mod settlement;
mod submit;
pub use files::RepoProposedFile;
pub(super) use files::{native_bundle_queue_only, received_bundle_queue_only};
pub(super) use guards::require_repo_artifact_in_txn;
use guards::validate_conflict_in_txn;
pub use queue_review::{QueueReviewAdmission, RepoProposalCritique, RepoProposalReview};
use submit::ProposalBase;

/// Durable per-operation code proposal. Key: id16.
pub(super) const PROPOSAL: SideTable<EntityId, RepoProposal, crate::side_table::Named> =
    SideTable::new(&side_table::REPO_MUTATION_PROPOSAL);
/// Binds one queued operation (repo, seq) back to the proposal id that
/// authorized it. Key: string (repo key hash, hex64) + u64 (seq, big-endian).
const PROPOSAL_OP: SideTable<OpKey, EntityId, Raw> =
    SideTable::new(&side_table::REPO_MUTATION_PROPOSAL_OP);

/// [`PROPOSAL_OP`]'s key: a repo key hash (fixed 64 lower-case hex characters)
/// and a sequence number, joined by a literal `:` exactly as the hand-spelled
/// key did.
struct OpKey {
    repo_key_hash: [u8; 64],
    seq: u64,
}

impl SideKey for OpKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.repo_key_hash);
        out.push(b':');
        out.extend_from_slice(&self.seq.to_be_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (head, rest) = bytes.split_at_checked(64)?;
        let (colon, seq_bytes) = rest.split_at_checked(1)?;
        if colon != b":" {
            return None;
        }
        let mut repo_key_hash = [0_u8; 64];
        repo_key_hash.copy_from_slice(head);
        Some(Self {
            repo_key_hash,
            seq: u64::from_be_bytes(seq_bytes.try_into().ok()?),
        })
    }
}

fn op_key(repo: &RepoRef, seq: u64) -> OpKey {
    let mut repo_key_hash = [0_u8; 64];
    repo_key_hash.copy_from_slice(repo_mutation_repo_key_hash(repo).as_bytes());
    OpKey { repo_key_hash, seq }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum RepoProposalStatus {
    Proposed,
    Approved,
    Applied,
    Failed,
    Rejected,
}

/// A bounded, immutable file change plus all the critic evidence that judged it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoProposal {
    #[serde(with = "entity_serde")]
    pub id: EntityId,
    pub repo: String,
    pub actor: actor_erase::ProposalActor,
    #[serde(with = "entity_serde")]
    pub session: EntityId,
    #[serde(with = "entity_serde")]
    pub provenance_claim: EntityId,
    /// Stamped onto the document operation this proposal lands as.
    pub op_provenance: crate::code_document::CodeOpProvenance,
    /// The reviewed files: exactly one for an ordinary operation; every
    /// file of one pushed ref update for a received bundle (G4 PR2).
    pub files: Vec<RepoProposedFile>,
    pub message: String,
    pub operation: RepoProposalOperation,
    /// Set only by atomic, all-member merge-queue admission.
    pub merge_stack: Option<String>,
    pub pre_action_fork_hash: RepoForkHash,
    /// Its own catalog, or the vault's review policy (FIX 8268). Stored
    /// under `catalog` as an optional catalog; every older row is explicit.
    #[serde(rename = "catalog")]
    pub review: RepoProposalReview,
    /// Votes on its own catalog's lenses.
    pub critiques: Vec<CritiqueArtifact>,
    /// Votes on the vault policy's lenses, each with the catalog it judged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_critiques: Vec<RepoProposalCritique>,
    /// The review its merge stack's admission sealed, if one admitted it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_review: Option<QueueReviewAdmission>,
    pub status: RepoProposalStatus,
    pub settlement: Option<settlement::RepoProposalSettlement>,
    pub operation_seq: Option<u64>,
    pub created_at: u64,
    /// The leased run it came from, bound before its first write (FIX
    /// 6867); `None` for a trusted or owner proposal.
    pub run: Option<crate::memory::repo_doors::RepoRunStamp>,
    /// The class a host stamped beside the actor (FIX 6867); `None` keeps
    /// the trusted and owner ingress as it is.
    pub actor_class: Option<u8>,
}

/// The complete reviewed operation identity. File bytes remain on `RepoProposal`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepoProposalOperation {
    CommitFile,
    ResolveConflictFile {
        #[serde(with = "entity_serde")]
        branch_subject: EntityId,
        #[serde(with = "entity_serde")]
        open_conflict_claim_id: EntityId,
        branch_name: String,
    },
    /// Every file of one accepted pushed ref update, as ONE reviewed
    /// bundle (G4 PR2): it lands through its merge queue only.
    ReceivedFiles {
        #[serde(with = "entity_serde")]
        candidate: EntityId,
    },
    /// Every file of one native reviewed bundle (FIX 7608 slice 5), each
    /// with its exact state change: it lands through its merge queue only.
    CommitFiles,
}

pub(super) fn invalid(reason: &'static str) -> Error {
    Error::Code(CodeError::InvalidRepoMutationRecord(reason))
}
pub(super) fn store(vault: &Vault, txn: &mut heed::RwTxn<'_>, row: &RepoProposal) -> Result<()> {
    PROPOSAL.put(&vault.store, txn, &row.id, row)
}
impl RepoProposal {
    /// File writes preserve the mode committed by the reviewed pre-action fork.
    /// The live checkout and revision metadata are not authority for a mode.
    /// A file bundle's file takes its reviewed replacement mode.
    pub(crate) fn reviewed_file_mode(
        &self,
        vault: &Vault,
        frontier: &crate::code_document::CodeDocumentFrontier,
    ) -> Result<u32> {
        if super::oplog::repo_mutation_repo_key(&RepoRef::parse(&self.repo)?) != frontier.repo {
            return Err(invalid("reviewed file belongs to another document"));
        }
        if self.is_file_bundle() {
            return self
                .files
                .iter()
                .find(|file| file.path == frontier.path)
                .and_then(|file| file.metadata_edit.as_ref())
                .and_then(|edit| edit.replacement.mode)
                .ok_or(invalid("a bundle file has no reviewed present mode"));
        }
        let (path, _) = self.ordinary_file()?;
        if path != frontier.path {
            return Err(invalid("reviewed file belongs to another document"));
        }
        let txn = vault.store.env.read_txn()?;
        let snapshot = SNAPSHOT
            .get(
                &vault.store,
                &txn,
                &repo_mutation_snapshot_key(self.pre_action_fork_hash),
            )?
            .ok_or(Error::EntityNotFound)?;
        let raw = SNAPSHOT.encode_value(&snapshot)?;
        if *blake3::hash(&raw).as_bytes() != self.pre_action_fork_hash {
            return Err(Error::CorruptedIndex("reviewed fork hash mismatch"));
        }
        let snapshot = super::snapshot::require_snapshot_schema(snapshot)?;
        match snapshot.entries.iter().find(|entry| entry.path == path) {
            None => Ok(crate::codebase::DEFAULT_CODE_FILE_MODE),
            Some(entry) if entry.kind == super::snapshot::StoredRepoSnapshotEntryKind::File => {
                Ok(if entry.executable { 0o100755 } else { 0o100644 })
            }
            // Both reviewed file operations refuse symlinks, rather than following
            // or creating them. Export must not widen that authority.
            Some(_) => Err(invalid(
                "reviewed file operation cannot authorize a symlink",
            )),
        }
    }
    pub(super) fn request(&self) -> Result<RepoMutationRequest> {
        Ok(RepoMutationRequest::new(
            RepoRef::parse(&self.repo)?,
            match &self.operation {
                RepoProposalOperation::CommitFile => {
                    let (path, content) = self.ordinary_file()?;
                    RepoMutationOperation::CommitFile {
                        path: path.to_owned(),
                        content: content.to_vec(),
                        message: self.message.clone(),
                    }
                }
                RepoProposalOperation::ResolveConflictFile {
                    branch_subject,
                    open_conflict_claim_id,
                    branch_name,
                } => {
                    let (path, content) = self.ordinary_file()?;
                    RepoMutationOperation::ResolveConflictFile {
                        branch_subject: *branch_subject,
                        open_conflict_claim_id: *open_conflict_claim_id,
                        branch_name: branch_name.clone(),
                        path: path.to_owned(),
                        content: content.to_vec(),
                        message: self.message.clone(),
                    }
                }
                RepoProposalOperation::ReceivedFiles { candidate } => {
                    RepoMutationOperation::ReceivedFiles {
                        candidate: *candidate,
                        source_operations: self
                            .files
                            .iter()
                            .map(|file| {
                                file.source_operation
                                    .ok_or(invalid("a received file names its source operation"))
                            })
                            .collect::<Result<Vec<_>>>()?,
                        message: self.message.clone(),
                    }
                }
                RepoProposalOperation::CommitFiles => {
                    super::bundle::bundle_request_operation(self)?
                }
            },
        )
        .with_recorded_actor(self.actor.id())
        .with_recorded_class(self.recorded_class()?)
        .with_session_id(self.session)
        .with_provenance_claim_id(self.provenance_claim)
        .with_op_provenance(self.op_provenance.clone()))
    }
    /// Scores are derived from the retained immutable evidence, not accepted from a caller.
    /// Its own catalog's votes; a vault-default proposal names no catalog.
    pub fn triage(&self) -> Result<CritiqueTriage> {
        let catalog = self.review.catalog().ok_or(invalid(
            "a vault-default proposal is judged under the vault's review policy",
        ))?;
        triage_critiques(catalog, &self.critiques, &[])
    }
    pub fn approval(&self) -> ClaimApprovalStatus {
        match self.status {
            RepoProposalStatus::Applied | RepoProposalStatus::Approved => {
                ClaimApprovalStatus::Approved
            }
            RepoProposalStatus::Proposed
            | RepoProposalStatus::Failed
            | RepoProposalStatus::Rejected => ClaimApprovalStatus::Proposed,
        }
    }
    /// Its own catalog's unanimous critics. Only an explicit catalog makes a
    /// proposal eligible outside its merge queue (FIX 8268).
    pub(super) fn eligible(&self) -> Result<bool> {
        let Some(catalog) = self.review.catalog() else {
            return Ok(false);
        };
        let distinct = self
            .critiques
            .iter()
            .filter(|c| self.counts_toward_quorum(c))
            .map(|c| c.provenance.critic_ref.as_str())
            .collect::<BTreeSet<_>>();
        let critics = crate::merge_queue::DEFAULT_QUEUE_REVIEW_CRITICS as usize;
        Ok(distinct.len() >= critics
            && catalog.lenses.iter().all(|lens| {
                self.critiques
                    .iter()
                    .any(|c| c.lens_id == lens.id && c.domain == lens.domain)
            })
            && self
                .critiques
                .iter()
                .all(|c| c.verdict == CritiqueVerdict::Accept && !c.out_of_scope)
            && self.triage()?.verdict == CritiqueVerdict::Accept)
    }
}
impl Vault {
    /// Stages exactly one Proposed file operation and its pre-action snapshot.
    /// Catalogs are supplied by host policy, never by untrusted guest code.
    pub fn propose_repo_mutation(
        &self,
        request: RepoMutationRequest,
        catalog: LensCatalog,
    ) -> Result<RepoProposal> {
        let proposed = self.propose_repo_mutation_checked::<std::convert::Infallible>(
            request,
            RepoProposalReview::Explicit(catalog),
            ProposalBase::CurrentCheckout,
            None,
            |_| Ok(Ok(())),
        )?;
        Ok(proposed.unwrap_or_else(|never| match never {}))
    }

    /// Owner doors revalidate their proof in the proposal's writer, not in a
    /// separate preflight transaction. Engine admission stays shared.
    pub(crate) fn propose_repo_mutation_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        repository: EntityId,
        request: RepoMutationRequest,
        review: RepoProposalReview,
    ) -> Result<RepoProposal> {
        let actor = request.actor_id;
        let repository_ref = request.repo_ref.clone();
        let session = request.session_id;
        let sources = [
            request.op_provenance.turn,
            request.op_provenance.activity,
            request.op_provenance.intent,
            request.op_provenance.substrate_ref,
        ];
        let proposed = self.propose_repo_mutation_checked::<std::convert::Infallible>(
            request,
            review,
            ProposalBase::CurrentCheckout,
            None,
            |txn| {
                guards::require_repo_artifact_in_txn(self, txn, repository, &repository_ref)?;
                if let Some(session) = session {
                    guards::require_entity_kind(
                        self,
                        txn,
                        session,
                        crate::registry::ENTITY_TYPE_SESSION,
                    )?;
                }
                for id in sources.into_iter().flatten() {
                    if !crate::ports::EntityStoreRead::port_entity_present(&self.store, txn, &id)? {
                        return Err(Error::EntityNotFound);
                    }
                }
                if Some(owner.revalidate_in_txn(self, txn)?) != actor {
                    return Err(invalid("proposal actor is not the authenticated owner"));
                }
                Ok(Ok(()))
            },
        )?;
        Ok(proposed.unwrap_or_else(|never| match never {}))
    }
    pub fn repo_proposal(&self, id: EntityId) -> Result<Option<RepoProposal>> {
        let txn = self.store.env.read_txn()?;
        PROPOSAL.get(&self.store, &txn, &id)
    }
    /// Unanimous multi-critic approval is the only attributed commit door.
    /// A split verdict leaves the proposal and its recovery snapshot intact.
    pub fn apply_repo_proposal(&self, id: EntityId) -> Result<RepoMutationOutcome> {
        let row = self.repo_proposal(id)?.ok_or(Error::EntityNotFound)?;
        let repo = RepoRef::parse(&row.repo)?;
        let repo_root = resolve_mutable_repo_root(&repo)?;
        let _guard = lock_repository(&git_common_dir(&repo_root)?)?;
        self.recover_prepared_repo_mutations_locked(&repo, &repo_root)?;
        let mut txn = self.store.env.write_txn()?;
        let mut row = PROPOSAL
            .get(&self.store, &txn, &id)?
            .ok_or(Error::EntityNotFound)?;
        if row.merge_stack.is_some() {
            return Err(invalid("stack-bound proposal requires its merge queue"));
        }
        // A file bundle has one route: its repository's merge queue.
        if row.is_file_bundle() {
            return Err(files::bundle_queue_only(&row));
        }
        if let Some(seq) = row.operation_seq {
            drop(txn);
            let entry = self
                .repo_mutation_oplog_for_canonical(&repo)?
                .into_iter()
                .find(|e| e.seq == seq)
                .ok_or(Error::CorruptedIndex("proposal oplog missing"))?;
            return if entry.status == RepoMutationStatus::Applied {
                Ok(RepoMutationOutcome {
                    entry,
                    repo_conflict_claim_id: resolution_claim_id(self, &row)?,
                })
            } else {
                Err(invalid(
                    "proposal operation did not apply; submit a fresh proposal",
                ))
            };
        }
        if !matches!(
            row.status,
            RepoProposalStatus::Proposed | RepoProposalStatus::Approved
        ) || !row.eligible()?
        {
            return Err(invalid(
                "proposal requires unanimous independent multi-critic acceptance",
            ));
        }
        row.status = RepoProposalStatus::Approved;
        store(self, &mut txn, &row)?;
        txn.commit()?;
        self.apply_repo_mutation_approved(row.request()?, id)
    }
}

/// Snapshot custody at proposal admission (ARCH-0069 S4/S5; OF-067): a
/// review holds the bytes it approves and reads the file they replace from
/// its snapshot, so a write the policy would withhold, a write to a file the
/// snapshot withholds, and a message that holds a secret are refused before
/// the proposal or its snapshot is stored.
fn admit_custody(
    custody: &SnapshotCustody,
    pre_action: &StoredRepoSnapshot,
    path: &str,
    content: &[u8],
    message: &str,
) -> Result<()> {
    if let Some(withheld) = custody.withholds(path, content) {
        return Err(withheld.refusal());
    }
    if pre_action
        .entries
        .iter()
        .any(|entry| entry.path == path && entry.kind == StoredRepoSnapshotEntryKind::Withheld)
    {
        return Err(SnapshotWithhold::Excluded.refusal());
    }
    match crate::batch::secret_scan::scan_file_content("", message.as_bytes()) {
        Some(reason) => Err(SnapshotWithhold::Quarantined(reason).refusal()),
        None => Ok(()),
    }
}

pub(super) fn authorize(
    vault: &Vault,
    request: &RepoMutationRequest,
    proposal: Option<EntityId>,
    repo_root: &std::path::Path,
    stack: Option<&super::reviewed_stack::StackStep>,
) -> Result<()> {
    let attributed = request.actor_id.is_some() || request.session_id.is_some();
    // A received bundle never runs as a trusted unattributed write: it
    // needs its source's pusher and fork, its review and its stack.
    if let RepoMutationOperation::CommitFiles { .. } = request.operation {
        super::bundle::require_bundle_route(request, proposal, stack)?;
    } else if let RepoMutationOperation::ReceivedFiles { .. } = request.operation {
        if request.actor_id.is_none() || request.session_id.is_none() || proposal.is_none() {
            return Err(invalid(
                "a received push bundle lands under its pusher, fork and review",
            ));
        }
        if stack.is_none() {
            return Err(received_bundle_queue_only());
        }
    } else if !attributed
        || !matches!(
            request.operation,
            RepoMutationOperation::CommitFile { .. }
                | RepoMutationOperation::ResolveConflictFile { .. }
        )
    {
        return Ok(());
    }
    let row = vault
        .repo_proposal(proposal.ok_or(invalid(
            "attributed code writes require a reviewed proposal",
        ))?)?
        .ok_or(Error::EntityNotFound)?;
    if row.status != RepoProposalStatus::Approved
        || row.operation_seq.is_some()
        || row.actor.id().is_none()
        || row.request()? != *request
    {
        return Err(invalid(
            "proposal capability does not authorize this operation",
        ));
    }
    let actual = capture_repo_snapshot(vault, repo_root)?.0;
    match stack {
        Some(step) => step.authorize(&row, actual)?,
        None => {
            if row.merge_stack.is_some() {
                return Err(invalid("stack-bound proposal requires its merge queue"));
            }
            if actual != row.pre_action_fork_hash {
                return Err(Error::ConcurrentWrite(
                    "proposal base changed; no automatic rebase",
                ));
            }
        }
    }
    validate_conflict(vault, &row, repo_root)
}
pub(super) fn bind_prepared(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: Option<EntityId>,
    repo: &RepoRef,
    seq: u64,
) -> Result<()> {
    let Some(id) = id else {
        return Ok(());
    };
    let mut row = PROPOSAL
        .get(&vault.store, txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    if row.operation_seq.is_some() || row.status != RepoProposalStatus::Approved {
        return Err(invalid("proposal already consumed"));
    }
    row.operation_seq = Some(seq);
    store(vault, txn, &row)?;
    PROPOSAL_OP.put(&vault.store, txn, &op_key(repo, seq), &id)?;
    Ok(())
}
pub(super) fn for_operation(
    vault: &Vault,
    repo: &RepoRef,
    seq: u64,
) -> Result<Option<RepoProposal>> {
    let txn = vault.store.env.read_txn()?;
    let Some(id) = PROPOSAL_OP.get(&vault.store, &txn, &op_key(repo, seq))? else {
        return Ok(None);
    };
    let row = PROPOSAL
        .get(&vault.store, &txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    if row.id != id || row.operation_seq != Some(seq) || RepoRef::parse(&row.repo)? != *repo {
        return Err(invalid("proposal operation binding differs"));
    }
    Ok(Some(row))
}

pub(super) fn finish(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    repo: &RepoRef,
    seq: u64,
    status: RepoMutationStatus,
) -> Result<()> {
    let Some(id) = PROPOSAL_OP.get(&vault.store, txn, &op_key(repo, seq))? else {
        return Ok(());
    };
    let mut row = PROPOSAL
        .get(&vault.store, txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    row.status = match status {
        RepoMutationStatus::Applied => RepoProposalStatus::Applied,
        RepoMutationStatus::Failed => RepoProposalStatus::Failed,
        RepoMutationStatus::Prepared => RepoProposalStatus::Approved,
    };
    // An erased actor's applied write approves its journal naming no one (FIX 4479).
    if status == RepoMutationStatus::Applied {
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?
            .ok_or(Error::EntityNotFound)?;
        let bytes = raw
            .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("proposal entity header"))?;
        let mut claim = crate::claim::decode_claim_body(bytes, true)?;
        if claim.predicate != "repo.proposed_diff"
            || crate::claim::session_claim_producer(&claim) != row.actor.id()
        {
            return Err(Error::CorruptedIndex("proposal claim binding changed"));
        }
        claim.approval = ClaimApprovalStatus::Approved;
        // Keep the producer envelope on the approval transition as well as
        // admission. A reserved raw put is not a session-write capability.
        // A stack member keeps the review its stack's admission sealed (FIX
        // 8268); a proposal applied alone, its own catalog's critics.
        let reviewed = match row.merge_stack.as_deref() {
            Some(batch) => row.stack_review_admitted(batch)?,
            None => row.eligible()?,
        };
        if !reviewed {
            return Err(invalid("proposal approval lost critic coverage"));
        }
        put_journal_claim(vault, txn, id, row.actor.id(), &claim, row.created_at)?;
    }
    store(vault, txn, &row)
}
pub(super) fn proposal_snapshot_recorded(
    vault: &Vault,
    repo: &RepoRef,
    hash: RepoForkHash,
) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    for (count, entry) in PROPOSAL.iter_from(&vault.store, &txn, &[])?.enumerate() {
        if count >= 100_000 {
            return Err(Error::IndexOverflow("repository proposals"));
        }
        let (_, row) = entry?;
        if repo_mutation_repo_key_hash(&RepoRef::parse(&row.repo)?)
            == repo_mutation_repo_key_hash(repo)
            && row.pre_action_fork_hash == hash
        {
            return Ok(true);
        }
    }
    Ok(false)
}

mod entity_serde {
    use crate::entity_id::EntityId;
    use serde::{Deserialize, Deserializer, Serializer};
    pub(super) fn serialize<S: Serializer>(
        id: &EntityId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&id.to_hex())
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EntityId, D::Error> {
        EntityId::from_hex(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Check claim and branch bindings before the document edit or Git mutation.
pub(super) fn validate_conflict(
    vault: &Vault,
    proposal: &RepoProposal,
    root: &std::path::Path,
) -> Result<()> {
    let RepoProposalOperation::ResolveConflictFile { branch_name, .. } = &proposal.operation else {
        return Ok(());
    };
    let txn = vault.store.env.read_txn()?;
    validate_conflict_in_txn(vault, &txn, proposal)?;
    drop(txn);
    let branch = super::support::utf8_trimmed(
        super::git::run_git(root, &["branch".into(), "--show-current".into()])?,
        "branch must be UTF-8",
    )?;
    if branch != *branch_name {
        return Err(invalid(
            "reviewed resolution requires its active conflict and branch",
        ));
    }
    Ok(())
}

/// Replayed outcomes keep the same typed resolution receipt as first execution.
pub(super) fn resolution_claim_id(vault: &Vault, row: &RepoProposal) -> Result<Option<EntityId>> {
    let RepoProposalOperation::ResolveConflictFile {
        branch_subject,
        open_conflict_claim_id,
        branch_name,
    } = &row.operation
    else {
        return Ok(None);
    };
    let repo = RepoRef::parse(&row.repo)?;
    let resolution = vault
        .repo_conflict_resolution_claims(branch_subject)?
        .into_iter()
        .find(|claim| {
            claim.open_conflict_claim_id == *open_conflict_claim_id
                && claim.repo_ref == repo
                && claim.branch == *branch_name
                && row
                    .ordinary_file()
                    .is_ok_and(|(path, _)| claim.resolved_paths.as_slice() == [path])
        })
        .ok_or(Error::CorruptedIndex(
            "applied proposal resolution receipt missing",
        ))?;
    Ok(Some(resolution.claim_id))
}

/// These are engine-owned review/session journal facts, not session-overlay
/// claim candidates. Their subject/value binds the session; `sess` is reserved
/// for envelope-routed session writes. Only the reviewed queue can advance them.
/// An erased actor's journal names no producer (`actor` none, FIX 4479).
fn put_journal_claim(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    actor: Option<EntityId>,
    body: &ClaimBody,
    now: u64,
) -> Result<()> {
    if !matches!(
        body.predicate.as_str(),
        "repo.proposed_diff" | "repo.session"
    ) || body.session_tag.is_some()
        || crate::claim::session_claim_producer(body) != actor
    {
        return Err(invalid("invalid repository journal producer"));
    }
    vault.put_reserved_claim_in_txn(
        txn,
        &id,
        body,
        crate::temporal::TimeRange {
            start: now,
            end: now,
        },
        now,
    )
}
