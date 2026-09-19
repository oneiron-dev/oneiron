//! Durable per-operation code proposals. Review never mutates the repository.
use std::collections::BTreeSet;

use super::git::{canonical_repo_ref_for_root, git_common_dir, resolve_mutable_repo_root};
use super::oplog::{repo_mutation_repo_key_hash, repo_mutation_snapshot_key};
use super::queue::validate_operation;
use super::snapshot::capture_repo_snapshot;
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
use rmpv::Value;
use serde::{Deserialize, Serialize};

const PREFIX: &[u8] = b"repo_mutation:proposal:v1:";
const OP_PREFIX: &[u8] = b"repo_mutation:proposal_op:v1:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepoProposalStatus {
    Proposed,
    Approved,
    Applied,
    Failed,
}

/// A bounded, immutable file change plus all the critic evidence that judged it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoProposal {
    #[serde(with = "entity_serde")]
    pub id: EntityId,
    pub repo: String,
    #[serde(with = "entity_serde")]
    pub actor: EntityId,
    #[serde(with = "entity_serde")]
    pub session: EntityId,
    #[serde(with = "entity_serde")]
    pub provenance_claim: EntityId,
    pub path: String,
    pub content: Vec<u8>,
    pub message: String,
    pub operation: RepoProposalOperation,
    /// Set only by atomic, all-member merge-queue admission.
    pub merge_stack: Option<String>,
    pub pre_action_fork_hash: RepoForkHash,
    pub catalog: LensCatalog,
    pub critiques: Vec<CritiqueArtifact>,
    pub status: RepoProposalStatus,
    pub operation_seq: Option<u64>,
    pub created_at: u64,
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
}

pub(super) fn invalid(reason: &'static str) -> Error {
    Error::Code(CodeError::InvalidRepoMutationRecord(reason))
}
pub(super) fn key(id: EntityId) -> Vec<u8> {
    [PREFIX, id.as_bytes()].concat()
}
fn op_key(repo: &RepoRef, seq: u64) -> Vec<u8> {
    [
        OP_PREFIX,
        repo_mutation_repo_key_hash(repo).as_bytes(),
        b":",
        &seq.to_be_bytes(),
    ]
    .concat()
}
pub(super) fn decode(bytes: &[u8]) -> Result<RepoProposal> {
    rmp_serde::from_slice(bytes).map_err(|_| invalid("invalid repository proposal"))
}
pub(super) fn store(vault: &Vault, txn: &mut heed::RwTxn<'_>, row: &RepoProposal) -> Result<()> {
    let bytes = rmp_serde::to_vec_named(row).map_err(|_| invalid("proposal encoding failed"))?;
    vault.store.vault_meta.put(txn, &key(row.id), &bytes)?;
    Ok(())
}
impl RepoProposal {
    pub(super) fn request(&self) -> Result<RepoMutationRequest> {
        Ok(RepoMutationRequest::new(
            RepoRef::parse(&self.repo)?,
            match &self.operation {
                RepoProposalOperation::CommitFile => RepoMutationOperation::CommitFile {
                    path: self.path.clone(),
                    content: self.content.clone(),
                    message: self.message.clone(),
                },
                RepoProposalOperation::ResolveConflictFile {
                    branch_subject,
                    open_conflict_claim_id,
                    branch_name,
                } => RepoMutationOperation::ResolveConflictFile {
                    branch_subject: *branch_subject,
                    open_conflict_claim_id: *open_conflict_claim_id,
                    branch_name: branch_name.clone(),
                    path: self.path.clone(),
                    content: self.content.clone(),
                    message: self.message.clone(),
                },
            },
        )
        .with_actor_id(self.actor)
        .with_session_id(self.session)
        .with_provenance_claim_id(self.provenance_claim))
    }
    /// Scores are derived from the retained immutable evidence, not accepted from a caller.
    pub fn triage(&self) -> Result<CritiqueTriage> {
        triage_critiques(&self.catalog, &self.critiques, &[])
    }
    pub fn approval(&self) -> ClaimApprovalStatus {
        match self.status {
            RepoProposalStatus::Applied | RepoProposalStatus::Approved => {
                ClaimApprovalStatus::Approved
            }
            RepoProposalStatus::Proposed | RepoProposalStatus::Failed => {
                ClaimApprovalStatus::Proposed
            }
        }
    }
    pub(super) fn eligible(&self) -> Result<bool> {
        let distinct = self
            .critiques
            .iter()
            .map(|c| c.provenance.critic_ref.as_str())
            .collect::<BTreeSet<_>>();
        Ok(distinct.len() >= 2
            && self.catalog.lenses.iter().all(|lens| {
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
        validate_operation(&request.operation)?;
        super::trailer::validate_repo_provenance_request(self, &request)?;
        let (Some(actor), Some(session), Some(provenance_claim)) = (
            request.actor_id,
            request.session_id,
            request.provenance_claim_id,
        ) else {
            return Err(invalid(
                "code proposal requires actor, session and provenance",
            ));
        };
        let (path, content, message, operation) = match request.operation {
            RepoMutationOperation::CommitFile {
                path,
                content,
                message,
            } => (path, content, message, RepoProposalOperation::CommitFile),
            RepoMutationOperation::ResolveConflictFile {
                branch_subject,
                open_conflict_claim_id,
                branch_name,
                path,
                content,
                message,
            } => (
                path,
                content,
                message,
                RepoProposalOperation::ResolveConflictFile {
                    branch_subject,
                    open_conflict_claim_id,
                    branch_name,
                },
            ),
            _ => return Err(invalid("code proposal supports one file operation")),
        };
        if content.len() > 32 * 1024 * 1024 || catalog.lenses.is_empty() {
            return Err(invalid(
                "proposal requires bounded content and review lenses",
            ));
        }
        // Empty triage validates the host's catalog without inventing a verdict.
        triage_critiques(&catalog, &[], &[])?;
        let repo_root = resolve_mutable_repo_root(&request.repo_ref)?;
        let repo = canonical_repo_ref_for_root(&request.repo_ref, &repo_root)?;
        let _guard = lock_repository(&git_common_dir(&repo_root)?)?;
        self.recover_prepared_repo_mutations_locked(&repo, &repo_root)?;
        let (fork, snapshot) = capture_repo_snapshot(&repo_root)?;
        let row = RepoProposal {
            id: EntityId::now(),
            repo: repo.canonical(),
            actor,
            session,
            provenance_claim,
            path,
            content,
            message,
            operation,
            merge_stack: None,
            pre_action_fork_hash: fork,
            catalog,
            critiques: Vec::new(),
            status: RepoProposalStatus::Proposed,
            operation_seq: None,
            created_at: now_millis() / 1000,
        };
        validate_conflict(self, &row, &repo_root)?;
        let mut body = ClaimBody::new(
            "repo.proposed_diff",
            ClaimSubject::Entity(session),
            Value::Map(vec![
                (Value::from("actor"), Value::from(actor.to_hex())),
                (Value::from("path"), Value::from(row.path.clone())),
                (
                    Value::from("operation"),
                    Value::from(row.request()?.operation.kind()),
                ),
                (
                    Value::from("operation_hash"),
                    Value::Binary(
                        blake3::hash(
                            &rmp_serde::to_vec_named(&(
                                &row.operation,
                                &row.path,
                                &row.content,
                                &row.message,
                            ))
                            .map_err(|_| invalid("proposal operation encoding failed"))?,
                        )
                        .as_bytes()
                        .to_vec(),
                    ),
                ),
                (
                    Value::from("content_hash"),
                    Value::Binary(blake3::hash(&row.content).as_bytes().to_vec()),
                ),
                (
                    Value::from("pre_action_fork_hash"),
                    Value::Binary(fork.to_vec()),
                ),
            ]),
            1.0,
            ClaimApprovalStatus::Proposed,
            ClaimLifecycleStatus::Active,
        );
        body.source = Some(ClaimSource::Generated);
        body.evidence = Some(Value::Map(vec![(
            Value::from(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
            Value::Binary(actor.as_bytes().to_vec()),
        )]));
        let session_claim_id = crate::codebase::entity_id_from_hash_material(
            b"oneiron:repo-session-claim:v1",
            &[session.as_bytes(), actor.as_bytes()],
        )?;
        let mut session_claim = ClaimBody::new(
            "repo.session",
            ClaimSubject::Entity(session),
            Value::Map(vec![
                (Value::from("actor"), Value::from(actor.to_hex())),
                (Value::from("session"), Value::from(session.to_hex())),
                (
                    Value::from("provenance_claim_id"),
                    Value::from(provenance_claim.to_hex()),
                ),
            ]),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        session_claim.source = Some(ClaimSource::Observed);
        session_claim.scope = Some(Value::Map(vec![(
            Value::from("sensitivity"),
            Value::from("public"),
        )]));
        session_claim.evidence = body.evidence.clone();
        let mut txn = self.store.env.write_txn()?;
        if self
            .store
            .entities
            .get(&txn, session_claim_id.as_bytes())?
            .is_none()
        {
            put_journal_claim(
                self,
                &mut txn,
                session_claim_id,
                actor,
                &session_claim,
                row.created_at,
            )?;
        }
        if self.store.entities.get(&txn, actor.as_bytes())?.is_none() {
            return Err(Error::EntityNotFound);
        }
        put_journal_claim(self, &mut txn, row.id, actor, &body, row.created_at)?;
        self.store
            .vault_meta
            .put(&mut txn, &repo_mutation_snapshot_key(fork), &snapshot)?;
        store(self, &mut txn, &row)?;
        txn.commit()?;
        Ok(row)
    }
    pub fn repo_proposal(&self, id: EntityId) -> Result<Option<RepoProposal>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &key(id))?
            .map(|raw| decode(&raw))
            .transpose()
    }
    /// Records one authenticated host critic identity. A critic cannot rewrite its vote.
    pub fn review_repo_proposal(
        &self,
        id: EntityId,
        critic: EntityId,
        critique: CritiqueArtifact,
    ) -> Result<RepoProposal> {
        let mut txn = self.store.env.write_txn()?;
        let raw = self
            .store
            .vault_meta
            .get(&txn, &key(id))?
            .ok_or(Error::EntityNotFound)?;
        let mut row = decode(&raw)?;
        if row.status != RepoProposalStatus::Proposed
            || critic == row.actor
            || critique.provenance.critic_ref != critic.to_hex()
            || critique.candidate_ref != id.to_hex()
            || critique.out_of_scope
            || row.critiques.len() >= 64
            || self.store.entities.get(&txn, critic.as_bytes())?.is_none()
        {
            return Err(invalid(
                "critic is unbound, self-reviewing, or proposal is closed",
            ));
        }
        if let Some(existing) = row.critiques.iter().find(|c| {
            c.provenance.critic_ref == critique.provenance.critic_ref
                && c.lens_id == critique.lens_id
                && c.domain == critique.domain
        }) {
            return if existing == &critique {
                Ok(row)
            } else {
                Err(invalid("critic vote is immutable"))
            };
        }
        row.critiques.push(critique);
        row.triage()?;
        store(self, &mut txn, &row)?;
        txn.commit()?;
        Ok(row)
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
        let mut row = decode(
            &self
                .store
                .vault_meta
                .get(&txn, &key(id))?
                .ok_or(Error::EntityNotFound)?,
        )?;
        if row.merge_stack.is_some() {
            return Err(invalid("stack-bound proposal requires its merge queue"));
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

pub(super) fn authorize(
    vault: &Vault,
    request: &RepoMutationRequest,
    proposal: Option<EntityId>,
    repo_root: &std::path::Path,
    stack: Option<&super::reviewed_stack::StackStep>,
) -> Result<()> {
    let attributed = request.actor_id.is_some() || request.session_id.is_some();
    if !attributed
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
        || row.request()? != *request
    {
        return Err(invalid(
            "proposal capability does not authorize this operation",
        ));
    }
    let actual = capture_repo_snapshot(repo_root)?.0;
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
    let mut row = decode(
        &vault
            .store
            .vault_meta
            .get(txn, &key(id))?
            .ok_or(Error::EntityNotFound)?,
    )?;
    if row.operation_seq.is_some() || row.status != RepoProposalStatus::Approved {
        return Err(invalid("proposal already consumed"));
    }
    row.operation_seq = Some(seq);
    store(vault, txn, &row)?;
    vault
        .store
        .vault_meta
        .put(txn, &op_key(repo, seq), id.as_bytes())?;
    Ok(())
}
pub(super) fn for_operation(
    vault: &Vault,
    repo: &RepoRef,
    seq: u64,
) -> Result<Option<RepoProposal>> {
    let txn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.vault_meta.get(&txn, &op_key(repo, seq))? else {
        return Ok(None);
    };
    let id = EntityId::from_bytes(
        raw.as_ref()
            .try_into()
            .map_err(|_| invalid("proposal operation index corrupt"))?,
    )?;
    let row = decode(
        &vault
            .store
            .vault_meta
            .get(&txn, &key(id))?
            .ok_or(Error::EntityNotFound)?,
    )?;
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
    let Some(raw) = vault.store.vault_meta.get(txn, &op_key(repo, seq))? else {
        return Ok(());
    };
    let id = EntityId::from_bytes(
        raw.as_ref()
            .try_into()
            .map_err(|_| invalid("proposal operation index corrupt"))?,
    )?;
    let mut row = decode(
        &vault
            .store
            .vault_meta
            .get(txn, &key(id))?
            .ok_or(Error::EntityNotFound)?,
    )?;
    row.status = match status {
        RepoMutationStatus::Applied => RepoProposalStatus::Applied,
        RepoMutationStatus::Failed => RepoProposalStatus::Failed,
        RepoMutationStatus::Prepared => RepoProposalStatus::Approved,
    };
    if status == RepoMutationStatus::Applied {
        let raw = vault
            .store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let bytes = raw
            .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("proposal entity header"))?;
        let mut claim = crate::claim::decode_claim_body(bytes, true)?;
        if claim.predicate != "repo.proposed_diff"
            || crate::claim::session_claim_producer(&claim) != Some(row.actor)
        {
            return Err(Error::CorruptedIndex("proposal claim binding changed"));
        }
        claim.approval = ClaimApprovalStatus::Approved;
        // Keep the producer envelope on the approval transition as well as
        // admission. A reserved raw put is not a session-write capability.
        if !row.eligible()? {
            return Err(invalid("proposal approval lost critic coverage"));
        }
        put_journal_claim(vault, txn, id, row.actor, &claim, row.created_at)?;
    }
    store(vault, txn, &row)
}
pub(super) fn proposal_snapshot_recorded(
    vault: &Vault,
    repo: &RepoRef,
    hash: RepoForkHash,
) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    for (count, entry) in vault
        .store
        .vault_meta
        .prefix_iter(&txn, PREFIX)?
        .enumerate()
    {
        if count >= 100_000 {
            return Err(Error::IndexOverflow("repository proposals"));
        }
        let (_, raw) = entry?;
        let row = decode(&raw)?;
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
    let RepoProposalOperation::ResolveConflictFile {
        branch_subject,
        open_conflict_claim_id,
        branch_name,
    } = &proposal.operation
    else {
        return Ok(());
    };
    let repo = RepoRef::parse(&proposal.repo)?;
    let matches = vault
        .repo_conflict_claims(branch_subject)?
        .into_iter()
        .any(|claim| {
            claim.claim_id == *open_conflict_claim_id
                && claim.repo_ref == repo
                && claim.branch == *branch_name
                && claim.conflicted_paths.contains(&proposal.path)
        });
    let branch = super::support::utf8_trimmed(
        super::git::run_git(root, &["branch".into(), "--show-current".into()])?,
        "branch must be UTF-8",
    )?;
    if !matches || branch != *branch_name {
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
                && claim.resolved_paths.as_slice() == std::slice::from_ref(&row.path)
        })
        .ok_or(Error::CorruptedIndex(
            "applied proposal resolution receipt missing",
        ))?;
    Ok(Some(resolution.claim_id))
}

/// These are engine-owned review/session journal facts, not session-overlay
/// claim candidates. Their subject/value binds the session; `sess` is reserved
/// for envelope-routed session writes. Only the reviewed queue can advance them.
fn put_journal_claim(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    actor: EntityId,
    body: &ClaimBody,
    now: u64,
) -> Result<()> {
    if !matches!(
        body.predicate.as_str(),
        "repo.proposed_diff" | "repo.session"
    ) || body.session_tag.is_some()
        || crate::claim::session_claim_producer(body) != Some(actor)
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
