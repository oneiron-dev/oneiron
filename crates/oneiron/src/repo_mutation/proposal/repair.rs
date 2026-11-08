//! General repair supersession (FIX 4364, CODE-CUSTODY-04): a fresh
//! proposal names the failed proposal it replaces, and the writer that
//! stores it keeps one append-once `repo.proposal_replacement` CLAIM. That
//! CLAIM links the failed source and its retained failure evidence to the
//! replacement, its admission receipt and its own retained base fork.
//!
//! The replacement is an ordinary Proposed proposal with its own review and
//! queue cycle. No id, vote, base or sequence of the source is reused, and
//! the secret-handle `resolves` successor is a different relation. The link
//! records that replacement work was submitted; it never says the source was
//! repaired, landed or green. One failed source has one replacement; a later
//! failed replacement gets its own link, so a chain stays immutable.

use std::path::Path;

use rmpv::Value;

use super::receipts::{
    failed_attempt_receipt_in_txn, put_receipt_once_in_txn, receipt_body, receipt_field,
    stored_receipt_in_txn,
};
use super::{
    PROPOSAL, RepoProposal, RepoProposalStatus, SNAPSHOT, invalid, repo_mutation_snapshot_key,
};
use crate::Vault;
use crate::claim::ClaimSubject;
use crate::codebase::{RepoRef, entity_id_from_hash_material};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::repo_mutation::types::RepoForkHash;

/// The predicate of the link from a failed proposal to its replacement.
pub(crate) const PROPOSAL_REPLACEMENT_PREDICATE: &str = "repo.proposal_replacement";

const PROPOSAL_REPLACEMENT_DOMAIN: &[u8] = b"oneiron:repo-proposal-replacement:v1";

/// The failed proposal a replacement names, and the object store whose
/// merge queue holds that failure, resolved before the replacement's writer.
pub(in crate::repo_mutation) struct RepairSource {
    pub(super) source: EntityId,
    store: String,
}

impl RepairSource {
    /// `source`, replaced by a proposal of the repository at `repo_root`:
    /// the queue of that repository's object store keeps its failure, as a
    /// replacement belongs to its source's repository.
    ///
    /// # Errors
    /// A repository whose object store does not resolve.
    pub(in crate::repo_mutation) fn of(
        vault: &Vault,
        source: EntityId,
        repo_root: &Path,
    ) -> Result<Self> {
        let store = crate::git_wire::GitWire::new(vault)?
            .repository_identity(repo_root)?
            .as_hex();
        Ok(Self { source, store })
    }
}

/// A stored repair link (FIX 4364): the failed source, its replacement and
/// the replacement's retained base fork.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoProposalReplacement {
    /// The `repo.proposal_replacement` CLAIM.
    pub receipt: EntityId,
    pub source: EntityId,
    pub replacement: EntityId,
    pub replacement_fork: RepoForkHash,
}

/// The id of the one replacement link of the failed proposal `source`.
fn replacement_receipt_id(source: EntityId) -> Result<EntityId> {
    entity_id_from_hash_material(PROPOSAL_REPLACEMENT_DOMAIN, &[source.as_bytes()])
}

/// The retained failure `source` ended in, read in `txn`: a receipted
/// terminal batch of the queue of `store` that quarantined it in its
/// failing group or rolled it back, or the failed completion receipt of a
/// standalone attempt. A good survivor, a proposal still queued or green,
/// and a stack member's failed attempt its stack may still retry are none.
///
/// # Errors
/// A stored receipt that binds another fact, or a store failure.
fn failure_evidence_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: &RepoProposal,
    store: &str,
) -> Result<Option<Value>> {
    if let Some(failure) =
        crate::merge_queue::proposal_queue_failure_in_txn(vault, txn, store, source.id)?
    {
        return Ok(Some(Value::Map(vec![
            ("batch".into(), failure.batch.into()),
            ("completion".into(), failure.completion.to_hex().into()),
            ("outcome".into(), failure.outcome.into()),
            (
                "group".into(),
                Value::Array(failure.group.into_iter().map(Value::from).collect()),
            ),
        ])));
    }
    let (RepoProposalStatus::Failed, None, Some(seq)) =
        (source.status, &source.merge_stack, source.operation_seq)
    else {
        return Ok(None);
    };
    Ok(
        failed_attempt_receipt_in_txn(vault, txn, source.id, seq)?.map(|attempt| {
            Value::Map(vec![
                ("attempt".into(), Value::from(seq)),
                ("completion".into(), attempt.to_hex().into()),
                ("outcome".into(), "failed".into()),
            ])
        }),
    )
}

/// Records `row` as the replacement of the failed proposal `repair` names,
/// in the writer `txn` that stores `row`, its admission receipt `admission`
/// and its base snapshot (FIX 4364). The source is read again here: it must
/// be another proposal of the same repository with retained failure
/// evidence, and the replacement's base must be stored and hash to its
/// fork. A retry finds its own link; a different replacement of the same
/// source conflicts, and none of the replacement's writes survive.
///
/// # Errors
/// A source that is missing, of another repository or not failed, a base
/// that is not stored, a source already replaced, or a store failure.
pub(super) fn record_replacement_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &RepoProposal,
    repair: &RepairSource,
    admission: EntityId,
) -> Result<()> {
    if row.repair_of != Some(repair.source) || repair.source == row.id {
        return Err(invalid(
            "a replacement proposal names one other failed source",
        ));
    }
    let source = PROPOSAL
        .get(&vault.store, txn, &repair.source)?
        .ok_or(Error::EntityNotFound)?;
    let repo = RepoRef::parse(&row.repo)?;
    if !RepoRef::parse(&source.repo)?.same_repository(&repo) {
        return Err(invalid(
            "a replacement proposal belongs to its source's repository",
        ));
    }
    let Some(failure) = failure_evidence_in_txn(vault, txn, &source, &repair.store)? else {
        return Err(invalid("a repair source has no retained failure evidence"));
    };
    let snapshot = SNAPSHOT
        .get(
            &vault.store,
            txn,
            &repo_mutation_snapshot_key(row.pre_action_fork_hash),
        )?
        .ok_or(Error::EntityNotFound)?;
    if *blake3::hash(&SNAPSHOT.encode_value(&snapshot)?).as_bytes() != row.pre_action_fork_hash {
        return Err(Error::CorruptedIndex("replacement fork hash mismatch"));
    }
    let id = replacement_receipt_id(source.id)?;
    if let Some(stored) = stored_receipt_in_txn(vault, txn, &id)?
        && receipt_field(&stored.value, "replacement").and_then(Value::as_str)
            != Some(row.id.to_hex().as_str())
    {
        return Err(Error::ConcurrentWrite(
            "the failed proposal already has a different replacement",
        ));
    }
    let mut fields = vec![
        ("schema_version", Value::from(1)),
        ("source", Value::from(source.id.to_hex())),
        ("failure", failure),
        ("replacement", Value::from(row.id.to_hex())),
        ("replacement_admission", Value::from(admission.to_hex())),
        (
            "replacement_fork",
            Value::Binary(row.pre_action_fork_hash.to_vec()),
        ),
        (
            "replacement_commit",
            repo.commit_hash().map_or(Value::Nil, Value::from),
        ),
        ("session", Value::from(row.session.to_hex())),
        (
            "provenance_claim",
            Value::from(row.provenance_claim.to_hex()),
        ),
    ];
    if let Some(stamp) = &row.run {
        fields.push(("replacement_work", Value::from(stamp.work.to_hex())));
    }
    let body = receipt_body(PROPOSAL_REPLACEMENT_PREDICATE, source.id, fields)?;
    put_receipt_once_in_txn(vault, txn, id, &body, row.created_at)
}

impl Vault {
    /// The replacement submitted for the failed proposal `source`, read and
    /// checked (FIX 4364); `None` while none is. Its status and receipts are
    /// the replacement's own, read separately.
    ///
    /// # Errors
    /// A stored link that binds another source, or a store failure.
    pub(crate) fn repo_proposal_replacement(
        &self,
        source: EntityId,
    ) -> Result<Option<RepoProposalReplacement>> {
        let txn = self.store.env.read_txn()?;
        let receipt = replacement_receipt_id(source)?;
        let Some(body) = stored_receipt_in_txn(self, &txn, &receipt)? else {
            return Ok(None);
        };
        let differs = || Error::CorruptedIndex("proposal replacement receipt binding differs");
        if body.predicate != PROPOSAL_REPLACEMENT_PREDICATE
            || body.subject != ClaimSubject::Entity(source)
            || receipt_field(&body.value, "source").and_then(Value::as_str)
                != Some(source.to_hex().as_str())
        {
            return Err(differs());
        }
        let replacement = receipt_field(&body.value, "replacement")
            .and_then(Value::as_str)
            .ok_or_else(differs)
            .and_then(EntityId::from_hex)?;
        let replacement_fork = receipt_field(&body.value, "replacement_fork")
            .and_then(Value::as_slice)
            .and_then(|fork| RepoForkHash::try_from(fork).ok())
            .ok_or_else(differs)?;
        Ok(Some(RepoProposalReplacement {
            receipt,
            source,
            replacement,
            replacement_fork,
        }))
    }
}
