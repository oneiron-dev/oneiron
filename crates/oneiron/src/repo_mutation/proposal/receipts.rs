//! A proposal's receipts (FIX 4338, CODE-CUSTODY-03): its submission
//! admission and the completion of each execution attempt. Each is an
//! engine-owned reserved CLAIM, written in the writer that stores the fact
//! it records, under an id hashed from that fact in its own domain. A
//! proposal id is a proposed-diff claim and an oplog seq a log position:
//! neither is one of these receipts. A reader returns a receipt only after
//! it reads the stored CLAIM and checks what it binds.

use rmpv::Value;

use super::{RepoProposal, invalid, repo_mutation_repo_key_hash};
use crate::Vault;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::codebase::{RepoRef, entity_id_from_hash_material};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::repo_mutation_record::RepoMutationStatus;
use crate::write_envelope::identity_pair::map_field;

/// The predicate of a proposal's submission admission receipt.
pub(crate) const PROPOSAL_ADMISSION_PREDICATE: &str = "repo.proposal_admission";

/// The predicate of one execution attempt's completion receipt.
pub(crate) const PROPOSAL_ATTEMPT_PREDICATE: &str = "repo.proposal_attempt_completion";

const PROPOSAL_ADMISSION_DOMAIN: &[u8] = b"oneiron:repo-proposal-admission:v1";
const PROPOSAL_ATTEMPT_DOMAIN: &[u8] = b"oneiron:repo-proposal-attempt-completion:v1";

/// The id of `proposal`'s submission admission receipt.
fn admission_receipt_id(proposal: EntityId) -> Result<EntityId> {
    entity_id_from_hash_material(PROPOSAL_ADMISSION_DOMAIN, &[proposal.as_bytes()])
}

/// The id of the completion receipt of `proposal`'s attempt at `seq`.
fn attempt_receipt_id(proposal: EntityId, seq: u64) -> Result<EntityId> {
    entity_id_from_hash_material(
        PROPOSAL_ATTEMPT_DOMAIN,
        &[proposal.as_bytes(), &seq.to_be_bytes()],
    )
}

/// One field of a receipt's map value.
pub(crate) fn receipt_field<'v>(value: &'v Value, key: &str) -> Option<&'v Value> {
    map_field(value.as_map()?, key)
}

/// An engine-owned receipt body of `predicate` about `subject`, its value
/// the map of `fields`. It names no actor: a proposal's producer is bound
/// through its proposed-diff claim, whose erase already names no one.
///
/// # Errors
/// A body that does not validate.
pub(crate) fn receipt_body(
    predicate: &str,
    subject: EntityId,
    fields: Vec<(&str, Value)>,
) -> Result<ClaimBody> {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        Value::Map(
            fields
                .into_iter()
                .map(|(key, value)| (Value::from(key), value))
                .collect(),
        ),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::Observed);
    Ok(body)
}

/// The stored receipt CLAIM `id`, read raw in `txn`, or `None`.
///
/// # Errors
/// A row that is not a CLAIM, or a body that does not decode.
pub(crate) fn stored_receipt_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<ClaimBody>> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)? else {
        return Ok(None);
    };
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("receipt entity header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Err(Error::CorruptedIndex("a receipt id holds another record"));
    }
    let bytes = raw
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .ok_or(Error::CorruptedIndex("receipt entity header"))?;
    crate::claim::decode_claim_body(bytes, true).map(Some)
}

/// Writes receipt `id` once, in `txn`, at `at`. A retry finds the same
/// stored fact and writes nothing; another fact under `id` is a concurrent
/// write.
///
/// # Errors
/// Another fact under `id`, a subject that is not there, or a store failure.
pub(crate) fn put_receipt_once_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    body: &ClaimBody,
    at: u64,
) -> Result<()> {
    if let Some(stored) = stored_receipt_in_txn(vault, txn, &id)? {
        if stored.predicate != body.predicate
            || stored.subject != body.subject
            || stored.value != body.value
        {
            return Err(Error::ConcurrentWrite(
                "a receipt id already holds another fact",
            ));
        }
        return Ok(());
    }
    // A receipt's subject is a claim, a session or a queue row, none of which
    // has a FACET of its own.
    let mut body = body.clone();
    body.scope_facet = vault.claim_put_facet_in_txn(txn, &id)?;
    vault.put_reserved_claim_in_txn(
        txn,
        &id,
        &body,
        crate::temporal::TimeRange { start: at, end: at },
        at,
    )
}

/// Records `row`'s submission admission in its writer `txn` (FIX 4338):
/// the proposal, its repository key and pinned commit, session and
/// provenance, the operation and content hashes its proposed-diff claim
/// `diff` binds, its retained base and, for a run's proposal, the work,
/// TASK and declaration it was made under. No host path is kept. It admits
/// the candidate into custody, never into the queue or the head. Returns
/// the receipt's id.
///
/// # Errors
/// A proposed-diff claim without its hashes, another fact under the id, or
/// a store failure.
pub(super) fn record_admission_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &RepoProposal,
    diff: &ClaimBody,
) -> Result<EntityId> {
    let hash = |key: &str| {
        receipt_field(&diff.value, key)
            .cloned()
            .ok_or_else(|| invalid("a proposed diff claim binds its hashes"))
    };
    let repo = RepoRef::parse(&row.repo)?;
    let mut fields = vec![
        ("schema_version", Value::from(1)),
        ("proposal", Value::from(row.id.to_hex())),
        (
            "repo_key_hash",
            Value::from(repo_mutation_repo_key_hash(&repo)),
        ),
        (
            "base_commit",
            repo.commit_hash().map_or(Value::Nil, Value::from),
        ),
        ("session", Value::from(row.session.to_hex())),
        (
            "provenance_claim",
            Value::from(row.provenance_claim.to_hex()),
        ),
        ("operation_hash", hash("operation_hash")?),
        ("content_hash", hash("content_hash")?),
        (
            "pre_action_fork_hash",
            Value::Binary(row.pre_action_fork_hash.to_vec()),
        ),
        ("admitted_at", Value::from(row.created_at)),
    ];
    if let Some(stamp) = &row.run {
        fields.push((
            "run",
            Value::Map(vec![
                ("work".into(), stamp.work.to_hex().into()),
                ("task".into(), stamp.task.to_hex().into()),
                ("executor_run".into(), stamp.executor_run.to_hex().into()),
                (
                    "declaration".into(),
                    stamp
                        .symbol_fence
                        .map_or(Value::Nil, |declaration| declaration.to_hex().into()),
                ),
            ]),
        ));
    }
    if let Some(source) = row.repair_of {
        fields.push(("repair_of", Value::from(source.to_hex())));
    }
    let id = admission_receipt_id(row.id)?;
    let body = receipt_body(PROPOSAL_ADMISSION_PREDICATE, row.id, fields)?;
    put_receipt_once_in_txn(vault, txn, id, &body, row.created_at)?;
    Ok(id)
}

/// `row`'s submission admission receipt, read in `txn` and checked against
/// the row (FIX 4338); `None` while none is stored.
///
/// # Errors
/// A stored receipt that binds another proposal or base, or a store failure.
pub(crate) fn proposal_admission_receipt_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &RepoProposal,
) -> Result<Option<EntityId>> {
    let id = admission_receipt_id(row.id)?;
    let Some(body) = stored_receipt_in_txn(vault, txn, &id)? else {
        return Ok(None);
    };
    if body.predicate != PROPOSAL_ADMISSION_PREDICATE
        || body.subject != ClaimSubject::Entity(row.id)
        || receipt_field(&body.value, "proposal").and_then(Value::as_str)
            != Some(row.id.to_hex().as_str())
        || receipt_field(&body.value, "pre_action_fork_hash").and_then(Value::as_slice)
            != Some(row.pre_action_fork_hash.as_slice())
    {
        return Err(Error::CorruptedIndex(
            "proposal admission receipt binding differs",
        ));
    }
    Ok(Some(id))
}

/// Records the completion of `row`'s execution attempt at `seq` of `repo`
/// in the oplog's final writer `txn` (FIX 4338): applied or failed for that
/// attempt alone, never queue green. A retried stack member's later attempt
/// takes a fresh seq and its own receipt, so every attempt stays history.
/// A prepared operation completes nothing.
///
/// # Errors
/// Another fact under the id, or a store failure.
pub(in crate::repo_mutation) fn record_attempt_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &RepoProposal,
    repo: &RepoRef,
    seq: u64,
    status: RepoMutationStatus,
) -> Result<()> {
    let outcome = match status {
        RepoMutationStatus::Applied => "applied",
        RepoMutationStatus::Failed => "failed",
        RepoMutationStatus::Prepared => return Ok(()),
    };
    let mut fields = vec![
        ("schema_version", Value::from(1)),
        ("proposal", Value::from(row.id.to_hex())),
        (
            "repo_key_hash",
            Value::from(repo_mutation_repo_key_hash(repo)),
        ),
        ("seq", Value::from(seq)),
        ("outcome", Value::from(outcome)),
    ];
    if let Some(batch) = &row.merge_stack {
        fields.push(("merge_stack", Value::from(batch.as_str())));
    }
    let body = receipt_body(PROPOSAL_ATTEMPT_PREDICATE, row.id, fields)?;
    put_receipt_once_in_txn(
        vault,
        txn,
        attempt_receipt_id(row.id, seq)?,
        &body,
        vault.now_recorded_at(),
    )
}

/// Whether `body` is the completion receipt of `proposal`'s attempt at
/// `seq` stored under `id`.
fn names_attempt(body: &ClaimBody, id: EntityId, proposal: EntityId, seq: u64) -> Result<bool> {
    Ok(body.predicate == PROPOSAL_ATTEMPT_PREDICATE
        && body.subject == ClaimSubject::Entity(proposal)
        && receipt_field(&body.value, "proposal").and_then(Value::as_str)
            == Some(proposal.to_hex().as_str())
        && receipt_field(&body.value, "seq").and_then(Value::as_u64) == Some(seq)
        && id == attempt_receipt_id(proposal, seq)?)
}

/// The completion receipt of `proposal`'s attempt at `seq`, read in `txn`,
/// when it is stored and records a failure (FIX 4364).
///
/// # Errors
/// A stored receipt that binds another attempt, or a store failure.
pub(super) fn failed_attempt_receipt_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    proposal: EntityId,
    seq: u64,
) -> Result<Option<EntityId>> {
    let id = attempt_receipt_id(proposal, seq)?;
    let Some(body) = stored_receipt_in_txn(vault, txn, &id)? else {
        return Ok(None);
    };
    if !names_attempt(&body, id, proposal, seq)? {
        return Err(Error::CorruptedIndex(
            "proposal attempt receipt binding differs",
        ));
    }
    Ok(
        (receipt_field(&body.value, "outcome").and_then(Value::as_str) == Some("failed"))
            .then_some(id),
    )
}

impl Vault {
    /// `row`'s submission admission receipt, read and checked (FIX 4338);
    /// `None` while none is stored.
    ///
    /// # Errors
    /// A stored receipt that binds another proposal, or a store failure.
    pub(crate) fn repo_proposal_admission_receipt(
        &self,
        row: &RepoProposal,
    ) -> Result<Option<EntityId>> {
        let txn = self.store.env.read_txn()?;
        proposal_admission_receipt_in_txn(self, &txn, row)
    }

    /// The completion receipts of `proposal`'s execution attempts, in seq
    /// order, each read and checked (FIX 4338). Empty before its first
    /// attempt completes. Each names one attempt, never queue green.
    ///
    /// # Errors
    /// A stored receipt that binds another attempt, or a store failure.
    pub(crate) fn repo_proposal_attempt_receipts(
        &self,
        proposal: EntityId,
    ) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        let mut attempts = Vec::new();
        for (id, body) in crate::ports::ClaimStore::port_claim_predicate_history(
            self,
            &txn,
            &proposal,
            PROPOSAL_ATTEMPT_PREDICATE,
        )? {
            let seq = receipt_field(&body.value, "seq")
                .and_then(Value::as_u64)
                .ok_or(Error::CorruptedIndex("proposal attempt receipt has no seq"))?;
            if !names_attempt(&body, id, proposal, seq)? {
                return Err(Error::CorruptedIndex(
                    "proposal attempt receipt binding differs",
                ));
            }
            attempts.push((seq, id));
        }
        attempts.sort_unstable();
        Ok(attempts.into_iter().map(|(_, id)| id).collect())
    }
}
