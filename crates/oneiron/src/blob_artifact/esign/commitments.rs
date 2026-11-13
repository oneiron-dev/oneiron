//! The commitments a signing document names (ARCH-0064 §3, the OF-187 wire).
//!
//! A draft that names obligations mints each as an INERT commitment in the
//! draft's own transaction, at [`esign_document_commitment_id`] of its index.
//! `esign.completed` opens each inert one, in the completion's transaction,
//! with the completion and the sealed bytes as evidence; a decline, void or
//! expiry releases it. An inert promise binds nobody: it never wakes,
//! reminds, lapses or projects until the document opens it.
//!
//! Every row here is written by the engine's own envelope
//! ([`commitment_envelope`]), the lapse sweep's: the draft's audit trail names
//! who drafted, the birth provenance names the document, and the signers'
//! own acts open it.

use super::model::{EsignCommitmentTerm, EsignDocument, EsignEvent, EsignEventRow, invalid};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::commitment::{
    CommitmentBirthKind, CommitmentBirthProvenance, CommitmentContent, CommitmentInstanceState,
    CommitmentObligor, CommitmentObligorKind, CommitmentRecord, CommitmentStatus,
    CommitmentStrength,
};
use crate::commitment_schedule::{CommitmentSchedulePayload, Schedule};
use crate::edge::EdgeActorClass;
use crate::entity_id::bytes_to_hex_lower;
use crate::entity_id::derived_domains::ESIGN_DOCUMENT_COMMITMENT;
use crate::memory::commitment_doors::CommitmentObligorKind as WireObligorKind;
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};
use crate::{EntityId, Result, TimeRange, Vault};
use rmpv::Value;

/// The provenance of every commitment row the e-sign organ writes.
pub const ESIGN_COMMITMENT_PROVENANCE: &str = "oneiron.esign.commitment.v1";

/// The id of the commitment born from term `index` of `document`'s draft.
/// # Errors
/// A derived id that lands on a reserved one.
pub fn esign_document_commitment_id(document: &EntityId, index: u32) -> Result<EntityId> {
    EntityId::derive(
        ESIGN_DOCUMENT_COMMITMENT,
        &[document.as_bytes(), &index.to_be_bytes()],
    )
}

/// Refuses an event that would leave a document's inert commitments behind
/// before anything is written: a redraft of a draft that names commitments,
/// or one that names them over an earlier draft. Its terms were minted with
/// the first draft, at ids its indices own.
pub(super) fn admit(prior: &[EsignEventRow], event: &EsignEvent) -> Result<()> {
    let EsignEvent::Drafted { document: redraft } = event else {
        return Ok(());
    };
    let named_before = prior.iter().any(|row| {
        matches!(&row.event, EsignEvent::Drafted { document } if !document.commitments.is_empty())
    });
    if !prior.is_empty() && (named_before || !redraft.commitments.is_empty()) {
        return Err(invalid("a draft that names commitments is not redrafted"));
    }
    Ok(())
}

/// What `event`, just appended to `document`'s chain as the claim
/// `event_claim`, does to the commitments the draft names, in the event's own
/// transaction. A first draft mints each term inert; `esign.completed` opens
/// each inert one; a decline, void or expiry releases it. A commitment no
/// longer inert (retracted, or settled already) is left as it stands.
pub(super) fn apply_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    document: EntityId,
    draft: &EsignDocument,
    event: &EsignEvent,
    event_claim: EntityId,
    now: u64,
) -> Result<()> {
    if draft.commitments.is_empty() {
        return Ok(());
    }
    let next = match event {
        EsignEvent::Drafted { .. } => return mint_in(vault, txn, document, draft, now),
        EsignEvent::Sealed {
            rejected: false, ..
        } => CommitmentStatus::Open,
        EsignEvent::Declined { .. } | EsignEvent::Voided { .. } | EsignEvent::Expired { .. } => {
            CommitmentStatus::Released
        }
        _ => return Ok(()),
    };
    let evidence = evidence(document, draft, event, event_claim);
    let envelope = commitment_envelope()?;
    for index in 0..draft.commitments.len() {
        let id = esign_document_commitment_id(&document, term_index(index)?)?;
        if !matches!(
            vault.commitment_instance_state_in_txn(txn, &id)?,
            CommitmentInstanceState::Inert(_)
        ) {
            continue;
        }
        let head = vault.commitment_head_in_txn(txn, &id)?;
        vault.update_commitment_status_in_txn(
            txn,
            &head,
            next,
            &envelope,
            now,
            Some(evidence.clone()),
        )?;
        if next == CommitmentStatus::Open {
            // The promise is owed from now: its series enters the due index
            // through the same hook a promise landed open takes.
            let opened = vault.commitment_head_in_txn(txn, &id)?;
            vault.index_landed_commitment_series_in_txn(txn, &opened, now)?;
        }
    }
    Ok(())
}

/// Mints each term of `draft` inert, bound to `document` by its birth
/// provenance and its derived id.
fn mint_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    document: EntityId,
    draft: &EsignDocument,
    now: u64,
) -> Result<()> {
    let envelope = commitment_envelope()?;
    for (index, term) in draft.commitments.iter().enumerate() {
        let id = esign_document_commitment_id(&document, term_index(index)?)?;
        vault.put_inert_commitment_in_txn(
            txn,
            &id,
            &term_record(term, document)?,
            &envelope,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
    }
    Ok(())
}

/// The inert commitment record `term` names.
fn term_record(term: &EsignCommitmentTerm, document: EntityId) -> Result<CommitmentRecord> {
    let kind = match term.obligor.kind {
        WireObligorKind::Owner => CommitmentObligorKind::Owner,
        WireObligorKind::Agent => CommitmentObligorKind::Agent,
        WireObligorKind::ThirdParty => CommitmentObligorKind::ThirdParty,
    };
    let schedule: Schedule = serde_json::to_value(&term.schedule)
        .and_then(serde_json::from_value)
        .map_err(|_| invalid("invalid commitment schedule"))?;
    let schedule = CommitmentSchedulePayload::series(schedule, term.lead_seconds)
        .encode()
        .map_err(|_| invalid("invalid commitment schedule"))?;
    CommitmentRecord::new(
        CommitmentObligor::new(kind, EntityId::from_hex(&term.obligor.entity_ref)?),
        EntityId::from_hex(&term.beneficiary)?,
        CommitmentContent::new(&term.content.text, term.content.payload_ref.clone())?,
        schedule,
        CommitmentStrength::Commitment,
        CommitmentStatus::Inert,
        CommitmentBirthProvenance::new(CommitmentBirthKind::EsignDocument, document.to_hex())?,
    )
}

/// The evidence a status change carries: the event, the document and the
/// event's claim; for `esign.completed`, each item's original version and
/// the sha256 of its sealed bytes too.
fn evidence(
    document: EntityId,
    draft: &EsignDocument,
    event: &EsignEvent,
    event_claim: EntityId,
) -> Value {
    let mut fields = vec![
        (Value::from("event"), Value::from(event.predicate())),
        (Value::from("document"), Value::from(document.to_hex())),
        (Value::from("claim"), Value::from(event_claim.to_hex())),
    ];
    if let EsignEvent::Sealed { item_sha256, .. } = event {
        let items = draft
            .items
            .iter()
            .zip(item_sha256)
            .map(|(item, sealed)| {
                Value::Map(vec![
                    (
                        Value::from("artifact_ref"),
                        Value::from(item.artifact_ref.clone()),
                    ),
                    (
                        Value::from("original_version"),
                        Value::from(item.original_version),
                    ),
                    (
                        Value::from("sealed_sha256"),
                        Value::from(bytes_to_hex_lower(sealed)),
                    ),
                ])
            })
            .collect();
        fields.push((Value::from("items"), Value::Array(items)));
    }
    Value::Map(vec![(Value::from("esign"), Value::Map(fields))])
}

/// The engine envelope every e-sign commitment row is written under: the
/// lapse sweep's (housekeeping), with its own provenance.
fn commitment_envelope() -> Result<WriteEnvelope> {
    Ok(WriteEnvelope::new(
        WriteActor::new(
            crate::vault::embedded_owner_actor_id()?,
            EdgeActorClass::Human,
        ),
        ClaimSource::Observed,
        WriteProvenance::new(Value::from(ESIGN_COMMITMENT_PROVENANCE))?,
        ClaimApprovalStatus::Auto,
    ))
}

fn term_index(index: usize) -> Result<u32> {
    u32::try_from(index).map_err(|_| invalid("too many commitments"))
}
