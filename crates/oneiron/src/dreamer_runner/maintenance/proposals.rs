//! The shared Generated/Proposed writer for deterministic maintenance findings.
//! Each finding lands in the owner's run tray (`/v1/owner/runs`) under the
//! attempt that wrote it, so one review approves or declines a night's batch.
//! Every finding cites the records it was read from: GATE-12 refuses a
//! Dreamer claim with no live evidence ref.
use crate::attempt_queue::AttemptId;
use crate::provenance::birth::{MAX_BIRTH_INPUTS, RowBirth};
use crate::provenance::made_by::MadeByClass;
use crate::write_envelope::{WriteEnvelope, WriteProvenance};
use crate::{ClaimCandidate, ClaimSubject, EntityId, Result, TimeRange, Vault};
use rmpv::Value;

/// The facet's shared proposal envelope plus the Gate's run-tray keys
/// (`runner=dreamer`, `run=<attempt>`), the same keys a representation
/// proposal carries. The authority stamp is unchanged.
pub(super) fn run_tray_envelope(
    vault: &Vault,
    facet: &str,
    attempt: AttemptId,
) -> Result<WriteEnvelope> {
    let shared = vault.dreamer_proposal_envelope(facet, attempt)?;
    let run = crate::entity_id::bytes_to_hex_lower(attempt.as_bytes());
    let mut provenance = shared
        .provenance()
        .value()
        .as_map()
        .ok_or_else(super::invalid)?
        .clone();
    if provenance
        .iter()
        .any(|(key, _)| matches!(key.as_str(), Some("runner" | "run")))
    {
        return Err(super::invalid());
    }
    provenance.push((Value::from("runner"), Value::from("dreamer")));
    provenance.push((Value::from("run"), Value::from(run)));
    Ok(WriteEnvelope::new(
        shared.actor(),
        shared.source(),
        WriteProvenance::new(Value::Map(provenance))?,
        shared.approval(),
    ))
}
#[expect(
    clippy::too_many_arguments,
    reason = "one finding's facet, subject, claim and evidence"
)]
pub(super) fn emit(
    vault: &Vault,
    attempt: AttemptId,
    facet: &str,
    subject: EntityId,
    predicate: &str,
    value: &serde_json::Value,
    evidence: &[EntityId],
    now: u64,
) -> Result<EntityId> {
    let envelope = run_tray_envelope(vault, facet, attempt)?;
    vault.with_write_txn_grouped(|txn| {
        emit_in_txn(
            vault, txn, subject, predicate, value, evidence, &envelope, now,
        )
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "one finding's subject, claim, evidence and write envelope"
)]
pub(super) fn emit_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    subject: EntityId,
    predicate: &str,
    value: &serde_json::Value,
    evidence: &[EntityId],
    envelope: &crate::WriteEnvelope,
    now: u64,
) -> Result<EntityId> {
    let bytes = serde_json::to_vec(value).map_err(|_| super::invalid())?;
    let id = crate::codebase::entity_id_from_hash_material(
        b"oneiron:dreamer-maintenance-proposal:v1",
        &[subject.as_bytes(), predicate.as_bytes(), &bytes],
    )?;
    if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &*txn, &id)? {
        let header = crate::batch::EntityMetadataHeader::parse(&raw).ok_or_else(super::invalid)?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Err(super::invalid());
        }
        let body = crate::claim::decode_claim_body(
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            true,
        )?;
        if body.subject != ClaimSubject::Entity(subject)
            || body.predicate != predicate
            || body.value.as_str() != std::str::from_utf8(&bytes).ok()
            || body.source != Some(crate::ClaimSource::Generated)
            || crate::claim::session_claim_producer(&body) != Some(envelope.actor().entity_ref())
        {
            return Err(super::invalid());
        }
        return Ok(id);
    }
    let candidate = ClaimCandidate::new(
        predicate,
        ClaimSubject::Entity(subject),
        Value::from(String::from_utf8(bytes).map_err(|_| super::invalid())?),
        1.0,
    )
    .with_evidence(crate::dreamer_consolidation::encode_consolidation_evidence(
        &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
            refs: evidence.to_vec(),
            chain: Vec::new(),
            source_meet: crate::ClaimSource::Generated,
        },
    ));
    let mut envelope = envelope.clone();
    vault.sign_retained_machine_claim_in_txn(&*txn, &id, &candidate, &mut envelope)?;
    // Rule A: the finding is concluded from the records it cites, the first
    // MAX_BIRTH_INPUTS of them.
    let birth = RowBirth::written(
        envelope.actor(),
        MadeByClass::Concluded,
        "dreamer.finding",
        &evidence[..evidence.len().min(MAX_BIRTH_INPUTS)],
        &[],
        now,
    );
    vault
        .batch_in()
        .claim_candidate(
            &id,
            candidate,
            &envelope,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .made_by(&id, birth)
        .apply_recording_gate_decisions(txn)?;
    vault.record_finding_notification_in_txn(txn, id, subject, now)?;
    Ok(id)
}
