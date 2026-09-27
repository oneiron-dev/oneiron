//! The shared Generated/Proposed writer for deterministic maintenance findings.
use crate::attempt_queue::AttemptId;
use crate::{ClaimCandidate, ClaimSubject, EntityId, Result, TimeRange, Vault};
use rmpv::Value;
pub(super) fn emit(
    vault: &Vault,
    attempt: AttemptId,
    facet: &str,
    subject: EntityId,
    predicate: &str,
    value: &serde_json::Value,
    now: u64,
) -> Result<EntityId> {
    let envelope = vault.dreamer_proposal_envelope(facet, attempt)?;
    vault.with_write_txn(|txn| emit_in_txn(vault, txn, subject, predicate, value, &envelope, now))
}

pub(super) fn emit_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    subject: EntityId,
    predicate: &str,
    value: &serde_json::Value,
    envelope: &crate::WriteEnvelope,
    now: u64,
) -> Result<EntityId> {
    let bytes = serde_json::to_vec(value).map_err(|_| super::invalid())?;
    let id = crate::codebase::entity_id_from_hash_material(
        b"oneiron:dreamer-maintenance-proposal:v1",
        &[subject.as_bytes(), predicate.as_bytes(), &bytes],
    )?;
    if let Some(raw) = vault.store.entities.get(&*txn, id.as_bytes())? {
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
    );
    vault
        .batch_in()
        .claim_candidate(
            &id,
            candidate,
            envelope,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .apply(txn)?;
    Ok(id)
}
