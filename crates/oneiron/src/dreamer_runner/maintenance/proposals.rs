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
    let bytes = serde_json::to_vec(value).map_err(|_| super::invalid())?;
    let id = crate::codebase::entity_id_from_hash_material(
        b"oneiron:dreamer-maintenance-proposal:v1",
        &[
            facet.as_bytes(),
            subject.as_bytes(),
            predicate.as_bytes(),
            &bytes,
        ],
    )?;
    let envelope = vault.dreamer_proposal_envelope(facet, attempt)?;
    if let Some(body) = vault.get_claim(&id)? {
        if body.subject != ClaimSubject::Entity(subject)
            || body.predicate != predicate
            || body.value.as_str() != std::str::from_utf8(&bytes).ok()
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
        .batch()
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
        .commit()?;
    Ok(id)
}
