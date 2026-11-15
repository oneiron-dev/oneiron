//! Door for `tests/conflict_settle_restriction.rs`: lands the Dreamer's
//! curator finding that retracts a stored claim, as the curator lands a
//! finding over a critical target (`maintenance::curator::run`, then
//! `proposals::emit`): Active, Proposed, Generated, produced by the Dreamer
//! and citing its target. The curator grades only the Dreamer's own aged
//! consolidations, and its writers are private to it; the door lands the
//! finding over any stored claim, so a test can settle it.

use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::error::{Error, Result};
use crate::write_envelope::{WriteEnvelope, WriteProvenance};
use crate::{ClaimCandidate, ClaimSubject, EntityId, TimeRange, Vault};
use rmpv::Value;

/// Lands the Dreamer's Proposed finding that retracts `target`, graded on
/// the body `target` holds now (its `source_hash`). Returns its id.
///
/// # Errors
///
/// The vault's, and a `target` that is no stored row.
pub fn emit_retract_finding(vault: &Vault, target: EntityId) -> Result<EntityId> {
    let dreamer = vault.dreamer_authority()?;
    let id = EntityId::now();
    let now = vault.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &*txn, &target)?
            .ok_or(Error::EntityNotFound)?;
        let body = raw
            .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
            .filter(|body| !body.is_empty())
            .ok_or(Error::EntityNotFound)?;
        let value = serde_json::json!({
            "target": target.to_hex(),
            "source_hash": blake3::hash(body).to_hex().to_string(),
            "action": { "kind": "retract" },
        });
        let candidate = ClaimCandidate::new(
            crate::dreamer_runner::maintenance::CURATOR_PROPOSAL_PREDICATE,
            ClaimSubject::Entity(target),
            Value::from(value.to_string()),
            1.0,
        )
        .with_evidence(crate::dreamer_consolidation::encode_consolidation_evidence(
            &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
                refs: vec![target],
                chain: Vec::new(),
                source_meet: ClaimSource::Generated,
            },
        ));
        let mut envelope = WriteEnvelope::new(
            dreamer,
            ClaimSource::Generated,
            WriteProvenance::new(Value::Map(vec![(
                Value::from("surface"),
                Value::from("test.curator_finding"),
            )]))?,
            ClaimApprovalStatus::Proposed,
        );
        vault.sign_retained_machine_claim_in_txn(&*txn, &id, &candidate, &mut envelope)?;
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
            .apply_recording_gate_decisions(txn)
    })?;
    Ok(id)
}
