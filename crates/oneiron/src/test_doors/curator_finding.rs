//! Doors for `tests/conflict_settle_restriction.rs`.
//! - [`emit_retract_finding`] lands the Dreamer's curator finding that
//!   retracts a stored claim, as the curator lands a finding over a critical
//!   target (`maintenance::curator::run`, then `proposals::emit`): Active,
//!   Proposed, Generated, produced by the Dreamer and citing its target. The
//!   curator grades only the Dreamer's own aged consolidations, and its
//!   writers are private to it; the door lands the finding over any stored
//!   claim, so a test can settle it.
//! - [`land_stale_consolidation`] lands a claim as the Dreamer's own
//!   consolidation on its last curator rung, a target the curator grades.
//! - [`run_curator_once`] runs one curator pass, as the wake driver runs it.

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

/// Lands `predicate` about `subject` holding `value` as the Dreamer's own
/// consolidation on its last curator rung, learned at `learned_at`: a
/// signed Generated Auto write whose evidence cites `subject` and names the
/// Dreamer under the surface `dreamer`, and whose scope holds the `stale`
/// demotion rung. A curator pass past its minimum age grades it for a
/// retract. Returns its id.
///
/// # Errors
///
/// The vault's, and the write door's.
pub fn land_stale_consolidation(
    vault: &Vault,
    subject: EntityId,
    predicate: &str,
    value: Value,
    learned_at: u64,
) -> Result<EntityId> {
    let dreamer = vault.dreamer_authority()?;
    let id = EntityId::now();
    let candidate = ClaimCandidate::new(predicate, ClaimSubject::Entity(subject), value, 1.0)
        .with_scope(Value::Map(vec![(
            Value::from(crate::claim::CLAIM_SCOPE_DEMOTION_RUNG_KEY),
            Value::from("stale"),
        )]))
        .with_evidence(crate::dreamer_consolidation::encode_consolidation_evidence(
            &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
                refs: vec![subject],
                chain: Vec::new(),
                source_meet: ClaimSource::Generated,
            },
        ));
    vault.with_write_txn_grouped(|txn| {
        let mut envelope = WriteEnvelope::new(
            dreamer,
            ClaimSource::Generated,
            WriteProvenance::new(Value::Map(vec![(
                Value::from("surface"),
                Value::from("dreamer"),
            )]))?,
            ClaimApprovalStatus::Auto,
        );
        vault.sign_retained_machine_claim_in_txn(&*txn, &id, &candidate, &mut envelope)?;
        vault
            .batch_in()
            .claim_candidate(
                &id,
                candidate,
                &envelope,
                TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
            )
            .apply_recording_gate_decisions(txn)
    })?;
    Ok(id)
}

/// Runs one curator pass at `now` (Unix seconds), as the wake driver runs
/// it: a maintenance attempt for the curator facet, admitted on the
/// maintenance lane and graded under the Dreamer's authority stamp. Answers
/// the findings the pass landed, held for a person or applied.
///
/// # Errors
///
/// The vault's, the pass's own, or an attempt that is not admitted.
pub fn run_curator_once(vault: &Vault, now: u64) -> Result<Vec<EntityId>> {
    use crate::dreamer_runner::maintenance::{CURATOR_FACET, MAINTENANCE_QUEUE_KIND, run_curator};
    use crate::dreamer_runner::{
        AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerAttemptPayload, DreamerRunnerStore,
    };

    let store = DreamerRunnerStore::new(vault);
    vault.with_write_txn(|txn| {
        store
            .enqueue_kind_in_txn(
                txn,
                MAINTENANCE_QUEUE_KIND,
                DreamerAttemptPayload {
                    attempt_type: CURATOR_FACET.to_owned(),
                    input: Value::from("nightly"),
                    parent_attempt: None,
                },
                Some(format!("test.curator_pass:{now}")),
                None,
                now,
            )
            .map(|_| ())
    })?;
    let DreamerAdmissionOutcome::Admitted(admitted) =
        store.admit_next_maintenance(AdmitDreamerAttempt {
            lease_owner: "test-door".to_owned(),
            now,
            budget_id: "wake".to_owned(),
            budget_total_units: 10_000,
            reserve_units: 100,
            started_milestone: None,
        })?
    else {
        return Err(Error::InvalidConfig(
            "the curator attempt was not admitted".into(),
        ));
    };
    run_curator(vault, &admitted, now)
}
