//! Doors for `tests/digest_erase_scrubs_stored_copies.rs` (PROACTIVITY-DIGEST-COPY-ERASURE).

use crate::dreamer_runner::maintenance::digest::{
    claim_digests_indexed_for_test, forget_claim_digest_index_for_test,
};

/// Clears the digest memberships and backfill marker without changing the digest rows.
///
/// # Errors
/// Returns a transaction, scan, or delete error.
pub fn forget_claim_digest_index(vault: &crate::Vault) -> crate::Result<()> {
    vault.with_write_txn_grouped(|txn| forget_claim_digest_index_for_test(&vault.store, txn))
}

/// Reads whether the digest membership backfill is marked complete.
///
/// # Errors
/// Returns a transaction or marker read error.
pub fn claim_digests_indexed(vault: &crate::Vault) -> crate::Result<bool> {
    let txn = vault.store.env.read_txn()?;
    claim_digests_indexed_for_test(&vault.store, &txn)
}

/// Lands the Dreamer's Proposed CLAIM `predicate` about `subject` holding
/// `value` and citing `evidence`: Active, Proposed, Generated and signed by
/// the Dreamer, as `test_doors::curator_finding::land_stale_consolidation`
/// lands an Auto one, so the owner's next digest carries it. Unlike the
/// curator finding, its value may be a map, which a value-field redaction
/// reaches. Returns its id.
///
/// # Errors
/// The vault's, and the write door's.
pub fn land_dreamer_proposal(
    vault: &crate::Vault,
    subject: crate::EntityId,
    predicate: &str,
    value: rmpv::Value,
    evidence: crate::EntityId,
) -> crate::Result<crate::EntityId> {
    use crate::claim::{ClaimApprovalStatus, ClaimSource};
    use crate::write_envelope::{WriteEnvelope, WriteProvenance};
    use crate::{ClaimCandidate, ClaimSubject, EntityId, TimeRange};
    use rmpv::Value;

    let dreamer = vault.dreamer_authority()?;
    let id = EntityId::now();
    let now = vault.now_recorded_at();
    let candidate = ClaimCandidate::new(predicate, ClaimSubject::Entity(subject), value, 1.0)
        .with_evidence(crate::dreamer_consolidation::encode_consolidation_evidence(
            &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
                refs: vec![evidence],
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
                Value::from("test.dreamer_proposal"),
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
