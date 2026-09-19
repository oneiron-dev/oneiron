//! W7-C01: rate and failure streak are soft checker inputs, never a durable trip.
use super::*;
fn run_write(
    vault: &crate::Vault,
    claim_id: EntityId,
    actor: EntityId,
    subject_seed: u8,
    run_id: &str,
    approval: ClaimApprovalStatus,
    learned_at: u64,
) -> Result<()> {
    let mut body = public_stamped(source_trust_claim(ClaimSource::Generated));
    body.subject = ClaimSubject::Entity(test_id(subject_seed));
    body.approval = approval;
    body.evidence = Some(precommit_evidence(vec![test_id(subject_seed)]));
    let (candidate, envelope) = dreamer_claim_candidate_write_parts(vault, &body, actor, run_id)?;
    vault
        .batch()
        .claim_candidate(
            &claim_id,
            candidate,
            &envelope,
            test_time(learned_at),
            learned_at,
        )
        .commit()
}

#[test]
fn thirty_first_in_window_write_keeps_auto_and_has_no_trip_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x40);
    let mut data = encode_policy_manifest(vec![
        source_trust_entry(ClaimSource::Generated, 0),
        signatures_entry(),
    ]);
    append_actor_ceiling(
        &mut data,
        actor_ceiling_row_for_ref("agent", &actor.to_hex(), "auto"),
    );
    put_policy_manifest_bytes(&vault, test_id(0x70), &data)?;
    for index in 0..31 {
        let claim = crate::EntityId::now();
        run_write(
            &vault,
            claim,
            actor,
            0x50,
            "untripped-run",
            ClaimApprovalStatus::Auto,
            index,
        )?;
        assert_eq!(
            stored_claim_body(&vault, &claim)?.approval,
            ClaimApprovalStatus::Auto
        );
        assert!(!has_pending_gate_consent(&vault, &claim)?);
    }
    let receipts = vault.store.gate_decisions(256)?;
    assert_eq!(
        receipts
            .iter()
            .filter(|r| r.actor_ref.as_deref() == Some(&actor.to_hex()))
            .count(),
        31
    );
    assert!(
        receipts
            .iter()
            .all(|r| r.content_kind != "circuit_breaker" && r.outcome != "breaker_tripped")
    );
    Ok(())
}
