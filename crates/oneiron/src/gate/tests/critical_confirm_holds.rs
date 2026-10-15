//! What keeps a critical claim held until its owner answers, and what lets it go.

use super::*;

fn clear(vault: &crate::Vault, pending: &PendingGateConsentRecord, seed: u8) -> Result<()> {
    let binding = critical_write_confirm_binding(pending)?;
    let (genesis, clear) = critical_confirm_owner_entry(
        pending,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        seed,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (clear, test_time(2), 2)])?;
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::Cleared
    );
    Ok(())
}

/// A later revision's ordinary review is not the owner's answer to the
/// critical confirm it replaces: the claim stays held until that review
/// settles, and the Dreamer wake count skips it meanwhile.
#[test]
fn a_proposed_rewrite_carries_the_critical_confirm_it_replaces() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x95);
    put_critical_auto_claim(&vault, claim)?;
    let mut body = stored_claim_body(&vault, &claim)?;
    body.approval = ClaimApprovalStatus::Proposed;
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time(4), 4)
        .commit()?;
    assert_eq!(
        stored_claim_body(&vault, &claim)?.approval,
        ClaimApprovalStatus::Proposed
    );
    let review = vault
        .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
        .expect("the rewrite's review");
    assert!(
        review
            .reason_codes
            .iter()
            .any(|reason| reason == crate::gate::GATE_REASON_PENDING_CRITICAL_CONFIRM_CARRIED)
    );
    assert!(
        !vault
            .wake_pending_records_for_test()?
            .contains(&claim.to_hex()),
        "FAILBEFORE H244 narrowed: a Proposed rewrite read as the owner's Clear"
    );

    // The review settling is what lets the claim go.
    vault.with_write_txn(|wtxn| vault.store.delete_pending_gate_consent_in_txn(wtxn, &claim))?;
    assert!(
        vault
            .wake_pending_records_for_test()?
            .contains(&claim.to_hex())
    );
    Ok(())
}

/// A wake pass that met a held claim moved its cursor past it. The owner's
/// Clear rewrites no bytes, yet the claim rejoins the wake count.
#[test]
fn a_cleared_claim_rejoins_the_wake_count_that_skipped_it() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x96);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let idle = crate::dreamer_wake::WakeIdleState {
        running_turns: false,
        live_background_work: false,
        compute_available: true,
        last_inbound_at: 0,
    };
    vault.enqueue_due_dreamer_wake(idle, crate::unix_seconds_now())?;
    assert!(
        !vault
            .wake_pending_records_for_test()?
            .contains(&claim.to_hex())
    );

    clear(&vault, &pending, 0x96)?;
    assert!(
        vault
            .wake_pending_records_for_test()?
            .contains(&claim.to_hex()),
        "FAILBEFORE H244 narrowed: a cleared claim never rejoined the wake count"
    );
    Ok(())
}
