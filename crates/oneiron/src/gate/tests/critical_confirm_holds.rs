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

/// The doors that remove or outdate a held claim's item without its owner's
/// answer (F14 H244-narrowed, review round 5). Each leaves the owner-answer
/// obligation open, so the Dreamer wake count still skips the claim, and the
/// owner is shown an item for its current revision; the owner's Clear of that
/// item lets the claim go.
#[derive(Clone, Copy, Debug)]
enum UnansweredDoor {
    /// A later revision's ordinary review replaces the confirm.
    ProposedRewrite,
    /// The asker lets its pending ask go.
    LetGo,
}

#[test]
fn a_door_without_the_owners_answer_leaves_the_claim_held() -> Result<()> {
    for (n, door) in [UnansweredDoor::ProposedRewrite, UnansweredDoor::LetGo]
        .into_iter()
        .enumerate()
    {
        let (_tmp, vault) = temp_vault();
        let claim = test_id(0x95);
        put_critical_auto_claim(&vault, claim)?;
        match door {
            UnansweredDoor::ProposedRewrite => {
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
            }
            UnansweredDoor::LetGo => {
                assert!(vault.let_go_pending_ask(&claim)?.is_some(), "{door:?}");
            }
        }
        assert!(
            vault
                .with_write_txn(|wtxn| vault.store.owner_answer_obligation_in_txn(wtxn, &claim))?
                .is_some(),
            "FAILBEFORE H244 narrowed: {door:?} closed the obligation with no owner answer"
        );
        assert!(
            !vault
                .wake_pending_records_for_test()?
                .contains(&claim.to_hex()),
            "FAILBEFORE H244 narrowed: {door:?} let a held claim reach the wake count"
        );
        // The owner is shown an item for the claim's current revision.
        let item = vault
            .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
            .unwrap_or_else(|| panic!("FAILBEFORE H244 narrowed: {door:?} left the owner no item"));
        let current = stored_claim_body(&vault, &claim)?;
        let (diff_handle, _) = vault.with_write_txn(|wtxn| {
            crate::gate::claim_consent_binding_parts(&vault.store, wtxn, &current)
        })?;
        assert_eq!(
            item.diff_handle, diff_handle,
            "{door:?}: the item binds an earlier revision"
        );
        if critical_write_confirm_binding(&item).is_err() {
            // An ordinary review of this revision is the item: the owner's
            // Clear needs a confirm, so the review is let go first.
            vault.let_go_pending_ask(&claim)?;
        }
        let item = vault
            .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
            .expect("the owner's confirm item");
        assert!(
            vault
                .pending_critical_write_confirms(10)?
                .iter()
                .any(|binding| binding.claim_id == claim),
            "{door:?}: the owner's listing shows no confirm"
        );
        clear(&vault, &item, 0x90 + u8::try_from(n).expect("row"))?;
        assert!(
            vault
                .with_write_txn(|wtxn| vault.store.owner_answer_obligation_in_txn(wtxn, &claim))?
                .is_none(),
            "{door:?}: the owner's Clear left the obligation open"
        );
        assert!(
            vault
                .wake_pending_records_for_test()?
                .contains(&claim.to_hex()),
            "{door:?}: the owner's Clear did not let the claim go"
        );
    }
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
