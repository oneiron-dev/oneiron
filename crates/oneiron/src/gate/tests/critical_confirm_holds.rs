//! What keeps a critical claim held until its owner answers, and what lets it go.

use super::*;

fn clear(vault: &crate::Vault, pending: &PendingGateConsentRecord, seed: u8) -> Result<()> {
    settle(
        vault,
        pending,
        seed,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        CriticalWriteConfirmResolution::Cleared,
        None,
    )
    .map(drop)
}

/// The owner's answer to `pending`, logged after `prev`, the owner's earlier
/// answer in this vault, or after a fresh genesis.
fn settle(
    vault: &crate::Vault,
    pending: &PendingGateConsentRecord,
    seed: u8,
    disposition: crate::authority::CriticalWriteConfirmDisposition,
    resolution: CriticalWriteConfirmResolution,
    prev: Option<&crate::authority::AuthorityLogEntry>,
) -> Result<crate::authority::AuthorityLogEntry> {
    use ed25519_dalek::{Signer, SigningKey};
    let binding = critical_write_confirm_binding(pending)?;
    let (genesis, mut entry) = critical_confirm_owner_entry(pending, disposition, seed);
    match prev {
        None => vault.put_authority_log_entries(&[
            (genesis, test_time(1), 1),
            (entry.clone(), test_time(2), 2),
        ])?,
        Some(prev) => {
            entry.seq = prev.seq + 1;
            entry.parent_hashes =
                vec![crate::authority::authority_entry_hash(prev).expect("entry hash")];
            entry.ts = prev.ts + 1;
            let transcript =
                crate::authority::authority_transcript(&entry).expect("authority transcript");
            entry.signer.signature = SigningKey::from_bytes(&[seed; 32])
                .sign(&transcript)
                .to_bytes()
                .to_vec();
            vault.put_authority_log_entries(&[(entry.clone(), test_time(entry.ts), entry.ts)])?;
        }
    }
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        resolution
    );
    Ok(entry)
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
    /// A demotion parks a critical confirm of its own over the unanswered
    /// assertion, and the owner declines the demotion: an answer to the
    /// demotion, not to the assertion.
    DeclinedDemotion,
}

#[test]
fn a_door_without_the_owners_answer_leaves_the_claim_held() -> Result<()> {
    for (n, door) in [
        UnansweredDoor::ProposedRewrite,
        UnansweredDoor::LetGo,
        UnansweredDoor::DeclinedDemotion,
    ]
    .into_iter()
    .enumerate()
    {
        let (_tmp, vault) = temp_vault();
        let claim = test_id(0x95);
        let seed = 0x90 + u8::try_from(n).expect("row");
        put_critical_auto_claim(&vault, claim)?;
        let mut answered = None;
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
            UnansweredDoor::DeclinedDemotion => {
                let parked = vault.apply_claim_demotion(
                    &claim,
                    crate::claim::ClaimDemotionAction::MarkStale,
                    crate::unix_seconds_now(),
                );
                assert!(
                    matches!(parked, Err(Error::Gate(_))),
                    "{door:?}: not parked"
                );
                let demotion = vault
                    .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
                    .expect("the demotion's confirm");
                answered = Some(settle(
                    &vault,
                    &demotion,
                    seed,
                    crate::authority::CriticalWriteConfirmDisposition::Decline,
                    CriticalWriteConfirmResolution::AlreadySettled,
                    None,
                )?);
                let body = stored_claim_body(&vault, &claim)?;
                assert_eq!(body.approval, ClaimApprovalStatus::Auto, "{door:?}");
                assert!(!body.stale, "{door:?}: the declined demotion landed");
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
        settle(
            &vault,
            &item,
            seed,
            crate::authority::CriticalWriteConfirmDisposition::Clear,
            CriticalWriteConfirmResolution::Cleared,
            answered.as_ref(),
        )?;
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

/// The doors that approve a held claim's item (Engine ruling Q5). Only an
/// owner-tier proof revalidated in the answering transaction is the owner's
/// answer; any other approval lands, and the owner is shown a fresh item.
#[derive(Clone, Copy, Debug)]
enum ApprovalDoor {
    /// The vault owner approves the Dreamer run's bundle that lists the claim.
    OwnerBundle,
    /// A person who is not the vault's owner approves that bundle.
    PersonBundle,
    /// The inbox approves the claim's review with no owner proof.
    Inbox,
}

/// An approval door runs the claim's VAD consolidation after its commit. A
/// claim still held refuses it, and the door reports that with the approval
/// already durable; the owner's answer leaves nothing held.
fn approval_landed(door: ApprovalDoor, result: Result<()>) -> Result<()> {
    match result {
        Err(Error::InvalidClaimBody("claim is not consolidatable"))
            if !matches!(door, ApprovalDoor::OwnerBundle) =>
        {
            Ok(())
        }
        other => other,
    }
}

#[test]
fn only_an_owner_tier_approval_answers_the_obligation() -> Result<()> {
    for door in [
        ApprovalDoor::OwnerBundle,
        ApprovalDoor::PersonBundle,
        ApprovalDoor::Inbox,
    ] {
        let (_tmp, vault) = temp_vault();
        let claim = test_id(0x97);
        put_critical_auto_claim(&vault, claim)?;
        put_policy_manifest_bytes(&vault, test_id(0xed), &encode_policy_manifest(vec![]))?;
        // A Dreamer pass proposes a revision: its review is the owner's item.
        let run = "owner-answer-run";
        let dreamer = test_id(0xef);
        let mut body = stored_claim_body(&vault, &claim)?;
        body.source = Some(ClaimSource::Generated);
        body.approval = ClaimApprovalStatus::Proposed;
        body.evidence = Some(said_evidence(&vault)?);
        let (candidate, envelope) =
            dreamer_claim_candidate_write_parts(&vault, &body, dreamer, run)?;
        vault
            .batch()
            .claim_candidate(&claim, candidate, &envelope, test_time(4), 4)
            .commit()?;
        let review = vault
            .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
            .expect("the Dreamer's review");
        assert_eq!(review.dreamer_run_id.as_deref(), Some(run), "{door:?}");

        match door {
            ApprovalDoor::OwnerBundle | ApprovalDoor::PersonBundle => {
                let reviewer = WriteActor::new(dreamer, EdgeActorClass::Agent);
                let bundle = vault.review_gate_consent_bundle(&reviewer, run)?;
                // A personal vault's owner is its embedded PERSON.
                let owner = match door {
                    ApprovalDoor::OwnerBundle => {
                        let id = crate::vault::embedded_owner_actor_id()?;
                        vault.authenticate_owner(
                            id,
                            &id.to_hex(),
                            true,
                            crate::store::GateDecisionId::now(),
                        )?
                    }
                    _ => consent_bundle_owner(&vault, test_id(0x60))?,
                };
                approval_landed(
                    door,
                    vault
                        .resolve_gate_consent_bundle(
                            &owner,
                            bundle.bundle_id,
                            run,
                            GateConsentBundleAction::Approve,
                            9,
                        )
                        .map(drop),
                )?;
            }
            ApprovalDoor::Inbox => {
                let current = stored_claim_body(&vault, &claim)?;
                approval_landed(
                    door,
                    vault
                        .approve_inbox_member_with_edit_at(
                            &claim,
                            &crate::claim::encode_claim_body(&current)?,
                            crate::unix_seconds_now(),
                        )
                        .map(drop),
                )?;
            }
        }
        assert_eq!(
            stored_claim_body(&vault, &claim)?.approval,
            ClaimApprovalStatus::Approved,
            "{door:?}: the approval did not land"
        );
        let open = vault
            .with_write_txn(|wtxn| vault.store.owner_answer_obligation_in_txn(wtxn, &claim))?
            .is_some();
        let eligible = vault.claim_consolidation_eligible(
            &claim,
            crate::gate::ConsolidationReader::VadAnnotation,
        )?;
        if matches!(door, ApprovalDoor::OwnerBundle) {
            assert!(
                !open,
                "{door:?}: the owner's approval left the obligation open"
            );
            assert!(
                eligible,
                "{door:?}: the owner's approval left the claim held"
            );
            continue;
        }
        assert!(
            open && !eligible,
            "FAILBEFORE H244 narrowed: {door:?} answered for the owner"
        );
        let item = vault
            .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
            .unwrap_or_else(|| panic!("{door:?}: the owner is shown no item"));
        let (diff_handle, _) = vault.with_write_txn(|wtxn| {
            crate::gate::claim_consent_binding_parts(
                &vault.store,
                wtxn,
                &stored_claim_body(&vault, &claim)?,
            )
        })?;
        assert_eq!(item.diff_handle, diff_handle, "{door:?}: a stale item");
    }
    Ok(())
}
