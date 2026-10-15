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
        None => {
            vault.put_authority_log_entries(&[
                (genesis, test_time(1), 1),
                (entry.clone(), test_time(2), 2),
            ])?;
        }
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

/// A retraction closes a held claim even after the owner relaxed its
/// predicate's policy: the obligation stays open, and the owner is shown no
/// item for the closed claim.
#[test]
fn a_retraction_closes_a_held_claim_under_a_relaxed_policy() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x95);
    put_critical_auto_claim(&vault, claim)?;
    let mut data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::UserStated, 0)]);
    trust_human_candidate_actor(&mut data);
    rewrite_policy_manifest_entries(&mut data, |entries| {
        for (key, value) in entries {
            if key.as_str() == Some(POLICY_RULES_KEY) {
                *value = Value::Array(Vec::new());
            }
        }
    });
    put_policy_manifest_bytes(&vault, test_id(0xee), &data)?;
    vault
        .retract_claim(&claim, crate::unix_seconds_now())
        .unwrap_or_else(|error| {
            panic!("FAILBEFORE H244 narrowed: the retraction rolled back: {error:?}")
        });
    assert_eq!(
        stored_claim_body(&vault, &claim)?.lifecycle,
        ClaimLifecycleStatus::Retracted
    );
    assert!(
        vault
            .with_write_txn(|wtxn| vault.store.owner_answer_obligation_in_txn(wtxn, &claim))?
            .is_some(),
        "the retraction closed the obligation with no owner answer"
    );
    assert!(
        vault
            .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
            .is_none(),
        "the owner is shown an item for a closed claim"
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

/// The owner's Clear of a critical decay settles on a MACHINE claim whose
/// history holds a carrier: the restriction lands, and the history still reads
/// back only after that carrier's own answer (F14 H244-narrowed, Astra A2).
#[test]
fn a_cleared_decay_lands_on_a_held_machine_history() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let [machine, owner, target] = [test_id(0x52), test_id(0x43), test_id(0x53)];
    vault.put_entity(&machine, ENTITY_TYPE_MACHINE, test_time(1), 1, b"machine")?;
    vault.put_entity(&owner, ENTITY_TYPE_PERSON, test_time(1), 1, b"owner")?;
    let issuer = crate::test_util::provision_engine_machines(&vault);
    vault.provision_host_machine_identity(&issuer, machine)?;
    crate::test_util::bind_test_owner(&vault, owner);
    let mut policy = crate::gate::default_policy_manifest()?;
    append_actor_ceiling(
        &mut policy,
        actor_ceiling_row_for_ref("system", &machine.to_hex(), "auto"),
    );
    put_policy_manifest_bytes(&vault, crate::gate::default_policy_manifest_id()?, &policy)?;
    let envelope = WriteEnvelope::new(
        WriteActor::new(machine, EdgeActorClass::System),
        ClaimSource::Observed,
        WriteProvenance::new(Value::from("machine fact"))?,
        ClaimApprovalStatus::Auto,
    );
    let candidate = ClaimCandidate::new(
        "profile.color",
        ClaimSubject::Entity(machine),
        Value::from("blue"),
        1.0,
    );
    let signed = crate::test_util::sign_machine_candidate(&vault, &target, &candidate, &envelope);
    vault
        .batch()
        .claim_candidate(&target, candidate, &signed, test_time(10), 10)
        .commit()?;
    let pin = vault.resolved_machine_claim(target)?.handoff_digest;
    let carrier = EntityId::from_bytes(pin[..16].try_into().expect("content id"))?;
    // The owner then marks the predicate critical, so a decay waits for them.
    // The claim is Auto: an Approved body takes no critical-confirm road, so
    // its demotion pends at the floor whatever the history holds.
    rewrite_policy_manifest_entries(&mut policy, |entries| {
        for (key, value) in entries {
            if key.as_str() == Some(POLICY_RULES_KEY) {
                let Value::Array(rules) = value else {
                    unreachable!("rules are an array");
                };
                rules.push(Value::Map(vec![
                    ("prefix".into(), "profile.color".into()),
                    ("exact".into(), true.into()),
                    (
                        "axes".into(),
                        Value::Map(vec![
                            ("criticality".into(), "critical".into()),
                            ("sensitivity".into(), "normal".into()),
                        ]),
                    ),
                ]));
            }
        }
    });
    put_policy_manifest_bytes(&vault, crate::gate::default_policy_manifest_id()?, &policy)?;
    let decay = crate::claim::ClaimDemotionAction::Decay {
        new_claim_of_weight: 0.5,
    };
    let error = vault
        .apply_claim_demotion(&target, decay, crate::unix_seconds_now())
        .expect_err("held for the owner");
    assert_eq!(error.kind(), crate::ErrorKind::GateWriteRejected);
    let pending = vault
        .with_write_txn(|txn| vault.store.pending_gate_consent_in_txn(txn, &target))?
        .expect("the decay's confirm");
    // The present handoff waits for its own answer.
    let held = critical_confirm_pending(carrier, 0x73, crate::unix_seconds_now());
    vault.with_write_txn(|txn| vault.store.put_pending_gate_consent_in_txn(txn, &held))?;
    let (_, clear) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        0x74,
    );
    vault.log_host_op_for_test(&issuer, clear.op)?;
    let binding = critical_write_confirm_binding(&pending)?;
    assert_eq!(
        vault
            .settle_critical_write_confirm(binding.confirm_id)
            .unwrap_or_else(|error| {
                panic!("FAILBEFORE A2: the cleared decay did not settle: {error:?}")
            }),
        CriticalWriteConfirmResolution::Cleared
    );
    let live = stored_claim_body(&vault, &target)?;
    assert_eq!(
        crate::claim::claim_demotion_rung(&live)?,
        Some(crate::claim::ClaimDemotionRung::Decayed)
    );
    assert_eq!(live.approval, ClaimApprovalStatus::Auto);
    assert!(
        matches!(
            vault.resolved_machine_claim(target),
            Err(Error::Claim(
                crate::error::ClaimError::MachineClaimHistoryIncomplete
            ))
        ),
        "the held history read back"
    );
    // The carrier's own answer lets the decayed history read back.
    vault.with_write_txn(|txn| {
        let removal = crate::gate::owner_answer::close_owner_answer_obligation_in_txn(
            &vault.store,
            txn,
            &carrier,
            &held.diff_handle,
            crate::gate::owner_answer::OwnerAnswer::authority_log(),
        )?;
        vault
            .store
            .remove_pending_gate_consent_in_txn(txn, &carrier, removal)
    })?;
    let view = vault.resolved_machine_claim(target)?;
    assert_eq!(
        crate::claim::claim_demotion_rung(&view.current)?,
        Some(crate::claim::ClaimDemotionRung::Decayed)
    );
    assert_eq!(view.current.approval, ClaimApprovalStatus::Auto);
    Ok(())
}
