//! Critical-write confirm lifecycle: binding, expiry, sweep, and overwrite invalidation.

use super::*;

pub(super) fn critical_confirm_pending(
    claim: EntityId,
    decision: u8,
    created_at: u64,
) -> PendingGateConsentRecord {
    PendingGateConsentRecord {
        version: 0,
        claim_id: *claim.as_bytes(),
        decision_id: GateDecisionId::from_bytes([decision; 16]),
        created_at,
        diff_handle: vec![decision, decision.wrapping_add(1)],
        read_frontier_hash: [decision.wrapping_add(2); 32],
        reason_codes: vec!["gate.pending.critical_confirm_attached".to_owned()],
        dreamer_run_id: None,
    }
}

#[test]
fn critical_write_confirm_expiry_is_a_terminal_demotion_only() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x75);
    let subject = test_id(0x21);
    put_raw_entity_row(
        &vault,
        &subject,
        crate::registry::ENTITY_TYPE_PERSON,
        b"subject",
    )?;
    let mut body = source_trust_claim(ClaimSource::UserStated);
    body.approval = ClaimApprovalStatus::Auto;
    put_claim_body(&vault, &claim, &body)?;
    let pending = critical_confirm_pending(claim, 32, 100);
    vault.with_write_txn(|wtxn| vault.store.put_pending_gate_consent_in_txn(wtxn, &pending))?;

    assert_eq!(vault.expire_critical_write_confirms_at(399)?, 0);
    assert_eq!(
        stored_claim_body(&vault, &claim)?.approval,
        ClaimApprovalStatus::Auto
    );
    assert_eq!(vault.expire_critical_write_confirms_at(400)?, 1);
    assert_eq!(
        stored_claim_body(&vault, &claim)?.approval,
        ClaimApprovalStatus::Proposed,
        "expiry must demote rather than delete or approve the claim"
    );
    let timed_out = vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &claim)?
            .ok_or(Error::CorruptedIndex("timed-out pending gate consent"))
    })?;
    assert_eq!(
        timed_out.reason_codes,
        vec![GATE_REASON_CRITICAL_CONFIRM_TIMEOUT.to_owned()],
        "expiry must replace every pending reason with its sole terminal marker"
    );
    assert_eq!(
        stored_claim_body(&vault, &claim)?.approval,
        ClaimApprovalStatus::Proposed,
        "expiry must demote rather than delete or approve the claim"
    );
    assert!(
        critical_write_confirm_binding(&timed_out).is_ok(),
        "the terminal marker remains a valid binding for audit/replay safety"
    );
    assert!(
        vault.pending_critical_write_confirms(10)?.is_empty(),
        "an expired attachment is not an outstanding confirmation"
    );
    Ok(())
}

#[test]
fn pending_critical_confirms_sweep_bounded_pages_and_demotes_every_expired_claim() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let now = crate::unix_seconds_now();
    let expiring = [sweep_id(0xf0, 1), sweep_id(0xf0, 2), sweep_id(0xf0, 3)];
    let live = [sweep_id(0xf0, 4), sweep_id(0xf0, 5)];
    vault.with_write_txn(|wtxn| {
        // 600 non-critical rows plus five critical rows require more than two pages.
        for ordinal in 0..600u16 {
            let claim = EntityId::from_bytes([
                0x10,
                (ordinal >> 8) as u8,
                ordinal as u8,
                0x5a,
                0x10,
                (ordinal >> 8) as u8,
                ordinal as u8,
                0x5a,
                0x10,
                (ordinal >> 8) as u8,
                ordinal as u8,
                0x5a,
                0x10,
                (ordinal >> 8) as u8,
                ordinal as u8,
                0x5a,
            ])
            .expect("sweep fixture id");
            let ordinary = PendingGateConsentRecord {
                version: 0,
                claim_id: *claim.as_bytes(),
                decision_id: GateDecisionId::from_bytes([(ordinal % 251) as u8 + 1; 16]),
                created_at: now,
                diff_handle: vec![ordinal as u8],
                read_frontier_hash: [((ordinal + 1) & 0xff) as u8; 32],
                reason_codes: vec!["gate.pending.ordinary".to_owned()],
                dreamer_run_id: None,
            };
            vault
                .store
                .put_pending_gate_consent_in_txn(wtxn, &ordinary)?;
        }
        for (ordinal, claim) in expiring.iter().enumerate() {
            vault.store.put_pending_gate_consent_in_txn(
                wtxn,
                &critical_confirm_pending(*claim, 240 + ordinal as u8, 1),
            )?;
        }
        for (ordinal, claim) in live.iter().enumerate() {
            vault.store.put_pending_gate_consent_in_txn(
                wtxn,
                &critical_confirm_pending(*claim, 250 + ordinal as u8, now),
            )?;
        }
        Ok(())
    })?;
    for claim in expiring {
        let mut body = source_trust_claim(ClaimSource::UserStated);
        body.approval = ClaimApprovalStatus::Auto;
        put_claim_body(&vault, &claim, &body)?;
    }

    // Each invocation inspects only a single 256-row page. The two cursors
    // nevertheless reach critical rows after an ordinary first page.
    assert!(vault.pending_critical_write_confirms(1)?.is_empty());
    assert!(vault.pending_critical_write_confirms(1)?.is_empty());
    let outstanding = vault.pending_critical_write_confirms(305)?;
    assert_eq!(outstanding.len(), 2);
    assert_eq!(
        outstanding
            .iter()
            .map(|binding| binding.claim_id)
            .collect::<Vec<_>>(),
        live,
        "live critical rows past the first store page remain discoverable"
    );
    for claim in expiring {
        assert_eq!(
            stored_claim_body(&vault, &claim)?.approval,
            ClaimApprovalStatus::Proposed
        );
    }

    // Re-arm the three already-demoted claims to make the explicit sweep count deterministic.
    for (ordinal, claim) in expiring.iter().enumerate() {
        vault.with_write_txn(|wtxn| {
            vault.store.put_pending_gate_consent_in_txn(
                wtxn,
                &critical_confirm_pending(*claim, 240 + ordinal as u8, 1),
            )
        })?;
        let mut body = source_trust_claim(ClaimSource::UserStated);
        body.approval = ClaimApprovalStatus::Auto;
        put_claim_body(&vault, claim, &body)?;
    }
    assert_eq!(
        vault.expire_critical_write_confirms_at(1 + CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS)?,
        0
    );
    assert_eq!(
        vault.expire_critical_write_confirms_at(1 + CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS)?,
        0
    );
    assert_eq!(
        vault.expire_critical_write_confirms_at(1 + CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS)?,
        3
    );
    Ok(())
}

pub(super) use crate::test_util::critical_confirm_owner_entry;

pub(super) fn put_critical_auto_claim(
    vault: &crate::Vault,
    claim: EntityId,
) -> Result<PendingGateConsentRecord> {
    let mut data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::UserStated, 0)]);
    trust_human_candidate_actor(&mut data);
    put_policy_manifest_bytes(vault, test_id(0xee), &data)?;
    let mut body = public_stamped(source_trust_claim(ClaimSource::UserStated));
    body.predicate = "health.allergy".to_owned();
    let (candidate, envelope) = claim_candidate_write_parts(vault, &body)?;
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time(3), 3)
        .commit()?;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &claim)?
            .ok_or(Error::EntityNotFound)
    })
}

/// Security pack 2, F14 H244 (narrowed): a critical write commits `Auto` with
/// its owner confirmation attached and stays retrieval-visible, but nothing
/// consolidates it until the owner clears it (ARCH-0026 §G3). After expiry it
/// follows the sweep, which demotes it.
#[test]
fn an_unconfirmed_critical_claim_is_read_but_never_consolidated() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x8c);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let body = stored_claim_body(&vault, &claim)?;
    assert_eq!(body.approval, ClaimApprovalStatus::Auto);
    assert!(
        crate::claim::claim_surfaceable(&body),
        "retrieval still sees it"
    );
    assert!(
        vault.consolidate_claim_vad_now(&claim, 10).is_err(),
        "FAILBEFORE H244 narrowed: an unconfirmed critical claim was consolidated"
    );

    // The owner clears it, and only then does it consolidate.
    let binding = critical_write_confirm_binding(&pending)?;
    let (genesis, clear) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        0x8c,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (clear, test_time(2), 2)])?;
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::Cleared
    );
    vault.consolidate_claim_vad_now(&claim, 11)?;

    // One its owner never answers times out: the sweep demotes it, and it is
    // still never consolidated.
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x8d);
    let pending = put_critical_auto_claim(&vault, claim)?;
    vault.expire_critical_write_confirms_at(
        pending
            .created_at
            .saturating_add(CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS),
    )?;
    assert_eq!(
        stored_claim_body(&vault, &claim)?.approval,
        ClaimApprovalStatus::Proposed
    );
    assert!(vault.consolidate_claim_vad_now(&claim, 12).is_err());
    Ok(())
}

#[test]
fn critical_auto_batch_write_attaches_pending_confirm_and_allow_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x81);
    let pending = put_critical_auto_claim(&vault, claim)?;
    assert_eq!(
        pending.reason_codes,
        vec![GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED.to_owned()]
    );
    let decision = vault
        .store
        .gate_decisions(10)?
        .into_iter()
        .find(|row| row.claim_id == Some(*claim.as_bytes()))
        .expect("write receipt");
    assert_eq!(decision.outcome, "allow");
    assert_eq!(
        decision.receipt_reasons,
        vec![GATE_REASON_ALLOW_CRITICAL_CONFIRM_ATTACHED.to_owned()]
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn rematerialized_critical_claim_overwrite_invalidates_attachment_and_rejects_stale_clear()
-> Result<()> {
    use crate::sync::bridge::Materializer;
    use crate::sync::loro_support::map_insert_bytes;
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::window::forward_rematerialize;

    let (_tmp, vault) = temp_vault();
    let claim = test_id(0xb1);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let binding = critical_write_confirm_binding(&pending)?;
    let window_key = WindowKey::new("2026-04");
    let doc = create_window_doc("peer", &window_key);
    let original = vault.get_raw(&claim)?.expect("attached claim row");

    // An unchanged rematerialization is idempotent: it preserves the live
    // attachment and its original persisted binding.
    map_insert_bytes(&doc.get_map("entities"), &claim.to_hex(), &original)?;
    doc.commit();
    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    let unchanged = vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &claim)?
            .ok_or(Error::EntityNotFound)
    })?;
    assert_eq!(critical_write_confirm_binding(&unchanged)?, binding);

    // A peer body change must consume neither the old binding nor its Auto
    // status. Rebinding the changed bytes to the old ceremony would be unsafe.
    let mut replacement = vault.get_claim(&claim)?.expect("claim body");
    replacement.value = Value::from("changed by peer");
    replacement.approval = ClaimApprovalStatus::Auto;
    let replacement_data = crate::claim::encode_claim_body(&replacement)?;
    map_insert_bytes(
        &doc.get_map("entities"),
        &claim.to_hex(),
        &entity_record(ENTITY_TYPE_CLAIM, test_time(3), 3, &replacement_data),
    )?;
    doc.commit();
    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    let reopened = vault
        .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
        .expect("the owner's item for the changed revision");
    assert_ne!(
        critical_write_confirm_binding(&reopened)?.confirm_id,
        binding.confirm_id,
        "changed replay must atomically invalidate the persisted attachment"
    );
    assert_eq!(
        vault.get_claim(&claim)?.expect("changed claim").approval,
        ClaimApprovalStatus::Proposed,
        "changed replay must not leave a critical claim Auto"
    );
    // The CRDT continues to carry the peer's Auto bytes, so rematerializing it
    // again must converge on the closed/tombstoned Proposed representation.
    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(
        vault
            .get_claim(&claim)?
            .expect("replayed changed claim")
            .approval,
        ClaimApprovalStatus::Proposed,
        "replaying the same changed peer body must not re-promote Auto"
    );

    let (genesis, clear) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        0xb1,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (clear, test_time(2), 2)])?;
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::AlreadySettled,
        "a stale Clear cannot consume a ceremony for the changed body"
    );
    assert_eq!(
        vault.get_claim(&claim)?.expect("changed claim").approval,
        ClaimApprovalStatus::Proposed
    );
    assert_eq!(
        vault.with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?,
        Some(reopened),
        "a stale Clear leaves the owner's item for the changed revision"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_critical_claim_overwrite_invalidates_attachment_before_stale_clear() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0xb2);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let binding = critical_write_confirm_binding(&pending)?;
    let mut replacement = vault.get_claim(&claim)?.expect("attached claim");
    replacement.value = Value::from("replicated replacement");
    replacement.approval = ClaimApprovalStatus::Auto;
    let replacement_data = crate::claim::encode_claim_body(&replacement)?;

    vault
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            test_time(4),
            4,
            &replacement_data,
        )
        .commit()?;
    assert_ne!(
        critical_write_confirm_binding(
            &vault
                .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
                .expect("the owner's item for the replicated revision"),
        )?
        .confirm_id,
        binding.confirm_id,
        "the replicated door must invalidate in its overwrite transaction"
    );
    assert!(
        vault
            .store
            .gate_decisions(20)?
            .iter()
            .any(|row| row.claim_id == Some(*claim.as_bytes())
                && row.outcome == "invalidated"
                && row.reason_codes == [GATE_REASON_CRITICAL_CONFIRM_REPLICATED_OVERWRITE]),
        "invalidation leaves a distinct durable closure receipt"
    );
    assert_eq!(
        vault
            .get_claim(&claim)?
            .expect("replacement claim")
            .approval,
        ClaimApprovalStatus::Proposed
    );
    vault
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            test_time(4),
            4,
            &replacement_data,
        )
        .commit()?;
    assert_eq!(
        vault
            .get_claim(&claim)?
            .expect("replayed replacement claim")
            .approval,
        ClaimApprovalStatus::Proposed,
        "a repeated changed replication must remain demoted"
    );

    // A new local ceremony is distinct from the invalidated one. The old Clear
    // must neither settle it nor disturb its pending attachment.
    let fresh = put_critical_auto_claim(&vault, claim)?;
    let fresh_binding = critical_write_confirm_binding(&fresh)?;
    assert_ne!(fresh_binding.confirm_id, binding.confirm_id);

    let (genesis, clear) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        0xb2,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (clear, test_time(2), 2)])?;
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::AlreadySettled
    );
    assert_eq!(
        critical_write_confirm_binding(
            &vault
                .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
                .expect("fresh ceremony remains pending"),
        )?,
        fresh_binding,
        "a stale old Clear cannot consume a fresh ceremony"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_changed_claim_duplicate_in_one_batch_stays_proposed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0xb3);
    put_critical_auto_claim(&vault, claim)?;
    let mut replacement = vault.get_claim(&claim)?.expect("attached claim");
    replacement.value = Value::from("same batch replacement");
    replacement.approval = ClaimApprovalStatus::Auto;
    let data = crate::claim::encode_claim_body(&replacement)?;
    vault
        .batch()
        .put_replicated(&claim, ENTITY_TYPE_CLAIM, test_time(5), 5, &data)
        .put_replicated(&claim, ENTITY_TYPE_CLAIM, test_time(5), 5, &data)
        .commit()?;
    assert_eq!(
        vault
            .get_claim(&claim)?
            .expect("replacement claim")
            .approval,
        ClaimApprovalStatus::Proposed
    );
    Ok(())
}

#[test]
fn critical_demotion_holds_body_until_bound_human_clear() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x86);
    put_critical_auto_claim(&vault, claim)?;
    let before = vault.get_claim(&claim)?.expect("critical head");
    let now = crate::unix_seconds_now();
    let error = vault
        .apply_claim_demotion(
            &claim,
            crate::claim::ClaimDemotionAction::Decay {
                new_claim_of_weight: 0.1,
            },
            now,
        )
        .expect_err("human hold");
    assert_eq!(error.kind(), crate::ErrorKind::GateWriteRejected);
    assert_eq!(
        vault.pending_claim_demotion(&claim)?,
        Some(crate::claim::ClaimDemotionAction::Decay {
            new_claim_of_weight: 0.1
        })
    );
    assert_eq!(vault.get_claim(&claim)?.expect("held head"), before);
    let pending = vault
        .with_write_txn(|txn| vault.store.pending_gate_consent_in_txn(txn, &claim))?
        .expect("operation confirm");
    let binding = critical_write_confirm_binding(&pending)?;
    let (genesis, clear) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        0x87,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (clear, test_time(2), 2)])?;
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::Cleared
    );
    assert_eq!(
        crate::claim::claim_demotion_rung(&vault.get_claim(&claim)?.expect("demoted"))?,
        Some(crate::claim::ClaimDemotionRung::Decayed)
    );
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::AlreadySettled
    );
    Ok(())
}

#[test]
fn critical_demotion_expiry_and_decline_do_not_retract_original_truth() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x88);
    put_critical_auto_claim(&vault, claim)?;
    let before = vault.get_claim(&claim)?.expect("head");
    let now = crate::unix_seconds_now();
    assert!(
        vault
            .apply_claim_demotion(
                &claim,
                crate::claim::ClaimDemotionAction::Decay {
                    new_claim_of_weight: 0.1
                },
                now
            )
            .is_err()
    );
    let pending = vault
        .with_write_txn(|txn| vault.store.pending_gate_consent_in_txn(txn, &claim))?
        .expect("confirm");
    vault.expire_critical_write_confirms_at(now + CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS + 1)?;
    assert_eq!(
        vault.get_claim(&claim)?.expect("expiry is not demotion"),
        before
    );
    let (genesis, decline) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Decline,
        0x89,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (decline, test_time(2), 2)])?;
    vault.settle_critical_write_confirm(critical_write_confirm_binding(&pending)?.confirm_id)?;
    assert_eq!(
        vault.get_claim(&claim)?.expect("decline is not retraction"),
        before
    );
    Ok(())
}

#[test]
fn critical_supersession_closes_only_after_bound_clear_with_companion() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let old = test_id(0x8a);
    put_critical_auto_claim(&vault, old)?;
    let mut replacement = vault.get_claim(&old)?.expect("old");
    replacement.value = Value::from("replacement");
    replacement.approval = ClaimApprovalStatus::Proposed;
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &replacement)?;
    let new = test_id(0x8b);
    let now = crate::unix_seconds_now();
    vault.with_write_txn(|txn| {
        vault
            .batch_in()
            .claim_candidate(&new, candidate, &envelope, test_time(now), now)
            .apply_recording_gate_decisions(txn)?;
        vault.stage_claim_supersession_in_txn(txn, &new, &old, &envelope, now)
    })?;
    assert_eq!(
        vault.get_claim(&new)?.expect("proposal").approval,
        ClaimApprovalStatus::Proposed
    );
    assert_eq!(
        vault.get_claim(&old)?.expect("prior").lifecycle,
        crate::claim::ClaimLifecycleStatus::Active
    );
    let demotion = crate::claim::ClaimDemotionAction::Decay {
        new_claim_of_weight: 0.1,
    };
    assert_eq!(
        vault
            .apply_claim_demotion(&old, demotion, now)
            .unwrap_err()
            .kind(),
        crate::ErrorKind::GateWriteRejected
    );
    let _old_pending = vault
        .with_write_txn(|txn| vault.store.pending_gate_consent_in_txn(txn, &old))?
        .expect("independent old consent");
    let pending = vault
        .with_write_txn(|txn| vault.store.pending_gate_consent_in_txn(txn, &new))?
        .expect("confirm");
    let (genesis, clear) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        0x8c,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (clear, test_time(2), 2)])?;
    vault.settle_critical_write_confirm(critical_write_confirm_binding(&pending)?.confirm_id)?;
    assert_eq!(
        vault.get_claim(&new)?.expect("granted").approval,
        ClaimApprovalStatus::Auto
    );
    assert_eq!(
        vault.get_claim(&old)?.expect("closed").lifecycle,
        crate::claim::ClaimLifecycleStatus::Superseded
    );
    let retained = vault
        .with_write_txn(|txn| vault.store.pending_gate_consent_in_txn(txn, &old))?
        .expect("old consent retained");
    assert_eq!(retained.claim_id, *old.as_bytes());
    assert_eq!(vault.pending_claim_demotion(&old)?, Some(demotion));
    assert!(
        vault
            .with_write_txn(|txn| vault.store.pending_gate_consent_in_txn(txn, &new))?
            .is_none()
    );
    assert!(vault.store.gate_decisions(100)?.iter().any(|row| {
        row.claim_id == Some(*new.as_bytes())
            && row
                .reason_codes
                .iter()
                .any(|reason| reason == "gate.supersede.contradiction_closure")
    }));
    assert!(vault.claims_for_subject(&new)?.into_iter().any(|id| {
        vault
            .get_claim(&id)
            .expect("read")
            .is_some_and(|body| body.predicate == "core.supersession.provenance")
    }));
    Ok(())
}

/// Sol r2 P1: a policy re-gate never binds a critical confirm to a denial.
/// A confirm waiting on an authored Auto claim whose fresh verdict denies it
/// (here under a manifest that fails closed) is left on its old frontier,
/// untouched and counted stale. Before, it was re-bound to the denial with
/// its ceremony reason, so a Clear could settle what the fresh gate refused.
#[test]
fn a_re_gate_that_denies_binds_no_critical_confirm() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x7a);
    let mut body = source_trust_claim(ClaimSource::UserStated);
    body.approval = ClaimApprovalStatus::Auto;
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time(4), 4)
        .commit()?;
    let parked = critical_confirm_pending(claim, 40, 100);
    vault.with_write_txn(|wtxn| vault.store.put_pending_gate_consent_in_txn(wtxn, &parked))?;
    let mut data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::UserStated, 0)]);
    rewrite_policy_manifest_entries(&mut data, |entries| {
        entries.retain(|(key, _)| key.as_str() != Some(POLICY_SCHEMA_VERSION_KEY));
    });
    put_policy_manifest_bytes(&vault, test_id(0x7b), &data)?;
    assert!(resolve(&vault)?.is_fail_closed());

    let regate = vault.with_write_txn(|wtxn| {
        crate::gate::policy_upgrade::regate_pending_consents_in_txn(
            &vault,
            wtxn,
            &parked.read_frontier_hash,
            500,
        )
    })?;
    assert_eq!(
        regate,
        crate::gate::ConsentRegate {
            rebound: 0,
            restaged: 0,
            stale: 1
        }
    );
    let row = vault.with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?;
    assert_eq!(row, Some(parked), "the waiting row is left as it was");
    Ok(())
}
