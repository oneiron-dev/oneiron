//! Critical-write confirm index, cursor, fence, and settle and decline receipts.

use super::*;

#[cfg(feature = "sync")]
#[test]
fn observer_b_malformed_critical_marker_quarantines_without_prior_mutation() -> Result<()> {
    use crate::sync::bridge::{Materializer, register_observer_b};
    use crate::sync::loro_support::map_insert_bytes;
    use crate::sync::quarantine::quarantined_records;
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use std::sync::Arc;

    let (_tmp, vault) = temp_vault();
    let vault = Arc::new(vault);
    let claim = test_id(0xb4);
    let mut pending = put_critical_auto_claim(&vault, claim)?;
    pending.reason_codes.push("gate.pending.extra".to_owned());
    vault.with_write_txn(|wtxn| vault.store.put_pending_gate_consent_in_txn(wtxn, &pending))?;
    let before = vault.get_raw(&claim)?.expect("claim row");
    let decisions_before = vault.store.gate_decisions(100)?;
    let mut replacement = vault.get_claim(&claim)?.expect("attached claim");
    replacement.value = Value::from("must not land");
    replacement.approval = ClaimApprovalStatus::Auto;
    let data = crate::claim::encode_claim_body(&replacement)?;

    // Observer B catches a remote-classified failure and commits quarantine in
    // the same transaction; this proves rejection preceded every C3 mutation.
    let window_key = WindowKey::new("2026-06");
    let doc = create_window_doc("peer", &window_key);
    let materializer = Arc::new(Materializer::new());
    let _subscriptions = register_observer_b(&doc, &vault, &materializer, window_key.as_str());
    map_insert_bytes(
        &doc.get_map("entities"),
        &claim.to_hex(),
        &entity_record(ENTITY_TYPE_CLAIM, test_time(6), 6, &data),
    )?;
    doc.commit();

    assert_eq!(vault.get_raw(&claim)?.expect("claim row"), before);
    assert_eq!(
        vault.with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?,
        Some(pending),
        "the catch-and-commit path cannot close or rewrite pending/index state"
    );
    assert_eq!(vault.store.gate_decisions(100)?, decisions_before);
    assert!(!vault.with_write_txn(|wtxn| {
        vault
            .store
            .critical_confirm_invalidation_exists_in_txn(wtxn, &claim)
    })?);
    assert!(
        !quarantined_records(&vault)?.is_empty(),
        "Observer B must have committed its quarantine record"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_delete_then_recreate_consults_claim_scoped_invalidation() -> Result<()> {
    use crate::sync::bridge::Materializer;
    use crate::sync::loro_support::map_insert_bytes;
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::window::forward_rematerialize;

    let (tmp, vault) = temp_vault();
    let claim = test_id(0xb5);
    put_critical_auto_claim(&vault, claim)?;
    let mut replacement = vault.get_claim(&claim)?.expect("attached claim");
    replacement.value = Value::from("invalidate before delete");
    replacement.approval = ClaimApprovalStatus::Auto;
    let replacement_data = crate::claim::encode_claim_body(&replacement)?;
    vault
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            test_time(7),
            7,
            &replacement_data,
        )
        .commit()?;
    assert!(vault.with_write_txn(|wtxn| {
        vault
            .store
            .critical_confirm_invalidation_exists_in_txn(wtxn, &claim)
    })?);

    vault
        .with_write_txn(|wtxn| crate::batch::deindex_entity_for_test(&vault.store, wtxn, &claim))?;
    assert!(vault.get_claim(&claim)?.is_none());
    // The forward door, starting from the missing logical row, must not
    // resurrect authority from the ceremony closed before deletion.
    let window_key = WindowKey::new("2026-07");
    let doc = create_window_doc("peer", &window_key);
    map_insert_bytes(
        &doc.get_map("entities"),
        &claim.to_hex(),
        &entity_record(ENTITY_TYPE_CLAIM, test_time(8), 8, &replacement_data),
    )?;
    doc.commit();
    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(
        vault
            .get_claim(&claim)?
            .expect("forward replayed claim")
            .approval,
        ClaimApprovalStatus::Proposed
    );
    drop(vault);
    let reopened = crate::Vault::open(tmp.path(), crate::config::VaultConfig::default())?;
    assert!(reopened.with_write_txn(|wtxn| {
        reopened
            .store
            .critical_confirm_invalidation_exists_in_txn(wtxn, &claim)
    })?);
    assert_eq!(
        reopened
            .get_claim(&claim)?
            .expect("reopened claim")
            .approval,
        ClaimApprovalStatus::Proposed
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn ordinary_pending_from_local_gate_survives_direct_and_rematerialized_marker_replays() -> Result<()>
{
    use crate::sync::bridge::Materializer;
    use crate::sync::loro_support::map_insert_bytes;
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::window::forward_rematerialize;

    let (_tmp, vault) = temp_vault();
    let claim = test_id(0xb6);
    put_critical_auto_claim(&vault, claim)?;
    let mut replacement = vault.get_claim(&claim)?.expect("attached claim");
    replacement.value = Value::from("tombstoned replacement");
    replacement.approval = ClaimApprovalStatus::Auto;
    let replacement_data = crate::claim::encode_claim_body(&replacement)?;
    vault
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            test_time(9),
            9,
            &replacement_data,
        )
        .commit()?;

    // Build ordinary Pending through the public local gate, rather than
    // fabricating a renamed critical attachment in the storage helper.
    put_policy_manifest_bytes(&vault, test_id(0xed), &encode_policy_manifest(vec![]))?;
    let dreamer_actor = test_id(0xef);
    let mut ordinary_body = replacement;
    ordinary_body.source = Some(ClaimSource::Generated);
    ordinary_body.approval = ClaimApprovalStatus::Proposed;
    // This body was read back from the earlier UserStated write, so its
    // `evidence` is still THAT write's envelope stamp — a map carrying no
    // `candidate_evidence` key at all. Re-signing it as Dreamer-authored puts
    // it under the GATE-12 evidence floor, which every Dreamer candidate must
    // clear on its own, so cite a real consolidation envelope naming the actor
    // entity `dreamer_claim_candidate_write_parts` seeds just below. The
    // semantic hash asserted further down is unchanged by this: the claim
    // inbox hash normalizes `evidence` and `source` away before hashing.
    ordinary_body.evidence = Some(precommit_evidence(vec![dreamer_actor]));
    let run_id = "dreamer-c3-index-run";
    let (candidate, envelope) =
        dreamer_claim_candidate_write_parts(&vault, &ordinary_body, dreamer_actor, run_id)?;
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time(10), 10)
        .commit()?;
    let ordinary = vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &claim)?
            .ok_or(Error::EntityNotFound)
    })?;
    assert!(
        !ordinary
            .reason_codes
            .iter()
            .any(|reason| reason.contains("critical_confirm")),
        "the local gate must create ordinary Pending, not a disguised attachment"
    );
    assert_eq!(ordinary.dreamer_run_id.as_deref(), Some(run_id));
    let semantic_hash = crate::inbox::inbox_claim_hash(&ordinary_body)?;
    let assert_indexes = |expected: &PendingGateConsentRecord| -> Result<()> {
        assert_eq!(
            vault.store.pending_gate_consents_for_run(run_id)?,
            vec![expected.clone()]
        );
        assert_eq!(
            vault.store.pending_gate_consents_for_group_key(run_id)?,
            vec![expected.clone()]
        );
        assert_eq!(
            vault
                .store
                .pending_gate_consents_for_semantic_claim_hash(&semantic_hash)?,
            vec![expected.clone()]
        );
        Ok(())
    };
    assert_indexes(&ordinary)?;

    vault
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            test_time(11),
            11,
            &replacement_data,
        )
        .commit()?;
    assert_eq!(
        vault.with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?,
        Some(ordinary.clone()),
        "direct replay leaves the real ordinary primary/index state untouched"
    );
    assert_indexes(&ordinary)?;

    let window_key = WindowKey::new("2026-05");
    let doc = create_window_doc("peer", &window_key);
    map_insert_bytes(
        &doc.get_map("entities"),
        &claim.to_hex(),
        &entity_record(ENTITY_TYPE_CLAIM, test_time(11), 11, &replacement_data),
    )?;
    doc.commit();
    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(
        vault.with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?,
        Some(ordinary.clone()),
        "forward rematerialization also preserves ordinary Pending and indexes"
    );
    assert_indexes(&ordinary)?;
    assert_eq!(
        vault.get_claim(&claim)?.expect("tombstoned claim").approval,
        ClaimApprovalStatus::Proposed
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn batch_in_fresh_critical_ceremony_never_reuses_invalidated_decision() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0xb8);
    let old_pending = put_critical_auto_claim(&vault, claim)?;
    let old_binding = critical_write_confirm_binding(&old_pending)?;
    let original = vault.get_claim(&claim)?.expect("original claim");

    let mut replacement = original.clone();
    replacement.value = Value::from("peer replacement");
    replacement.approval = ClaimApprovalStatus::Auto;
    let replacement_data = crate::claim::encode_claim_body(&replacement)?;
    vault
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            test_time(11),
            11,
            &replacement_data,
        )
        .commit()?;

    // This public caller-owned transaction intentionally uses the historical
    // body/policy. It must mint and persist a new identity before marker clear.
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &original)?;
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .claim_candidate(&claim, candidate, &envelope, test_time(12), 12)
            .apply(wtxn)
    })?;
    let fresh = vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &claim)?
            .ok_or(Error::EntityNotFound)
    })?;
    let fresh_binding = critical_write_confirm_binding(&fresh)?;
    assert_ne!(fresh_binding.gate_decision_id, old_binding.gate_decision_id);
    assert_ne!(fresh_binding.confirm_id, old_binding.confirm_id);
    assert!(
        vault.store.gate_decisions(20)?.iter().any(|decision| {
            decision.decision_id == fresh_binding.gate_decision_id
                && decision.claim_id == Some(*claim.as_bytes())
        }),
        "the fresh pending binding must have a same-transaction ledger row"
    );

    let (genesis, clear) = critical_confirm_owner_entry(
        &old_pending,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        0xb8,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (clear, test_time(2), 2)])?;
    assert_eq!(
        vault.settle_critical_write_confirm(old_binding.confirm_id)?,
        CriticalWriteConfirmResolution::AlreadySettled
    );
    assert_eq!(
        critical_write_confirm_binding(
            &vault
                .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
                .expect("fresh attachment survives old clear"),
        )?,
        fresh_binding
    );
    assert_eq!(
        vault.get_claim(&claim)?.expect("fresh claim").approval,
        ClaimApprovalStatus::Auto
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn fresh_critical_ceremony_transactionally_clears_marker_and_exact_replay_converges() -> Result<()>
{
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0xb7);
    put_critical_auto_claim(&vault, claim)?;
    let mut replacement = vault.get_claim(&claim)?.expect("attached claim");
    replacement.value = Value::from("requires a new ceremony");
    replacement.approval = ClaimApprovalStatus::Auto;
    let replacement_data = crate::claim::encode_claim_body(&replacement)?;
    vault
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            test_time(10),
            10,
            &replacement_data,
        )
        .commit()?;
    assert!(vault.with_write_txn(|wtxn| {
        vault
            .store
            .critical_confirm_invalidation_exists_in_txn(wtxn, &claim)
    })?);

    let fresh = put_critical_auto_claim(&vault, claim)?;
    assert!(!vault.with_write_txn(|wtxn| {
        vault
            .store
            .critical_confirm_invalidation_exists_in_txn(wtxn, &claim)
    })?);
    let fresh_data =
        crate::claim::encode_claim_body(&vault.get_claim(&claim)?.expect("fresh claim"))?;
    vault
        .batch()
        .put_replicated(&claim, ENTITY_TYPE_CLAIM, test_time(3), 3, &fresh_data)
        .commit()?;
    assert_eq!(
        vault.get_claim(&claim)?.expect("fresh replay").approval,
        ClaimApprovalStatus::Auto,
        "an exact replay of the fresh attached body preserves its new ceremony"
    );
    assert_eq!(
        vault.with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?,
        Some(fresh),
        "exact replay converges without replacing the fresh attachment"
    );
    Ok(())
}

#[test]
fn critical_write_confirm_clear_settles_and_deletes_pending_row() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x82);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let binding = critical_write_confirm_binding(&pending)?;
    let (genesis, clear) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        82,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (clear, test_time(2), 2)])?;
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::Cleared
    );
    assert!(
        vault
            .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
            .is_none()
    );
    assert!(vault.with_write_txn(|wtxn| {
        Ok::<_, Error>(
            vault
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &binding.confirm_id)?
                .is_none(),
        )
    })?);
    Ok(())
}

#[test]
fn critical_write_confirm_decline_before_timeout_retracts_with_declined_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x83);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let binding = critical_write_confirm_binding(&pending)?;
    let (genesis, decline) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Decline,
        83,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (decline, test_time(2), 2)])?;
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::Retracted
    );
    assert_eq!(
        stored_claim_body(&vault, &claim)?.lifecycle,
        ClaimLifecycleStatus::Retracted
    );
    assert!(vault.with_write_txn(|wtxn| {
        Ok::<_, Error>(
            vault
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &binding.confirm_id)?
                .is_none(),
        )
    })?);
    assert!(
        vault
            .store
            .gate_decisions(20)?
            .iter()
            .any(|row| row.claim_id == Some(*claim.as_bytes())
                && row.outcome == "rejected"
                && row.reason_codes == [GATE_REASON_CRITICAL_CONFIRM_DECLINED])
    );
    Ok(())
}

#[test]
fn critical_write_confirm_decline_after_timeout_retracts_with_declined_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x84);
    let mut pending = put_critical_auto_claim(&vault, claim)?;
    pending.created_at = 1;
    vault.with_write_txn(|wtxn| vault.store.put_pending_gate_consent_in_txn(wtxn, &pending))?;
    let binding = critical_write_confirm_binding(&pending)?;
    let (genesis, decline) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Decline,
        84,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (decline, test_time(2), 2)])?;
    // A post-timeout decline remains a terminal retraction once an owner decline is folded.
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::Retracted
    );
    assert_eq!(
        stored_claim_body(&vault, &claim)?.lifecycle,
        ClaimLifecycleStatus::Retracted
    );
    assert!(
        vault
            .store
            .gate_decisions(20)?
            .iter()
            .any(|row| row.claim_id == Some(*claim.as_bytes())
                && row.outcome == "rejected"
                && row.reason_codes == [GATE_REASON_CRITICAL_CONFIRM_DECLINED])
    );
    Ok(())
}

#[test]
fn critical_write_confirm_stale_binding_is_already_settled() -> Result<()> {
    use ed25519_dalek::{Signer, SigningKey};

    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x85);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let binding = critical_write_confirm_binding(&pending)?;
    let (genesis, mut clear) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        85,
    );
    if let crate::authority::AuthorityOp::CriticalWriteConfirm(action) = &mut clear.op {
        action.nonce[0] ^= 1;
    }
    // Re-sign the deliberately stale authority entry after changing its binding material.
    let key = SigningKey::from_bytes(&[85; 32]);
    clear.signer.signature = key
        .sign(&crate::authority::authority_transcript(&clear)?)
        .to_bytes()
        .to_vec();
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (clear, test_time(2), 2)])?;
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::AlreadySettled
    );
    Ok(())
}

#[test]
fn critical_confirm_sweep_preserves_ordinary_pending_rows() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let critical = test_id(0x86);
    let ordinary = test_id(0x87);
    let mut pending = put_critical_auto_claim(&vault, critical)?;
    pending.created_at = 1;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .put_pending_gate_consent_in_txn(wtxn, &pending)?;
        vault.store.put_pending_gate_consent_in_txn(
            wtxn,
            &PendingGateConsentRecord {
                version: 0,
                claim_id: *ordinary.as_bytes(),
                decision_id: GateDecisionId::from_bytes([87; 16]),
                created_at: 1,
                diff_handle: vec![87],
                read_frontier_hash: [88; 32],
                reason_codes: vec!["gate.pending.ordinary".to_owned()],
                dreamer_run_id: None,
            },
        )
    })?;
    assert_eq!(
        vault.expire_critical_write_confirms_at(1 + CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS)?,
        1
    );
    let ordinary_row = vault
        .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &ordinary))?
        .expect("ordinary remains pending");
    assert_eq!(ordinary_row.reason_codes, vec!["gate.pending.ordinary"]);
    Ok(())
}

#[test]
fn critical_write_confirm_double_settle_replay_is_already_settled() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x88);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let binding = critical_write_confirm_binding(&pending)?;
    let (genesis, clear) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        88,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (clear, test_time(2), 2)])?;
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::Cleared
    );
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::AlreadySettled
    );
    Ok(())
}

#[test]
fn critical_confirm_decline_uses_preauthorized_status_door_after_manifest_fails_closed()
-> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x89);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let binding = critical_write_confirm_binding(&pending)?;
    let receipts_before = vault.store.gate_decisions(20)?.len();

    // A malformed later manifest makes ordinary local CLAIM writes fail closed.
    put_policy_manifest_bytes(&vault, test_id(0x8a), b"not-a-manifest")?;
    assert!(resolve(&vault)?.is_fail_closed());
    let (genesis, decline) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Decline,
        89,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (decline, test_time(2), 2)])?;

    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::Retracted
    );
    assert_eq!(
        stored_claim_body(&vault, &claim)?.lifecycle,
        ClaimLifecycleStatus::Retracted
    );
    assert!(
        vault
            .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
            .is_none(),
        "the original attached row is closed, not replaced"
    );
    let receipts_after = vault.store.gate_decisions(20)?;
    assert_eq!(
        receipts_after.len(),
        receipts_before + 1,
        "settlement creates only its resolution receipt"
    );
    assert!(receipts_after.iter().all(|row| {
        row.receipt_reasons != [GATE_REASON_ALLOW_CRITICAL_CONFIRM_ATTACHED]
            || row.decision_id == pending.decision_id
    }));
    Ok(())
}

#[test]
fn critical_confirm_exact_index_interleaves_absent_and_present_ids() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0xc1);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let binding = critical_write_confirm_binding(&pending)?;
    let (genesis, clear) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        0xc1,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (clear, test_time(2), 2)])?;
    let absent = [0xa5; 32];
    assert_eq!(
        vault.settle_critical_write_confirm(absent)?,
        CriticalWriteConfirmResolution::AlreadySettled,
    );
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::Cleared,
        "an absent lookup must not scan or consume a different live confirmation",
    );
    assert_eq!(
        vault.settle_critical_write_confirm(absent)?,
        CriticalWriteConfirmResolution::AlreadySettled,
    );
    Ok(())
}

#[test]
fn critical_confirm_stale_or_malformed_alias_is_removed_fail_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let ordinary = test_id(0xc2);
    let confirm_id = [0x42; 32];
    vault.with_write_txn(|wtxn| {
        vault.store.put_pending_gate_consent_in_txn(
            wtxn,
            &PendingGateConsentRecord {
                version: 0,
                claim_id: *ordinary.as_bytes(),
                decision_id: GateDecisionId::from_bytes([0xc2; 16]),
                created_at: 1,
                diff_handle: vec![0xc2],
                read_frontier_hash: [0xc2; 32],
                reason_codes: vec!["gate.pending.ordinary".to_owned()],
                dreamer_run_id: None,
            },
        )?;
        vault
            .store
            .put_critical_confirm_index_in_txn(wtxn, &confirm_id, ordinary.as_bytes())
    })?;
    assert!(vault.settle_critical_write_confirm(confirm_id).is_err());
    assert!(vault.with_write_txn(|wtxn| {
        Ok::<_, Error>(
            vault
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &confirm_id)?
                .is_none(),
        )
    })?);
    Ok(())
}

#[test]
fn preauthorized_status_door_rejects_a_body_not_bound_to_the_attachment() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x8b);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let mut changed = stored_claim_body(&vault, &claim)?;
    changed.confidence = 0.25;
    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .entities
        .get(&rtxn, claim.as_bytes())?
        .expect("claim");
    let header = EntityMetadataHeader::parse(&raw).expect("header");
    let error = vault
        .with_write_txn(|wtxn| {
            put_preauthorized_claim_status_in_txn(
                &vault,
                wtxn,
                &claim,
                &changed,
                PreauthorizedClaimStatusGrant::test_timeout_demotion(),
                TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                header.learned_at,
            )
        })
        .expect_err("non-status mutation must not use settlement door");
    assert!(matches!(error, Error::InvariantViolation(_)));
    assert_eq!(
        vault.with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?,
        Some(pending)
    );
    Ok(())
}

#[test]
fn preauthorized_status_door_rejects_wrong_id_and_header_binding() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x8c);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let body = stored_claim_body(&vault, &claim)?;
    let raw = vault.get_raw(&claim)?.expect("claim");
    let header = EntityMetadataHeader::parse(&raw).expect("header");
    let grant = PreauthorizedClaimStatusGrant::test_timeout_demotion();
    let wrong_id = vault
        .with_write_txn(|wtxn| {
            put_preauthorized_claim_status_in_txn(
                &vault,
                wtxn,
                &test_id(0x8d),
                &body,
                grant,
                TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                header.learned_at,
            )
        })
        .expect_err("wrong id must not reach the status writer");
    assert!(matches!(wrong_id, Error::EntityNotFound));
    let wrong_header = vault
        .with_write_txn(|wtxn| {
            put_preauthorized_claim_status_in_txn(
                &vault,
                wtxn,
                &claim,
                &body,
                grant,
                TimeRange {
                    start: header.occurred_start + 1,
                    end: header.occurred_end,
                },
                header.learned_at,
            )
        })
        .expect_err("wrong header must not reach the status writer");
    assert!(matches!(wrong_header, Error::InvariantViolation(_)));
    assert_eq!(
        vault.with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?,
        Some(pending)
    );
    Ok(())
}

#[test]
fn critical_confirm_timeout_sweep_ignores_a_later_fail_closed_manifest() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x8e);
    let mut pending = put_critical_auto_claim(&vault, claim)?;
    pending.created_at = 1;
    vault.with_write_txn(|wtxn| vault.store.put_pending_gate_consent_in_txn(wtxn, &pending))?;
    let receipts_before = vault.store.gate_decisions(20)?;
    put_policy_manifest_bytes(&vault, test_id(0x8f), b"not-a-manifest")?;
    assert!(resolve(&vault)?.is_fail_closed());
    assert_eq!(
        vault.expire_critical_write_confirms_at(1 + CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS)?,
        1
    );
    assert_eq!(
        stored_claim_body(&vault, &claim)?.approval,
        ClaimApprovalStatus::Proposed
    );
    assert_eq!(
        vault.store.gate_decisions(20)?,
        receipts_before,
        "sweep mints no receipt"
    );
    assert_eq!(
        vault.pending_gate_consents(20)?,
        vec![PendingGateConsentRecord {
            reason_codes: vec![GATE_REASON_CRITICAL_CONFIRM_TIMEOUT.to_owned()],
            ..pending
        }]
    );
    Ok(())
}

#[test]
fn critical_confirm_decline_ignores_a_later_narrowed_manifest_without_artifacts() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x90);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let binding = critical_write_confirm_binding(&pending)?;
    let receipts_before = vault.store.gate_decisions(20)?;
    // This remains a valid manifest but narrows ordinary source writes to Pending.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x91),
        &encode_policy_manifest(vec![source_trust_entry_without_auto_permit(
            ClaimSource::UserStated,
            0,
        )]),
    )?;
    assert!(matches!(
        resolve(&vault)?
            .evaluate_gate(&gate_evaluator_input(
                "first_party",
                None,
                ClaimSource::UserStated,
                PolicyCriticality::Critical
            ))
            .outcome(),
        GateOutcome::Pending
    ));
    let (genesis, decline) =
        critical_confirm_owner_entry(&pending, CriticalWriteConfirmDisposition::Decline, 90);
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (decline, test_time(2), 2)])?;
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::Retracted
    );
    assert!(vault.pending_gate_consents(20)?.is_empty());
    let receipts_after = vault.store.gate_decisions(20)?;
    assert_eq!(receipts_after.len(), receipts_before.len() + 1);
    assert!(
        receipts_after
            .iter()
            .filter(|row| row.claim_id == Some(*claim.as_bytes()))
            .all(|row| row.decision_id == pending.decision_id
                || row.reason_codes == [GATE_REASON_CRITICAL_CONFIRM_DECLINED])
    );
    Ok(())
}

#[test]
fn critical_confirm_alias_orphan_mismatch_and_ordinary_replacement_are_removed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0xca);
    let pending = critical_confirm_pending(claim, 1, crate::unix_seconds_now());
    let binding = critical_write_confirm_binding(&pending)?;
    let mismatched = [0x5a; 32];
    let orphan = [0x6a; 32];
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .put_pending_gate_consent_in_txn(wtxn, &pending)?;
        vault
            .store
            .put_critical_confirm_index_in_txn(wtxn, &mismatched, claim.as_bytes())?;
        vault
            .store
            .put_critical_confirm_index_in_txn(wtxn, &orphan, test_id(0xcb).as_bytes())
    })?;
    assert_eq!(
        vault.settle_critical_write_confirm(mismatched)?,
        CriticalWriteConfirmResolution::AlreadySettled,
    );
    assert_eq!(
        vault.settle_critical_write_confirm(orphan)?,
        CriticalWriteConfirmResolution::AlreadySettled,
    );
    vault.with_write_txn(|wtxn| {
        let ordinary = PendingGateConsentRecord {
            version: 0,
            claim_id: *claim.as_bytes(),
            decision_id: GateDecisionId::from_bytes([0xca; 16]),
            created_at: 1,
            diff_handle: vec![0xca],
            read_frontier_hash: [0xca; 32],
            reason_codes: vec!["gate.pending.ordinary".to_owned()],
            dreamer_run_id: None,
        };
        vault
            .store
            .put_pending_gate_consent_in_txn(wtxn, &ordinary)?;
        assert!(
            vault
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &binding.confirm_id)?
                .is_none()
        );
        assert!(
            vault
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &mismatched)?
                .is_none()
        );
        assert!(
            vault
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &orphan)?
                .is_none()
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
fn critical_confirm_index_cursor_and_fence_survive_reopen() -> Result<()> {
    let (tmp, vault) = temp_vault();
    let first = sweep_id(0xc3, 1);
    let second = sweep_id(0xc3, 2);
    let first_pending = critical_confirm_pending(first, 1, crate::unix_seconds_now());
    let second_pending = critical_confirm_pending(second, 2, crate::unix_seconds_now());
    let first_binding = critical_write_confirm_binding(&first_pending)?;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .put_pending_gate_consent_in_txn(wtxn, &first_pending)?;
        vault
            .store
            .put_pending_gate_consent_in_txn(wtxn, &second_pending)
    })?;
    assert_eq!(vault.pending_critical_write_confirms(1)?[0].claim_id, first);
    drop(vault);

    let reopened = crate::Vault::open(tmp.path(), crate::config::VaultConfig::default())?;
    reopened.with_write_txn(|wtxn| {
        assert_eq!(
            reopened
                .store
                .critical_confirm_list_sweep_state_in_txn(&*wtxn)?,
            (Some(1), Some(2)),
        );
        assert_eq!(
            reopened
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &first_binding.confirm_id)?,
            Some(first),
        );
        Ok(())
    })?;
    assert_eq!(
        reopened.pending_critical_write_confirms(1)?[0].claim_id,
        second
    );
    Ok(())
}

#[test]
fn critical_confirm_index_tracks_replace_delete_and_reattach_lifecycle() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0xc4);
    let original = critical_confirm_pending(claim, 1, crate::unix_seconds_now());
    let original_id = critical_write_confirm_binding(&original)?.confirm_id;
    let replacement = critical_confirm_pending(claim, 2, crate::unix_seconds_now());
    let replacement_id = critical_write_confirm_binding(&replacement)?.confirm_id;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .put_pending_gate_consent_in_txn(wtxn, &original)?;
        vault
            .store
            .put_pending_gate_consent_in_txn(wtxn, &replacement)?;
        assert_eq!(
            vault
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &original_id)?,
            None,
            "replacement removes the old exact alias",
        );
        assert_eq!(
            vault
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &replacement_id)?,
            Some(claim),
        );
        vault
            .store
            .delete_pending_gate_consent_in_txn(wtxn, &claim)?;
        assert_eq!(
            vault
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &replacement_id)?,
            None,
            "delete removes the replacement alias",
        );
        vault
            .store
            .put_pending_gate_consent_in_txn(wtxn, &original)?;
        assert_eq!(
            vault
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &original_id)?,
            Some(claim),
            "a reattachment installs a fresh alias",
        );
        Ok(())
    })?;
    Ok(())
}
