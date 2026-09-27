//! Write velocity does not replace the ordinary verdict or create a pause.

use super::*;

fn auto_manifest(actor: EntityId) -> Vec<u8> {
    let mut data = encode_policy_manifest(vec![
        source_trust_entry(ClaimSource::Generated, 0),
        signatures_entry(),
    ]);
    append_actor_ceiling(
        &mut data,
        actor_ceiling_row_for_ref("agent", &actor.to_hex(), "auto"),
    );
    data
}

#[test]
fn writes_past_the_retired_limit_keep_auto_in_single_and_multi_operation_batches() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x40);
    put_policy_manifest_bytes(&vault, test_id(0x70), &auto_manifest(actor))?;
    let mut body = public_stamped(source_trust_claim(ClaimSource::Generated));
    body.subject = ClaimSubject::Entity(test_id(0x50));
    body.evidence = Some(precommit_evidence(vec![test_id(0x50)]));
    let (_, envelope) = dreamer_claim_candidate_write_parts(&vault, &body, actor, "rate-only-run")?;
    let ids: Vec<_> = (0x80..=0xA0).map(test_id).collect();
    for id in &ids {
        vault
            .batch()
            .claim_candidate(
                id,
                claim_candidate_from_body(&body),
                &envelope,
                test_time(3),
                3,
            )
            .commit()?;
        assert_eq!(
            stored_claim_body(&vault, id)?.approval,
            ClaimApprovalStatus::Auto
        );
        assert!(!has_pending_gate_consent(&vault, id)?);
    }
    // Overwrites are still separate writes. The same actor/run cannot acquire
    // an implicit limit just because these operations share one transaction.
    let mut batch = vault.batch();
    for id in &ids {
        batch = batch.claim_candidate(
            id,
            claim_candidate_from_body(&body),
            &envelope,
            test_time(4),
            4,
        );
    }
    batch.commit()?;
    for id in &ids {
        assert_eq!(
            stored_claim_body(&vault, id)?.approval,
            ClaimApprovalStatus::Auto
        );
        assert!(!has_pending_gate_consent(&vault, id)?);
    }
    let receipts = vault.store.gate_decisions(256)?;
    assert_eq!(receipts.len(), ids.len() * 2);
    assert!(
        receipts
            .iter()
            .all(|row| row.outcome == "allow" && row.content_kind == "claim")
    );
    assert!(
        receipts
            .iter()
            .all(|row| row.reason_codes == ["gate.allow"])
    );
    Ok(())
}

#[test]
fn retired_manifest_dial_is_an_unknown_key_not_a_silent_limit() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = auto_manifest(test_id(0x40));
    rewrite_policy_manifest_entries(&mut data, |entries| {
        entries.push((
            Value::from("actor_burst_breaker"),
            Value::Map(vec![
                (Value::from("max_events"), Value::from(1)),
                (Value::from("window_secs"), Value::from(600)),
            ]),
        ));
    });
    put_policy_manifest_bytes(&vault, test_id(0x70), &data)?;
    assert!(resolve(&vault)?.is_fail_closed());
    Ok(())
}

#[test]
fn repeated_claim_id_pending_writes_bind_the_last_operation_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x40);
    put_policy_manifest_bytes(&vault, test_id(0x70), &auto_manifest(actor))?;
    let mut first = public_stamped(source_trust_claim(ClaimSource::Generated));
    first.predicate = "health.allergy".to_owned();
    first.subject = ClaimSubject::Entity(test_id(0x50));
    first.approval = ClaimApprovalStatus::Proposed;
    first.evidence = Some(precommit_evidence(vec![test_id(0x50)]));
    let (_, envelope) = dreamer_claim_candidate_write_parts(&vault, &first, actor, "receipt-fifo")?;
    let mut last = first.clone();
    last.value = Value::from("second allergy");
    let id = test_id(0x30);
    vault
        .batch()
        .claim_candidate(
            &id,
            claim_candidate_from_body(&first),
            &envelope,
            test_time(3),
            3,
        )
        .claim_candidate(
            &id,
            claim_candidate_from_body(&last),
            &envelope,
            test_time(4),
            4,
        )
        .commit()?;
    let landed = stored_claim_body(&vault, &id)?;
    assert_eq!(landed.value, last.value);
    assert_eq!(landed.approval, ClaimApprovalStatus::Proposed);
    let txn = vault.store.env.read_txn()?;
    let pending = vault
        .store
        .pending_gate_consent_in_txn(&txn, &id)?
        .expect("pending claim");
    let record = vault
        .store
        .gate_decision_in_txn(&txn, pending.decision_id)?
        .expect("bound receipt");
    assert_eq!(record.claim_id, Some(*id.as_bytes()));
    assert_eq!(record.outcome, "pending");
    let (diff, frontier) = claim_consent_binding_parts(&vault.store, &txn, &landed)?;
    assert_eq!(record.diff_handle, diff);
    assert_eq!(record.read_frontier_hash, frontier);
    drop(txn);
    assert_eq!(vault.store.gate_decisions(256)?.len(), 2);
    Ok(())
}

#[test]
fn delete_then_pending_write_keeps_the_later_preflight_binding() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x40);
    put_policy_manifest_bytes(&vault, test_id(0x70), &auto_manifest(actor))?;
    let mut body = public_stamped(source_trust_claim(ClaimSource::Generated));
    body.predicate = "health.allergy".to_owned();
    body.subject = ClaimSubject::Entity(test_id(0x50));
    body.approval = ClaimApprovalStatus::Proposed;
    body.evidence = Some(precommit_evidence(vec![test_id(0x50)]));
    let (_, envelope) = dreamer_claim_candidate_write_parts(&vault, &body, actor, "erase-order")?;
    let id = test_id(0x30);
    vault
        .batch()
        .delete(&id)
        .claim_candidate(
            &id,
            claim_candidate_from_body(&body),
            &envelope,
            test_time(3),
            3,
        )
        .commit()?;
    let landed = stored_claim_body(&vault, &id)?;
    assert_eq!(landed.approval, ClaimApprovalStatus::Proposed);
    let txn = vault.store.env.read_txn()?;
    let pending = vault
        .store
        .pending_gate_consent_in_txn(&txn, &id)?
        .expect("later write has pending consent");
    let decision = vault
        .store
        .gate_decision_in_txn(&txn, pending.decision_id)?
        .expect("later preflight decision survives earlier delete");
    let (diff, frontier) = claim_consent_binding_parts(&vault.store, &txn, &landed)?;
    assert_eq!(decision.redacted_at, None);
    assert_eq!(decision.diff_handle, diff);
    assert_eq!(decision.read_frontier_hash, frontier);
    Ok(())
}

#[test]
fn delete_then_allowed_write_keeps_receipt_but_put_then_delete_redacts_it() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x40);
    put_policy_manifest_bytes(&vault, test_id(0x70), &auto_manifest(actor))?;
    let mut body = public_stamped(source_trust_claim(ClaimSource::Generated));
    body.subject = ClaimSubject::Entity(test_id(0x50));
    body.evidence = Some(precommit_evidence(vec![test_id(0x50)]));
    let (_, envelope) =
        dreamer_claim_candidate_write_parts(&vault, &body, actor, "erase-order-auto")?;
    let first_id = test_id(0x31);
    vault
        .batch()
        .delete(&first_id)
        .claim_candidate(
            &first_id,
            claim_candidate_from_body(&body),
            &envelope,
            test_time(3),
            3,
        )
        .commit()?;
    let landed = stored_claim_body(&vault, &first_id)?;
    assert_eq!(landed.approval, ClaimApprovalStatus::Auto);
    let txn = vault.store.env.read_txn()?;
    let receipts = vault
        .store
        .gate_decisions_for_claim_in_txn(&txn, first_id.as_bytes())?;
    assert_eq!(receipts.len(), 1);
    let (diff, frontier) = claim_consent_binding_parts(&vault.store, &txn, &landed)?;
    assert_eq!(receipts[0].redacted_at, None);
    assert_eq!(receipts[0].diff_handle, diff);
    assert_eq!(receipts[0].read_frontier_hash, frontier);
    drop(txn);

    let later_delete = test_id(0x32);
    vault
        .batch()
        .claim_candidate(
            &later_delete,
            claim_candidate_from_body(&body),
            &envelope,
            test_time(4),
            4,
        )
        .delete(&later_delete)
        .commit()?;
    assert!(vault.get_claim(&later_delete)?.is_none());
    let txn = vault.store.env.read_txn()?;
    let receipts = vault
        .store
        .gate_decisions_for_claim_in_txn(&txn, later_delete.as_bytes())?;
    assert_eq!(receipts.len(), 1);
    assert!(receipts[0].redacted_at.is_some());
    assert!(receipts[0].diff_handle.is_empty());
    Ok(())
}
