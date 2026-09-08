//! External-effect policy holds and pending-row coalescing.

use super::*;

#[test]
fn external_effect_public_first_touch_applies_hold_floor_and_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
        "sender",
        "send",
        Value::Map(vec![
            (
                Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
                Value::from("line"),
            ),
            (
                Value::from(EXTERNAL_EFFECT_SCOPE_POLICY_RISK_KEY),
                Value::from(ExternalEffectPolicyRisk::Normal.as_str()),
            ),
        ]),
        None,
    )]);
    put_policy_manifest_bytes(&vault, test_id(0xD6), &data)?;
    let policy = resolve(&vault)?;
    let identity = test_id(0xCE);

    let mut normal_effect = external_effect_gate_input("sender", "send", "line");
    normal_effect.channel_identity_ref = Some(identity);
    normal_effect.counterparty = Some("unknown@example.com".to_owned());
    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &normal_effect, &policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);
    assert!(decision.receipt_reasons().is_empty());

    let contact_id = test_id(0xCF);
    let public_contact = CounterpartyContactRecord::public(identity, "public@example.com", 10)?;
    vault.create_counterparty_contact(&contact_id, &public_contact)?;

    let mut public_effect = external_effect_gate_input("sender", "send", "line");
    public_effect.channel_identity_ref = Some(identity);
    public_effect.counterparty = Some("public@example.com".to_owned());
    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &public_effect, &policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec![
            "gate.pending.consent.irreversible_effect",
            "gate.pending.external_effect_authority",
        ]
    );
    assert_eq!(
        decision.receipt_reasons(),
        &["counterparty_first_touch_public"]
    );

    let decisions = vault.store.gate_decisions(10)?;
    let shaped = decisions
        .iter()
        .find(|record| record.receipt_reasons == vec!["counterparty_first_touch_public"])
        .expect("public first-touch gate decision is persisted with receipt reason");
    assert_eq!(shaped.outcome, "pending");
    assert_eq!(
        shaped.reason_codes,
        vec![
            "gate.pending.consent.irreversible_effect",
            "gate.pending.external_effect_authority",
        ]
    );

    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    let shaped_receipt = receipts
        .iter()
        .find(|receipt| {
            receipt
                .policy_trace
                .iter()
                .any(|reason| reason == "counterparty_first_touch_public")
        })
        .expect("public first-touch gate receipt is projected");
    assert_eq!(
        shaped_receipt.policy_trace,
        vec![
            "gate.pending.consent.irreversible_effect",
            "gate.pending.external_effect_authority",
            "counterparty_first_touch_public"
        ]
    );
    assert_eq!(
        shaped_receipt
            .fields
            .get("receipt_reason")
            .map(String::as_str),
        Some("counterparty_first_touch_public")
    );
    Ok(())
}

#[test]
fn external_effect_requires_opt_in_and_permission() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
        "sender",
        "send",
        Value::Map(vec![(
            Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
            Value::from("line"),
        )]),
        None,
    )]);
    put_policy_manifest_bytes(&vault, test_id(0xD1), &data)?;
    let policy = resolve(&vault)?;

    let mut missing_opt_in = external_effect_gate_input("sender", "send", "line");
    missing_opt_in.has_opted_in = false;
    let decision = policy.evaluate_gate(&missing_opt_in.gate_input(None, None));
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.external_effect_authority"]
    );

    let mut missing_permission = external_effect_gate_input("sender", "send", "line");
    missing_permission.has_permission = false;
    let decision = policy.evaluate_gate(&missing_permission.gate_input(None, None));
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.external_effect_authority"]
    );
    Ok(())
}

#[test]
fn external_effect_policy_risk_holds_but_owner_grant_can_dial_allow_all() -> Result<()> {
    let (_pending_tmp, pending_vault) = temp_vault();
    put_policy_manifest_bytes(
        &pending_vault,
        test_id(0xD2),
        &encode_policy_manifest(vec![]),
    )?;
    let pending_policy = resolve(&pending_vault)?;
    let mut risky = external_effect_gate_input("sender", "send", "line");
    risky.policy_risk = ExternalEffectPolicyRisk::HoldToProposal;

    let decision = pending_policy.evaluate_gate(&risky.gate_input(None, None));
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.external_effect_authority"]
    );

    let (_allowed_tmp, allowed_vault) = temp_vault();
    let data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
        "sender",
        "external:*",
        Value::Map(vec![
            (
                Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
                Value::from("line"),
            ),
            (
                Value::from(EXTERNAL_EFFECT_SCOPE_POLICY_RISK_KEY),
                Value::from(EXTERNAL_EFFECT_WILDCARD),
            ),
        ]),
        None,
    )]);
    put_policy_manifest_bytes(&allowed_vault, test_id(0xD3), &data)?;
    let allowed_policy = resolve(&allowed_vault)?;
    let decision = allowed_policy.evaluate_gate(&risky.gate_input(None, None));
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);
    Ok(())
}

#[test]
fn external_effect_budgeted_grants_hold_without_budget_enforcer() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
        "sender",
        "send",
        Value::Map(vec![(
            Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
            Value::from("line"),
        )]),
        Some(Value::Map(vec![(Value::from("limit"), Value::from(1_u64))])),
    )]);
    put_policy_manifest_bytes(&vault, test_id(0xD4), &data)?;
    let policy = resolve(&vault)?;
    let effect = external_effect_gate_input("sender", "send", "line");
    let decision = policy.evaluate_gate(&effect.gate_input(None, None));
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.external_effect_authority"]
    );
    Ok(())
}

#[test]
fn external_effect_fail_closed_policy_holds_instead_of_denies() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = resolve(&vault)?;
    assert!(policy.is_fail_closed());
    let effect = external_effect_gate_input("sender", "send", "line");

    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;

    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.external_effect_authority"]
    );
    let decisions = vault.store.gate_decisions(10)?;
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].outcome, "pending");
    assert_eq!(
        decisions[0].reason_codes,
        vec!["gate.pending.external_effect_authority"]
    );
    assert_eq!(decisions[0].content_kind, "external_effect");
    assert_eq!(decisions[0].claim_id, None);
    Ok(())
}

pub(super) fn coalescing_effect_record(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
) -> Result<GateDecisionRecord> {
    let governance = evaluate_external_effect_policy(store, wtxn, effect, policy, None)?;
    let (decision_id, decision) = record_external_effect_policy(store, wtxn, governance)?;
    let record = store
        .gate_decision_in_txn(&*wtxn, decision_id)?
        .expect("returned decision ref exists in the caller's txn");
    assert_eq!(record.outcome, decision.outcome().as_str());
    Ok(record)
}

pub(super) fn coalescing_ledger_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<GateDecisionRecord>> {
    let mut records = Vec::new();
    store.for_each_gate_decision_in_txn(txn, |record| {
        records.push(record);
        Ok(())
    })?;
    Ok(records)
}

#[test]
fn external_effect_pending_coalesces_same_wtxn_and_committed_retries() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("send:pending-coalesce".to_owned());

    let first = vault.with_write_txn(|wtxn| {
        let first = coalescing_effect_record(&vault.store, wtxn, &effect, &policy)?;
        assert_eq!(first.outcome, "pending");
        for _ in 0..4 {
            let retry = coalescing_effect_record(&vault.store, wtxn, &effect, &policy)?;
            assert_eq!(retry.decision_id.to_hex(), first.decision_id.to_hex());
            assert_eq!(retry, first);
            assert_eq!(
                coalescing_ledger_in_txn(&vault.store, wtxn)?,
                vec![first.clone()]
            );
        }
        Ok(first)
    })?;
    assert_eq!(vault.store.gate_decisions(10)?, vec![first.clone()]);
    vault.with_write_txn(|wtxn| {
        assert_eq!(
            coalescing_effect_record(&vault.store, wtxn, &effect, &policy)?,
            first
        );
        assert_eq!(
            coalescing_ledger_in_txn(&vault.store, wtxn)?,
            vec![first.clone()]
        );
        Ok(())
    })?;
    assert_eq!(vault.store.gate_decisions(10)?, vec![first]);
    Ok(())
}

#[test]
fn external_effect_pending_actor_and_send_changes_mint_distinct_rows() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("send:original".to_owned());
    let mut other_actor = effect.clone();
    other_actor.actor.actor_ref = Some("other-sender".to_owned());
    let mut other_class = effect.clone();
    other_class.actor.actor_class = "user".to_owned();
    let mut other_send = effect.clone();
    other_send.send_ref = Some("send:other".to_owned());

    vault.with_write_txn(|wtxn| {
        let first = coalescing_effect_record(&vault.store, wtxn, &effect, &policy)?;
        let mut records = vec![first.clone()];
        for changed in [&other_actor, &other_class, &other_send] {
            let row = coalescing_effect_record(&vault.store, wtxn, changed, &policy)?;
            assert_eq!(row.outcome, "pending");
            assert_eq!(row.actor_class, changed.actor.actor_class);
            assert_eq!(row.actor_ref, changed.actor.actor_ref);
            assert_eq!(row.reason_codes, first.reason_codes);
            assert_eq!(row.read_frontier_hash, first.read_frontier_hash);
            assert_ne!(row.diff_handle, first.diff_handle);
            assert!(
                records
                    .iter()
                    .all(|prior| prior.decision_id != row.decision_id)
            );
            records.push(row.clone());
            assert_eq!(
                coalescing_effect_record(&vault.store, wtxn, changed, &policy)?,
                row
            );
            let stored = coalescing_ledger_in_txn(&vault.store, wtxn)?;
            assert_eq!(stored.len(), records.len());
            assert!(records.iter().all(|prior| stored.contains(prior)));
        }
        // The match need not be the most recently appended Pending row.
        assert_eq!(
            coalescing_effect_record(&vault.store, wtxn, &effect, &policy)?,
            first
        );
        assert_eq!(coalescing_ledger_in_txn(&vault.store, wtxn)?.len(), 4);
        Ok(())
    })?;
    assert_eq!(vault.store.gate_decisions(10)?.len(), 4);
    Ok(())
}

#[test]
fn external_effect_pending_reason_and_receipt_changes_mint_distinct_rows() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = resolve(&vault)?;
    let effect = external_effect_gate_input("sender", "send", "line");
    let mut opted_out = effect.clone();
    opted_out.counterparty_opted_out = true;
    let mut explained = opted_out.clone();
    explained.counterparty_opt_out_receipt_reason = Some("counterparty_opt_out_do_not_contact");

    vault.with_write_txn(|wtxn| {
        let first = coalescing_effect_record(&vault.store, wtxn, &effect, &policy)?;
        let reason = coalescing_effect_record(&vault.store, wtxn, &opted_out, &policy)?;
        let receipt = coalescing_effect_record(&vault.store, wtxn, &explained, &policy)?;
        assert_ne!(reason.reason_codes, first.reason_codes);
        assert_eq!(reason.receipt_reasons, first.receipt_reasons);
        assert_eq!(receipt.reason_codes, reason.reason_codes);
        assert_ne!(receipt.receipt_reasons, reason.receipt_reasons);
        assert_ne!(first.decision_id, reason.decision_id);
        assert_ne!(first.decision_id, receipt.decision_id);
        assert_ne!(reason.decision_id, receipt.decision_id);
        for (input, row) in [
            (&effect, &first),
            (&opted_out, &reason),
            (&explained, &receipt),
        ] {
            assert_eq!(row.outcome, "pending");
            // These changes are NOT covered by the effect diff or policy hash.
            assert_eq!(row.diff_handle, first.diff_handle);
            assert_eq!(row.read_frontier_hash, first.read_frontier_hash);
            assert_eq!(
                &coalescing_effect_record(&vault.store, wtxn, input, &policy)?,
                row
            );
        }
        let stored = coalescing_ledger_in_txn(&vault.store, wtxn)?;
        assert_eq!(stored.len(), 3);
        assert!(stored.contains(&first));
        assert!(stored.contains(&reason));
        assert!(stored.contains(&receipt));
        Ok(())
    })?;
    assert_eq!(vault.store.gate_decisions(10)?.len(), 3);
    Ok(())
}

#[test]
fn external_effect_pending_policy_frontier_change_mints_distinct_row() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![]);
    put_policy_manifest_bytes(&vault, test_id(0xD0), &data)?;
    let first_policy = resolve(&vault)?;
    rewrite_policy_manifest_entries(&mut data, |entries| {
        let (_, version) = entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some(POLICY_PACK_VERSION_KEY))
            .expect("pack version");
        *version = Value::from("v2");
    });
    put_policy_manifest_bytes(&vault, test_id(0xD0), &data)?;
    let changed_policy = resolve(&vault)?;
    let effect = external_effect_gate_input("sender", "send", "line");

    vault.with_write_txn(|wtxn| {
        let first = coalescing_effect_record(&vault.store, wtxn, &effect, &first_policy)?;
        let changed = coalescing_effect_record(&vault.store, wtxn, &effect, &changed_policy)?;
        assert_eq!(first.outcome, "pending");
        assert_eq!(changed.outcome, "pending");
        assert_eq!(changed.reason_codes, first.reason_codes);
        assert_eq!(changed.receipt_reasons, first.receipt_reasons);
        assert_eq!(changed.diff_handle, first.diff_handle);
        assert_eq!(
            changed.policy_manifest_version,
            first.policy_manifest_version
        );
        assert_ne!(changed.read_frontier_hash, first.read_frontier_hash);
        assert_ne!(changed.decision_id, first.decision_id);
        assert_eq!(
            coalescing_effect_record(&vault.store, wtxn, &effect, &changed_policy)?,
            changed
        );
        assert_eq!(
            coalescing_effect_record(&vault.store, wtxn, &effect, &first_policy)?,
            first
        );
        let stored = coalescing_ledger_in_txn(&vault.store, wtxn)?;
        assert_eq!(stored.len(), 2);
        assert!(stored.contains(&first));
        assert!(stored.contains(&changed));
        Ok(())
    })?;
    assert_eq!(vault.store.gate_decisions(10)?.len(), 2);
    Ok(())
}

#[test]
fn external_effect_pending_retry_rechecks_permission_allow_deny_still_append() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
        "sender",
        "external:send",
        Value::Map(vec![(
            Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
            Value::from("line"),
        )]),
        None,
    )]);
    put_policy_manifest_bytes(&vault, test_id(0xD0), &data)?;
    let policy = resolve(&vault)?;
    let allowed = external_effect_gate_input("sender", "send", "line");
    let mut pending = allowed.clone();
    pending.has_permission = false;
    let mut denied = allowed.clone();
    denied.provenance.actor_entity_ref = None;

    let records = vault.with_write_txn(|wtxn| {
        let parked = coalescing_effect_record(&vault.store, wtxn, &pending, &policy)?;
        assert_eq!(parked.outcome, "pending");
        assert_eq!(
            coalescing_effect_record(&vault.store, wtxn, &pending, &policy)?,
            parked
        );
        let mut records = vec![parked.clone()];
        for (input, outcome) in [(&allowed, "allow"), (&denied, "deny")] {
            let first = coalescing_effect_record(&vault.store, wtxn, input, &policy)?;
            let retry = coalescing_effect_record(&vault.store, wtxn, input, &policy)?;
            assert_eq!(first.outcome, outcome);
            assert_eq!(retry.outcome, outcome);
            assert_eq!(retry.reason_codes, first.reason_codes);
            assert_eq!(retry.diff_handle, first.diff_handle);
            assert_ne!(retry.decision_id, first.decision_id);
            assert!(records.iter().all(|prior| {
                prior.decision_id != first.decision_id && prior.decision_id != retry.decision_id
            }));
            records.extend([first, retry]);
        }
        assert_eq!(
            coalescing_effect_record(&vault.store, wtxn, &pending, &policy)?,
            parked
        );
        let stored = coalescing_ledger_in_txn(&vault.store, wtxn)?;
        assert_eq!(stored.len(), 5);
        assert!(records.iter().all(|row| stored.contains(row)));
        Ok(records)
    })?;
    let stored = vault.store.gate_decisions(10)?;
    assert_eq!(stored.len(), 5);
    assert!(records.iter().all(|row| stored.contains(row)));
    Ok(())
}

#[test]
fn external_effect_pending_coalescing_never_deletes_or_rewrites_existing_rows() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = resolve(&vault)?;
    let effect = external_effect_gate_input("sender", "send", "line");
    // Build a real candidate in an aborted txn, then seed an older receipt.
    // Its timestamp must survive even though every retry evaluates at "now".
    let mut original = {
        let mut wtxn = vault.store.env.write_txn()?;
        coalescing_effect_record(&vault.store, &mut wtxn, &effect, &policy)?
    };
    original.decision_id = GateDecisionId::from_bytes([0x41; 16]);
    original.created_at = 1;
    let mut other = original.clone();
    // A different actor sorts before the exact match despite sharing its diff.
    other.decision_id = GateDecisionId::from_bytes([0x40; 16]);
    other.actor_ref = Some("other-sender".to_owned());
    vault.with_write_txn(|wtxn| {
        vault.store.append_gate_decision_in_txn(wtxn, &original)?;
        vault.store.append_gate_decision_in_txn(wtxn, &other)?;
        Ok(())
    })?;

    vault.with_write_txn(|wtxn| {
        assert_eq!(
            coalescing_effect_record(&vault.store, wtxn, &effect, &policy)?,
            original
        );
        let stored = coalescing_ledger_in_txn(&vault.store, wtxn)?;
        assert_eq!(stored.len(), 2);
        assert!(stored.contains(&original));
        assert!(stored.contains(&other));
        Ok(())
    })?;
    let stored = vault.store.gate_decisions(10)?;
    assert_eq!(stored.len(), 2);
    assert!(stored.contains(&original));
    assert!(stored.contains(&other));
    Ok(())
}
