//! Connector-key lifecycle, rate limits, and the effector-budget ledger.

use super::*;

pub(super) fn connector_key_line_send_manifest() -> Vec<u8> {
    encode_policy_manifest(vec![external_effect_scoped_grant_entry(
        "sender",
        "external:send",
        Value::Map(vec![(
            Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
            Value::from("line"),
        )]),
        None,
    )])
}

pub(super) fn connector_key_two_verb_manifest(channel: &str) -> Vec<u8> {
    let grant_row = |effector: String| {
        Value::Map(vec![
            (Value::from(ACTOR_REF_KEY), Value::from("sender")),
            (Value::from(GRANT_EFFECTOR_KEY), Value::from(effector)),
            (
                Value::from(GRANT_SCOPE_KEY),
                Value::Map(vec![(
                    Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
                    Value::from(channel),
                )]),
            ),
        ])
    };
    encode_policy_manifest(vec![(
        Value::from(POLICY_SCOPED_GRANTS_KEY),
        Value::Array(vec![
            grant_row("external:send".to_owned()),
            grant_row("external:provision".to_owned()),
        ]),
    )])
}

pub(super) fn check_effect(
    vault: &crate::Vault,
    effect: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
) -> Result<(
    GateDecision,
    Option<crate::connector_key::EffectorBudgetCharge>,
)> {
    let (_decision_id, decision, charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy_with_budget(&vault.store, wtxn, effect, policy, true)
    })?;
    Ok((decision, charge))
}

pub(super) fn day_window() -> crate::connector_key::EffectorBudgetWindow {
    crate::connector_key::EffectorBudgetWindow::Calendar {
        period: crate::connector_key::CalendarPeriod::Day,
        tz: None,
    }
}

#[test]
fn connector_key_unset_is_noop_and_empty_budget_key_is_equivalent() -> Result<()> {
    let run = |with_key: bool| -> Result<(
        GateDecision,
        Option<crate::connector_key::EffectorBudgetCharge>,
        crate::store::GateDecisionRecord,
    )> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
        if with_key {
            vault.register_connector_key(
                &test_id(0x77),
                crate::connector_key::ConnectorKeyRecord::active("line", None, Vec::new(), 1_000),
            )?;
        }
        let policy = resolve(&vault)?;
        let effect = external_effect_gate_input("sender", "send", "line");
        let (decision, charge) = check_effect(&vault, &effect, &policy)?;
        let record = vault
            .store
            .gate_decisions(10)?
            .into_iter()
            .find(|record| record.content_kind == "external_effect")
            .expect("dispatch decision record");
        Ok((decision, charge, record))
    };

    let (no_key_decision, no_key_charge, no_key_record) = run(false)?;
    let (keyed_decision, keyed_charge, keyed_record) = run(true)?;

    // Decision, reason codes, and receipt reasons are identical; the only
    // difference is the (dropped-in-GOV-01) charge: None vs empty NoRows.
    assert_eq!(no_key_decision, keyed_decision);
    assert_eq!(no_key_decision.outcome(), GateOutcome::Allow);
    assert!(no_key_charge.is_none());
    let keyed_charge = keyed_charge.expect("budget stage ran under a governing key");
    assert!(keyed_charge.read.rows.is_empty());
    assert!(keyed_charge.matched_rows.is_empty());
    assert!(keyed_charge.ladder_events.is_empty());
    assert_eq!(keyed_charge.sends_debit, 0);

    assert_eq!(no_key_record.outcome, keyed_record.outcome);
    assert_eq!(no_key_record.reason_codes, keyed_record.reason_codes);
    assert_eq!(no_key_record.receipt_reasons, keyed_record.receipt_reasons);
    Ok(())
}

#[test]
fn connector_key_rate_refuse_denies_third_call_and_keeps_key_active() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    let key_id = test_id(0x71);
    vault.register_connector_key(
        &key_id,
        crate::connector_key::ConnectorKeyRecord::active(
            "line",
            None,
            vec![crate::connector_key::EffectorBudget::rate(2, 3_600)],
            1_000,
        ),
    )?;
    let policy = resolve(&vault)?;
    let effect = external_effect_gate_input("sender", "send", "line");

    for _ in 0..2 {
        let (decision, charge) = check_effect(&vault, &effect, &policy)?;
        assert_eq!(decision.outcome(), GateOutcome::Allow);
        assert!(charge.is_some());
    }
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.effector_budget_exhausted"]
    );
    assert!(
        decision
            .receipt_reasons()
            .contains(&"effector_budget_exhausted")
    );
    let charge = charge.expect("exhaustion still returns the charge");
    assert_eq!(charge.read.rows[0].used, 2);
    assert_eq!(charge.read.rows[0].remaining, 0);
    assert_eq!(charge.sends_debit, 0);
    // on_exhaust: refuse leaves the key Active.
    assert_eq!(
        vault.get_connector_key(&key_id)?.expect("key").status,
        crate::connector_key::ConnectorKeyStatus::Active
    );
    Ok(())
}

#[test]
fn connector_key_lifecycle_effect_debits_rate_not_sends() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0xD0),
        &connector_key_two_verb_manifest("line"),
    )?;
    let key_id = test_id(0x72);
    vault.register_connector_key(
        &key_id,
        crate::connector_key::ConnectorKeyRecord::active(
            "line",
            None,
            vec![
                crate::connector_key::EffectorBudget::sends(
                    1,
                    day_window(),
                    crate::connector_key::EffectorBudgetOnExhaust::Suspend,
                ),
                crate::connector_key::EffectorBudget::rate(1, 3_600),
            ],
            1_000,
        ),
    )?;
    let policy = resolve(&vault)?;
    // A channel-identity-lifecycle-shaped effect: send_ref None.
    let lifecycle_effect = external_effect_gate_input("sender", "provision", "line");
    assert!(lifecycle_effect.send_ref.is_none());

    let (decision, charge) = check_effect(&vault, &lifecycle_effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    let charge = charge.expect("budget stage ran");
    assert_eq!(
        charge.sends_debit, 0,
        "lifecycle ops never eat a sends budget"
    );
    assert_eq!(charge.read.rows[0].used, 0, "sends row undebited");
    assert_eq!(charge.read.rows[1].used, 1, "rate row debited");

    // The rate row (limit 1) is now exhausted for the next lifecycle op —
    // the sends row (limit 1) is not.
    let (decision, _charge) = check_effect(&vault, &lifecycle_effect, &policy)?;
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.effector_budget_exhausted"]
    );
    assert_eq!(
        vault.get_connector_key(&key_id)?.expect("key").status,
        crate::connector_key::ConnectorKeyStatus::Active,
        "the exhausted row is the refuse-class rate row, not the suspend-class sends row"
    );
    Ok(())
}

#[test]
fn connector_key_exact_at_limit_admits_then_refuses() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    vault.register_connector_key(
        &test_id(0x73),
        crate::connector_key::ConnectorKeyRecord::active(
            "line",
            None,
            vec![crate::connector_key::EffectorBudget::sends(
                1,
                day_window(),
                crate::connector_key::EffectorBudgetOnExhaust::Refuse,
            )],
            1_000,
        ),
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    // used + amount == limit admits and exhausts the row.
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    let charge = charge.expect("charged");
    assert_eq!(charge.sends_debit, 1);
    assert_eq!(charge.read.rows[0].used, 1);
    assert_eq!(charge.read.rows[0].remaining, 0);
    assert_eq!(charge.read.rows[0].percent_used, 100);

    let (decision, _charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.effector_budget_exhausted"]
    );
    Ok(())
}

#[test]
fn connector_key_exhaustion_and_suspension_increment_effector_budget_metrics() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    let key_id = test_id(0x74);
    vault.register_connector_key(
        &key_id,
        crate::connector_key::ConnectorKeyRecord::active(
            "line",
            None,
            vec![crate::connector_key::EffectorBudget::sends(
                1,
                day_window(),
                crate::connector_key::EffectorBudgetOnExhaust::Suspend,
            )],
            1_000,
        ),
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    let before =
        gate_metrics_snapshot().count(GateOutcome::Deny, GateMetricReasonClass::EffectorBudget);
    let (allowed, _) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(allowed.outcome(), GateOutcome::Allow);
    // Exhaustion deny (flips the key Suspended) + status-wall deny.
    let (exhausted, _) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(
        gate_reason_strs(&exhausted),
        vec!["gate.deny.effector_budget_exhausted"]
    );
    let (walled, _) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(
        gate_reason_strs(&walled),
        vec!["gate.deny.connector_key_suspended"]
    );
    let after =
        gate_metrics_snapshot().count(GateOutcome::Deny, GateMetricReasonClass::EffectorBudget);
    assert!(
        after >= before + 2,
        "expected >= 2 new EffectorBudget deny counts, before {before} after {after}"
    );
    Ok(())
}

#[test]
fn connector_key_revoked_tuple_resolution_after_reregister() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    // The fixture effect's provenance actor.
    let actor = test_id(0xE0);
    let key_a = test_id(0x75);
    vault.register_connector_key(
        &key_a,
        crate::connector_key::ConnectorKeyRecord::active(
            "line",
            Some(actor),
            vec![crate::connector_key::EffectorBudget::sends(
                1,
                day_window(),
                crate::connector_key::EffectorBudgetOnExhaust::Suspend,
            )],
            1_000,
        ),
    )?;
    vault.revoke_connector_key(&key_a, 1_010)?;
    let key_b = test_id(0x76);
    vault.register_connector_key(
        &key_b,
        crate::connector_key::ConnectorKeyRecord::active(
            "line",
            Some(actor),
            vec![crate::connector_key::EffectorBudget::sends(
                2,
                day_window(),
                crate::connector_key::EffectorBudgetOnExhaust::Suspend,
            )],
            1_011,
        ),
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    // The non-revoked record wins within the tuple: key B governs and debits.
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    let charge = charge.expect("key B charged");
    assert_eq!(charge.key_ref, key_b);
    assert_eq!(charge.read.rows[0].used, 1);
    assert_eq!(charge.read.rows[0].limit, 2);

    // A revoked-only tuple still resolves to the status wall.
    vault.revoke_connector_key(&key_b, 1_020)?;
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.connector_key_suspended"]
    );
    assert!(
        decision
            .receipt_reasons()
            .contains(&"connector_key_revoked")
    );
    assert!(
        charge.is_none(),
        "the status wall never reaches the budget stage"
    );
    Ok(())
}

#[test]
fn connector_key_normalization_governs_hyphenated_channel() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0xD0),
        &encode_policy_manifest(vec![external_effect_scoped_grant_entry(
            "sender",
            "external:send",
            Value::Map(vec![(
                Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
                Value::from("slack-chat"),
            )]),
            None,
        )]),
    )?;
    // Registered with the messy owner-typed connector string.
    let key_id = test_id(0x78);
    vault.register_connector_key(
        &key_id,
        crate::connector_key::ConnectorKeyRecord::active(
            " Slack-Chat ",
            None,
            vec![crate::connector_key::EffectorBudget::rate(5, 60)],
            1_000,
        ),
    )?;
    let policy = resolve(&vault)?;
    // The dispatched effect carries the raw hyphenated channel.
    let effect = external_effect_gate_input("sender", "send", "slack-chat");
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    let charge = charge.expect("normalized connector governs the effect");
    assert_eq!(charge.read.rows[0].used, 1);

    // The ordinary never-list compiler retains the raw operand, but matching
    // uses the normalized stored connector for ordinary rows.
    let pending = vault.propose_connector_charter(&key_id, "never send on Slack-Chat", 1_001)?;
    vault.approve_connector_charter(&key_id, pending.compiled_hash, "owner", 1_002)?;
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert!(charge.is_none(), "never-list deny must not reach budgets");
    Ok(())
}

#[test]
fn exhaustion_charge_carries_history_read_only() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    vault.register_connector_key(
        &test_id(0x79),
        crate::connector_key::ConnectorKeyRecord::active(
            "line",
            None,
            vec![crate::connector_key::EffectorBudget::sends(
                1,
                day_window(),
                crate::connector_key::EffectorBudgetOnExhaust::Refuse,
            )],
            1_000,
        ),
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    // Limit 1: the single admitted send crosses 50/80/95 at once.
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    let charge = charge.expect("charged");
    let fired: Vec<_> = charge
        .ladder_events
        .iter()
        .map(|event| event.threshold)
        .collect();
    assert_eq!(
        fired,
        vec![
            crate::llm::BudgetThreshold::Silent50,
            crate::llm::BudgetThreshold::Plan80,
            crate::llm::BudgetThreshold::Land95,
        ]
    );

    // The refused retries fire NOTHING new (carry-read-only, M5b): the
    // signal history rides the read's fired_thresholds, so the hard cut is
    // never signal-silent — and never signal-spammy.
    for _ in 0..2 {
        let (decision, charge) = check_effect(&vault, &effect, &policy)?;
        assert_eq!(decision.outcome(), GateOutcome::Deny);
        let charge = charge.expect("exhaustion charge");
        assert!(charge.ladder_events.is_empty());
        assert_eq!(
            charge.read.rows[0].fired_thresholds,
            vec![
                crate::llm::BudgetThreshold::Silent50,
                crate::llm::BudgetThreshold::Plan80,
                crate::llm::BudgetThreshold::Land95,
            ]
        );
    }
    Ok(())
}

#[test]
fn effector_budget_read_is_pure_and_charges_see_unchanged_state() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    vault.register_connector_key(
        &test_id(0x7A),
        crate::connector_key::ConnectorKeyRecord::active(
            "line",
            None,
            vec![crate::connector_key::EffectorBudget::sends(
                2,
                day_window(),
                crate::connector_key::EffectorBudgetOnExhaust::Refuse,
            )],
            1_000,
        ),
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    // First send debits to 50% and fires Silent50 (persisted).
    let (_, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(charge.expect("charged").ladder_events.len(), 1);

    // Two consecutive reads agree and write nothing.
    let first = vault
        .effector_budget_read("line", None)?
        .expect("governing key");
    let second = vault
        .effector_budget_read("line", None)?
        .expect("governing key");
    assert_eq!(first, second);
    assert_eq!(first.rows[0].used, 1);
    assert_eq!(
        first.rows[0].fired_thresholds,
        vec![crate::llm::BudgetThreshold::Silent50]
    );

    // A subsequent charge sees the fired state unchanged by the reads:
    // Silent50 does NOT re-fire; the 100% crossing fires Plan80 + Land95.
    let (_, charge) = check_effect(&vault, &effect, &policy)?;
    let fired: Vec<_> = charge
        .expect("charged")
        .ladder_events
        .iter()
        .map(|event| event.threshold)
        .collect();
    assert_eq!(
        fired,
        vec![
            crate::llm::BudgetThreshold::Plan80,
            crate::llm::BudgetThreshold::Land95
        ]
    );
    Ok(())
}

#[test]
fn gate_ledger_accepts_only_pinned_receipt_reason_prefix_families() {
    let (_tmp, vault) = temp_vault();
    let append = |reason: &str| -> Result<()> {
        vault.with_write_txn(|wtxn| {
            vault.store.append_gate_decision_in_txn(
                wtxn,
                &GateDecisionRecord {
                    version: 0,
                    decision_id: GateDecisionId::now(),
                    created_at: 1,
                    outcome: "deny".to_owned(),
                    reason_codes: vec!["gate.deny.effector_budget_exhausted".to_owned()],
                    receipt_reasons: vec![reason.to_owned()],
                    system_notices: Vec::new(),
                    actor_class: "first_party".to_owned(),
                    actor_ref: None,
                    content_kind: "external_effect".to_owned(),
                    policy_manifest_version: POLICY_SCHEMA_VERSION.to_owned(),
                    claim_id: None,
                    grant_ref: None,
                    diff_handle: vec![0xAA],
                    read_frontier_hash: [0; 32],
                    redacted_at: None,
                },
            )
        })
    };

    for accepted in [
        "counterparty_opt_out",
        "connector_key_suspended",
        "effector_budget_exhausted",
        "charter_drift",
    ] {
        append(accepted).unwrap_or_else(|error| panic!("{accepted} must be accepted: {error}"));
    }
    for rejected in [
        // Unknown prefix family.
        "foo_bar",
        // Family prefix but charset rules still bind.
        "connector_key_SUSPENDED",
        "charter_drift.extra",
        // Reason-code namespace never leaks into receipt reasons.
        "gate.connector_key.register",
    ] {
        assert!(
            matches!(append(rejected), Err(Error::CorruptedIndex(_))),
            "{rejected} must be rejected"
        );
    }
}

#[test]
fn budget_stage_skips_dispatches_not_admitted_for_execution() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    let key_id = test_id(0x7F);
    vault.register_connector_key(
        &key_id,
        crate::connector_key::ConnectorKeyRecord::active(
            "line",
            None,
            vec![crate::connector_key::EffectorBudget::sends(
                1,
                day_window(),
                crate::connector_key::EffectorBudgetOnExhaust::Suspend,
            )],
            1_000,
        ),
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    // A dispatch the pipeline will park (window Hold / seat-policy stop)
    // passes the gate but neither debits nor exhausts.
    let (_id, decision, charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy_with_budget(&vault.store, wtxn, &effect, &policy, false)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert!(charge.is_none(), "no budget stage without execution");

    // The un-admitted pass left the budget untouched: the one allowed send
    // still fits, and only after IT does the key exhaust.
    let (_id, decision, charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy_with_budget(&vault.store, wtxn, &effect, &policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert_eq!(charge.expect("charged").read.rows[0].used, 1);

    // The status wall is governance, not accounting: it still converts a
    // non-admitted dispatch once the key is suspended.
    vault.suspend_connector_key(&key_id, "owner", 2_000)?;
    let (_id, decision, charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy_with_budget(&vault.store, wtxn, &effect, &policy, false)
    })?;
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.connector_key_suspended"]
    );
    assert!(charge.is_none());
    Ok(())
}

#[test]
fn ladder_events_carry_the_firing_row_identity() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    vault.register_connector_key(
        &test_id(0x81),
        crate::connector_key::ConnectorKeyRecord::active(
            "line",
            None,
            vec![
                crate::connector_key::EffectorBudget::sends(
                    10,
                    day_window(),
                    crate::connector_key::EffectorBudgetOnExhaust::Refuse,
                ),
                crate::connector_key::EffectorBudget::rate(10, 3_600),
            ],
            1_000,
        ),
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    let fired_rows = |events: &[crate::llm::BudgetLadderEvent]| {
        let mut rows: Vec<_> = events.iter().map(|event| event.row_index).collect();
        rows.sort_unstable();
        rows
    };

    // Both rows debit every send; the 5th crosses 50% on both. Two events,
    // one per firing row, with DISTINCT row ids — not two indistinguishable
    // duplicates a steering consumer could neither dedupe nor attribute.
    for _ in 0..4 {
        let (_, charge) = check_effect(&vault, &effect, &policy)?;
        assert!(charge.expect("charged").ladder_events.is_empty());
    }
    let (_, charge) = check_effect(&vault, &effect, &policy)?;
    let events = charge.expect("charged").ladder_events;
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .all(|event| event.threshold == crate::llm::BudgetThreshold::Silent50)
    );
    assert_eq!(fired_rows(&events), vec![Some(0), Some(1)]);

    // The 8th crosses 80% on both rows — again uniquely attributable.
    for _ in 0..2 {
        let (_, charge) = check_effect(&vault, &effect, &policy)?;
        assert!(charge.expect("charged").ladder_events.is_empty());
    }
    let (_, charge) = check_effect(&vault, &effect, &policy)?;
    let events = charge.expect("charged").ladder_events;
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .all(|event| event.threshold == crate::llm::BudgetThreshold::Plan80)
    );
    assert_eq!(fired_rows(&events), vec![Some(0), Some(1)]);
    Ok(())
}

#[test]
fn exhausted_denial_carries_backfilled_ladder_history() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    let key_id = test_id(0x82);
    vault.register_connector_key(
        &key_id,
        crate::connector_key::ConnectorKeyRecord::active(
            "line",
            None,
            vec![crate::connector_key::EffectorBudget::spend(
                100,
                "USD",
                day_window(),
                crate::connector_key::EffectorBudgetOnExhaust::Refuse,
            )],
            1_000,
        ),
    )?;
    // A single settlement jumps the row 0 -> limit WITHOUT any incremental
    // event firing (spend-ladder signals are the M3b v1 non-goal), so the
    // stored `fired` memory is empty when exhaustion is reached.
    vault.settle_connector_spend(&key_id, 0, 100, 1_100, "settle:jump")?;

    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    // The very first charge is Exhausted — and its denial read still
    // carries the crossed thresholds (not empty), with NO new events
    // (M5b carry-read-only). A retry is identical.
    for _ in 0..2 {
        let (decision, charge) = check_effect(&vault, &effect, &policy)?;
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.deny.effector_budget_exhausted"]
        );
        let charge = charge.expect("exhaustion charge");
        assert!(charge.ladder_events.is_empty(), "no events on the denial");
        assert_eq!(
            charge.read.rows[0].fired_thresholds,
            vec![
                crate::llm::BudgetThreshold::Silent50,
                crate::llm::BudgetThreshold::Plan80,
                crate::llm::BudgetThreshold::Land95,
            ],
            "jump-to-exhausted history is never signal-silent"
        );
    }

    // The self.* meter read reports the same true ladder state.
    let read = vault
        .effector_budget_read("line", None)?
        .expect("governing key");
    assert_eq!(
        read.rows[0].fired_thresholds,
        vec![
            crate::llm::BudgetThreshold::Silent50,
            crate::llm::BudgetThreshold::Plan80,
            crate::llm::BudgetThreshold::Land95,
        ]
    );
    Ok(())
}
