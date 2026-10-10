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
                crate::federation::scope_codec::encode_scope_value(
                    &crate::federation::scope_codec::effect_preset(),
                )
                .unwrap(),
            ),
            (
                Value::from(GRANT_SELECTORS_KEY),
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
        "connector_manifest_drift",
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
