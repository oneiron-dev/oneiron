//! Dispatch budget debit, exhaustion/suspend/resume, ladders, wrap window and charter drift.

use super::*;

#[test]
fn dispatch_with_no_key_and_empty_budget_key_are_equivalent()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let dispatch_once = |with_key: bool| -> std::result::Result<
        OutboundDispatchResult,
        Box<dyn std::error::Error>,
    > {
        let (_tmp, vault) = temp_vault();
        let actor = auto_agent_actor(&vault)?;
        put_policy_manifest_bytes(
            &vault,
            entity(0xD0),
            &policy_manifest(
                actor.actor_ref.as_deref().expect("actor ref"),
                "email",
                &["send"],
            ),
        )?;
        if with_key {
            vault.register_connector_key(
                &entity(0xB9),
                crate::connector_key::ConnectorKeyRecord::active("email", None, Vec::new(), 1_000),
            )?;
        }
        let mut executor = RecordingExecutor::default();
        Ok(vault.dispatch_outbound_intent(email_send_dispatch_request(actor, 0), &mut executor)?)
    };

    let without_key = dispatch_once(false)?;
    let with_empty_key = dispatch_once(true)?;
    assert_eq!(without_key.outcome, with_empty_key.outcome);
    assert_eq!(without_key.gate_outcome, with_empty_key.gate_outcome);
    assert_eq!(
        without_key.gate_reason_codes,
        with_empty_key.gate_reason_codes
    );
    assert_eq!(
        without_key.receipt.policy_trace,
        with_empty_key.receipt.policy_trace
    );
    // Receipts are field-identical modulo the per-run gate decision id and
    // (since GOV-02) the honest connector-key stamps a governing key adds:
    // an empty-budget key records `connector_key_ref` + `budget_debit: "0"`
    // but no `budget` field (no matched rows) and changes nothing else.
    let strip = |result: &OutboundDispatchResult| {
        let mut fields = result.receipt.fields.clone();
        fields.remove("gate_decision_ref");
        fields.remove("connector_key_ref");
        fields.remove("budget_debit");
        fields
    };
    assert_eq!(strip(&without_key), strip(&with_empty_key));
    assert!(!without_key.receipt.fields.contains_key("connector_key_ref"));
    assert!(!without_key.receipt.fields.contains_key("budget_debit"));
    assert!(without_key.effector_budget.is_none());
    assert!(without_key.budget_ladder_events.is_empty());
    assert_eq!(
        with_empty_key
            .receipt
            .fields
            .get("budget_debit")
            .map(String::as_str),
        Some("0")
    );
    assert!(!with_empty_key.receipt.fields.contains_key("budget"));
    Ok(())
}

#[test]
fn dispatch_sends_budget_exhausts_suspends_and_walls_until_resume()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = auto_agent_actor(&vault)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0xD0),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;
    let key_id = entity(0xB7);
    vault.register_connector_key(
        &key_id,
        crate::connector_key::ConnectorKeyRecord::active(
            "email",
            None,
            vec![crate::connector_key::EffectorBudget::sends(
                2,
                crate::connector_key::EffectorBudgetWindow::Calendar {
                    period: crate::connector_key::CalendarPeriod::Day,
                    tz: None,
                },
                crate::connector_key::EffectorBudgetOnExhaust::Suspend,
            )],
            1_000,
        ),
    )?;

    let mut executor = RecordingExecutor::default();
    // AC6: sends 1-2 deliver.
    for seq in 1..=2 {
        let result = vault.dispatch_outbound_intent(
            email_send_dispatch_request(actor.clone(), seq),
            &mut executor,
        )?;
        assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    }
    // Send 3: suppressed, exhausted, and the key flips Suspended.
    let result = vault
        .dispatch_outbound_intent(email_send_dispatch_request(actor.clone(), 3), &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::Suppressed);
    assert_eq!(
        result.gate_reason_codes,
        vec!["gate.deny.effector_budget_exhausted"]
    );
    let record = vault.get_connector_key(&key_id)?.expect("key");
    assert_eq!(
        record.status,
        crate::connector_key::ConnectorKeyStatus::Suspended
    );
    assert_eq!(
        record.suspended_reason.as_deref(),
        Some("budget_exhausted:row:0")
    );

    // AC7: the suspension is a real ceiling — the 4th dispatch hits the
    // status wall (NOT the exhausted code), proving suspension outlives the
    // exhausting call and would outlive a window rollover.
    let result = vault
        .dispatch_outbound_intent(email_send_dispatch_request(actor.clone(), 4), &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::Suppressed);
    assert_eq!(
        result.gate_reason_codes,
        vec!["gate.deny.connector_key_suspended"]
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("gate_receipt_reasons")
            .map(String::as_str),
        Some("connector_key_suspended")
    );

    // After an owner resume, budgets evaluate again — and, same window,
    // re-deny with the exhausted code (the reason-code difference across the
    // three phases is the AC).
    vault.resume_connector_key(&key_id, 2_000)?;
    let result =
        vault.dispatch_outbound_intent(email_send_dispatch_request(actor, 5), &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::Suppressed);
    assert_eq!(
        result.gate_reason_codes,
        vec!["gate.deny.effector_budget_exhausted"]
    );
    // Only the first two sends reached the connector.
    assert_eq!(executor.calls.len(), 2);
    Ok(())
}

#[test]
fn parked_and_seat_suppressed_dispatches_never_debit_budgets()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let sends_budget = || {
        vec![crate::connector_key::EffectorBudget::sends(
            5,
            crate::connector_key::EffectorBudgetWindow::Calendar {
                period: crate::connector_key::CalendarPeriod::Day,
                tz: None,
            },
            crate::connector_key::EffectorBudgetOnExhaust::Suspend,
        )]
    };
    let usage_row_absent = |vault: &Vault, key_id: &EntityId| -> crate::Result<bool> {
        let usage_key = crate::connector_key::connector_key_usage_row_key(key_id, 0);
        let rtxn = vault.store.env.read_txn()?;
        Ok(vault.store.vault_meta.get(&rtxn, &usage_key)?.is_none())
    };

    // A window-Held dispatch passes the gate but never becomes an effect —
    // it must not consume or exhaust the key's budget.
    let (_tmp, vault) = temp_vault();
    let actor = auto_agent_actor(&vault)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0xD0),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;
    let key_id = entity(0xB8);
    vault.register_connector_key(
        &key_id,
        crate::connector_key::ConnectorKeyRecord::active("email", None, sends_budget(), 1_000),
    )?;

    let held_request = OutboundDispatchRequest::new(
        "outbound:intent:held",
        "intent:held",
        dispatch_intent(OutboundIntentTrigger::agent_immediate("session:held")),
        actor.clone(),
        OutboundDispatchGate::allow_when_policy_grants(),
        1_000,
        OutboundDeliveryWindowDecision::Hold {
            reason: "quiet_hours".to_owned(),
            retry_at: None,
        },
    );
    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(held_request, &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert_eq!(result.gate_outcome, "allow");
    assert!(
        usage_row_absent(&vault, &key_id)?,
        "held dispatch left usage unchanged"
    );
    assert!(executor.calls.is_empty());

    // The same intent debits when it re-enters and actually delivers.
    let result =
        vault.dispatch_outbound_intent(email_send_dispatch_request(actor, 1), &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert!(
        !usage_row_absent(&vault, &key_id)?,
        "delivered dispatch debits"
    );

    // A seat-policy-suppressed dispatch (kill switch engaged) also passes
    // the gate but never becomes an effect: no debit.
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xB1);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;
    let key_id = entity(0xB9);
    vault.register_connector_key(
        &key_id,
        crate::connector_key::ConnectorKeyRecord::active(
            LINKEDIN_CHANNEL,
            None,
            sends_budget(),
            1_000,
        ),
    )?;
    let killed = active_linkedin_policy()?.mark_killed(1_050, "command:kill-switch")?;
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(actor, "outbound:intent:killed", "intent:killed")
            .linkedin_sandbox_policy(killed),
        &mut executor,
    )?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::Suppressed);
    assert_eq!(
        result.gate_outcome, "allow",
        "the seat policy suppressed, not the gate"
    );
    assert!(
        usage_row_absent(&vault, &key_id)?,
        "seat-suppressed dispatch left usage unchanged"
    );
    Ok(())
}

#[test]
fn dispatch_budget_injection_echoes_meter_and_receipt_fields()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault, actor) = budget_vault_with_key(100)?;
    let mut executor = RecordingExecutor::default();
    let result =
        vault.dispatch_outbound_intent(email_send_dispatch_request(actor, 1), &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);

    let read = result.effector_budget.as_ref().expect("budget echo");
    assert_eq!(read.connector, "email");
    assert_eq!(
        read.status,
        crate::connector_key::ConnectorKeyStatus::Active
    );
    assert_eq!(read.rows.len(), 1);
    assert_eq!(read.rows[0].used, 1);
    assert_eq!(read.rows[0].remaining, 99);
    assert_eq!(read.rows[0].percent_used, 1);

    let key_ref = format!("ckey:{}", entity(0xB7).to_hex());
    assert_eq!(
        result
            .receipt
            .fields
            .get("connector_key_ref")
            .map(String::as_str),
        Some(key_ref.as_str())
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("budget_debit")
            .map(String::as_str),
        Some("1")
    );
    assert_eq!(
        result.receipt.fields.get("budget").map(String::as_str),
        Some("99")
    );

    // AC4c echo property: the dispatch-borne budget equals a fresh meter
    // read at the same instant.
    let fresh = vault
        .effector_budget_read("email", None)?
        .expect("governing key read");
    assert_eq!(read, &fresh);
    Ok(())
}

#[test]
fn ladder_fires_once_per_threshold_across_separate_dispatches()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault, actor) = budget_vault_with_key(10)?;
    let mut executor = RecordingExecutor::default();
    let mut events_by_send = Vec::new();
    for seq in 1..=9 {
        let result = vault.dispatch_outbound_intent(
            email_send_dispatch_request(actor.clone(), seq),
            &mut executor,
        )?;
        assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
        events_by_send.push(result.budget_ladder_events);
    }

    for (index, events) in events_by_send.iter().enumerate() {
        let send = index + 1;
        match send {
            5 => {
                // Crossing 50% fires the silent tick (no steering); a
                // single-row cross emits ONE event tagged with its row.
                assert_eq!(events.len(), 1, "send 5 fires Silent50");
                assert_eq!(events[0].threshold, BudgetThreshold::Silent50);
                assert!(events[0].steering.is_none());
                assert_eq!(events[0].row_index, Some(0));
            }
            8 => {
                // Crossing 80% fires the wrap-up notice.
                assert_eq!(events.len(), 1, "send 8 fires Plan80");
                assert_eq!(events[0].threshold, BudgetThreshold::Plan80);
                let steering = events[0].steering.as_ref().expect("plan steering");
                assert_eq!(steering.template_id, "effector_budget.plan.80");
                assert_eq!(
                    steering.channel,
                    BudgetSignalDeliveryChannel::SteeringQueueNextTurn
                );
                assert_eq!(
                    steering.message,
                    crate::connector_key::EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE
                );
                assert_eq!(events[0].row_index, Some(0));
            }
            // Single-fire is persisted in the usage row: re-crossings on
            // separate dispatch calls (9th send, 90%) fire nothing new.
            _ => assert!(events.is_empty(), "send {send} fires nothing"),
        }
    }
    Ok(())
}

#[test]
fn graceful_wrap_window_is_bounded_then_hard_cut_suspends()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let limit: u64 = 100;
    let wrap = limit - (95 * limit).div_ceil(100);
    assert_eq!(wrap, 5, "the bounded graceful-wrap window");

    let (_tmp, vault, actor) = budget_vault_with_key(limit)?;
    let mut executor = RecordingExecutor::default();
    for seq in 1..=100 {
        let result = vault.dispatch_outbound_intent(
            email_send_dispatch_request(actor.clone(), seq),
            &mut executor,
        )?;
        assert_eq!(
            result.outcome,
            OutboundDispatchOutcome::DeliveredToChannel,
            "send {seq} still admits"
        );
        let thresholds: Vec<_> = result
            .budget_ladder_events
            .iter()
            .map(|event| event.threshold)
            .collect();
        match seq {
            50 => assert_eq!(thresholds, vec![BudgetThreshold::Silent50]),
            80 => assert_eq!(thresholds, vec![BudgetThreshold::Plan80]),
            95 => {
                // 95% fires LAND: the finalize signal ahead of the hard cut.
                assert_eq!(thresholds, vec![BudgetThreshold::Land95]);
                let steering = result.budget_ladder_events[0]
                    .steering
                    .as_ref()
                    .expect("land steering");
                assert_eq!(steering.template_id, "effector_budget.land.95");
                assert_eq!(
                    steering.message,
                    crate::connector_key::EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE
                );
            }
            _ => assert!(thresholds.is_empty(), "send {seq} fires nothing"),
        }
        // A3 conformance: every steering signal rides the ONE channel.
        for event in &result.budget_ladder_events {
            if let Some(steering) = event.steering.as_ref() {
                assert_eq!(
                    steering.channel,
                    BudgetSignalDeliveryChannel::SteeringQueueNextTurn
                );
            }
        }
    }

    // The 101st unit is the hard cut: refused AND the key flips Suspended.
    let result =
        vault.dispatch_outbound_intent(email_send_dispatch_request(actor, 101), &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::Suppressed);
    assert_eq!(
        result.gate_reason_codes,
        vec!["gate.deny.effector_budget_exhausted"]
    );
    assert!(result.budget_ladder_events.is_empty());
    let echoed = result.effector_budget.expect("exhaustion still echoes");
    assert_eq!(
        echoed.status,
        crate::connector_key::ConnectorKeyStatus::Suspended
    );
    assert_eq!(echoed.rows[0].remaining, 0);
    assert_eq!(
        result
            .receipt
            .fields
            .get("budget_debit")
            .map(String::as_str),
        Some("0")
    );
    assert_eq!(
        result.receipt.fields.get("budget").map(String::as_str),
        Some("0")
    );
    Ok(())
}

#[test]
fn dispatch_holds_on_charter_drift_until_restamped()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault, actor) = budget_vault_with_key(5)?;
    let key_id = entity(0xB7);
    let pending = vault.propose_connector_charter(&key_id, "never delete on email", 1_001)?;
    vault.approve_connector_charter(&key_id, pending.compiled_hash, "owner", 1_002)?;

    // Hand-corrupt the stored charter text under the stale stamp.
    let mut record = vault.get_connector_key(&key_id)?.expect("record");
    record.charter.as_mut().expect("charter").text = "never delete on email (edited)".to_owned();
    vault.with_write_txn(|wtxn| {
        crate::connector_key::rewrite_connector_key_in_txn(&vault.store, wtxn, &key_id, &record)
    })?;

    // Drift degrades the send to proposed-only: Held, receipted, no debit.
    let mut executor = RecordingExecutor::default();
    let result = vault
        .dispatch_outbound_intent(email_send_dispatch_request(actor.clone(), 1), &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert_eq!(result.gate_reason_codes, vec!["gate.pending.charter_drift"]);
    assert_eq!(
        result
            .receipt
            .fields
            .get("gate_receipt_reasons")
            .map(String::as_str),
        Some("charter_drift")
    );
    assert!(result.effector_budget.is_none(), "drift skips all debits");
    assert!(executor.calls.is_empty());
    let read = vault
        .effector_budget_read("email", None)?
        .expect("governing key");
    assert_eq!(read.rows[0].used, 0);

    // A fresh propose/approve re-stamps and restores enforcement.
    let restamp = vault.propose_connector_charter(&key_id, "never delete on email", 1_010)?;
    vault.approve_connector_charter(&key_id, restamp.compiled_hash, "owner", 1_011)?;
    let result =
        vault.dispatch_outbound_intent(email_send_dispatch_request(actor, 2), &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    Ok(())
}
