use super::*;

#[test]
fn admitted_sender_replays_after_new_facet_without_another_effect_or_debit()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use crate::outbound_intent_ledger::{IntentState, RecordedOutboundOutcome};

    // Ordinary sends can resume definite non-delivery. An idempotent replace
    // can resume uncertainty. An admitted absent sender is also frozen, not a
    // wildcard that re-enters automatic selection on retry.
    for (verb, uncertain_first, with_sender) in [
        ("send", false, true),
        ("replace", true, true),
        ("replace", true, false),
    ] {
        let (tmp, vault) = temp_vault();
        let actor = auto_agent_actor(&vault)?;
        let actor_ref = actor.actor_entity_ref.expect("actor");
        install_sender_retry_policy(&vault, actor_ref)?;
        let first = entity(0x93);
        if with_sender {
            put_sending_identity(&vault, first, ChannelIdentityBinding::actor(actor_ref))?;
        }
        let original_sender = with_sender.then_some(first);
        let mut request = email_send_dispatch_request(actor.clone(), 0);
        request.intent.verb = verb.to_owned();
        request.ledger_identity_ref = Some("intent:logical-send:sender-retry".to_owned());
        let mut sink = RetrySenderSink {
            uncertain_first,
            ..Default::default()
        };
        let admitted = vault.dispatch_outbound_intent(request.clone(), &mut sink)?;
        assert_eq!(admitted.outcome, OutboundDispatchOutcome::Failed);
        let pending = intent_ledger_records(&vault)?;
        assert!(pending.corrupt.is_empty());
        assert_eq!(pending.records.len(), 1);
        assert_eq!(pending[0].state, IntentState::Pending);
        assert_eq!(
            pending[0].recorded_outcome,
            if uncertain_first {
                None
            } else {
                Some(RecordedOutboundOutcome::DefiniteNonDelivery)
            }
        );
        let frozen: serde_json::Value = serde_json::from_slice(pending[0].payload())?;
        assert_eq!(frozen["actor_entity_ref"], actor_ref.to_hex());
        assert_eq!(
            frozen["channel_identity_ref"],
            serde_json::to_value(original_sender.map(|id| id.to_hex()))?
        );
        assert_eq!(sink.senders, vec![original_sender]);
        assert_eq!(sink.effects.len(), usize::from(uncertain_first));

        // Prove the choice survives a restart, not just a cached request.
        drop(vault);
        let vault = Vault::open(tmp.path(), crate::config::VaultConfig::default())?;
        if !with_sender {
            put_sending_identity(&vault, first, ChannelIdentityBinding::actor(actor_ref))?;
        }
        put_sending_identity(
            &vault,
            entity(0x94),
            ChannelIdentityBinding::actor_with_facet(actor_ref, entity(0x91)),
        )?;
        let gates_before = vault.gate_decisions(100)?;
        let receipts_before = vault.receipts(ReceiptQuery::new(100))?;
        let key_before = vault.get_connector_key(&entity(0xB7))?;

        // Same paid logical send, but a fresh sink-facing scheduled reference.
        request.intent_ref = "intent:task:sender-retry-new-attempt".to_owned();
        request.receipt_id = "outbound:sender-retry-new-attempt".to_owned();
        request.occurred_at += 1;
        let retried = vault.dispatch_outbound_intent(request.clone(), &mut sink)?;
        assert_eq!(retried.outcome, OutboundDispatchOutcome::DeliveredToChannel);
        assert_eq!(retried.gate_decision_id, None);
        assert!(retried.effector_budget.is_none());
        assert_eq!(
            retried.receipt.fields.get("channel_identity_ref"),
            original_sender.map(|sender| sender.to_hex()).as_ref()
        );
        assert_eq!(sink.senders, vec![original_sender; 2]);
        assert_eq!(sink.keys[0], sink.keys[1]);
        assert_eq!(sink.keys[0].is_some(), uncertain_first);
        assert_eq!(
            sink.effects.len(),
            1,
            "retry must not duplicate the provider effect"
        );
        let done = intent_ledger_records(&vault)?;
        assert!(done.corrupt.is_empty());
        assert_eq!(done.records.len(), 1);
        assert_eq!(done[0].id, pending[0].id);
        assert_eq!(done[0].state, IntentState::Done);
        assert_eq!(done[0].payload(), pending[0].payload());
        assert_eq!(done[0].budget_accounting, pending[0].budget_accounting);
        let deduped = vault.dispatch_outbound_intent(request, &mut sink)?;
        assert_eq!(deduped.outcome, OutboundDispatchOutcome::DeliveredToChannel);
        assert_eq!(sink.senders.len(), 2, "Done replay must not call the sink");

        // A new logical send still hits the live ambiguity wall, with no gate,
        // receipt, ledger row, queue work, budget debit, or transport call.
        let fresh = email_send_dispatch_request(actor, 1);
        let error = vault
            .dispatch_outbound_intent(fresh, &mut sink)
            .expect_err("fresh ambiguity");
        assert!(matches!(
            error,
            OutboundDispatchError::Engine(Error::InvalidConfig(reason))
                if reason.starts_with("ambiguous outbound sender:")
        ));
        assert_eq!(sink.senders.len(), 2);
        assert_eq!(sink.effects.len(), 1);
        assert_eq!(vault.gate_decisions(100)?, gates_before);
        assert_eq!(vault.receipts(ReceiptQuery::new(100))?, receipts_before);
        assert_eq!(vault.get_connector_key(&entity(0xB7))?, key_before);
        assert_eq!(intent_ledger_records(&vault)?.records, done.records);
        assert!(AttemptQueue::new(&vault).list()?.is_empty());
    }
    Ok(())
}

#[test]
fn pending_sender_retry_rechecks_policy_without_changing_frozen_admission()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use crate::outbound_intent_ledger::IntentState;

    for (verb, uncertain_first) in [("send", false), ("replace", true)] {
        let (tmp, vault) = temp_vault();
        let actor = auto_agent_actor(&vault)?;
        let actor_ref = actor.actor_entity_ref.expect("actor");
        install_sender_retry_policy(&vault, actor_ref)?;
        let sender = entity(0x93);
        put_sending_identity(&vault, sender, ChannelIdentityBinding::actor(actor_ref))?;
        let mut request = email_send_dispatch_request(actor, 0);
        request.intent.verb = verb.to_owned();
        let mut sink = RetrySenderSink {
            uncertain_first,
            ..Default::default()
        };
        let first = vault.dispatch_outbound_intent(request.clone(), &mut sink)?;
        assert_eq!(first.outcome, OutboundDispatchOutcome::Failed);
        let pending = intent_ledger_records(&vault)?;
        assert!(pending.corrupt.is_empty());
        assert_eq!(pending.records.len(), 1);
        assert_eq!(pending[0].state, IntentState::Pending);
        let key_before = vault.get_connector_key(&entity(0xB7))?;

        drop(vault);
        let vault = Vault::open(tmp.path(), crate::config::VaultConfig::default())?;
        put_sending_identity(
            &vault,
            entity(0x94),
            ChannelIdentityBinding::actor_with_facet(actor_ref, entity(0x91)),
        )?;
        // Only live policy changes. The actor, sender and request stay bound to
        // the admitted row, and the connector remains active with paid budget.
        put_policy_manifest_bytes(
            &vault,
            entity(0xD0),
            &policy_manifest(&actor_ref.to_hex(), "email", &[]),
        )?;
        let stopped = vault.dispatch_outbound_intent(request.clone(), &mut sink)?;
        assert_eq!(stopped.outcome, OutboundDispatchOutcome::Held);
        assert_ne!(stopped.gate_outcome, "allow");
        assert!(stopped.gate_decision_id.is_some());
        assert!(stopped.effector_budget.is_none());
        assert_eq!(sink.senders, vec![Some(sender)]);
        assert_eq!(sink.effects.len(), usize::from(uncertain_first));
        assert_eq!(intent_ledger_records(&vault)?.records, pending.records);
        assert_eq!(vault.get_connector_key(&entity(0xB7))?, key_before);

        put_policy_manifest_bytes(
            &vault,
            entity(0xD0),
            &policy_manifest(&actor_ref.to_hex(), "email", &["send", "replace"]),
        )?;
        let gates_before = vault.gate_decisions(100)?;
        let resumed = vault.dispatch_outbound_intent(request.clone(), &mut sink)?;
        assert_eq!(resumed.outcome, OutboundDispatchOutcome::DeliveredToChannel);
        assert_eq!(resumed.gate_decision_id, None);
        assert!(resumed.effector_budget.is_none());
        assert_eq!(sink.senders, vec![Some(sender); 2]);
        assert_eq!(sink.keys[0], sink.keys[1]);
        assert_eq!(sink.keys[0].is_some(), uncertain_first);
        assert_eq!(sink.effects.len(), 1, "the provider deduplicates the retry");
        let done = intent_ledger_records(&vault)?;
        assert!(done.corrupt.is_empty());
        assert_eq!(done.records.len(), 1);
        assert_eq!(done[0].state, IntentState::Done);
        assert_eq!(done[0].id, pending[0].id);
        assert_eq!(done[0].payload(), pending[0].payload());
        assert_eq!(done[0].budget_accounting, pending[0].budget_accounting);

        // Terminal dedup reports the prior effect even after policy withdrawal;
        // it does not authorize another wire call or demand another admission.
        put_policy_manifest_bytes(
            &vault,
            entity(0xD0),
            &policy_manifest(&actor_ref.to_hex(), "email", &[]),
        )?;
        let deduped = vault.dispatch_outbound_intent(request, &mut sink)?;
        assert_eq!(deduped.outcome, OutboundDispatchOutcome::DeliveredToChannel);
        assert_eq!(deduped.gate_decision_id, None);
        assert_eq!(sink.senders.len(), 2);
        assert_eq!(sink.effects.len(), 1);
        assert_eq!(vault.gate_decisions(100)?, gates_before);
        assert_eq!(vault.get_connector_key(&entity(0xB7))?, key_before);
        assert_eq!(intent_ledger_records(&vault)?.records, done.records);
    }
    Ok(())
}

#[test]
fn pending_sender_retry_honors_live_counterparty_opt_out()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use crate::counterparty_contact::{CounterpartyContactRecord, CounterpartyOptOutReason};
    use crate::outbound_intent_ledger::IntentState;

    let (_tmp, vault) = temp_vault();
    let actor = auto_agent_actor(&vault)?;
    let actor_ref = actor.actor_entity_ref.expect("actor");
    install_sender_retry_policy(&vault, actor_ref)?;
    let sender = entity(0x93);
    put_sending_identity(&vault, sender, ChannelIdentityBinding::actor(actor_ref))?;
    let contact_id = entity(0x95);
    let contact =
        CounterpartyContactRecord::user_introduction(sender, "recipient@example.com", 1_000)?;
    vault.create_counterparty_contact(&contact_id, &contact)?;
    let mut request =
        email_send_dispatch_request(actor, 0).counterparty_ref("recipient@example.com");
    request.intent.verb = "replace".to_owned();
    let mut sink = RetrySenderSink {
        uncertain_first: true,
        ..Default::default()
    };
    let first = vault.dispatch_outbound_intent(request.clone(), &mut sink)?;
    assert_eq!(first.outcome, OutboundDispatchOutcome::Failed);
    let pending = intent_ledger_records(&vault)?;
    assert!(pending.corrupt.is_empty());
    assert_eq!(pending.records.len(), 1);
    assert_eq!(pending[0].state, IntentState::Pending);
    let key_before = vault.get_connector_key(&entity(0xB7))?;

    vault.opt_out_counterparty_contact(
        &contact_id,
        CounterpartyOptOutReason::Unsubscribe,
        1_001,
    )?;
    let stopped = vault.dispatch_outbound_intent(request, &mut sink)?;
    assert_eq!(stopped.outcome, OutboundDispatchOutcome::Held);
    assert_ne!(stopped.gate_outcome, "allow");
    assert!(stopped.gate_decision_id.is_some());
    assert!(stopped.effector_budget.is_none());
    assert!(
        stopped.receipt.fields["gate_receipt_reasons"].contains("counterparty_opt_out_unsubscribe")
    );
    assert_eq!(sink.senders, vec![Some(sender)]);
    assert_eq!(sink.effects.len(), 1);
    assert_eq!(intent_ledger_records(&vault)?.records, pending.records);
    assert_eq!(vault.get_connector_key(&entity(0xB7))?, key_before);
    Ok(())
}

#[test]
fn stable_sender_retry_cannot_borrow_authority_for_a_different_request()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use crate::edge::EdgeActorClass;
    use crate::outbound::OutboundDispatchPolicyRisk;
    use crate::outbound_intent_ledger::{IntentLedgerError, IntentState};

    // Every replay state must reject changes before sending or returning a terminal result.
    for (state, uncertain_first) in [
        (IntentState::Pending, true),
        (IntentState::Pending, false),
        (IntentState::Done, true),
        (IntentState::Abandoned, true),
    ] {
        let (_tmp, vault) = temp_vault();
        let actor = auto_agent_actor(&vault)?;
        let actor_ref = actor.actor_entity_ref.expect("actor");
        install_sender_retry_policy(&vault, actor_ref)?;
        put_sending_identity(
            &vault,
            entity(0x93),
            ChannelIdentityBinding::actor(actor_ref),
        )?;
        let mut request = email_send_dispatch_request(actor, 0);
        request.intent.verb = "replace".to_owned();
        request.ledger_identity_ref = Some("intent:logical-send:bound-retry".to_owned());
        let mut sink = RetrySenderSink {
            uncertain_first,
            ..Default::default()
        };
        vault.dispatch_outbound_intent_with_verified_actor(
            request.clone(),
            &mut sink,
            actor_ref,
            EdgeActorClass::Agent,
        )?;
        if state == IntentState::Abandoned {
            vault.revoke_connector_key(&entity(0xB7), 1_001)?;
        }
        if state != IntentState::Pending {
            vault.dispatch_outbound_intent(request.clone(), &mut sink)?;
        }
        let expected_calls = if state == IntentState::Done { 2 } else { 1 };
        let expected_effects = usize::from(uncertain_first || state == IntentState::Done);
        put_sending_identity(
            &vault,
            entity(0x94),
            ChannelIdentityBinding::actor_with_facet(actor_ref, entity(0x91)),
        )?;
        let other_actor = entity(0x95);
        put_connector_task_actor(&vault, other_actor, 1_000)?;
        let ledger_before = intent_ledger_records(&vault)?;
        assert_eq!(ledger_before[0].state, state);
        let gates_before = vault.gate_decisions(100)?;
        let receipts_before = vault.receipts(ReceiptQuery::new(100))?;
        let key_before = vault.get_connector_key(&entity(0xB7))?;
        for axis in [
            "actor",
            "actor_ref",
            "actor_entity_ref",
            "actor_class",
            "intent_actor",
            "verb",
            "target",
            "content",
            "idempotency",
            "permission",
            "opt_in",
            "risk",
            "counterparty",
            "session",
            "sender",
            "channel",
            "on_behalf_of",
            "dedupe",
            "intent_source",
            "trigger",
            "job",
        ] {
            let mut forged = request.clone();
            match axis {
                "actor" => {
                    forged.actor = crate::outbound::OutboundDispatchActor::agent(other_actor);
                }
                "actor_ref" => forged.actor.actor_ref = Some(other_actor.to_hex()),
                "actor_entity_ref" => forged.actor.actor_entity_ref = Some(other_actor),
                "actor_class" => forged.actor.actor_class = "owner".to_owned(),
                "intent_actor" => forged.intent.actor = other_actor.to_hex(),
                "verb" => forged.intent.verb = "send".to_owned(),
                "target" => forged.intent.target = "someone-else@example.com".to_owned(),
                "content" => forged.intent.content_ref = Some("content:forged".to_owned()),
                "idempotency" => forged.intent.idempotency_key = Some("forged".to_owned()),
                "permission" => forged.gate.has_permission = false,
                "opt_in" => forged.gate.has_opted_in = false,
                "risk" => forged.gate.policy_risk = OutboundDispatchPolicyRisk::HoldToProposal,
                "counterparty" => forged.counterparty_ref = Some("party:forged".to_owned()),
                "session" => forged.originating_session_ref = Some("session:forged".to_owned()),
                "sender" => forged.channel_identity_ref = Some(entity(0x94)),
                "channel" => forged.intent.channel = "EMAIL".to_owned(),
                "on_behalf_of" => forged.intent.on_behalf_of = Some("other-owner".to_owned()),
                "dedupe" => forged.intent.dedupe_key = Some("dedupe:forged".to_owned()),
                "intent_source" => forged.intent.intent_source = "gap_queue".to_owned(),
                "trigger" => forged.intent.trigger_ref = "session:other".to_owned(),
                "job" => forged.intent.job_ref = Some("job:forged".to_owned()),
                _ => unreachable!(),
            }
            let error = vault
                .dispatch_outbound_intent(forged, &mut sink)
                .expect_err("changed request must not inherit admitted authority");
            assert!(
                matches!(
                    error,
                    OutboundDispatchError::Chokepoint(IntentLedgerError::InvalidRecord(_))
                ),
                "{axis}"
            );
        }
        let error = vault
            .dispatch_outbound_intent_with_verified_actor(
                request.clone(),
                &mut sink,
                other_actor,
                EdgeActorClass::Agent,
            )
            .expect_err("facade-bound actor must match even on replay");
        assert!(matches!(error, OutboundDispatchError::InvalidBoundActor));
        assert_eq!(sink.senders, vec![Some(entity(0x93)); expected_calls]);
        assert_eq!(sink.effects.len(), expected_effects);
        assert_eq!(
            intent_ledger_records(&vault)?.records,
            ledger_before.records
        );
        assert_eq!(vault.gate_decisions(100)?, gates_before);
        assert_eq!(vault.receipts(ReceiptQuery::new(100))?, receipts_before);
        assert_eq!(vault.get_connector_key(&entity(0xB7))?, key_before);

        // Selecting the original sender explicitly is still a valid replay.
        let retried = vault.dispatch_outbound_intent_with_verified_actor(
            request.channel_identity_ref(entity(0x93)),
            &mut sink,
            actor_ref,
            EdgeActorClass::Agent,
        )?;
        assert_eq!(
            retried.outcome,
            if state == IntentState::Abandoned {
                OutboundDispatchOutcome::Failed
            } else {
                OutboundDispatchOutcome::DeliveredToChannel
            }
        );
        assert_eq!(
            sink.senders,
            vec![
                Some(entity(0x93));
                if state == IntentState::Abandoned {
                    1
                } else {
                    2
                }
            ]
        );
        assert_eq!(sink.effects.len(), 1);
    }
    Ok(())
}

#[test]
fn connector_executor_resumes_uncertain_sender_after_second_facet_is_added()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use crate::attempt_queue::AttemptState;
    use crate::edge::EdgeActorClass;
    use crate::outbound::ConnectorSendTaskOutcome;
    use crate::outbound_intent_ledger::IntentState;
    use crate::receipt::ReceiptKind;

    let (_tmp, vault) = temp_vault();
    let actor = auto_agent_actor(&vault)?.actor_entity_ref.expect("actor");
    install_sender_retry_policy(&vault, actor)?;
    put_sending_identity(&vault, entity(0x93), ChannelIdentityBinding::actor(actor))?;
    let mut draft = connector_task_draft("facet-executor-retry", "session:facet-retry", 1_000);
    draft.verb = "replace".to_owned();
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("schedule under one sender");
    let task = vault.connector_send_tasks()?[0].clone();
    let mut sink = RetrySenderSink {
        uncertain_first: true,
        ..Default::default()
    };
    assert_eq!(vault.run_connector_task_executor(&mut sink, 1_001)?, 0);
    let pending = intent_ledger_records(&vault)?;
    assert_eq!(pending.records.len(), 1);
    assert_eq!(pending[0].state, IntentState::Pending);
    assert_eq!(pending[0].recorded_outcome, None);
    let retry = AttemptQueue::new(&vault)
        .list()?
        .into_iter()
        .find(|attempt| attempt.state == AttemptState::Scheduled)
        .expect("uncertain effect has a fresh retry");
    assert!(retry.retry_of.is_some());
    put_sending_identity(
        &vault,
        entity(0x94),
        ChannelIdentityBinding::actor_with_facet(actor, entity(0x91)),
    )?;
    let retry_at = retry.scheduled_at.expect("scheduled retry instant");
    assert_eq!(vault.run_connector_task_executor(&mut sink, retry_at)?, 1);
    assert_eq!(sink.senders, vec![Some(entity(0x93)); 2]);
    assert_eq!(sink.keys[0], sink.keys[1]);
    assert!(sink.keys[0].is_some());
    assert_eq!(sink.effects.len(), 1);
    let done = intent_ledger_records(&vault)?;
    assert_eq!(done.records.len(), 1);
    assert_eq!(done[0].id, pending[0].id);
    assert_eq!(done[0].state, IntentState::Done);
    assert_eq!(
        vault
            .connector_send_task(&task.task_ref)?
            .expect("task")
            .outcome,
        Some(ConnectorSendTaskOutcome::Delivered)
    );
    assert_eq!(
        vault
            .effector_budget_read("email", Some(&actor))?
            .expect("budget")
            .rows[0]
            .used,
        1
    );
    let receipts = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Outbound))?;
    let delivered = receipts
        .iter()
        .filter(|receipt| receipt.outcome == "delivered_to_channel")
        .collect::<Vec<_>>();
    assert_eq!(delivered.len(), 1);
    assert_eq!(
        delivered[0].fields.get("channel_identity_ref"),
        Some(&entity(0x93).to_hex())
    );
    assert_eq!(
        vault.run_connector_task_executor(&mut sink, retry_at + 1)?,
        0
    );
    assert_eq!(sink.senders.len(), 2);
    Ok(())
}

#[test]
fn sender_replay_keeps_non_idempotent_and_revoked_connector_stops()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use crate::outbound_intent_ledger::IntentState;

    for verb in ["send", "replace"] {
        let (_tmp, vault) = temp_vault();
        let actor = auto_agent_actor(&vault)?;
        let actor_ref = actor.actor_entity_ref.expect("actor");
        install_sender_retry_policy(&vault, actor_ref)?;
        put_sending_identity(
            &vault,
            entity(0x93),
            ChannelIdentityBinding::actor(actor_ref),
        )?;
        let mut request = email_send_dispatch_request(actor, 0);
        request.intent.verb = verb.to_owned();
        let mut sink = RetrySenderSink {
            uncertain_first: true,
            ..Default::default()
        };
        let first = vault.dispatch_outbound_intent(request.clone(), &mut sink)?;
        assert_eq!(first.outcome, OutboundDispatchOutcome::Failed);
        let before = intent_ledger_records(&vault)?;
        assert_eq!(before.records.len(), 1);
        put_sending_identity(
            &vault,
            entity(0x94),
            ChannelIdentityBinding::actor_with_facet(actor_ref, entity(0x91)),
        )?;
        if verb == "replace" {
            vault.suspend_connector_key(&entity(0xB7), "test recovery stop", 1_001)?;
            let held = vault.dispatch_outbound_intent(request.clone(), &mut sink)?;
            assert_eq!(held.outcome, OutboundDispatchOutcome::Held);
            assert!(
                held.receipt.fields["gate_receipt_reasons"].contains("connector_key_suspended")
            );
            assert_eq!(sink.senders.len(), 1);
            assert_eq!(
                intent_ledger_records(&vault)?[0].state,
                IntentState::Pending
            );
            vault.revoke_connector_key(&entity(0xB7), 1_002)?;
        } else {
            assert_eq!(before[0].state, IntentState::Abandoned);
        }
        let stopped = vault.dispatch_outbound_intent(request, &mut sink)?;
        assert_eq!(stopped.outcome, OutboundDispatchOutcome::Failed);
        assert_eq!(sink.senders, vec![Some(entity(0x93))]);
        assert_eq!(sink.effects.len(), 1);
        let after = intent_ledger_records(&vault)?;
        assert_eq!(after.records.len(), 1);
        assert_eq!(after[0].id, before[0].id);
        assert_eq!(after[0].state, IntentState::Abandoned);
        assert_eq!(after[0].budget_accounting, before[0].budget_accounting);
    }
    Ok(())
}
