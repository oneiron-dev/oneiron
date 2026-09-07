use super::{
    auto_agent_actor, connector_task_draft, email_send_dispatch_request, entity, policy_manifest,
    put_connector_task_actor, put_policy_manifest_bytes, temp_vault,
};
use crate::Vault;
use crate::attempt_queue::AttemptQueue;
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape,
};
use crate::connector_key::{
    ConnectorKeyRecord, EffectorBudget, EffectorBudgetOnExhaust, EffectorBudgetWindow,
};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::outbound::{
    OutboundDispatchError, OutboundDispatchOutcome, OutboundExecutionOutcome,
    OutboundExecutionRequest, OutboundExecutionSink,
};
use crate::outbound_intent_ledger::intent_ledger_records;
use crate::receipt::ReceiptQuery;
use crate::temporal::TimeRange;

#[derive(Default)]
struct SenderRecordingSink {
    senders: Vec<Option<EntityId>>,
}

impl OutboundExecutionSink for SenderRecordingSink {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.senders.push(request.channel_identity_ref);
        OutboundExecutionOutcome::delivered_to_channel("provider:sender-selection")
    }
}

fn put_sending_identity(
    vault: &Vault,
    id: EntityId,
    binding: ChannelIdentityBinding,
) -> crate::Result<()> {
    let mut identity = ChannelIdentity::requested(
        "email",
        format!("sender-{}@example.com", id.to_hex()),
        SelfHeldShape::DedicatedAddress,
        binding,
        1_000,
    );
    identity.state = ChannelIdentityState::Active;
    vault.create_channel_identity(&id, &identity)
}

#[test]
fn ambiguous_automatic_sender_refuses_before_dispatch_effects()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for second_is_faceted in [false, true] {
        let (_tmp, vault) = temp_vault();
        let actor = auto_agent_actor(&vault)?;
        let actor_ref = actor.actor_entity_ref.expect("actor entity");
        put_policy_manifest_bytes(
            &vault,
            entity(0xD0),
            &policy_manifest(&actor_ref.to_hex(), "email", &["send"]),
        )?;
        let key_ref = entity(0xB7);
        vault.register_connector_key(
            &key_ref,
            ConnectorKeyRecord::active(
                "email",
                Some(actor_ref),
                vec![EffectorBudget::sends(
                    10,
                    EffectorBudgetWindow::Rolling { duration_s: 86_400 },
                    EffectorBudgetOnExhaust::Suspend,
                )],
                1_000,
            ),
        )?;
        for facet in [entity(0x91), entity(0x92)] {
            vault.put_entity(
                &facet,
                crate::registry::ENTITY_TYPE_FACET,
                TimeRange {
                    start: 1_000,
                    end: 1_000,
                },
                1_000,
                b"sender facet",
            )?;
        }
        let first = entity(0x93);
        let second = entity(0x94);
        put_sending_identity(
            &vault,
            first,
            ChannelIdentityBinding::actor_with_facet(actor_ref, entity(0x91)),
        )?;
        put_sending_identity(
            &vault,
            second,
            if second_is_faceted {
                ChannelIdentityBinding::actor_with_facet(actor_ref, entity(0x92))
            } else {
                ChannelIdentityBinding::actor(actor_ref)
            },
        )?;
        let receipts_before = vault.receipts(ReceiptQuery::new(100))?;
        let key_before = vault.get_connector_key(&key_ref)?;
        let request = email_send_dispatch_request(actor.clone(), 0);
        let mut sink = SenderRecordingSink::default();
        let error = vault
            .dispatch_outbound_intent(request.clone(), &mut sink)
            .expect_err("multiple eligible senders must refuse automatic dispatch");
        assert!(matches!(
            error,
            OutboundDispatchError::Engine(Error::InvalidConfig(reason))
                if reason.starts_with("ambiguous outbound sender:")
        ));
        assert!(
            sink.senders.is_empty(),
            "ambiguous dispatch must not call the sink"
        );
        assert_eq!(vault.receipts(ReceiptQuery::new(100))?, receipts_before);
        assert_eq!(vault.get_connector_key(&key_ref)?, key_before);
        let budget = vault
            .effector_budget_read("email", Some(&actor_ref))?
            .expect("governing budget");
        assert_eq!(budget.rows.len(), 1);
        assert_eq!(
            budget.rows[0].used, 0,
            "ambiguity must not debit the budget"
        );
        let ledger = intent_ledger_records(&vault)?;
        assert!(
            ledger.records.is_empty(),
            "ambiguity must not journal an intent"
        );
        assert!(ledger.corrupt.is_empty());
        assert_eq!(vault.standalone_outbound_intent_count()?, 0);
        assert!(AttemptQueue::new(&vault).list()?.is_empty());

        // The same request is valid when the caller selects one of the senders.
        let explicit =
            vault.dispatch_outbound_intent(request.channel_identity_ref(first), &mut sink)?;
        assert_eq!(
            explicit.outcome,
            OutboundDispatchOutcome::DeliveredToChannel
        );
        assert_eq!(explicit.gate_outcome, "allow");
        assert_eq!(sink.senders, vec![Some(first)]);
        assert_eq!(
            explicit.effector_budget.expect("budget debit").rows[0].used,
            1
        );

        // Removing only the competing sender makes automatic faceted sending valid.
        vault.transition_channel_identity(
            &second,
            ChannelIdentityState::Released,
            None,
            1_001,
            None,
        )?;
        let automatic =
            vault.dispatch_outbound_intent(email_send_dispatch_request(actor, 2), &mut sink)?;
        assert_eq!(
            automatic.outcome,
            OutboundDispatchOutcome::DeliveredToChannel
        );
        assert_eq!(automatic.gate_outcome, "allow");
        assert_eq!(sink.senders, vec![Some(first), Some(first)]);
        assert_eq!(
            automatic.effector_budget.expect("budget debit").rows[0].used,
            2
        );
    }
    Ok(())
}

#[test]
fn absent_optional_sender_still_dispatches_with_and_without_a_connector_key()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for with_key in [false, true] {
        let (_tmp, vault) = temp_vault();
        let actor = auto_agent_actor(&vault)?;
        let actor_ref = actor.actor_entity_ref.expect("actor entity");
        put_policy_manifest_bytes(
            &vault,
            entity(0xD0),
            &policy_manifest(&actor_ref.to_hex(), "email", &["send"]),
        )?;
        if with_key {
            vault.register_connector_key(
                &entity(0xB7),
                ConnectorKeyRecord::active("email", Some(actor_ref), Vec::new(), 1_000),
            )?;
        }
        let mut sink = SenderRecordingSink::default();
        let result =
            vault.dispatch_outbound_intent(email_send_dispatch_request(actor, 0), &mut sink)?;
        assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
        assert_eq!(result.gate_outcome, "allow");
        assert_eq!(sink.senders, vec![None]);
    }
    Ok(())
}

// A provider double that applies an uncertain first call, then deduplicates a
// retry by the key the real pipeline supplies. A definite failure applies nothing.
#[derive(Default)]
struct RetrySenderSink {
    uncertain_first: bool,
    senders: Vec<Option<EntityId>>,
    keys: Vec<Option<String>>,
    effects: std::collections::BTreeSet<String>,
}

impl OutboundExecutionSink for RetrySenderSink {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.senders.push(request.channel_identity_ref);
        self.keys.push(request.idempotency_key.map(str::to_owned));
        let first = self.senders.len() == 1;
        if !first || self.uncertain_first {
            self.effects.insert(
                request
                    .idempotency_key
                    .map_or_else(|| format!("call:{}", self.senders.len()), str::to_owned),
            );
        }
        if first {
            let failed = OutboundExecutionOutcome::failed("sender-retry:first-call");
            if self.uncertain_first {
                failed.with_possible_delivery()
            } else {
                failed
            }
        } else {
            OutboundExecutionOutcome::delivered_to_channel("provider:sender-retry")
        }
    }
}

fn install_sender_retry_policy(vault: &Vault, actor: EntityId) -> crate::Result<()> {
    put_policy_manifest_bytes(
        vault,
        entity(0xD0),
        &policy_manifest(&actor.to_hex(), "email", &["send", "replace"]),
    )?;
    vault.register_connector_key(
        &entity(0xB7),
        ConnectorKeyRecord::active(
            "email",
            Some(actor),
            vec![EffectorBudget::sends(
                10,
                EffectorBudgetWindow::Rolling { duration_s: 86_400 },
                EffectorBudgetOnExhaust::Suspend,
            )],
            1_000,
        ),
    )?;
    vault.put_entity(
        &entity(0x91),
        crate::registry::ENTITY_TYPE_FACET,
        TimeRange {
            start: 1_000,
            end: 1_000,
        },
        1_000,
        b"retry sender facet",
    )
}

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

#[derive(Clone)]
struct SharedRetrySink(std::sync::Arc<std::sync::Mutex<RetrySenderSink>>);

impl OutboundExecutionSink for SharedRetrySink {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.0.lock().expect("provider lock").execute(request)
    }
}

#[test]
fn concurrent_first_admissions_bind_one_sender_principal_and_request()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use crate::outbound_chokepoint::BEFORE_NEW_ADMISSION;
    use crate::outbound_intent_ledger::{IntentLedgerError, IntentState};
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::Duration;

    for axis in [
        "sender",
        "actor",
        "target",
        "permission",
        "risk",
        "verb",
        "same",
    ] {
        let (_tmp, vault) = temp_vault();
        let actor = auto_agent_actor(&vault)?;
        let actor_ref = actor.actor_entity_ref.expect("actor");
        install_sender_retry_policy(&vault, actor_ref)?;
        for sender in [entity(0x93), entity(0x94)] {
            put_sending_identity(&vault, sender, ChannelIdentityBinding::actor(actor_ref))?;
        }
        let mut request = email_send_dispatch_request(actor, 0).channel_identity_ref(entity(0x93));
        request.intent.verb = "replace".to_owned();
        request.ledger_identity_ref = Some("intent:concurrent-first-admission".to_owned());
        let mut competing = request.clone();
        match axis {
            "sender" => competing.channel_identity_ref = Some(entity(0x94)),
            "actor" => {
                competing.actor = crate::outbound::OutboundDispatchActor::agent(entity(0x95));
            }
            "target" => competing.intent.target = "other@example.com".to_owned(),
            "permission" => competing.gate.has_permission = false,
            "risk" => {
                competing.gate.policy_risk =
                    crate::outbound::OutboundDispatchPolicyRisk::HoldToProposal;
            }
            "verb" => competing.intent.verb = "send".to_owned(),
            "same" => {}
            _ => unreachable!(),
        }
        let provider = Arc::new(Mutex::new(RetrySenderSink {
            uncertain_first: true,
            ..Default::default()
        }));
        let mut sink = SharedRetrySink(Arc::clone(&provider));
        let gates_before = vault.gate_decisions(100)?.len();
        let (first, second, admitted) = std::thread::scope(|scope| {
            let vault = &vault;
            let (ready_tx, ready_rx) = mpsc::channel();
            let (first_tx, first_rx) = mpsc::channel();
            let (second_tx, second_rx) = mpsc::channel();
            let ready_first = ready_tx.clone();
            let first_request = request.clone();
            let mut first_sink = sink.clone();
            let first = scope.spawn(move || {
                BEFORE_NEW_ADMISSION.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        ready_first.send(()).expect("first prepared");
                        first_rx
                            .recv_timeout(Duration::from_secs(10))
                            .expect("release first");
                    }));
                });
                vault.dispatch_outbound_intent(first_request, &mut first_sink)
            });
            let mut second_sink = sink.clone();
            let second = scope.spawn(move || {
                BEFORE_NEW_ADMISSION.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        ready_tx.send(()).expect("second prepared");
                        second_rx
                            .recv_timeout(Duration::from_secs(10))
                            .expect("release second");
                    }));
                });
                vault.dispatch_outbound_intent(competing, &mut second_sink)
            });
            // Both calls have read an EMPTY ledger and frozen their bindings.
            // Release one writer, then the other with its now-stale preparation.
            // No timing sleeps: the old payload-id-only admission admits both.
            for _ in 0..2 {
                ready_rx
                    .recv_timeout(Duration::from_secs(10))
                    .expect("both prepared");
            }
            first_tx.send(()).expect("admit first");
            let first = first.join().expect("first dispatch thread");
            let admitted = intent_ledger_records(vault).expect("first durable row");
            second_tx.send(()).expect("admit second");
            (
                first,
                second.join().expect("second dispatch thread"),
                admitted,
            )
        });
        assert_eq!(first?.outcome, OutboundDispatchOutcome::Failed);
        assert_eq!(admitted.records.len(), 1);
        assert_eq!(admitted[0].state, IntentState::Pending);
        assert_eq!(admitted[0].recorded_outcome, None);
        if axis == "same" {
            let replay = second?;
            assert_eq!(replay.outcome, OutboundDispatchOutcome::DeliveredToChannel);
            assert!(replay.gate_decision_id.is_none());
            assert!(replay.effector_budget.is_none());
        } else {
            assert!(
                matches!(
                    second,
                    Err(OutboundDispatchError::Chokepoint(
                        IntentLedgerError::InvalidRecord(_)
                    ))
                ),
                "{axis}"
            );
            assert_eq!(
                provider.lock().expect("provider").senders.len(),
                1,
                "{axis}"
            );
            assert_eq!(intent_ledger_records(&vault)?.records, admitted.records);
            let replay = vault.dispatch_outbound_intent(request.clone(), &mut sink)?;
            assert_eq!(replay.outcome, OutboundDispatchOutcome::DeliveredToChannel);
        }
        let done = intent_ledger_records(&vault)?;
        assert!(done.corrupt.is_empty());
        assert_eq!(done.records.len(), 1);
        assert_eq!(done[0].id, admitted[0].id);
        assert_eq!(done[0].payload(), admitted[0].payload());
        assert_eq!(done[0].budget_accounting, admitted[0].budget_accounting);
        assert_eq!(done[0].state, IntentState::Done);
        let deduped = vault.dispatch_outbound_intent(request, &mut sink)?;
        assert_eq!(deduped.outcome, OutboundDispatchOutcome::DeliveredToChannel);
        let provider = provider.lock().expect("provider");
        assert_eq!(provider.senders, vec![Some(entity(0x93)); 2]);
        assert_eq!(provider.keys[0], provider.keys[1]);
        assert!(provider.keys[0].is_some());
        assert_eq!(provider.effects.len(), 1);
        assert_eq!(vault.gate_decisions(100)?.len(), gates_before + 1);
        assert_eq!(
            vault
                .effector_budget_read("email", Some(&actor_ref))?
                .expect("budget")
                .rows[0]
                .used,
            1
        );
    }
    Ok(())
}

#[test]
fn exact_attempt_lookup_isolates_corruption_and_refuses_unindexed_ledger()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use crate::outbound_intent_ledger::IntentLedgerError;

    let (_tmp, vault) = temp_vault();
    let actor = auto_agent_actor(&vault)?;
    install_sender_retry_policy(&vault, actor.actor_entity_ref.expect("actor"))?;
    let request = email_send_dispatch_request(actor.clone(), 0);
    let mut sink = SenderRecordingSink::default();
    vault.dispatch_outbound_intent(request.clone(), &mut sink)?;
    let admitted = intent_ledger_records(&vault)?;
    let mut key = b"outbound:intent_ledger:v2:".to_vec();
    key.extend_from_slice(&admitted[0].id);
    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .vault_meta
        .put(&mut wtxn, &key, b"corrupt row")?;
    wtxn.commit()?;
    let error = vault
        .dispatch_outbound_intent(request, &mut sink)
        .expect_err("corrupt target");
    assert!(matches!(
        error,
        OutboundDispatchError::Chokepoint(IntentLedgerError::InvalidRecord(_))
    ));
    assert_eq!(sink.senders.len(), 1);
    let fresh = email_send_dispatch_request(actor.clone(), 1);
    let delivered = vault.dispatch_outbound_intent(fresh.clone(), &mut sink)?;
    assert_eq!(
        delivered.outcome,
        OutboundDispatchOutcome::DeliveredToChannel
    );
    assert_eq!(
        sink.senders.len(),
        2,
        "unrelated corruption must not block a fresh call"
    );
    let healthy = intent_ledger_records(&vault)?.records.remove(0);
    let mut index_key = b"outbound:intent_attempt:v1:".to_vec();
    index_key.extend_from_slice(healthy.attempt_id.as_bytes());
    index_key.extend_from_slice(&healthy.call_seq.to_be_bytes());
    for bad_pointer in [b"bad index".to_vec(), vec![0xEE; 32]] {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .vault_meta
            .put(&mut wtxn, &index_key, &bad_pointer)?;
        wtxn.commit()?;
        let error = vault
            .dispatch_outbound_intent(fresh.clone(), &mut sink)
            .expect_err("invalid or dangling index pointer must fail closed");
        assert!(matches!(
            error,
            OutboundDispatchError::Chokepoint(IntentLedgerError::InvalidRecord(_))
        ));
        assert_eq!(sink.senders.len(), 2);
    }
    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .vault_meta
        .delete(&mut wtxn, b"outbound:intent_attempt_format")?;
    wtxn.commit()?;
    let error = vault
        .dispatch_outbound_intent(email_send_dispatch_request(actor, 2), &mut sink)
        .expect_err("nonempty ledger without index format must fail closed");
    assert!(matches!(
        error,
        OutboundDispatchError::Chokepoint(IntentLedgerError::InvalidRecord(_))
    ));
    assert_eq!(sink.senders.len(), 2);
    Ok(())
}
