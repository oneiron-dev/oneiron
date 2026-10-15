//! Intent shape, verb capability contract, manifests and pipeline execute-and-receipt core.

use super::*;

#[test]
fn every_outbound_verb_declares_the_closed_seven_field_contract() {
    assert_eq!(
        OUTBOUND_VERB_FIELD_CONTRACT,
        [
            "kind",
            "channel_call",
            "params",
            "interruption_class",
            "delivery_semantics",
            "retry_class",
            "capability_vs_permission",
        ]
    );

    for manifest in outbound_capability_manifests() {
        assert_eq!(
            manifest.manifest_version, OUTBOUND_CAPABILITY_MANIFEST_VERSION,
            "{} uses an unexpected manifest version",
            manifest.connector
        );
        assert!(
            !manifest.verbs.is_empty(),
            "{} must expose at least one outbound verb",
            manifest.connector
        );
        for verb in &manifest.verbs {
            let value = serde_json::to_value(verb).expect("serialize outbound verb");
            let object = value.as_object().expect("verb serializes as object");
            let fields = object.keys().map(String::as_str).collect::<Vec<_>>();
            assert_eq!(
                fields, OUTBOUND_VERB_FIELD_CONTRACT,
                "{}.{} drifted from the closed field contract",
                manifest.connector, verb.kind
            );
            assert!(
                verb.capability_vs_permission.capability,
                "{}.{} must describe a capability",
                manifest.connector, verb.kind
            );
        }
    }
}

#[test]
fn dispatch_pipeline_resolves_gates_executes_and_emits_receipt()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0x51);
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
    put_policy_manifest_bytes(
        &vault,
        entity(0xD0),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;

    let intent = dispatch_intent(
        OutboundIntentTrigger::agent_immediate("session:send-now").job_ref("brief:party"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:invite-kenji",
        "intent:invite-kenji",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_000,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .counterparty_ref("counterparty:kenji");

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(
        executor.calls,
        vec![(
            "intent:invite-kenji".to_owned(),
            "email".to_owned(),
            "send".to_owned()
        )]
    );
    assert_eq!(result.gate_outcome, "allow");
    assert_eq!(result.gate_reason_codes, vec!["gate.allow"]);
    assert_eq!(
        result
            .receipt
            .fields
            .get("gate_decision_ref")
            .map(String::as_str),
        result.gate_decision_id.as_deref()
    );
    assert!(!result.receipt.fields.contains_key("gate_decision_id"));
    assert_eq!(result.receipt.outcome, "delivered_to_channel");
    assert_eq!(
        result
            .receipt
            .fields
            .get("channel_call")
            .map(String::as_str),
        Some("send_email")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("provider_ref")
            .map(String::as_str),
        Some("provider:message:one")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("idempotency_key")
            .map(String::as_str),
        Some("idem:invite-kenji")
    );
    assert_eq!(
        result.receipt.fields.get("dedupe_key").map(String::as_str),
        Some("dedupe:invite-kenji")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_action")
            .map(String::as_str),
        Some("deliver_now")
    );
    assert!(
        result
            .receipt
            .policy_trace
            .contains(&"delivery_window.no_restriction".to_owned())
    );
    Ok(())
}

#[test]
fn verified_dispatch_classifies_a_missing_bound_actor_as_authorization_failure() {
    let (_tmp, vault) = temp_vault();
    let missing_actor = entity(0x52);
    let request = OutboundDispatchRequest::new(
        "outbound:intent:missing-actor",
        "intent:missing-actor",
        dispatch_intent(OutboundIntentTrigger::agent_immediate(
            "session:missing-actor",
        )),
        OutboundDispatchActor::agent(missing_actor),
        OutboundDispatchGate::allow_when_policy_grants(),
        1_001,
        OutboundDeliveryWindowDecision::DeliverNow,
    );
    let mut executor = RecordingExecutor::default();

    let err = OutboundDispatchPipeline
        .dispatch_with_verified_actor(
            &vault,
            request,
            &mut executor,
            missing_actor,
            EdgeActorClass::Agent,
        )
        .expect_err("missing bound actor must fail closed");

    assert!(matches!(err, OutboundDispatchError::InvalidBoundActor));
    assert!(executor.calls.is_empty());
}

#[test]
fn unsupported_connector_verb_is_typed_and_actionable() {
    let error = outbound_verb_contract("line", "edit").expect_err("line edit unsupported");

    assert_eq!(error.connector(), "line");
    assert_eq!(error.verb(), Some("edit"));
    assert!(error.connector_known());
    assert!(
        error.supported_verbs().contains(&"send".to_owned()),
        "known connector errors should include supported verbs"
    );
    assert!(
        error
            .recovery_suggestions()
            .iter()
            .any(|suggestion| suggestion.contains("/v1/core/outbound/capabilities/line")),
        "unsupported errors must tell clients how to recover"
    );

    let error = outbound_verb_contract("unknown-connector", "send")
        .expect_err("unknown connector unsupported");
    assert!(!error.connector_known());
    assert!(error.supported_verbs().is_empty());
    assert!(
        error.supported_connectors().contains(&"slack".to_owned()),
        "unknown connector errors should include registered connectors"
    );
}

#[test]
fn dispatch_rejects_unsupported_tapback_before_transport() {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0x53);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    let mut executor = RecordingExecutor::default();
    for channel in ["line", "imessage_mfb", "email"] {
        let intent = OutboundIntent::from_trigger(
            OutboundIntentDraft::new("agent-alpha", "react", channel, "message:target"),
            OutboundIntentTrigger::agent_immediate("session:tapback"),
        );
        let request = OutboundDispatchRequest::new(
            format!("outbound:intent:{channel}-tapback"),
            format!("intent:{channel}-tapback"),
            intent,
            OutboundDispatchActor::agent(entity(0x53)),
            OutboundDispatchGate::allow_when_policy_grants(),
            1_020,
            OutboundDeliveryWindowDecision::DeliverNow,
        );
        let error = vault
            .dispatch_outbound_intent(request, &mut executor)
            .expect_err("unsupported tapback must fail before transport");
        match error {
            OutboundDispatchError::UnsupportedCapability(error) => {
                assert_eq!(error.connector(), channel);
                assert_eq!(error.verb(), Some("react"));
                assert!(error.connector_known());
            }
            other => panic!("expected typed unsupported capability, got {other}"),
        }
    }
    assert!(executor.calls.is_empty());
}

#[test]
fn semantic_cooldown_survives_reopen() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (tmp, vault) = temp_vault();
    let actor_id = entity(0x72);
    vault.put_entity(
        &actor_id,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"actor",
    )?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x73),
        &policy_manifest(&actor_id.to_hex(), "email", &["send"]),
    )?;
    let request = |name: &str| {
        let mut intent = dispatch_intent(OutboundIntentTrigger::agent_immediate(format!(
            "session:{name}"
        )));
        intent.idempotency_key = Some(format!("idem:{name}"));
        OutboundDispatchRequest::new(
            format!("receipt:{name}"),
            format!("intent:{name}"),
            intent,
            OutboundDispatchActor::agent(actor_id),
            OutboundDispatchGate::allow_when_policy_grants(),
            1_000,
            OutboundDeliveryWindowDecision::DeliverNow,
        )
    };
    vault.clock.set(1_000);
    let mut first_sink = RecordingExecutor::default();
    assert_eq!(
        vault
            .dispatch_outbound_intent(request("first"), &mut first_sink)?
            .outcome,
        OutboundDispatchOutcome::DeliveredToChannel
    );
    drop(vault);
    let clock = crate::ports::ManualClock::new(1_001);
    let reopened = Vault::open(
        tmp.path(),
        VaultConfig {
            store_clock: clock.bundle(),
            ..VaultConfig::default()
        },
    )?;
    let mut second_sink = RecordingExecutor::default();
    let result = reopened.dispatch_outbound_intent(request("second"), &mut second_sink)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::Suppressed);
    assert_eq!(
        result.receipt.fields.get("suppression").map(String::as_str),
        Some("dedupe")
    );
    assert!(second_sink.calls.is_empty());
    let before = reopened.gate_decisions(100)?.len();
    drop(reopened);
    let reopened = Vault::open(
        tmp.path(),
        VaultConfig {
            store_clock: crate::ports::ManualClock::new(1_002).bundle(),
            ..VaultConfig::default()
        },
    )?;
    let queried = reopened.receipts(
        crate::receipt::ReceiptQuery::new(10).with_kind(crate::receipt::ReceiptKind::Outbound),
    )?;
    assert_eq!(
        queried
            .iter()
            .filter(|row| row.receipt_id == result.receipt.receipt_id)
            .count(),
        1
    );
    let replay = reopened.dispatch_outbound_intent(request("second"), &mut second_sink)?;
    assert_eq!(replay.outcome, OutboundDispatchOutcome::Suppressed);
    assert_eq!(replay.receipt, result.receipt);
    assert_eq!(reopened.gate_decisions(100)?.len(), before);
    assert!(second_sink.calls.is_empty());
    Ok(())
}

#[test]
fn replicated_suppression_artifact_projects_on_another_vault()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use crate::batch::ENTITY_METADATA_HEADER_LEN;
    use crate::receipt::{ReceiptKind, ReceiptQuery};
    let (_tmp, source) = temp_vault();
    let actor = entity(0x78);
    source.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"actor",
    )?;
    put_policy_manifest_bytes(
        &source,
        entity(0x79),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    source.clock.set(1_000);
    let request = |name: &str| {
        let mut intent = dispatch_intent(OutboundIntentTrigger::agent_immediate(format!(
            "session:{name}"
        )));
        intent.idempotency_key = Some(format!("idem:{name}"));
        OutboundDispatchRequest::new(
            format!("receipt:{name}"),
            format!("intent:{name}"),
            intent,
            OutboundDispatchActor::agent(actor),
            OutboundDispatchGate::allow_when_policy_grants(),
            1_000,
            OutboundDeliveryWindowDecision::DeliverNow,
        )
    };
    let mut sink = RecordingExecutor::default();
    source.dispatch_outbound_intent(request("first"), &mut sink)?;
    let suppressed = source.dispatch_outbound_intent(request("second"), &mut sink)?;
    assert_eq!(suppressed.outcome, OutboundDispatchOutcome::Suppressed);
    let (_peer_tmp, peer) = temp_vault();
    // A replicated receipt uses its maintenance-kind batch door; an ordinary
    // public put cannot mint the record or substitute an ASSET at its id.
    let record = source
        .entities_by_type(crate::registry::ENTITY_TYPE_RECEIPT_RECORD)?
        .into_iter()
        .next()
        .expect("source receipt record");
    let raw = source.get_raw(&record)?.expect("source record");
    let at = crate::temporal::TimeRange {
        start: 1_000,
        end: 1_000,
    };
    assert!(
        peer.put_entity(
            &record,
            crate::registry::ENTITY_TYPE_RECEIPT_RECORD,
            at,
            1_000,
            &raw[ENTITY_METADATA_HEADER_LEN..]
        )
        .is_err()
    );
    let put_maintenance = |id: EntityId, body: &[u8]| -> crate::Result<()> {
        peer.with_write_txn(|txn| {
            crate::batch::apply_ops(
                &peer.store,
                &peer.config,
                &peer.analyzer,
                txn,
                vec![crate::batch::BatchOp::Put {
                    id,
                    entity_type: crate::registry::ENTITY_TYPE_RECEIPT_RECORD,
                    occurred: at,
                    learned_at: 1_000,
                    data: body.to_vec(),
                    allow_maintenance: true,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                }],
                peer.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                false,
                true,
            )
        })
    };
    put_maintenance(record, &raw[ENTITY_METADATA_HEADER_LEN..])?;
    for (id, body) in [
        (entity(0x85), &raw[ENTITY_METADATA_HEADER_LEN..]),
        (record, &b"bad receipt"[..]),
    ] {
        assert!(put_maintenance(id, body).is_err());
    }
    assert!(
        peer.put_entity(
            &record,
            crate::registry::ENTITY_TYPE_ASSET,
            at,
            1_000,
            b"ordinary content"
        )
        .is_err()
    );
    assert!(peer.delete_entity(&record).is_err());
    let projected = peer.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?;
    assert_eq!(projected, vec![suppressed.receipt]);
    let scan = peer.scan_receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?;
    assert_eq!(scan.records, projected);
    Ok(())
}

#[test]
fn suppressed_approve_once_replays_without_spending_the_unused_approval()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use crate::consent::{
        ActionClass, ActionEnvelope, ActorBound, ComposedEffect, EffectFacts, GrantBound,
        UndoFidelity,
    };
    let (_tmp, vault) = temp_vault();
    let actor = entity(0x7c);
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"actor",
    )?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x7d),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    let request = |name: &str, at: u64| {
        let mut intent = dispatch_intent(OutboundIntentTrigger::agent_immediate(format!(
            "session:{name}"
        )));
        intent.idempotency_key = Some(format!("idem:{name}"));
        OutboundDispatchRequest::new(
            format!("receipt:{name}"),
            format!("intent:{name}"),
            intent,
            OutboundDispatchActor::agent(actor),
            OutboundDispatchGate::allow_when_policy_grants(),
            at,
            OutboundDeliveryWindowDecision::DeliverNow,
        )
    };
    vault.clock.set(1_000);
    let mut sink = RecordingExecutor::default();
    assert_eq!(
        vault
            .dispatch_outbound_intent(request("first", 1_000), &mut sink)?
            .outcome,
        OutboundDispatchOutcome::DeliveredToChannel
    );
    let owner_id = entity(0x7e);
    vault.put_entity(
        &owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let mut facts = EffectFacts::new("external:email:send")?;
    facts.fires_hooks = true;
    facts.triggers_publish = true;
    facts.external_observers = true;
    facts.undo_fidelity = UndoFidelity::None;
    let bound = GrantBound::action(
        ActorBound::new(actor.to_hex())?,
        ActionClass::new("send")?,
        ActionEnvelope::new(["verb:send".to_owned()])?.with_target("email")?,
    )?;
    let digest = ComposedEffect::new(facts)
        .with_action_requirement(bound)?
        .digest();
    vault.approve_once(&owner, digest)?;
    let second = request("second", 1_001);
    let suppression = vault.dispatch_outbound_intent(second.clone(), &mut sink)?;
    assert_eq!(suppression.outcome, OutboundDispatchOutcome::Suppressed);
    assert_eq!(
        vault.dispatch_outbound_intent(second, &mut sink)?.receipt,
        suppression.receipt
    );
    vault.clock.set(87_401);
    // If suppression spent the marker, Gate evaluation refuses this send
    // with ConsentApproveOnceSpent before it can reach the connector.
    assert_eq!(
        vault
            .dispatch_outbound_intent(request("third", 87_401), &mut sink)?
            .outcome,
        OutboundDispatchOutcome::DeliveredToChannel
    );
    assert_eq!(sink.calls.len(), 2);
    Ok(())
}
