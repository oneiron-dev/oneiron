//! Real preparation → owner grant → authorization → durable dispatch/recovery.
use super::*;
use crate::consent::AuthenticatedOwner;
use crate::outbound_consent::tool_call::{
    MutationIntent, PreparedToolCall, ToolCallDescriptor, ToolGrantDataClass, prepare_tool_call,
};
use crate::outbound_grant::StandingOutboundGrant;
use serde_json::{Value, json};

fn owner(vault: &Vault) -> AuthenticatedOwner {
    let actor = entity(0xB1);
    vault
        .put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"tool owner",
        )
        .unwrap();
    vault
        .authenticate_owner(
            actor,
            &actor.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap()
}

fn grant(vault: &Vault, classes: Vec<ToolGrantDataClass>) -> (EntityId, StandingOutboundGrant) {
    let owner = owner(vault);
    let id = entity(0xB2);
    let mut intent = scoped_intent();
    intent.principal_ref = owner.principal_ref().to_owned();
    intent.tool_data_classes = classes;
    let grant = vault
        .mint_scoped_mcp_outbound_grant_with_owner(&owner, &id, &intent, 10)
        .unwrap();
    register_active_scoped_connector_key_with_budget(vault, &id, "files", 100);
    (id, grant)
}

fn prepare(arguments: &Value, mutation: MutationIntent) -> PreparedToolCall {
    prepare_tool_call(
        scoped_call(),
        ToolCallDescriptor {
            schema: &json!({"properties": {
                "tenant": {"type": "string", "x-mcp-header": "X-Tenant"},
                "record": {"type": "string"},
                "dry_run": {"type": "boolean"}
            }}),
            destructive_hint: true,
            replay: fixture_descriptor(),
        },
        arguments,
        mutation,
    )
    .unwrap()
}

#[test]
fn missing_header_class_refuses_both_authorize_and_atomic_mint_despite_argument_grant() {
    let (_dir, vault) = temp_vault();
    let (id, grant) = grant(&vault, vec![ToolGrantDataClass::Arguments]);
    let authority = OutboundBindingAuthority::for_vault(&vault).unwrap();
    let prepared = prepare(
        &json!({"tenant": "original", "record": "r1"}),
        MutationIntent::default(),
    );
    let attempt = AttemptId::now();
    let expected =
        ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::ToolDataClassNotGranted);
    let authorization = authority
        .authorize_request(
            &vault,
            id,
            &grant,
            &grant.principal_ref,
            attempt,
            1,
            &prepared,
        )
        .unwrap();
    assert_eq!(authorization.decision, expected);
    assert!(authorization.binding.is_none());
    let txn = vault.store.env.write_txn().unwrap();
    let intent = crate::outbound_intent_ledger::derive_intent_id(
        attempt,
        1,
        &prepared.call().server,
        &prepared.call().tool,
        blake3::hash(prepared.frozen_bytes()).as_bytes(),
    )
    .unwrap();
    assert!(
        authority
            .mint_scoped_binding_in_txn(&vault, &txn, id, &grant.principal_ref, &intent, &prepared)
            .unwrap()
            .is_none()
    );
    drop(txn);
    let mut sender = RecordingResultSender::default();
    let result = prepared
        .execute(
            &vault,
            &authority,
            id,
            &grant,
            &grant.principal_ref,
            attempt,
            1,
            11,
            &mut sender,
        )
        .unwrap();
    assert_eq!(result.decision, expected);
    assert!(sender.sent_payloads.is_empty());
    assert!(intent_ledger_records(&vault).unwrap().is_empty());
}

#[test]
fn granted_headers_and_default_destructive_preview_survive_durable_recovery_byte_exactly() {
    let (dir, vault) = temp_vault();
    let (id, grant) = grant(
        &vault,
        vec![
            ToolGrantDataClass::Arguments,
            ToolGrantDataClass::XMcpHeader,
        ],
    );
    let authority = OutboundBindingAuthority::for_vault(&vault).unwrap();
    let mut arguments = json!({"tenant": "original", "record": "r1", "dry_run": false});
    let prepared = prepare(&arguments, MutationIntent::default());
    let expected = prepared.frozen_bytes().to_vec();
    arguments["tenant"] = json!("changed after preparation");
    let attempt = AttemptId::now();
    assert_eq!(
        authority
            .authorize_request(
                &vault,
                id,
                &grant,
                &grant.principal_ref,
                attempt,
                1,
                &prepared
            )
            .unwrap()
            .decision,
        ScopedMcpConsentDecision::AutoFire
    );
    let sent = prepared
        .execute(
            &vault,
            &authority,
            id,
            &grant,
            &grant.principal_ref,
            attempt,
            1,
            11,
            &mut AmbiguousResultSender,
        )
        .unwrap();
    assert_eq!(sent.dispatch.unwrap().state, Some(IntentState::Pending));
    let rows = intent_ledger_records(&vault).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].payload(), expected);
    let wire: Value = serde_json::from_slice(rows[0].payload()).unwrap();
    assert_eq!(wire["headers"]["x-tenant"], "original");
    assert!(wire["arguments"].get("tenant").is_none());
    assert_eq!(wire["arguments"]["dry_run"], true);
    assert_eq!(wire["grant_requirements"][0]["data_class"], "x_mcp_header");
    drop(rows);
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let authority = OutboundBindingAuthority::for_vault(&vault).unwrap();
    let mut sender = RecordingResultSender::default();
    let recovered =
        recover_authorized_outbound_intents(&vault, &authority, &mut sender, 12, 30_000).unwrap();
    assert_eq!(recovered.effectful_sends, 1);
    assert_eq!(sender.sent_payloads, vec![expected]);
    assert_eq!(
        intent_ledger_records(&vault).unwrap()[0].state,
        IntentState::Done
    );
}

#[test]
fn explicit_mutation_does_not_supply_missing_consent_or_relax_sensitivity() {
    for (classes, sensitivity, expected) in [
        (
            vec![ToolGrantDataClass::Arguments],
            DataClass::Personal,
            ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::ToolDataClassNotGranted),
        ),
        (
            vec![ToolGrantDataClass::XMcpHeader],
            DataClass::Personal,
            ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::ToolDataClassNotGranted),
        ),
        (
            vec![
                ToolGrantDataClass::Arguments,
                ToolGrantDataClass::XMcpHeader,
            ],
            DataClass::Secret,
            ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::DataClassCeilingExceeded),
        ),
        (
            vec![
                ToolGrantDataClass::Arguments,
                ToolGrantDataClass::XMcpHeader,
            ],
            DataClass::Personal,
            ScopedMcpConsentDecision::AutoFire,
        ),
    ] {
        let (_dir, vault) = temp_vault();
        let (id, grant) = grant(&vault, classes);
        let authority = OutboundBindingAuthority::for_vault(&vault).unwrap();
        let mut call = scoped_call();
        call.payload_data_class = sensitivity;
        let prepared = prepare_tool_call(
            call,
            ToolCallDescriptor {
                schema: &json!({"properties":{"tenant":{"x-mcp-header":"X-Tenant"},"dry_run":{"type":"boolean"}}}),
                destructive_hint: true,
                replay: fixture_descriptor(),
            },
            &json!({"tenant":"original", "dry_run":true}),
            MutationIntent::ExplicitMutation,
        )
        .unwrap();
        let attempt = AttemptId::now();
        let authorization = authority
            .authorize_request(
                &vault,
                id,
                &grant,
                &grant.principal_ref,
                attempt,
                1,
                &prepared,
            )
            .unwrap();
        assert_eq!(authorization.decision, expected);
        let mut sender = RecordingResultSender::default();
        let result = prepared
            .execute(
                &vault,
                &authority,
                id,
                &grant,
                &grant.principal_ref,
                attempt,
                1,
                11,
                &mut sender,
            )
            .unwrap();
        assert_eq!(result.decision, expected);
        if expected == ScopedMcpConsentDecision::AutoFire {
            assert_eq!(sender.sent_payloads.len(), 1);
            let rows = intent_ledger_records(&vault).unwrap();
            assert_eq!(rows[0].state, IntentState::Done);
            assert_eq!(
                serde_json::from_slice::<Value>(rows[0].payload()).unwrap()["arguments"]["dry_run"],
                false
            );
        } else {
            assert!(sender.sent_payloads.is_empty());
            assert!(intent_ledger_records(&vault).unwrap().is_empty());
        }
    }
}

#[test]
fn header_class_requires_owner_door_and_revocation_blocks_prepared_mutation() {
    let (_dir, vault) = temp_vault();
    let mut intent = scoped_intent();
    intent
        .tool_data_classes
        .push(ToolGrantDataClass::XMcpHeader);
    assert_eq!(
        vault
            .mint_scoped_mcp_outbound_grant(&entity(0xB3), &intent, 10)
            .unwrap_err()
            .kind(),
        crate::ErrorKind::ConsentOwnerNotAuthenticated
    );
    let (id, grant) = grant(&vault, intent.tool_data_classes);
    let authority = OutboundBindingAuthority::for_vault(&vault).unwrap();
    let prepared = prepare(
        &json!({"tenant":"original"}),
        MutationIntent::ExplicitMutation,
    );
    let attempt = AttemptId::now();
    assert!(
        authority
            .authorize_request(
                &vault,
                id,
                &grant,
                &grant.principal_ref,
                attempt,
                1,
                &prepared
            )
            .unwrap()
            .binding
            .is_some()
    );
    vault.revoke_standing_outbound_grant(&id, 11).unwrap();
    let mut sender = RecordingResultSender::default();
    let result = prepared
        .execute(
            &vault,
            &authority,
            id,
            &grant,
            &grant.principal_ref,
            attempt,
            1,
            12,
            &mut sender,
        )
        .unwrap();
    assert_eq!(
        result.decision,
        ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::InvalidGrant)
    );
    assert!(sender.sent_payloads.is_empty());
    assert!(intent_ledger_records(&vault).unwrap().is_empty());
}

fn prepared_effect(
    grant_id: EntityId,
    grant: &StandingOutboundGrant,
    prepared: PreparedToolCall,
) -> crate::outbound_chokepoint::PreparedEffect {
    let call = prepared.call().clone();
    crate::outbound_chokepoint::PreparedEffect {
        attempt_id: AttemptId::now(),
        call_seq: 1,
        server: call.server.clone(),
        tool: call.tool.clone(),
        payload: prepared.frozen_bytes().to_vec(),
        idempotency_supported: prepared.idempotency_supported(),
        resolved_endpoint: Some(call.resolved_endpoint.clone()),
        gate: crate::gate::ExternalEffectGateInput {
            actor: crate::gate::GateActor {
                actor_class: "first_party".to_owned(),
                actor_ref: Some(grant.principal_ref.clone()),
                delegation_grant_ref: None,
            },
            provenance: crate::gate::GateProvenanceHandles {
                actor_entity_ref: Some(EntityId::from_hex(&grant.principal_ref).unwrap()),
                ..Default::default()
            },
            verb: "send".to_owned(),
            channel: format!("mcp:{}", call.server),
            channel_identity_ref: None,
            counterparty: None,
            brief_ref: None,
            send_ref: None,
            standing_grant_ref: None,
            scoped_mcp_call: Some(call),
            counterparty_first_touch: None,
            counterparty_opted_out: false,
            counterparty_opt_out_receipt_reason: None,
            has_opted_in: false,
            has_permission: false,
            policy_risk: crate::gate::ExternalEffectPolicyRisk::Normal,
        },
        budget_class: crate::outbound_intent_ledger::BudgetClass::Send,
        authorization: crate::outbound_chokepoint::PreparedAuthorization::ScopedMcp {
            grant_id,
            principal_ref: grant.principal_ref.clone(),
            prepared,
        },
        verified_actor: None,
    }
}

#[test]
fn raw_payload_cannot_replace_preparation_or_downgrade_to_unscoped_authority() {
    for downgrade in [false, true] {
        let (_dir, vault) = temp_vault();
        let (id, grant) = grant(
            &vault,
            vec![
                ToolGrantDataClass::Arguments,
                ToolGrantDataClass::XMcpHeader,
            ],
        );
        let authority = OutboundBindingAuthority::for_vault(&vault).unwrap();
        let prepared = prepare(&json!({"tenant":"original"}), MutationIntent::default());
        let mut effect = prepared_effect(id, &grant, prepared);
        effect.payload =
            br#"{"arguments":{"dry_run":false},"headers":{"x-tenant":"raw bypass"}}"#.to_vec();
        if downgrade {
            effect.authorization = crate::outbound_chokepoint::PreparedAuthorization::None;
            effect.resolved_endpoint = None;
        }
        let mut sender = RecordingResultSender::default();
        let result = crate::outbound_chokepoint::execute_outbound_effect(
            &vault,
            &authority,
            crate::outbound_chokepoint::OutboundEffectCommand::New(effect),
            11,
            &mut crate::outbound_consent::execution::ScopedResultTransport::new(&mut sender),
        );
        assert!(matches!(
            result,
            Err(crate::outbound_intent_ledger::IntentLedgerError::InvalidInput(_))
        ));
        assert!(sender.sent_payloads.is_empty());
        assert!(intent_ledger_records(&vault).unwrap().is_empty());
    }
}
