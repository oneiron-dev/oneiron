//! Common vault/actor helpers plus the scoped-MCP fixture shared by the 1690 and 1691 oracles.

use rmpv::Value;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::outbound_chokepoint::{PreparedAuthorization, PreparedEffect};
use crate::outbound_consent::{DataClass, OutboundBindingAuthority, ScopedMcpCallContext};
use crate::outbound_grant::ScopedMcpGrantMintIntent;
use crate::outbound_intent_ledger::BudgetClass;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

pub(super) fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    (dir, vault)
}

pub(super) fn t(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

pub(super) fn empty_map_body() -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &Value::Map(Vec::new())).expect("encode empty map");
    body
}

pub(super) fn person_actor(vault: &Vault, seed: u8, class: EdgeActorClass) -> WriteActor {
    let id = EntityId::from_bytes([seed; 16]).expect("actor id");
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, t(1), 1, b"oracle actor")
        .expect("put actor");
    WriteActor::new(id, class)
}

pub(super) struct OracleScopedFixture {
    pub(super) grant_id: EntityId,
    pub(super) principal_ref: String,
    pub(super) call: ScopedMcpCallContext,
    pub(super) authority: OutboundBindingAuthority,
}

pub(super) fn install_oracle_scoped_fixture(vault: &Vault) -> OracleScopedFixture {
    let grant_id = EntityId::from_bytes([0x90; 16]).expect("grant id");
    let principal_ref = "principal:oracle".to_owned();
    vault
        .mint_scoped_mcp_outbound_grant(
            &grant_id,
            &ScopedMcpGrantMintIntent {
                principal_ref: principal_ref.clone(),
                origin_component_id: "consent:oracle".to_owned(),
                origin_action_id: "grant:oracle".to_owned(),
                origin_receipt_ref: Some("gate:oracle".to_owned()),
                server: "files".to_owned(),
                tool: "read_file".to_owned(),
                data_class_ceiling: DataClass::Personal,
                endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
            },
            10,
        )
        .expect("mint oracle scoped grant");
    vault
        .register_connector_key(
            &EntityId::from_bytes([0x92; 16]).expect("connector key id"),
            crate::connector_key::ConnectorKeyRecord::active(
                crate::connector_key::ScopedCapabilityProvenance::mint("files", &grant_id)
                    .expect("safe canonical scoped server")
                    .connector(),
                None,
                vec![crate::connector_key::EffectorBudget::sends(
                    100,
                    crate::connector_key::EffectorBudgetWindow::Calendar {
                        period: crate::connector_key::CalendarPeriod::Day,
                        tz: None,
                    },
                    crate::connector_key::EffectorBudgetOnExhaust::Refuse,
                )],
                10,
            ),
        )
        .expect("register active scoped connector key");
    OracleScopedFixture {
        grant_id,
        principal_ref,
        call: ScopedMcpCallContext {
            server: "files".to_owned(),
            tool: "read_file".to_owned(),
            payload_data_class: DataClass::Personal,
            resolved_endpoint: "https://files.internal.example".to_owned(),
        },
        authority: OutboundBindingAuthority::for_vault(vault).expect("binding authority"),
    }
}

pub(super) fn oracle_prepared_effect(
    fixture: &OracleScopedFixture,
    attempt_id: AttemptId,
    call_seq: u64,
    payload: Vec<u8>,
    idempotency_supported: bool,
) -> PreparedEffect {
    let call = fixture.call.clone();
    PreparedEffect {
        attempt_id,
        call_seq,
        server: call.server.clone(),
        tool: call.tool.clone(),
        payload,
        idempotency_supported,
        resolved_endpoint: Some(call.resolved_endpoint.clone()),
        gate: crate::gate::ExternalEffectGateInput {
            actor: crate::gate::GateActor {
                actor_class: "first_party".to_owned(),
                actor_ref: Some(fixture.principal_ref.clone()),
                delegation_grant_ref: None,
            },
            provenance: crate::gate::GateProvenanceHandles {
                actor_entity_ref: Some(fixture.grant_id),
                ..crate::gate::GateProvenanceHandles::default()
            },
            verb: "send".to_owned(),
            channel: format!("mcp:{}", call.server),
            channel_identity_ref: None,
            counterparty: None,
            brief_ref: None,
            send_ref: None,
            standing_grant_ref: None,
            scoped_mcp_call: Some(call.clone()),
            counterparty_first_touch: None,
            counterparty_opted_out: false,
            counterparty_opt_out_receipt_reason: None,
            has_opted_in: false,
            has_permission: false,
            policy_risk: crate::gate::ExternalEffectPolicyRisk::Normal,
        },
        budget_class: BudgetClass::Send,
        authorization: PreparedAuthorization::ScopedMcp {
            grant_id: fixture.grant_id,
            principal_ref: fixture.principal_ref.clone(),
            call,
        },
        verified_actor: None,
    }
}
