//! Common vault/actor helpers plus the scoped-MCP fixture shared by the 1690 and 1691 oracles.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::config::VaultConfig;
use crate::entity_id::EntityId;
use crate::outbound_chokepoint::{PreparedAuthorization, PreparedEffect};
use crate::outbound_consent::{DataClass, OutboundBindingAuthority, ScopedMcpCallContext};
use crate::outbound_grant::ScopedMcpGrantMintIntent;
use crate::outbound_intent_ledger::BudgetClass;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;

pub(super) fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    (dir, vault)
}

pub(super) fn t(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

pub(super) struct OracleScopedFixture {
    pub(super) grant_id: EntityId,
    pub(super) key_id: EntityId,
    pub(super) principal_ref: String,
    pub(super) call: ScopedMcpCallContext,
    pub(super) authority: OutboundBindingAuthority,
}

pub(super) fn install_oracle_scoped_fixture(vault: &Vault) -> OracleScopedFixture {
    struct Suite;
    impl crate::connector_key::ConnectorManifestQualifier for Suite {
        fn qualify(
            &self,
            _: &crate::connector_key::ResolvedConnectorManifest,
            _: &str,
        ) -> crate::error::Result<String> {
            Ok("a".repeat(64))
        }
    }

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
                tool_data_classes: vec![
                    crate::outbound_consent::tool_call::ToolGrantDataClass::Arguments,
                ],
                endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
            },
            10,
        )
        .expect("mint oracle scoped grant");
    let key_id = EntityId::from_bytes([0x92; 16]).expect("connector key id");
    vault
        .register_connector_key(
            &key_id,
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
        .expect("register pending scoped connector key");
    let manifest = crate::connector_key::ResolvedConnectorManifest::resolve(vec![
        crate::connector_key::ConnectorToolSchema {
            name: "read_file".into(),
            permissions: ["read".into()].into(),
            triggers: Default::default(),
            input_schema: serde_json::json!({"properties": {}}),
        },
    ])
    .expect("resolved oracle schema");
    vault
        .stage_connector_manifest(&key_id, manifest.clone(), "R1", &Suite, 11)
        .expect("qualify oracle");
    let owner = EntityId::now();
    vault
        .put_entity(&owner, ENTITY_TYPE_PERSON, t(1), 1, b"owner")
        .expect("owner person");
    let auth = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::from_bytes(*EntityId::now().as_bytes()),
        )
        .expect("owner auth");
    let candidate = vault
        .get_connector_key(&key_id)
        .unwrap()
        .unwrap()
        .pending_manifest
        .unwrap()
        .candidate_id;
    vault
        .approve_connector_manifest(
            &auth,
            &key_id,
            candidate,
            manifest.hash().unwrap(),
            &"a".repeat(64),
            12,
        )
        .expect("owner stamp");
    OracleScopedFixture {
        grant_id,
        key_id,
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
    vault: &Vault,
    fixture: &OracleScopedFixture,
    attempt_id: AttemptId,
    call_seq: u64,
    payload: Vec<u8>,
    idempotency_supported: bool,
) -> PreparedEffect {
    let call = fixture.call.clone();
    let prepared = vault
        .prepare_connector_tool_call(
            &fixture.key_id,
            call.clone(),
            crate::outbound_consent::tool_call::ToolCallDescriptor {
                schema: &serde_json::json!({"properties": {}}),
                destructive_hint: false,
                replay: crate::outbound_intent_ledger::OutboundToolDescriptor {
                    read_only_hint: Some(false),
                    idempotency_supported_hint: Some(idempotency_supported),
                },
            },
            &serde_json::json!({"fixture_bytes": payload}),
            crate::outbound_consent::tool_call::MutationIntent::default(),
        )
        .expect("prepare oracle tool call");
    PreparedEffect {
        attempt_id,
        call_seq,
        server: call.server.clone(),
        tool: call.tool.clone(),
        payload: prepared.frozen_bytes().to_vec(),
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
            scoped_mcp_call: Some(call),
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
            prepared: Box::new(prepared),
        },
        verified_actor: None,
        dedupe_key: None,
        suppression_receipt: None,
    }
}
