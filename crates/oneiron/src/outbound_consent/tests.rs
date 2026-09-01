use super::*;
use crate::config::VaultConfig;
use crate::outbound_grant::ScopedMcpGrantMintIntent;
use crate::outbound_intent_ledger::{
    IntentEscalationReason, OUTBOUND_BINDING_VERSION, RecordedOutboundOutcome,
    intent_ledger_records,
};
use std::collections::VecDeque;

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::device()).expect("open vault");
    (tmp, vault)
}

use crate::test_util::entity;

fn scoped_intent() -> ScopedMcpGrantMintIntent {
    ScopedMcpGrantMintIntent {
        principal_ref: "principal:owner".to_owned(),
        origin_component_id: "consent:scope".to_owned(),
        origin_action_id: "grant:scoped_tool".to_owned(),
        origin_receipt_ref: Some("gate:scoped-tool".to_owned()),
        server: "files".to_owned(),
        tool: "read_file".to_owned(),
        data_class_ceiling: DataClass::Personal,
        endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
    }
}

fn scoped_call() -> ScopedMcpCallContext {
    ScopedMcpCallContext {
        server: "files".to_owned(),
        tool: "read_file".to_owned(),
        payload_data_class: DataClass::Personal,
        resolved_endpoint: "https://files.internal.example".to_owned(),
    }
}

/// The real engine-produced per-grant capability connector for one grant. It is
/// the ONLY way a test may spell a capability identity (ONE-1885).
fn scoped_capability_connector(server: &str, grant_id: &EntityId) -> String {
    crate::connector_key::ScopedCapabilityProvenance::mint(server, grant_id)
        .expect("safe canonical scoped server")
        .connector()
        .to_owned()
}

fn register_active_scoped_connector_key_with_budget(
    vault: &Vault,
    grant_id: &EntityId,
    server: &str,
    sends: u64,
) -> EntityId {
    register_active_scoped_connector_key_with_budgets(
        vault,
        grant_id,
        server,
        vec![crate::connector_key::EffectorBudget::sends(
            sends,
            crate::connector_key::EffectorBudgetWindow::Calendar {
                period: crate::connector_key::CalendarPeriod::Day,
                tz: None,
            },
            crate::connector_key::EffectorBudgetOnExhaust::Refuse,
        )],
    )
}

fn register_active_scoped_connector_key_with_budgets(
    vault: &Vault,
    grant_id: &EntityId,
    server: &str,
    budgets: Vec<crate::connector_key::EffectorBudget>,
) -> EntityId {
    let key_id = entity(0xD0);
    vault
        .register_connector_key(
            &key_id,
            crate::connector_key::ConnectorKeyRecord::active(
                scoped_capability_connector(server, grant_id),
                None,
                budgets,
                10,
            ),
        )
        .expect("register active scoped connector key");
    key_id
}

#[derive(Default)]
struct RecordingResultSender {
    sent_payloads: Vec<Vec<u8>>,
    sent_endpoints: Vec<Option<String>>,
}

impl OutboundResultSender for RecordingResultSender {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundTransportResult {
        self.sent_payloads.push(call.payload().to_vec());
        self.sent_endpoints
            .push(call.resolved_endpoint().map(str::to_owned));
        OutboundTransportResult {
            outcome: OutboundSendOutcome::Acked,
            raw_result: RawOutboundResult::new(None, None, None, None),
        }
    }
}

struct AmbiguousResultSender;

impl OutboundResultSender for AmbiguousResultSender {
    fn send(&mut self, _call: &FrozenOutboundCall) -> OutboundTransportResult {
        OutboundTransportResult {
            outcome: OutboundSendOutcome::Ambiguous,
            raw_result: RawOutboundResult::new(None, None, None, None),
        }
    }
}

struct ScriptedResultSender {
    outcomes: VecDeque<OutboundSendOutcome>,
    keys: Vec<String>,
}

impl OutboundResultSender for ScriptedResultSender {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundTransportResult {
        self.keys.push(
            call.idempotency_key()
                .expect("effect carries idempotency key")
                .to_owned(),
        );
        OutboundTransportResult {
            outcome: self.outcomes.pop_front().expect("scripted outcome"),
            raw_result: RawOutboundResult::new(None, None, None, None),
        }
    }
}

struct PaidPendingInspectingSender<'a> {
    vault: &'a Vault,
    governing_connector: String,
    calls: usize,
}

impl OutboundResultSender for PaidPendingInspectingSender<'_> {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundTransportResult {
        self.calls = self.calls.saturating_add(1);
        let rows = intent_ledger_records(self.vault).expect("read row at transport boundary");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, IntentState::Pending);
        assert_eq!(rows[0].recorded_outcome, None);
        assert_eq!(rows[0].budget_accounting.sends_debit, 1);
        assert_eq!(Some(&rows[0].id), call.intent_id());
        let budget = self
            .vault
            .effector_budget_read(&self.governing_connector, None)
            .expect("read paid budget")
            .expect("governing key");
        assert_eq!(budget.rows[0].used, 1);
        OutboundTransportResult {
            outcome: OutboundSendOutcome::Acked,
            raw_result: RawOutboundResult::new(None, None, None, None),
        }
    }
}

#[test]
fn data_class_order_and_unknown_parse_fail_closed() {
    assert!(DataClass::Public < DataClass::Personal);
    assert!(DataClass::Personal < DataClass::Secret);
    let unknown = DataClass::parse("internal");
    // Discriminating: treating an unknown spelling as Public would put it
    // below this ceiling and silently authorize it.
    assert!(unknown > DataClass::Secret);
    assert!(!unknown.is_grantable());
}

#[test]
fn scoped_call_matrix_counts_every_scope_exceed() {
    let endpoints = vec!["https://files.internal.example".to_owned()];
    let grant = ScopedMcpGrantRef {
        server: "files",
        tool: "read_file",
        data_class_ceiling: DataClass::Personal,
        endpoint_allowlist: &endpoints,
    };
    let in_scope = ScopedMcpCall {
        server: "files",
        tool: "read_file",
        payload_data_class: DataClass::Personal,
        resolved_endpoint: "https://files.internal.example",
    };

    let verdict = evaluate_scoped_mcp_calls(grant, &[in_scope]);
    assert_eq!(verdict.auto_fired, 1);
    assert_eq!(verdict.human_escalations, 0);

    let exceeds = [
        ScopedMcpCall {
            server: "calendar",
            ..in_scope
        },
        ScopedMcpCall {
            tool: "write_file",
            ..in_scope
        },
        ScopedMcpCall {
            resolved_endpoint: "https://exfil.example",
            ..in_scope
        },
        ScopedMcpCall {
            payload_data_class: DataClass::Secret,
            ..in_scope
        },
        ScopedMcpCall {
            payload_data_class: DataClass::Unclassified,
            ..in_scope
        },
    ];
    let verdict = evaluate_scoped_mcp_calls(grant, &exceeds);
    // Discriminating: bypassing any one axis increments auto_fired and drops
    // this exact escalation count.
    assert_eq!(verdict.auto_fired, 0);
    assert_eq!(verdict.human_escalations, 5);
}

#[test]
fn invalid_scoped_grant_strings_never_auto_fire() {
    let blank_endpoint = vec![" ".to_owned()];
    let valid_endpoint = vec!["https://files.internal.example".to_owned()];
    let matching_blank_server_call = ScopedMcpCall {
        server: " ",
        tool: "read_file",
        payload_data_class: DataClass::Personal,
        resolved_endpoint: "https://files.internal.example",
    };
    let matching_blank_endpoint_call = ScopedMcpCall {
        server: "files",
        tool: "read_file",
        payload_data_class: DataClass::Personal,
        resolved_endpoint: " ",
    };
    let decisions = [
        evaluate_scoped_mcp_call(
            ScopedMcpGrantRef {
                server: " ",
                tool: "read_file",
                data_class_ceiling: DataClass::Personal,
                endpoint_allowlist: &valid_endpoint,
            },
            matching_blank_server_call,
        ),
        evaluate_scoped_mcp_call(
            ScopedMcpGrantRef {
                server: "files",
                tool: "read_file",
                data_class_ceiling: DataClass::Personal,
                endpoint_allowlist: &blank_endpoint,
            },
            matching_blank_endpoint_call,
        ),
    ];

    // Discriminating: is_empty-only validation would auto-fire both matching
    // whitespace fixtures instead of producing two InvalidGrant escalations.
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| {
                **decision
                    == ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::InvalidGrant)
            })
            .count(),
        2
    );
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| **decision == ScopedMcpConsentDecision::AutoFire)
            .count(),
        0
    );
}

#[test]
fn binding_authenticity_and_endpoint_swap_fail_closed_at_chokepoint() {
    let (_tmp, vault) = temp_vault();
    let grant_id = entity(0x91);
    let mut intent = scoped_intent();
    intent
        .endpoint_allowlist
        .push("https://files-backup.internal.example".to_owned());
    let grant = vault
        .mint_scoped_mcp_outbound_grant(&grant_id, &intent, 10)
        .expect("mint scoped grant");
    register_active_scoped_connector_key_with_budget(&vault, &grant_id, "files", 100);
    let authority = OutboundBindingAuthority::for_vault(&vault).expect("binding authority");
    let descriptor = OutboundToolDescriptor {
        read_only_hint: Some(false),
        idempotency_supported_hint: Some(true),
    };
    let mut transport = RecordingResultSender::default();
    let valid = execute_scoped_mcp_outbound_call(
        &vault,
        &authority,
        grant_id,
        &grant,
        &grant.principal_ref,
        descriptor,
        AttemptId::from_bytes(&[0x31; 16]).expect("attempt id"),
        1,
        scoped_call(),
        FrozenMcpPayload::new(b"valid payload".to_vec()),
        11,
        &mut transport,
    )
    .expect("valid dispatch");
    assert_eq!(valid.effectful_sends, 1);
    assert_eq!(transport.sent_payloads.len(), 1);

    let mut ambiguous = AmbiguousResultSender;
    let pending = execute_scoped_mcp_outbound_call(
        &vault,
        &authority,
        grant_id,
        &grant,
        &grant.principal_ref,
        descriptor,
        AttemptId::from_bytes(&[0x32; 16]).expect("attempt id"),
        2,
        scoped_call(),
        FrozenMcpPayload::new(b"tampered payload".to_vec()),
        12,
        &mut ambiguous,
    )
    .expect("pending dispatch");
    assert_eq!(
        pending.dispatch.as_ref().and_then(|row| row.state),
        Some(IntentState::Pending)
    );
    let mut row = intent_ledger_records(&vault)
        .expect("read pending")
        .into_iter()
        .find(|row| row.state == IntentState::Pending)
        .expect("pending row");
    let mut binding = *row
        .authorization_binding
        .expect("scoped binding")
        .as_bytes();
    let pending_id = row.id;
    binding[0] ^= 1;
    row.authorization_binding = Some(OutboundAuthorizationBinding::new(binding));
    crate::outbound_intent_ledger::replace_intent_record_for_test(&vault, &row)
        .expect("persist MAC tamper with canonical digest");

    let recovered =
        recover_authorized_outbound_intents(&vault, &authority, &mut transport, 13, 30_000)
            .expect("tampered recovery");
    assert_eq!(recovered.effectful_sends, 0);
    assert_eq!(recovered.authorization_rejections, 1);
    assert_eq!(transport.sent_payloads.len(), 1);
    let row = intent_ledger_records(&vault)
        .expect("read abandoned")
        .into_iter()
        .find(|row| row.id == pending_id && row.state == IntentState::Abandoned)
        .expect("abandoned tampered row");
    assert_eq!(
        row.recorded_outcome,
        Some(RecordedOutboundOutcome::Abandoned(
            IntentEscalationReason::BindingInvalid
        ))
    );

    let mut ambiguous = AmbiguousResultSender;
    let pending = execute_scoped_mcp_outbound_call(
        &vault,
        &authority,
        grant_id,
        &grant,
        &grant.principal_ref,
        descriptor,
        AttemptId::from_bytes(&[0x33; 16]).expect("attempt id"),
        3,
        scoped_call(),
        FrozenMcpPayload::new(b"endpoint-bound payload".to_vec()),
        14,
        &mut ambiguous,
    )
    .expect("second pending dispatch");
    let pending_id = pending
        .dispatch
        .as_ref()
        .and_then(|dispatch| dispatch.intent_id)
        .expect("pending intent id");
    let mut row = intent_ledger_records(&vault)
        .expect("read endpoint-bound pending")
        .into_iter()
        .find(|row| row.id == pending_id)
        .expect("endpoint-bound pending row");
    row.resolved_endpoint = Some("https://files-backup.internal.example".to_owned());
    crate::outbound_intent_ledger::replace_intent_record_for_test(&vault, &row)
        .expect("persist allowlisted endpoint swap with canonical digest");

    let recovered =
        recover_authorized_outbound_intents(&vault, &authority, &mut transport, 15, 30_000)
            .expect("endpoint-swap recovery");
    assert_eq!(recovered.effectful_sends, 0);
    assert_eq!(recovered.authorization_rejections, 1);
    assert_eq!(transport.sent_payloads.len(), 1);
    let swapped_row = intent_ledger_records(&vault)
        .expect("read endpoint-swap abandonment")
        .into_iter()
        .find(|row| row.id == pending_id)
        .expect("endpoint-swap row");
    assert_eq!(swapped_row.state, IntentState::Abandoned);
    assert_eq!(
        swapped_row.recorded_outcome,
        Some(RecordedOutboundOutcome::Abandoned(
            IntentEscalationReason::BindingInvalid
        ))
    );

    let swapped = execute_scoped_mcp_outbound_call(
        &vault,
        &authority,
        grant_id,
        &grant,
        &grant.principal_ref,
        descriptor,
        AttemptId::from_bytes(&[0x34; 16]).expect("attempt id"),
        4,
        ScopedMcpCallContext {
            resolved_endpoint: "https://exfil.example".to_owned(),
            ..scoped_call()
        },
        FrozenMcpPayload::new(b"swapped endpoint".to_vec()),
        16,
        &mut transport,
    )
    .expect("endpoint swap rejected");
    assert_eq!(
        swapped.decision,
        ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::EndpointNotAllowed)
    );
    assert_eq!(swapped.effectful_sends, 0);
    assert_eq!(transport.sent_payloads.len(), 1);
}

#[test]
fn authorize_request_reloads_persisted_grant_liveness() {
    let (_tmp, vault) = temp_vault();
    let grant_id = entity(0x93);
    let stale_active_grant = vault
        .mint_scoped_mcp_outbound_grant(&grant_id, &scoped_intent(), 10)
        .expect("mint scoped grant");
    vault
        .revoke_standing_outbound_grant(&grant_id, 20)
        .expect("revoke persisted grant");
    let authority = OutboundBindingAuthority::for_vault(&vault).expect("binding authority");
    let authorization = authority
        .authorize_request(
            &vault,
            grant_id,
            &stale_active_grant,
            &stale_active_grant.principal_ref,
            AttemptId::from_bytes(&[0x34; 16]).expect("attempt id"),
            1,
            &scoped_call(),
            b"stale caller payload",
        )
        .expect("stale caller grant must fail closed");

    // Discriminating: trusting the caller-supplied Active object would mint a
    // binding even though the persisted row at the same id is revoked.
    assert_eq!(
        authorization.decision,
        ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::InvalidGrant)
    );
    assert_eq!(authorization.binding, None);
}

#[test]
fn scoped_mcp_authorization_is_bound_to_the_acting_principal() {
    let (_tmp, vault) = temp_vault();
    let grant_id = entity(0x94);
    let intent = scoped_intent();
    let principal_a = intent.principal_ref.clone();
    let principal_b = format!("{principal_a}:different");
    let grant = vault
        .mint_scoped_mcp_outbound_grant(&grant_id, &intent, 10)
        .expect("mint scoped grant");
    register_active_scoped_connector_key_with_budget(&vault, &grant_id, "files", 100);
    let authority = OutboundBindingAuthority::for_vault(&vault).expect("binding authority");
    let call = scoped_call();

    let wrong_principal = authority
        .authorize_request(
            &vault,
            grant_id,
            &grant,
            &principal_b,
            AttemptId::from_bytes(&[0x35; 16]).expect("attempt id"),
            1,
            &call,
            b"wrong principal payload",
        )
        .expect("wrong principal must fail closed");
    // Discriminating: without the principal check, caller B mints a valid
    // binding for caller A's grant.
    assert_eq!(
        wrong_principal.decision,
        ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::WrongPrincipal)
    );
    assert_eq!(wrong_principal.binding, None);

    let descriptor = OutboundToolDescriptor {
        read_only_hint: Some(false),
        idempotency_supported_hint: Some(true),
    };
    let mut transport = RecordingResultSender::default();
    let rejected = execute_scoped_mcp_outbound_call(
        &vault,
        &authority,
        grant_id,
        &grant,
        &principal_b,
        descriptor,
        AttemptId::from_bytes(&[0x36; 16]).expect("attempt id"),
        2,
        call.clone(),
        FrozenMcpPayload::new(b"rejected payload".to_vec()),
        11,
        &mut transport,
    )
    .expect("wrong principal dispatch must fail closed");
    assert_eq!(
        rejected.decision,
        ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::WrongPrincipal)
    );
    assert_eq!(rejected.dispatch, None);
    assert_eq!(rejected.effectful_sends, 0);
    assert!(transport.sent_payloads.is_empty());

    let authorized = execute_scoped_mcp_outbound_call(
        &vault,
        &authority,
        grant_id,
        &grant,
        &principal_a,
        descriptor,
        AttemptId::from_bytes(&[0x37; 16]).expect("attempt id"),
        3,
        call,
        FrozenMcpPayload::new(b"authorized payload".to_vec()),
        12,
        &mut transport,
    )
    .expect("matching principal dispatch");
    assert_eq!(authorized.decision, ScopedMcpConsentDecision::AutoFire);
    assert!(authorized.dispatch.is_some());
    assert_eq!(authorized.effectful_sends, 1);
    assert_eq!(transport.sent_payloads.len(), 1);
}

#[test]
fn suspended_scoped_mcp_connector_key_blocks_the_public_send_path() {
    let (_tmp, vault) = temp_vault();
    let grant_id = entity(0x95);
    let grant = vault
        .mint_scoped_mcp_outbound_grant(&grant_id, &scoped_intent(), 10)
        .expect("mint scoped grant");
    let key_id = register_active_scoped_connector_key_with_budget(&vault, &grant_id, "files", 100);
    vault
        .suspend_connector_key(&key_id, "owner", 11)
        .expect("suspend scoped connector key");
    let authority = OutboundBindingAuthority::for_vault(&vault).expect("binding authority");
    let mut transport = RecordingResultSender::default();

    let refused = execute_scoped_mcp_outbound_call(
        &vault,
        &authority,
        grant_id,
        &grant,
        &grant.principal_ref,
        OutboundToolDescriptor {
            read_only_hint: Some(false),
            idempotency_supported_hint: Some(true),
        },
        AttemptId::from_bytes(&[0x51; 16]).expect("attempt id"),
        1,
        scoped_call(),
        FrozenMcpPayload::new(b"blocked payload".to_vec()),
        12,
        &mut transport,
    )
    .expect("suspended connector key refuses without a send");

    // Discriminating: a live in-scope grant is present, so omitting the
    // send-path status wall produces one transport send here.
    assert_eq!(
        refused.decision,
        ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::ConnectorKeySuspended)
    );
    assert_eq!(refused.dispatch, None);
    assert_eq!(refused.effectful_sends, 0);
    assert!(transport.sent_payloads.is_empty());
}

#[test]
fn drifted_scoped_mcp_connector_charter_blocks_the_direct_send_path() {
    let (_tmp, vault) = temp_vault();
    let grant_id = entity(0x97);
    let grant = vault
        .mint_scoped_mcp_outbound_grant(&grant_id, &scoped_intent(), 10)
        .expect("mint scoped grant");
    let key_id = register_active_scoped_connector_key_with_budget(&vault, &grant_id, "files", 1);
    let pending = vault
        .propose_connector_charter(&key_id, "never write_file", 11)
        .expect("propose charter");
    vault
        .approve_connector_charter(&key_id, pending.compiled_hash, "owner", 12)
        .expect("approve charter");
    let mut drifted = vault
        .get_connector_key(&key_id)
        .expect("read connector key")
        .expect("connector key");
    drifted
        .charter
        .as_mut()
        .expect("approved charter")
        .text
        .push_str("\n# drift");
    vault
        .with_write_txn(|wtxn| {
            crate::connector_key::rewrite_connector_key_in_txn(
                &vault.store,
                wtxn,
                &key_id,
                &drifted,
            )
        })
        .expect("persist drift fixture");

    let authority = OutboundBindingAuthority::for_vault(&vault).expect("binding authority");
    let mut transport = RecordingResultSender::default();
    let refused = execute_scoped_mcp_outbound_call(
        &vault,
        &authority,
        grant_id,
        &grant,
        &grant.principal_ref,
        OutboundToolDescriptor {
            read_only_hint: Some(false),
            idempotency_supported_hint: Some(true),
        },
        AttemptId::from_bytes(&[0x71; 16]).expect("attempt id"),
        1,
        scoped_call(),
        FrozenMcpPayload::new(b"drifted charter payload".to_vec()),
        13,
        &mut transport,
    )
    .expect("charter drift refuses without a send");

    // Discriminating: without the direct-path drift wall, this active key
    // debits its single Sends row and reaches the transport.
    assert_eq!(
        refused.decision,
        ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::ConnectorKeyCharterDrift)
    );
    assert_eq!(refused.dispatch, None);
    assert_eq!(refused.effectful_sends, 0);
    assert!(transport.sent_payloads.is_empty());
    let governing = scoped_capability_connector("files", &grant_id);
    let budget = vault
        .effector_budget_read(&governing, None)
        .expect("read budget")
        .expect("governing key");
    assert_eq!(budget.rows[0].used, 0, "charter drift must not debit");
}

#[test]
fn scoped_mcp_connector_key_budget_refuses_the_n_plus_one_send() {
    let (_tmp, vault) = temp_vault();
    let grant_id = entity(0x96);
    let grant = vault
        .mint_scoped_mcp_outbound_grant(&grant_id, &scoped_intent(), 10)
        .expect("mint scoped grant");
    let send_limit = 2_usize;
    register_active_scoped_connector_key_with_budget(
        &vault,
        &grant_id,
        "files",
        u64::try_from(send_limit).expect("small limit"),
    );
    let authority = OutboundBindingAuthority::for_vault(&vault).expect("binding authority");
    let descriptor = OutboundToolDescriptor {
        read_only_hint: Some(false),
        idempotency_supported_hint: Some(true),
    };
    let mut transport = RecordingResultSender::default();

    for index in 0..send_limit {
        let attempt_seed = 0x60_u8.saturating_add(u8::try_from(index).expect("small index"));
        let sent = execute_scoped_mcp_outbound_call(
            &vault,
            &authority,
            grant_id,
            &grant,
            &grant.principal_ref,
            descriptor,
            AttemptId::from_bytes(&[attempt_seed; 16]).expect("attempt id"),
            u64::try_from(index).expect("small index") + 1,
            scoped_call(),
            FrozenMcpPayload::new(format!("payload {index}").into_bytes()),
            20 + u64::try_from(index).expect("small index"),
            &mut transport,
        )
        .expect("budgeted send");
        assert_eq!(sent.decision, ScopedMcpConsentDecision::AutoFire);
        assert!(sent.dispatch.is_some());
        assert_eq!(sent.effectful_sends, 1);
    }

    let refused = execute_scoped_mcp_outbound_call(
        &vault,
        &authority,
        grant_id,
        &grant,
        &grant.principal_ref,
        descriptor,
        AttemptId::from_bytes(&[0x62; 16]).expect("attempt id"),
        3,
        scoped_call(),
        FrozenMcpPayload::new(b"payload refused".to_vec()),
        22,
        &mut transport,
    )
    .expect("exhausted budget refuses without a send");

    // Discriminating: without the send-path budget charge, the N+1th call
    // auto-fires and the transport records three payloads instead of N.
    assert_eq!(
        refused.decision,
        ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::ConnectorKeyBudgetExhausted)
    );
    assert_eq!(refused.dispatch, None);
    assert_eq!(refused.effectful_sends, 0);
    assert_eq!(transport.sent_payloads.len(), send_limit);
}

#[test]
fn done_intent_replay_skips_the_connector_key_debit() {
    let (_tmp, vault) = temp_vault();
    let grant_id = entity(0x99);
    let grant = vault
        .mint_scoped_mcp_outbound_grant(&grant_id, &scoped_intent(), 10)
        .expect("mint scoped grant");
    register_active_scoped_connector_key_with_budgets(
        &vault,
        &grant_id,
        "files",
        vec![crate::connector_key::EffectorBudget::rate(1, 3_600)],
    );
    let authority = OutboundBindingAuthority::for_vault(&vault).expect("binding authority");
    let descriptor = OutboundToolDescriptor {
        read_only_hint: Some(false),
        idempotency_supported_hint: Some(true),
    };
    let attempt_id = AttemptId::from_bytes(&[0x73; 16]).expect("attempt id");
    let mut transport = RecordingResultSender::default();

    let first = execute_scoped_mcp_outbound_call(
        &vault,
        &authority,
        grant_id,
        &grant,
        &grant.principal_ref,
        descriptor,
        attempt_id,
        1,
        scoped_call(),
        FrozenMcpPayload::new(b"replay payload".to_vec()),
        11,
        &mut transport,
    )
    .expect("initial dispatch");
    assert_eq!(first.effectful_sends, 1);
    assert_eq!(transport.sent_payloads.len(), 1);

    let replay = execute_scoped_mcp_outbound_call(
        &vault,
        &authority,
        grant_id,
        &grant,
        &grant.principal_ref,
        descriptor,
        attempt_id,
        1,
        scoped_call(),
        FrozenMcpPayload::new(b"replay payload".to_vec()),
        12,
        &mut transport,
    )
    .expect("done replay remains admissible at the rate cap");

    // Discriminating: charging before the ledger replay fence makes the
    // rate-1 key reject this second dispatch as budget-exhausted.
    assert_eq!(replay.decision, ScopedMcpConsentDecision::AutoFire);
    assert!(replay.dispatch.as_ref().is_some_and(|row| row.replayed));
    assert_eq!(
        replay.dispatch.as_ref().and_then(|row| row.state),
        Some(IntentState::Done)
    );
    assert_eq!(replay.effectful_sends, 0);
    assert_eq!(transport.sent_payloads.len(), 1);
    let governing = scoped_capability_connector("files", &grant_id);
    let budget = vault
        .effector_budget_read(&governing, None)
        .expect("read budget")
        .expect("governing key");
    assert_eq!(budget.rows[0].used, 1, "replay must not re-debit");
}

#[test]
fn pending_resume_and_done_replay_charge_and_complete_once() {
    let (_tmp, vault) = temp_vault();
    let grant_id = entity(0x9F);
    let grant = vault
        .mint_scoped_mcp_outbound_grant(&grant_id, &scoped_intent(), 10)
        .expect("mint scoped grant");
    register_active_scoped_connector_key_with_budget(&vault, &grant_id, "files", 1);
    let authority = OutboundBindingAuthority::for_vault(&vault).expect("binding authority");
    let descriptor = OutboundToolDescriptor {
        read_only_hint: Some(false),
        idempotency_supported_hint: Some(true),
    };
    let attempt_id = AttemptId::from_bytes(&[0x7A; 16]).expect("attempt id");
    let mut transport = ScriptedResultSender {
        outcomes: [OutboundSendOutcome::Ambiguous, OutboundSendOutcome::Acked]
            .into_iter()
            .collect(),
        keys: Vec::new(),
    };
    let dispatch = |now_ms, transport: &mut ScriptedResultSender| {
        execute_scoped_mcp_outbound_call(
            &vault,
            &authority,
            grant_id,
            &grant,
            &grant.principal_ref,
            descriptor,
            attempt_id,
            1,
            scoped_call(),
            FrozenMcpPayload::new(b"exactly once".to_vec()),
            now_ms,
            transport,
        )
        .expect("chokepoint dispatch")
    };

    let first = dispatch(11, &mut transport);
    assert_eq!(
        first.dispatch.as_ref().and_then(|row| row.state),
        Some(IntentState::Pending)
    );
    let resumed = dispatch(12, &mut transport);
    assert_eq!(
        resumed.dispatch.as_ref().and_then(|row| row.state),
        Some(IntentState::Done)
    );
    let done_replay = dispatch(13, &mut transport);
    assert_eq!(
        done_replay.dispatch.as_ref().and_then(|row| row.state),
        Some(IntentState::Done)
    );
    assert_eq!(
        done_replay
            .dispatch
            .as_ref()
            .and_then(|row| row.send_outcome),
        Some(OutboundSendOutcome::Acked)
    );
    assert_eq!(done_replay.effectful_sends, 0);
    assert_eq!(transport.keys.len(), 2);
    assert_eq!(transport.keys[0], transport.keys[1]);
    let governing = scoped_capability_connector("files", &grant_id);
    let budget = vault
        .effector_budget_read(&governing, None)
        .expect("read budget")
        .expect("governing key");
    assert_eq!(budget.rows[0].used, 1);
    let row = intent_ledger_records(&vault).expect("read ledger");
    assert_eq!(row.len(), 1);
    assert_eq!(row[0].state, IntentState::Done);
    assert_eq!(row[0].budget_accounting.sends_debit, 1);
    assert_eq!(
        row[0].recorded_outcome,
        Some(RecordedOutboundOutcome::Acked)
    );
}

#[test]
fn pending_and_budget_marker_are_committed_before_transport() {
    let (_tmp, vault) = temp_vault();
    let grant_id = entity(0x8F);
    let grant = vault
        .mint_scoped_mcp_outbound_grant(&grant_id, &scoped_intent(), 10)
        .expect("mint scoped grant");
    register_active_scoped_connector_key_with_budget(&vault, &grant_id, "files", 1);
    let authority = OutboundBindingAuthority::for_vault(&vault).expect("binding authority");
    let mut transport = PaidPendingInspectingSender {
        vault: &vault,
        governing_connector: scoped_capability_connector("files", &grant_id),
        calls: 0,
    };
    let result = execute_scoped_mcp_outbound_call(
        &vault,
        &authority,
        grant_id,
        &grant,
        &grant.principal_ref,
        OutboundToolDescriptor {
            read_only_hint: Some(false),
            idempotency_supported_hint: Some(true),
        },
        AttemptId::from_bytes(&[0x7B; 16]).expect("attempt id"),
        1,
        scoped_call(),
        FrozenMcpPayload::new(b"commit before transport".to_vec()),
        11,
        &mut transport,
    )
    .expect("committed dispatch");
    assert_eq!(transport.calls, 1);
    assert_eq!(
        result.dispatch.as_ref().and_then(|dispatch| dispatch.state),
        Some(IntentState::Done)
    );
}

#[test]
fn same_version_reopen_recovers_own_budget_marker_and_outcome_row() {
    assert_eq!(
        crate::outbound_intent_ledger::INTENT_LEDGER_SCHEMA_VERSION,
        3
    );
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault_path = tmp.path().to_path_buf();
    let grant_id = entity(0x8D);
    let expected_marker = {
        let vault = Vault::open(&vault_path, VaultConfig::device()).expect("open initial vault");
        let grant = vault
            .mint_scoped_mcp_outbound_grant(&grant_id, &scoped_intent(), 10)
            .expect("mint scoped grant");
        let key_id =
            register_active_scoped_connector_key_with_budget(&vault, &grant_id, "files", 1);
        let authority = OutboundBindingAuthority::for_vault(&vault).expect("binding authority");
        let mut ambiguous = AmbiguousResultSender;
        let initial = execute_scoped_mcp_outbound_call(
            &vault,
            &authority,
            grant_id,
            &grant,
            &grant.principal_ref,
            OutboundToolDescriptor {
                read_only_hint: Some(false),
                idempotency_supported_hint: Some(true),
            },
            AttemptId::from_bytes(&[0x7D; 16]).expect("attempt id"),
            1,
            scoped_call(),
            FrozenMcpPayload::new(b"same-version crash row".to_vec()),
            11,
            &mut ambiguous,
        )
        .expect("seed current-format Pending row");
        assert_eq!(
            initial.dispatch.as_ref().and_then(|row| row.state),
            Some(IntentState::Pending)
        );
        let rows = intent_ledger_records(&vault).expect("read current-format Pending row");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, IntentState::Pending);
        assert_eq!(rows[0].recorded_outcome, None);
        assert_eq!(rows[0].budget_accounting.key_ref, Some(key_id));
        assert_eq!(
            rows[0].budget_accounting.budget_class,
            crate::outbound_intent_ledger::BudgetClass::Send
        );
        assert_eq!(rows[0].budget_accounting.matched_rows, vec![0]);
        assert_eq!(rows[0].budget_accounting.sends_debit, 1);
        rows[0].budget_accounting.clone()
    };

    {
        let vault = Vault::open(&vault_path, VaultConfig::device()).expect("reopen crashed vault");
        let authority = OutboundBindingAuthority::for_vault(&vault).expect("binding authority");
        let mut transport = RecordingResultSender::default();
        let recovered =
            recover_authorized_outbound_intents(&vault, &authority, &mut transport, 12, 30_000)
                .expect("recover current-format Pending row");
        assert_eq!(recovered.effectful_sends, 1);
        assert_eq!(recovered.ledger.resent, 1);
        assert_eq!(recovered.ledger.completed, 1);
        assert_eq!(transport.sent_payloads.len(), 1);
        let rows = intent_ledger_records(&vault).expect("read recovered current-format row");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, IntentState::Done);
        assert_eq!(rows[0].budget_accounting, expected_marker);
        assert_eq!(
            rows[0].recorded_outcome,
            Some(RecordedOutboundOutcome::Acked)
        );
    }

    let vault = Vault::open(&vault_path, VaultConfig::device()).expect("reopen completed vault");
    let rows = intent_ledger_records(&vault).expect("decode this build's completed row");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, IntentState::Done);
    assert_eq!(rows[0].budget_accounting, expected_marker);
    assert_eq!(
        rows[0].recorded_outcome,
        Some(RecordedOutboundOutcome::Acked)
    );
}

#[test]
fn scoped_effect_without_send_ref_still_debits_the_sends_dimension() {
    let (_tmp, vault) = temp_vault();
    let grant_id = entity(0x9A);
    let grant = vault
        .mint_scoped_mcp_outbound_grant(&grant_id, &scoped_intent(), 10)
        .expect("mint scoped grant");
    register_active_scoped_connector_key_with_budget(&vault, &grant_id, "files", 1);
    let authority = OutboundBindingAuthority::for_vault(&vault).expect("binding authority");
    let mut transport = RecordingResultSender::default();

    let lookup = execute_scoped_mcp_outbound_call(
        &vault,
        &authority,
        grant_id,
        &grant,
        &grant.principal_ref,
        OutboundToolDescriptor {
            read_only_hint: Some(true),
            idempotency_supported_hint: None,
        },
        AttemptId::from_bytes(&[0x74; 16]).expect("attempt id"),
        1,
        scoped_call(),
        FrozenMcpPayload::new(b"lookup payload".to_vec()),
        11,
        &mut transport,
    )
    .expect("read-only lookup");
    assert_eq!(lookup.decision, ScopedMcpConsentDecision::AutoFire);
    assert_eq!(
        lookup.dispatch.as_ref().map(|row| row.class),
        Some(OutboundCallClass::Effectful)
    );
    assert_eq!(lookup.effectful_sends, 1);
    assert_eq!(transport.sent_payloads.len(), 1);
    let governing = scoped_capability_connector("files", &grant_id);
    let after_lookup = vault
        .effector_budget_read(&governing, None)
        .expect("read budget")
        .expect("governing key");
    assert_eq!(after_lookup.rows[0].used, 1);

    let send = execute_scoped_mcp_outbound_call(
        &vault,
        &authority,
        grant_id,
        &grant,
        &grant.principal_ref,
        OutboundToolDescriptor {
            read_only_hint: Some(false),
            idempotency_supported_hint: Some(true),
        },
        AttemptId::from_bytes(&[0x75; 16]).expect("attempt id"),
        2,
        scoped_call(),
        FrozenMcpPayload::new(b"effectful payload".to_vec()),
        12,
        &mut transport,
    )
    .expect("effectful send retains the single Sends charge");

    // Discriminating: semantic BudgetClass::Send charges the first scoped
    // effect even though its gate input has no send_ref.
    assert_eq!(
        send.decision,
        ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::ConnectorKeyBudgetExhausted)
    );
    assert_eq!(send.effectful_sends, 0);
    assert_eq!(transport.sent_payloads.len(), 1);
    let after_send = vault
        .effector_budget_read(&governing, None)
        .expect("read budget")
        .expect("governing key");
    assert_eq!(after_send.rows[0].used, 1);
}

#[test]
fn result_scrub_destroys_all_provider_fields_and_debug_content() {
    let raw = RawOutboundResult::new(
        Some(b"private body".to_vec()),
        Some("provider error".to_owned()),
        Some(b"provider stderr".to_vec()),
        Some("https://provider.example/private".to_owned()),
    );
    assert_eq!(raw.scrubbable_field_count(), 4);
    let scrubbed = scrub_outbound_result(raw);
    assert_eq!(scrubbed.scrubbed_field_count(), 4);
    let debug = format!("{scrubbed:?}");
    // Discriminating: retaining any raw result field makes at least one of
    // these provider-controlled strings observable through Debug.
    for secret in [
        "private body",
        "provider error",
        "provider stderr",
        "https://provider.example/private",
    ] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn paid_pending_ignores_later_standing_grant_revocation_and_completes() {
    let (_tmp, vault) = temp_vault();
    // Seed avoids the reserved system-agent-preset id band [0xA1;16]..=[0xA5;16]
    // (entity materialization rejects those as authority-bearing collisions).
    let grant_id = entity(0x92);
    let grant = vault
        .mint_scoped_mcp_outbound_grant(&grant_id, &scoped_intent(), 10)
        .expect("mint scoped grant");
    register_active_scoped_connector_key_with_budget(&vault, &grant_id, "files", 1);
    let authority = OutboundBindingAuthority::for_vault(&vault).expect("binding authority");
    let mut ambiguous = AmbiguousResultSender;
    let initial = execute_scoped_mcp_outbound_call(
        &vault,
        &authority,
        grant_id,
        &grant,
        &grant.principal_ref,
        OutboundToolDescriptor {
            read_only_hint: Some(false),
            idempotency_supported_hint: Some(true),
        },
        AttemptId::from_bytes(&[0x41; 16]).expect("attempt id"),
        1,
        scoped_call(),
        FrozenMcpPayload::new(b"pending payload".to_vec()),
        11,
        &mut ambiguous,
    )
    .expect("initial ambiguous dispatch");
    assert_eq!(initial.effectful_sends, 1);
    assert_eq!(
        crate::outbound_intent_ledger::intent_ledger_records(&vault)
            .unwrap()
            .len(),
        1
    );
    // Discriminating: PENDING intent authority is device-local and never
    // materializes as a synced connector-send TASK row.
    assert!(vault.connector_send_tasks().unwrap().is_empty());

    vault
        .revoke_standing_outbound_grant(&grant_id, 20)
        .expect("revoke grant");
    let mut transport = RecordingResultSender::default();
    let recovered =
        recover_authorized_outbound_intents(&vault, &authority, &mut transport, 21, 30_000)
            .expect("authorized recovery");
    // Discriminating: this already-paid row does not re-run standing-grant
    // liveness or budget admission; it resumes the authenticated frozen call.
    assert_eq!(recovered.effectful_sends, 1);
    assert_eq!(recovered.authorization_rejections, 0);
    assert_eq!(recovered.ledger.resent, 1);
    assert_eq!(recovered.ledger.completed, 1);
    assert_eq!(transport.sent_payloads.len(), 1);
    let governing = scoped_capability_connector("files", &grant_id);
    assert_eq!(
        vault
            .effector_budget_read(&governing, None)
            .expect("read paid budget")
            .expect("governing key")
            .rows[0]
            .used,
        1,
        "paid Pending completes at used == limit without a second debit"
    );
    assert_eq!(
        intent_ledger_records(&vault)
            .expect("read completed ledger")
            .first()
            .map(|row| row.state),
        Some(IntentState::Done)
    );
}

#[test]
fn recovery_rechecks_suspended_connector_key_and_keeps_intent_pending() {
    let (_tmp, vault) = temp_vault();
    let grant_id = entity(0x9B);
    let grant = vault
        .mint_scoped_mcp_outbound_grant(&grant_id, &scoped_intent(), 10)
        .expect("mint scoped grant");
    let key_id = register_active_scoped_connector_key_with_budget(&vault, &grant_id, "files", 100);
    let authority = OutboundBindingAuthority::for_vault(&vault).expect("binding authority");
    let mut ambiguous = AmbiguousResultSender;
    let initial = execute_scoped_mcp_outbound_call(
        &vault,
        &authority,
        grant_id,
        &grant,
        &grant.principal_ref,
        OutboundToolDescriptor {
            read_only_hint: Some(false),
            idempotency_supported_hint: Some(true),
        },
        AttemptId::from_bytes(&[0x76; 16]).expect("attempt id"),
        1,
        scoped_call(),
        FrozenMcpPayload::new(b"pending recovery payload".to_vec()),
        11,
        &mut ambiguous,
    )
    .expect("initial ambiguous dispatch");
    assert_eq!(initial.effectful_sends, 1);
    assert_eq!(
        intent_ledger_records(&vault)
            .expect("read ledger")
            .first()
            .map(|row| row.state),
        Some(IntentState::Pending)
    );

    vault
        .suspend_connector_key(&key_id, "owner", 12)
        .expect("suspend connector key after crash");
    let mut transport = RecordingResultSender::default();
    let recovered =
        recover_authorized_outbound_intents(&vault, &authority, &mut transport, 13, 30_000)
            .expect("authorized recovery");

    // Suspension is recoverable governance: the paid row remains Pending and
    // transport stays closed until the owner lifts the key suspension.
    assert_eq!(recovered.effectful_sends, 0);
    assert_eq!(recovered.authorization_rejections, 1);
    assert_eq!(recovered.ledger.resent, 0);
    assert_eq!(recovered.ledger.pending, 1);
    assert_eq!(recovered.ledger.completed, 0);
    assert!(transport.sent_payloads.is_empty());
    let rows = intent_ledger_records(&vault).expect("read ledger after recovery");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, IntentState::Pending);
}

#[test]
fn recovery_keeps_charter_never_list_and_drift_recoverable_pending() {
    let (_tmp, vault) = temp_vault();
    let grant_id = entity(0x8E);
    let grant = vault
        .mint_scoped_mcp_outbound_grant(&grant_id, &scoped_intent(), 10)
        .expect("mint scoped grant");
    let key_id = register_active_scoped_connector_key_with_budget(&vault, &grant_id, "files", 1);
    let authority = OutboundBindingAuthority::for_vault(&vault).expect("binding authority");
    let mut ambiguous = AmbiguousResultSender;
    execute_scoped_mcp_outbound_call(
        &vault,
        &authority,
        grant_id,
        &grant,
        &grant.principal_ref,
        OutboundToolDescriptor {
            read_only_hint: Some(false),
            idempotency_supported_hint: Some(true),
        },
        AttemptId::from_bytes(&[0x7C; 16]).expect("attempt id"),
        1,
        scoped_call(),
        FrozenMcpPayload::new(b"charter pending".to_vec()),
        11,
        &mut ambiguous,
    )
    .expect("seed paid Pending");
    let proposal = vault
        .propose_connector_charter(&key_id, "never read_file", 12)
        .expect("propose never-list");
    vault
        .approve_connector_charter(&key_id, proposal.compiled_hash, "owner", 13)
        .expect("approve never-list");

    let mut transport = RecordingResultSender::default();
    let never_list =
        recover_authorized_outbound_intents(&vault, &authority, &mut transport, 14, 30_000)
            .expect("never-list recovery");
    assert_eq!(never_list.effectful_sends, 0);
    assert_eq!(never_list.ledger.pending, 1);
    assert!(transport.sent_payloads.is_empty());
    assert_eq!(
        intent_ledger_records(&vault)
            .expect("read never-list row")
            .first()
            .map(|row| row.state),
        Some(IntentState::Pending)
    );

    let mut drifted = vault
        .get_connector_key(&key_id)
        .expect("read connector key")
        .expect("connector key");
    drifted
        .charter
        .as_mut()
        .expect("approved charter")
        .text
        .push_str("\n# drift");
    vault
        .with_write_txn(|wtxn| {
            crate::connector_key::rewrite_connector_key_in_txn(
                &vault.store,
                wtxn,
                &key_id,
                &drifted,
            )
        })
        .expect("persist drift");
    let drift = recover_authorized_outbound_intents(&vault, &authority, &mut transport, 15, 30_000)
        .expect("drift recovery");
    assert_eq!(drift.effectful_sends, 0);
    assert_eq!(drift.ledger.pending, 1);
    assert!(transport.sent_payloads.is_empty());
    assert_eq!(
        intent_ledger_records(&vault)
            .expect("read drift row")
            .first()
            .map(|row| row.state),
        Some(IntentState::Pending)
    );
    let governing = scoped_capability_connector("files", &grant_id);
    assert_eq!(
        vault
            .effector_budget_read(&governing, None)
            .expect("read paid budget")
            .expect("governing key")
            .rows[0]
            .used,
        1
    );
}

#[test]
fn revoked_connector_abandons_paid_pending_without_transport() {
    let (_tmp, vault) = temp_vault();
    let grant_id = entity(0x9C);
    let grant = vault
        .mint_scoped_mcp_outbound_grant(&grant_id, &scoped_intent(), 10)
        .expect("mint scoped grant");
    let key_id = register_active_scoped_connector_key_with_budget(&vault, &grant_id, "files", 1);
    let authority = OutboundBindingAuthority::for_vault(&vault).expect("binding authority");
    let mut ambiguous = AmbiguousResultSender;
    execute_scoped_mcp_outbound_call(
        &vault,
        &authority,
        grant_id,
        &grant,
        &grant.principal_ref,
        OutboundToolDescriptor {
            read_only_hint: Some(false),
            idempotency_supported_hint: Some(true),
        },
        AttemptId::from_bytes(&[0x77; 16]).expect("attempt id"),
        1,
        scoped_call(),
        FrozenMcpPayload::new(b"revoked pending".to_vec()),
        11,
        &mut ambiguous,
    )
    .expect("initial paid Pending");
    vault
        .revoke_connector_key(&key_id, 12)
        .expect("revoke connector key");

    let mut transport = RecordingResultSender::default();
    let recovered =
        recover_authorized_outbound_intents(&vault, &authority, &mut transport, 13, 30_000)
            .expect("revoked recovery");
    assert_eq!(recovered.effectful_sends, 0);
    assert_eq!(recovered.ledger.resent, 0);
    assert_eq!(recovered.ledger.pending, 0);
    assert_eq!(recovered.ledger.escalations.len(), 1);
    assert!(transport.sent_payloads.is_empty());
    let row = intent_ledger_records(&vault)
        .expect("read abandoned row")
        .into_iter()
        .next()
        .expect("row");
    assert_eq!(row.state, IntentState::Abandoned);
    assert_eq!(
        row.recorded_outcome,
        Some(RecordedOutboundOutcome::Abandoned(
            IntentEscalationReason::ConnectorRevoked
        ))
    );
    assert_eq!(row.budget_accounting.sends_debit, 1);
}

#[test]
fn non_idempotent_pending_abandons_without_resume_attempt() {
    let (_tmp, vault) = temp_vault();
    let grant_id = entity(0x9E);
    let grant = vault
        .mint_scoped_mcp_outbound_grant(&grant_id, &scoped_intent(), 10)
        .expect("mint scoped grant");
    register_active_scoped_connector_key_with_budget(&vault, &grant_id, "files", 1);
    let authority = OutboundBindingAuthority::for_vault(&vault).expect("binding authority");
    let mut ambiguous = AmbiguousResultSender;
    execute_scoped_mcp_outbound_call(
        &vault,
        &authority,
        grant_id,
        &grant,
        &grant.principal_ref,
        OutboundToolDescriptor {
            read_only_hint: Some(false),
            idempotency_supported_hint: Some(true),
        },
        AttemptId::from_bytes(&[0x79; 16]).expect("attempt id"),
        1,
        scoped_call(),
        FrozenMcpPayload::new(b"non-idempotent crash row".to_vec()),
        11,
        &mut ambiguous,
    )
    .expect("seed paid Pending");
    let mut row = intent_ledger_records(&vault)
        .expect("read paid Pending")
        .into_iter()
        .next()
        .expect("row");
    row.idempotency_supported = false;
    crate::outbound_intent_ledger::replace_intent_record_for_test(&vault, &row)
        .expect("persist same-format crash fixture");

    let mut transport = RecordingResultSender::default();
    let recovered =
        recover_authorized_outbound_intents(&vault, &authority, &mut transport, 12, 30_000)
            .expect("non-idempotent recovery");
    assert_eq!(recovered.effectful_sends, 0);
    assert_eq!(recovered.ledger.resent, 0);
    assert!(transport.sent_payloads.is_empty());
    let row = intent_ledger_records(&vault)
        .expect("read abandoned row")
        .into_iter()
        .next()
        .expect("row");
    assert_eq!(row.state, IntentState::Abandoned);
    assert_eq!(
        row.recorded_outcome,
        Some(RecordedOutboundOutcome::Abandoned(
            IntentEscalationReason::NonIdempotentPending
        ))
    );
}

#[test]
fn allowlisted_endpoint_rotation_freezes_the_selected_endpoint() {
    let (_tmp, vault) = temp_vault();
    let grant_id = entity(0x9D);
    let mut intent = scoped_intent();
    intent
        .endpoint_allowlist
        .push("https://files-backup.internal.example".to_owned());
    let grant = vault
        .mint_scoped_mcp_outbound_grant(&grant_id, &intent, 10)
        .expect("mint rotating scoped grant");
    register_active_scoped_connector_key_with_budget(&vault, &grant_id, "files", 1);
    let authority = OutboundBindingAuthority::for_vault(&vault).expect("binding authority");
    let mut transport = RecordingResultSender::default();
    let result = execute_scoped_mcp_outbound_call(
        &vault,
        &authority,
        grant_id,
        &grant,
        &grant.principal_ref,
        OutboundToolDescriptor {
            read_only_hint: Some(false),
            idempotency_supported_hint: Some(true),
        },
        AttemptId::from_bytes(&[0x78; 16]).expect("attempt id"),
        1,
        ScopedMcpCallContext {
            resolved_endpoint: "https://files-backup.internal.example".to_owned(),
            ..scoped_call()
        },
        FrozenMcpPayload::new(b"rotated endpoint".to_vec()),
        11,
        &mut transport,
    )
    .expect("allowlisted rotation");
    assert_eq!(result.decision, ScopedMcpConsentDecision::AutoFire);
    assert_eq!(result.effectful_sends, 1);
    assert_eq!(
        transport.sent_endpoints,
        vec![Some("https://files-backup.internal.example".to_owned())]
    );
    let row = intent_ledger_records(&vault).expect("read frozen endpoint");
    assert_eq!(
        row[0].resolved_endpoint.as_deref(),
        Some("https://files-backup.internal.example")
    );
    assert_eq!(row[0].binding_version, OUTBOUND_BINDING_VERSION);
}

#[test]
fn authorized_recovery_skips_non_scoped_connector_rows() {
    let (_tmp, vault) = temp_vault();
    let authority = OutboundBindingAuthority::for_vault(&vault).expect("binding authority");

    // A connector-send row: no scoped authorization binding, no resolved
    // endpoint, and no governing connector key. The connector-task attempt
    // queue owns its recovery; the scoped/MCP result transport must never see
    // it, or a connector payload would leave through the MCP result sender.
    let request = crate::outbound_intent_ledger::OutboundCallRequest::new(
        AttemptId::from_bytes(&[0x5A; 16]).expect("attempt id"),
        0,
        "connector-channel",
        "send_message",
        b"connector payload".to_vec(),
        10,
    );
    let marker = crate::outbound_intent_ledger::BudgetChargeMarker {
        key_ref: None,
        budget_class: crate::outbound_intent_ledger::BudgetClass::Send,
        matched_rows: Vec::new(),
        sends_debit: 0,
        accounted_at_ms: 10,
    };
    let pending = crate::outbound_intent_ledger::IntentLedgerRecord::pending(request, true, marker)
        .expect("connector pending record");
    let pending_id = pending.id;
    assert!(
        pending.authorization_binding.is_none(),
        "connector rows carry no scoped authorization binding"
    );
    let mut wtxn = vault.store.env.write_txn().expect("write txn");
    crate::outbound_intent_ledger::insert_pending_in_txn(&vault, &mut wtxn, &pending)
        .expect("insert connector pending");
    wtxn.commit().expect("commit connector pending");

    let mut transport = RecordingResultSender::default();
    let recovered =
        recover_authorized_outbound_intents(&vault, &authority, &mut transport, 13, 30_000)
            .expect("authorized recovery");

    // The connector row is skipped, not resumed through the MCP transport.
    assert_eq!(recovered.effectful_sends, 0);
    assert_eq!(recovered.ledger.resent, 0);
    assert!(transport.sent_payloads.is_empty());
    // It stays Pending, untouched, for the connector-task attempt queue.
    let rows = intent_ledger_records(&vault).expect("read ledger after recovery");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, pending_id);
    assert_eq!(rows[0].state, IntentState::Pending);
}

// --- ONE-1885 typed capability provenance round trip -------------------------

fn register_scoped_key(vault: &Vault, key_id: &EntityId, grant_id: &EntityId, server: &str) {
    vault
        .register_connector_key(
            key_id,
            crate::connector_key::ConnectorKeyRecord::active(
                scoped_capability_connector(server, grant_id),
                None,
                Vec::new(),
                10,
            ),
        )
        .expect("register active scoped connector key");
}

fn stamp_charter(vault: &Vault, key_id: &EntityId, text: &str) {
    let pending = vault
        .propose_connector_charter(key_id, text, 12)
        .expect("propose charter");
    vault
        .approve_connector_charter(key_id, pending.compiled_hash, "owner", 13)
        .expect("approve charter");
}

#[test]
fn capability_provenance_survives_admission_ledger_and_recovery() {
    let (_tmp, vault) = temp_vault();
    let denied_grant = entity(0x71);
    let neighbour_grant = entity(0x72);
    let denied_key = entity(0x73);
    let neighbour_key = entity(0x74);
    let authority = OutboundBindingAuthority::for_vault(&vault).expect("binding authority");
    let mut grants = Vec::new();
    for (grant_id, key_id) in [(denied_grant, denied_key), (neighbour_grant, neighbour_key)] {
        grants.push(
            vault
                .mint_scoped_mcp_outbound_grant(&grant_id, &scoped_intent(), 10)
                .expect("mint scoped grant"),
        );
        register_scoped_key(&vault, &key_id, &grant_id, "files");
    }

    // Two real engine-produced scoped dispatches leave durable Pending rows.
    let mut ambiguous = AmbiguousResultSender;
    for (index, (grant_id, grant)) in [(denied_grant, &grants[0]), (neighbour_grant, &grants[1])]
        .into_iter()
        .enumerate()
    {
        execute_scoped_mcp_outbound_call(
            &vault,
            &authority,
            grant_id,
            grant,
            &grant.principal_ref,
            OutboundToolDescriptor {
                read_only_hint: Some(false),
                idempotency_supported_hint: Some(true),
            },
            AttemptId::from_bytes(&[0x71 + u8::try_from(index).expect("index"); 16])
                .expect("attempt id"),
            1,
            scoped_call(),
            FrozenMcpPayload::new(b"capability payload".to_vec()),
            11,
            &mut ambiguous,
        )
        .expect("seed paid Pending");
    }

    // The typed identity is present on the durable row after the MessagePack
    // encode/decode round trip and the content-digest check that read it back.
    let rows = intent_ledger_records(&vault).expect("read pending rows");
    assert_eq!(rows.len(), 2);
    for grant_id in [denied_grant, neighbour_grant] {
        let row = rows
            .iter()
            .find(|row| {
                row.capability_provenance()
                    .is_some_and(|capability| capability.grant_id() == grant_id)
            })
            .expect("scoped row carries typed capability provenance");
        let capability = row.capability_provenance().expect("typed provenance");
        assert_eq!(capability.server(), "files");
        assert_eq!(
            capability.connector(),
            scoped_capability_connector("files", &grant_id)
        );
        assert_eq!(row.state, IntentState::Pending);
    }

    // ONE grant is denied by its exact `never key`. Both keys carry the SAME
    // stamped text, so only the typed provenance can tell the rows apart.
    let text = format!(
        "never key {}",
        scoped_capability_connector("files", &denied_grant)
    );
    stamp_charter(&vault, &denied_key, &text);
    stamp_charter(&vault, &neighbour_key, &text);

    let mut transport = RecordingResultSender::default();
    let recovered =
        recover_authorized_outbound_intents(&vault, &authority, &mut transport, 14, 30_000)
            .expect("recovery");
    assert_eq!(
        recovered.effectful_sends, 1,
        "only the neighbour grant may reach transport"
    );
    let rows = intent_ledger_records(&vault).expect("read rows after recovery");
    let denied_row = rows
        .iter()
        .find(|row| {
            row.capability_provenance()
                .is_some_and(|capability| capability.grant_id() == denied_grant)
        })
        .expect("denied row");
    assert_eq!(denied_row.state, IntentState::Pending);
    let neighbour_row = rows
        .iter()
        .find(|row| {
            row.capability_provenance()
                .is_some_and(|capability| capability.grant_id() == neighbour_grant)
        })
        .expect("neighbour row");
    assert_eq!(neighbour_row.state, IntentState::Done);
}
