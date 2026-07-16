use super::*;
use crate::config::VaultConfig;
use crate::outbound_grant::ScopedMcpGrantMintIntent;

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::device()).expect("open vault");
    (tmp, vault)
}

fn entity(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("test entity id")
}

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
        vec![crate::EffectorBudget::sends(
            sends,
            crate::EffectorBudgetWindow::Calendar {
                period: crate::CalendarPeriod::Day,
                tz: None,
            },
            crate::EffectorBudgetOnExhaust::Refuse,
        )],
    )
}

fn register_active_scoped_connector_key_with_budgets(
    vault: &Vault,
    grant_id: &EntityId,
    server: &str,
    budgets: Vec<crate::EffectorBudget>,
) -> EntityId {
    let key_id = entity(0xD0);
    vault
        .register_connector_key(
            &key_id,
            crate::ConnectorKeyRecord::active(
                crate::gate::scoped_mcp_credential_connector_key(server, grant_id),
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
}

impl OutboundResultSender for RecordingResultSender {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundTransportResult {
        self.sent_payloads.push(call.payload().to_vec());
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
fn binding_authenticity_and_revocation_fail_closed_at_send_boundary() {
    let (_tmp, vault) = temp_vault();
    let grant_id = entity(0x91);
    let grant = vault
        .mint_scoped_mcp_outbound_grant(&grant_id, &scoped_intent(), 10)
        .expect("mint scoped grant");
    register_active_scoped_connector_key_with_budget(&vault, &grant_id, "files", 100);
    let authority = OutboundBindingAuthority::for_vault(&vault).expect("binding authority");
    let descriptor = OutboundToolDescriptor {
        read_only_hint: Some(false),
        idempotency_supported_hint: Some(true),
    };
    let call = scoped_call();

    let valid_attempt = AttemptId::from_bytes(&[0x31; 16]).expect("attempt id");
    let valid = authority
        .authorize_request(
            &vault,
            grant_id,
            &grant,
            &grant.principal_ref,
            valid_attempt,
            1,
            &call,
            b"valid payload",
        )
        .expect("authorize valid request")
        .binding
        .expect("valid binding");
    let mut transport = RecordingResultSender::default();
    let mut sender = AuthenticatedResultSender::new(&vault, &authority, &mut transport);
    execute_outbound_call(
        &vault,
        descriptor,
        OutboundCallRequest::new(
            valid_attempt,
            1,
            &call.server,
            &call.tool,
            b"valid payload".to_vec(),
            11,
        )
        .with_authorization_binding(valid),
        &mut sender,
    )
    .expect("valid dispatch");
    assert_eq!(sender.effectful_sends, 1);
    assert_eq!(transport.sent_payloads.len(), 1);

    let tampered_attempt = AttemptId::from_bytes(&[0x32; 16]).expect("attempt id");
    let mut tampered = *authority
        .authorize_request(
            &vault,
            grant_id,
            &grant,
            &grant.principal_ref,
            tampered_attempt,
            2,
            &call,
            b"tampered payload",
        )
        .expect("authorize tamper fixture")
        .binding
        .expect("binding")
        .as_bytes();
    tampered[0] ^= 1;
    let mut sender = AuthenticatedResultSender::new(&vault, &authority, &mut transport);
    execute_outbound_call(
        &vault,
        descriptor,
        OutboundCallRequest::new(
            tampered_attempt,
            2,
            &call.server,
            &call.tool,
            b"tampered payload".to_vec(),
            12,
        )
        .with_authorization_binding(OutboundAuthorizationBinding::new(tampered)),
        &mut sender,
    )
    .expect("tampered binding fails as definite non-delivery");
    // Discriminating: with presence-only authorization, this one-byte tamper
    // reaches the transport and increases its send count.
    assert_eq!(sender.authorization_rejections, 1);
    assert_eq!(transport.sent_payloads.len(), 1);

    let revoked_attempt = AttemptId::from_bytes(&[0x33; 16]).expect("attempt id");
    let revoked_binding = authority
        .authorize_request(
            &vault,
            grant_id,
            &grant,
            &grant.principal_ref,
            revoked_attempt,
            3,
            &call,
            b"revoked payload",
        )
        .expect("authorize before revoke")
        .binding
        .expect("binding");
    vault
        .revoke_standing_outbound_grant(&grant_id, 20)
        .expect("revoke grant");
    let mut sender = AuthenticatedResultSender::new(&vault, &authority, &mut transport);
    execute_outbound_call(
        &vault,
        descriptor,
        OutboundCallRequest::new(
            revoked_attempt,
            3,
            &call.server,
            &call.tool,
            b"revoked payload".to_vec(),
            21,
        )
        .with_authorization_binding(revoked_binding),
        &mut sender,
    )
    .expect("revoked binding fails as definite non-delivery");
    assert_eq!(sender.authorization_rejections, 1);
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
    let governing = crate::gate::scoped_mcp_credential_connector_key("files", &grant_id);
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
        vec![crate::EffectorBudget::rate(1, 3_600)],
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
    let governing = crate::gate::scoped_mcp_credential_connector_key("files", &grant_id);
    let budget = vault
        .effector_budget_read(&governing, None)
        .expect("read budget")
        .expect("governing key");
    assert_eq!(budget.rows[0].used, 1, "replay must not re-debit");
}

#[test]
fn read_only_call_does_not_debit_the_sends_dimension() {
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
        Some(OutboundCallClass::ReadOnly)
    );
    assert_eq!(lookup.effectful_sends, 0);
    assert_eq!(transport.sent_payloads.len(), 1);
    let governing = crate::gate::scoped_mcp_credential_connector_key("files", &grant_id);
    let after_lookup = vault
        .effector_budget_read(&governing, None)
        .expect("read budget")
        .expect("governing key");
    assert_eq!(after_lookup.rows[0].used, 0);

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

    // Discriminating: a hardcoded send-like charge consumes the cap during
    // the lookup, so this effectful call is denied and never reaches transport.
    assert_eq!(send.decision, ScopedMcpConsentDecision::AutoFire);
    assert_eq!(send.effectful_sends, 1);
    assert_eq!(transport.sent_payloads.len(), 2);
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
fn recovery_revalidates_revocation_and_pending_intent_stays_node_local() {
    let (_tmp, vault) = temp_vault();
    // Seed avoids the reserved system-agent-preset id band [0xA1;16]..=[0xA5;16]
    // (entity materialization rejects those as authority-bearing collisions).
    let grant_id = entity(0x92);
    let grant = vault
        .mint_scoped_mcp_outbound_grant(&grant_id, &scoped_intent(), 10)
        .expect("mint scoped grant");
    register_active_scoped_connector_key_with_budget(&vault, &grant_id, "files", 100);
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
    // Discriminating: recovery without liveness re-validation would resend
    // once and record no authorization rejection.
    assert_eq!(recovered.effectful_sends, 0);
    assert_eq!(recovered.authorization_rejections, 1);
    assert!(transport.sent_payloads.is_empty());
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

    // Discriminating: binding-only recovery resends through the now-suspended
    // key, increments effectful_sends, and transitions this row to Done.
    assert_eq!(recovered.effectful_sends, 0);
    assert_eq!(recovered.authorization_rejections, 1);
    assert_eq!(recovered.ledger.resent, 1);
    assert_eq!(recovered.ledger.pending, 1);
    assert_eq!(recovered.ledger.completed, 0);
    assert!(transport.sent_payloads.is_empty());
    let rows = intent_ledger_records(&vault).expect("read ledger after recovery");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, IntentState::Pending);
}
