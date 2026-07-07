use oneiron::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityShape, ChannelIdentityState, EntityId,
    InboundSurfaceRouteOutcome, LINKEDIN_CHANNEL, LINKEDIN_CONNECT_CONSENT_BODY,
    LINKEDIN_CONNECT_REQUEST_VERB, LINKEDIN_DEFAULT_CADENCE_JITTER_MAX_SECONDS,
    LINKEDIN_DEFAULT_CADENCE_JITTER_MIN_SECONDS, LINKEDIN_DEFAULT_DAILY_DM_CAP,
    LINKEDIN_DEFAULT_DAILY_PROFILE_READ_CAP, LINKEDIN_MCP_CONNECT_WITH_PERSON_TOOL,
    LINKEDIN_MCP_SEND_MESSAGE_TOOL, LINKEDIN_SEND_DM_VERB, LinkedInAccountRiskLimits,
    LinkedInMcpConnectorAdapter, LinkedInPasswordCustody, LinkedInSandboxHostConfig,
    LinkedInSandboxHostHarness, LinkedInSandboxRuntime, LinkedInSeatDispatchState,
    LinkedInSeatPolicyAction, LinkedInSeatSandboxPolicy, OutboundPermissionState, Result,
    SurfaceCounterpartyStamp, Vault, VaultConfig, linkedin_connect_consent_screen_copy,
    outbound_capability_manifest, outbound_verb_contract, run_linkedin_kill_switch,
};
use serde_json::{Value, json};

fn entity(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("valid test id")
}

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    let vault = Vault::open(tmp.path(), cfg).expect("open vault");
    (tmp, vault)
}

fn fixture(json: &str) -> Value {
    serde_json::from_str(json).expect("fixture parses")
}

fn adapter() -> Result<LinkedInMcpConnectorAdapter> {
    LinkedInMcpConnectorAdapter::new("linkedin:member:yura")?
        .with_session_ref("linkedin:session:yura:tokyo-sandbox")
}

#[derive(Default)]
struct RecordingSandboxHarness {
    destroyed: Vec<String>,
    revoked: Vec<String>,
}

impl LinkedInSandboxHostHarness for RecordingSandboxHarness {
    fn destroy_sandbox(&mut self, host: &LinkedInSandboxHostConfig) -> Result<()> {
        self.destroyed.push(host.sandbox_ref.clone());
        Ok(())
    }

    fn revoke_verb_catalog(&mut self, seat_ref: &str) -> Result<()> {
        self.revoked.push(seat_ref.to_owned());
        Ok(())
    }
}

fn sandbox_host() -> Result<LinkedInSandboxHostConfig> {
    LinkedInSandboxHostConfig::new(
        "linkedin:seat:yura",
        "sandbox:tokyo:yura",
        "browser-profile:linkedin:yura",
        "vault-secret:linkedin:yura:session-cookie",
    )
}

#[test]
fn linkedin_outbound_manifest_registers_dm_and_connect_request_verbs() -> Result<()> {
    let manifest = outbound_capability_manifest("linkedin").expect("linkedin manifest");
    assert_eq!(manifest.connector, "linkedin");
    assert_eq!(manifest.connector_family, "professional_network");

    let send_dm =
        outbound_verb_contract("linkedin", LINKEDIN_SEND_DM_VERB).expect("linkedin send_dm verb");
    assert_eq!(send_dm.kind, LINKEDIN_SEND_DM_VERB);
    assert_eq!(send_dm.channel_call, LINKEDIN_MCP_SEND_MESSAGE_TOOL);
    assert_eq!(
        send_dm.capability_vs_permission.permission,
        OutboundPermissionState::Conditional
    );
    assert!(send_dm.capability_vs_permission.policy_risk);
    assert_eq!(
        send_dm.params["confirm_send"],
        "true only after OF-327 grant/gate approval"
    );

    let connect = outbound_verb_contract("linkedin", LINKEDIN_CONNECT_REQUEST_VERB)
        .expect("linkedin connect_request verb");
    assert_eq!(connect.kind, LINKEDIN_CONNECT_REQUEST_VERB);
    assert_eq!(connect.channel_call, LINKEDIN_MCP_CONNECT_WITH_PERSON_TOOL);
    assert_eq!(
        connect.capability_vs_permission.permission,
        OutboundPermissionState::Conditional
    );
    assert!(connect.params.get("note").is_some());

    let adapter = adapter()?;
    assert_eq!(
        adapter.mcp_tool_for_verb("linkedin.send_dm"),
        Some(LINKEDIN_MCP_SEND_MESSAGE_TOOL)
    );
    assert_eq!(
        adapter.mcp_tool_for_verb("connect-request"),
        Some(LINKEDIN_MCP_CONNECT_WITH_PERSON_TOOL)
    );
    assert_eq!(
        adapter.supported_outbound_verbs(),
        [LINKEDIN_SEND_DM_VERB, LINKEDIN_CONNECT_REQUEST_VERB]
    );
    Ok(())
}

#[test]
fn linkedin_sandbox_host_config_records_custody_and_login_handoff() -> Result<()> {
    let config = sandbox_host()?;
    assert_eq!(config.runtime, LinkedInSandboxRuntime::Container);
    assert!(config.mcp_server.persistent_browser_profile);
    assert_eq!(
        config.session_cookie_secret_ref,
        "vault-secret:linkedin:yura:session-cookie"
    );
    assert!(config.login_handoff.one_time_remote_browser);
    assert!(config.login_handoff.member_completes_2fa);
    assert_eq!(
        config.login_handoff.password_custody,
        LinkedInPasswordCustody::MemberOnly
    );

    let bad_secret_ref = LinkedInSandboxHostConfig::new(
        "linkedin:seat:yura",
        "sandbox:tokyo:yura",
        "browser-profile:linkedin:yura",
        "raw-cookie",
    )
    .expect_err("session cookie custody must be a vault-scoped secret ref");
    assert!(
        format!("{bad_secret_ref:?}").contains("vault-scoped"),
        "unexpected error: {bad_secret_ref:?}"
    );
    Ok(())
}

#[test]
fn linkedin_d5_consent_copy_and_caps_are_plain_and_mechanical() -> Result<()> {
    let copy = linkedin_connect_consent_screen_copy();
    assert_eq!(copy.title, "Connect LinkedIn");
    for required in [
        "does not officially support",
        "own logged-in browser session",
        "does not need or store your password",
        "account limited",
        "15 DMs per day",
        "sweeps are not allowed",
        "deletes the sandbox",
    ] {
        assert!(
            LINKEDIN_CONNECT_CONSENT_BODY.contains(required),
            "consent copy missing D5 phrase: {required}"
        );
    }
    assert!(
        copy.acknowledgements
            .iter()
            .any(|ack| ack.contains("15 DMs per day") && ack.contains("no sweeps"))
    );

    let limits = LinkedInAccountRiskLimits::default();
    assert_eq!(limits.daily_dm_cap, LINKEDIN_DEFAULT_DAILY_DM_CAP);
    assert_eq!(
        limits.daily_profile_read_cap,
        LINKEDIN_DEFAULT_DAILY_PROFILE_READ_CAP
    );
    assert_eq!(
        limits.cadence_jitter_min_seconds,
        LINKEDIN_DEFAULT_CADENCE_JITTER_MIN_SECONDS
    );
    assert_eq!(
        limits.cadence_jitter_max_seconds,
        LINKEDIN_DEFAULT_CADENCE_JITTER_MAX_SECONDS
    );
    let next_send = limits.jittered_next_send_not_before(1_800_000_000, 42);
    assert!(next_send >= 1_800_000_000 + u64::from(LINKEDIN_DEFAULT_CADENCE_JITTER_MIN_SECONDS));
    assert!(next_send <= 1_800_000_000 + u64::from(LINKEDIN_DEFAULT_CADENCE_JITTER_MAX_SECONDS));
    assert_eq!(limits.capped_down(10)?.daily_dm_cap, 10);
    assert!(
        LinkedInAccountRiskLimits::default()
            .capped_down(LINKEDIN_DEFAULT_DAILY_DM_CAP + 1)
            .is_err(),
        "seat owners can lower default caps, not silently raise them"
    );
    assert_eq!(
        LinkedInAccountRiskLimits::default()
            .with_owner_approved_daily_dm_cap(20, "consent:linkedin-owner-warning")?
            .owner_warning_ack_ref
            .as_deref(),
        Some("consent:linkedin-owner-warning")
    );
    Ok(())
}

#[test]
fn linkedin_profile_read_cap_is_engine_policy_not_adapter_state() -> Result<()> {
    let policy = LinkedInSeatSandboxPolicy::active(sandbox_host()?).with_state(
        LinkedInSeatDispatchState::active()
            .with_profile_reads_today(LINKEDIN_DEFAULT_DAILY_PROFILE_READ_CAP),
    );

    let decision = policy.evaluate_profile_read();
    assert_eq!(decision.action, LinkedInSeatPolicyAction::Hold);
    assert_eq!(
        decision.reason_code.as_deref(),
        Some("linkedin.daily_profile_read_cap")
    );
    assert_eq!(
        decision
            .receipt_fields
            .get("linkedin_daily_profile_read_cap")
            .map(String::as_str),
        Some("25")
    );
    assert_eq!(
        decision
            .receipt_fields
            .get("linkedin_profile_reads_today")
            .map(String::as_str),
        Some("25")
    );
    assert_eq!(
        decision
            .receipt_fields
            .get("linkedin_policy_enforced_engine_side")
            .map(String::as_str),
        Some("true")
    );
    Ok(())
}

#[test]
fn linkedin_kill_switch_harness_destroys_sandbox_and_revokes_catalog() -> Result<()> {
    let policy = LinkedInSeatSandboxPolicy::active(sandbox_host()?)
        .with_state(LinkedInSeatDispatchState::active());
    assert_eq!(
        policy.verb_catalog(),
        [LINKEDIN_SEND_DM_VERB, LINKEDIN_CONNECT_REQUEST_VERB]
    );

    let mut harness = RecordingSandboxHarness::default();
    let killed = run_linkedin_kill_switch(
        policy,
        &mut harness,
        1_800_000_100,
        "consent:owner-disabled-linkedin",
    )?;
    assert_eq!(harness.destroyed, vec!["sandbox:tokyo:yura"]);
    assert_eq!(harness.revoked, vec!["linkedin:seat:yura"]);
    assert!(killed.verb_catalog().is_empty());

    let decision = killed.evaluate_outbound(LINKEDIN_CHANNEL, LINKEDIN_SEND_DM_VERB, 1_800_000_101);
    assert_eq!(decision.action, LinkedInSeatPolicyAction::Suppress);
    assert_eq!(
        decision.reason_code.as_deref(),
        Some("linkedin.kill_switch_engaged")
    );
    assert_eq!(
        decision
            .receipt_fields
            .get("linkedin_sandbox_destroyed")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        decision
            .receipt_fields
            .get("linkedin_verb_catalog_revoked")
            .map(String::as_str),
        Some("true")
    );
    Ok(())
}

#[test]
fn linkedin_get_conversation_fixture_normalizes_to_idempotent_surface_event() -> Result<()> {
    let adapter = adapter()?;
    let output = fixture(include_str!(
        "fixtures/linkedin_mcp/get_conversation.mcp.json"
    ));

    let events = adapter.normalize_get_conversation_tool_output(&output, 1_800_000_010)?;
    let repeated = adapter.normalize_get_conversation_tool_output(&output, 1_800_000_010)?;
    assert_eq!(events, repeated);
    assert_eq!(events.len(), 1);

    let event = &events[0];
    assert!(
        event
            .event_id
            .starts_with("linkedin:conversation:2-jane-doe-abc:")
    );
    assert_eq!(event.channel, LINKEDIN_CHANNEL);
    assert_eq!(event.receiving_address_or_handle, "linkedin:member:yura");
    assert_eq!(
        event.workspace_ref.as_deref(),
        Some("linkedin:session:yura:tokyo-sandbox")
    );
    assert_eq!(
        event.payload_ref.as_deref(),
        Some("linkedin:mcp:get_conversation:2-jane-doe-abc:ab75e3d9fd7e4a60")
    );
    assert!(event.foreign_inbound);
    assert_eq!(
        event.counterparty,
        SurfaceCounterpartyStamp::unknown("linkedin:thread:2-jane-doe-abc")
    );
    Ok(())
}

#[test]
fn linkedin_get_inbox_fixture_normalizes_each_thread_and_routes() -> Result<()> {
    let adapter = adapter()?;
    let mut output = fixture(include_str!("fixtures/linkedin_mcp/get_inbox.json"));
    let duplicate = output["references"]["inbox"][0].clone();
    output["references"]["inbox"]
        .as_array_mut()
        .expect("inbox references")
        .push(duplicate);

    let events = adapter.normalize_get_inbox_tool_output(&output, 1_800_000_020)?;
    assert_eq!(events.len(), 2);
    assert_ne!(events[0].event_id, events[1].event_id);
    assert!(
        events[0]
            .event_id
            .starts_with("linkedin:inbox:2-jane-doe-abc:")
    );
    assert!(
        events[1]
            .event_id
            .starts_with("linkedin:inbox:2-kenji-mori-def:")
    );

    let mut changed_inbox_text = output.clone();
    changed_inbox_text["sections"]["inbox"] =
        json!("Messaging\nJane Doe\nChanged preview text\nKenji Mori\nCan you send the overview?");
    let repeated = adapter.normalize_get_inbox_tool_output(&changed_inbox_text, 1_800_000_020)?;
    assert_eq!(events[0].event_id, repeated[0].event_id);
    assert_eq!(events[0].payload_ref, repeated[0].payload_ref);

    let (_tmp, vault) = temp_vault();
    let identity_id = entity(0x51);
    let agent_ref = entity(0xA1);
    let mut identity = ChannelIdentity::requested(
        LINKEDIN_CHANNEL,
        adapter.receiving_address_or_handle(),
        ChannelIdentityShape::DedicatedHandle,
        ChannelIdentityBinding::agent(agent_ref),
        1_800_000_000,
    );
    identity.state = ChannelIdentityState::Active;
    vault.create_channel_identity(&identity_id, &identity)?;

    let receipt = vault.route_inbound_surface_event(events[0].clone())?;
    assert_eq!(receipt.outcome, InboundSurfaceRouteOutcome::Routed);
    assert_eq!(receipt.receiving_identity_ref, Some(identity_id.to_hex()));
    assert_eq!(receipt.agent_ref, Some(agent_ref.to_hex()));
    let surface_event = receipt.surface_event.expect("surface event");
    assert!(surface_event.claims_not_instructions);
    assert!(surface_event.foreign_inbound);
    assert_eq!(
        surface_event.payload_ref.as_deref(),
        events[0].payload_ref.as_deref()
    );
    Ok(())
}

#[test]
fn linkedin_conversation_reference_filtering_never_uses_display_text_as_key() -> Result<()> {
    let adapter = adapter()?;
    let output = json!({
        "sections": {
            "conversation": "Jane Doe\n10:01 AM\nThanks for reaching out."
        },
        "references": {
            "conversation": [
                {
                    "kind": "profile",
                    "thread_id": "bad:id",
                    "text": "Mutable Display Name"
                },
                {
                    "kind": "conversation",
                    "url": "/messaging/thread/2-jane-doe-abc/",
                    "text": "Jane Doe"
                }
            ]
        }
    });

    let events = adapter.normalize_get_conversation_tool_output(&output, 1_800_000_030)?;
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].counterparty,
        SurfaceCounterpartyStamp::unknown("linkedin:thread:2-jane-doe-abc")
    );
    Ok(())
}

#[test]
fn linkedin_rejects_unknown_mcp_shapes_and_bad_thread_ids() -> Result<()> {
    let adapter = adapter()?;

    let err = adapter
        .normalize_get_inbox_tool_output(&json!({"unexpected": true}), 1_800_000_040)
        .expect_err("unknown envelope fails loudly");
    assert!(
        format!("{err:?}").contains("recognized shape"),
        "unexpected error: {err:?}"
    );

    let err = adapter
        .normalize_get_conversation_tool_output(
            &json!({
                "url": "https://www.linkedin.com/messaging/thread/bad:id/",
                "sections": {
                    "conversation": "Jane Doe\nReserved delimiter."
                }
            }),
            1_800_000_041,
        )
        .expect_err("colon-delimited thread id fails");
    assert!(
        format!("{err:?}").contains("reserved delimiter"),
        "unexpected error: {err:?}"
    );

    let oversized_thread_id = "a".repeat(257);
    let err = adapter
        .normalize_get_conversation_tool_output(
            &json!({
                "sections": {
                    "conversation": "Jane Doe\nOversized thread id."
                },
                "references": {
                    "conversation": [
                        {
                            "kind": "conversation",
                            "thread_id": oversized_thread_id
                        }
                    ]
                }
            }),
            1_800_000_042,
        )
        .expect_err("oversized thread id fails");
    assert!(
        format!("{err:?}").contains("maximum length"),
        "unexpected error: {err:?}"
    );

    Ok(())
}
