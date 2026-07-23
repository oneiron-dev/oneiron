mod common;

use common::entity;
use std::collections::BTreeMap;

use oneiron::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityShape, ChannelIdentityState,
    EnqueueOutcome, EntityId, ErrorKind, InboundSurfaceRouteOutcome, LINKEDIN_CHANNEL,
    LINKEDIN_CONNECT_CONSENT_BODY, LINKEDIN_CONNECT_REQUEST_VERB,
    LINKEDIN_DEFAULT_CADENCE_JITTER_MAX_SECONDS, LINKEDIN_DEFAULT_CADENCE_JITTER_MIN_SECONDS,
    LINKEDIN_DEFAULT_DAILY_DM_CAP, LINKEDIN_DEFAULT_DAILY_PROFILE_READ_CAP,
    LINKEDIN_MCP_CONNECT_WITH_PERSON_TOOL, LINKEDIN_MCP_SEND_MESSAGE_TOOL, LINKEDIN_SEND_DM_VERB,
    LinkedInAccountRiskLimits, LinkedInInboxSyncConfig, LinkedInInboxSyncRunner,
    LinkedInMcpConnectorAdapter, LinkedInMcpInboxSyncTransport, LinkedInPasswordCustody,
    LinkedInSandboxHostConfig, LinkedInSandboxHostHarness, LinkedInSandboxRuntime,
    LinkedInSeatDispatchState, LinkedInSeatPolicyAction, LinkedInSeatSandboxPolicy,
    OutboundPermissionState, Result, SurfaceCounterpartyStamp, Vault, VaultConfig,
    linkedin_connect_consent_screen_copy, linkedin_inbox_sync_provenance_rows,
    outbound_capability_manifest, outbound_verb_contract, run_linkedin_kill_switch,
};
use serde_json::{Value, json};

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

#[derive(Clone)]
struct ScriptedInboxTransport {
    inbox: Value,
    conversations: BTreeMap<String, Value>,
}

impl ScriptedInboxTransport {
    fn new(inbox: Value, conversations: impl IntoIterator<Item = (String, Value)>) -> Self {
        Self {
            inbox,
            conversations: conversations.into_iter().collect(),
        }
    }
}

impl LinkedInMcpInboxSyncTransport for ScriptedInboxTransport {
    fn get_inbox(&mut self) -> std::result::Result<Value, String> {
        Ok(self.inbox.clone())
    }

    fn get_conversation(&mut self, thread_id: &str) -> std::result::Result<Value, String> {
        self.conversations
            .get(thread_id)
            .cloned()
            .ok_or_else(|| format!("missing conversation {thread_id}"))
    }
}

fn active_linkedin_identity(
    vault: &Vault,
    adapter: &LinkedInMcpConnectorAdapter,
) -> Result<(EntityId, EntityId)> {
    active_linkedin_identity_with_seeds(vault, adapter, 0x51, 0x53)
}

fn active_linkedin_identity_with_seeds(
    vault: &Vault,
    adapter: &LinkedInMcpConnectorAdapter,
    identity_seed: u8,
    agent_seed: u8,
) -> Result<(EntityId, EntityId)> {
    let identity_id = entity(identity_seed);
    let agent_ref = entity(agent_seed);
    let mut identity = ChannelIdentity::requested(
        LINKEDIN_CHANNEL,
        adapter.receiving_address_or_handle(),
        ChannelIdentityShape::DedicatedHandle,
        ChannelIdentityBinding::agent(agent_ref),
        1_800_000_000,
    );
    identity.state = ChannelIdentityState::Active;
    vault.create_channel_identity(&identity_id, &identity)?;
    Ok((identity_id, agent_ref))
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
    let agent_ref = entity(0x52);
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
fn linkedin_inbox_sync_double_poll_routes_no_duplicates_and_imported_external_provenance()
-> Result<()> {
    let adapter = adapter()?;
    let (_tmp, vault) = temp_vault();
    active_linkedin_identity(&vault, &adapter)?;

    let config =
        LinkedInInboxSyncConfig::from_adapter(&adapter).with_backfill_window_secs(3_600)?;
    let EnqueueOutcome::Enqueued(_) =
        adapter.enqueue_inbox_sync_poll(&vault, config.clone(), 1_800_000_020)?
    else {
        panic!("first scheduled poll should enqueue");
    };
    let EnqueueOutcome::Existing(_) =
        adapter.enqueue_inbox_sync_poll(&vault, config.clone(), 1_800_000_021)?
    else {
        panic!("second scheduled poll should reuse dedupe row");
    };

    let inbox = json!({
        "url": "https://www.linkedin.com/messaging/",
        "sections": {
            "inbox": "Messaging\nJane Doe\nThanks for reaching out about the pilot."
        },
        "references": {
            "inbox": [
                {
                    "kind": "conversation",
                    "url": "/messaging/thread/2-jane-doe-abc/",
                    "context": "inbox",
                    "text": "Jane Doe"
                }
            ]
        }
    });
    let conversation = json!({
        "url": "https://www.linkedin.com/messaging/thread/2-jane-doe-abc/",
        "messages": [
            {
                "id": "msg-1",
                "text": "Thanks for reaching out about the pilot.",
                "occurred_at": 1_800_000_010_u64
            },
            {
                "id": "msg-2",
                "text": "Happy to share more details.",
                "occurred_at": 1_800_000_015_u64
            }
        ]
    });
    let transport =
        ScriptedInboxTransport::new(inbox, [("2-jane-doe-abc".to_owned(), conversation)]);

    let mut first_runner =
        LinkedInInboxSyncRunner::new(&vault, adapter.clone(), transport.clone(), config.clone());
    let first = first_runner.run_once(1_800_000_020)?;
    assert_eq!(first.threads_seen, 1);
    assert_eq!(first.messages_seen, 2);
    assert_eq!(first.new_messages, 2);
    assert_eq!(first.duplicate_messages, 0);
    assert_eq!(first.receipts.len(), 2);
    assert!(
        first
            .receipts
            .iter()
            .all(|receipt| receipt.outcome == InboundSurfaceRouteOutcome::Routed)
    );

    let rows = linkedin_inbox_sync_provenance_rows(&vault)?;
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| row.source == "imported"));
    assert!(rows.iter().all(|row| row.tier == "external"));
    assert!(
        rows.iter()
            .all(|row| row.receiving_address_or_handle == "linkedin:member:yura")
    );
    assert!(
        rows.iter()
            .all(|row| row.session_ref.as_deref() == Some("linkedin:session:yura:tokyo-sandbox"))
    );
    assert!(
        rows.iter()
            .all(|row| row.thread_id == "2-jane-doe-abc" && row.channel == LINKEDIN_CHANNEL)
    );

    let mut second_runner = LinkedInInboxSyncRunner::new(&vault, adapter, transport, config);
    let second = second_runner.run_once(1_800_000_020)?;
    assert_eq!(second.threads_seen, 1);
    assert_eq!(second.messages_seen, 2);
    assert_eq!(second.new_messages, 0);
    assert_eq!(second.duplicate_messages, 2);
    assert!(second.receipts.is_empty());
    assert_eq!(linkedin_inbox_sync_provenance_rows(&vault)?.len(), 2);

    Ok(())
}

#[test]
fn linkedin_inbox_sync_scopes_seen_rows_by_receiving_identity_and_session() -> Result<()> {
    let adapter_a = adapter()?;
    let adapter_b = LinkedInMcpConnectorAdapter::new("linkedin:member:akira")?
        .with_session_ref("linkedin:session:akira:tokyo-sandbox")?;
    let (_tmp, vault) = temp_vault();
    active_linkedin_identity_with_seeds(&vault, &adapter_a, 0x51, 0x53)?;
    active_linkedin_identity_with_seeds(&vault, &adapter_b, 0x52, 0x54)?;

    let inbox = json!({
        "sections": {
            "inbox": "Messaging\nJane Doe\nShared thread message."
        },
        "references": {
            "inbox": [
                {
                    "kind": "conversation",
                    "url": "/messaging/thread/2-shared-thread/",
                    "context": "inbox",
                    "text": "Jane Doe"
                }
            ]
        }
    });
    let conversation = json!({
        "url": "https://www.linkedin.com/messaging/thread/2-shared-thread/",
        "messages": [
            {
                "id": "shared-msg",
                "text": "Shared thread message.",
                "occurred_at": 1_800_000_010_u64
            }
        ]
    });
    let transport =
        ScriptedInboxTransport::new(inbox, [("2-shared-thread".to_owned(), conversation)]);

    let config_a = LinkedInInboxSyncConfig::from_adapter(&adapter_a);
    let config_b = LinkedInInboxSyncConfig::from_adapter(&adapter_b);
    let mut runner_a = LinkedInInboxSyncRunner::new(&vault, adapter_a, transport.clone(), config_a);
    let mut runner_b = LinkedInInboxSyncRunner::new(&vault, adapter_b, transport, config_b);

    let first = runner_a.run_once(1_800_000_020)?;
    let second = runner_b.run_once(1_800_000_020)?;
    assert_eq!(first.new_messages, 1);
    assert_eq!(second.new_messages, 1);

    let rows = linkedin_inbox_sync_provenance_rows(&vault)?;
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().any(|row| {
        row.receiving_address_or_handle == "linkedin:member:yura"
            && row.session_ref.as_deref() == Some("linkedin:session:yura:tokyo-sandbox")
    }));
    assert!(rows.iter().any(|row| {
        row.receiving_address_or_handle == "linkedin:member:akira"
            && row.session_ref.as_deref() == Some("linkedin:session:akira:tokyo-sandbox")
    }));
    Ok(())
}

#[test]
fn linkedin_inbox_sync_uses_known_thread_for_message_only_payload() -> Result<()> {
    let adapter = adapter()?;
    let (_tmp, vault) = temp_vault();
    active_linkedin_identity(&vault, &adapter)?;
    let config = LinkedInInboxSyncConfig::from_adapter(&adapter);
    let inbox = json!({
        "sections": {
            "inbox": "Messaging\nJane Doe\nMessage-only payload."
        },
        "references": {
            "inbox": [
                {
                    "kind": "conversation",
                    "url": "/messaging/thread/2-message-only/",
                    "context": "inbox",
                    "text": "Jane Doe"
                }
            ]
        }
    });
    let conversation = json!({
        "messages": [
            {
                "id": "message-only-msg",
                "text": "Message-only payload.",
                "occurred_at": 1_800_000_010_u64
            }
        ]
    });
    let transport =
        ScriptedInboxTransport::new(inbox, [("2-message-only".to_owned(), conversation)]);

    let mut runner = LinkedInInboxSyncRunner::new(&vault, adapter, transport, config);
    let report = runner.run_once(1_800_000_020)?;
    assert_eq!(report.new_messages, 1);
    let rows = linkedin_inbox_sync_provenance_rows(&vault)?;
    assert_eq!(rows[0].thread_id, "2-message-only");
    assert_eq!(rows[0].message_id, "message-only-msg");
    Ok(())
}

#[test]
fn linkedin_inbox_sync_tool_failures_are_retryable() -> Result<()> {
    let adapter = adapter()?;
    let (_tmp, vault) = temp_vault();
    active_linkedin_identity(&vault, &adapter)?;
    let config = LinkedInInboxSyncConfig::from_adapter(&adapter);
    let inbox = json!({
        "sections": {
            "inbox": "Messaging\nJane Doe\nMissing conversation."
        },
        "references": {
            "inbox": [
                {
                    "kind": "conversation",
                    "url": "/messaging/thread/2-missing-conversation/",
                    "context": "inbox",
                    "text": "Jane Doe"
                }
            ]
        }
    });
    let transport = ScriptedInboxTransport::new(inbox, []);
    let mut runner = LinkedInInboxSyncRunner::new(&vault, adapter, transport, config);

    let err = runner
        .run_once(1_800_000_020)
        .expect_err("missing tool output fails");
    assert_eq!(err.kind(), ErrorKind::UpstreamToolFailure);
    assert!(err.is_retryable());
    assert!(
        format!("{err}").contains("tool=get_conversation"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn linkedin_inbox_sync_backfill_window_is_configurable() -> Result<()> {
    let adapter = adapter()?;
    let (_tmp, vault) = temp_vault();
    active_linkedin_identity(&vault, &adapter)?;
    let config = LinkedInInboxSyncConfig::from_adapter(&adapter).with_backfill_window_secs(60)?;
    let inbox = json!({
        "sections": {
            "inbox": "Messaging\nKenji Mori\nCan you send the overview?"
        },
        "references": {
            "inbox": [
                {
                    "kind": "conversation",
                    "url": "/messaging/thread/2-kenji-mori-def/",
                    "context": "inbox",
                    "text": "Kenji Mori"
                }
            ]
        }
    });
    let conversation = json!({
        "url": "https://www.linkedin.com/messaging/thread/2-kenji-mori-def/",
        "messages": [
            {
                "id": "old-msg",
                "text": "Older than configured backfill.",
                "occurred_at": 1_799_999_000_u64
            },
            {
                "id": "fresh-msg",
                "text": "Can you send the overview?",
                "occurred_at": 1_800_000_019_u64
            }
        ]
    });
    let transport =
        ScriptedInboxTransport::new(inbox, [("2-kenji-mori-def".to_owned(), conversation)]);

    let mut runner = LinkedInInboxSyncRunner::new(&vault, adapter, transport, config);
    let report = runner.run_once(1_800_000_020)?;
    assert_eq!(report.messages_seen, 2);
    assert_eq!(report.backfill_skipped_messages, 1);
    assert_eq!(report.new_messages, 1);
    let rows = linkedin_inbox_sync_provenance_rows(&vault)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].message_id, "fresh-msg");
    assert_eq!(rows[0].source, "imported");
    assert_eq!(rows[0].tier, "external");
    Ok(())
}

#[test]
fn linkedin_inbox_sync_normalizes_millisecond_timestamps_for_backfill() -> Result<()> {
    let adapter = adapter()?;
    let (_tmp, vault) = temp_vault();
    active_linkedin_identity(&vault, &adapter)?;
    let config = LinkedInInboxSyncConfig::from_adapter(&adapter).with_backfill_window_secs(60)?;
    let inbox = json!({
        "sections": {
            "inbox": "Messaging\nKenji Mori\nFresh millisecond payload."
        },
        "references": {
            "inbox": [
                {
                    "kind": "conversation",
                    "url": "/messaging/thread/2-ms-timestamps/",
                    "context": "inbox",
                    "text": "Kenji Mori"
                }
            ]
        }
    });
    let conversation = json!({
        "url": "https://www.linkedin.com/messaging/thread/2-ms-timestamps/",
        "messages": [
            {
                "id": "old-ms",
                "text": "Old millisecond payload.",
                "timestamp": 1_799_999_000_000_u64
            },
            {
                "id": "fresh-ms",
                "text": "Fresh millisecond payload.",
                "timestamp": 1_800_000_019_000_u64
            }
        ]
    });
    let transport =
        ScriptedInboxTransport::new(inbox, [("2-ms-timestamps".to_owned(), conversation)]);

    let mut runner = LinkedInInboxSyncRunner::new(&vault, adapter, transport, config);
    let report = runner.run_once(1_800_000_020)?;
    assert_eq!(report.messages_seen, 2);
    assert_eq!(report.backfill_skipped_messages, 1);
    assert_eq!(report.new_messages, 1);
    let rows = linkedin_inbox_sync_provenance_rows(&vault)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].message_id, "fresh-ms");
    assert_eq!(rows[0].occurred_at, Some(1_800_000_019));
    Ok(())
}

#[test]
fn linkedin_fallback_message_ids_are_content_stable_and_date_labels_group_rows() -> Result<()> {
    let adapter = adapter()?;
    let output = json!({
        "url": "https://www.linkedin.com/messaging/thread/2-text-fallback/",
        "sections": {
            "conversation": "Jane Doe\nJul 1\nFirst dated body.\nKenji Mori\nMar 14\nSecond dated body."
        }
    });
    let shifted_output = json!({
        "url": "https://www.linkedin.com/messaging/thread/2-text-fallback/",
        "sections": {
            "conversation": "Alex Kim\nJun 1\nOlder prepended body.\nJane Doe\nJul 1\nFirst dated body.\nKenji Mori\nMar 14\nSecond dated body."
        }
    });

    let events = adapter.normalize_get_conversation_message_events(&output, 1_800_000_020, 60)?;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].message.text.as_deref(), Some("First dated body."));
    assert_eq!(
        events[1].message.text.as_deref(),
        Some("Second dated body.")
    );
    let original_ids = events
        .iter()
        .map(|event| event.message.message_id.clone())
        .collect::<Vec<_>>();

    let shifted =
        adapter.normalize_get_conversation_message_events(&shifted_output, 1_800_000_020, 60)?;
    assert_eq!(shifted.len(), 3);
    let shifted_ids = shifted
        .iter()
        .map(|event| event.message.message_id.as_str())
        .collect::<Vec<_>>();
    assert!(shifted_ids.contains(&original_ids[0].as_str()));
    assert!(shifted_ids.contains(&original_ids[1].as_str()));
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
