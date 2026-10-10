use crate::common::entity;
use std::collections::BTreeMap;

use oneiron::{
    EntityId, InboundSurfaceRouteOutcome, Result, Vault, VaultConfig,
    attempt_queue::EnqueueOutcome, channel_identity::ChannelIdentityBinding,
    channel_identity::ChannelIdentityState, channel_identity::SelfHeldShape,
    linkedin_connector::LINKEDIN_CHANNEL, linkedin_connector::LINKEDIN_CONNECT_REQUEST_VERB,
    linkedin_connector::LINKEDIN_SEND_DM_VERB, linkedin_connector::LinkedInInboxSyncConfig,
    linkedin_connector::LinkedInInboxSyncRunner, linkedin_connector::LinkedInMcpConnectorAdapter,
    linkedin_connector::LinkedInMcpInboxSyncTransport, linkedin_connector::LinkedInPasswordCustody,
    linkedin_connector::LinkedInSandboxHostConfig, linkedin_connector::LinkedInSandboxHostHarness,
    linkedin_connector::LinkedInSandboxRuntime, linkedin_connector::LinkedInSeatDispatchState,
    linkedin_connector::LinkedInSeatPolicyAction, linkedin_connector::LinkedInSeatSandboxPolicy,
    linkedin_connector::linkedin_inbox_sync_provenance_rows,
    linkedin_connector::run_linkedin_kill_switch,
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
    let identity = crate::common::self_held_identity_in_state(
        LINKEDIN_CHANNEL,
        adapter.receiving_address_or_handle(),
        SelfHeldShape::DedicatedHandle,
        ChannelIdentityBinding::agent(agent_ref),
        ChannelIdentityState::Active,
        1_800_000_000,
    );
    vault.create_channel_identity(&identity_id, &identity)?;
    Ok((identity_id, agent_ref))
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
fn linkedin_get_inbox_fixture_normalizes_each_thread_and_routes() -> Result<()> {
    let adapter = adapter()?;
    let mut output = fixture(include_str!("../fixtures/linkedin_mcp/get_inbox.json"));
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
    let identity = crate::common::self_held_identity_in_state(
        LINKEDIN_CHANNEL,
        adapter.receiving_address_or_handle(),
        SelfHeldShape::DedicatedHandle,
        ChannelIdentityBinding::agent(agent_ref),
        ChannelIdentityState::Active,
        1_800_000_000,
    );
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
