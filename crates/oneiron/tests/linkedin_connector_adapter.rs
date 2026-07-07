use oneiron::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityShape, ChannelIdentityState, EntityId,
    InboundSurfaceRouteOutcome, LINKEDIN_CHANNEL, LINKEDIN_CONNECT_REQUEST_VERB,
    LINKEDIN_MCP_CONNECT_WITH_PERSON_TOOL, LINKEDIN_MCP_SEND_MESSAGE_TOOL, LINKEDIN_SEND_DM_VERB,
    LinkedInMcpConnectorAdapter, OutboundPermissionState, Result, SurfaceCounterpartyStamp, Vault,
    VaultConfig, outbound_capability_manifest, outbound_verb_contract,
};
use serde_json::Value;

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
        SurfaceCounterpartyStamp::unknown("linkedin:thread:2-jane-doe-abc:participant:Jane Doe")
    );
    Ok(())
}

#[test]
fn linkedin_get_inbox_fixture_normalizes_each_thread_and_routes() -> Result<()> {
    let adapter = adapter()?;
    let output = fixture(include_str!("fixtures/linkedin_mcp/get_inbox.json"));

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
        Some("linkedin:mcp:get_inbox:2-jane-doe-abc:779bec96ce760587")
    );
    Ok(())
}
