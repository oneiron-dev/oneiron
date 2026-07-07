use oneiron::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityShape, ChannelIdentityState, EntityId,
    InboundSurfaceRouteOutcome, LINKEDIN_CHANNEL, LINKEDIN_CONNECT_REQUEST_VERB,
    LINKEDIN_MCP_CONNECT_WITH_PERSON_TOOL, LINKEDIN_MCP_SEND_MESSAGE_TOOL, LINKEDIN_SEND_DM_VERB,
    LinkedInMcpConnectorAdapter, OutboundPermissionState, Result, SurfaceCounterpartyStamp, Vault,
    VaultConfig, outbound_capability_manifest, outbound_verb_contract,
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
