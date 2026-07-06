use oneiron::{
    ChannelIdentityFulfillment, ChannelIdentityLifecycleActor, ChannelIdentityProviderAdapter,
    ChannelIdentityProviderInbound, ChannelIdentityState, EntityId, InboundSurfaceRouteOutcome,
    ProvisionIntent, Result, SLACK_CHANNEL, SlackOutboundMessage, SlackPersonaAttribution,
    SlackProviderInbound, SlackSharedPresenceAdapter, SlackSharedPresenceAdapterConfig, Vault,
    VaultConfig,
};

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

fn adapter() -> Result<SlackSharedPresenceAdapter> {
    Ok(SlackSharedPresenceAdapter::new(
        SlackSharedPresenceAdapterConfig::new(
            "Oneiron",
            "Oneiron",
            "https://oneiron.example.test/slack/events",
            vec!["https://oneiron.example.test/slack/oauth/callback".to_owned()],
        )?,
    ))
}

#[test]
fn cid8_slack_shared_presence_routes_two_agents_in_one_workspace() -> Result<()> {
    let adapter = adapter()?;
    let (_tmp, vault) = temp_vault();
    let workspace_id = "T123ABC";
    let identity_a_id = entity(0x71);
    let identity_b_id = entity(0x72);
    let agent_a = entity(0xA1);
    let agent_b = entity(0xA2);
    let actor_a = ChannelIdentityLifecycleActor::agent(agent_a);
    let actor_b = ChannelIdentityLifecycleActor::agent(agent_b);
    let identity_a = adapter.requested_identity(agent_a, workspace_id, "eiri", 1_800_000_000)?;
    let identity_b = adapter.requested_identity(agent_b, workspace_id, "herald", 1_800_000_000)?;

    vault.create_channel_identity(&identity_a_id, &identity_a)?;
    vault.create_channel_identity(&identity_b_id, &identity_b)?;
    vault.transition_channel_identity(
        &identity_a_id,
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Api),
        1_800_000_001,
        None,
    )?;
    vault.transition_channel_identity(
        &identity_b_id,
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Api),
        1_800_000_001,
        None,
    )?;

    let provision_a = adapter.provision(
        &ProvisionIntent {
            identity_id: identity_a_id,
            identity: identity_a,
            fulfillment_mode: ChannelIdentityFulfillment::Api,
        },
        1_800_000_002,
    )?;
    let provision_b = adapter.provision(
        &ProvisionIntent {
            identity_id: identity_b_id,
            identity: identity_b,
            fulfillment_mode: ChannelIdentityFulfillment::Api,
        },
        1_800_000_002,
    )?;
    vault.fulfill_channel_identity(provision_a.fulfillment_input(actor_a))?;
    vault.fulfill_channel_identity(provision_b.fulfillment_input(actor_b))?;

    let inbound_a = adapter.parse_inbound(ChannelIdentityProviderInbound::Slack(
        SlackProviderInbound::new(
            "EvA",
            workspace_id,
            "C123ABC",
            "U123ABC",
            "eiri",
            1_800_000_003,
        ),
    ))?;
    let inbound_b = adapter.parse_inbound(ChannelIdentityProviderInbound::Slack(
        SlackProviderInbound::new(
            "EvB",
            workspace_id,
            "C123ABC",
            "U456DEF",
            "herald",
            1_800_000_004,
        ),
    ))?;

    let receipt_a = vault.route_inbound_surface_event(inbound_a)?;
    let receipt_b = vault.route_inbound_surface_event(inbound_b)?;

    assert_eq!(receipt_a.outcome, InboundSurfaceRouteOutcome::Routed);
    assert_eq!(receipt_b.outcome, InboundSurfaceRouteOutcome::Routed);
    assert_eq!(receipt_a.channel, SLACK_CHANNEL);
    assert_eq!(
        receipt_a.workspace_ref.as_deref(),
        Some("slack:workspace:T123ABC")
    );
    assert_eq!(
        receipt_b.workspace_ref.as_deref(),
        Some("slack:workspace:T123ABC")
    );
    assert_eq!(
        receipt_a.receiving_identity_ref,
        Some(identity_a_id.to_hex())
    );
    assert_eq!(
        receipt_b.receiving_identity_ref,
        Some(identity_b_id.to_hex())
    );
    assert_eq!(receipt_a.agent_ref, Some(agent_a.to_hex()));
    assert_eq!(receipt_b.agent_ref, Some(agent_b.to_hex()));
    assert_ne!(
        receipt_a.receiving_address_or_handle,
        receipt_b.receiving_address_or_handle
    );

    let surface_a = receipt_a.surface_event.expect("surface event");
    assert_eq!(
        surface_a.workspace_ref.as_deref(),
        Some("slack:workspace:T123ABC")
    );
    assert!(surface_a.claims_not_instructions);

    let eiri = SlackPersonaAttribution::new("eiri", "Eiri")?;
    let herald = SlackPersonaAttribution::new("herald", "Herald")?;
    let message = SlackOutboundMessage::new(workspace_id, "C123ABC", "I can handle this.")?;
    let outbound_a = adapter.persona_outbound(&eiri, &message)?;
    let outbound_b = adapter.persona_outbound(&herald, &message)?;

    assert_eq!(outbound_a.body["username"], "Eiri");
    assert_eq!(outbound_b.body["username"], "Herald");
    assert_eq!(
        outbound_a.body["metadata"]["event_payload"]["identity_key"],
        "slack:workspace:T123ABC:persona:eiri"
    );
    assert_eq!(
        outbound_b.body["metadata"]["event_payload"]["identity_key"],
        "slack:workspace:T123ABC:persona:herald"
    );
    Ok(())
}
