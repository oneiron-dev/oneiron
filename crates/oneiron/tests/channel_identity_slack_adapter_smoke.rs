use std::env;

use oneiron::{
    ChannelIdentityFulfillment, ChannelIdentityLifecycleActor, ChannelIdentityProviderAdapter,
    ChannelIdentityProviderInbound, ChannelIdentityState, EntityId, Error,
    InboundSurfaceRouteOutcome, ProvisionIntent, Result, SLACK_CHANNEL, SlackOutboundMessage,
    SlackPersonaAttribution, SlackProviderInbound, SlackSharedPresenceAdapter,
    SlackSharedPresenceAdapterConfig, Vault, VaultConfig,
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

struct SlackSmokeCase {
    workspace_id: String,
    enterprise_id: Option<String>,
    channel_id: String,
    user_a_id: String,
    user_b_id: String,
    persona_a: String,
    persona_b: String,
}

impl SlackSmokeCase {
    fn workspace() -> Self {
        Self {
            workspace_id: "T123ABC".to_owned(),
            enterprise_id: None,
            channel_id: "C123ABC".to_owned(),
            user_a_id: "U123ABC".to_owned(),
            user_b_id: "U456DEF".to_owned(),
            persona_a: "eiri".to_owned(),
            persona_b: "herald".to_owned(),
        }
    }

    fn enterprise_grid() -> Self {
        Self {
            enterprise_id: Some("E123ABC".to_owned()),
            ..Self::workspace()
        }
    }

    fn from_dev_workspace_env() -> Result<Self> {
        Ok(Self {
            workspace_id: required_env("ONEIRON_SLACK_SMOKE_WORKSPACE_ID")?,
            enterprise_id: optional_env("ONEIRON_SLACK_SMOKE_ENTERPRISE_ID"),
            channel_id: required_env("ONEIRON_SLACK_SMOKE_CHANNEL_ID")?,
            user_a_id: required_env("ONEIRON_SLACK_SMOKE_USER_A_ID")?,
            user_b_id: required_env("ONEIRON_SLACK_SMOKE_USER_B_ID")?,
            persona_a: optional_env("ONEIRON_SLACK_SMOKE_PERSONA_A")
                .unwrap_or_else(|| "eiri".to_owned()),
            persona_b: optional_env("ONEIRON_SLACK_SMOKE_PERSONA_B")
                .unwrap_or_else(|| "herald".to_owned()),
        })
    }
}

fn required_env(name: &'static str) -> Result<String> {
    env::var(name).map_err(|_| Error::InvalidConfig(format!("{name} must be set")))
}

fn optional_env(name: &'static str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn requested_identity(
    adapter: &SlackSharedPresenceAdapter,
    agent_ref: EntityId,
    case: &SlackSmokeCase,
    persona_handle: &str,
    requested_at: u64,
) -> Result<oneiron::ChannelIdentity> {
    match case.enterprise_id.as_deref() {
        Some(enterprise_id) => adapter.requested_enterprise_identity(
            agent_ref,
            enterprise_id,
            case.workspace_id.as_str(),
            persona_handle,
            requested_at,
        ),
        None => adapter.requested_identity(
            agent_ref,
            case.workspace_id.as_str(),
            persona_handle,
            requested_at,
        ),
    }
}

fn slack_inbound(
    case: &SlackSmokeCase,
    event_id: &'static str,
    user_id: &str,
    persona_handle: &str,
    received_at: u64,
) -> SlackProviderInbound {
    let inbound = SlackProviderInbound::new(
        event_id,
        case.workspace_id.as_str(),
        case.channel_id.as_str(),
        user_id,
        persona_handle,
        received_at,
    );
    match case.enterprise_id.as_deref() {
        Some(enterprise_id) => inbound.with_enterprise_id(enterprise_id),
        None => inbound,
    }
}

fn slack_message(case: &SlackSmokeCase) -> Result<SlackOutboundMessage> {
    let message = SlackOutboundMessage::new(
        case.workspace_id.as_str(),
        case.channel_id.as_str(),
        "I can handle this.",
    )?;
    match case.enterprise_id.as_deref() {
        Some(enterprise_id) => message.with_enterprise_id(enterprise_id),
        None => Ok(message),
    }
}

fn run_two_agent_smoke(case: SlackSmokeCase) -> Result<()> {
    let adapter = adapter()?;
    let (_tmp, vault) = temp_vault();
    let workspace_ref = SlackSharedPresenceAdapter::workspace_ref(
        case.workspace_id.as_str(),
        case.enterprise_id.as_deref(),
    )?;
    let identity_key_a = SlackSharedPresenceAdapter::persona_identity_key(
        case.workspace_id.as_str(),
        case.enterprise_id.as_deref(),
        case.persona_a.as_str(),
    )?;
    let identity_key_b = SlackSharedPresenceAdapter::persona_identity_key(
        case.workspace_id.as_str(),
        case.enterprise_id.as_deref(),
        case.persona_b.as_str(),
    )?;
    let identity_a_id = entity(0x71);
    let identity_b_id = entity(0x72);
    let agent_a = entity(0xA1);
    let agent_b = entity(0xA2);
    let actor_a = ChannelIdentityLifecycleActor::agent(agent_a);
    let actor_b = ChannelIdentityLifecycleActor::agent(agent_b);
    let identity_a = requested_identity(
        &adapter,
        agent_a,
        &case,
        case.persona_a.as_str(),
        1_800_000_000,
    )?;
    let identity_b = requested_identity(
        &adapter,
        agent_b,
        &case,
        case.persona_b.as_str(),
        1_800_000_000,
    )?;

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

    let inbound_a = adapter.parse_inbound(ChannelIdentityProviderInbound::Slack(slack_inbound(
        &case,
        "EvA",
        case.user_a_id.as_str(),
        case.persona_a.as_str(),
        1_800_000_003,
    )))?;
    let inbound_b = adapter.parse_inbound(ChannelIdentityProviderInbound::Slack(slack_inbound(
        &case,
        "EvB",
        case.user_b_id.as_str(),
        case.persona_b.as_str(),
        1_800_000_004,
    )))?;

    let receipt_a = vault.route_inbound_surface_event(inbound_a)?;
    let receipt_b = vault.route_inbound_surface_event(inbound_b)?;

    assert_eq!(receipt_a.outcome, InboundSurfaceRouteOutcome::Routed);
    assert_eq!(receipt_b.outcome, InboundSurfaceRouteOutcome::Routed);
    assert_eq!(receipt_a.channel, SLACK_CHANNEL);
    assert_eq!(
        receipt_a.workspace_ref.as_deref(),
        Some(workspace_ref.as_str())
    );
    assert_eq!(
        receipt_b.workspace_ref.as_deref(),
        Some(workspace_ref.as_str())
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
    assert_eq!(receipt_a.receiving_address_or_handle, identity_key_a);
    assert_eq!(receipt_b.receiving_address_or_handle, identity_key_b);
    assert_ne!(
        receipt_a.receiving_address_or_handle,
        receipt_b.receiving_address_or_handle
    );

    let surface_a = receipt_a.surface_event.expect("surface event");
    assert_eq!(
        surface_a.workspace_ref.as_deref(),
        Some(workspace_ref.as_str())
    );
    assert!(surface_a.claims_not_instructions);

    let eiri = SlackPersonaAttribution::new(case.persona_a.as_str(), "Eiri")?;
    let herald = SlackPersonaAttribution::new(case.persona_b.as_str(), "Herald")?;
    let message = slack_message(&case)?;
    let outbound_a = adapter.persona_outbound(&eiri, &message)?;
    let outbound_b = adapter.persona_outbound(&herald, &message)?;

    assert_eq!(outbound_a.body["username"], "Eiri");
    assert_eq!(outbound_b.body["username"], "Herald");
    assert_eq!(outbound_a.workspace_ref, workspace_ref);
    assert_eq!(outbound_a.identity_key, identity_key_a);
    assert_eq!(outbound_b.identity_key, identity_key_b);
    assert_eq!(
        outbound_a.body["metadata"]["event_payload"]["identity_key"],
        outbound_a.identity_key
    );
    assert_eq!(
        outbound_b.body["metadata"]["event_payload"]["identity_key"],
        outbound_b.identity_key
    );
    Ok(())
}

#[test]
fn cid8_slack_shared_presence_routes_two_agents_in_one_workspace() -> Result<()> {
    run_two_agent_smoke(SlackSmokeCase::workspace())
}

#[test]
fn cid8_slack_enterprise_grid_routes_two_agents_in_one_workspace() -> Result<()> {
    run_two_agent_smoke(SlackSmokeCase::enterprise_grid())
}

#[test]
#[ignore = "requires dev Slack workspace IDs; see docs/channel-identity-slack.md"]
fn cid8_slack_dev_workspace_env_smoke_seam() -> Result<()> {
    run_two_agent_smoke(SlackSmokeCase::from_dev_workspace_env()?)
}
