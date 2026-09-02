use super::*;
use crate::channel_identity::ChannelIdentityState;
use crate::surface_event::{InboundSurfaceRouteOutcome, SurfaceCounterpartyStamp};
use crate::{Vault, VaultConfig};

use crate::test_util::entity;

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    let vault = Vault::open(tmp.path(), cfg).expect("open vault");
    (tmp, vault)
}

const LINE_DESTINATION: &str = "U11111111111111111111111111111111";
const LINE_OTHER_DESTINATION: &str = "U22222222222222222222222222222222";
const LINE_USER_A: &str = "Uaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const LINE_USER_B: &str = "Ubbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn activate_line_identity(
    adapter: &LineOfficialAccountAdapter,
    vault: &Vault,
    identity_id: EntityId,
    agent_ref: EntityId,
    source_user_id: &str,
    requested_at: u64,
) -> Result<ChannelIdentity> {
    let identity =
        adapter.requested_identity(identity_id, agent_ref, source_user_id, requested_at)?;
    vault.create_channel_identity(&identity_id, &identity)?;
    vault.transition_channel_identity(
        &identity_id,
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Manual),
        requested_at + 1,
        None,
    )?;
    let provision = adapter.provision(
        &ProvisionIntent {
            identity_id,
            identity: identity.clone(),
            fulfillment_mode: ChannelIdentityFulfillment::Manual,
        },
        requested_at + 2,
    )?;
    vault.fulfill_channel_identity(
        provision.fulfillment_input(ChannelIdentityLifecycleActor::agent(agent_ref)),
    )?;
    Ok(identity)
}

fn assert_provider_conformance<A: ChannelIdentityProviderAdapter>(
    adapter: &A,
    intent: ProvisionIntent,
    inbound: ChannelIdentityProviderInbound,
) -> Result<()> {
    assert_eq!(
        adapter.fulfillment_mode(ChannelIdentityLifecycleVerb::Provision),
        Some(ChannelIdentityFulfillment::Api)
    );
    assert_eq!(
        adapter.fulfillment_mode(ChannelIdentityLifecycleVerb::Bind),
        None
    );
    let provision = adapter.provision(&intent, 2_000)?;
    assert_eq!(provision.identity_id, intent.identity_id);
    assert_eq!(provision.channel, intent.identity.channel);
    assert_eq!(
        provision.address_or_handle,
        intent.identity.address_or_handle
    );
    assert_eq!(provision.fulfillment_mode, ChannelIdentityFulfillment::Api);
    assert_eq!(
        provision
            .fulfillment_input(ChannelIdentityLifecycleActor::agent(entity(0x51)))
            .identity_id,
        intent.identity_id
    );
    let parsed = adapter.parse_inbound(inbound)?;
    assert_eq!(parsed.channel, EMAIL_CHANNEL);
    assert_eq!(
        parsed.receiving_address_or_handle,
        intent.identity.address_or_handle
    );
    assert!(parsed.foreign_inbound);
    Ok(())
}

#[test]
fn mock_adapter_conformance_suite_consumes_provision_and_inbound() -> Result<()> {
    let identity_id = entity(0x60);
    let agent_ref = entity(0x51);
    let address = "agent@example.test";
    let identity = ChannelIdentity::requested(
        EMAIL_CHANNEL,
        address,
        ChannelIdentityShape::DedicatedAddress,
        ChannelIdentityBinding::agent(agent_ref),
        1_000,
    );
    let adapter = MockChannelIdentityProviderAdapter::email(address);
    assert_provider_conformance(
        &adapter,
        ProvisionIntent {
            identity_id,
            identity,
            fulfillment_mode: ChannelIdentityFulfillment::Api,
        },
        ChannelIdentityProviderInbound::Email(EmailProviderInbound::new(
            "evt-1",
            address,
            "sender@example.test",
            2_001,
        )),
    )
}

#[test]
fn dev_email_adapter_derives_signed_per_identity_addresses() -> Result<()> {
    let adapter = DevEmailIdentityAdapter::new(DevEmailIdentityAdapterConfig::new(
        "Agents.Example.Test",
        "dev-secret",
    )?);
    let identity_id = entity(0x21);
    let agent_ref = entity(0x52);
    let address = adapter.address_for_identity(identity_id);

    assert!(address.ends_with("@agents.example.test"));
    assert!(address.starts_with("agent-21212121212121212121212121212121-"));

    let identity = adapter.requested_identity(identity_id, agent_ref, 1_000);
    assert_eq!(identity.address_or_handle, address);
    assert_eq!(identity.state, ChannelIdentityState::Requested);

    assert_provider_conformance(
        &adapter,
        ProvisionIntent {
            identity_id,
            identity,
            fulfillment_mode: ChannelIdentityFulfillment::Api,
        },
        ChannelIdentityProviderInbound::Email(EmailProviderInbound::new(
            "evt-dev",
            address,
            "Friend@Example.Test",
            2_002,
        )),
    )
}

#[test]
fn dev_email_adapter_rejects_catch_all_and_unsigned_local_parts() -> Result<()> {
    let adapter = DevEmailIdentityAdapter::new(DevEmailIdentityAdapterConfig::new(
        "agents.example.test",
        "dev-secret",
    )?);

    for address in ["*@agents.example.test", "random@agents.example.test"] {
        assert!(
            adapter
                .parse_inbound(ChannelIdentityProviderInbound::Email(
                    EmailProviderInbound::new("evt-reject", address, "sender@example.test", 2_003)
                ))
                .is_err(),
            "{address} should be rejected"
        );
    }
    Ok(())
}

#[test]
fn email_adapters_reject_oversized_inbound_fields_before_routing() -> Result<()> {
    let adapter = DevEmailIdentityAdapter::new(DevEmailIdentityAdapterConfig::new(
        "agents.example.test",
        "dev-secret",
    )?);
    let address = adapter.address_for_identity(entity(0x29));

    for inbound in [
        EmailProviderInbound::new(
            "e".repeat(MAX_EMAIL_PROVIDER_EVENT_ID_BYTES + 1),
            address.clone(),
            "sender@example.test",
            2_004,
        ),
        EmailProviderInbound::new(
            "evt-long-payload",
            address.clone(),
            "sender@example.test",
            2_004,
        )
        .with_payload_ref("p".repeat(MAX_EMAIL_PAYLOAD_REF_BYTES + 1)),
        EmailProviderInbound::new(
            "evt-long-from",
            address,
            format!(
                "{}@example.test",
                "s".repeat(MAX_EMAIL_LOCAL_PART_BYTES + 1)
            ),
            2_004,
        ),
        EmailProviderInbound::new(
            "evt-long-to",
            format!(
                "{}@agents.example.test",
                "r".repeat(MAX_EMAIL_LOCAL_PART_BYTES + 1)
            ),
            "sender@example.test",
            2_004,
        ),
    ] {
        assert!(
            adapter
                .parse_inbound(ChannelIdentityProviderInbound::Email(inbound))
                .is_err(),
            "oversized inbound field should be rejected"
        );
    }

    let mock = MockChannelIdentityProviderAdapter::email("agent@example.test");
    assert!(
        mock.parse_inbound(ChannelIdentityProviderInbound::Email(
            EmailProviderInbound::new(
                "evt-mock-long-from",
                "agent@example.test",
                format!(
                    "{}@example.test",
                    "s".repeat(MAX_EMAIL_LOCAL_PART_BYTES + 1)
                ),
                2_004,
            )
        ))
        .is_err(),
        "mock adapter must also bound persisted counterparty addresses"
    );
    Ok(())
}

#[test]
fn dev_email_adapter_prefix_limit_keeps_local_part_smtp_sized() -> Result<()> {
    let valid_prefix = "p".repeat(MAX_LOCAL_PART_PREFIX_BYTES);
    let adapter = DevEmailIdentityAdapter::new(DevEmailIdentityAdapterConfig::with_prefix(
        "agents.example.test",
        &valid_prefix,
        "dev-secret",
    )?);
    let address = adapter.address_for_identity(entity(0x41));
    let (local_part, _) = address
        .split_once('@')
        .expect("adapter emits email address");
    assert_eq!(local_part.len(), MAX_EMAIL_LOCAL_PART_BYTES);

    let too_long_prefix = "p".repeat(MAX_LOCAL_PART_PREFIX_BYTES + 1);
    assert!(
        DevEmailIdentityAdapterConfig::with_prefix(
            "agents.example.test",
            too_long_prefix,
            "dev-secret"
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn dev_email_adapter_requires_agent_scoped_dedicated_address() -> Result<()> {
    let adapter = DevEmailIdentityAdapter::new(DevEmailIdentityAdapterConfig::new(
        "agents.example.test",
        "dev-secret",
    )?);
    let identity_id = entity(0x31);
    let mut identity = adapter.requested_identity(identity_id, entity(0x53), 1_000);
    identity.binding = ChannelIdentityBinding::vault(42);

    let err = adapter
        .provision(
            &ProvisionIntent {
                identity_id,
                identity,
                fulfillment_mode: ChannelIdentityFulfillment::Api,
            },
            2_000,
        )
        .expect_err("vault-scoped email identity must be rejected");
    assert!(matches!(err, Error::InvalidConfig(_)));
    Ok(())
}

fn slack_adapter() -> Result<SlackSharedPresenceAdapter> {
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
fn slack_manifest_payload_is_ready_for_apps_manifest_create() -> Result<()> {
    let adapter = slack_adapter()?;
    let payload = adapter.apps_manifest_create_payload();
    let manifest_arg = payload["manifest"]
        .as_str()
        .expect("apps.manifest.create manifest argument is a string");
    let manifest: Value = serde_json::from_str(manifest_arg)
        .map_err(|err| Error::InvalidConfig(format!("invalid manifest json: {err}")))?;

    assert_eq!(manifest["display_information"]["name"], "Oneiron");
    assert_eq!(
        manifest["settings"]["event_subscriptions"]["request_url"],
        "https://oneiron.example.test/slack/events"
    );
    assert_eq!(
        manifest["settings"]["token_rotation_enabled"],
        Value::Bool(true)
    );
    let scopes = manifest["oauth_config"]["scopes"]["bot"]
        .as_array()
        .expect("bot scopes");
    assert!(scopes.contains(&Value::from("chat:write")));
    assert!(scopes.contains(&Value::from("chat:write.customize")));
    assert!(scopes.contains(&Value::from("app_mentions:read")));
    Ok(())
}

#[test]
fn slack_shared_presence_identities_distinguish_agents_in_one_workspace() -> Result<()> {
    let adapter = slack_adapter()?;
    let agent_a = entity(0xB1);
    let agent_b = entity(0xB2);
    let identity_a = adapter.requested_identity(agent_a, "T123ABC", "@eiri", 1_000)?;
    let identity_b = adapter.requested_identity(agent_b, "T123ABC", "herald", 1_000)?;

    assert_eq!(identity_a.channel, SLACK_CHANNEL);
    assert_eq!(identity_a.shape, ChannelIdentityShape::SharedPresence);
    assert_eq!(identity_a.binding, ChannelIdentityBinding::agent(agent_a));
    assert_eq!(
        identity_a.address_or_handle,
        "slack:workspace:T123ABC:persona:eiri"
    );
    assert_eq!(
        identity_b.address_or_handle,
        "slack:workspace:T123ABC:persona:herald"
    );

    let identity_id = entity(0x61);
    let provision = adapter.provision(
        &ProvisionIntent {
            identity_id,
            identity: identity_a,
            fulfillment_mode: ChannelIdentityFulfillment::Api,
        },
        2_000,
    )?;
    assert_eq!(provision.provider_key, SLACK_SHARED_PRESENCE_PROVIDER_KEY);
    assert_eq!(provision.channel, SLACK_CHANNEL);
    assert_eq!(provision.fulfillment_mode, ChannelIdentityFulfillment::Api);
    assert!(
        provision
            .provider_identity_ref
            .contains("slack:workspace:T123ABC:persona:eiri")
    );
    Ok(())
}

#[test]
fn slack_enterprise_identity_matches_inbound_and_outbound_keys() -> Result<()> {
    let adapter = slack_adapter()?;
    let expected_workspace_ref = "slack:enterprise:E123ABC:workspace:T123ABC";
    let expected_identity_key = "slack:enterprise:E123ABC:workspace:T123ABC:persona:eiri";
    let identity = adapter.requested_enterprise_identity(
        entity(0xB3),
        "E123ABC",
        "T123ABC",
        "@Eiri",
        1_000,
    )?;

    assert_eq!(identity.channel, SLACK_CHANNEL);
    assert_eq!(identity.shape, ChannelIdentityShape::SharedPresence);
    assert_eq!(identity.address_or_handle, expected_identity_key);
    assert_eq!(
        SlackSharedPresenceAdapter::workspace_ref("T123ABC", Some("E123ABC"))?,
        expected_workspace_ref
    );
    assert_eq!(
        SlackSharedPresenceAdapter::persona_identity_key("T123ABC", Some("E123ABC"), "@Eiri")?,
        expected_identity_key
    );

    let parsed = adapter.parse_inbound(ChannelIdentityProviderInbound::Slack(
        SlackProviderInbound::new("EvGrid", "T123ABC", "C123ABC", "U123ABC", "eiri", 2_001)
            .with_enterprise_id("E123ABC"),
    ))?;
    assert_eq!(
        parsed.workspace_ref.as_deref(),
        Some(expected_workspace_ref)
    );
    assert_eq!(parsed.receiving_address_or_handle, expected_identity_key);
    assert_eq!(
        parsed.counterparty,
        SurfaceCounterpartyStamp::unknown(
            "slack:enterprise:E123ABC:workspace:T123ABC:user:U123ABC"
        )
    );

    let attribution = SlackPersonaAttribution::new("eiri", "Eiri")?;
    let message = SlackOutboundMessage::new("T123ABC", "C123ABC", "Grid hello")?
        .with_enterprise_id("E123ABC")?;
    let outbound = adapter.persona_outbound(&attribution, &message)?;
    assert_eq!(outbound.workspace_ref, expected_workspace_ref);
    assert_eq!(outbound.identity_key, expected_identity_key);
    assert!(outbound.body.get("metadata").is_none());

    let outbound_with_metadata = adapter.persona_outbound_with_metadata(&attribution, &message)?;
    assert_eq!(
        outbound_with_metadata.body["metadata"]["event_payload"]["workspace_ref"],
        expected_workspace_ref
    );
    assert_eq!(
        outbound_with_metadata.body["metadata"]["event_payload"]["identity_key"],
        expected_identity_key
    );
    Ok(())
}

#[test]
fn slack_adapter_rejects_non_shared_presence_provision() -> Result<()> {
    let adapter = slack_adapter()?;
    let mut identity = adapter.requested_identity(entity(0xB1), "T123ABC", "eiri", 1_000)?;
    identity.shape = ChannelIdentityShape::DedicatedHandle;

    let err = adapter
        .provision(
            &ProvisionIntent {
                identity_id: entity(0x62),
                identity,
                fulfillment_mode: ChannelIdentityFulfillment::Api,
            },
            2_000,
        )
        .expect_err("slack adapter must require shared_presence");
    assert!(matches!(err, Error::InvalidConfig(_)));
    Ok(())
}

#[test]
fn slack_inbound_stamps_workspace_and_persona_identity() -> Result<()> {
    let adapter = slack_adapter()?;
    let parsed = adapter.parse_inbound(ChannelIdentityProviderInbound::Slack(
        SlackProviderInbound::new("Ev123", "T123ABC", "C123ABC", "U123ABC", "@Eiri", 2_001)
            .with_payload_ref("slack:event:Ev123"),
    ))?;

    assert_eq!(parsed.channel, SLACK_CHANNEL);
    assert_eq!(
        parsed.receiving_address_or_handle,
        "slack:workspace:T123ABC:persona:eiri"
    );
    assert_eq!(
        parsed.workspace_ref.as_deref(),
        Some("slack:workspace:T123ABC")
    );
    assert_eq!(parsed.payload_ref.as_deref(), Some("slack:event:Ev123"));
    assert_eq!(
        parsed.counterparty,
        SurfaceCounterpartyStamp::unknown("slack:workspace:T123ABC:user:U123ABC")
    );
    assert!(parsed.foreign_inbound);
    Ok(())
}

#[test]
fn slack_outbound_payload_carries_persona_attribution() -> Result<()> {
    let adapter = slack_adapter()?;
    let attribution =
        SlackPersonaAttribution::new("@Eiri", "Eiri")?.with_icon_emoji(":sparkles:")?;
    let message = SlackOutboundMessage::new("T123ABC", "C123ABC", "I can take this.")?
        .with_thread_ts("1719860000.000100")?
        .with_payload_ref("outbound:one")?;

    let outbound = adapter.persona_outbound(&attribution, &message)?;

    assert_eq!(outbound.method, "chat.postMessage");
    assert_eq!(outbound.workspace_ref, "slack:workspace:T123ABC");
    assert_eq!(
        outbound.identity_key,
        "slack:workspace:T123ABC:persona:eiri"
    );
    assert_eq!(outbound.body["channel"], "C123ABC");
    assert_eq!(outbound.body["username"], "Eiri");
    assert_eq!(outbound.body["icon_emoji"], ":sparkles:");
    assert!(outbound.body.get("metadata").is_none());

    let outbound_with_metadata = adapter.persona_outbound_with_metadata(&attribution, &message)?;
    assert_eq!(
        outbound_with_metadata.body["metadata"]["event_payload"]["identity_key"],
        "slack:workspace:T123ABC:persona:eiri"
    );
    assert_eq!(
        outbound_with_metadata.body["metadata"]["event_payload"]["payload_ref"],
        "outbound:one"
    );
    Ok(())
}
#[test]
fn line_oa_adapter_manual_fulfillment_and_inbound_stamping() -> Result<()> {
    let config =
        LineOfficialAccountAdapterConfig::new(LINE_DESTINATION, LineOfficialAccountPlanTier::Free)?;
    let adapter = LineOfficialAccountAdapter::new(config);
    let identity_id = entity(0x61);
    let agent_ref = entity(0xD6);
    let source_user_id = LINE_USER_A;
    let address = adapter.address_for_line_user(source_user_id)?;

    assert_eq!(
        adapter.fulfillment_mode(ChannelIdentityLifecycleVerb::Provision),
        Some(ChannelIdentityFulfillment::Manual)
    );
    assert_eq!(
        adapter.fulfillment_mode(ChannelIdentityLifecycleVerb::Bind),
        Some(ChannelIdentityFulfillment::Manual)
    );
    assert_eq!(
        adapter.fulfillment_mode(ChannelIdentityLifecycleVerb::RouteInbound),
        None
    );

    let identity = adapter.requested_identity(identity_id, agent_ref, source_user_id, 1_000)?;
    assert_eq!(identity.channel, LINE_CHANNEL);
    assert_eq!(identity.address_or_handle, address);
    assert_eq!(identity.shape, ChannelIdentityShape::SharedPresence);
    assert!(matches!(
        identity.binding,
        ChannelIdentityBinding::Agent { agent_ref: bound } if bound == agent_ref
    ));

    let provision = adapter.provision(
        &ProvisionIntent {
            identity_id,
            identity: identity.clone(),
            fulfillment_mode: ChannelIdentityFulfillment::Manual,
        },
        1_002,
    )?;
    assert_eq!(provision.provider_key, LINE_OFFICIAL_ACCOUNT_PROVIDER_KEY);
    assert_eq!(
        provision.fulfillment_mode,
        ChannelIdentityFulfillment::Manual
    );
    assert_eq!(
        provision.provider_identity_ref,
        format!("line-oa:{LINE_DESTINATION}")
    );

    let (_tmp, vault) = temp_vault();
    vault.create_channel_identity(&identity_id, &identity)?;
    vault.transition_channel_identity(
        &identity_id,
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Manual),
        1_001,
        None,
    )?;
    vault.fulfill_channel_identity(
        provision.fulfillment_input(ChannelIdentityLifecycleActor::agent(agent_ref)),
    )?;

    let parsed = adapter.parse_inbound(ChannelIdentityProviderInbound::Line(
        LineOfficialAccountInbound::new("line-event-1", LINE_DESTINATION, source_user_id, 1_003)
            .with_reply_token("reply-token-redacted")
            .with_payload_ref("provider:line-event-1"),
    ))?;

    assert_eq!(parsed.channel, LINE_CHANNEL);
    assert_eq!(parsed.receiving_address_or_handle, address);
    assert_eq!(
        parsed.counterparty,
        SurfaceCounterpartyStamp::unknown(format!("line:user:{LINE_USER_A}"))
    );
    assert!(parsed.foreign_inbound);

    let receipt = vault.route_inbound_surface_event(parsed)?;
    assert_eq!(receipt.outcome, InboundSurfaceRouteOutcome::Routed);
    assert_eq!(receipt.receiving_identity_ref, Some(identity_id.to_hex()));
    assert_eq!(receipt.agent_ref, Some(agent_ref.to_hex()));
    let surface_event = receipt.surface_event.expect("routed event");
    assert_eq!(surface_event.receiving_identity_ref, identity_id.to_hex());
    assert_eq!(surface_event.agent_ref, agent_ref.to_hex());
    assert_eq!(
        surface_event.payload_ref.as_deref(),
        Some("provider:line-event-1")
    );
    assert!(surface_event.claims_not_instructions);

    let serialized = serde_json::to_value(ChannelIdentityProviderInbound::Line(
        LineOfficialAccountInbound::new(
            "line-event-serialized",
            LINE_DESTINATION,
            source_user_id,
            1_004,
        )
        .with_reply_token("reply-token-secret")
        .with_payload_ref("provider:line-event-serialized"),
    ))
    .expect("serialize LINE inbound");
    assert!(serialized.get("reply_token").is_none());
    assert_eq!(
        serialized
            .get("payload_ref")
            .and_then(serde_json::Value::as_str),
        Some("provider:line-event-serialized")
    );

    let missing_handle_err = adapter
        .parse_inbound(ChannelIdentityProviderInbound::Line(
            LineOfficialAccountInbound::new(
                "line-event-missing-handle",
                LINE_DESTINATION,
                source_user_id,
                1_005,
            )
            .with_reply_token("reply-token-without-host-handle"),
        ))
        .expect_err("LINE reply token without payload_ref must fail closed");
    assert!(matches!(
        missing_handle_err,
        Error::InvalidConfig(reason)
            if reason == "LINE reply token requires payload_ref host-local handle"
    ));
    Ok(())
}

#[test]
fn line_oa_shared_presence_routes_users_to_separate_personas() -> Result<()> {
    let adapter = LineOfficialAccountAdapter::new(
        LineOfficialAccountAdapterConfig::with_monthly_push_allowance(
            LINE_DESTINATION,
            LineOfficialAccountPlanTier::Paid,
            10_000,
        )?,
    );
    let (_tmp, vault) = temp_vault();

    let identity_a = entity(0x71);
    let identity_b = entity(0x72);
    let agent_a = entity(0xA7);
    let agent_b = entity(0xB7);
    activate_line_identity(&adapter, &vault, identity_a, agent_a, LINE_USER_A, 2_000)?;
    activate_line_identity(&adapter, &vault, identity_b, agent_b, LINE_USER_B, 2_100)?;

    let parsed_a = adapter.parse_inbound(ChannelIdentityProviderInbound::Line(
        LineOfficialAccountInbound::new("line-event-a", LINE_DESTINATION, LINE_USER_A, 2_200),
    ))?;
    let parsed_b = adapter.parse_inbound(ChannelIdentityProviderInbound::Line(
        LineOfficialAccountInbound::new("line-event-b", LINE_DESTINATION, LINE_USER_B, 2_201),
    ))?;
    assert_ne!(
        parsed_a.receiving_address_or_handle,
        parsed_b.receiving_address_or_handle
    );

    let receipt_a = vault.route_inbound_surface_event(parsed_a)?;
    let receipt_b = vault.route_inbound_surface_event(parsed_b)?;
    assert_eq!(receipt_a.receiving_identity_ref, Some(identity_a.to_hex()));
    assert_eq!(receipt_a.agent_ref, Some(agent_a.to_hex()));
    assert_eq!(receipt_b.receiving_identity_ref, Some(identity_b.to_hex()));
    assert_eq!(receipt_b.agent_ref, Some(agent_b.to_hex()));
    Ok(())
}

#[test]
fn line_oa_adapter_rejects_wrong_destination_and_non_shared_presence() -> Result<()> {
    let adapter = LineOfficialAccountAdapter::new(LineOfficialAccountAdapterConfig::new(
        LINE_DESTINATION,
        LineOfficialAccountPlanTier::Free,
    )?);
    let inbound_err = adapter
        .parse_inbound(ChannelIdentityProviderInbound::Line(
            LineOfficialAccountInbound::new(
                "line-event-wrong",
                LINE_OTHER_DESTINATION,
                LINE_USER_A,
                3_000,
            ),
        ))
        .expect_err("wrong OA destination must fail closed");
    assert!(matches!(inbound_err, Error::InvalidConfig(_)));

    let identity_id = entity(0x81);
    let mut identity = adapter.requested_identity(identity_id, entity(0xA8), LINE_USER_A, 3_100)?;
    identity.shape = ChannelIdentityShape::DedicatedHandle;
    let provision_err = adapter
        .provision(
            &ProvisionIntent {
                identity_id,
                identity,
                fulfillment_mode: ChannelIdentityFulfillment::Manual,
            },
            3_101,
        )
        .expect_err("dedicated per-companion OA is out of v1 shared_presence scope");
    assert!(matches!(provision_err, Error::InvalidConfig(_)));

    let overlong_user_id = "U".repeat(MAX_LINE_COMPONENT_BYTES + 1);
    let length_err = adapter
        .address_for_line_user(&overlong_user_id)
        .expect_err("overlong LINE source user id must fail clearly");
    assert!(matches!(
        length_err,
        Error::InvalidConfig(reason)
            if reason == format!(
                "LINE source user id exceeds maximum length: {MAX_LINE_COMPONENT_BYTES} bytes"
            )
    ));
    Ok(())
}

#[test]
fn line_oa_non_free_plans_require_explicit_push_allowance() -> Result<()> {
    let free =
        LineOfficialAccountAdapterConfig::new(LINE_DESTINATION, LineOfficialAccountPlanTier::Free)?;
    assert_eq!(
        free.monthly_push_allowance(),
        DEFAULT_LINE_PUSH_MONTHLY_ALLOWANCE
    );

    for plan_tier in [
        LineOfficialAccountPlanTier::Paid,
        LineOfficialAccountPlanTier::Enterprise,
    ] {
        let err = LineOfficialAccountAdapterConfig::new(LINE_DESTINATION, plan_tier)
            .expect_err("non-free LINE OA plans must not inherit the free allowance");
        assert!(matches!(
            err,
            Error::InvalidConfig(reason)
                if reason == "LINE OA non-free plan requires explicit monthly push allowance"
        ));

        let explicit = LineOfficialAccountAdapterConfig::with_monthly_push_allowance(
            LINE_DESTINATION,
            plan_tier,
            25_000,
        )?;
        assert_eq!(explicit.plan_tier(), plan_tier);
        assert_eq!(explicit.monthly_push_allowance(), 25_000);
    }
    Ok(())
}

#[test]
fn line_oa_adapter_validates_provider_native_id_shapes() -> Result<()> {
    let destination_err =
        LineOfficialAccountAdapterConfig::new("Uproductoa123", LineOfficialAccountPlanTier::Free)
            .expect_err("LINE destination must use provider-native shape");
    assert!(matches!(
        destination_err,
        Error::InvalidConfig(reason)
            if reason
                == "LINE OA Messaging API destination must match LINE user id shape U[0-9a-f]{32}"
    ));

    let adapter = LineOfficialAccountAdapter::new(LineOfficialAccountAdapterConfig::new(
        LINE_DESTINATION,
        LineOfficialAccountPlanTier::Free,
    )?);
    let source_err = adapter
        .requested_identity(entity(0x91), entity(0xA9), "UlineUserA", 4_000)
        .expect_err("LINE source user id must use provider-native shape");
    assert!(matches!(
        source_err,
        Error::InvalidConfig(reason)
            if reason == "LINE source user id must match LINE user id shape U[0-9a-f]{32}"
    ));

    let inbound_err = adapter
        .parse_inbound(ChannelIdentityProviderInbound::Line(
            LineOfficialAccountInbound::new(
                "line-event-invalid-source",
                LINE_DESTINATION,
                "UlineUserA",
                4_001,
            ),
        ))
        .expect_err("invalid LINE source user id must not route inbound");
    assert!(matches!(
        inbound_err,
        Error::InvalidConfig(reason)
            if reason == "LINE source user id must match LINE user id shape U[0-9a-f]{32}"
    ));
    Ok(())
}

// --- INB-00: Gmail/Workspace delegated-grant adapter -----------------------

use crate::attempt_queue::{AttemptQueue, EnqueueOutcome};
use crate::channel_identity::{
    CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION, DelegatedGrantScope, encode_channel_identity_body,
};
use crate::channel_identity_provider::gmail::{
    GMAIL_CONNECTOR_EFFECTOR, GMAIL_DELEGATED_PROVIDER_KEY, GMAIL_INBOX_POLL_ATTEMPT_KIND,
    GMAIL_METADATA_OAUTH_SCOPE, GMAIL_READONLY_OAUTH_SCOPE, GmailDelegatedAdapter,
    GmailDelegatedAdapterConfig, GmailInboxPage, GmailInboxPollConfig, GmailMessageMetadata,
    GmailReadWire, delegated_scope_for_google_oauth_scope, gmail_inbox_poll_dedupe_key,
};
use crate::secret_custody::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_SCHEMA_VERSION, SecretBinding, SecretCustodyFloor,
    SecretCustodyRecord, SecretCustodyStatus,
};

const MEMBER_MAILBOX: &str = "member@member-owned.test";
const GMAIL_CUSTODY_REF: &str = "gmail-delegated:member@member-owned.test";
// Benign stand-in: no detector-shaped credential material (the gate write
// wall scans bodies).
const GRANT_VALUE: &[u8] = b"wave6-inb00-delegated-grant-value";

fn gmail_custody_record(name: &str, bindings: Vec<SecretBinding>) -> SecretCustodyRecord {
    SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: name.to_owned(),
        class: CustodyClass::CustodyPortable,
        device_only: false,
        value_bytes: GRANT_VALUE.to_vec(),
        status: SecretCustodyStatus::Active,
        registered_at: 1_700_000_000,
        rotated_at: None,
        rotation_generation: 0,
        bindings,
        manifest_ref: "secrets.toml".to_owned(),
        declared_paths: Vec::new(),
        policy_floor_snapshot: SecretCustodyFloor::default(),
    }
}

fn gmail_read_binding() -> SecretBinding {
    SecretBinding {
        effector: GMAIL_CONNECTOR_EFFECTOR.to_owned(),
        tier_ceiling: CustodyTier::T1Leased,
        scopes: vec!["read".to_owned()],
    }
}

fn gmail_adapter() -> Result<GmailDelegatedAdapter> {
    Ok(GmailDelegatedAdapter::new(
        GmailDelegatedAdapterConfig::new(MEMBER_MAILBOX, GMAIL_CUSTODY_REF)?
            .with_google_oauth_scopes(&[GMAIL_READONLY_OAUTH_SCOPE, GMAIL_METADATA_OAUTH_SCOPE])?,
    ))
}

/// Host wire stand-in. It is handed the custody NAME and never a value, which
/// is the whole point of the seam.
struct RecordingGmailWire {
    page: GmailInboxPage,
    seen_secret_ref: std::cell::RefCell<Option<String>>,
}

impl GmailReadWire for RecordingGmailWire {
    fn fetch_inbox_page(
        &self,
        secret_ref: &str,
        _mailbox_address: &str,
        _cursor: Option<&str>,
    ) -> Result<GmailInboxPage> {
        *self.seen_secret_ref.borrow_mut() = Some(secret_ref.to_owned());
        Ok(self.page.clone())
    }
}

#[test]
fn gmail_delegated_adapter_provisions_routes_and_polls() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let adapter = gmail_adapter()?;
    assert_eq!(adapter.provider_key(), GMAIL_DELEGATED_PROVIDER_KEY);

    vault.register_secret(gmail_custody_record(
        GMAIL_CUSTODY_REF,
        vec![gmail_read_binding()],
    ))?;

    let identity_id = entity(0x7A);
    let agent_ref = entity(0xAA);
    let requested = adapter.requested_identity(&vault, agent_ref, 7_000)?;
    assert_eq!(requested.shape, ChannelIdentityShape::DelegatedGrant);
    assert_eq!(requested.address_or_handle, MEMBER_MAILBOX);
    assert_eq!(
        requested
            .delegated_grant
            .as_ref()
            .expect("grant")
            .custody_record_ref,
        GMAIL_CUSTODY_REF
    );

    // The row is a pointer into custody: the durable body carries the name
    // and never the granted value.
    let encoded = encode_channel_identity_body(&requested)?;
    assert!(
        !encoded
            .windows(GRANT_VALUE.len())
            .any(|window| window == GRANT_VALUE)
    );
    assert!(
        encoded
            .windows(GMAIL_CUSTODY_REF.len())
            .any(|window| window == GMAIL_CUSTODY_REF.as_bytes())
    );

    let provision = adapter.provision(
        &ProvisionIntent {
            identity_id,
            identity: requested.clone(),
            fulfillment_mode: ChannelIdentityFulfillment::Api,
        },
        7_010,
    )?;
    assert_eq!(provision.channel, EMAIL_CHANNEL);
    assert_eq!(provision.address_or_handle, MEMBER_MAILBOX);
    assert_eq!(provision.fulfillment_mode, ChannelIdentityFulfillment::Api);

    vault.create_channel_identity(&identity_id, &requested)?;
    vault.transition_channel_identity(
        &identity_id,
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Api),
        7_020,
        None,
    )?;
    let active = vault.transition_channel_identity(
        &identity_id,
        ChannelIdentityState::Active,
        None,
        7_030,
        None,
    )?;
    assert_eq!(active.state, ChannelIdentityState::Active);

    // Read one page through the wire, then normalize Gmail-native fields into
    // the ordinary email inbound envelope.
    let wire = RecordingGmailWire {
        page: GmailInboxPage::new(
            vec![GmailMessageMetadata::new(
                "18f0a1b2c3d4e5f6",
                "18f0a1b2c3d4e500",
                MEMBER_MAILBOX,
                "counterparty@example.test",
                7_040,
            )],
            Some("history-9001".to_owned()),
        ),
        seen_secret_ref: std::cell::RefCell::new(None),
    };
    let page = adapter.fetch_inbox_page(&wire, None)?;
    assert_eq!(
        wire.seen_secret_ref.borrow().as_deref(),
        Some(GMAIL_CUSTODY_REF)
    );
    assert_eq!(page.next_cursor.as_deref(), Some("history-9001"));

    let message = page.messages.into_iter().next().expect("one message");
    let parsed = adapter.parse_inbound(ChannelIdentityProviderInbound::Email(
        message.into_provider_inbound()?,
    ))?;
    assert_eq!(parsed.channel, EMAIL_CHANNEL);
    assert_eq!(parsed.receiving_address_or_handle, MEMBER_MAILBOX);
    assert_eq!(parsed.event_id, "gmail:18f0a1b2c3d4e5f6");
    assert_eq!(
        parsed.counterparty,
        SurfaceCounterpartyStamp::unknown("email:counterparty@example.test".to_owned())
    );
    assert!(parsed.foreign_inbound);

    // Delegated inbound rides the existing stamp with no special-casing.
    let receipt = vault.route_inbound_surface_event(parsed)?;
    assert_eq!(receipt.outcome, InboundSurfaceRouteOutcome::Routed);
    assert_eq!(receipt.receiving_identity_ref, Some(identity_id.to_hex()));
    assert_eq!(receipt.agent_ref, Some(agent_ref.to_hex()));
    let surface_event = receipt.surface_event.expect("routed event");
    assert_eq!(surface_event.receiving_identity_ref, identity_id.to_hex());
    assert_eq!(
        surface_event.payload_ref.as_deref(),
        Some("gmail:thread:18f0a1b2c3d4e500")
    );
    assert!(surface_event.claims_not_instructions);

    // Exactly one poll attempt, deduped per identity, over the read-only
    // attempt-queue API.
    let first = adapter.enqueue_inbox_poll(&vault, identity_id, 7_050)?;
    let EnqueueOutcome::Enqueued(attempt) = first else {
        panic!("first poll enqueue must mint an attempt");
    };
    assert_eq!(attempt.kind, GMAIL_INBOX_POLL_ATTEMPT_KIND);
    assert_eq!(
        attempt.dedupe_key.as_deref(),
        Some(gmail_inbox_poll_dedupe_key(identity_id).as_str())
    );
    let payload = serde_json::from_slice::<GmailInboxPollConfig>(&attempt.payload)
        .expect("poll payload decodes");
    assert_eq!(payload.mailbox_address, MEMBER_MAILBOX);
    assert_eq!(payload.custody_record_ref, GMAIL_CUSTODY_REF);
    assert_eq!(payload.identity_ref, identity_id.to_hex());
    assert!(
        !attempt
            .payload
            .windows(GRANT_VALUE.len())
            .any(|window| window == GRANT_VALUE)
    );

    let second = adapter.enqueue_inbox_poll(&vault, identity_id, 7_060)?;
    assert!(matches!(second, EnqueueOutcome::Existing(_)));
    assert_eq!(
        AttemptQueue::new(&vault)
            .list()?
            .iter()
            .filter(|row| row.kind == GMAIL_INBOX_POLL_ATTEMPT_KIND)
            .count(),
        1
    );
    Ok(())
}

#[test]
fn gmail_delegated_provisioning_requires_a_covering_custody_binding() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let adapter = gmail_adapter()?;
    let agent_ref = entity(0xAB);

    // No custody record at all.
    let missing = adapter
        .requested_identity(&vault, agent_ref, 8_000)
        .expect_err("provisioning without an existing grant must fail closed");
    assert!(matches!(
        missing,
        Error::SecretRefNotFound { name } if name == GMAIL_CUSTODY_REF
    ));

    // A record exists, but nothing binds `connector:gmail` with a read scope.
    // Naming the effector is not itself a grant, and an empty scope list is
    // no grant at all.
    vault.register_secret(gmail_custody_record(
        GMAIL_CUSTODY_REF,
        vec![
            SecretBinding {
                effector: "connector:other".to_owned(),
                tier_ceiling: CustodyTier::T1Leased,
                scopes: vec!["read".to_owned()],
            },
            SecretBinding {
                effector: GMAIL_CONNECTOR_EFFECTOR.to_owned(),
                tier_ceiling: CustodyTier::T1Leased,
                scopes: Vec::new(),
            },
        ],
    ))?;
    let uncovered = adapter
        .requested_identity(&vault, agent_ref, 8_010)
        .expect_err("an uncovered binding must fail closed");
    assert!(matches!(
        uncovered,
        Error::SecretBindingDenied { effector, secret_ref }
            if effector == GMAIL_CONNECTOR_EFFECTOR && secret_ref == GMAIL_CUSTODY_REF
    ));
    Ok(())
}

#[test]
fn gmail_delegated_token_use_goes_through_the_custody_door() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let adapter = gmail_adapter()?;
    vault.register_secret(gmail_custody_record(
        GMAIL_CUSTODY_REF,
        vec![gmail_read_binding()],
    ))?;

    // The value is reachable only INSIDE the door closure, under the
    // `connector:gmail` effector binding, and the receipt carries none of it.
    let mut seen_len = 0usize;
    let door_receipt = adapter.with_delegated_token_at_door(&vault, &mut |value| {
        seen_len = value.len();
        Ok(())
    })?;
    assert_eq!(seen_len, GRANT_VALUE.len());
    assert_eq!(door_receipt.secret_ref, GMAIL_CUSTODY_REF);
    assert_eq!(door_receipt.effector, GMAIL_CONNECTOR_EFFECTOR);
    let serialized = serde_json::to_vec(&door_receipt).expect("receipt serializes");
    assert!(
        !serialized
            .windows(GRANT_VALUE.len())
            .any(|window| window == GRANT_VALUE)
    );
    Ok(())
}

#[test]
fn gmail_delegated_adapter_exposes_no_send_surface() -> Result<()> {
    // Write scopes have nowhere to land: neither the provider-scope mapping
    // nor the config builder admits one, so a row can never claim send.
    for write_scope in [
        "https://www.googleapis.com/auth/gmail.send",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.compose",
        "https://mail.google.com/",
    ] {
        assert_eq!(delegated_scope_for_google_oauth_scope(write_scope), None);
        let err = GmailDelegatedAdapterConfig::new(MEMBER_MAILBOX, GMAIL_CUSTODY_REF)?
            .with_google_oauth_scopes(&[GMAIL_READONLY_OAUTH_SCOPE, write_scope])
            .expect_err("a write scope must be refused, not silently narrowed");
        assert!(matches!(err, Error::InvalidConfig(reason) if reason.contains("read scopes only")));
    }
    assert_eq!(
        delegated_scope_for_google_oauth_scope(GMAIL_READONLY_OAUTH_SCOPE),
        Some(DelegatedGrantScope::MailRead)
    );
    assert_eq!(
        delegated_scope_for_google_oauth_scope(GMAIL_METADATA_OAUTH_SCOPE),
        Some(DelegatedGrantScope::MailMetadata)
    );

    // The capability matrix carries the fourth shape on the email channel and
    // declares receive capabilities only — there is no send capability listed
    // for delegated_grant because the manifest has no send surface at all.
    let email = crate::channel_identity_manifest::channel_identity_manifest("email")
        .expect("email manifest");
    assert!(email.shapes.contains(&ChannelIdentityShape::DelegatedGrant));
    assert!(email.receive_capabilities.messaging);
    assert!(
        email
            .policy_risk_notes
            .iter()
            .any(|note| note.contains("scoped-read only"))
    );
    assert!(
        email
            .policy_risk_notes
            .iter()
            .any(|note| note.contains("Revocation and rotation"))
    );

    // The adapter offers a fulfillment lane for provisioning only; rotation
    // is not something it can even be asked to do.
    let adapter = gmail_adapter()?;
    assert_eq!(
        adapter.fulfillment_mode(ChannelIdentityLifecycleVerb::Provision),
        Some(ChannelIdentityFulfillment::Api)
    );
    for verb in [
        ChannelIdentityLifecycleVerb::Bind,
        ChannelIdentityLifecycleVerb::Rotate,
        ChannelIdentityLifecycleVerb::Release,
        ChannelIdentityLifecycleVerb::RouteInbound,
    ] {
        assert_eq!(adapter.fulfillment_mode(verb), None);
    }
    Ok(())
}

#[test]
fn gmail_delegated_adapter_rejects_foreign_mailboxes_and_shapes() -> Result<()> {
    let adapter = gmail_adapter()?;

    let wrong_mailbox = adapter
        .parse_inbound(ChannelIdentityProviderInbound::Email(
            GmailMessageMetadata::new(
                "18f0a1b2c3d4e5f7",
                "18f0a1b2c3d4e501",
                "someone-else@member-owned.test",
                "counterparty@example.test",
                9_000,
            )
            .into_provider_inbound()?,
        ))
        .expect_err("inbound for another mailbox must not route");
    assert!(matches!(
        wrong_mailbox,
        Error::InvalidConfig(reason) if reason == "gmail inbound envelope-to is not the granted mailbox"
    ));

    // A self-held row cannot be provisioned through the delegated adapter,
    // and a delegated row whose grant ref disagrees with the binding is
    // refused rather than re-pointed.
    let self_held = ChannelIdentity::requested(
        EMAIL_CHANNEL,
        MEMBER_MAILBOX,
        ChannelIdentityShape::DedicatedAddress,
        ChannelIdentityBinding::agent(entity(0xAC)),
        9_010,
    );
    let shape_err = adapter
        .provision(
            &ProvisionIntent {
                identity_id: entity(0x7B),
                identity: self_held,
                fulfillment_mode: ChannelIdentityFulfillment::Api,
            },
            9_020,
        )
        .expect_err("dedicated_address must not provision through the delegated adapter");
    assert!(matches!(
        shape_err,
        Error::InvalidConfig(reason)
            if reason == "gmail delegated adapter requires delegated_grant identities"
    ));

    let mismatched = ChannelIdentity::requested_delegated(
        EMAIL_CHANNEL,
        MEMBER_MAILBOX,
        ChannelIdentityBinding::agent(entity(0xAD)),
        crate::channel_identity::DelegatedGrant::new(
            "gmail-delegated:someone-else",
            vec![DelegatedGrantScope::MailRead],
        ),
        9_030,
    );
    let grant_err = adapter
        .provision(
            &ProvisionIntent {
                identity_id: entity(0x7C),
                identity: mismatched,
                fulfillment_mode: ChannelIdentityFulfillment::Api,
            },
            9_040,
        )
        .expect_err("a foreign grant ref must not provision");
    assert!(matches!(
        grant_err,
        Error::InvalidConfig(reason)
            if reason == "gmail delegated adapter grant ref does not match ProvisionIntent"
    ));
    assert_eq!(CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION, 2);
    Ok(())
}
