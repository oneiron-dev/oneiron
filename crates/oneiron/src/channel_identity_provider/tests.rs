use super::gmail::{
    GMAIL_CONNECTOR_EFFECTOR, GMAIL_INBOX_POLL_ATTEMPT_KIND, GMAIL_METADATA_OAUTH_SCOPE,
    GmailDelegatedAdapter, GmailDelegatedAdapterConfig, GmailInboxPollConfig,
    delegated_scope_for_google_oauth_scope, gmail_inbox_poll_dedupe_key,
};
use super::*;
use crate::attempt_queue::{AttemptQueue, EnqueueOutcome};
use crate::channel_identity::{
    ChannelIdentityState, DelegatedGrant, DelegatedGrantScope, DelegatedProvisionRequest,
    delegated_custody_scopes,
};
use crate::secret_custody::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_SCHEMA_VERSION, SecretBinding, SecretCustodyFloor,
    SecretCustodyRecord, SecretCustodyStatus,
};
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
        SelfHeldShape::DedicatedAddress,
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
        ChannelIdentityBinding::Actor { actor_ref: bound, .. } if bound == agent_ref
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
    assert_eq!(surface_event.actor_ref, agent_ref.to_hex());
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

// ---------------------------------------------------------------------------
// Gmail delegated adapter
// ---------------------------------------------------------------------------

const GMAIL_MAILBOX: &str = "Member@Member-Owned.Example";
const GMAIL_CUSTODY_REF: &str = "oauth/gmail/member";

fn gmail_adapter() -> Result<GmailDelegatedAdapter> {
    Ok(GmailDelegatedAdapter::new(
        GmailDelegatedAdapterConfig::new(GMAIL_MAILBOX, GMAIL_CUSTODY_REF)?,
    ))
}

/// Registers the member's OAuth grant: live, `connector:gmail` read-bound, and
/// naming THIS mailbox as its subject.
fn register_gmail_custody(vault: &Vault) -> Result<EntityId> {
    vault.register_secret(SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: GMAIL_CUSTODY_REF.to_owned(),
        class: CustodyClass::CrossVault,
        device_only: true,
        value_bytes: b"member-oauth-token".to_vec(),
        status: SecretCustodyStatus::Active,
        registered_at: 1_800_000_000,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![SecretBinding {
            effector: GMAIL_CONNECTOR_EFFECTOR.to_owned(),
            tier_ceiling: CustodyTier::T0Doored,
            scopes: delegated_custody_scopes(EMAIL_CHANNEL, GMAIL_MAILBOX),
        }],
        manifest_ref: String::new(),
        declared_paths: Vec::new(),
        policy_floor_snapshot: SecretCustodyFloor::default(),
    })
}

#[test]
fn gmail_delegated_reads_require_an_active_identity_row() -> Result<()> {
    let (_dir, vault) = temp_vault();
    register_gmail_custody(&vault)?;
    let adapter = gmail_adapter()?;
    let identity_id = entity(0xC1);
    let agent_ref = entity(0xC2);

    let provisioned =
        adapter.provision_delegated_identity(&vault, identity_id, agent_ref, 1_800_000_000)?;
    assert_eq!(provisioned.identity.state, ChannelIdentityState::Requested);

    // The door must never reach the VALUE on a refusal, so every arm below
    // watches this flag rather than only the returned error.
    let saw_bytes = std::cell::Cell::new(false);
    let mut door = |_: &[u8]| -> Result<()> {
        saw_bytes.set(true);
        Ok(())
    };

    // 1. REQUESTED: the grant exists, the row does not yet claim it.
    let refused = adapter
        .enqueue_inbox_poll(&vault, identity_id, 1_800_000_001)
        .expect_err("a not-yet-live row arms no poll");
    assert!(matches!(
        refused,
        Error::InvalidConfig(ref reason)
            if reason == "gmail delegated reads require an active identity row, not requested"
    ));
    adapter
        .with_delegated_token_at_door(&vault, identity_id, &mut door)
        .expect_err("a not-yet-live row opens no token door");

    vault.transition_channel_identity(
        &identity_id,
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Api),
        1_800_000_002,
        None,
    )?;

    // 2. PENDING_FULFILLMENT: same reason.
    adapter
        .enqueue_inbox_poll(&vault, identity_id, 1_800_000_003)
        .expect_err("a pending row arms no poll");
    adapter
        .with_delegated_token_at_door(&vault, identity_id, &mut door)
        .expect_err("a pending row opens no token door");

    // 3. ACTIVE: both doors open, and the token reaches the closure exactly
    //    once, through the SECRET-02 injection.
    vault.transition_channel_identity(
        &identity_id,
        ChannelIdentityState::Active,
        None,
        1_800_000_004,
        None,
    )?;
    let outcome = adapter.enqueue_inbox_poll(&vault, identity_id, 1_800_000_005)?;
    assert!(matches!(outcome, EnqueueOutcome::Enqueued(_)));
    let receipt = adapter.with_delegated_token_at_door(&vault, identity_id, &mut door)?;
    assert!(saw_bytes.get(), "the live row reaches the value");
    assert_eq!(receipt.effector, GMAIL_CONNECTOR_EFFECTOR);
    assert_eq!(receipt.secret_ref, GMAIL_CUSTODY_REF);
    saw_bytes.set(false);

    // 4. RELEASED, then TOMBSTONE. Custody is NOT revoked by either — the
    //    member's OAuth grant is not ours to revoke — so a custody-only check
    //    still passes at both stops while the row's authority is gone.
    for (state, at) in [
        (ChannelIdentityState::Released, 1_800_000_006),
        (ChannelIdentityState::Tombstone, 1_800_000_007),
    ] {
        vault.transition_channel_identity(&identity_id, state, None, at, None)?;
        adapter
            .verify_custody_grant(&vault)
            .expect("the member's grant outlives the row that pointed at it");

        let refused = adapter
            .enqueue_inbox_poll(&vault, identity_id, at)
            .expect_err("a withdrawn row arms no poll");
        assert!(matches!(
            refused,
            Error::InvalidConfig(ref reason)
                if *reason == format!(
                    "gmail delegated reads require an active identity row, not {}",
                    state.as_str()
                )
        ));
        adapter
            .with_delegated_token_at_door(&vault, identity_id, &mut door)
            .expect_err("a withdrawn row opens no token door");
    }
    assert!(!saw_bytes.get(), "no refusal ever reached the token bytes");

    // No refusal minted or squatted a durable attempt: the only attempt in the
    // queue is the one the ACTIVE row armed, on its own dedupe key.
    let attempts: Vec<_> = AttemptQueue::new(&vault)
        .list()?
        .into_iter()
        .filter(|attempt| attempt.kind == GMAIL_INBOX_POLL_ATTEMPT_KIND)
        .collect();
    assert_eq!(attempts.len(), 1);
    assert_eq!(
        attempts[0].dedupe_key.as_deref(),
        Some(gmail_inbox_poll_dedupe_key(identity_id).as_str()),
    );
    // The durable payload carries NAMES only.
    let payload: GmailInboxPollConfig =
        serde_json::from_slice(&attempts[0].payload).expect("poll payload decodes");
    assert_eq!(payload.custody_record_ref, GMAIL_CUSTODY_REF);
    assert_eq!(payload.mailbox_address, "member@member-owned.example");
    assert_eq!(payload.identity_ref, identity_id.to_hex());
    assert!(!String::from_utf8_lossy(&attempts[0].payload).contains("member-oauth-token"));
    Ok(())
}

#[test]
fn gmail_delegated_doors_refuse_a_row_that_is_not_this_adapters() -> Result<()> {
    let (_dir, vault) = temp_vault();
    register_gmail_custody(&vault)?;
    let adapter = gmail_adapter()?;

    // No row at all.
    assert!(matches!(
        adapter
            .enqueue_inbox_poll(&vault, entity(0xD0), 1_800_000_000)
            .expect_err("an absent row arms no poll"),
        Error::EntityNotFound
    ));

    // A SELF-HELD row: real, active, and carrying no grant.
    let self_held_id = entity(0xD1);
    let self_held = ChannelIdentity::requested(
        EMAIL_CHANNEL,
        "agent@example.com",
        crate::channel_identity::SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(entity(0xD2)),
        1_800_000_000,
    );
    vault.create_channel_identity(&self_held_id, &self_held)?;
    assert!(matches!(
        adapter
            .enqueue_inbox_poll(&vault, self_held_id, 1_800_000_001)
            .expect_err("a self-held row is not a delegated mailbox"),
        Error::InvalidConfig(ref reason)
            if reason == "gmail inbox poll requires a delegated_grant identity row"
    ));

    // A delegated row over ANOTHER member's mailbox, live, under its own grant:
    // the field arms still speak for themselves rather than collapsing into the
    // state arm.
    let other_mailbox = "other@member-owned.example";
    let other_grant = DelegatedGrant::new(
        "oauth/gmail/other",
        vec![crate::channel_identity::DelegatedGrantScope::MailRead],
    );
    vault.register_secret(SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: other_grant.custody_record_ref.clone(),
        class: CustodyClass::CrossVault,
        device_only: true,
        value_bytes: b"other-oauth-token".to_vec(),
        status: SecretCustodyStatus::Active,
        registered_at: 1_800_000_000,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![SecretBinding {
            effector: GMAIL_CONNECTOR_EFFECTOR.to_owned(),
            tier_ceiling: CustodyTier::T0Doored,
            scopes: delegated_custody_scopes(EMAIL_CHANNEL, other_mailbox),
        }],
        manifest_ref: String::new(),
        declared_paths: Vec::new(),
        policy_floor_snapshot: SecretCustodyFloor::default(),
    })?;
    let other_id = entity(0xD3);
    vault.provision_delegated_identity(
        &other_id,
        DelegatedProvisionRequest {
            channel: EMAIL_CHANNEL.to_owned(),
            address_or_handle: other_mailbox.to_owned(),
            binding: ChannelIdentityBinding::agent(entity(0xD4)),
            grant: other_grant,
        },
        1_800_000_000,
    )?;
    vault.transition_channel_identity(
        &other_id,
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Api),
        1_800_000_001,
        None,
    )?;
    vault.transition_channel_identity(
        &other_id,
        ChannelIdentityState::Active,
        None,
        1_800_000_002,
        None,
    )?;
    assert!(matches!(
        adapter
            .enqueue_inbox_poll(&vault, other_id, 1_800_000_003)
            .expect_err("another member's mailbox is not this adapter's row"),
        Error::InvalidConfig(ref reason)
            if reason
                == "gmail inbox poll identity row is assigned to another channel or mailbox"
    ));
    Ok(())
}

#[test]
fn gmail_delegated_grant_admits_read_scopes_only() -> Result<()> {
    let config = GmailDelegatedAdapterConfig::new(GMAIL_MAILBOX, GMAIL_CUSTODY_REF)?;
    assert_eq!(config.mailbox_address(), "member@member-owned.example");
    assert_eq!(config.scopes(), &[DelegatedGrantScope::MailRead]);

    let narrowed = GmailDelegatedAdapterConfig::new(GMAIL_MAILBOX, GMAIL_CUSTODY_REF)?
        .with_google_oauth_scopes(&[GMAIL_METADATA_OAUTH_SCOPE])?;
    assert_eq!(narrowed.scopes(), &[DelegatedGrantScope::MailMetadata]);

    let widened = GmailDelegatedAdapterConfig::new(GMAIL_MAILBOX, GMAIL_CUSTODY_REF)?
        .with_google_oauth_scopes(&["https://www.googleapis.com/auth/gmail.send"])
        .expect_err("an over-broad consent screen fails closed");
    assert!(matches!(widened, Error::InvalidConfig(_)));
    assert_eq!(
        delegated_scope_for_google_oauth_scope("https://mail.google.com/"),
        None,
    );
    Ok(())
}
