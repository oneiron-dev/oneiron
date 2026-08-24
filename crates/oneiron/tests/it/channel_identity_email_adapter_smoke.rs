use crate::common::entity;
use oneiron::{
    ChannelIdentityFulfillment, ChannelIdentityLifecycleActor, ChannelIdentityProviderAdapter,
    ChannelIdentityProviderInbound, ChannelIdentityState, DevEmailIdentityAdapter,
    DevEmailIdentityAdapterConfig, EmailProviderInbound, Error, InboundSurfaceRouteOutcome,
    ProvisionIntent, Result, Vault, VaultConfig,
};

fn smoke_config() -> Result<Option<DevEmailIdentityAdapterConfig>> {
    smoke_config_from_env(
        std::env::var("ONEIRON_CID3_EMAIL_DOMAIN").ok(),
        std::env::var("ONEIRON_CID3_EMAIL_SIGNING_SECRET").ok(),
    )
}

fn smoke_config_from_env(
    domain: Option<String>,
    signing_secret: Option<String>,
) -> Result<Option<DevEmailIdentityAdapterConfig>> {
    match (domain, signing_secret) {
        (None, None) => Ok(None),
        (Some(domain), Some(signing_secret)) => {
            if domain.trim().is_empty() || signing_secret.trim().is_empty() {
                return Err(Error::InvalidConfig(
                    "CID-3 email smoke env must be non-empty when configured".to_owned(),
                ));
            }
            DevEmailIdentityAdapterConfig::new(domain, signing_secret).map(Some)
        }
        _ => Err(Error::InvalidConfig(
            "CID-3 email smoke env must set domain and signing secret together".to_owned(),
        )),
    }
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

#[test]
fn cid3_email_adapter_env_gated_smoke() -> Result<()> {
    let Some(config) = smoke_config()? else {
        return Ok(());
    };

    let adapter = DevEmailIdentityAdapter::new(config);
    let (_tmp, vault) = temp_vault();
    let identity_id = entity(0x51);
    let agent_ref = entity(0x52);
    let actor = ChannelIdentityLifecycleActor::agent(agent_ref);
    let identity = adapter.requested_identity(identity_id, agent_ref, 1_800_000_000);
    let address = identity.address_or_handle.clone();

    vault.create_channel_identity(&identity_id, &identity)?;
    vault.transition_channel_identity(
        &identity_id,
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Api),
        1_800_000_001,
        None,
    )?;

    let provision = adapter.provision(
        &ProvisionIntent {
            identity_id,
            identity,
            fulfillment_mode: ChannelIdentityFulfillment::Api,
        },
        1_800_000_002,
    )?;
    vault.fulfill_channel_identity(provision.fulfillment_input(actor))?;

    let parsed = adapter.parse_inbound(ChannelIdentityProviderInbound::Email(
        EmailProviderInbound::new(
            "cid3-email-smoke",
            address,
            "counterparty@example.test",
            1_800_000_003,
        )
        .with_payload_ref("provider:cid3-email-smoke"),
    ))?;
    let receipt = vault.route_inbound_surface_event(parsed)?;

    assert_eq!(receipt.outcome, InboundSurfaceRouteOutcome::Routed);
    assert_eq!(receipt.receiving_identity_ref, Some(identity_id.to_hex()));
    assert_eq!(receipt.agent_ref, Some(agent_ref.to_hex()));
    assert!(receipt.surface_event.is_some());
    Ok(())
}

#[test]
fn cid3_email_adapter_smoke_fails_when_env_is_partially_or_invalid_configured() {
    assert!(matches!(smoke_config_from_env(None, None), Ok(None)));
    assert!(matches!(
        smoke_config_from_env(
            Some("agents.example.test".to_owned()),
            Some("dev-secret".to_owned())
        ),
        Ok(Some(_))
    ));
    assert!(matches!(
        smoke_config_from_env(Some("agents.example.test".to_owned()), None),
        Err(Error::InvalidConfig(_))
    ));
    assert!(matches!(
        smoke_config_from_env(Some("agents.example.test".to_owned()), Some(" ".to_owned())),
        Err(Error::InvalidConfig(_))
    ));
    assert!(matches!(
        smoke_config_from_env(
            Some("*.example.test".to_owned()),
            Some("dev-secret".to_owned())
        ),
        Err(Error::InvalidConfig(_))
    ));
}
