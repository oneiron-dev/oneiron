use super::*;

#[test]
fn faceted_sender_selection_preserves_actor_custody_and_ambiguity_checks() -> crate::Result<()> {
    use crate::channel_identity::{
        ChannelIdentityFulfillment, DelegatedGrant, DelegatedGrantScope, DelegatedProvisionRequest,
    };
    use crate::test_util::entity;

    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let actor = entity(0xC1);
    let other = entity(0xC2);
    let facet = entity(0xC3);
    let other_facet = entity(0xC4);
    for (id, kind) in [
        (actor, ENTITY_TYPE_PERSON),
        (other, ENTITY_TYPE_PERSON),
        (facet, crate::registry::ENTITY_TYPE_FACET),
        (other_facet, crate::registry::ENTITY_TYPE_FACET),
    ] {
        vault.put_entity(
            &id,
            kind,
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
            b"sender fixture",
        )?;
    }
    let binding = ChannelIdentityBinding::actor_with_facet(actor, facet);
    let put = |seed: u8, channel: &str, binding, state| -> crate::Result<()> {
        let mut identity = ChannelIdentity::requested(
            channel,
            format!("sender-{seed}@example.com"),
            SelfHeldShape::DedicatedAddress,
            binding,
            NOW,
        );
        identity.state = state;
        vault.create_channel_identity(&entity(seed), &identity)
    };
    put(
        0xC5,
        "email",
        ChannelIdentityBinding::actor_with_facet(other, facet),
        ChannelIdentityState::Active,
    )?;
    put(
        0xC6,
        "email",
        ChannelIdentityBinding::vault(7),
        ChannelIdentityState::Active,
    )?;
    put(0xA7, "email", binding, ChannelIdentityState::Requested)?;
    assert!(
        sending_address(&vault, actor)
            .expect("sender lookup")
            .is_none()
    );

    let grant = DelegatedGrant::new("oauth/faceted-sender", vec![DelegatedGrantScope::MailRead]);
    vault.register_secret(crate::secret_custody::SecretCustodyRecord {
        schema_version: crate::secret_custody::SECRET_CUSTODY_SCHEMA_VERSION,
        name: grant.custody_record_ref.clone(),
        class: crate::secret_custody::CustodyClass::CrossVault,
        device_only: true,
        value_bytes: b"test-delegated-token".to_vec(),
        status: crate::secret_custody::SecretCustodyStatus::Active,
        registered_at: 1_800_000_000,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![crate::secret_custody::SecretBinding {
            effector: "connector:gmail".to_owned(),
            tier_ceiling: crate::secret_custody::CustodyTier::T0Doored,
            scopes: crate::channel_identity::delegated_custody_scopes(
                "email",
                "delegated@example.com",
            ),
        }],
        manifest_ref: String::new(),
        declared_paths: Vec::new(),
        policy_floor_snapshot: crate::secret_custody::SecretCustodyFloor::default(),
    })?;
    vault.provision_delegated_identity(
        &entity(0xA8),
        DelegatedProvisionRequest {
            channel: "email".to_owned(),
            address_or_handle: "delegated@example.com".to_owned(),
            binding,
            grant,
        },
        NOW,
    )?;
    vault.transition_channel_identity(
        &entity(0xA8),
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Api),
        NOW + 10,
        None,
    )?;
    let delegated = vault.transition_channel_identity(
        &entity(0xA8),
        ChannelIdentityState::Active,
        None,
        NOW + 20,
        None,
    )?;
    assert_eq!(delegated.binding, binding);
    assert!(!delegated.may_send());
    assert!(
        sending_address(&vault, actor)
            .expect("read custody is not send authority")
            .is_none()
    );

    put(0xA9, "email", binding, ChannelIdentityState::Active)?;
    assert_eq!(
        sending_address(&vault, actor).expect("lookup"),
        Some("sender-169@example.com".to_owned())
    );
    put(
        0xAA,
        "email",
        ChannelIdentityBinding::actor(actor),
        ChannelIdentityState::Active,
    )?;
    assert!(
        sending_address(&vault, actor).is_err(),
        "masked plus unmasked is ambiguous"
    );
    vault.transition_channel_identity(
        &entity(0xAA),
        ChannelIdentityState::Released,
        None,
        NOW + 30,
        None,
    )?;
    put(0xAB, "calendar", binding, ChannelIdentityState::Active)?;
    assert_eq!(
        sending_address(&vault, actor).expect("lookup"),
        Some("sender-171@example.com".to_owned())
    );
    put(
        0xAC,
        "calendar",
        ChannelIdentityBinding::actor_with_facet(actor, other_facet),
        ChannelIdentityState::Active,
    )?;
    assert!(
        sending_address(&vault, actor).is_err(),
        "two calendar masks must refuse, not fall back to the unique email sender",
    );
    Ok(())
}
