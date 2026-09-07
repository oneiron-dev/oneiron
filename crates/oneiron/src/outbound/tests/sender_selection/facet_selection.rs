use super::{EntityId, Error, TimeRange, Vault, entity, temp_vault};

#[test]
fn automatic_outbound_selection_matches_actor_not_facet_and_preserves_safety() -> crate::Result<()>
{
    use super::dispatch_pipeline::{
        enrich_dispatch_channel_identity, resolve_channel_identity_ref_for_connector,
    };

    use crate::channel_identity::{
        ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityState,
        DelegatedGrant, DelegatedGrantScope, DelegatedProvisionRequest, SelfHeldShape,
    };
    use crate::error::Result;

    let (_dir, vault) = temp_vault();
    let seed_entity = |vault: &Vault, id, kind| {
        if kind == crate::registry::ENTITY_TYPE_AGENT_DEF {
            return crate::test_util::seed_agent_definition(vault, id, "faceted sender");
        }
        vault
            .put_entity(
                &id,
                kind,
                TimeRange {
                    start: 100,
                    end: 100,
                },
                100,
                b"facet",
            )
            .expect("seed facet");
        id
    };
    let actor = seed_entity(&vault, entity(0x91), crate::registry::ENTITY_TYPE_AGENT_DEF);
    let other = seed_entity(&vault, entity(0x92), crate::registry::ENTITY_TYPE_AGENT_DEF);
    let facet = seed_entity(&vault, entity(0x93), crate::registry::ENTITY_TYPE_FACET);
    let binding = ChannelIdentityBinding::actor_with_facet(actor, facet);
    vault.register_connector_key(
        &entity(0x94),
        crate::connector_key::ConnectorKeyRecord::active("email", Some(actor), Vec::new(), 100),
    )?;
    let resolve = |who: Option<&EntityId>| -> Result<Option<EntityId>> {
        let txn = vault.store.env.read_txn()?;
        resolve_channel_identity_ref_for_connector(&vault.store, &txn, "email", who)
    };
    let put = |seed: u8, channel: &str, binding, state| -> Result<()> {
        let mut identity = ChannelIdentity::requested(
            channel,
            format!("sender-{seed}@example.com"),
            SelfHeldShape::DedicatedAddress,
            binding,
            100,
        );
        identity.state = state;
        vault.create_channel_identity(&entity(seed), &identity)
    };
    put(
        0x95,
        "email",
        ChannelIdentityBinding::actor_with_facet(other, facet),
        ChannelIdentityState::Active,
    )?;
    put(
        0x96,
        "email",
        ChannelIdentityBinding::vault(7),
        ChannelIdentityState::Active,
    )?;
    put(0x97, "calendar", binding, ChannelIdentityState::Active)?;
    put(0x98, "email", binding, ChannelIdentityState::Requested)?;
    assert_eq!(resolve(Some(&actor))?, None);

    // A real faceted delegated row can be provisioned and activated, but its
    // read custody must not become sender authority or sender ambiguity.
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
        &entity(0x99),
        DelegatedProvisionRequest {
            channel: "email".to_owned(),
            address_or_handle: "delegated@example.com".to_owned(),
            binding,
            grant,
        },
        1_800_000_000,
    )?;
    vault.transition_channel_identity(
        &entity(0x99),
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Api),
        1_800_000_010,
        None,
    )?;
    let delegated = vault.transition_channel_identity(
        &entity(0x99),
        ChannelIdentityState::Active,
        None,
        1_800_000_020,
        None,
    )?;
    assert_eq!(delegated.binding, binding);
    assert!(!delegated.may_send());
    assert_eq!(resolve(Some(&actor))?, None);

    put(0x9A, "email", binding, ChannelIdentityState::Active)?;
    assert_eq!(resolve(Some(&actor))?, Some(entity(0x9A)));
    assert_eq!(
        resolve(Some(&other))?,
        None,
        "another actor has no governing key"
    );
    assert_eq!(resolve(None)?, None, "do not infer an actor from a facet");
    put(
        0x9B,
        "email",
        ChannelIdentityBinding::actor(actor),
        ChannelIdentityState::Active,
    )?;
    assert!(
        matches!(resolve(Some(&actor)), Err(Error::InvalidConfig(_))),
        "masked plus unmasked is ambiguous"
    );
    vault.transition_channel_identity(
        &entity(0x9B),
        ChannelIdentityState::Released,
        None,
        200,
        None,
    )?;
    assert_eq!(resolve(Some(&actor))?, Some(entity(0x9A)));
    let second_facet = seed_entity(&vault, entity(0x9C), crate::registry::ENTITY_TYPE_FACET);
    put(
        0x9D,
        "email",
        ChannelIdentityBinding::actor_with_facet(actor, second_facet),
        ChannelIdentityState::Active,
    )?;
    assert!(
        matches!(resolve(Some(&actor)), Err(Error::InvalidConfig(_))),
        "two masks are still two identities"
    );
    let txn = vault.store.env.read_txn()?;
    assert_eq!(
        enrich_dispatch_channel_identity(
            &vault.store,
            &txn,
            "email",
            Some(&actor),
            Some(entity(0x9A))
        )?,
        Some(entity(0x9A)),
        "explicit identity behavior is unchanged",
    );
    Ok(())
}
