use super::*;

/// A bound facet must name a real type-13 FACET. This is a vault question, so
/// it is enforced at the write chokepoint rather than in the pure codec.
#[test]
fn facet_type_is_checked() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed_entity(&vault, entity(0x71), crate::registry::ENTITY_TYPE_AGENT_DEF);
    let not_a_facet = seed_entity(&vault, entity(0x72), crate::registry::ENTITY_TYPE_PERSON);

    let err = vault
        .create_channel_identity(&entity(0x73), &sample_identity_faceted(actor, not_a_facet))
        .expect_err("non-FACET mask must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidChannelIdentityBody);

    // An absent entity is refused on the same axis.
    let err = vault
        .create_channel_identity(&entity(0x74), &sample_identity_faceted(actor, entity(0x7E)))
        .expect_err("dangling mask must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidChannelIdentityBody);

    // The real thing lands.
    let facet = seed_entity(&vault, entity(0x75), crate::registry::ENTITY_TYPE_FACET);
    vault.create_channel_identity(&entity(0x76), &sample_identity_faceted(actor, facet))?;
    assert_eq!(
        vault
            .get_channel_identity(&entity(0x76))?
            .expect("stored")
            .binding()
            .facet_ref(),
        Some(facet)
    );
    Ok(())
}

/// [`sample_identity`] bound to `actor` wearing `facet` on this channel.
fn sample_identity_faceted(actor: EntityId, facet: EntityId) -> ChannelIdentity {
    sample_identity_bound(
        Custody::requested_self_held(SelfHeldShape::DedicatedAddress),
        ChannelIdentityBinding::actor_with_facet(actor, facet),
    )
}

fn seed_entity(vault: &Vault, id: EntityId, entity_type: u8) -> EntityId {
    if entity_type == crate::registry::ENTITY_TYPE_AGENT_DEF {
        return crate::test_util::seed_agent_definition(vault, id, "channel_identity");
    }
    vault
        .put_entity(
            &id,
            entity_type,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"channel identity fixture",
        )
        .expect("seed entity");
    id
}

#[test]
fn facet_check_covers_delegated_provision_and_shared_lifecycle_admission() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = entity(0x81);
    let not_a_facet = seed_entity(&vault, entity(0x82), crate::registry::ENTITY_TYPE_PERSON);
    let binding = ChannelIdentityBinding::actor_with_facet(actor, not_a_facet);
    let grant = DelegatedGrant::new("oauth/faceted", vec![DelegatedGrantScope::MailRead]);
    register_delegated_custody(&vault, &grant, "faceted@example.com")?;
    let id = entity(0x83);
    let err = vault
        .provision_delegated_identity(
            &id,
            DelegatedProvisionRequest {
                channel: "email".to_owned(),
                address_or_handle: "faceted@example.com".to_owned(),
                binding,
                grant,
            },
            1_800_000_000,
        )
        .expect_err("delegated custody must not bypass facet validation");
    assert_eq!(err.kind(), ErrorKind::InvalidChannelIdentityBody);
    assert_eq!(vault.get_channel_identity(&id)?, None);

    let prior = sample_identity();
    let next = sample_identity_bound(
        Custody::requested_self_held(SelfHeldShape::DedicatedAddress),
        binding,
    );
    let rtxn = vault.store.env.read_txn()?;
    for transition in [
        IdentityTransition::Birth { next: &next },
        IdentityTransition::Step {
            prior: &prior,
            next: &next,
        },
    ] {
        assert_eq!(
            admit_channel_identity_transition_in_txn(&vault.store, &rtxn, &id, transition)
                .expect_err("both lifecycle doors use the same facet check")
                .kind(),
            ErrorKind::InvalidChannelIdentityBody,
        );
    }
    Ok(())
}
