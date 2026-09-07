use super::*;

fn subject_owner(vault: &Vault) -> Result<crate::write_envelope::WriteActor> {
    let owner = seed_entity(vault, entity(0xE0), crate::registry::ENTITY_TYPE_PERSON);
    let writer = crate::write_envelope::WriteActor::new(owner, crate::edge::EdgeActorClass::Human);
    // Signed genesis and a live owner binding, not an Agent capability exemption.
    crate::subject_model::tests::authorization::root_owner(vault, writer, 0xE0)?;
    Ok(writer)
}

/// An identity bound to an actor anchored to a PERSON round-trips, mask and
/// all. The binding names the ACTOR; the person is reached through the actor's
/// subject anchor, never stored on the identity.
#[test]
fn actor_person_round_trip() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed_entity(&vault, entity(0x51), crate::registry::ENTITY_TYPE_AGENT_DEF);
    let person = seed_entity(&vault, entity(0x52), crate::registry::ENTITY_TYPE_PERSON);
    let facet = seed_entity(&vault, entity(0x53), crate::registry::ENTITY_TYPE_FACET);

    crate::subject_model::anchor_actor_subject(
        &vault,
        actor,
        person,
        subject_owner(&vault)?,
        1_800_000_000,
    )?;

    let identity_id = entity(0x60);
    let mut identity = sample_identity();
    identity.binding = ChannelIdentityBinding::actor_with_facet(actor, facet);
    vault.create_channel_identity(&identity_id, &identity)?;

    let stored = vault
        .get_channel_identity(&identity_id)?
        .expect("identity stored");
    assert_eq!(stored.binding, identity.binding);
    assert_eq!(stored.binding.actor_ref(), Some(actor));
    assert_eq!(stored.binding.facet_ref(), Some(facet));
    // Binding is unchanged, but the anchor is absent before its occurrence.
    assert_eq!(
        crate::subject_model::actor_subject_anchor(&vault, &actor, 1_799_999_999)?,
        None
    );
    assert_eq!(
        crate::subject_model::actor_subject_anchor(&vault, &actor, 1_800_000_000)?,
        Some(person)
    );
    Ok(())
}

/// The same shape with an ORG behind the actor. ORG and PERSON are the two
/// anchor targets; nothing about the binding changes between them.
#[test]
fn actor_org_round_trip() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed_entity(&vault, entity(0x61), crate::registry::ENTITY_TYPE_AGENT_DEF);
    let org = seed_entity(&vault, entity(0x62), crate::registry::ENTITY_TYPE_ORG);

    crate::subject_model::anchor_actor_subject(
        &vault,
        actor,
        org,
        subject_owner(&vault)?,
        1_800_000_000,
    )?;

    let identity_id = entity(0x63);
    let mut identity = sample_identity();
    identity.binding = ChannelIdentityBinding::actor(actor);
    vault.create_channel_identity(&identity_id, &identity)?;

    let stored = vault
        .get_channel_identity(&identity_id)?
        .expect("identity stored");
    assert_eq!(stored.binding, ChannelIdentityBinding::actor(actor));
    assert_eq!(stored.binding.facet_ref(), None);
    assert_eq!(
        crate::subject_model::actor_subject_anchor(&vault, &org, 1_800_000_000)?,
        None,
        "the anchor hangs off the actor, not the org"
    );
    assert_eq!(
        crate::subject_model::actor_subject_anchor(&vault, &actor, 1_800_000_000)?,
        Some(org)
    );
    Ok(())
}

/// A bound facet must name a real type-13 FACET. This is a vault question, so
/// it is enforced at the write chokepoint rather than in the pure codec.
#[test]
fn facet_type_is_checked() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed_entity(&vault, entity(0x71), crate::registry::ENTITY_TYPE_AGENT_DEF);
    let not_a_facet = seed_entity(&vault, entity(0x72), crate::registry::ENTITY_TYPE_PERSON);

    let mut identity = sample_identity();
    identity.binding = ChannelIdentityBinding::actor_with_facet(actor, not_a_facet);
    let err = vault
        .create_channel_identity(&entity(0x73), &identity)
        .expect_err("non-FACET mask must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidChannelIdentityBody);

    // An absent entity is refused on the same axis.
    identity.binding = ChannelIdentityBinding::actor_with_facet(actor, entity(0x7E));
    let err = vault
        .create_channel_identity(&entity(0x74), &identity)
        .expect_err("dangling mask must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidChannelIdentityBody);

    // The real thing lands.
    let facet = seed_entity(&vault, entity(0x75), crate::registry::ENTITY_TYPE_FACET);
    identity.binding = ChannelIdentityBinding::actor_with_facet(actor, facet);
    vault.create_channel_identity(&entity(0x76), &identity)?;
    assert_eq!(
        vault
            .get_channel_identity(&entity(0x76))?
            .expect("stored")
            .binding
            .facet_ref(),
        Some(facet)
    );
    Ok(())
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
    let next = ChannelIdentity {
        binding,
        ..prior.clone()
    };
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
