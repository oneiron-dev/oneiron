use super::*;
use crate::Vault;
use crate::channel_identity_provider::EMAIL_CHANNEL;
use crate::config::VaultConfig;
use crate::error::ErrorKind;
use crate::registry::{
    ENTITY_TYPE_CHANNEL_IDENTITY, EntityClassification, TypeByteZone, entity_type_registry_entry,
};
use crate::secret_custody::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_SCHEMA_VERSION, SECRET_SCOPE_READ, SecretBinding,
    SecretCustodyFloor, SecretCustodyRecord, SecretCustodyStatus,
};
use crate::temporal::TimeRange;
use crate::test_util::open_test_vault_with;

use crate::test_util::entity;

/// Registers the OAuth grant a delegated `email` row is made true by: a live
/// custody record whose `connector:gmail` binding grants read AND names this
/// mailbox as its subject.
fn register_delegated_custody(
    vault: &Vault,
    grant: &DelegatedGrant,
    mailbox: &str,
) -> Result<EntityId> {
    vault.register_secret(SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: grant.custody_record_ref.clone(),
        class: CustodyClass::CrossVault,
        device_only: true,
        value_bytes: b"member-oauth-token".to_vec(),
        status: SecretCustodyStatus::Active,
        registered_at: 1_800_000_000,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![SecretBinding {
            effector: "connector:gmail".to_owned(),
            tier_ceiling: CustodyTier::T0Doored,
            scopes: delegated_custody_scopes(EMAIL_CHANNEL, mailbox),
        }],
        manifest_ref: String::new(),
        declared_paths: Vec::new(),
        policy_floor_snapshot: SecretCustodyFloor::default(),
    })
}

fn sample_identity() -> ChannelIdentity {
    let mut identity = ChannelIdentity::requested(
        "email",
        "agent@example.com",
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(entity(0x51)),
        1_800_000_000,
    );
    identity.reputation_ref = Some(entity(0xB1));
    identity.manifest_ref = Some(entity(0xC1));
    identity
}

fn test_vault() -> (tempfile::TempDir, Vault) {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    open_test_vault_with(cfg)
}

#[test]
fn channel_identity_codec_and_claim_family_round_trip() -> Result<()> {
    let identity = sample_identity().transition(
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Manual),
        1_800_000_010,
        None,
    )?;

    let encoded = encode_channel_identity_body(&identity)?;
    validate_channel_identity_body_bytes(&encoded)?;
    assert_eq!(decode_channel_identity_body(&encoded)?, identity);

    let claims = identity.claim_bodies(entity(0xD1));
    assert_eq!(claims.len(), CHANNEL_IDENTITY_CLAIM_PREDICATES.len());
    for claim in &claims {
        validate_channel_identity_claim_structure(claim)?;
    }
    assert!(claims.iter().any(|claim| {
        claim.predicate == PREDICATE_CHANNEL_IDENTITY_SHAPE
            && claim.value.as_str() == Some("dedicated_address")
    }));
    assert!(claims.iter().any(|claim| {
        claim.predicate == PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE
            && claim.value.as_str() == Some("agent")
    }));
    assert!(claims.iter().any(|claim| {
        claim.predicate == PREDICATE_CHANNEL_IDENTITY_PENDING_FULFILLMENT
            && claim.value.as_str() == Some("manual")
    }));
    Ok(())
}

#[test]
fn state_machine_rejects_skips_and_pins_quarantine_window() -> Result<()> {
    let requested = sample_identity();
    assert!(
        requested
            .transition(ChannelIdentityState::Active, None, 1_800_000_010, None)
            .is_err()
    );

    let pending = requested.transition(
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Api),
        1_800_000_010,
        None,
    )?;
    let active = pending.transition(ChannelIdentityState::Active, None, 1_800_000_020, None)?;
    assert!(
        active
            .transition(ChannelIdentityState::Tombstone, None, 1_800_000_030, None)
            .is_err()
    );

    let released = active.transition(ChannelIdentityState::Released, None, 1_800_000_030, None)?;
    assert!(
        released
            .transition(
                ChannelIdentityState::Quarantine,
                None,
                1_800_000_020,
                Some(1_800_000_020 + CHANNEL_IDENTITY_MIN_QUARANTINE_SECS),
            )
            .is_err()
    );
    assert!(
        released
            .transition(
                ChannelIdentityState::Quarantine,
                None,
                1_800_000_040,
                Some(1_800_000_040 + CHANNEL_IDENTITY_MIN_QUARANTINE_SECS - 1),
            )
            .is_err()
    );
    let quarantine = released.transition(
        ChannelIdentityState::Quarantine,
        None,
        1_800_000_040,
        Some(1_800_000_040 + CHANNEL_IDENTITY_MIN_QUARANTINE_SECS),
    )?;
    quarantine.transition(ChannelIdentityState::Tombstone, None, 1_900_000_000, None)?;
    Ok(())
}

#[test]
fn channel_identity_claim_binding_target_rejects_invalid_values() {
    let subject = ClaimSubject::Entity(entity(0xD2));
    let claim = |value| {
        ClaimBody::new(
            PREDICATE_CHANNEL_IDENTITY_BINDING_TARGET,
            subject,
            value,
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
    };

    validate_channel_identity_claim_structure(&claim(Value::from(entity(0x51).to_hex())))
        .expect("agent entity target accepted");
    validate_channel_identity_claim_structure(&claim(Value::from(7_u64)))
        .expect("non-zero vault target accepted");

    let zero_err = validate_channel_identity_claim_structure(&claim(Value::from(0_u64)))
        .expect_err("zero vault id must be rejected");
    assert_eq!(zero_err.kind(), ErrorKind::InvalidClaimBody);

    let bogus_err = validate_channel_identity_claim_structure(&claim(Value::from("not-hex")))
        .expect_err("malformed target must be rejected");
    assert_eq!(bogus_err.kind(), ErrorKind::InvalidClaimBody);
}

#[test]
fn own_app_home_identity_is_constructible_active_agent_binding() -> Result<()> {
    let agent = entity(0x5E);
    let identity = ChannelIdentity::own_app_home(agent, 7);
    identity.validate()?;
    assert_eq!(identity.channel, "own_app");
    assert_eq!(identity.shape, ChannelIdentityShape::DedicatedHandle);
    assert_eq!(identity.binding, ChannelIdentityBinding::agent(agent));
    assert_eq!(identity.state, ChannelIdentityState::Active);
    Ok(())
}

#[test]
fn vault_create_transition_and_never_recycle_invariant() -> Result<()> {
    let (_dir, vault) = test_vault();
    let id = entity(0x60);
    let identity = sample_identity();

    let data = encode_channel_identity_body(&identity)?;
    let err = vault
        .put_entity(
            &id,
            ENTITY_TYPE_CHANNEL_IDENTITY,
            TimeRange {
                start: identity.state_changed_at,
                end: identity.state_changed_at,
            },
            identity.state_changed_at,
            &data,
        )
        .expect_err("generic public put must reject maintenance CID records");
    assert_eq!(err.kind(), ErrorKind::MaintenanceKindNotWritable);

    vault.create_channel_identity(&id, &identity)?;
    assert_eq!(vault.get_channel_identity(&id)?, Some(identity));

    vault.transition_channel_identity(
        &id,
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Api),
        1_800_000_010,
        None,
    )?;
    vault.transition_channel_identity(
        &id,
        ChannelIdentityState::Active,
        None,
        1_800_000_020,
        None,
    )?;
    vault.transition_channel_identity(
        &id,
        ChannelIdentityState::Released,
        None,
        1_800_000_030,
        None,
    )?;
    vault.transition_channel_identity(
        &id,
        ChannelIdentityState::Quarantine,
        None,
        1_800_000_040,
        Some(1_800_000_040 + CHANNEL_IDENTITY_MIN_QUARANTINE_SECS),
    )?;
    let tombstone = vault.transition_channel_identity(
        &id,
        ChannelIdentityState::Tombstone,
        None,
        1_900_000_000,
        None,
    )?;
    assert_eq!(tombstone.state, ChannelIdentityState::Tombstone);

    let duplicate = ChannelIdentity::requested(
        "email",
        "agent@example.com",
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(entity(0x52)),
        1_900_000_010,
    );
    let err = vault
        .create_channel_identity(&entity(0x12), &duplicate)
        .expect_err("released/tombstoned identities must never be reassigned");
    assert_eq!(err.kind(), ErrorKind::ChannelIdentityAlreadyExists);
    Ok(())
}

#[test]
fn malformed_channel_identity_bodies_fail_closed() {
    let mut encoded = encode_channel_identity_body(&sample_identity()).unwrap();
    encoded.push(0xc0);
    let err = decode_channel_identity_body(&encoded).expect_err("trailing bytes rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidChannelIdentityBody);

    let mut blank = sample_identity();
    blank.address_or_handle = " ".to_owned();
    let err = encode_channel_identity_body(&blank).expect_err("blank address rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidChannelIdentityBody);
}

#[test]
fn delegated_custody_subject_scope_normalizes_its_channel() -> Result<()> {
    // The registration-side helper and the admission-side check are two halves
    // of ONE tie. If the helper interpolates the caller's raw channel spelling
    // while the engine normalizes before looking the scope up, a host that
    // registers in good faith is refused forever for a mailbox the engine
    // otherwise accepts.
    let canonical = delegated_custody_subject_scope(EMAIL_CHANNEL, "member@member-owned.example");
    assert_eq!(canonical, "subject:email:member@member-owned.example");

    for spelling in ["email", "Email", "EMAIL", "  email  ", " eMaIl\t"] {
        assert_eq!(
            delegated_custody_subject_scope(spelling, "Member@Member-Owned.Example"),
            canonical,
            "channel spelling {spelling:?} must emit the one subject scope",
        );
        assert_eq!(
            delegated_custody_scopes(spelling, "Member@Member-Owned.Example"),
            vec![SECRET_SCOPE_READ.to_owned(), canonical.clone()],
            "delegated_custody_scopes inherits the fix rather than restating it",
        );
    }

    // And the tie is REAL, not merely string-equal: a custody record whose
    // binding scopes are literally what the helper emits for an unnormalized
    // channel is admitted by the engine's own verification door.
    let (_dir, vault) = test_vault();
    let grant = DelegatedGrant::new(
        "oauth/gmail/member",
        vec![crate::channel_identity::DelegatedGrantScope::MailRead],
    );
    vault.register_secret(SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: grant.custody_record_ref.clone(),
        class: CustodyClass::CrossVault,
        device_only: true,
        value_bytes: b"member-oauth-token".to_vec(),
        status: SecretCustodyStatus::Active,
        registered_at: 1_800_000_000,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![SecretBinding {
            effector: "connector:gmail".to_owned(),
            tier_ceiling: CustodyTier::T0Doored,
            scopes: delegated_custody_scopes("EMAIL", "Member@Member-Owned.Example"),
        }],
        manifest_ref: String::new(),
        declared_paths: Vec::new(),
        policy_floor_snapshot: SecretCustodyFloor::default(),
    })?;

    vault.verify_delegated_custody(EMAIL_CHANNEL, "member@member-owned.example", &grant)?;
    Ok(())
}

#[test]
fn self_held_requested_door_admits_no_delegated_shape() {
    // Exhaustive over the wire vocabulary: every shape either has a
    // `SelfHeldShape` preimage that this door preserves EXACTLY, or it has no
    // preimage at all — and the set with no preimage is exactly
    // `[DelegatedGrant]`.
    let wire_vocabulary = [
        ChannelIdentityShape::DedicatedAddress,
        ChannelIdentityShape::DedicatedHandle,
        ChannelIdentityShape::SharedPresence,
        ChannelIdentityShape::DelegatedGrant,
    ];
    let mut unspellable = Vec::new();
    for wire in wire_vocabulary {
        let Some(self_held) = SelfHeldShape::from_shape(wire) else {
            unspellable.push(wire);
            continue;
        };
        let row = ChannelIdentity::requested(
            "email",
            "agent@example.com",
            self_held,
            ChannelIdentityBinding::agent(entity(0x51)),
            1_800_000_000,
        );
        // No shape is silently rewritten on the way through.
        assert_eq!(row.shape, wire);
        assert_eq!(row.state, ChannelIdentityState::Requested);
        assert!(!row.is_delegated());
        assert!(row.grant.is_none());
        row.validate().expect("self-held requested row validates");
    }
    assert_eq!(unspellable, vec![ChannelIdentityShape::DelegatedGrant]);

    // The escalation the missing variant closes, stated directly: every
    // self-held shape this door returns reaches `may_send() == true` once
    // Active, while a delegated row never does. Degrading a delegated request
    // onto a self-held shape here would hand the caller outbound authority over
    // an account it asked to only READ.
    let active = ChannelIdentity::requested(
        "email",
        "agent@example.com",
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(entity(0x51)),
        1_800_000_000,
    )
    .transition(
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Api),
        1_800_000_010,
        None,
    )
    .and_then(|pending| pending.transition(ChannelIdentityState::Active, None, 1_800_000_020, None))
    .expect("self-held row reaches Active");
    assert!(active.may_send());
}

#[test]
fn delegated_rows_are_read_only_and_free_their_key_when_retired() -> Result<()> {
    let (_dir, vault) = test_vault();
    let grant = DelegatedGrant::new(
        "oauth/gmail/member",
        vec![crate::channel_identity::DelegatedGrantScope::MailRead],
    );
    register_delegated_custody(&vault, &grant, "member@member-owned.example")?;

    let id = entity(0x70);
    let requested = vault.provision_delegated_identity(
        &id,
        DelegatedProvisionRequest {
            channel: EMAIL_CHANNEL.to_owned(),
            address_or_handle: "Member@Member-Owned.Example".to_owned(),
            binding: ChannelIdentityBinding::agent(entity(0x51)),
            grant: grant.clone(),
        },
        1_800_000_000,
    )?;
    // Birth is `Requested` and the mailbox is normalized once, at the door.
    assert_eq!(requested.state, ChannelIdentityState::Requested);
    assert_eq!(requested.address_or_handle, "member@member-owned.example");
    assert!(requested.is_delegated());
    assert!(!requested.may_send());

    // A delegated row has no rotation and no quarantine to step into.
    for banned in [
        ChannelIdentityState::Rotating,
        ChannelIdentityState::Quarantine,
    ] {
        assert!(
            vault
                .transition_channel_identity(&id, banned, None, 1_800_000_010, None)
                .is_err(),
            "{banned:?} is not on the delegated machine",
        );
    }

    vault.transition_channel_identity(
        &id,
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Api),
        1_800_000_010,
        None,
    )?;
    let active = vault.transition_channel_identity(
        &id,
        ChannelIdentityState::Active,
        None,
        1_800_000_020,
        None,
    )?;
    // Even live, a scoped-read grant over someone else's mailbox never sends.
    assert!(!active.may_send());
    assert!(active.occupies_assignment_key());

    // Retirement frees the key: the mailbox was never ours to hold back, so
    // lawful re-consent stays open after the close.
    let released = vault.transition_channel_identity(
        &id,
        ChannelIdentityState::Released,
        None,
        1_800_000_030,
        None,
    )?;
    assert!(!released.occupies_assignment_key());
    assert_eq!(
        vault.channel_identity_by_assignment(EMAIL_CHANNEL, "member@member-owned.example")?,
        None,
    );
    let reconsented = vault.provision_delegated_identity(
        &entity(0x71),
        DelegatedProvisionRequest {
            channel: EMAIL_CHANNEL.to_owned(),
            address_or_handle: "member@member-owned.example".to_owned(),
            binding: ChannelIdentityBinding::agent(entity(0x52)),
            grant,
        },
        1_800_000_040,
    )?;
    assert_eq!(reconsented.state, ChannelIdentityState::Requested);
    Ok(())
}

#[test]
fn delegated_births_outside_requested_are_refused_at_the_store() -> Result<()> {
    let (_dir, vault) = test_vault();
    let grant = DelegatedGrant::new(
        "oauth/gmail/member",
        vec![crate::channel_identity::DelegatedGrantScope::MailRead],
    );
    register_delegated_custody(&vault, &grant, "member@member-owned.example")?;

    // An assembled body claiming ACTIVE asserts a provision decision, a bind
    // edge, a fulfillment and a receipt that never happened.
    let crafted = ChannelIdentity {
        channel: EMAIL_CHANNEL.to_owned(),
        address_or_handle: "member@member-owned.example".to_owned(),
        shape: ChannelIdentityShape::DelegatedGrant,
        binding: ChannelIdentityBinding::agent(entity(0x51)),
        state: ChannelIdentityState::Active,
        pending_fulfillment: None,
        state_changed_at: 1_800_000_000,
        quarantine_until: None,
        reputation_ref: None,
        manifest_ref: None,
        grant: Some(grant),
    };
    let err = vault
        .create_channel_identity(&entity(0x72), &crafted)
        .expect_err("a delegated row is born Requested");
    assert_eq!(err.kind(), ErrorKind::InvalidChannelIdentityBody);

    // And a delegated body naming custody this vault does not hold is refused
    // whatever state it claims.
    let unbacked = ChannelIdentity {
        grant: Some(DelegatedGrant::new(
            "oauth/gmail/stranger",
            vec![crate::channel_identity::DelegatedGrantScope::MailRead],
        )),
        state: ChannelIdentityState::Requested,
        ..crafted
    };
    let err = vault
        .create_channel_identity(&entity(0x73), &unbacked)
        .expect_err("custody is verified, never asserted");
    assert_eq!(err.kind(), ErrorKind::SecretRefNotFound);
    Ok(())
}

#[test]
fn assignment_keys_are_canonical_on_every_road() -> Result<()> {
    let (_dir, vault) = test_vault();
    let id = entity(0x74);
    let identity = ChannelIdentity::requested(
        "Email",
        "Agent@Example.COM",
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(entity(0x51)),
        1_800_000_000,
    );
    assert_eq!(identity.channel, "email");
    assert_eq!(identity.address_or_handle, "agent@example.com");
    vault.create_channel_identity(&id, &identity)?;

    // Every spelling of the one mailbox finds the one row...
    for (channel, address) in [
        ("email", "agent@example.com"),
        ("EMAIL", "Agent@Example.COM"),
        (" Email ", " agent@example.com. "),
    ] {
        assert_eq!(
            vault
                .channel_identity_by_assignment(channel, address)?
                .map(|(found, _)| found),
            Some(id),
            "{channel}/{address} names the stored row",
        );
    }

    // ...and cannot become a second occupant of it.
    let err = vault
        .create_channel_identity(
            &entity(0x75),
            &ChannelIdentity::requested(
                "EMAIL",
                "AGENT@example.com.",
                SelfHeldShape::DedicatedAddress,
                ChannelIdentityBinding::agent(entity(0x52)),
                1_800_000_010,
            ),
        )
        .expect_err("two spellings of one mailbox are one assignment key");
    assert_eq!(err.kind(), ErrorKind::ChannelIdentityAlreadyExists);
    Ok(())
}

#[test]
fn channel_identity_type_registration_is_stable() {
    let entry = entity_type_registry_entry(ENTITY_TYPE_CHANNEL_IDENTITY)
        .expect("CHANNEL_IDENTITY registry row");

    assert_eq!(ENTITY_TYPE_CHANNEL_IDENTITY, 79);
    assert_eq!(entry.kind, "CHANNEL_IDENTITY");
    assert_eq!(entry.short_id_prefix, None);
    assert_eq!(entry.classification, EntityClassification::Maintenance);
    assert_eq!(entry.zone, TypeByteZone::System);
}
