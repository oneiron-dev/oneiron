use super::*;
use crate::Vault;
use crate::error::ErrorKind;
use crate::registry::{
    ENTITY_TYPE_CHANNEL_IDENTITY, EntityClassification, TypeByteBand, entity_type_registry_entry,
};
use crate::test_util::open_test_vault_with;
use crate::types::{TimeRange, VaultConfig};

fn entity(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("valid entity id")
}

fn sample_identity() -> ChannelIdentity {
    let mut identity = ChannelIdentity::requested(
        "email",
        "agent@example.com",
        ChannelIdentityShape::DedicatedAddress,
        ChannelIdentityBinding::agent(entity(0xA1)),
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

    validate_channel_identity_claim_structure(&claim(Value::from(entity(0xA1).to_hex())))
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
    let agent = entity(0xE1);
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
    let id = entity(0x11);
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
        ChannelIdentityShape::DedicatedAddress,
        ChannelIdentityBinding::agent(entity(0xA2)),
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
fn channel_identity_type_registration_is_stable() {
    let entry = entity_type_registry_entry(ENTITY_TYPE_CHANNEL_IDENTITY)
        .expect("CHANNEL_IDENTITY registry row");

    assert_eq!(ENTITY_TYPE_CHANNEL_IDENTITY, 131);
    assert_eq!(entry.kind, "CHANNEL_IDENTITY");
    assert_eq!(entry.short_id_prefix, None);
    assert_eq!(entry.classification, EntityClassification::Maintenance);
    assert_eq!(entry.band, TypeByteBand::InducedDynamicMaintenance);
}
