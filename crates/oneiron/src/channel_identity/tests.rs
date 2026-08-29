use super::*;
use crate::Vault;
use crate::config::VaultConfig;
use crate::error::ErrorKind;
use crate::registry::{
    ENTITY_TYPE_CHANNEL_IDENTITY, EntityClassification, TypeByteZone, entity_type_registry_entry,
};
use crate::temporal::TimeRange;
use crate::test_util::open_test_vault_with;

use crate::test_util::entity;

fn sample_identity() -> ChannelIdentity {
    let mut identity = ChannelIdentity::requested(
        "email",
        "agent@example.com",
        ChannelIdentityShape::DedicatedAddress,
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
        ChannelIdentityShape::DedicatedAddress,
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

fn sample_delegated_identity() -> ChannelIdentity {
    ChannelIdentity::requested_delegated(
        "email",
        "member@member-owned.example",
        ChannelIdentityBinding::agent(entity(0x51)),
        DelegatedGrant::new(
            "gmail-delegated:member@member-owned.example",
            vec![DelegatedGrantScope::MailRead],
        ),
        1_800_000_000,
    )
}

/// Rebuilds the exact twelve-key, `schema_version: 1` body head wrote, from
/// literal key strings rather than the crate constants. If a future change
/// renames a key, reorders the map, or bumps the version out from under the
/// three self-held shapes, this fails instead of silently orphaning every
/// pre-INB-00 row on disk.
fn head_encoded_body(identity: &ChannelIdentity) -> Vec<u8> {
    let value = Value::Map(vec![
        (Value::from("schema_version"), Value::from(1u64)),
        (
            Value::from("channel"),
            Value::from(identity.channel.as_str()),
        ),
        (
            Value::from("address_or_handle"),
            Value::from(identity.address_or_handle.as_str()),
        ),
        (Value::from("shape"), Value::from(identity.shape.as_str())),
        (
            Value::from("binding_scope"),
            Value::from(identity.binding.scope_str()),
        ),
        (
            Value::from("binding_target"),
            encode_binding_target(identity.binding),
        ),
        (Value::from("state"), Value::from(identity.state.as_str())),
        (
            Value::from("pending_fulfillment"),
            identity
                .pending_fulfillment
                .map_or(Value::Nil, |mode| Value::from(mode.as_str())),
        ),
        (
            Value::from("state_changed_at"),
            Value::from(identity.state_changed_at),
        ),
        (
            Value::from("quarantine_until"),
            identity.quarantine_until.map_or(Value::Nil, Value::from),
        ),
        (
            Value::from("reputation_ref"),
            encode_optional_entity_ref(identity.reputation_ref),
        ),
        (
            Value::from("manifest_ref"),
            encode_optional_entity_ref(identity.manifest_ref),
        ),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value).expect("head body encodes");
    out
}

fn delegated_body_entries(shape: &str, version: u64) -> Vec<(Value, Value)> {
    vec![
        (Value::from("schema_version"), Value::from(version)),
        (Value::from("channel"), Value::from("email")),
        (
            Value::from("address_or_handle"),
            Value::from("member@member-owned.example"),
        ),
        (Value::from("shape"), Value::from(shape)),
        (Value::from("binding_scope"), Value::from("agent")),
        (
            Value::from("binding_target"),
            Value::from(entity(0x51).to_hex()),
        ),
        (Value::from("state"), Value::from("requested")),
        (Value::from("pending_fulfillment"), Value::Nil),
        (
            Value::from("state_changed_at"),
            Value::from(1_800_000_000u64),
        ),
        (Value::from("quarantine_until"), Value::Nil),
        (Value::from("reputation_ref"), Value::Nil),
        (Value::from("manifest_ref"), Value::Nil),
        (
            Value::from("delegated_grant_ref"),
            Value::from("gmail-delegated:member@member-owned.example"),
        ),
        (
            Value::from("grant_scopes"),
            Value::Array(vec![Value::from("mail.read")]),
        ),
    ]
}

fn encode_entries(entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("fixture encodes");
    out
}

#[test]
fn head_three_shape_bodies_are_byte_stable_after_the_fourth_shape() -> Result<()> {
    // Back-compat is a byte claim, not a "it still parses" claim: adding the
    // fourth shape must leave the three self-held shapes writing the exact
    // bytes already on disk, so no row needs migrating.
    for shape in [
        ChannelIdentityShape::DedicatedAddress,
        ChannelIdentityShape::DedicatedHandle,
        ChannelIdentityShape::SharedPresence,
    ] {
        let mut identity = sample_identity();
        identity.shape = shape;
        let encoded = encode_channel_identity_body(&identity)?;
        assert_eq!(
            encoded,
            head_encoded_body(&identity),
            "{} body must stay byte-identical to head",
            shape.as_str()
        );
        assert_eq!(decode_channel_identity_body(&encoded)?, identity);
        assert!(identity.delegated_grant.is_none());
        assert!(shape.is_self_held());
    }

    let pending = sample_identity().transition(
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Review),
        1_800_000_010,
        None,
    )?;
    assert_eq!(
        encode_channel_identity_body(&pending)?,
        head_encoded_body(&pending)
    );
    Ok(())
}

#[test]
fn delegated_grant_body_round_trips_and_carries_no_token_bytes() -> Result<()> {
    let identity = sample_delegated_identity();
    let encoded = encode_channel_identity_body(&identity)?;
    validate_channel_identity_body_bytes(&encoded)?;
    assert_eq!(decode_channel_identity_body(&encoded)?, identity);

    let decoded_value: Value =
        rmpv::decode::read_value(&mut std::io::Cursor::new(encoded.as_slice()))
            .expect("delegated body decodes as a map");
    let Value::Map(entries) = decoded_value else {
        panic!("delegated body must encode as a map");
    };
    let keys = entries
        .iter()
        .map(|(key, _)| key.as_str().expect("string key").to_owned())
        .collect::<Vec<_>>();
    assert_eq!(keys, CHANNEL_IDENTITY_DELEGATED_BODY_KEYS.to_vec());
    assert_eq!(
        entries[0].1.as_u64(),
        Some(CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION)
    );

    // The body holds a custody NAME. A byte scan proves no grant material
    // rode along: the row is a pointer into custody, not a copy of it.
    let contains = |needle: &[u8]| encoded.windows(needle.len()).any(|slice| slice == needle);
    assert!(!contains(b"ya29.delegated-access-token"));
    assert!(!contains(b"refresh_token"));
    assert!(contains(b"gmail-delegated:member@member-owned.example"));

    // Claim family is untouched: a delegated row emits the same eleven
    // predicates, so downstream consumers never branch on the shape.
    let claims = identity.claim_bodies(entity(0xD2));
    assert_eq!(claims.len(), CHANNEL_IDENTITY_CLAIM_PREDICATES.len());
    for claim in &claims {
        validate_channel_identity_claim_structure(claim)?;
        assert!(!format!("{:?}", claim.value).contains("gmail-delegated:"));
    }
    assert!(claims.iter().any(|claim| {
        claim.predicate == PREDICATE_CHANNEL_IDENTITY_SHAPE
            && claim.value.as_str() == Some("delegated_grant")
    }));
    Ok(())
}

#[test]
fn delegated_bodies_fail_closed_on_version_shape_key_and_scope_drift() {
    let reject = |entries: Vec<(Value, Value)>, why: &str| {
        let err = decode_channel_identity_body(&encode_entries(entries)).expect_err(why);
        assert_eq!(err.kind(), ErrorKind::InvalidChannelIdentityBody, "{why}");
    };

    // The version selects the key set, so neither key set can wear the
    // other's version.
    reject(
        delegated_body_entries("delegated_grant", CHANNEL_IDENTITY_SCHEMA_VERSION),
        "delegated body at schema_version 1 must fail closed",
    );
    reject(
        delegated_body_entries("delegated_grant", 3),
        "unknown schema_version must fail closed",
    );
    reject(
        delegated_body_entries(
            "dedicated_address",
            CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION,
        ),
        "self-held shape carrying custody keys must fail closed",
    );

    let mut self_held_with_custody_key =
        delegated_body_entries("dedicated_address", CHANNEL_IDENTITY_SCHEMA_VERSION);
    self_held_with_custody_key.truncate(13);
    reject(
        self_held_with_custody_key,
        "v1 body with an extra custody key must fail closed",
    );

    let mut missing_scopes =
        delegated_body_entries("delegated_grant", CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION);
    missing_scopes.truncate(13);
    reject(
        missing_scopes,
        "delegated body missing grant_scopes must fail closed",
    );

    let mut unknown_shape =
        delegated_body_entries("delegated_grant", CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION);
    unknown_shape[3].1 = Value::from("delegated_mailbox");
    reject(unknown_shape, "unknown shape string must fail closed");

    // A write scope has no variant to decode into. Consent screens that
    // over-grant cannot become a row that claims send.
    for scope in ["mail.send", "mail.delete", "mail.modify", ""] {
        let mut write_scope =
            delegated_body_entries("delegated_grant", CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION);
        write_scope[13].1 = Value::Array(vec![Value::from(scope)]);
        reject(write_scope, "write scope must fail closed");
    }

    let mut empty_scopes =
        delegated_body_entries("delegated_grant", CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION);
    empty_scopes[13].1 = Value::Array(Vec::new());
    reject(empty_scopes, "empty scope list must fail closed");

    let mut repeated_scopes =
        delegated_body_entries("delegated_grant", CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION);
    repeated_scopes[13].1 = Value::Array(vec![Value::from("mail.read"), Value::from("mail.read")]);
    reject(repeated_scopes, "repeated scopes must fail closed");

    let mut blank_ref =
        delegated_body_entries("delegated_grant", CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION);
    blank_ref[12].1 = Value::from("  ");
    reject(blank_ref, "blank custody ref must fail closed");
}

#[test]
fn delegated_rows_have_no_rotation_or_quarantine_state() -> Result<()> {
    let identity = sample_delegated_identity();
    let active = identity
        .transition(
            ChannelIdentityState::PendingFulfillment,
            Some(ChannelIdentityFulfillment::Api),
            1_800_000_010,
            None,
        )?
        .transition(ChannelIdentityState::Active, None, 1_800_000_020, None)?;

    // ROTATING and QUARANTINE both assert product custody of the underlying
    // account. On a member's mailbox neither is ours to claim, at any layer.
    let err = active
        .transition(ChannelIdentityState::Rotating, None, 1_800_000_030, None)
        .expect_err("delegated rows must not rotate");
    assert_eq!(err.kind(), ErrorKind::InvalidChannelIdentityBody);

    let released = active.transition(ChannelIdentityState::Released, None, 1_800_000_030, None)?;
    let err = released
        .transition(
            ChannelIdentityState::Quarantine,
            None,
            1_800_000_040,
            Some(1_800_000_040 + CHANNEL_IDENTITY_MIN_QUARANTINE_SECS),
        )
        .expect_err("delegated rows must not quarantine");
    assert_eq!(err.kind(), ErrorKind::InvalidChannelIdentityBody);

    // The tie runs both ways: custody without the shape, and the shape
    // without custody, are equally unconstructible.
    let mut shape_without_custody = sample_delegated_identity();
    shape_without_custody.delegated_grant = None;
    assert_eq!(
        shape_without_custody
            .validate()
            .expect_err("delegated shape requires custody")
            .kind(),
        ErrorKind::InvalidChannelIdentityBody
    );

    let mut custody_without_shape = sample_identity();
    custody_without_shape.delegated_grant = Some(DelegatedGrant::new(
        "gmail-delegated:stray",
        vec![DelegatedGrantScope::MailMetadata],
    ));
    assert_eq!(
        custody_without_shape
            .validate()
            .expect_err("self-held shape refuses custody")
            .kind(),
        ErrorKind::InvalidChannelIdentityBody
    );
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
