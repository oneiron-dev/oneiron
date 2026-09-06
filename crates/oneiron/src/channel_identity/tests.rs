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
            && claim.value.as_str() == Some("actor")
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

fn sample_delegated_identity() -> ChannelIdentity {
    decode_channel_identity_body(&encode_entries(delegated_body_entries(
        "delegated_grant",
        CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION,
    )))
    .expect("delegated codec fixture")
}

/// Rebuilds the exact twelve-key, `schema_version: 1` body pre-INB-06 head
/// wrote, from literal key strings rather than the crate constants — including
/// its `binding_scope: "agent"` spelling.
///
/// This is the ON-DISK fixture, so it is frozen forever: if a decode path ever
/// stops accepting it, every row written before INB-06 is orphaned, and that
/// is what the tests below exist to catch.
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
            // The head spelling, pinned as a literal: pre-INB-06 rows say
            // "agent" and no live constant may drift this fixture off it.
            Value::from("binding_scope"),
            Value::from(match identity.binding {
                ChannelIdentityBinding::Actor { .. } => "agent",
                ChannelIdentityBinding::Vault { .. } => "vault",
            }),
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

/// Builds a delegated body in the CURRENT fifteen-key layout.
///
/// `binding_facet_ref` sits between the self-held keys and the two custody
/// keys, so the custody keys live at [`DELEGATED_GRANT_REF_IDX`] and
/// [`GRANT_SCOPES_IDX`].
fn delegated_body_entries(shape: &str, version: u64) -> Vec<(Value, Value)> {
    let mut entries = legacy_delegated_body_entries(shape, version);
    entries[4].1 = Value::from("actor");
    entries.insert(12, (Value::from("binding_facet_ref"), Value::Nil));
    entries
}

const DELEGATED_GRANT_REF_IDX: usize = 13;
const GRANT_SCOPES_IDX: usize = 14;

/// Builds a delegated body in the pre-INB-06 fourteen-key layout.
fn legacy_delegated_body_entries(shape: &str, version: u64) -> Vec<(Value, Value)> {
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

/// INB-06 moved back-compat from a BYTE claim to a DECODE claim, on purpose.
///
/// The pre-INB-06 encoding cannot express what the record now holds: the
/// binding names an ACTOR that may wear a facet mask, so the canonical body
/// gained a `binding_facet_ref` key and spells its scope `actor`. No byte
/// sequence satisfies both that and "identical to what head wrote".
///
/// What actually protected users was never the byte identity — it was that no
/// row on disk gets orphaned. That is what this asserts now, and it is
/// strictly the load-bearing half: every pre-INB-06 body still decodes, to the
/// right record, with no facet.
#[test]
fn head_three_shape_bodies_still_decode_after_the_actor_binding() -> Result<()> {
    for shape in [
        ChannelIdentityShape::DedicatedAddress,
        ChannelIdentityShape::DedicatedHandle,
        ChannelIdentityShape::SharedPresence,
    ] {
        let mut identity = sample_identity();
        identity.shape = shape;

        // The exact bytes head wrote still decode to the exact record.
        let head_bytes = head_encoded_body(&identity);
        let decoded = decode_channel_identity_body(&head_bytes)?;
        assert_eq!(
            decoded,
            identity,
            "{} head body must still decode",
            shape.as_str()
        );
        assert_eq!(
            decoded.binding,
            ChannelIdentityBinding::Actor {
                actor_ref: entity(0x51),
                facet_ref: None,
            },
            "a legacy agent binding is an unmasked actor"
        );

        // Rewriting it emits the new canonical encoding, which round-trips.
        let rewritten = encode_channel_identity_body(&decoded)?;
        assert_ne!(rewritten, head_bytes, "rewrite must canonicalize");
        assert_eq!(decode_channel_identity_body(&rewritten)?, identity);
        assert!(identity.grant.is_none());
        assert!(shape.is_self_held());
    }

    let pending = sample_identity().transition(
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Review),
        1_800_000_010,
        None,
    )?;
    assert_eq!(
        decode_channel_identity_body(&head_encoded_body(&pending))?,
        pending
    );
    Ok(())
}

/// The canonical self-held body is the thirteen pinned keys at the current
/// version, in order — the counterpart of the legacy fixture above.
#[test]
fn canonical_self_held_body_carries_the_facet_key() -> Result<()> {
    let identity = sample_identity();
    let encoded = encode_channel_identity_body(&identity)?;
    let Value::Map(entries) =
        rmpv::decode::read_value(&mut std::io::Cursor::new(encoded.as_slice()))
            .expect("body decodes as a map")
    else {
        panic!("body must encode as a map");
    };
    let keys = entries
        .iter()
        .map(|(key, _)| key.as_str().expect("string key").to_owned())
        .collect::<Vec<_>>();
    assert_eq!(keys, CHANNEL_IDENTITY_BODY_KEYS.to_vec());
    assert_eq!(entries[0].1.as_u64(), Some(CHANNEL_IDENTITY_SCHEMA_VERSION));
    assert_eq!(entries[4].1.as_str(), Some("actor"));
    assert_eq!(entries[12].1, Value::Nil);
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

    // The version selects the key set, so no key set can wear another's
    // version — including the two decode-only legacy versions.
    reject(
        delegated_body_entries("delegated_grant", CHANNEL_IDENTITY_SCHEMA_VERSION),
        "delegated body at the self-held version must fail closed",
    );
    reject(
        delegated_body_entries("delegated_grant", CHANNEL_IDENTITY_LEGACY_SCHEMA_VERSION),
        "delegated body at legacy schema_version 1 must fail closed",
    );
    reject(
        legacy_delegated_body_entries("delegated_grant", CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION),
        "legacy key set at the current delegated version must fail closed",
    );
    reject(
        delegated_body_entries(
            "delegated_grant",
            CHANNEL_IDENTITY_LEGACY_DELEGATED_SCHEMA_VERSION,
        ),
        "current key set at the legacy delegated version must fail closed",
    );
    reject(
        delegated_body_entries("delegated_grant", 99),
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
    self_held_with_custody_key.truncate(14);
    reject(
        self_held_with_custody_key,
        "self-held body with an extra custody key must fail closed",
    );

    let mut missing_scopes =
        delegated_body_entries("delegated_grant", CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION);
    missing_scopes.truncate(GRANT_SCOPES_IDX);
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
        write_scope[GRANT_SCOPES_IDX].1 = Value::Array(vec![Value::from(scope)]);
        reject(write_scope, "write scope must fail closed");
    }

    let mut empty_scopes =
        delegated_body_entries("delegated_grant", CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION);
    empty_scopes[GRANT_SCOPES_IDX].1 = Value::Array(Vec::new());
    reject(empty_scopes, "empty scope list must fail closed");

    let mut repeated_scopes =
        delegated_body_entries("delegated_grant", CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION);
    repeated_scopes[GRANT_SCOPES_IDX].1 =
        Value::Array(vec![Value::from("mail.read"), Value::from("mail.read")]);
    reject(repeated_scopes, "repeated scopes must fail closed");

    let mut blank_ref =
        delegated_body_entries("delegated_grant", CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION);
    blank_ref[DELEGATED_GRANT_REF_IDX].1 = Value::from("  ");
    reject(blank_ref, "blank custody ref must fail closed");

    // A vault-scoped row cannot carry a facet: there is no actor to mask.
    let mut vault_with_facet =
        delegated_body_entries("delegated_grant", CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION);
    vault_with_facet[4].1 = Value::from("vault");
    vault_with_facet[5].1 = Value::from(7u64);
    vault_with_facet[12].1 = Value::from(entity(0x77).to_hex());
    reject(
        vault_with_facet,
        "vault binding with a facet must fail closed",
    );
}

/// A pre-INB-06 delegated row on disk still decodes, and its rewrite
/// canonicalizes onto the current version.
#[test]
fn legacy_delegated_body_still_decodes() -> Result<()> {
    let legacy = encode_entries(legacy_delegated_body_entries(
        "delegated_grant",
        CHANNEL_IDENTITY_LEGACY_DELEGATED_SCHEMA_VERSION,
    ));
    let decoded = decode_channel_identity_body(&legacy)?;
    assert_eq!(
        decoded.binding,
        ChannelIdentityBinding::Actor {
            actor_ref: entity(0x51),
            facet_ref: None,
        }
    );
    assert_eq!(decoded.shape, ChannelIdentityShape::DelegatedGrant);

    let rewritten = encode_channel_identity_body(&decoded)?;
    assert_ne!(rewritten, legacy, "rewrite must canonicalize");
    assert_eq!(decode_channel_identity_body(&rewritten)?, decoded);
    Ok(())
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
    shape_without_custody.grant = None;
    assert_eq!(
        shape_without_custody
            .validate()
            .expect_err("delegated shape requires custody")
            .kind(),
        ErrorKind::InvalidChannelIdentityBody
    );

    let mut custody_without_shape = sample_identity();
    custody_without_shape.grant = Some(DelegatedGrant::new(
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
        crate::write_envelope::WriteActor::new(actor, crate::edge::EdgeActorClass::Agent),
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
    assert_eq!(
        crate::subject_model::actor_subject_anchor(&vault, &actor)?,
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
        crate::write_envelope::WriteActor::new(actor, crate::edge::EdgeActorClass::Agent),
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
        crate::subject_model::actor_subject_anchor(&vault, &org)?,
        None,
        "the anchor hangs off the actor, not the org"
    );
    assert_eq!(
        crate::subject_model::actor_subject_anchor(&vault, &actor)?,
        Some(org)
    );
    Ok(())
}

/// The whole legacy-decode contract in one place: a stored v1 body with
/// `binding_scope: "agent"` is an unmasked actor.
#[test]
fn legacy_agent_binding_decodes() -> Result<()> {
    let identity = sample_identity();
    let decoded = decode_channel_identity_body(&head_encoded_body(&identity))?;
    assert_eq!(
        decoded.binding,
        ChannelIdentityBinding::Actor {
            actor_ref: entity(0x51),
            facet_ref: None,
        }
    );
    assert_eq!(decoded.binding.scope_str(), "actor");

    // A claim body carrying the legacy scope string still validates, so the
    // claim family does not orphan pre-INB-06 rows either.
    let mut legacy_claim = ClaimBody::new(
        PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE,
        ClaimSubject::Entity(entity(0xD1)),
        Value::from("agent"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    validate_channel_identity_claim_structure(&legacy_claim)?;
    legacy_claim.value = Value::from("actor");
    validate_channel_identity_claim_structure(&legacy_claim)?;
    legacy_claim.value = Value::from("person");
    assert_eq!(
        validate_channel_identity_claim_structure(&legacy_claim)
            .expect_err("unknown scope must fail")
            .kind(),
        ErrorKind::InvalidClaimBody
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
