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

mod codec;
mod subject_binding;

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

/// The stored row R1's accessors are read through: a requested self-held email
/// mailbox already bound to its channel actor and provisioned against a
/// manifest.
///
/// Built through the CODEC's door rather than by assigning fields, because
/// after R1 there are no fields to assign — which is the property under test in
/// half the cases below.
fn sample_identity() -> ChannelIdentity {
    sample_identity_stored(Custody::requested_self_held(
        SelfHeldShape::DedicatedAddress,
    ))
}

/// [`sample_identity`] carrying a chosen custody value.
fn sample_identity_stored(custody: Custody) -> ChannelIdentity {
    sample_identity_bound(custody, ChannelIdentityBinding::agent(entity(0x51)))
}

/// [`sample_identity`] carrying a chosen custody value and binding.
fn sample_identity_bound(custody: Custody, binding: ChannelIdentityBinding) -> ChannelIdentity {
    ChannelIdentity::from_stored_parts(StoredIdentityParts {
        auth_mode: ChannelAuthMode::ApiKey,
        channel: "email".to_owned(),
        address_or_handle: "agent@example.com".to_owned(),
        binding,
        custody,
        state_changed_at: 1_800_000_000,
        reputation_ref: Some(entity(0xB1)),
        manifest_ref: Some(entity(0xC1)),
    })
    .expect("sample identity")
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
    let identity = sample_identity().step(
        ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Manual),
        1_800_000_010,
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
            .step(ChannelIdentityStep::Fulfill, 1_800_000_010)
            .is_err()
    );

    let pending = requested.step(
        ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
        1_800_000_010,
    )?;
    assert_eq!(
        pending.pending_fulfillment(),
        Some(ChannelIdentityFulfillment::Api),
        "the lane rides on the act, so a pending row always names one",
    );
    let active = pending.step(ChannelIdentityStep::Fulfill, 1_800_000_020)?;
    assert!(
        active
            .step(ChannelIdentityStep::Close, 1_800_000_030)
            .is_err()
    );

    let released = active.step(ChannelIdentityStep::Release, 1_800_000_030)?;
    assert!(
        released
            .step(
                ChannelIdentityStep::Quarantine {
                    until: 1_800_000_020 + CHANNEL_IDENTITY_MIN_QUARANTINE_SECS,
                },
                1_800_000_020,
            )
            .is_err()
    );
    assert!(
        released
            .step(
                ChannelIdentityStep::Quarantine {
                    until: 1_800_000_040 + CHANNEL_IDENTITY_MIN_QUARANTINE_SECS - 1,
                },
                1_800_000_040,
            )
            .is_err()
    );
    let quarantine = released.step(
        ChannelIdentityStep::Quarantine {
            until: 1_800_000_040 + CHANNEL_IDENTITY_MIN_QUARANTINE_SECS,
        },
        1_800_000_040,
    )?;
    assert_eq!(
        quarantine.quarantine_until(),
        Some(1_800_000_040 + CHANNEL_IDENTITY_MIN_QUARANTINE_SECS),
        "a quarantined row always names the window it is held for",
    );
    quarantine.step(ChannelIdentityStep::Close, 1_900_000_000)?;
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
    assert_eq!(identity.channel(), "own_app");
    assert_eq!(identity.shape(), ChannelIdentityShape::DedicatedHandle);
    assert_eq!(identity.binding(), ChannelIdentityBinding::agent(agent));
    assert_eq!(identity.state(), ChannelIdentityState::Active);
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
                start: identity.state_changed_at(),
                end: identity.state_changed_at(),
            },
            identity.state_changed_at(),
            &data,
        )
        .expect_err("generic public put must reject maintenance CID records");
    assert_eq!(err.kind(), ErrorKind::MaintenanceKindNotWritable);

    vault.create_channel_identity(&id, &identity)?;
    assert_eq!(vault.get_channel_identity(&id)?, Some(identity));

    vault.step_channel_identity(
        &id,
        ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
        1_800_000_010,
    )?;
    vault.step_channel_identity(&id, ChannelIdentityStep::Fulfill, 1_800_000_020)?;
    vault.step_channel_identity(&id, ChannelIdentityStep::Release, 1_800_000_030)?;
    vault.step_channel_identity(
        &id,
        ChannelIdentityStep::Quarantine {
            until: 1_800_000_040 + CHANNEL_IDENTITY_MIN_QUARANTINE_SECS,
        },
        1_800_000_040,
    )?;
    let tombstone = vault.step_channel_identity(&id, ChannelIdentityStep::Close, 1_900_000_000)?;
    assert_eq!(tombstone.state(), ChannelIdentityState::Tombstone);

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

    // A blank address cannot be assigned onto a built row any more, so the
    // refusal is proved at the door that can still present one: the decoder's.
    let err = ChannelIdentity::from_stored_parts(StoredIdentityParts {
        auth_mode: ChannelAuthMode::ApiKey,
        channel: "email".to_owned(),
        address_or_handle: " ".to_owned(),
        binding: ChannelIdentityBinding::agent(entity(0x51)),
        custody: Custody::requested_self_held(SelfHeldShape::DedicatedAddress),
        state_changed_at: 1_800_000_000,
        reputation_ref: None,
        manifest_ref: None,
    })
    .expect_err("blank address rejected");
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
        assert_eq!(row.shape(), wire);
        assert_eq!(row.state(), ChannelIdentityState::Requested);
        assert!(!row.is_delegated());
        assert!(row.grant().is_none());
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
    .step(
        ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
        1_800_000_010,
    )
    .and_then(|pending| pending.step(ChannelIdentityStep::Fulfill, 1_800_000_020))
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
    assert_eq!(requested.state(), ChannelIdentityState::Requested);
    assert_eq!(requested.address_or_handle(), "member@member-owned.example");
    assert!(requested.is_delegated());
    assert!(!requested.may_send());

    // A delegated row has no rotation and no quarantine to step into.
    for banned in [
        ChannelIdentityStep::Rotate,
        ChannelIdentityStep::Quarantine {
            until: 1_800_000_010 + CHANNEL_IDENTITY_MIN_QUARANTINE_SECS,
        },
    ] {
        assert!(
            vault
                .step_channel_identity(&id, banned, 1_800_000_010)
                .is_err(),
            "{banned:?} is not on the delegated machine",
        );
    }

    // And the row itself refuses to step at all outside the vault door: a
    // delegated act that asserts a live grant can only be proved in the
    // transaction that writes it.
    assert_eq!(
        requested
            .step(
                ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
                1_800_000_010
            )
            .expect_err("delegated rows step only through the vault")
            .kind(),
        ErrorKind::InvalidChannelIdentityBody,
    );

    vault.step_channel_identity(
        &id,
        ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
        1_800_000_010,
    )?;
    let active = vault.step_channel_identity(&id, ChannelIdentityStep::Fulfill, 1_800_000_020)?;
    // Even live, a scoped-read grant over someone else's mailbox never sends.
    assert!(!active.may_send());
    assert!(active.occupies_assignment_key());

    // Retirement frees the key: the mailbox was never ours to hold back, so
    // lawful re-consent stays open after the close.
    let released = vault.step_channel_identity(&id, ChannelIdentityStep::Release, 1_800_000_030)?;
    assert!(!released.occupies_assignment_key());
    assert_eq!(
        vault
            .channel_identity_by_assignment(EMAIL_CHANNEL, "member@member-owned.example")?
            .map(|(found, _)| found),
        Some(id), // the retiring predecessor still receives in-flight mail
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
    assert_eq!(reconsented.state(), ChannelIdentityState::Requested);
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

    // A STORED body claiming ACTIVE asserts a provision decision, a bind edge,
    // a fulfillment and a receipt that never happened. The decoder's door is
    // now the only road that can present one — no caller assembles a row field
    // by field any more — so the birth law is proved against exactly what a
    // hostile replica can hand the store.
    let delegated = |grant: DelegatedGrant, lifecycle: DelegatedLifecycle| {
        ChannelIdentity::from_stored_parts(StoredIdentityParts {
            auth_mode: ChannelAuthMode::OAuth,
            channel: EMAIL_CHANNEL.to_owned(),
            address_or_handle: "member@member-owned.example".to_owned(),
            binding: ChannelIdentityBinding::agent(entity(0x51)),
            custody: Custody::Delegated { grant, lifecycle },
            state_changed_at: 1_800_000_000,
            reputation_ref: None,
            manifest_ref: None,
        })
    };
    let crafted = delegated(grant, DelegatedLifecycle::Active)?;
    let err = vault
        .create_channel_identity(&entity(0x72), &crafted)
        .expect_err("a delegated row is born Requested");
    assert_eq!(err.kind(), ErrorKind::InvalidChannelIdentityBody);

    // And a delegated body naming custody this vault does not hold is refused
    // whatever state it claims.
    let unbacked = delegated(
        DelegatedGrant::new(
            "oauth/gmail/stranger",
            vec![crate::channel_identity::DelegatedGrantScope::MailRead],
        ),
        DelegatedLifecycle::Requested,
    )?;
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
    assert_eq!(identity.channel(), "email");
    assert_eq!(identity.address_or_handle(), "agent@example.com");
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

    assert_eq!(ENTITY_TYPE_CHANNEL_IDENTITY, 81);
    assert_eq!(entry.kind, "CHANNEL_IDENTITY");
    assert_eq!(entry.short_id_prefix, None);
    assert_eq!(entry.classification, EntityClassification::Maintenance);
    assert_eq!(entry.zone, TypeByteZone::System);
}

#[test]
fn channel_auth_modes_register_without_credential_material() -> Result<()> {
    use crate::channel_identity::ChannelAuthMode;
    for mode in [
        ChannelAuthMode::Local,
        ChannelAuthMode::ApiKey,
        ChannelAuthMode::OAuth,
    ] {
        let (_dir, vault) = test_vault();
        let identity = ChannelIdentity::from_stored_parts(StoredIdentityParts {
            auth_mode: mode,
            channel: "email".to_owned(),
            address_or_handle: "agent@example.com".to_owned(),
            binding: ChannelIdentityBinding::agent(entity(0x51)),
            custody: Custody::requested_self_held(SelfHeldShape::DedicatedAddress),
            state_changed_at: 1_800_000_000,
            reputation_ref: None,
            manifest_ref: None,
        })?;
        let id = entity(0xD1);
        vault.create_channel_identity(&id, &identity)?;
        assert_eq!(vault.get_channel_identity(&id)?, Some(identity.clone()));
        let bytes = encode_channel_identity_body(&identity)?;
        let decoded = decode_channel_identity_body(&bytes)?;
        assert_eq!(decoded.auth_mode(), mode);
        assert_eq!(mode.as_str().parse::<ChannelAuthMode>()?, mode);
        let claims = identity.claim_bodies(entity(0xD1));
        assert!(
            claims
                .iter()
                .any(|claim| claim.predicate == "channel_identity.auth_mode"
                    && claim.value.as_str() == Some(mode.as_str()))
        );
        // An unknown mode or a credential-bearing body is refused by the same
        // decoder used at the record write chokepoint.
        let Value::Map(fields) = rmpv::decode::read_value(&mut Cursor::new(&bytes)).unwrap() else {
            panic!()
        };
        for credential in [false, true] {
            let mut fields = fields.clone();
            if credential {
                fields.push((
                    Value::from("credentials"),
                    Value::from("must-stay-host-side"),
                ));
            } else {
                fields
                    .iter_mut()
                    .find(|(k, _)| k.as_str() == Some("auth_mode"))
                    .unwrap()
                    .1 = Value::from("unknown");
            }
            let mut raw = Vec::new();
            rmpv::encode::write_value(&mut raw, &Value::Map(fields)).unwrap();
            assert_eq!(
                decode_channel_identity_body(&raw).unwrap_err().kind(),
                ErrorKind::InvalidChannelIdentityBody
            );
        }
        drop(vault);
    }
    Ok(())
}

mod actors;

#[test]
fn assignment_two_slots_route_retiring_predecessor_until_reconsent_is_active() -> Result<()> {
    let (_dir, vault) = test_vault();
    let mailbox = "member@member-owned.example";
    let grant = DelegatedGrant::new("oauth/gmail/member", vec![DelegatedGrantScope::MailRead]);
    register_delegated_custody(&vault, &grant, mailbox)?;
    let first = entity(0xA8);
    let second = entity(0xA9);
    let request = |actor| DelegatedProvisionRequest {
        channel: EMAIL_CHANNEL.to_owned(),
        address_or_handle: mailbox.to_owned(),
        binding: ChannelIdentityBinding::agent(actor),
        grant: grant.clone(),
    };
    vault.provision_delegated_identity(&first, request(entity(0x51)), 100)?;
    vault.step_channel_identity(
        &first,
        ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
        101,
    )?;
    vault.step_channel_identity(&first, ChannelIdentityStep::Fulfill, 102)?;
    vault.step_channel_identity(&first, ChannelIdentityStep::Release, 103)?;
    vault.provision_delegated_identity(&second, request(entity(0x52)), u64::MAX - 1)?;
    // Deliberately skewed timestamps do not decide precedence. Requested and
    // pending re-consent cannot shadow a released row's in-flight mail.
    assert_eq!(
        vault
            .channel_identity_by_assignment(EMAIL_CHANNEL, mailbox)?
            .map(|(id, _)| id),
        Some(first)
    );
    vault.step_channel_identity(
        &second,
        ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
        u64::MAX - 1,
    )?;
    assert_eq!(
        vault
            .channel_identity_by_assignment(EMAIL_CHANNEL, mailbox)?
            .map(|(id, _)| id),
        Some(first)
    );
    vault.step_channel_identity(&second, ChannelIdentityStep::Fulfill, u64::MAX)?;
    assert_eq!(
        vault
            .channel_identity_by_assignment(EMAIL_CHANNEL, mailbox)?
            .map(|(id, _)| id),
        Some(second)
    );
    vault.rebuild_channel_identity_assignment_index()?;
    assert_eq!(
        vault
            .channel_identity_by_assignment(EMAIL_CHANNEL, mailbox)?
            .map(|(id, _)| id),
        Some(second)
    );
    Ok(())
}

#[test]
fn delegated_custody_must_name_the_exact_mailbox_at_engine_door() -> Result<()> {
    let (_dir, vault) = test_vault();
    let grant = DelegatedGrant::new("oauth/gmail/alice", vec![DelegatedGrantScope::MailRead]);
    register_delegated_custody(&vault, &grant, "alice@example.test")?;
    let request = DelegatedProvisionRequest {
        channel: EMAIL_CHANNEL.to_owned(),
        address_or_handle: "bob@example.test".to_owned(),
        binding: ChannelIdentityBinding::agent(entity(0x51)),
        grant: grant.clone(),
    };
    assert_eq!(
        vault
            .provision_delegated_identity(&entity(0xB1), request, 1_800_000_000)
            .expect_err("custody of alice never authorizes bob's mailbox")
            .kind(),
        ErrorKind::SecretBindingDenied,
    );
    assert!(vault.get_channel_identity(&entity(0xB1))?.is_none());
    // Verification is itself engine-side; the adapter cannot vouch for Bob.
    assert_eq!(
        vault
            .verify_delegated_custody(EMAIL_CHANNEL, "bob@example.test", &grant)
            .expect_err("proof cannot be minted for a different subject")
            .kind(),
        ErrorKind::SecretBindingDenied,
    );
    Ok(())
}
