use super::*;

fn sample_delegated_identity() -> ChannelIdentity {
    decode_channel_identity_body(&encode_entries(delegated_body_entries(
        "delegated_grant",
        CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION,
    )))
    .expect("delegated codec fixture")
}

/// Builds a delegated body in the CURRENT fifteen-key layout.
///
/// `binding_facet_ref` sits between the self-held keys and the two custody
/// keys, so the custody keys live at [`DELEGATED_GRANT_REF_IDX`] and
/// [`GRANT_SCOPES_IDX`].
fn delegated_body_entries(shape: &str, version: u64) -> Vec<(Value, Value)> {
    vec![
        (Value::from("schema_version"), Value::from(version)),
        (Value::from("channel"), Value::from("email")),
        (
            Value::from("address_or_handle"),
            Value::from("member@member-owned.example"),
        ),
        (Value::from("shape"), Value::from(shape)),
        (Value::from("binding_scope"), Value::from("actor")),
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
        (Value::from("binding_facet_ref"), Value::Nil),
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

const DELEGATED_GRANT_REF_IDX: usize = 13;
const GRANT_SCOPES_IDX: usize = 14;

fn encode_entries(entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("fixture encodes");
    out
}

/// All three self-held shapes use the thirteen pinned keys at the current version.
#[test]
fn canonical_self_held_bodies_carry_the_facet_key() -> Result<()> {
    for shape in [
        ChannelIdentityShape::DedicatedAddress,
        ChannelIdentityShape::DedicatedHandle,
        ChannelIdentityShape::SharedPresence,
    ] {
        let mut identity = sample_identity();
        identity.shape = shape;
        let encoded = encode_channel_identity_body(&identity)?;
        assert_eq!(decode_channel_identity_body(&encoded)?, identity);
        let Value::Map(entries) =
            rmpv::decode::read_value(&mut Cursor::new(&encoded)).expect("body decodes as a map")
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
    }
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

    // The version selects the key set, so no key set can wear another's version.
    reject(
        delegated_body_entries("delegated_grant", CHANNEL_IDENTITY_SCHEMA_VERSION),
        "delegated body at the self-held version must fail closed",
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

#[test]
fn unsupported_schema_versions_are_rejected() -> Result<()> {
    for identity in [sample_identity(), sample_delegated_identity()] {
        let encoded = encode_channel_identity_body(&identity)?;
        let Value::Map(entries) =
            rmpv::decode::read_value(&mut Cursor::new(&encoded)).expect("current body map")
        else {
            panic!("current identity must be a map");
        };
        for version in [0u64, 1, 2, 5, u64::MAX] {
            let mut unsupported = entries.clone();
            unsupported[0].1 = Value::from(version);
            assert!(matches!(
                decode_channel_identity_body(&encode_entries(unsupported)),
                Err(Error::InvalidChannelIdentityBody(
                    "unsupported channel identity schema version"
                ))
            ));
        }
    }
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
fn claim_binding_scope_accepts_only_current_spellings() -> Result<()> {
    let mut claim = ClaimBody::new(
        PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE,
        ClaimSubject::Entity(entity(0xD1)),
        Value::from("actor"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    for scope in ["actor", "vault"] {
        claim.value = Value::from(scope);
        validate_channel_identity_claim_structure(&claim)?;
    }
    for scope in ["agent", "person"] {
        claim.value = Value::from(scope);
        assert_eq!(
            validate_channel_identity_claim_structure(&claim)
                .expect_err("unsupported scope must fail")
                .kind(),
            ErrorKind::InvalidClaimBody
        );
    }
    Ok(())
}

#[test]
fn current_bindings_round_trip_and_reject_obsolete_scope_or_missing_facet_key() -> Result<()> {
    for mut identity in [sample_identity(), sample_delegated_identity()] {
        for binding in [
            ChannelIdentityBinding::actor(entity(0x51)),
            ChannelIdentityBinding::actor_with_facet(entity(0x51), entity(0x77)),
            ChannelIdentityBinding::vault(7),
        ] {
            identity.binding = binding;
            let encoded = encode_channel_identity_body(&identity)?;
            let decoded = decode_channel_identity_body(&encoded)?;
            assert_eq!(decoded, identity);
            assert_eq!(encode_channel_identity_body(&decoded)?, encoded);
            let Value::Map(mut entries) =
                rmpv::decode::read_value(&mut Cursor::new(&encoded)).expect("current body map")
            else {
                panic!("current identity must be a map");
            };

            let mut missing_facet_key = entries.clone();
            missing_facet_key.remove(12);
            assert_eq!(
                decode_channel_identity_body(&encode_entries(missing_facet_key))
                    .expect_err("current schema requires the facet key even when nil")
                    .kind(),
                ErrorKind::InvalidChannelIdentityBody,
            );
            entries[4].1 = Value::from("agent");
            assert_eq!(
                decode_channel_identity_body(&encode_entries(entries))
                    .expect_err("current schema cannot use the obsolete scope")
                    .kind(),
                ErrorKind::InvalidChannelIdentityBody,
            );
        }
    }
    Ok(())
}
