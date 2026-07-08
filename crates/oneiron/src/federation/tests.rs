use super::*;
use crate::error::ErrorKind;
use crate::registry::{
    ENTITY_TYPE_FEDERATION_GRANT, EntityClassification, TypeByteBand, entity_type_registry_entry,
};

fn member_ref() -> EntityId {
    EntityId::from_bytes([0x42; 16]).expect("valid member id")
}

fn test_grant() -> FederationGrant {
    FederationGrant::new(
        FederationGrantScope::vault(7),
        member_ref(),
        FederationGrantRole::Admin,
        FederationGrantPreset::Admin,
    )
}

fn encode_value(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).expect("encode msgpack");
    out
}

fn valid_entries() -> Vec<(Value, Value)> {
    vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(FEDERATION_GRANT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_SCOPE),
            Value::Map(vec![
                (
                    Value::from(FEDERATION_GRANT_SCOPE_KEYS[0]),
                    Value::from(SCOPE_KIND_VAULT),
                ),
                (
                    Value::from(FEDERATION_GRANT_SCOPE_KEYS[1]),
                    Value::from(7_u64),
                ),
            ]),
        ),
        (
            Value::from(KEY_MEMBER_REF),
            Value::from(member_ref().to_hex()),
        ),
        (Value::from(KEY_ROLE), Value::from("admin")),
        (Value::from(KEY_PRESET), Value::from("admin")),
    ]
}

fn grant_map(entries: Vec<(Value, Value)>) -> Vec<u8> {
    encode_value(&Value::Map(entries))
}

#[test]
fn federation_grant_codec_round_trips_scope_role_and_preset() -> Result<()> {
    let grant = test_grant();

    let encoded = encode_federation_grant_body(&grant)?;
    validate_federation_grant_body_bytes(&encoded)?;
    let decoded = decode_federation_grant_body(&encoded)?;

    assert_eq!(decoded, grant);
    assert!(decoded.is_admin());
    Ok(())
}

#[test]
fn federation_grant_body_encodes_member_ref_as_hex_string() -> Result<()> {
    let encoded = encode_federation_grant_body(&test_grant())?;
    let mut cursor = Cursor::new(&encoded);
    let value = rmpv::decode::read_value(&mut cursor).expect("decode grant body");
    let Value::Map(entries) = value else {
        panic!("grant body must encode as a map");
    };

    let expected = member_ref().to_hex();
    let member = required_value(&entries, KEY_MEMBER_REF)?;
    assert_eq!(member.as_str(), Some(expected.as_str()));
    Ok(())
}

#[test]
fn federation_grant_decode_fails_closed_for_malformed_bodies() {
    let mut trailing = grant_map(valid_entries());
    trailing.push(0xc0);

    let mut missing_preset = valid_entries();
    missing_preset.retain(|(key, _)| key.as_str() != Some(KEY_PRESET));

    let mut duplicate_role = valid_entries();
    duplicate_role.push((Value::from(KEY_ROLE), Value::from("viewer")));

    let mut unknown_key = valid_entries();
    unknown_key.push((Value::from("future"), Value::from("permit")));

    let mut bad_role = valid_entries();
    for (key, value) in &mut bad_role {
        if key.as_str() == Some(KEY_ROLE) {
            *value = Value::from("super_admin");
        }
    }

    let mut bad_scope_kind = valid_entries();
    for (key, value) in &mut bad_scope_kind {
        if key.as_str() == Some(KEY_SCOPE) {
            *value = Value::Map(vec![
                (
                    Value::from(FEDERATION_GRANT_SCOPE_KEYS[0]),
                    Value::from("selector"),
                ),
                (
                    Value::from(FEDERATION_GRANT_SCOPE_KEYS[1]),
                    Value::from(7_u64),
                ),
            ]);
        }
    }

    let mut zero_vault = valid_entries();
    for (key, value) in &mut zero_vault {
        if key.as_str() == Some(KEY_SCOPE) {
            *value = Value::Map(vec![
                (
                    Value::from(FEDERATION_GRANT_SCOPE_KEYS[0]),
                    Value::from(SCOPE_KIND_VAULT),
                ),
                (
                    Value::from(FEDERATION_GRANT_SCOPE_KEYS[1]),
                    Value::from(0_u64),
                ),
            ]);
        }
    }

    let mut bad_member = valid_entries();
    for (key, value) in &mut bad_member {
        if key.as_str() == Some(KEY_MEMBER_REF) {
            *value = Value::from("not-a-32-char-hex-entity-id");
        }
    }

    let mut binary_member = valid_entries();
    for (key, value) in &mut binary_member {
        if key.as_str() == Some(KEY_MEMBER_REF) {
            *value = Value::Binary(member_ref().as_bytes().to_vec());
        }
    }

    for (case, bytes) in [
        ("not msgpack", b"not-msgpack".to_vec()),
        ("not map", encode_value(&Value::from("grant"))),
        ("trailing bytes", trailing),
        ("missing preset", grant_map(missing_preset)),
        ("duplicate role", grant_map(duplicate_role)),
        ("unknown key", grant_map(unknown_key)),
        ("bad role", grant_map(bad_role)),
        ("bad scope kind", grant_map(bad_scope_kind)),
        ("zero vault", grant_map(zero_vault)),
        ("bad member", grant_map(bad_member)),
        ("binary member", grant_map(binary_member)),
    ] {
        let err = match decode_federation_grant_body(&bytes) {
            Ok(decoded) => panic!("{case}: malformed grant decoded as {decoded:?}"),
            Err(err) => err,
        };
        assert_eq!(
            err.kind(),
            ErrorKind::InvalidFederationGrantBody,
            "{case}: wrong error"
        );
    }
}

#[test]
fn federation_grant_policy_rejects_admin_role_under_non_admin_preset() {
    let grant = FederationGrant::new(
        FederationGrantScope::vault(7),
        member_ref(),
        FederationGrantRole::Admin,
        FederationGrantPreset::ReadOnly,
    );

    let err = grant
        .validate()
        .expect_err("read-only preset must not carry admin role");

    assert_eq!(err.kind(), ErrorKind::InvalidFederationGrantBody);
}

#[test]
fn federation_grant_type_registration_is_stable() {
    let entry = entity_type_registry_entry(ENTITY_TYPE_FEDERATION_GRANT)
        .expect("FEDERATION_GRANT registry row");

    assert_eq!(ENTITY_TYPE_FEDERATION_GRANT, 124);
    assert_eq!(entry.kind, "FEDERATION_GRANT");
    assert_eq!(entry.short_id_prefix, None);
    assert_eq!(entry.classification, EntityClassification::Maintenance);
    assert_eq!(entry.band, TypeByteBand::InducedDynamicMaintenance);
}
