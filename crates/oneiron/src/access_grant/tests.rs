use super::*;
use crate::error::ErrorKind;
use crate::registry::{
    ENTITY_TYPE_ACCESS_GRANT, EntityClassification, TypeByteBand, entity_type_registry_entry,
};

fn entity(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("valid entity id")
}

fn test_grant() -> AccessGrant {
    AccessGrant::companion_profile_read(entity(0xA1), entity(0xB1), entity(0xC1), 42)
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
            Value::from(ACCESS_GRANT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_PRINCIPAL_REF),
            Value::from(entity(0xA1).to_hex()),
        ),
        (
            Value::from(KEY_SCOPE),
            Value::Map(vec![
                (
                    Value::from(SCOPE_KEYS[0]),
                    Value::from(SCOPE_KIND_COMPANION_PROFILE),
                ),
                (
                    Value::from(SCOPE_KEYS[1]),
                    Value::from(entity(0xB1).to_hex()),
                ),
                (
                    Value::from(SCOPE_KEYS[2]),
                    Value::from(entity(0xC1).to_hex()),
                ),
            ]),
        ),
        (
            Value::from(KEY_CAPABILITY),
            Value::from("companion_profile.read"),
        ),
        (Value::from(KEY_STATUS), Value::from("active")),
        (Value::from(KEY_CREATED_AT), Value::from(42_u64)),
        (Value::from(KEY_REVOKED_AT), Value::Nil),
    ]
}

fn grant_map(entries: Vec<(Value, Value)>) -> Vec<u8> {
    encode_value(&Value::Map(entries))
}

#[test]
fn access_grant_codec_round_trips_scoped_active_grant() -> Result<()> {
    let grant = test_grant();

    let encoded = encode_access_grant_body(&grant)?;
    validate_access_grant_body_bytes(&encoded)?;
    let decoded = decode_access_grant_body(&encoded)?;

    assert_eq!(decoded, grant);
    assert!(decoded.allows_companion_profile_read(&entity(0xA1), &entity(0xB1), &entity(0xC1)));
    assert!(!decoded.allows_companion_profile_read(&entity(0xA1), &entity(0xB2), &entity(0xC1)));
    Ok(())
}

#[test]
fn access_grant_revocation_removes_authorization() -> Result<()> {
    let revoked = test_grant().revoked(60)?;

    assert!(!revoked.allows_companion_profile_read(&entity(0xA1), &entity(0xB1), &entity(0xC1)));
    let encoded = encode_access_grant_body(&revoked)?;
    let decoded = decode_access_grant_body(&encoded)?;
    assert_eq!(decoded.status, AccessGrantStatus::Revoked);
    assert_eq!(decoded.revoked_at, Some(60));
    Ok(())
}

#[test]
fn access_grant_decode_fails_closed_for_malformed_bodies() {
    let mut trailing = grant_map(valid_entries());
    trailing.push(0xc0);

    let mut missing_scope = valid_entries();
    missing_scope.retain(|(key, _)| key.as_str() != Some(KEY_SCOPE));

    let mut duplicate_status = valid_entries();
    duplicate_status.push((Value::from(KEY_STATUS), Value::from("revoked")));

    let mut unknown_key = valid_entries();
    unknown_key.push((Value::from("future"), Value::from("permit")));

    let mut bad_capability = valid_entries();
    for (key, value) in &mut bad_capability {
        if key.as_str() == Some(KEY_CAPABILITY) {
            *value = Value::from("companion_profile.write");
        }
    }

    let mut revoked_without_time = valid_entries();
    for (key, value) in &mut revoked_without_time {
        if key.as_str() == Some(KEY_STATUS) {
            *value = Value::from("revoked");
        }
    }

    let mut active_with_revoked_at = valid_entries();
    for (key, value) in &mut active_with_revoked_at {
        if key.as_str() == Some(KEY_REVOKED_AT) {
            *value = Value::from(60_u64);
        }
    }

    let mut bad_scope_person = valid_entries();
    if let Some((_, Value::Map(scope))) = bad_scope_person
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some(KEY_SCOPE))
    {
        for (key, value) in scope {
            if key.as_str() == Some(SCOPE_KEYS[1]) {
                *value = Value::from("not-an-entity");
            }
        }
    }

    for (case, bytes) in [
        ("not msgpack", b"not-msgpack".to_vec()),
        ("not map", encode_value(&Value::from("grant"))),
        ("trailing bytes", trailing),
        ("missing scope", grant_map(missing_scope)),
        ("duplicate status", grant_map(duplicate_status)),
        ("unknown key", grant_map(unknown_key)),
        ("bad capability", grant_map(bad_capability)),
        ("revoked without time", grant_map(revoked_without_time)),
        ("active with revoked_at", grant_map(active_with_revoked_at)),
        ("bad scope person", grant_map(bad_scope_person)),
    ] {
        let err = match decode_access_grant_body(&bytes) {
            Ok(decoded) => panic!("{case}: malformed grant decoded as {decoded:?}"),
            Err(err) => err,
        };
        assert_eq!(
            err.kind(),
            ErrorKind::InvalidAccessGrantBody,
            "{case}: wrong error"
        );
    }
}

#[test]
fn access_grant_type_registration_is_stable() {
    let entry =
        entity_type_registry_entry(ENTITY_TYPE_ACCESS_GRANT).expect("ACCESS_GRANT registry row");

    assert_eq!(ENTITY_TYPE_ACCESS_GRANT, 128);
    assert_eq!(entry.kind, "ACCESS_GRANT");
    assert_eq!(entry.short_id_prefix, None);
    assert_eq!(entry.classification, EntityClassification::Maintenance);
    assert_eq!(entry.band, TypeByteBand::InducedDynamicMaintenance);
}
