use super::*;
use crate::error::ErrorKind;
use crate::registry::{
    ENTITY_TYPE_ACCESS_GRANT, EntityClassification, TypeByteZone, entity_type_registry_entry,
};

use crate::test_util::entity;

fn test_grant() -> AccessGrant {
    AccessGrant::companion_profile_read(entity(0x51), entity(0xB1), entity(0xC1), 42)
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
            Value::from(entity(0x51).to_hex()),
        ),
        (
            Value::from(KEY_SCOPE),
            Value::Map(vec![
                (
                    Value::from(SCOPE_KEYS_COMPANION_PROFILE[0]),
                    Value::from(SCOPE_KIND_COMPANION_PROFILE),
                ),
                (
                    Value::from(SCOPE_KEYS_COMPANION_PROFILE[1]),
                    Value::from(entity(0xB1).to_hex()),
                ),
                (
                    Value::from(SCOPE_KEYS_COMPANION_PROFILE[2]),
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
    assert!(decoded.allows_companion_profile_read(&entity(0x51), &entity(0xB1), &entity(0xC1)));
    assert!(!decoded.allows_companion_profile_read(&entity(0x51), &entity(0xB2), &entity(0xC1)));
    Ok(())
}

#[test]
fn access_grant_revocation_removes_authorization() -> Result<()> {
    let revoked = test_grant().revoked(60)?;

    assert!(!revoked.allows_companion_profile_read(&entity(0x51), &entity(0xB1), &entity(0xC1)));
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
            if key.as_str() == Some(SCOPE_KEYS_COMPANION_PROFILE[1]) {
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
    assert_eq!(entry.zone, TypeByteZone::System);
}

// ---------------------------------------------------------------------------
// ONE-1812 [BK-01] — the calendar disclosure scope (ARCH-0062 R1)
// ---------------------------------------------------------------------------

fn calendar_grant() -> AccessGrant {
    AccessGrant::calendar_disclosure(entity(0x52), entity(0xB2), DisclosureRung::Titles, 42)
}

#[test]
fn calendar_access_grant_scope_round_trip_preserves_old_tags() -> Result<()> {
    // The pre-existing companion-profile encoding is byte-identical after the
    // append: same keys, same kind tag, same order.
    let companion = test_grant();
    assert_eq!(
        encode_access_grant_body(&companion)?,
        grant_map(valid_entries())
    );
    assert_eq!(
        decode_access_grant_body(&grant_map(valid_entries()))?,
        companion
    );

    // And the new scope round-trips on its own pinned key set.
    let grant = calendar_grant();
    let encoded = encode_access_grant_body(&grant)?;
    validate_access_grant_body_bytes(&encoded)?;
    assert_eq!(decode_access_grant_body(&encoded)?, grant);

    let scope = encode_scope(grant.scope);
    let Value::Map(entries) = &scope else {
        panic!("scope encodes as a map");
    };
    let keys: Vec<&str> = entries
        .iter()
        .map(|(key, _)| key.as_str().expect("string key"))
        .collect();
    assert_eq!(keys, SCOPE_KEYS_CALENDAR);
    assert_eq!(
        entries[0].1.as_str(),
        Some(SCOPE_KIND_CALENDAR),
        "the kind tag selects the key set"
    );
    assert_eq!(entries[2].1.as_str(), Some("titles"));

    // A scope may not borrow the other kind's keys.
    let hybrid = grant_map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(ACCESS_GRANT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_PRINCIPAL_REF),
            Value::from(entity(0x52).to_hex()),
        ),
        (
            Value::from(KEY_SCOPE),
            Value::Map(vec![
                (
                    Value::from(SCOPE_KEY_KIND),
                    Value::from(SCOPE_KIND_CALENDAR),
                ),
                (
                    Value::from(SCOPE_KEYS_COMPANION_PROFILE[1]),
                    Value::from(entity(0xB2).to_hex()),
                ),
                (
                    Value::from(SCOPE_KEYS_COMPANION_PROFILE[2]),
                    Value::from(entity(0xC2).to_hex()),
                ),
            ]),
        ),
        (
            Value::from(KEY_CAPABILITY),
            Value::from("calendar.disclosure_read"),
        ),
        (Value::from(KEY_STATUS), Value::from("active")),
        (Value::from(KEY_CREATED_AT), Value::from(42_u64)),
        (Value::from(KEY_REVOKED_AT), Value::Nil),
    ]);
    assert_eq!(
        decode_access_grant_body(&hybrid)
            .expect_err("mismatched scope keys")
            .kind(),
        ErrorKind::InvalidAccessGrantBody
    );
    Ok(())
}

#[test]
fn calendar_grant_reuses_access_grant_entity_type_128() {
    // No new entity byte: the calendar scope rides ACCESS_GRANT = 128.
    assert_eq!(ENTITY_TYPE_ACCESS_GRANT, 128);
    let entry =
        entity_type_registry_entry(ENTITY_TYPE_ACCESS_GRANT).expect("ACCESS_GRANT registry row");
    assert_eq!(entry.kind, "ACCESS_GRANT");

    let grant = calendar_grant();
    assert_eq!(
        grant.capability,
        AccessGrantCapability::CalendarDisclosureRead
    );
    assert_eq!(
        grant.calendar_disclosure_rung(&entity(0x52), &entity(0xB2)),
        Some(DisclosureRung::Titles)
    );
    // Wrong principal, wrong calendar, and the companion capability all deny.
    assert_eq!(
        grant.calendar_disclosure_rung(&entity(0x53), &entity(0xB2)),
        None
    );
    assert_eq!(
        grant.calendar_disclosure_rung(&entity(0x52), &entity(0xB3)),
        None
    );
    assert_eq!(
        test_grant().calendar_disclosure_rung(&entity(0x51), &entity(0xB1)),
        None
    );
    // The calendar scope is not a companion-profile scope.
    assert!(
        !grant
            .scope
            .matches_companion_profile(&entity(0xB2), &entity(0xC2))
    );
    assert_eq!(grant.scope.companion_profile_refs(), None);
}

#[test]
fn calendar_grant_registry_lists_and_revokes() {
    use crate::booking::{RungProjection, SurfaceClass, project_calendar_grant};
    use crate::test_util::{embedding_test_config, open_test_vault_with};

    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let calendar = entity(0xB2);
    let reader = entity(0x52);
    let grant_ref = entity(0x63);

    let grant = AccessGrant::calendar_disclosure(reader, calendar, DisclosureRung::Full, 42);
    vault
        .create_access_grant(&grant_ref, &grant)
        .expect("mint calendar grant");

    // Listed as a typed calendar row, keyed by a revocable handle.
    let rows = vault
        .list_calendar_access_grants(&calendar)
        .expect("list calendar grants");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].grant_ref, grant_ref);
    assert_eq!(rows[0].grant, grant);
    assert!(
        vault
            .list_calendar_access_grants(&entity(0xB3))
            .expect("list other calendar")
            .is_empty()
    );

    // Revoke through the calendar surface; the next read discloses Nothing.
    let revoked = vault
        .revoke_calendar_access_grant(&grant_ref, 99)
        .expect("revoke calendar grant");
    assert_eq!(revoked.status, AccessGrantStatus::Revoked);
    assert_eq!(
        project_calendar_grant(
            &revoked,
            &reader,
            &calendar,
            &[],
            SurfaceClass::CrossVault,
            None
        )
        .expect("post-revoke projection"),
        RungProjection::Nothing
    );

    // The calendar door is not a general revoke door.
    let companion_ref = entity(0x64);
    vault
        .create_access_grant(&companion_ref, &test_grant())
        .expect("mint companion grant");
    assert_eq!(
        vault
            .revoke_calendar_access_grant(&companion_ref, 99)
            .expect_err("companion grant is not revocable here")
            .kind(),
        ErrorKind::InvalidAccessGrantBody
    );
}

#[test]
fn access_grant_scope_and_capability_must_be_a_matched_pair() {
    // The scope×capability space is not two free axes. A calendar scope paired
    // with the companion read would list in the calendar registry and count as
    // an active projection while every rung read denied it; the reverse pairing
    // would be a live disclosure bound on a profile. Both are rejected at the
    // one door every codec and write path passes through.
    let calendar_scope_profile_capability = AccessGrant {
        capability: AccessGrantCapability::CompanionProfileRead,
        ..calendar_grant()
    };
    let profile_scope_calendar_capability = AccessGrant {
        capability: AccessGrantCapability::CalendarDisclosureRead,
        ..test_grant()
    };

    assert_eq!(
        AccessGrantScope::calendar(entity(0xB2), DisclosureRung::Titles).required_capability(),
        AccessGrantCapability::CalendarDisclosureRead
    );
    assert_eq!(
        AccessGrantScope::companion_profile(entity(0xB1), entity(0xC1)).required_capability(),
        AccessGrantCapability::CompanionProfileRead
    );

    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    for (case, grant) in [
        (
            "calendar scope, profile capability",
            calendar_scope_profile_capability,
        ),
        (
            "profile scope, calendar capability",
            profile_scope_calendar_capability,
        ),
    ] {
        assert_eq!(
            grant.validate().expect_err(case).kind(),
            ErrorKind::InvalidAccessGrantBody,
            "{case}: validate admitted a mispaired grant"
        );
        assert_eq!(
            encode_access_grant_body(&grant).expect_err(case).kind(),
            ErrorKind::InvalidAccessGrantBody,
            "{case}: encoded a mispaired grant"
        );
        assert_eq!(
            grant.revoked(99).expect_err(case).kind(),
            ErrorKind::InvalidAccessGrantBody,
            "{case}: revoked a mispaired grant"
        );
        assert_eq!(
            vault
                .create_access_grant(&entity(0x70), &grant)
                .expect_err(case)
                .kind(),
            ErrorKind::InvalidAccessGrantBody,
            "{case}: persisted a mispaired grant"
        );
    }

    // And a mispaired body on disk decodes fail-closed, not into a live grant.
    let mut mispaired_body = valid_entries();
    for (key, value) in &mut mispaired_body {
        if key.as_str() == Some(KEY_CAPABILITY) {
            *value = Value::from("calendar.disclosure_read");
        }
    }
    assert_eq!(
        decode_access_grant_body(&grant_map(mispaired_body))
            .expect_err("mispaired body")
            .kind(),
        ErrorKind::InvalidAccessGrantBody
    );
}

#[test]
fn revoke_calendar_access_grant_admits_and_rewrites_one_record() {
    use crate::test_util::{embedding_test_config, open_test_vault_with};

    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let companion_ref = entity(0x65);
    let companion = test_grant();
    vault
        .create_access_grant(&companion_ref, &companion)
        .expect("mint companion grant");

    // The scope gate rides the revoking write transaction, so a rejected scope
    // aborts that transaction whole: no partial revocation is left behind and
    // no second snapshot exists for a racing put to swap under the check.
    assert_eq!(
        vault
            .revoke_calendar_access_grant(&companion_ref, 99)
            .expect_err("companion scope is not admitted here")
            .kind(),
        ErrorKind::InvalidAccessGrantBody
    );
    assert_eq!(
        vault
            .get_access_grant(&companion_ref)
            .expect("read companion grant")
            .expect("companion grant still present"),
        companion,
        "a rejected calendar revoke must leave the record untouched"
    );

    // The admitted path revokes exactly the record it read.
    let calendar_ref = entity(0x66);
    let grant = calendar_grant();
    vault
        .create_access_grant(&calendar_ref, &grant)
        .expect("mint calendar grant");
    let revoked = vault
        .revoke_calendar_access_grant(&calendar_ref, 99)
        .expect("revoke calendar grant");
    assert_eq!(revoked.scope, grant.scope);
    assert_eq!(revoked.status, AccessGrantStatus::Revoked);
    assert_eq!(
        vault
            .get_access_grant(&calendar_ref)
            .expect("read calendar grant")
            .expect("calendar grant still present"),
        revoked
    );
}
