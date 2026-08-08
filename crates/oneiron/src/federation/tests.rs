use super::*;
use crate::claim::{CLAIM_PREDICATE_REGISTRY, ScopedReadActorKey};
use crate::config::VaultConfig;
use crate::error::ErrorKind;
use crate::registry::{
    ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON, EntityClassification, TypeByteZone,
    entity_type_registry_entry,
};
use crate::test_util::{entity, open_test_vault_with};

fn member_ref() -> EntityId {
    EntityId::from_bytes([0x62; 16]).expect("valid member id")
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

// ---------------------------------------------------------------------------
// Attenuated delegate tier (ONE-1409)
// ---------------------------------------------------------------------------

/// Fixed clock for every delegate fixture. Delegate expiry is a wall-clock
/// edge, so nothing here reads the real clock.
const DELEGATE_NOW: u64 = 1_700_000_000;
const DELEGATE_EXPIRES_AT: u64 = DELEGATE_NOW + 3_600;

/// Delegate principal, pinned distinct from [`member_ref`] so
/// `delegated_by != member_ref` is observable in every round-trip.
fn delegate_member_ref() -> EntityId {
    EntityId::from_bytes([0x63; 16]).expect("valid delegate member id")
}

fn test_delegate() -> FederationGrant {
    FederationGrant::attenuated_delegate(
        &test_grant(),
        delegate_member_ref(),
        DELEGATE_NOW,
        DELEGATE_EXPIRES_AT,
    )
    .expect("an admin parent mints a delegate")
}

fn non_delegate_grant(role: FederationGrantRole, preset: FederationGrantPreset) -> FederationGrant {
    FederationGrant::new(FederationGrantScope::vault(7), member_ref(), role, preset)
}

/// A hand-built seven-key delegate body, bypassing `attenuated_delegate`.
fn valid_delegate_entries() -> Vec<(Value, Value)> {
    let mut entries = valid_entries();
    for (key, value) in &mut entries {
        match key.as_str() {
            Some(KEY_MEMBER_REF) => *value = Value::from(delegate_member_ref().to_hex()),
            Some(KEY_ROLE | KEY_PRESET) => *value = Value::from("delegate"),
            _ => {}
        }
    }
    entries.push((
        Value::from(KEY_EXPIRES_AT),
        Value::from(DELEGATE_EXPIRES_AT),
    ));
    entries.push((
        Value::from(KEY_DELEGATED_BY),
        Value::from(member_ref().to_hex()),
    ));
    entries
}

fn assert_grant_rejected(case: &str, bytes: &[u8]) {
    let err = match decode_federation_grant_body(bytes) {
        Ok(decoded) => panic!("{case}: malformed grant decoded as {decoded:?}"),
        Err(err) => err,
    };
    assert_eq!(
        err.kind(),
        ErrorKind::InvalidFederationGrantBody,
        "{case}: wrong error"
    );
}

/// Done-means 1: the attenuated delegate is byte-stable across the codec and
/// both wire strings are exactly `delegate`.
#[test]
fn attenuated_delegate_round_trips_byte_stable() -> Result<()> {
    let parent = test_grant();
    let delegate = test_delegate();

    assert_eq!(delegate.scope, parent.scope, "scope is inherited");
    assert_eq!(delegate.member_ref, delegate_member_ref());
    assert_eq!(delegate.role, FederationGrantRole::Delegate);
    assert_eq!(delegate.preset, FederationGrantPreset::Delegate);
    assert_eq!(delegate.expires_at, Some(DELEGATE_EXPIRES_AT));
    // The PARENT'S PRINCIPAL, never a grant entity id.
    assert_eq!(delegate.delegated_by, Some(parent.member_ref));

    let encoded = encode_federation_grant_body(&delegate)?;
    validate_federation_grant_body_bytes(&encoded)?;
    let decoded = decode_federation_grant_body(&encoded)?;
    assert_eq!(decoded, delegate);
    assert_eq!(
        encode_federation_grant_body(&decoded)?,
        encoded,
        "decode/encode must be byte-stable"
    );

    let mut cursor = Cursor::new(&encoded);
    let value = rmpv::decode::read_value(&mut cursor).expect("decode delegate body");
    let Value::Map(entries) = value else {
        panic!("delegate body must encode as a map");
    };
    assert_eq!(entries.len(), FEDERATION_GRANT_BODY_KEYS.len());
    assert_eq!(
        required_value(&entries, KEY_ROLE)?.as_str(),
        Some("delegate")
    );
    assert_eq!(
        required_value(&entries, KEY_PRESET)?.as_str(),
        Some("delegate")
    );
    assert_eq!(
        required_value(&entries, KEY_EXPIRES_AT)?.as_u64(),
        Some(DELEGATE_EXPIRES_AT)
    );
    assert_eq!(
        required_value(&entries, KEY_DELEGATED_BY)?.as_str(),
        Some(member_ref().to_hex().as_str())
    );
    Ok(())
}

/// Done-means 6: the TTL window is half-open at both ends — `now` itself is
/// already too late, the 90-day maximum is reachable exactly, and the ceiling
/// addition is checked.
#[test]
fn delegate_ttl_bounds_are_exact() {
    let parent = test_grant();
    let mint = |now: u64, expires_at: u64| {
        FederationGrant::attenuated_delegate(&parent, delegate_member_ref(), now, expires_at)
    };

    assert_eq!(MAX_DELEGATE_TTL_SECS, 7_776_000, "90 days in seconds");

    mint(DELEGATE_NOW, DELEGATE_NOW + 1).expect("one second past now is the minimum TTL");
    mint(DELEGATE_NOW, DELEGATE_NOW + MAX_DELEGATE_TTL_SECS)
        .expect("equality at the 90-day maximum is allowed");

    for (case, now, expires_at) in [
        ("expiry equals now", DELEGATE_NOW, DELEGATE_NOW),
        ("expiry before now", DELEGATE_NOW, DELEGATE_NOW - 1),
        ("expiry at zero", DELEGATE_NOW, 0),
        (
            "one second past the maximum",
            DELEGATE_NOW,
            DELEGATE_NOW + MAX_DELEGATE_TTL_SECS + 1,
        ),
        // `now + MAX_DELEGATE_TTL_SECS` overflows: the ceiling is unreachable,
        // so the mint rejects rather than wrapping into a permissive bound.
        ("ceiling overflow", u64::MAX - 1, u64::MAX),
    ] {
        let err = mint(now, expires_at).expect_err(case);
        assert_eq!(
            err.kind(),
            ErrorKind::InvalidFederationGrantBody,
            "{case}: wrong error"
        );
    }
}

/// Done-means 3: the tier cannot self-widen. Only Owner/Admin parents delegate,
/// a delegate is never administrative, and a delegate cannot re-delegate.
#[test]
fn delegate_minting_never_self_widens() {
    let delegate = test_delegate();
    assert!(!delegate.is_admin(), "a delegate is never administrative");
    assert!(!FederationGrantRole::Delegate.is_admin());
    for role in [
        FederationGrantRole::Owner,
        FederationGrantRole::Admin,
        FederationGrantRole::Member,
        FederationGrantRole::Viewer,
        FederationGrantRole::Auditor,
        FederationGrantRole::Delegate,
    ] {
        assert_eq!(
            role.is_admin(),
            matches!(
                role,
                FederationGrantRole::Owner | FederationGrantRole::Admin
            ),
            "{role:?}: is_admin must stay Owner/Admin only"
        );
    }

    for (case, parent) in [
        (
            "owner",
            non_delegate_grant(FederationGrantRole::Owner, FederationGrantPreset::Owner),
        ),
        (
            "admin",
            non_delegate_grant(FederationGrantRole::Admin, FederationGrantPreset::Admin),
        ),
    ] {
        FederationGrant::attenuated_delegate(
            &parent,
            delegate_member_ref(),
            DELEGATE_NOW,
            DELEGATE_EXPIRES_AT,
        )
        .unwrap_or_else(|e| panic!("{case}: an administrative parent must delegate: {e:?}"));
    }

    for (case, parent) in [
        (
            "member",
            non_delegate_grant(FederationGrantRole::Member, FederationGrantPreset::Member),
        ),
        (
            "viewer",
            non_delegate_grant(FederationGrantRole::Viewer, FederationGrantPreset::ReadOnly),
        ),
        (
            "auditor",
            non_delegate_grant(FederationGrantRole::Auditor, FederationGrantPreset::Audit),
        ),
        // One hop, not a chain.
        ("delegate", delegate),
    ] {
        let err = FederationGrant::attenuated_delegate(
            &parent,
            delegate_member_ref(),
            DELEGATE_NOW,
            DELEGATE_EXPIRES_AT,
        )
        .expect_err(case);
        assert_eq!(
            err.kind(),
            ErrorKind::InvalidFederationGrantBody,
            "{case}: wrong error"
        );
    }
}

/// Done-means 3 + 11: Delegate is a 1:1 role/preset pair. No other preset
/// carries the role — including Owner, which is otherwise universal.
#[test]
fn delegate_is_a_one_to_one_role_preset_pair() {
    let non_delegate_presets = [
        FederationGrantPreset::Owner,
        FederationGrantPreset::Admin,
        FederationGrantPreset::Member,
        FederationGrantPreset::ReadOnly,
        FederationGrantPreset::Audit,
    ];
    let non_delegate_roles = [
        FederationGrantRole::Owner,
        FederationGrantRole::Admin,
        FederationGrantRole::Member,
        FederationGrantRole::Viewer,
        FederationGrantRole::Auditor,
    ];

    for preset in non_delegate_presets {
        assert!(
            !preset.permits_role(FederationGrantRole::Delegate),
            "{preset:?} must not carry the delegate role"
        );
        let mut body = valid_delegate_entries();
        for (key, value) in &mut body {
            if key.as_str() == Some(KEY_PRESET) {
                *value = Value::from(preset.as_str());
            }
        }
        assert_grant_rejected(preset.as_str(), &grant_map(body));
    }

    for role in non_delegate_roles {
        assert!(
            !FederationGrantPreset::Delegate.permits_role(role),
            "the delegate preset must not carry {role:?}"
        );
    }
    assert!(FederationGrantPreset::Delegate.permits_role(FederationGrantRole::Delegate));

    // Every pre-existing role/preset verdict is unchanged.
    for preset in non_delegate_presets {
        for role in non_delegate_roles {
            let expected = match preset {
                FederationGrantPreset::Owner => true,
                FederationGrantPreset::Admin => !matches!(role, FederationGrantRole::Owner),
                FederationGrantPreset::Member => matches!(
                    role,
                    FederationGrantRole::Member
                        | FederationGrantRole::Viewer
                        | FederationGrantRole::Auditor
                ),
                FederationGrantPreset::ReadOnly => matches!(
                    role,
                    FederationGrantRole::Viewer | FederationGrantRole::Auditor
                ),
                FederationGrantPreset::Audit => matches!(role, FederationGrantRole::Auditor),
                FederationGrantPreset::Delegate => unreachable!("non-delegate presets only"),
            };
            assert_eq!(
                preset.permits_role(role),
                expected,
                "{preset:?}/{role:?}: pre-existing verdict moved"
            );
        }
    }
}

/// Done-means 4 + 8: `expires_at`/`delegated_by` are role-conditional, and the
/// four-argument constructor cannot produce a delegate.
#[test]
fn role_conditional_fields_are_required_and_forbidden() {
    // Done-means 8: `new` keeps its four-argument signature, sets both option
    // fields to None, and a delegate built through it fails validation.
    let through_new = non_delegate_grant(
        FederationGrantRole::Delegate,
        FederationGrantPreset::Delegate,
    );
    assert_eq!(through_new.expires_at, None);
    assert_eq!(through_new.delegated_by, None);
    let err = through_new
        .validate()
        .expect_err("`new` cannot mint a delegate");
    assert_eq!(err.kind(), ErrorKind::InvalidFederationGrantBody);
    assert!(encode_federation_grant_body(&through_new).is_err());

    // Done-means 4: existing five-key bodies decode unchanged, reject either
    // new key, and confer at any age.
    for (case, role, preset) in [
        (
            "owner",
            FederationGrantRole::Owner,
            FederationGrantPreset::Owner,
        ),
        (
            "admin",
            FederationGrantRole::Admin,
            FederationGrantPreset::Admin,
        ),
        (
            "member",
            FederationGrantRole::Member,
            FederationGrantPreset::Member,
        ),
        (
            "viewer",
            FederationGrantRole::Viewer,
            FederationGrantPreset::ReadOnly,
        ),
        (
            "auditor",
            FederationGrantRole::Auditor,
            FederationGrantPreset::Audit,
        ),
    ] {
        let grant = non_delegate_grant(role, preset);
        let encoded = encode_federation_grant_body(&grant).expect(case);
        assert_eq!(decode_federation_grant_body(&encoded).expect(case), grant);
        assert!(
            grant.confers_at(0) && grant.confers_at(u64::MAX),
            "{case}: a non-delegate confers regardless of age"
        );

        let mut with_expiry = valid_entries();
        let mut with_parent = valid_entries();
        for (key, value) in with_expiry.iter_mut().chain(with_parent.iter_mut()) {
            match key.as_str() {
                Some(KEY_ROLE) => *value = Value::from(role.as_str()),
                Some(KEY_PRESET) => *value = Value::from(preset.as_str()),
                _ => {}
            }
        }
        with_expiry.push((
            Value::from(KEY_EXPIRES_AT),
            Value::from(DELEGATE_EXPIRES_AT),
        ));
        with_parent.push((
            Value::from(KEY_DELEGATED_BY),
            Value::from(member_ref().to_hex()),
        ));
        assert_grant_rejected(&format!("{case} with expires_at"), &grant_map(with_expiry));
        assert_grant_rejected(
            &format!("{case} with delegated_by"),
            &grant_map(with_parent),
        );
    }

    // A delegate missing either key is not a delegate.
    for key in [KEY_EXPIRES_AT, KEY_DELEGATED_BY] {
        let mut body = valid_delegate_entries();
        body.retain(|(candidate, _)| candidate.as_str() != Some(key));
        assert_grant_rejected(&format!("delegate missing {key}"), &grant_map(body));
    }
}

/// Done-means 2 (the predicate half) and 12: expiry is a `<` test against the
/// stored second, so the expiry second itself denies.
#[test]
fn confers_at_denies_from_the_expiry_second_onward() {
    let delegate = test_delegate();
    assert!(delegate.confers_at(DELEGATE_EXPIRES_AT - 1));
    assert!(
        !delegate.confers_at(DELEGATE_EXPIRES_AT),
        "the expiry second itself must deny"
    );
    assert!(!delegate.confers_at(DELEGATE_EXPIRES_AT + 1));
    assert!(!delegate.confers_at(u64::MAX));
    assert!(delegate.confers_at(0));
}

/// Done-means 7: the two new keys are typed as strictly as the old five.
#[test]
fn delegate_body_decode_fails_closed_on_new_keys() {
    let mutate = |key: &'static str, value: Value| {
        let mut body = valid_delegate_entries();
        for (candidate, slot) in &mut body {
            if candidate.as_str() == Some(key) {
                *slot = value.clone();
            }
        }
        grant_map(body)
    };
    let mut duplicate_expiry = valid_delegate_entries();
    duplicate_expiry.push((
        Value::from(KEY_EXPIRES_AT),
        Value::from(DELEGATE_EXPIRES_AT),
    ));
    let mut unknown_key = valid_delegate_entries();
    unknown_key.push((Value::from("renewed_at"), Value::from(1_u64)));

    for (case, bytes) in [
        ("zero expiry", mutate(KEY_EXPIRES_AT, Value::from(0_u64))),
        (
            "negative expiry",
            mutate(KEY_EXPIRES_AT, Value::from(-1_i64)),
        ),
        (
            "string expiry",
            mutate(KEY_EXPIRES_AT, Value::from("1700003600")),
        ),
        (
            "float expiry",
            mutate(KEY_EXPIRES_AT, Value::from(1.700_003_6_f64)),
        ),
        ("nil expiry", mutate(KEY_EXPIRES_AT, Value::Nil)),
        // `EntityId::from_hex` is case-insensitive, so the canonical-spelling
        // check is what rejects this — the bytes themselves are valid.
        (
            "uppercase parent hex",
            mutate(
                KEY_DELEGATED_BY,
                Value::from(
                    EntityId::from_bytes([0xab; 16])
                        .unwrap()
                        .to_hex()
                        .to_uppercase(),
                ),
            ),
        ),
        (
            "short parent hex",
            mutate(KEY_DELEGATED_BY, Value::from("62626262")),
        ),
        (
            "binary parent",
            mutate(
                KEY_DELEGATED_BY,
                Value::Binary(member_ref().as_bytes().to_vec()),
            ),
        ),
        ("duplicate expiry", grant_map(duplicate_expiry)),
        ("unknown key", grant_map(unknown_key)),
    ] {
        assert_grant_rejected(case, &bytes);
    }

    // The canonical hand-built body still decodes, so each case above failed
    // for its own reason and not because the fixture is broken.
    decode_federation_grant_body(&grant_map(valid_delegate_entries()))
        .expect("the canonical delegate body decodes");
}

/// Done-means 5 (forward compatibility) + 9 (hydration does not grow).
///
/// Schema version stays 1 while the on-disk body grows to seven keys. There is
/// no runtime assertion to make against a binary that no longer exists, so what
/// is pinned here is the property that makes the old reader safe: a
/// pre-Delegate reader's key allowlist is exactly the five-key head, and a
/// delegate body carries keys outside it — so that reader FAILS CLOSED rather
/// than reading a delegate as a non-expiring grant.
#[test]
fn delegate_body_grows_while_schema_version_and_hydration_hold() -> Result<()> {
    assert_eq!(FEDERATION_GRANT_SCHEMA_VERSION, 1);
    assert_eq!(FEDERATION_GRANT_BODY_KEYS.len(), 7);

    // Hydration profiles keep their pre-Delegate content and lengths.
    assert_eq!(FEDERATION_GRANT_FIELDS_MINIMAL, ["scope", "role", "preset"]);
    assert_eq!(
        FEDERATION_GRANT_FIELDS_STANDARD,
        ["scope", "member_ref", "role", "preset"]
    );
    assert_eq!(
        FEDERATION_GRANT_FIELDS_FULL,
        ["schema_version", "scope", "member_ref", "role", "preset"]
    );
    for key in [KEY_EXPIRES_AT, KEY_DELEGATED_BY] {
        assert!(
            !FEDERATION_GRANT_FIELDS_FULL.contains(&key),
            "{key} must not enter context-pack hydration"
        );
    }

    let legacy_keys = &FEDERATION_GRANT_BODY_KEYS[..5];
    let encoded = encode_federation_grant_body(&test_delegate())?;
    let mut cursor = Cursor::new(&encoded);
    let Value::Map(entries) = rmpv::decode::read_value(&mut cursor).expect("decode delegate body")
    else {
        panic!("delegate body must encode as a map");
    };
    let outside_legacy = entries
        .iter()
        .filter(|(key, _)| !legacy_keys.contains(&key.as_str().expect("string key")))
        .count();
    assert_eq!(
        outside_legacy, 2,
        "a five-key reader's allowlist rejects the delegate body"
    );

    // The same reader sees no new key on a non-delegate body, so pre-Delegate
    // grants keep round-tripping through it untouched.
    let non_delegate = encode_federation_grant_body(&test_grant())?;
    let mut cursor = Cursor::new(&non_delegate);
    let Value::Map(entries) = rmpv::decode::read_value(&mut cursor).expect("decode grant body")
    else {
        panic!("grant body must encode as a map");
    };
    assert!(
        entries
            .iter()
            .all(|(key, _)| legacy_keys.contains(&key.as_str().expect("string key"))),
        "a non-delegate body must stay inside the five-key set"
    );
    Ok(())
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

fn scope_entity(byte: u8) -> EntityId {
    crate::test_util::entity(byte)
}

fn direction(
    worlds: FederationScopeWorlds,
    facets: FederationScopeFacets,
    bands: FederationScopeBands,
) -> FederationDirectionScope {
    FederationDirectionScope {
        worlds,
        facets,
        bands,
    }
}

fn sample_pact_scope() -> FederationPactScope {
    FederationPactScope {
        lo_to_hi: direction(
            FederationScopeWorlds::Worlds(vec![scope_entity(0x10), scope_entity(0x12)]),
            FederationScopeFacets::Some(vec![scope_entity(0x21), scope_entity(0x22)]),
            FederationScopeBands::Some(vec![SelectorRange::Semantic, SelectorRange::Core]),
        ),
        hi_to_lo: direction(
            FederationScopeWorlds::Base,
            FederationScopeFacets::All,
            FederationScopeBands::Bottom,
        ),
    }
}

#[test]
fn federation_pact_scope_codec_round_trips_every_axis_kind() -> Result<()> {
    let scope = sample_pact_scope();
    let encoded = encode_federation_pact_scope(&scope)?;
    assert_eq!(decode_federation_pact_scope(&encoded)?, scope);
    Ok(())
}

#[test]
fn federation_pact_scope_decode_fails_closed() {
    let scope = sample_pact_scope();
    let canonical = encode_federation_pact_scope(&scope).unwrap();

    let mut trailing = canonical;
    trailing.push(0xc0);
    assert!(decode_federation_pact_scope(&trailing).is_err());
    assert!(decode_federation_pact_scope(b"not-msgpack").is_err());

    let axis = |kind: &str, ids: Option<Vec<Value>>| {
        let mut entries = vec![(Value::from("kind"), Value::from(kind))];
        if let Some(ids) = ids {
            entries.push((Value::from("ids"), Value::Array(ids)));
        }
        Value::Map(entries)
    };
    let direction_value = |worlds: Value, facets: Value, bands: Value| {
        Value::Map(vec![
            (Value::from("worlds"), worlds),
            (Value::from("facets"), facets),
            (Value::from("bands"), bands),
        ])
    };
    let all = || axis("all", None);
    let pact_value = |lo: Value, hi: Value| {
        encode_value(&Value::Map(vec![
            (
                Value::from("schema_version"),
                Value::from(FEDERATION_PACT_SCOPE_SCHEMA_VERSION),
            ),
            (Value::from("lo_to_hi"), lo),
            (Value::from("hi_to_lo"), hi),
        ]))
    };
    let hex = |byte: u8| Value::from(scope_entity(byte).to_hex());

    // An empty id set must NEVER decode as "all facets"/"all bands"/"all
    // worlds" — the bottom is a distinct wire kind (ARCH-0022).
    let empty_some = pact_value(
        direction_value(all(), axis("some", Some(vec![])), all()),
        direction_value(all(), all(), all()),
    );
    let empty_worlds = pact_value(
        direction_value(axis("worlds", Some(vec![])), all(), all()),
        direction_value(all(), all(), all()),
    );
    let unsorted_ids = pact_value(
        direction_value(all(), axis("some", Some(vec![hex(0x22), hex(0x21)])), all()),
        direction_value(all(), all(), all()),
    );
    let duplicate_ids = pact_value(
        direction_value(all(), axis("some", Some(vec![hex(0x21), hex(0x21)])), all()),
        direction_value(all(), all(), all()),
    );
    let foreign_world = pact_value(
        direction_value(axis("worlds", Some(vec![hex(0xF1)])), all(), all()),
        direction_value(all(), all(), all()),
    );
    let unknown_axis_kind = pact_value(
        direction_value(all(), axis("everything", None), all()),
        direction_value(all(), all(), all()),
    );
    let ids_on_all = pact_value(
        direction_value(all(), axis("all", Some(vec![hex(0x21)])), all()),
        direction_value(all(), all(), all()),
    );
    let ids_on_bottom = pact_value(
        direction_value(all(), axis("bottom", Some(vec![hex(0x21)])), all()),
        direction_value(all(), all(), all()),
    );
    let missing_ids_on_some = pact_value(
        direction_value(all(), axis("some", None), all()),
        direction_value(all(), all(), all()),
    );
    let unordered_bands = pact_value(
        direction_value(
            all(),
            all(),
            axis(
                "some",
                Some(vec![Value::from("core"), Value::from("semantic")]),
            ),
        ),
        direction_value(all(), all(), all()),
    );
    let unknown_band = pact_value(
        direction_value(
            all(),
            all(),
            axis("some", Some(vec![Value::from("everything")])),
        ),
        direction_value(all(), all(), all()),
    );
    let bad_version = encode_value(&Value::Map(vec![
        (Value::from("schema_version"), Value::from(2_u64)),
        (
            Value::from("lo_to_hi"),
            direction_value(all(), all(), all()),
        ),
        (
            Value::from("hi_to_lo"),
            direction_value(all(), all(), all()),
        ),
    ]));
    let unknown_top_key = encode_value(&Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(FEDERATION_PACT_SCOPE_SCHEMA_VERSION),
        ),
        (
            Value::from("lo_to_hi"),
            direction_value(all(), all(), all()),
        ),
        (
            Value::from("hi_to_lo"),
            direction_value(all(), all(), all()),
        ),
        (Value::from("future"), Value::from("permit")),
    ]));

    for (case, bytes) in [
        ("empty some", empty_some),
        ("empty worlds", empty_worlds),
        ("unsorted ids", unsorted_ids),
        ("duplicate ids", duplicate_ids),
        ("foreign world", foreign_world),
        ("unknown axis kind", unknown_axis_kind),
        ("ids on all", ids_on_all),
        ("ids on bottom", ids_on_bottom),
        ("missing ids on some", missing_ids_on_some),
        ("unordered bands", unordered_bands),
        ("unknown band", unknown_band),
        ("bad version", bad_version),
        ("unknown top key", unknown_top_key),
    ] {
        let err = match decode_federation_pact_scope(&bytes) {
            Ok(decoded) => panic!("{case}: malformed pact scope decoded as {decoded:?}"),
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
fn federation_direction_scope_partial_order_is_axis_wise() {
    let all = direction(
        FederationScopeWorlds::All,
        FederationScopeFacets::All,
        FederationScopeBands::All,
    );
    let narrow = direction(
        FederationScopeWorlds::Worlds(vec![scope_entity(0x10)]),
        FederationScopeFacets::Some(vec![scope_entity(0x21)]),
        FederationScopeBands::Some(vec![SelectorRange::Semantic]),
    );
    let bottom = direction(
        FederationScopeWorlds::Base,
        FederationScopeFacets::Bottom,
        FederationScopeBands::Bottom,
    );

    assert!(narrow.is_narrowing_of(&all));
    assert!(!all.is_narrowing_of(&narrow));
    assert!(bottom.is_narrowing_of(&narrow));
    assert!(!narrow.is_narrowing_of(&bottom));
    assert!(all.is_narrowing_of(&all));
    assert!(bottom.is_narrowing_of(&bottom));

    // Worlds: Base ⊑ Worlds(S) ⊑ Worlds(T ⊇ S) ⊑ All.
    let one_world = FederationScopeWorlds::Worlds(vec![scope_entity(0x10)]);
    let two_worlds = FederationScopeWorlds::Worlds(vec![scope_entity(0x10), scope_entity(0x12)]);
    assert!(FederationScopeWorlds::Base.is_narrowing_of(&one_world));
    assert!(one_world.is_narrowing_of(&two_worlds));
    assert!(!two_worlds.is_narrowing_of(&one_world));
    assert!(!FederationScopeWorlds::All.is_narrowing_of(&two_worlds));
    assert!(!one_world.is_narrowing_of(&FederationScopeWorlds::Base));
}

#[test]
fn federation_direction_scope_disjoint_meet_is_bottom_not_all() {
    let left = direction(
        FederationScopeWorlds::Worlds(vec![scope_entity(0x10)]),
        FederationScopeFacets::Some(vec![scope_entity(0x21), scope_entity(0x22)]),
        FederationScopeBands::Some(vec![SelectorRange::Semantic]),
    );
    let right = direction(
        FederationScopeWorlds::Worlds(vec![scope_entity(0x12)]),
        FederationScopeFacets::Some(vec![scope_entity(0x22), scope_entity(0x23)]),
        FederationScopeBands::Some(vec![SelectorRange::Core]),
    );

    let met = left.intersect(&right);
    // Disjoint worlds meet at Base (worlds always include base reality);
    // disjoint facet/band sets meet at the kind-tagged ⊥ — NEVER at ⊤.
    assert_eq!(met.worlds, FederationScopeWorlds::Base);
    assert_eq!(
        met.facets,
        FederationScopeFacets::Some(vec![scope_entity(0x22)])
    );
    assert_eq!(met.bands, FederationScopeBands::Bottom);
    assert_eq!(met, right.intersect(&left));

    let all = direction(
        FederationScopeWorlds::All,
        FederationScopeFacets::All,
        FederationScopeBands::All,
    );
    assert_eq!(all.intersect(&left), left);
    assert_eq!(left.intersect(&left), left);

    let bottom = direction(
        FederationScopeWorlds::Base,
        FederationScopeFacets::Bottom,
        FederationScopeBands::Bottom,
    );
    assert_eq!(
        bottom.intersect(&left).facets,
        FederationScopeFacets::Bottom
    );
    assert_eq!(bottom.intersect(&left).bands, FederationScopeBands::Bottom);
}

#[test]
fn federation_grant_type_registration_is_stable() {
    let entry = entity_type_registry_entry(ENTITY_TYPE_FEDERATION_GRANT)
        .expect("FEDERATION_GRANT registry row");

    assert_eq!(ENTITY_TYPE_FEDERATION_GRANT, 68);
    assert_eq!(entry.kind, "FEDERATION_GRANT");
    assert_eq!(entry.short_id_prefix, None);
    assert_eq!(entry.classification, EntityClassification::Maintenance);
    assert_eq!(entry.zone, TypeByteZone::System);
}

// ── ONE-1412 [FED-05]: relationship-tagged membership ────────────────────────

const MEMBER_SEED: u8 = 0x71;
/// Hex letters are LOAD-BEARING here: the canonical-spelling test uppercases
/// this id's hex, and a digits-only seed (`0x72` → `"7272…"`) would make that
/// a no-op and silently pass. Any replacement seed must keep a hex letter.
const PERSON_SEED: u8 = 0xBC;
const SELF_BOUND_SEED: u8 = 0x73;
const GHOST_PERSON_SEED: u8 = 0x74;

fn relationship_time() -> TimeRange {
    TimeRange { start: 1, end: 1 }
}

/// Vault holding the PERSON entities these tests bind. `GHOST_PERSON_SEED` is
/// deliberately NOT stored — it is the nonexistent-person fixture.
fn relationship_vault() -> (tempfile::TempDir, Vault) {
    let (dir, vault) = open_test_vault_with(VaultConfig::device());
    for seed in [MEMBER_SEED, PERSON_SEED, SELF_BOUND_SEED] {
        vault
            .put_entity(
                &entity(seed),
                ENTITY_TYPE_PERSON,
                relationship_time(),
                1,
                b"person",
            )
            .expect("put relationship fixture person");
    }
    (dir, vault)
}

/// A relationship claim written at an EXPLICIT id and learned_at.
///
/// The writer sugar mints ids with `EntityId::now()`, which is only
/// millisecond-ordered — a precedence test asserting the id-descending
/// tiebreak has to pin both axes itself.
struct RelationshipClaimFixture {
    id: EntityId,
    predicate: &'static str,
    subject: EntityId,
    value: Value,
    approval: ClaimApprovalStatus,
    lifecycle: ClaimLifecycleStatus,
    learned_at: u64,
}

impl RelationshipClaimFixture {
    fn person_ref(id_seed: u8, member: EntityId, person: EntityId) -> Self {
        Self {
            id: entity(id_seed),
            predicate: PREDICATE_RELATIONSHIP_PERSON_REF,
            subject: member,
            value: Value::from(person.to_hex()),
            approval: ClaimApprovalStatus::Approved,
            lifecycle: ClaimLifecycleStatus::Active,
            learned_at: 1,
        }
    }

    fn label(id_seed: u8, person: EntityId, label: &str) -> Self {
        Self {
            id: entity(id_seed),
            predicate: PREDICATE_RELATIONSHIP_LABEL,
            subject: person,
            value: Value::from(label),
            approval: ClaimApprovalStatus::Auto,
            lifecycle: ClaimLifecycleStatus::Active,
            learned_at: 1,
        }
    }

    fn predicate(mut self, predicate: &'static str) -> Self {
        self.predicate = predicate;
        self
    }

    fn value(mut self, value: Value) -> Self {
        self.value = value;
        self
    }

    fn approval(mut self, approval: ClaimApprovalStatus) -> Self {
        self.approval = approval;
        self
    }

    fn lifecycle(mut self, lifecycle: ClaimLifecycleStatus) -> Self {
        self.lifecycle = lifecycle;
        self
    }

    fn learned_at(mut self, learned_at: u64) -> Self {
        self.learned_at = learned_at;
        self
    }

    fn store(self, vault: &Vault) -> EntityId {
        vault
            .put_claim(
                &self.id,
                &ClaimBody::new(
                    self.predicate,
                    ClaimSubject::Entity(self.subject),
                    self.value,
                    1.0,
                    self.approval,
                    self.lifecycle,
                ),
                relationship_time(),
                self.learned_at,
            )
            .expect("store relationship claim fixture");
        self.id
    }
}

fn labeled(relationship: MemberRelationship) -> MemberRelationshipContext {
    match relationship {
        MemberRelationship::Labeled(context) => context,
        other => panic!("expected a labeled relationship, got {other:?}"),
    }
}

#[test]
fn member_relationship_binds_a_person_and_reports_unbound_without_one() -> Result<()> {
    let (_dir, vault) = relationship_vault();
    let member = entity(MEMBER_SEED);
    let person = entity(PERSON_SEED);

    assert_eq!(
        resolve_member_relationship(&vault, member)?,
        MemberRelationship::Unbound
    );

    bind_member_person(&vault, member, person, relationship_time(), 1)?;
    assert_eq!(
        resolve_member_relationship(&vault, member)?,
        MemberRelationship::Unlabeled { person }
    );

    // A member may BE the person: self-binding is legal, not a cycle.
    let solo = entity(SELF_BOUND_SEED);
    bind_member_person(&vault, solo, solo, relationship_time(), 1)?;
    assert_eq!(
        resolve_member_relationship(&vault, solo)?,
        MemberRelationship::Unlabeled { person: solo }
    );
    Ok(())
}

#[test]
fn member_relationship_label_prefers_approved_then_newest() -> Result<()> {
    let (_dir, vault) = relationship_vault();
    let member = entity(MEMBER_SEED);
    let person = entity(PERSON_SEED);
    RelationshipClaimFixture::person_ref(0x80, member, person).store(&vault);

    let client = RelationshipClaimFixture::label(0x81, person, "client")
        .learned_at(10)
        .store(&vault);
    let context = labeled(resolve_member_relationship(&vault, member)?);
    assert_eq!(context.person, person);
    assert_eq!(context.label, "client");
    assert_eq!(context.label_claim, client);
    assert_eq!(context.trust_class, RelationshipTrustClass::Client);

    // A newer Auto beats an older Auto.
    let girlfriend = RelationshipClaimFixture::label(0x82, person, "girlfriend")
        .learned_at(20)
        .store(&vault);
    let context = labeled(resolve_member_relationship(&vault, member)?);
    assert_eq!(context.label, "girlfriend");
    assert_eq!(context.label_claim, girlfriend);
    assert_eq!(context.trust_class, RelationshipTrustClass::Intimate);

    // An OLDER Approved beats every Auto — approval outranks age.
    let coworker = RelationshipClaimFixture::label(0x83, person, "coworker")
        .approval(ClaimApprovalStatus::Approved)
        .learned_at(5)
        .store(&vault);
    let context = labeled(resolve_member_relationship(&vault, member)?);
    assert_eq!(context.label, "coworker");
    assert_eq!(context.label_claim, coworker);
    assert_eq!(context.trust_class, RelationshipTrustClass::Professional);
    Ok(())
}

#[test]
fn member_relationship_person_ref_takes_the_newest_then_highest_id() -> Result<()> {
    let (_dir, vault) = relationship_vault();
    let member = entity(MEMBER_SEED);
    let person = entity(PERSON_SEED);
    let other = entity(SELF_BOUND_SEED);

    // Approval does NOT order the person-ref contest: the newer Auto wins over
    // the older Approved, unlike the label axis above.
    RelationshipClaimFixture::person_ref(0x80, member, other)
        .learned_at(20)
        .store(&vault);
    RelationshipClaimFixture::person_ref(0x81, member, person)
        .approval(ClaimApprovalStatus::Auto)
        .learned_at(30)
        .store(&vault);
    assert_eq!(
        resolve_member_relationship(&vault, member)?,
        MemberRelationship::Unlabeled { person }
    );

    // Same learned_at: the higher claim id wins.
    RelationshipClaimFixture::person_ref(0x82, member, other)
        .learned_at(30)
        .store(&vault);
    assert!(entity(0x82) > entity(0x81));
    assert_eq!(
        resolve_member_relationship(&vault, member)?,
        MemberRelationship::Unlabeled { person: other }
    );
    Ok(())
}

#[test]
fn relationship_trust_tier_and_band_tables_are_fixed() {
    for label in [
        "girlfriend",
        "boyfriend",
        "partner",
        "wife",
        "husband",
        "spouse",
    ] {
        assert_eq!(
            relationship_trust_class(label),
            RelationshipTrustClass::Intimate,
            "{label}"
        );
    }
    for label in [
        "mother", "father", "mom", "dad", "parent", "brother", "sister", "sibling", "son",
        "daughter", "family",
    ] {
        assert_eq!(
            relationship_trust_class(label),
            RelationshipTrustClass::Family,
            "{label}"
        );
    }
    for label in ["friend", "roommate"] {
        assert_eq!(
            relationship_trust_class(label),
            RelationshipTrustClass::Friend,
            "{label}"
        );
    }
    for label in [
        "coworker",
        "colleague",
        "manager",
        "report",
        "boss",
        "teammate",
    ] {
        assert_eq!(
            relationship_trust_class(label),
            RelationshipTrustClass::Professional,
            "{label}"
        );
    }
    for label in ["client", "customer", "vendor", "contractor"] {
        assert_eq!(
            relationship_trust_class(label),
            RelationshipTrustClass::Client,
            "{label}"
        );
    }
    // No synonym model and no folding: a near-miss is not a near-match.
    for label in ["girlfriends", "step_mother", "ex_wife", "acquaintance_xyz"] {
        assert_eq!(
            relationship_trust_class(label),
            RelationshipTrustClass::Unlabeled,
            "{label}"
        );
    }

    assert_eq!(default_trust_tier(RelationshipTrustClass::Intimate), 3);
    assert_eq!(default_trust_tier(RelationshipTrustClass::Family), 3);
    assert_eq!(default_trust_tier(RelationshipTrustClass::Friend), 2);
    assert_eq!(default_trust_tier(RelationshipTrustClass::Professional), 1);
    assert_eq!(default_trust_tier(RelationshipTrustClass::Client), 1);
    assert_eq!(default_trust_tier(RelationshipTrustClass::Unlabeled), 0);

    assert_eq!(
        default_retrieval_bands(RelationshipTrustClass::Intimate),
        vec![
            SelectorRange::Semantic,
            SelectorRange::Core,
            SelectorRange::Companion
        ]
    );
    assert_eq!(
        default_retrieval_bands(RelationshipTrustClass::Family),
        vec![
            SelectorRange::Semantic,
            SelectorRange::Core,
            SelectorRange::Companion
        ]
    );
    assert_eq!(
        default_retrieval_bands(RelationshipTrustClass::Friend),
        vec![SelectorRange::Semantic, SelectorRange::Core]
    );
    assert_eq!(
        default_retrieval_bands(RelationshipTrustClass::Professional),
        vec![
            SelectorRange::Semantic,
            SelectorRange::Core,
            SelectorRange::Productivity
        ]
    );
    assert_eq!(
        default_retrieval_bands(RelationshipTrustClass::Client),
        vec![
            SelectorRange::Semantic,
            SelectorRange::Crm,
            SelectorRange::Productivity
        ]
    );
    assert_eq!(
        default_retrieval_bands(RelationshipTrustClass::Unlabeled),
        vec![SelectorRange::Semantic]
    );

    // Client and Intimate are visibly different defaults, not a shared blob:
    // a client reaches Crm and never Core or Companion.
    assert_ne!(
        default_trust_tier(RelationshipTrustClass::Client),
        default_trust_tier(RelationshipTrustClass::Intimate)
    );
    let client_bands = default_retrieval_bands(RelationshipTrustClass::Client);
    assert!(client_bands.contains(&SelectorRange::Crm));
    assert!(!client_bands.contains(&SelectorRange::Core));
    assert!(!client_bands.contains(&SelectorRange::Companion));
}

#[test]
fn unknown_labels_stay_unlabeled_class_and_closed_claims_never_win() -> Result<()> {
    let (_dir, vault) = relationship_vault();
    let member = entity(MEMBER_SEED);
    let person = entity(PERSON_SEED);
    RelationshipClaimFixture::person_ref(0x80, member, person).store(&vault);

    let unknown = RelationshipClaimFixture::label(0x81, person, "acquaintance_xyz").store(&vault);
    let context = labeled(resolve_member_relationship(&vault, member)?);
    assert_eq!(context.label, "acquaintance_xyz");
    assert_eq!(context.label_claim, unknown);
    assert_eq!(context.trust_class, RelationshipTrustClass::Unlabeled);
    assert_eq!(default_trust_tier(context.trust_class), 0);
    assert_eq!(
        default_retrieval_bands(context.trust_class),
        vec![SelectorRange::Semantic]
    );

    // Every closed status loses to the one valid label, however much newer.
    for (seed, approval, lifecycle) in [
        (
            0x82,
            ClaimApprovalStatus::Rejected,
            ClaimLifecycleStatus::Active,
        ),
        (
            0x83,
            ClaimApprovalStatus::Proposed,
            ClaimLifecycleStatus::Active,
        ),
        (
            0x84,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Retracted,
        ),
        (
            0x85,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Superseded,
        ),
    ] {
        RelationshipClaimFixture::label(seed, person, "girlfriend")
            .approval(approval)
            .lifecycle(lifecycle)
            .learned_at(99)
            .store(&vault);
    }
    let context = labeled(resolve_member_relationship(&vault, member)?);
    assert_eq!(context.label_claim, unknown);
    assert_eq!(context.trust_class, RelationshipTrustClass::Unlabeled);

    // The same closed statuses on the person-ref axis leave the member Unbound.
    let (_other_dir, other_vault) = relationship_vault();
    for (seed, approval, lifecycle) in [
        (
            0x86,
            ClaimApprovalStatus::Rejected,
            ClaimLifecycleStatus::Active,
        ),
        (
            0x87,
            ClaimApprovalStatus::Proposed,
            ClaimLifecycleStatus::Active,
        ),
        (
            0x88,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Retracted,
        ),
    ] {
        RelationshipClaimFixture::person_ref(seed, member, person)
            .approval(approval)
            .lifecycle(lifecycle)
            .store(&other_vault);
    }
    assert_eq!(
        resolve_member_relationship(&other_vault, member)?,
        MemberRelationship::Unbound
    );
    Ok(())
}

#[test]
fn member_relationship_resolution_is_agent_independent() -> Result<()> {
    let (_dir, vault) = relationship_vault();
    let member = entity(MEMBER_SEED);
    let person = entity(PERSON_SEED);
    bind_member_person(&vault, member, person, relationship_time(), 1)?;
    put_member_relationship_label(
        &vault,
        person,
        "friend",
        ClaimApprovalStatus::Approved,
        relationship_time(),
        1,
    )?;

    // Two distinct agent lanes over one vault. The resolver takes no actor, so
    // neither lane can steer the answer.
    let agent_a = vault.scoped_read(ScopedReadActorKey::new("agent-a").expect("agent-a key"));
    let agent_b = vault.scoped_read(ScopedReadActorKey::new("agent-b").expect("agent-b key"));
    assert_ne!(
        agent_a.actor_key().actor_ref(),
        agent_b.actor_key().actor_ref()
    );

    let from_a = resolve_member_relationship(&vault, member)?;
    let from_b = resolve_member_relationship(&vault, member)?;
    assert_eq!(from_a, from_b);
    assert_eq!(labeled(from_a).trust_class, RelationshipTrustClass::Friend);
    Ok(())
}

#[test]
fn member_relationship_resolves_for_every_grant_role_including_delegate() -> Result<()> {
    let (_dir, vault) = relationship_vault();
    let member = entity(MEMBER_SEED);
    let person = entity(PERSON_SEED);
    bind_member_person(&vault, member, person, relationship_time(), 1)?;
    put_member_relationship_label(
        &vault,
        person,
        "manager",
        ClaimApprovalStatus::Auto,
        relationship_time(),
        1,
    )?;

    let scope = FederationGrantScope::vault(7);
    let parent = FederationGrant::new(
        scope,
        member_ref(),
        FederationGrantRole::Admin,
        FederationGrantPreset::Admin,
    );
    let mut grants = vec![
        FederationGrant::new(
            scope,
            member,
            FederationGrantRole::Owner,
            FederationGrantPreset::Owner,
        ),
        FederationGrant::new(
            scope,
            member,
            FederationGrantRole::Admin,
            FederationGrantPreset::Admin,
        ),
        FederationGrant::new(
            scope,
            member,
            FederationGrantRole::Member,
            FederationGrantPreset::Member,
        ),
        FederationGrant::new(
            scope,
            member,
            FederationGrantRole::Viewer,
            FederationGrantPreset::ReadOnly,
        ),
        FederationGrant::new(
            scope,
            member,
            FederationGrantRole::Auditor,
            FederationGrantPreset::Audit,
        ),
    ];
    grants.push(FederationGrant::attenuated_delegate(
        &parent, member, 100, 200,
    )?);

    // Exhaustive over the role enum, Delegate (ONE-1409) included.
    let covered: Vec<&str> = grants.iter().map(|grant| grant.role.as_str()).collect();
    assert_eq!(
        covered,
        ["owner", "admin", "member", "viewer", "auditor", "delegate"]
    );

    for grant in grants {
        grant.validate()?;
        let context = labeled(resolve_member_relationship(&vault, grant.member_ref)?);
        assert_eq!(context.person, person, "{}", grant.role.as_str());
        assert_eq!(
            context.trust_class,
            RelationshipTrustClass::Professional,
            "{}",
            grant.role.as_str()
        );
    }
    Ok(())
}

#[test]
fn malformed_relationship_claims_are_ignored_on_read() -> Result<()> {
    let (_dir, vault) = relationship_vault();
    let member = entity(MEMBER_SEED);
    let person = entity(PERSON_SEED);
    let hex = person.to_hex();
    // Guards the fixture, not the code: an all-digit id would make the
    // uppercase case below indistinguishable from the canonical one.
    assert_ne!(hex.to_uppercase(), hex);

    // Non-canonical, truncated, non-string, and wrong-predicate refs never bind.
    RelationshipClaimFixture::person_ref(0x80, member, person)
        .value(Value::from(hex.to_uppercase()))
        .store(&vault);
    RelationshipClaimFixture::person_ref(0x81, member, person)
        .value(Value::from(&hex[..30]))
        .store(&vault);
    RelationshipClaimFixture::person_ref(0x82, member, person)
        .value(Value::Binary(person.as_bytes().to_vec()))
        .store(&vault);
    RelationshipClaimFixture::person_ref(0x83, member, person)
        .predicate("core.relationship.person")
        .store(&vault);
    assert_eq!(
        resolve_member_relationship(&vault, member)?,
        MemberRelationship::Unbound
    );

    // With a canonical ref in place, off-grammar labels still lose.
    RelationshipClaimFixture::person_ref(0x84, member, person).store(&vault);
    for (seed, label) in [
        (0x85_u8, "Friend".to_owned()),
        (0x86, "co-worker".to_owned()),
        (0x87, "friend ".to_owned()),
        (0x88, "fri3nd".to_owned()),
        (0x89, String::new()),
        (0x8A, "a".repeat(MAX_RELATIONSHIP_LABEL_BYTES + 1)),
    ] {
        RelationshipClaimFixture::label(seed, person, &label)
            .learned_at(99)
            .store(&vault);
    }
    RelationshipClaimFixture::label(0x8B, person, "friend")
        .predicate("core.relationship.labels")
        .learned_at(99)
        .store(&vault);
    assert_eq!(
        resolve_member_relationship(&vault, member)?,
        MemberRelationship::Unlabeled { person }
    );

    // Exactly MAX_RELATIONSHIP_LABEL_BYTES is inside the grammar.
    let longest = "a".repeat(MAX_RELATIONSHIP_LABEL_BYTES);
    RelationshipClaimFixture::label(0x8C, person, &longest).store(&vault);
    let context = labeled(resolve_member_relationship(&vault, member)?);
    assert_eq!(context.label, longest);
    assert_eq!(context.trust_class, RelationshipTrustClass::Unlabeled);
    Ok(())
}

#[test]
fn bind_member_person_refuses_a_nonexistent_person_before_writing() -> Result<()> {
    let (_dir, vault) = relationship_vault();
    let member = entity(MEMBER_SEED);
    let ghost = entity(GHOST_PERSON_SEED);

    assert_eq!(
        bind_member_person(&vault, member, ghost, relationship_time(), 1)
            .expect_err("nonexistent person must be refused")
            .kind(),
        ErrorKind::EntityNotFound
    );
    // Refusal precedes the write: no claim landed on the member.
    assert!(vault.claims_for_subject(&member)?.is_empty());
    assert_eq!(
        resolve_member_relationship(&vault, member)?,
        MemberRelationship::Unbound
    );

    let person = entity(PERSON_SEED);
    let claim = bind_member_person(&vault, member, person, relationship_time(), 1)?;
    let body = vault.get_claim(&claim)?.expect("bound claim body");
    assert_eq!(body.predicate, PREDICATE_RELATIONSHIP_PERSON_REF);
    assert_eq!(body.subject, ClaimSubject::Entity(member));
    assert_eq!(body.value.as_str(), Some(person.to_hex().as_str()));
    assert_eq!(body.approval, ClaimApprovalStatus::Approved);
    assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
    Ok(())
}

#[test]
fn relationship_writer_sugar_refuses_malformed_input() -> Result<()> {
    let (_dir, vault) = relationship_vault();
    let person = entity(PERSON_SEED);
    let overlong = "a".repeat(MAX_RELATIONSHIP_LABEL_BYTES + 1);

    for label in ["Friend", "co-worker", "friend ", "fri3nd", "", &overlong] {
        assert_eq!(
            put_member_relationship_label(
                &vault,
                person,
                label,
                ClaimApprovalStatus::Approved,
                relationship_time(),
                1,
            )
            .expect_err("malformed label must be refused")
            .kind(),
            ErrorKind::InvalidClaimBody,
            "{label}"
        );
    }
    for approval in [ClaimApprovalStatus::Proposed, ClaimApprovalStatus::Rejected] {
        assert_eq!(
            put_member_relationship_label(
                &vault,
                person,
                "friend",
                approval,
                relationship_time(),
                1,
            )
            .expect_err("only Auto and Approved may be written")
            .kind(),
            ErrorKind::InvalidClaimBody
        );
    }
    assert!(vault.claims_for_subject(&person)?.is_empty());

    // Both accepted approvals ride the existing typed claim door, which is what
    // wires the `claim_of` edge `claims_for_subject` reads back.
    for approval in [ClaimApprovalStatus::Auto, ClaimApprovalStatus::Approved] {
        let claim = put_member_relationship_label(
            &vault,
            person,
            "friend",
            approval,
            relationship_time(),
            1,
        )?;
        let body = vault.get_claim(&claim)?.expect("label claim body");
        assert_eq!(body.predicate, PREDICATE_RELATIONSHIP_LABEL);
        assert_eq!(body.subject, ClaimSubject::Entity(person));
        assert_eq!(body.value.as_str(), Some("friend"));
        assert_eq!(body.approval, approval);
        assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
        assert!(vault.claims_for_subject(&person)?.contains(&claim));
    }

    // Neither predicate joins the registry: they are ordinary non-structural
    // predicates the generic claim door already accepts.
    assert!(!CLAIM_PREDICATE_REGISTRY.contains(&PREDICATE_RELATIONSHIP_PERSON_REF));
    assert!(!CLAIM_PREDICATE_REGISTRY.contains(&PREDICATE_RELATIONSHIP_LABEL));
    Ok(())
}

// ---------------------------------------------------------------------------
// FED-03 — peer authority-log admission and fold-derived peer rosters
// (ONE-1410)
// ---------------------------------------------------------------------------

use ed25519_dalek::{Signer, SigningKey};

use crate::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AuthorityAttestation, AuthorityEntryHash, AuthorityFoldIssue,
    AuthoritySignature, AuthorityTier, DeviceAuthority, FederationLifecycleAction,
    FederationLifecycleKind, FederationLifecycleRejection, FederationPactGesture, ROLE_ADMIN,
    ROLE_AGENT, ROLE_OWNER, authority_transcript, encode_authority_log_entry_body,
    federation_scope_digest, fold_authority_log_with_peer_consent_roots,
    sign_federation_pact_gesture,
};
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;

fn auth_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn auth_pub(key: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(key.verifying_key().to_bytes())
}

fn auth_device(key: AuthorityKey, roles: u16) -> DeviceAuthority {
    DeviceAuthority {
        key,
        transport_key_binding: [7; 32],
        attestation: AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier: AuthorityTier::Software,
        roles,
    }
}

fn auth_entry(
    vault_id: Option<AuthorityVaultId>,
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer: &SigningKey,
    cosigner: Option<&SigningKey>,
    ts: u64,
) -> AuthorityLogEntry {
    let signer_key = auth_pub(signer);
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id,
        seq,
        parent_hashes: parents,
        op,
        signer: AuthoritySignature {
            suite: signer_key.suite(),
            public_key: signer_key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts,
    };
    if let Some(cosigner) = cosigner {
        let cosign_key = auth_pub(cosigner);
        entry.cosigns.push(AuthoritySignature {
            suite: cosign_key.suite(),
            public_key: cosign_key,
            signature: vec![0; 64],
        });
    }
    let transcript = authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    if let Some(cosigner) = cosigner {
        entry.cosigns[0].signature = cosigner.sign(&transcript).to_bytes().to_vec();
    }
    entry
}

fn auth_genesis(seed: u8) -> AuthorityLogEntry {
    let signing = auth_key(seed);
    auth_entry(
        None,
        0,
        Vec::new(),
        AuthorityOp::Genesis {
            device: auth_device(auth_pub(&signing), ROLE_OWNER | ROLE_ADMIN),
            genesis_nonce: [seed.wrapping_add(10); 32],
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: 86_400,
        },
        &signing,
        None,
        1,
    )
}

/// A synthetic peer vault on the host-key premise: its genesis device is
/// owner/admin at a LAWFUL attestation tier (canon never stamps a host-root
/// genesis `ROLE_CLOUD`/`CloudCustodial`).
///
/// Chain: genesis(host) → enroll(admin) → enroll(agent) → enroll(spare) →
/// revoke(spare).
struct PeerVaultFixture {
    host: AuthorityKey,
    admin: AuthorityKey,
    agent: AuthorityKey,
    revoked: AuthorityKey,
    host_signing: SigningKey,
    admin_signing: SigningKey,
    agent_signing: SigningKey,
    revoked_signing: SigningKey,
    vault_id: AuthorityVaultId,
    entries: Vec<AuthorityLogEntry>,
}

impl PeerVaultFixture {
    fn bytes(&self) -> Vec<Vec<u8>> {
        self.entries
            .iter()
            .map(|entry| encode_authority_log_entry_body(entry).expect("canonical body"))
            .collect()
    }

    fn admit_all(&self, vault: &Vault) {
        for body in self.bytes() {
            admit_peer_authority_log_entry(vault, &self.vault_id, &body).expect("admit peer entry");
        }
    }

    fn consent_roots(&self) -> BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>> {
        BTreeMap::from([(
            self.vault_id,
            peer_consent_roots(&fold_peer_authority_log(&self.entries)),
        )])
    }
}

fn peer_vault_fixture(seed: u8) -> PeerVaultFixture {
    let host_signing = auth_key(seed);
    let admin_signing = auth_key(seed.wrapping_add(1));
    let agent_signing = auth_key(seed.wrapping_add(2));
    let revoked_signing = auth_key(seed.wrapping_add(3));

    let genesis = auth_genesis(seed);
    let vault_id = genesis_vault_id(&genesis).expect("genesis vault id");
    let genesis_hash = authority_entry_hash(&genesis).expect("genesis hash");

    let enroll_admin = auth_entry(
        Some(vault_id),
        1,
        vec![genesis_hash],
        AuthorityOp::EnrollDevice {
            device: auth_device(auth_pub(&admin_signing), ROLE_OWNER | ROLE_ADMIN),
        },
        &host_signing,
        None,
        2,
    );
    let enroll_agent = auth_entry(
        Some(vault_id),
        2,
        vec![authority_entry_hash(&enroll_admin).expect("hash")],
        AuthorityOp::EnrollDevice {
            device: auth_device(auth_pub(&agent_signing), ROLE_AGENT),
        },
        &host_signing,
        Some(&admin_signing),
        3,
    );
    let enroll_spare = auth_entry(
        Some(vault_id),
        3,
        vec![authority_entry_hash(&enroll_agent).expect("hash")],
        AuthorityOp::EnrollDevice {
            device: auth_device(auth_pub(&revoked_signing), ROLE_OWNER | ROLE_ADMIN),
        },
        &host_signing,
        Some(&admin_signing),
        4,
    );
    let revoke_spare = auth_entry(
        Some(vault_id),
        4,
        vec![authority_entry_hash(&enroll_spare).expect("hash")],
        AuthorityOp::RevokeDevice {
            revoked_key: auth_pub(&revoked_signing),
        },
        &host_signing,
        Some(&admin_signing),
        5,
    );

    PeerVaultFixture {
        host: auth_pub(&host_signing),
        admin: auth_pub(&admin_signing),
        agent: auth_pub(&agent_signing),
        revoked: auth_pub(&revoked_signing),
        host_signing,
        admin_signing,
        agent_signing,
        revoked_signing,
        vault_id,
        entries: vec![
            genesis,
            enroll_admin,
            enroll_agent,
            enroll_spare,
            revoke_spare,
        ],
    }
}

fn peer_scope() -> FederationPactScope {
    let half = FederationDirectionScope {
        worlds: FederationScopeWorlds::Base,
        facets: FederationScopeFacets::All,
        bands: FederationScopeBands::All,
    };
    FederationPactScope {
        lo_to_hi: half.clone(),
        hi_to_lo: half,
    }
}

/// A LOCAL vault that has connected to `peer`, pinning the peer ADMIN key at
/// Connect (TOFU). Later gestures signed by any OTHER peer key are the thing
/// under test.
struct LocalPactFixture {
    owner_signing: SigningKey,
    vault_id: AuthorityVaultId,
    peer_vault_id: AuthorityVaultId,
    pact_id: [u8; 32],
    grant_ref: EntityId,
    nonce: [u8; 16],
    scope: FederationPactScope,
    genesis: AuthorityLogEntry,
    connect: AuthorityLogEntry,
}

/// `grant_seed` is passed per call site rather than derived from `seed`: a
/// derived byte can drift into `PINNED_ID_BYTES` when the vault seed moves, and
/// the collision only surfaces as a panic in whichever test moved.
fn local_pact_fixture(seed: u8, grant_seed: u8, peer: &PeerVaultFixture) -> LocalPactFixture {
    let owner_signing = auth_key(seed);
    let genesis = auth_genesis(seed);
    let vault_id = genesis_vault_id(&genesis).expect("local vault id");
    let pact_id = [seed.wrapping_add(20); 32];
    let grant_ref = entity(grant_seed);
    let nonce = [seed.wrapping_add(22); 16];
    let scope = peer_scope();
    let digest = federation_scope_digest(
        &nonce,
        &encode_federation_pact_scope(&scope).expect("canonical scope"),
    );

    let connect = auth_entry(
        Some(vault_id),
        1,
        vec![authority_entry_hash(&genesis).expect("hash")],
        AuthorityOp::FederationLifecycle(FederationLifecycleAction {
            kind: FederationLifecycleKind::Connect,
            pact_id,
            grant_ref,
            peer_vault_id: peer.vault_id,
            pact_epoch: 1,
            pact_scope: Some(scope.clone()),
            effective_scope: None,
            scope_digest: Some(digest),
            gesture: Some(
                sign_federation_pact_gesture(
                    FederationLifecycleKind::Connect,
                    &pact_id,
                    &vault_id,
                    &peer.vault_id,
                    1,
                    &digest,
                    None,
                    &nonce,
                    peer.admin.clone(),
                    |transcript| Ok(peer.admin_signing.sign(transcript).to_bytes().to_vec()),
                )
                .expect("connect gesture"),
            ),
            successor_vault_id: None,
            pact_nonce: nonce,
        }),
        &owner_signing,
        None,
        2,
    );

    LocalPactFixture {
        owner_signing,
        vault_id,
        peer_vault_id: peer.vault_id,
        pact_id,
        grant_ref,
        nonce,
        scope,
        genesis,
        connect,
    }
}

/// Rescope-REPACT at epoch 2, dual-signed by `gesture_signer`.
fn repact_entry(fixture: &LocalPactFixture, gesture_signer: &SigningKey) -> AuthorityLogEntry {
    let digest = federation_scope_digest(
        &fixture.nonce,
        &encode_federation_pact_scope(&fixture.scope).expect("canonical scope"),
    );
    auth_entry(
        Some(fixture.vault_id),
        2,
        vec![authority_entry_hash(&fixture.connect).expect("hash")],
        AuthorityOp::FederationLifecycle(FederationLifecycleAction {
            kind: FederationLifecycleKind::Rescope,
            pact_id: fixture.pact_id,
            grant_ref: fixture.grant_ref,
            peer_vault_id: fixture.peer_vault_id,
            pact_epoch: 2,
            pact_scope: Some(fixture.scope.clone()),
            effective_scope: None,
            scope_digest: Some(digest),
            gesture: Some(
                sign_federation_pact_gesture(
                    FederationLifecycleKind::Rescope,
                    &fixture.pact_id,
                    &fixture.vault_id,
                    &fixture.peer_vault_id,
                    2,
                    &digest,
                    None,
                    &fixture.nonce,
                    auth_pub(gesture_signer),
                    |transcript| Ok(gesture_signer.sign(transcript).to_bytes().to_vec()),
                )
                .expect("repact gesture"),
            ),
            successor_vault_id: None,
            pact_nonce: fixture.nonce,
        }),
        &fixture.owner_signing,
        None,
        3,
    )
}

fn lifecycle_rejection_for(
    fold: &AuthorityFold,
    hash: AuthorityEntryHash,
) -> Option<FederationLifecycleRejection> {
    fold.issues.iter().find_map(|issue| match issue {
        AuthorityFoldIssue::FederationLifecycleRejected { entry, reason } if *entry == hash => {
            Some(*reason)
        }
        _ => None,
    })
}

/// Folds `[genesis, connect, repact]` with the given admitted peer roster in
/// scope and reports whether the repact was accepted.
fn repact_accepted(
    fixture: &LocalPactFixture,
    repact: &AuthorityLogEntry,
    peer_roots: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
) -> std::result::Result<(), FederationLifecycleRejection> {
    let fold = fold_authority_log_with_peer_consent_roots(
        &[
            fixture.genesis.clone(),
            fixture.connect.clone(),
            repact.clone(),
        ],
        &BTreeMap::new(),
        0,
        peer_roots,
    );
    let hash = authority_entry_hash(repact).expect("hash");
    match lifecycle_rejection_for(&fold, hash) {
        Some(reason) => Err(reason),
        None => {
            assert!(
                fold.valid_entries.contains(&hash),
                "an unrejected repact must fold as a valid entry"
            );
            assert_eq!(fold.federation_pacts[&fixture.pact_id].pact_epoch, 2);
            Ok(())
        }
    }
}

#[test]
fn peer_roster_is_refolded_from_relayed_bytes_never_relayed_whole() {
    let peer = peer_vault_fixture(0x21);
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());
    peer.admit_all(&vault);

    let roster = peer_authority_roster(&vault, &peer.vault_id).expect("peer roster");
    assert_eq!(
        roster,
        fold_peer_authority_log(&peer.entries),
        "the stored roster IS the pure fold over the same entries — nothing \
         cached, nothing relay-asserted"
    );
    assert_eq!(roster.vault_id, Some(peer.vault_id));

    let roots = peer_consent_roots(&roster);
    assert!(
        roots.contains(&peer.host),
        "host-root: the peer HOST key roots"
    );
    assert!(roots.contains(&peer.admin));
    assert!(!roots.contains(&peer.agent));
    assert!(!roots.contains(&peer.revoked));
}

#[test]
fn peer_entry_admission_is_idempotent_and_order_free() {
    let peer = peer_vault_fixture(0x25);
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());
    let mut bodies = peer.bytes();
    bodies.reverse();
    for body in &bodies {
        admit_peer_authority_log_entry(&vault, &peer.vault_id, body).expect("admit");
        admit_peer_authority_log_entry(&vault, &peer.vault_id, body).expect("re-admit is Ok");
    }
    assert_eq!(
        peer_authority_roster(&vault, &peer.vault_id).expect("roster"),
        fold_peer_authority_log(&peer.entries)
    );
}

#[test]
fn peer_entry_from_another_vault_is_refused_under_the_claimed_peer() {
    let peer = peer_vault_fixture(0x29);
    let other = peer_vault_fixture(0x35);
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());

    for body in other.bytes() {
        let err = admit_peer_authority_log_entry(&vault, &peer.vault_id, &body)
            .expect_err("a foreign-vault entry must not be admitted under this peer");
        assert!(
            matches!(err, Error::InvalidAuthorityLogBody(msg) if msg == "peer authority log vault id"),
            "unexpected error: {err:?}"
        );
    }
    assert!(
        matches!(
            peer_authority_roster(&vault, &peer.vault_id),
            Err(Error::InvalidAuthorityLogBody(msg)) if msg == "peer authority fold root mismatch"
        ),
        "with nothing admitted there is no rooted peer log to report"
    );
}

#[test]
fn peer_log_without_its_genesis_reports_a_fold_root_mismatch() {
    let peer = peer_vault_fixture(0x39);
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());
    // Every entry EXCEPT the genesis: each one binds the peer vault id, so
    // admission accepts them, but the log has no root to fold from.
    for body in peer.bytes().into_iter().skip(1) {
        admit_peer_authority_log_entry(&vault, &peer.vault_id, &body).expect("admit");
    }
    assert!(matches!(
        peer_authority_roster(&vault, &peer.vault_id),
        Err(Error::InvalidAuthorityLogBody(msg)) if msg == "peer authority fold root mismatch"
    ));
}

#[test]
fn peer_admission_rejects_the_four_thousand_ninety_seventh_distinct_hash() {
    let peer = peer_vault_fixture(0x3d);
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());
    let bodies = peer.bytes();
    admit_peer_authority_log_entry(&vault, &peer.vault_id, &bodies[0]).expect("admit genesis");

    // Fill the peer's slice to exactly the ceiling. The rows carry real bytes
    // under fabricated hashes: the ceiling counts DISTINCT STORED HASHES, which
    // is what the keys are.
    vault
        .with_write_txn(|wtxn| {
            for filler in 1..MAX_PEER_AUTHORITY_ENTRIES_PER_PEER {
                let mut hash = [0u8; 32];
                hash[..4].copy_from_slice(&u32::try_from(filler).unwrap().to_be_bytes());
                let key = peer_authority_entry_key(&peer.vault_id, &hash);
                vault.store.sync_state.put(wtxn, &key, &bodies[0])?;
            }
            Ok(())
        })
        .expect("seed the peer slice to the ceiling");

    let err = admit_peer_authority_log_entry(&vault, &peer.vault_id, &bodies[1])
        .expect_err("a new distinct hash past the ceiling must be refused");
    assert!(
        matches!(err, Error::InvalidAuthorityLogBody(msg) if msg == "peer authority log flood"),
        "unexpected error: {err:?}"
    );
    admit_peer_authority_log_entry(&vault, &peer.vault_id, &bodies[0])
        .expect("re-admitting a STORED hash stays idempotent Ok at the ceiling");

    // A different peer is unaffected: the ceiling is per-peer.
    let other = peer_vault_fixture(0x51);
    admit_peer_authority_log_entry(&vault, &other.vault_id, &other.bytes()[0])
        .expect("the ceiling is per-peer");
}

#[test]
fn corrupt_stored_peer_bytes_fail_closed_instead_of_shrinking_the_roster() {
    let peer = peer_vault_fixture(0x55);
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());
    peer.admit_all(&vault);
    let healthy = peer_authority_roster(&vault, &peer.vault_id).expect("roster");

    let corrupt_key = peer_authority_entry_key(
        &peer.vault_id,
        &authority_entry_hash(&peer.entries[1]).expect("hash"),
    );
    vault
        .with_write_txn(|wtxn| {
            vault
                .store
                .sync_state
                .put(wtxn, &corrupt_key, b"not a canonical authority body")?;
            Ok(())
        })
        .expect("corrupt one stored row");

    assert!(
        matches!(
            peer_authority_roster(&vault, &peer.vault_id),
            Err(Error::CorruptedIndex("peer authority log row"))
        ),
        "a corrupt local row is refused, never skipped into a partial roster"
    );
    assert!(
        peer_consent_roots(&healthy).contains(&peer.admin),
        "the skipped-row roster would have silently dropped this consent root"
    );
    assert!(
        vault.authority_fold().is_err(),
        "the local fold reads the same rows and fails closed with them"
    );
}

#[test]
fn peer_host_key_gesture_folds_only_once_the_peer_log_is_admitted() {
    let peer = peer_vault_fixture(0x59);
    let fixture = local_pact_fixture(0x61, 0x63, &peer);
    let repact = repact_entry(&fixture, &peer.host_signing);

    assert_eq!(
        repact_accepted(&fixture, &repact, &BTreeMap::new()),
        Err(FederationLifecycleRejection::GestureInvalid),
        "with no admitted peer log the pinned connect key is the only signer \
         FED-01 accepts"
    );
    assert_eq!(
        repact_accepted(&fixture, &repact, &peer.consent_roots()),
        Ok(()),
        "the peer HOST genesis key — never pinned at Connect — is accepted \
         through the admitted, locally REFOLDED peer roster"
    );
}

#[test]
fn only_consenting_peer_roster_keys_carry_a_gesture() {
    let peer = peer_vault_fixture(0x65);
    let fixture = local_pact_fixture(0x71, 0x73, &peer);
    let roots = peer.consent_roots();

    for (name, signing) in [("host", &peer.host_signing), ("admin", &peer.admin_signing)] {
        assert_eq!(
            repact_accepted(&fixture, &repact_entry(&fixture, signing), &roots),
            Ok(()),
            "{name} is an owner/admin peer consent root"
        );
    }
    for (name, signing) in [
        ("agent-role", &peer.agent_signing),
        ("revoked", &peer.revoked_signing),
        ("never-enrolled", &auth_key(0x77)),
    ] {
        assert_eq!(
            repact_accepted(&fixture, &repact_entry(&fixture, signing), &roots),
            Err(FederationLifecycleRejection::GestureInvalid),
            "{name} peer keys must not carry a gesture"
        );
    }
}

#[test]
fn admitting_peer_logs_leaves_the_local_vault_id_roster_and_storage_untouched() {
    let peer = peer_vault_fixture(0x81);
    let fixture = local_pact_fixture(0x8d, 0x8f, &peer);
    let repact = repact_entry(&fixture, &peer.host_signing);
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());
    for entry in [&fixture.genesis, &fixture.connect, &repact] {
        vault
            .put_authority_log_entry(entry, TimeRange { start: 1, end: 1 }, 1)
            .expect("store local authority entry");
    }

    let before = vault.authority_fold().expect("local fold");
    let stored_before = stored_authority_log_ids(&vault);
    assert_eq!(before.vault_id, Some(fixture.vault_id));
    assert!(
        lifecycle_rejection_for(&before, authority_entry_hash(&repact).expect("hash"))
            == Some(FederationLifecycleRejection::GestureInvalid),
        "before admission the host-key gesture is not accepted"
    );

    peer.admit_all(&vault);
    let after = vault.authority_fold().expect("local fold");

    assert_eq!(
        after.vault_id, before.vault_id,
        "local vault id is untouched"
    );
    assert_eq!(after.roster, before.roster, "local roster is untouched");
    assert!(
        !after.roster.contains_key(&peer.host) && !after.roster.contains_key(&peer.admin),
        "peer keys never enter the LOCAL roster"
    );
    assert_eq!(
        stored_authority_log_ids(&vault),
        stored_before,
        "peer entries stay out of AUTHORITY_LOG entity storage"
    );
    assert_eq!(
        after.federation_pacts[&fixture.pact_id].pact_epoch, 2,
        "the admitted peer roster is what lets Vault::authority_fold accept \
         the host-key repact"
    );
}

fn stored_authority_log_ids(vault: &Vault) -> Vec<EntityId> {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let mut ids = Vec::new();
    for row in vault
        .store
        .type_index
        .prefix_iter(&rtxn, &[ENTITY_TYPE_AUTHORITY_LOG])
        .expect("type index scan")
    {
        let (key, _) = row.expect("type index row");
        ids.push(crate::vault::entity_id_from_type_index_key(&key).expect("entity id"));
    }
    ids
}

// ---------------------------------------------------------------------------
// Cross-vault coreference (FED-07, ONE-1414)
// ---------------------------------------------------------------------------

const COREFERENCE_ACTOR_SEED: u8 = 0x55;
const COREFERENCE_MACHINE_SEED: u8 = 0x56;
const COREFERENCE_LOCAL_SEED: u8 = 0x57;
const COREFERENCE_OTHER_SEED: u8 = 0x58;
const COREFERENCE_STRANGER_SEED: u8 = 0x59;
/// Deliberately unstored — the absent-person fixture.
const COREFERENCE_GHOST_SEED: u8 = 0x5A;

fn coreference_time() -> TimeRange {
    TimeRange { start: 1, end: 1 }
}

fn pact(byte: u8) -> [u8; COREFERENCE_PACT_ID_LEN] {
    [byte; COREFERENCE_PACT_ID_LEN]
}

/// The owner principal these writes are attributed to.
fn coreference_actor() -> WriteActor {
    WriteActor::new(
        entity(COREFERENCE_ACTOR_SEED),
        crate::edge::EdgeActorClass::Human,
    )
}

fn coreference_vault() -> (tempfile::TempDir, Vault) {
    let (dir, vault) = open_test_vault_with(VaultConfig::device());
    for seed in [
        COREFERENCE_ACTOR_SEED,
        COREFERENCE_LOCAL_SEED,
        COREFERENCE_OTHER_SEED,
        COREFERENCE_STRANGER_SEED,
    ] {
        vault
            .put_entity(
                &entity(seed),
                ENTITY_TYPE_PERSON,
                coreference_time(),
                1,
                b"person",
            )
            .expect("put coreference fixture person");
    }
    vault
        .put_entity(
            &entity(COREFERENCE_MACHINE_SEED),
            crate::registry::ENTITY_TYPE_MACHINE,
            coreference_time(),
            1,
            b"machine",
        )
        .expect("put coreference fixture machine");
    (dir, vault)
}

/// The single status claim on a link, decoded.
fn coreference_status_claim(
    vault: &Vault,
    source: EntityId,
    target: EntityId,
) -> Option<ClaimBody> {
    vault
        .claims_for_subject(&source)
        .expect("scan claims for the link source")
        .into_iter()
        .filter_map(|id| vault.get_claim(&id).expect("read claim"))
        .find(|body| {
            body.predicate == crate::claim::PREDICATE_COREFERENCE_STATUS
                && body.subject
                    == (ClaimSubject::Edge {
                        source,
                        kind: EdgeKind::SameAs,
                        target,
                    })
        })
}

/// ONE-1414 done-means 2 (write half) + the explicit `0.0` stored weight.
///
/// Both statuses in one test because the pairing is one rule: `Confirmed`
/// writes `Approved`, `Proposed` writes `Proposed`, and the claim validator
/// would reject either mismatch at the same door.
#[test]
fn put_coreference_link_writes_the_link_and_its_status_atomically() {
    for (status, wire, approval) in [
        (
            CoreferenceStatus::Confirmed,
            "confirmed",
            ClaimApprovalStatus::Approved,
        ),
        (
            CoreferenceStatus::Proposed,
            "proposed",
            ClaimApprovalStatus::Proposed,
        ),
    ] {
        let (_dir, vault) = coreference_vault();
        let local = entity(COREFERENCE_LOCAL_SEED);
        let other = entity(COREFERENCE_OTHER_SEED);

        let claim_id = put_coreference_link(
            &vault,
            &coreference_actor(),
            local,
            other,
            status,
            coreference_time(),
            1,
        )
        .expect("the owning door writes the link");

        // src = local_person, tgt = other_person, weight EXACTLY 0.0.
        let edge = vault
            .edges_out(&local)
            .expect("read outbound edges")
            .into_iter()
            .find(|edge| edge.kind == EdgeKind::SameAs)
            .expect("the same_as link is stored in the written orientation");
        assert_eq!(edge.target, other);
        assert_eq!(edge.weight.to_bits(), 0.0_f32.to_bits());

        let body = coreference_status_claim(&vault, local, other)
            .expect("the status claim landed with the link");
        assert_eq!(body.value.as_str(), Some(wire));
        assert_eq!(body.approval, approval);
        assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
        assert!(vault.get_claim(&claim_id).expect("read claim").is_some());
    }
}

/// ONE-1414 done-means 8 — prevalidation failure leaves NEITHER row.
///
/// Both persons must exist, and the check runs before the transaction opens,
/// so a link never outlives its status and a status never describes a link
/// that was never written.
#[test]
fn put_coreference_link_writes_nothing_when_a_person_is_absent() {
    let (_dir, vault) = coreference_vault();
    let local = entity(COREFERENCE_LOCAL_SEED);
    let ghost = entity(COREFERENCE_GHOST_SEED);

    for (a, b) in [(local, ghost), (ghost, local)] {
        assert!(matches!(
            put_coreference_link(
                &vault,
                &coreference_actor(),
                a,
                b,
                CoreferenceStatus::Confirmed,
                coreference_time(),
                1,
            ),
            Err(Error::EntityNotFound)
        ));
    }

    assert!(!vault.edge_exists(&local, EdgeKind::SameAs, &ghost).unwrap());
    assert!(!vault.edge_exists(&ghost, EdgeKind::SameAs, &local).unwrap());
    assert!(coreference_status_claim(&vault, local, ghost).is_none());
    assert!(coreference_status_claim(&vault, ghost, local).is_none());
}

/// Either endpoint may be scoped into a FOREIGN world — that is the whole
/// cross-vault case. The door checks EXISTENCE, never locality.
#[test]
fn put_coreference_link_accepts_a_foreign_world_scoped_person() {
    let (_dir, vault) = coreference_vault();
    let local = entity(COREFERENCE_LOCAL_SEED);
    let other = entity(COREFERENCE_OTHER_SEED);
    let foreign_world = EntityId::from_bytes([0xF1; 16]).expect("foreign-range world id");
    assert!(is_foreign_world_id_range(foreign_world));
    vault
        .put_entity(
            &foreign_world,
            crate::registry::ENTITY_TYPE_WORLD,
            coreference_time(),
            1,
            b"foreign-world",
        )
        .expect("put foreign world");
    vault
        .batch()
        .edge(&other, EdgeKind::InWorld, &foreign_world, 0.7)
        .commit()
        .expect("scope the other person into the foreign world");

    put_coreference_link(
        &vault,
        &coreference_actor(),
        local,
        other,
        CoreferenceStatus::Confirmed,
        coreference_time(),
        1,
    )
    .expect("a foreign-world-scoped endpoint is the point, not an error");
    assert!(vault.edge_exists(&local, EdgeKind::SameAs, &other).unwrap());
}

/// ONE-1414 done-means 12 — the ACTOR GATE, on BOTH write doors.
///
/// Unattributed (an actor ref no entity backs) and wrong-principal (an actor
/// asserting a class its entity type cannot hold) are both refused BEFORE the
/// transaction opens, so a refused call leaves no trace.
#[test]
fn coreference_write_doors_reject_unattributed_and_wrong_principal_actors() {
    let (_dir, vault) = coreference_vault();
    let local = entity(COREFERENCE_LOCAL_SEED);
    let other = entity(COREFERENCE_OTHER_SEED);

    let unattributed = WriteActor::new(
        entity(COREFERENCE_GHOST_SEED),
        crate::edge::EdgeActorClass::Human,
    );
    // A MACHINE is a system actor; asserting `Human` for it is a wrong
    // principal, not merely a mislabel.
    let wrong_principal = WriteActor::new(
        entity(COREFERENCE_MACHINE_SEED),
        crate::edge::EdgeActorClass::Human,
    );

    assert!(matches!(
        put_coreference_link(
            &vault,
            &unattributed,
            local,
            other,
            CoreferenceStatus::Confirmed,
            coreference_time(),
            1,
        ),
        Err(Error::EntityNotFound)
    ));
    assert!(matches!(
        put_coreference_link(
            &vault,
            &wrong_principal,
            local,
            other,
            CoreferenceStatus::Confirmed,
            coreference_time(),
            1,
        ),
        Err(Error::ActorClassMismatch { .. })
    ));
    assert!(
        !vault.edge_exists(&local, EdgeKind::SameAs, &other).unwrap(),
        "a refused actor must leave no link behind"
    );

    // Now establish the link with a valid principal and re-test the consent
    // door on its own: the actor gate is ahead of the link lookup, so a bad
    // actor is refused as an actor rather than as a missing link.
    put_coreference_link(
        &vault,
        &coreference_actor(),
        local,
        other,
        CoreferenceStatus::Confirmed,
        coreference_time(),
        1,
    )
    .expect("owner principal writes the link");

    assert!(matches!(
        coreference_share_consent(
            &vault,
            &unattributed,
            local,
            other,
            &pact(0x63),
            coreference_time(),
            1,
        ),
        Err(Error::EntityNotFound)
    ));
    assert!(matches!(
        coreference_share_consent(
            &vault,
            &wrong_principal,
            local,
            other,
            &pact(0x63),
            coreference_time(),
            1,
        ),
        Err(Error::ActorClassMismatch { .. })
    ));
    assert!(
        !coreference_shared_for_pact(&vault, local, other, &pact(0x63)).unwrap(),
        "a refused actor must leave no consent behind"
    );
}

/// ONE-1414 done-means 9 — consent to share a link that does not exist is a
/// caller error, not a stored no-op.
#[test]
fn coreference_share_consent_requires_an_existing_link() {
    let (_dir, vault) = coreference_vault();
    let local = entity(COREFERENCE_LOCAL_SEED);
    let stranger = entity(COREFERENCE_STRANGER_SEED);

    assert!(matches!(
        coreference_share_consent(
            &vault,
            &coreference_actor(),
            local,
            stranger,
            &pact(0x63),
            coreference_time(),
            1,
        ),
        Err(Error::EdgeNotFound)
    ));
}

/// ONE-1414 done-means 3 (query half) — consent is per LINK and per PACT, and
/// the link is found in EITHER orientation.
///
/// The reversed-argument reads are the load-bearing half: consent attaches to
/// the link, so which endpoint the caller names first must not change the
/// answer.
#[test]
fn coreference_consent_is_per_pact_and_orientation_independent() {
    let (_dir, vault) = coreference_vault();
    let local = entity(COREFERENCE_LOCAL_SEED);
    let other = entity(COREFERENCE_OTHER_SEED);
    // Stored OTHER -> LOCAL, i.e. the reverse of how the queries name it.
    put_coreference_link(
        &vault,
        &coreference_actor(),
        other,
        local,
        CoreferenceStatus::Confirmed,
        coreference_time(),
        1,
    )
    .expect("write the link in the reverse orientation");

    assert!(!coreference_shared_for_pact(&vault, local, other, &pact(0x63)).unwrap());

    coreference_share_consent(
        &vault,
        &coreference_actor(),
        local,
        other,
        &pact(0x63),
        coreference_time(),
        1,
    )
    .expect("consent finds the link in the stored orientation");

    for (a, b) in [(local, other), (other, local)] {
        assert!(
            coreference_shared_for_pact(&vault, a, b, &pact(0x63)).unwrap(),
            "consent must read the same in both orientations"
        );
        assert!(
            !coreference_shared_for_pact(&vault, a, b, &pact(0x64)).unwrap(),
            "consent for one pact says nothing about another"
        );
    }

    // A link that carries no consent at all stays unshared even for a pact
    // some OTHER link was shared into.
    let stranger = entity(COREFERENCE_STRANGER_SEED);
    put_coreference_link(
        &vault,
        &coreference_actor(),
        local,
        stranger,
        CoreferenceStatus::Confirmed,
        coreference_time(),
        1,
    )
    .expect("write a second, unconsented link");
    assert!(!coreference_shared_for_pact(&vault, local, stranger, &pact(0x63)).unwrap());
}

/// ONE-1414 done-means 1 — THE NO-POOLING CONTRACT.
///
/// A Confirmed link between A and B lets NO PPR mass cross, in EITHER
/// orientation, so a walk seeded on A never reaches B and therefore never
/// reaches B's claims. The control edge proves the walk itself works — without
/// it, an empty result would "pass" for the wrong reason.
#[test]
fn confirmed_coreference_never_pools_claims_through_ppr() {
    for reverse in [false, true] {
        let (_dir, vault) = coreference_vault();
        let local = entity(COREFERENCE_LOCAL_SEED);
        let other = entity(COREFERENCE_OTHER_SEED);
        let control = entity(COREFERENCE_STRANGER_SEED);

        // B's own claim, reachable from B by the ordinary claim_of edge.
        let other_claim = entity(0x5B);
        vault
            .put_claim(
                &other_claim,
                &ClaimBody::new(
                    "profile.lives_in",
                    ClaimSubject::Entity(other),
                    Value::from("elsewhere"),
                    1.0,
                    ClaimApprovalStatus::Approved,
                    ClaimLifecycleStatus::Active,
                ),
                coreference_time(),
                1,
            )
            .expect("write the other person's own claim");
        // Control: a traversable structural edge out of A.
        vault
            .batch()
            .edge(&local, EdgeKind::BelongsTo, &control, 1.0)
            .commit()
            .expect("write the control edge");

        let (src, tgt) = if reverse {
            (other, local)
        } else {
            (local, other)
        };
        put_coreference_link(
            &vault,
            &coreference_actor(),
            src,
            tgt,
            CoreferenceStatus::Confirmed,
            coreference_time(),
            1,
        )
        .expect("write the confirmed link");

        let rtxn = vault.store.env.read_txn().unwrap();
        let scores = crate::ppr::ppr_compute_weighted(
            &vault.store,
            &rtxn,
            &[local],
            crate::ppr::SeedWeighting::Uniform,
            3,
            0.15,
        )
        .expect("ppr walk from the local person");
        let reached: Vec<EntityId> = scores.iter().map(|scored| scored.id).collect();
        drop(rtxn);

        assert!(
            reached.contains(&control),
            "reverse={reverse}: the control edge must be traversed, else this proves nothing"
        );
        assert!(
            !reached.contains(&other),
            "reverse={reverse}: same_as must never be traversed"
        );
        assert!(
            !reached.contains(&other_claim),
            "reverse={reverse}: the other person's claims must never be pooled"
        );

        // The link rewrites nothing about the other person's claim.
        let body = vault
            .get_claim(&other_claim)
            .expect("read claim")
            .expect("the claim survives");
        assert_eq!(body.subject, ClaimSubject::Entity(other));
        assert_eq!(body.source, None);
        assert_eq!(body.world, None);
    }
}

/// VERDICT-FIX (P1 `raw-same-as-write-bypass`) — done-means 5, engine half.
///
/// The facade and `self.memory` doors already refuse `same_as`, but the raw
/// engine writers did not: `Vault::put_edge` and the batch edge builders gated
/// only on the redirect-shell kinds, so a caller could mint a link with no
/// status claim and no actor, then have consent name it into an export.
///
/// The gate is CREATION-side by construction, and both halves are asserted here
/// because collapsing them into one predicate is the tempting wrong fix:
/// deleting a link must stay possible (there is no revoke door to route it
/// through, and removal only narrows disclosure), and the RECEIVE-side
/// predicate `validate_public_edge_kind` must keep passing `same_as` or a
/// consented link arriving from a peer would be quarantined.
#[test]
fn raw_edge_writers_cannot_mint_a_coreference_link() {
    let (_dir, vault) = coreference_vault();
    let local = entity(COREFERENCE_LOCAL_SEED);
    let other = entity(COREFERENCE_OTHER_SEED);

    assert!(matches!(
        vault.put_edge(&local, EdgeKind::SameAs, &other, 1.0),
        Err(Error::ReservedEdgeKind("same_as"))
    ));
    assert!(matches!(
        vault
            .batch()
            .edge(&local, EdgeKind::SameAs, &other, 0.0)
            .commit(),
        Err(Error::ReservedEdgeKind("same_as"))
    ));
    assert!(matches!(
        vault
            .batch()
            .edge_with_created_at(&local, EdgeKind::SameAs, &other, 0.0, 7)
            .commit(),
        Err(Error::ReservedEdgeKind("same_as"))
    ));
    assert!(
        !vault.edge_exists(&local, EdgeKind::SameAs, &other).unwrap(),
        "a refused raw write must leave no link behind"
    );

    // The owning door still works, and the link it writes is still removable.
    put_coreference_link(
        &vault,
        &coreference_actor(),
        local,
        other,
        CoreferenceStatus::Confirmed,
        coreference_time(),
        1,
    )
    .expect("the federation door is the write door, not a blocked path");
    assert!(
        vault
            .delete_edge(&local, EdgeKind::SameAs, &other)
            .expect("deleting a link is not reserved to a door"),
    );

    // RECEIVE side: sync admission, remat, and the export selector all gate on
    // the narrower predicate, which must still admit the kind.
    assert!(crate::edge::validate_public_edge_kind(EdgeKind::SameAs).is_ok());
    assert!(crate::edge::validate_public_edge_creation_kind(EdgeKind::SameAs).is_err());
}

/// VERDICT-FIX (P2 `consent-orientation-short-circuit`) — done-means 3, query
/// half, in the DUAL-ORIENTATION state.
///
/// The write door files consent against whichever single orientation it finds,
/// but nothing local guarantees only one row exists — a peer can replicate the
/// mirror. Reading only the first orientation found made the answer depend on
/// the caller's argument order: consent filed on `B -> A` read as "not shared"
/// when asked as `(A, B)`.
#[test]
fn coreference_consent_reads_every_stored_orientation() {
    let (_dir, vault) = coreference_vault();
    let local = entity(COREFERENCE_LOCAL_SEED);
    let other = entity(COREFERENCE_OTHER_SEED);

    for (src, tgt) in [(local, other), (other, local)] {
        put_coreference_link(
            &vault,
            &coreference_actor(),
            src,
            tgt,
            CoreferenceStatus::Confirmed,
            coreference_time(),
            1,
        )
        .expect("write the link in both orientations");
    }
    assert!(vault.edge_exists(&local, EdgeKind::SameAs, &other).unwrap());
    assert!(vault.edge_exists(&other, EdgeKind::SameAs, &local).unwrap());

    // Consent lands on `other -> local`: the write door resolves `(other,
    // local)` to that row first.
    coreference_share_consent(
        &vault,
        &coreference_actor(),
        other,
        local,
        &pact(0x63),
        coreference_time(),
        1,
    )
    .expect("consent files against the orientation the door finds");

    for (a, b) in [(local, other), (other, local)] {
        assert!(
            coreference_shared_for_pact(&vault, a, b, &pact(0x63)).unwrap(),
            "consent is a property of the LINK, so argument order cannot decide it"
        );
        assert!(
            !coreference_shared_for_pact(&vault, a, b, &pact(0x64)).unwrap(),
            "reading both orientations must not widen WHICH pact is consented"
        );
    }
}

/// VERDICT-FIX (banked `sync-receipt consent laundering`) — a REPLICATED
/// consent claim is not this vault's consent.
///
/// Federation admission restamps every inbound claim `Imported`, and the raw
/// server import path performs no admission at all, so a peer-controlled row
/// carrying a structurally perfect Approved `share_consent` claim plus its
/// `claim_of` edge can reach local storage. Honoring it would let the peer
/// decide what this vault discloses about its own local-by-default links.
///
/// The locally written claim in the second half is the control: without it an
/// all-refusing query would "pass" for the wrong reason.
#[test]
fn replicated_consent_never_shares_a_coreference_link() {
    let (_dir, vault) = coreference_vault();
    let local = entity(COREFERENCE_LOCAL_SEED);
    let other = entity(COREFERENCE_OTHER_SEED);
    put_coreference_link(
        &vault,
        &coreference_actor(),
        local,
        other,
        CoreferenceStatus::Confirmed,
        coreference_time(),
        1,
    )
    .expect("write the link the peer wants exported");

    let mut planted = ClaimBody::new(
        crate::claim::PREDICATE_COREFERENCE_SHARE_CONSENT,
        ClaimSubject::Edge {
            source: local,
            kind: EdgeKind::SameAs,
            target: other,
        },
        Value::Map(vec![(
            Value::from(crate::claim::COREFERENCE_SHARE_CONSENT_PACT_KEY),
            Value::from(bytes_to_hex_lower(&pact(0x63))),
        )]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    planted.source = Some(ClaimSource::Imported);
    let planted_id = entity(0x5C);
    vault
        .put_claim(&planted_id, &planted, coreference_time(), 1)
        .expect("the body is structurally valid — that is the point");
    // EdgeRef-subject claims carry no claim_of wiring of their own, so the
    // reachability the query walks is supplied here exactly as the door does.
    vault
        .batch()
        .edge(
            &planted_id,
            EdgeKind::ClaimOf,
            &local,
            crate::vault::CLAIM_OF_DEFAULT_WEIGHT,
        )
        .commit()
        .expect("wire the planted claim to the link source");

    assert!(
        !coreference_shared_for_pact(&vault, local, other, &pact(0x63)).unwrap(),
        "an imported consent row is a PEER asserting that WE consented"
    );

    // Control: the same claim written locally DOES share the link.
    coreference_share_consent(
        &vault,
        &coreference_actor(),
        local,
        other,
        &pact(0x63),
        coreference_time(),
        1,
    )
    .expect("the owner's own consent");
    assert!(coreference_shared_for_pact(&vault, local, other, &pact(0x63)).unwrap());
}

// ---------------------------------------------------------------------------
// FED-04 — terminal-pact stale stamping (ONE-1411)
// ---------------------------------------------------------------------------

const STALE_PACT_A: [u8; 32] = [0xA7; 32];
const STALE_PACT_B: [u8; 32] = [0xB9; 32];
const STALE_NONCE_A: [u8; 16] = [0xA8; 16];
const STALE_NONCE_B: [u8; 16] = [0xBA; 16];
const STALE_SUCCESSOR: AuthorityVaultId = [0x77; 32];

/// A WORLD id in the received-foreign range — the only range registration takes.
fn foreign_world(seed: u8) -> ForeignWorldId {
    ForeignWorldId::from_entity_id(EntityId::from_bytes([seed; 16]).expect("valid world id"))
        .expect("seed must sit in the foreign world id range")
}

/// A local vault rooted at `seed` that pacts with a synthetic peer.
struct StaleFixture {
    peer: PeerVaultFixture,
    owner_signing: SigningKey,
    vault_id: AuthorityVaultId,
    genesis: AuthorityLogEntry,
}

fn stale_fixture(seed: u8, peer_seed: u8) -> StaleFixture {
    let genesis = auth_genesis(seed);
    StaleFixture {
        peer: peer_vault_fixture(peer_seed),
        owner_signing: auth_key(seed),
        vault_id: genesis_vault_id(&genesis).expect("local vault id"),
        genesis,
    }
}

impl StaleFixture {
    fn scope_digest(&self, nonce: &[u8; 16]) -> [u8; 32] {
        federation_scope_digest(
            nonce,
            &encode_federation_pact_scope(&peer_scope()).expect("canonical scope"),
        )
    }

    fn gesture(
        &self,
        kind: FederationLifecycleKind,
        pact_id: &[u8; 32],
        pact_epoch: u64,
        digest: &[u8; 32],
        successor: Option<&AuthorityVaultId>,
        nonce: &[u8; 16],
    ) -> FederationPactGesture {
        sign_federation_pact_gesture(
            kind,
            pact_id,
            &self.vault_id,
            &self.peer.vault_id,
            pact_epoch,
            digest,
            successor,
            nonce,
            self.peer.admin.clone(),
            |transcript| Ok(self.peer.admin_signing.sign(transcript).to_bytes().to_vec()),
        )
        .expect("peer gesture")
    }

    fn connect(
        &self,
        pact_id: [u8; 32],
        nonce: [u8; 16],
        grant_ref: EntityId,
        seq: u64,
        parent: AuthorityEntryHash,
    ) -> AuthorityLogEntry {
        let digest = self.scope_digest(&nonce);
        self.entry(
            seq,
            parent,
            FederationLifecycleAction {
                kind: FederationLifecycleKind::Connect,
                pact_id,
                grant_ref,
                peer_vault_id: self.peer.vault_id,
                pact_epoch: 1,
                pact_scope: Some(peer_scope()),
                effective_scope: None,
                scope_digest: Some(digest),
                gesture: Some(self.gesture(
                    FederationLifecycleKind::Connect,
                    &pact_id,
                    1,
                    &digest,
                    None,
                    &nonce,
                )),
                successor_vault_id: None,
                pact_nonce: nonce,
            },
        )
    }

    /// Disconnect / Dissolve: unilateral, epoch UNCHANGED, no scope, no gesture.
    fn sever(
        &self,
        kind: FederationLifecycleKind,
        pact_id: [u8; 32],
        nonce: [u8; 16],
        grant_ref: EntityId,
        seq: u64,
        parent: AuthorityEntryHash,
    ) -> AuthorityLogEntry {
        self.entry(
            seq,
            parent,
            FederationLifecycleAction {
                kind,
                pact_id,
                grant_ref,
                peer_vault_id: self.peer.vault_id,
                pact_epoch: 1,
                pact_scope: None,
                effective_scope: None,
                scope_digest: None,
                gesture: None,
                successor_vault_id: None,
                pact_nonce: nonce,
            },
        )
    }

    /// Promote: dual-signed succession; the epoch BUMPS and the digest must
    /// equal the stored one byte-for-byte.
    fn promote(
        &self,
        pact_id: [u8; 32],
        nonce: [u8; 16],
        grant_ref: EntityId,
        seq: u64,
        parent: AuthorityEntryHash,
    ) -> AuthorityLogEntry {
        let digest = self.scope_digest(&nonce);
        self.entry(
            seq,
            parent,
            FederationLifecycleAction {
                kind: FederationLifecycleKind::Promote,
                pact_id,
                grant_ref,
                peer_vault_id: self.peer.vault_id,
                pact_epoch: 2,
                pact_scope: None,
                effective_scope: None,
                scope_digest: Some(digest),
                gesture: Some(self.gesture(
                    FederationLifecycleKind::Promote,
                    &pact_id,
                    2,
                    &digest,
                    Some(&STALE_SUCCESSOR),
                    &nonce,
                )),
                successor_vault_id: Some(STALE_SUCCESSOR),
                pact_nonce: nonce,
            },
        )
    }

    fn entry(
        &self,
        seq: u64,
        parent: AuthorityEntryHash,
        action: FederationLifecycleAction,
    ) -> AuthorityLogEntry {
        auth_entry(
            Some(self.vault_id),
            seq,
            vec![parent],
            AuthorityOp::FederationLifecycle(action),
            &self.owner_signing,
            None,
            seq + 1,
        )
    }
}

/// Stores `entries` through the real write door, in order, one second apart.
fn store_authority(vault: &Vault, entries: &[&AuthorityLogEntry]) {
    for (index, entry) in entries.iter().enumerate() {
        let at = index as u64 + 1;
        vault
            .put_authority_log_entry(entry, TimeRange { start: at, end: at }, at)
            .expect("store authority entry");
    }
}

fn read_stale_map(vault: &Vault) -> Result<BTreeMap<EntityId, WorldStaleStamp>> {
    let rtxn = vault.store.env.read_txn()?;
    stale_stamped_worlds(&vault.store, &rtxn)
}

fn write_sync_row(vault: &Vault, key: &str, value: &[u8]) {
    vault
        .with_write_txn(|wtxn| {
            vault.store.sync_state.put(wtxn, key, value)?;
            Ok(())
        })
        .expect("seed a raw sync_state row");
}

/// ONE-1411 done-means 1 + 9 — an Active pact stamps nothing; a Disconnect
/// through the real write door stamps every world registered to it at the
/// pact's own epoch; and re-sweeping unchanged state writes nothing.
#[test]
fn disconnect_stamps_every_registered_world_and_resweeps_are_no_ops() -> Result<()> {
    let fixture = stale_fixture(0xC1, 0xC9);
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());
    let grant = entity(0xCD);
    let connect = fixture.connect(
        STALE_PACT_A,
        STALE_NONCE_A,
        grant,
        1,
        authority_entry_hash(&fixture.genesis)?,
    );
    let disconnect = fixture.sever(
        FederationLifecycleKind::Disconnect,
        STALE_PACT_A,
        STALE_NONCE_A,
        grant,
        2,
        authority_entry_hash(&connect)?,
    );

    store_authority(&vault, &[&fixture.genesis, &connect]);
    let (first, second) = (foreign_world(0xF1), foreign_world(0xF2));
    for world in [first, second] {
        register_foreign_world_for_pact(&vault, &STALE_PACT_A, world)?;
    }
    assert_eq!(
        apply_federation_stale_stamps(&vault)?,
        0,
        "a live pact stamps nothing — registration alone is not staleness"
    );

    // The write door sweeps on its own; nothing else is called here.
    vault.put_authority_log_entry(&disconnect, TimeRange { start: 3, end: 3 }, 3)?;

    for world in [first, second] {
        let stamp = foreign_world_stale_stamp(&vault, world.entity_id())?
            .expect("every registered world of a disconnected pact is stamped");
        assert_eq!(stamp.reason, FederationStaleReason::Disconnected);
        assert_eq!(
            stamp.disconnect_epoch, 1,
            "Disconnect is terminal AT the current epoch, not past it"
        );
    }
    assert_eq!(
        apply_federation_stale_stamps(&vault)?,
        0,
        "a second sweep over unchanged state writes nothing"
    );

    // A world registered AFTER the pact died still catches up: the sweep reads
    // pact STATE, not one transition's timing.
    let late = foreign_world(0xF3);
    register_foreign_world_for_pact(&vault, &STALE_PACT_A, late)?;
    assert_eq!(apply_federation_stale_stamps(&vault)?, 1);
    assert!(foreign_world_stale_stamp(&vault, late.entity_id())?.is_some());
    Ok(())
}

/// ONE-1411 done-means 2 — Dissolve and Promote carry their OWN reason, and
/// each preserves the epoch its transition ended at (Promote's is the bumped
/// one, the severances' is the current one).
#[test]
fn dissolve_and_promote_carry_their_own_reason_and_terminal_epoch() -> Result<()> {
    let dissolving = stale_fixture(0xD1, 0xD9);
    let (_dissolve_dir, dissolve_vault) = open_test_vault_with(VaultConfig::device());
    let dissolve_grant = entity(0xDD);
    let dissolve_connect = dissolving.connect(
        STALE_PACT_A,
        STALE_NONCE_A,
        dissolve_grant,
        1,
        authority_entry_hash(&dissolving.genesis)?,
    );
    let dissolve = dissolving.sever(
        FederationLifecycleKind::Dissolve,
        STALE_PACT_A,
        STALE_NONCE_A,
        dissolve_grant,
        2,
        authority_entry_hash(&dissolve_connect)?,
    );
    let dissolved_world = foreign_world(0xF4);
    store_authority(&dissolve_vault, &[&dissolving.genesis, &dissolve_connect]);
    register_foreign_world_for_pact(&dissolve_vault, &STALE_PACT_A, dissolved_world)?;
    dissolve_vault.put_authority_log_entry(&dissolve, TimeRange { start: 3, end: 3 }, 3)?;

    let stamp = foreign_world_stale_stamp(&dissolve_vault, dissolved_world.entity_id())?
        .expect("dissolved world stamp");
    assert_eq!(stamp.reason, FederationStaleReason::Dissolved);
    assert_eq!(stamp.disconnect_epoch, 1);

    let promoting = stale_fixture(0xE3, 0xE9);
    let (_promote_dir, promote_vault) = open_test_vault_with(VaultConfig::device());
    let promote_grant = entity(0xEE);
    let promote_connect = promoting.connect(
        STALE_PACT_A,
        STALE_NONCE_A,
        promote_grant,
        1,
        authority_entry_hash(&promoting.genesis)?,
    );
    let promote = promoting.promote(
        STALE_PACT_A,
        STALE_NONCE_A,
        promote_grant,
        2,
        authority_entry_hash(&promote_connect)?,
    );
    let promoted_world = foreign_world(0xF5);
    store_authority(&promote_vault, &[&promoting.genesis, &promote_connect]);
    register_foreign_world_for_pact(&promote_vault, &STALE_PACT_A, promoted_world)?;
    promote_vault.put_authority_log_entry(&promote, TimeRange { start: 3, end: 3 }, 3)?;

    let stamp = foreign_world_stale_stamp(&promote_vault, promoted_world.entity_id())?
        .expect("promoted world stamp");
    assert_eq!(
        stamp.reason,
        FederationStaleReason::Promoted,
        "a promotion stays distinguishable from a severance"
    );
    assert_eq!(
        stamp.disconnect_epoch, 2,
        "Promote's terminal epoch is the epoch it bumped TO"
    );
    Ok(())
}

/// ONE-1411 done-means 6 — no auto-purge. Stamping ADDS sync-state rows and
/// nothing else: the WORLD entity, the claim entity, and the claim BODY all
/// read back unchanged.
#[test]
fn stamping_adds_rows_only_and_never_purges_world_or_claim_entities() -> Result<()> {
    let fixture = stale_fixture(0x33, 0x39);
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());
    let world = foreign_world(0xF6);
    let subject = entity(0x35);
    vault.put_entity(
        &world.entity_id(),
        crate::registry::ENTITY_TYPE_WORLD,
        TimeRange { start: 1, end: 1 },
        1,
        b"foreign-world",
    )?;
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        &encode_value(&Value::Map(vec![(
            Value::from("name"),
            Value::from("federated person"),
        )])),
    )?;
    let mut body = ClaimBody::new(
        PREDICATE_RELATIONSHIP_LABEL,
        ClaimSubject::Entity(subject),
        Value::from("friend"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.world = Some(world.entity_id());
    let claim_id = entity(0x37);
    vault.put_claim(&claim_id, &body, TimeRange { start: 1, end: 1 }, 1)?;

    let grant = entity(0x3B);
    let connect = fixture.connect(
        STALE_PACT_A,
        STALE_NONCE_A,
        grant,
        1,
        authority_entry_hash(&fixture.genesis)?,
    );
    let disconnect = fixture.sever(
        FederationLifecycleKind::Disconnect,
        STALE_PACT_A,
        STALE_NONCE_A,
        grant,
        2,
        authority_entry_hash(&connect)?,
    );
    store_authority(&vault, &[&fixture.genesis, &connect]);
    register_foreign_world_for_pact(&vault, &STALE_PACT_A, world)?;
    vault.put_authority_log_entry(&disconnect, TimeRange { start: 3, end: 3 }, 3)?;

    assert!(
        foreign_world_stale_stamp(&vault, world.entity_id())?.is_some(),
        "the world is stamped — this test is about what else did NOT happen"
    );
    assert!(
        vault.get_raw(&world.entity_id())?.is_some(),
        "no tombstone, no delete: the WORLD entity still reads through get_raw"
    );
    assert!(
        vault.get_raw(&claim_id)?.is_some(),
        "the claim entity still reads through get_raw"
    );
    assert_eq!(
        vault.get_claim(&claim_id)?.expect("claim body"),
        body,
        "the claim BODY is untouched: stamping never mutates content"
    );
    Ok(())
}

/// ONE-1411 done-means 7 — first stamp wins. Two pacts deliver one world; the
/// first to go terminal owns the stamp forever, and the second's DIFFERENT
/// reason is what proves nothing was rewritten.
#[test]
fn the_first_terminal_stamp_wins_across_pacts() -> Result<()> {
    let fixture = stale_fixture(0x45, 0x49);
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());
    let (grant_a, grant_b) = (entity(0x4B), entity(0x4D));
    let connect_a = fixture.connect(
        STALE_PACT_A,
        STALE_NONCE_A,
        grant_a,
        1,
        authority_entry_hash(&fixture.genesis)?,
    );
    let connect_b = fixture.connect(
        STALE_PACT_B,
        STALE_NONCE_B,
        grant_b,
        2,
        authority_entry_hash(&connect_a)?,
    );
    let disconnect_a = fixture.sever(
        FederationLifecycleKind::Disconnect,
        STALE_PACT_A,
        STALE_NONCE_A,
        grant_a,
        3,
        authority_entry_hash(&connect_b)?,
    );
    let dissolve_b = fixture.sever(
        FederationLifecycleKind::Dissolve,
        STALE_PACT_B,
        STALE_NONCE_B,
        grant_b,
        4,
        authority_entry_hash(&disconnect_a)?,
    );

    store_authority(&vault, &[&fixture.genesis, &connect_a, &connect_b]);
    let shared = foreign_world(0xF7);
    for pact in [&STALE_PACT_A, &STALE_PACT_B] {
        register_foreign_world_for_pact(&vault, pact, shared)?;
    }

    vault.put_authority_log_entry(&disconnect_a, TimeRange { start: 4, end: 4 }, 4)?;
    let first = foreign_world_stale_stamp(&vault, shared.entity_id())?.expect("first stamp");
    assert_eq!(first.reason, FederationStaleReason::Disconnected);

    vault.put_authority_log_entry(&dissolve_b, TimeRange { start: 5, end: 5 }, 5)?;
    assert_eq!(
        foreign_world_stale_stamp(&vault, shared.entity_id())?.expect("stamp survives"),
        first,
        "the later Dissolve must not rewrite reason, epoch, or timestamp"
    );
    assert_eq!(
        apply_federation_stale_stamps(&vault)?,
        0,
        "and an explicit re-sweep with both pacts terminal writes nothing"
    );
    Ok(())
}

/// ONE-1411 done-means 8 — malformed LOCAL rows are corruption, not rows to
/// skip. Silently skipping any of these would un-stale a world whose pact is
/// provably dead.
#[test]
fn malformed_stale_rows_and_registrations_fail_closed_as_corruption() -> Result<()> {
    let world = foreign_world(0xF8);
    let healthy = encode_world_stale_stamp(WorldStaleStamp {
        reason: FederationStaleReason::Disconnected,
        disconnect_epoch: 1,
        stamped_at_secs: 9,
    });

    // Bad VALUES on an otherwise well-formed stale key.
    let mut unknown_version = healthy;
    unknown_version[0] = 2;
    let mut unknown_reason = healthy;
    unknown_reason[1] = 4;
    for (name, value) in [
        ("truncated", healthy[..WORLD_STALE_STAMP_LEN - 1].to_vec()),
        ("overlong", [healthy.as_slice(), &[0]].concat()),
        ("unknown version", unknown_version.to_vec()),
        ("unknown reason", unknown_reason.to_vec()),
    ] {
        let (_dir, vault) = open_test_vault_with(VaultConfig::device());
        let key = federation_stale_key(world.entity_id());
        write_sync_row(&vault, &key, &value);
        assert!(
            matches!(
                foreign_world_stale_stamp(&vault, world.entity_id()),
                Err(Error::CorruptedIndex("federation world stale stamp"))
            ),
            "{name} stale value must fail closed"
        );
        assert!(
            matches!(
                read_stale_map(&vault),
                Err(Error::CorruptedIndex("federation world stale stamp"))
            ),
            "{name} stale value must fail closed on the bulk read too"
        );
    }

    // Bad KEYS under the stale prefix: non-hex, uppercase (never our own
    // `to_hex` spelling), and a LOCAL-range id no registration door could mint.
    for (name, tail) in [
        ("non-hex", "not-a-world-id".to_owned()),
        ("uppercase", world.entity_id().to_hex().to_ascii_uppercase()),
        ("local-range", entity(0x51).to_hex()),
    ] {
        let (_dir, vault) = open_test_vault_with(VaultConfig::device());
        write_sync_row(
            &vault,
            &format!("{FEDERATION_STALE_KEY_PREFIX}{tail}"),
            &healthy,
        );
        assert!(
            matches!(
                read_stale_map(&vault),
                Err(Error::CorruptedIndex("federation world stale stamp"))
            ),
            "{name} stale key must fail closed"
        );
    }

    // Bad registration rows, seen by the sweep over a terminal pact.
    for (name, key, value) in [
        (
            "wrong registration value",
            format!(
                "{FEDERATION_WORLD_KEY_PREFIX}{}:{}",
                bytes_to_hex_lower(&STALE_PACT_A),
                world.entity_id().to_hex()
            ),
            vec![0x02],
        ),
        (
            "malformed registration key",
            format!(
                "{FEDERATION_WORLD_KEY_PREFIX}{}:not-a-world-id",
                bytes_to_hex_lower(&STALE_PACT_A)
            ),
            vec![0x01],
        ),
    ] {
        let fixture = stale_fixture(0x55, 0x59);
        let (_dir, vault) = open_test_vault_with(VaultConfig::device());
        let grant = entity(0x5B);
        let connect = fixture.connect(
            STALE_PACT_A,
            STALE_NONCE_A,
            grant,
            1,
            authority_entry_hash(&fixture.genesis)?,
        );
        let disconnect = fixture.sever(
            FederationLifecycleKind::Disconnect,
            STALE_PACT_A,
            STALE_NONCE_A,
            grant,
            2,
            authority_entry_hash(&connect)?,
        );
        store_authority(&vault, &[&fixture.genesis, &connect]);
        write_sync_row(&vault, &key, &value);
        assert!(
            matches!(
                vault.put_authority_log_entry(&disconnect, TimeRange { start: 3, end: 3 }, 3),
                Err(Error::CorruptedIndex("federation world registration"))
            ),
            "{name} must fail the sweep closed"
        );
    }
    Ok(())
}

/// ONE-1411 done-means 8, the sweep's own read — a malformed stale row is NOT
/// an immutable first stamp. Existence alone would let a corrupt row pose as
/// the winner forever, leaving a provably dead world with no valid stamp: the
/// exact un-staling a write-capable attacker wants. The sweep must decode what
/// it declines to overwrite.
#[test]
fn a_corrupt_existing_stamp_fails_the_sweep_closed_instead_of_posing_as_first() -> Result<()> {
    let healthy = encode_world_stale_stamp(WorldStaleStamp {
        reason: FederationStaleReason::Disconnected,
        disconnect_epoch: 1,
        stamped_at_secs: 9,
    });
    let mut unknown_version = healthy;
    unknown_version[0] = 2;

    for (name, value) in [
        ("truncated", healthy[..WORLD_STALE_STAMP_LEN - 1].to_vec()),
        ("unknown version", unknown_version.to_vec()),
    ] {
        let fixture = stale_fixture(0x65, 0x69);
        let (_dir, vault) = open_test_vault_with(VaultConfig::device());
        let grant = entity(0x6B);
        let connect = fixture.connect(
            STALE_PACT_A,
            STALE_NONCE_A,
            grant,
            1,
            authority_entry_hash(&fixture.genesis)?,
        );
        let disconnect = fixture.sever(
            FederationLifecycleKind::Disconnect,
            STALE_PACT_A,
            STALE_NONCE_A,
            grant,
            2,
            authority_entry_hash(&connect)?,
        );
        store_authority(&vault, &[&fixture.genesis, &connect]);

        let world = foreign_world(0xF9);
        register_foreign_world_for_pact(&vault, &STALE_PACT_A, world)?;
        write_sync_row(&vault, &federation_stale_key(world.entity_id()), &value);

        assert!(
            matches!(
                vault.put_authority_log_entry(&disconnect, TimeRange { start: 3, end: 3 }, 3),
                Err(Error::CorruptedIndex("federation world stale stamp"))
            ),
            "{name} pre-existing stamp must fail the sweep closed"
        );
    }

    Ok(())
}

/// The pinned wire layout: `[version][reason][epoch LE][stamped_at LE]`.
#[test]
fn world_stale_stamp_wire_layout_is_pinned_and_decode_fails_closed() {
    for (reason, byte, word) in [
        (FederationStaleReason::Disconnected, 1u8, "disconnected"),
        (FederationStaleReason::Dissolved, 2, "dissolved"),
        (FederationStaleReason::Promoted, 3, "promoted"),
    ] {
        assert_eq!(reason.as_wire_byte(), byte);
        assert_eq!(FederationStaleReason::from_wire_byte(byte), Some(reason));
        assert_eq!(reason.as_str(), word);
    }
    for unknown in [0u8, 4, 255] {
        assert_eq!(FederationStaleReason::from_wire_byte(unknown), None);
    }

    let stamp = WorldStaleStamp {
        reason: FederationStaleReason::Promoted,
        disconnect_epoch: 0x0102_0304_0506_0708,
        stamped_at_secs: 0x1112_1314_1516_1718,
    };
    let encoded = encode_world_stale_stamp(stamp);
    assert_eq!(encoded.len(), WORLD_STALE_STAMP_LEN);
    assert_eq!(encoded[0], 1, "version byte");
    assert_eq!(encoded[1], FederationStaleReason::Promoted.as_wire_byte());
    assert_eq!(&encoded[2..10], &stamp.disconnect_epoch.to_le_bytes());
    assert_eq!(&encoded[10..18], &stamp.stamped_at_secs.to_le_bytes());
    assert_eq!(
        decode_world_stale_stamp(&encoded).expect("round trip"),
        stamp
    );

    for (name, bytes) in [
        ("empty", Vec::new()),
        ("short", encoded[..WORLD_STALE_STAMP_LEN - 1].to_vec()),
        ("long", [encoded.as_slice(), &[0]].concat()),
    ] {
        assert!(
            matches!(
                decode_world_stale_stamp(&bytes),
                Err(Error::CorruptedIndex("federation world stale stamp"))
            ),
            "{name} must fail closed"
        );
    }
}

/// The stale marker is ENGINE DIAGNOSTIC CONTRACT text: readers match it
/// verbatim, so it is pinned here character for character.
#[test]
fn world_stale_marker_text_is_pinned() {
    assert_eq!(
        world_stale_marker(WorldStaleStamp {
            reason: FederationStaleReason::Promoted,
            disconnect_epoch: 7,
            stamped_at_secs: 123,
        }),
        "⚠ stale federation content (promoted at pact epoch 7) — may be outdated"
    );
}
