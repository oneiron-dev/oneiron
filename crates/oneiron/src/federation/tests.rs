use super::*;
use crate::error::ErrorKind;
use crate::registry::{
    ENTITY_TYPE_FEDERATION_GRANT, EntityClassification, TypeByteBand, entity_type_registry_entry,
};

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
            FederationScopeBands::Some(vec![TypeByteBand::Semantic, TypeByteBand::Core]),
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
        FederationScopeBands::Some(vec![TypeByteBand::Semantic]),
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
        FederationScopeBands::Some(vec![TypeByteBand::Semantic]),
    );
    let right = direction(
        FederationScopeWorlds::Worlds(vec![scope_entity(0x12)]),
        FederationScopeFacets::Some(vec![scope_entity(0x22), scope_entity(0x23)]),
        FederationScopeBands::Some(vec![TypeByteBand::Core]),
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

    assert_eq!(ENTITY_TYPE_FEDERATION_GRANT, 124);
    assert_eq!(entry.kind, "FEDERATION_GRANT");
    assert_eq!(entry.short_id_prefix, None);
    assert_eq!(entry.classification, EntityClassification::Maintenance);
    assert_eq!(entry.band, TypeByteBand::InducedDynamicMaintenance);
}
