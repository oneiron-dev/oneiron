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

fn scope_entity(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("valid scope id")
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
            FederationScopeWorlds::Worlds(vec![scope_entity(0x12), scope_entity(0x60)]),
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
        FederationScopeWorlds::Worlds(vec![scope_entity(0x60)]),
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
    let one_world = FederationScopeWorlds::Worlds(vec![scope_entity(0x60)]);
    let two_worlds = FederationScopeWorlds::Worlds(vec![scope_entity(0x60), scope_entity(0x12)]);
    assert!(FederationScopeWorlds::Base.is_narrowing_of(&one_world));
    assert!(one_world.is_narrowing_of(&two_worlds));
    assert!(!two_worlds.is_narrowing_of(&one_world));
    assert!(!FederationScopeWorlds::All.is_narrowing_of(&two_worlds));
    assert!(!one_world.is_narrowing_of(&FederationScopeWorlds::Base));
}

#[test]
fn federation_direction_scope_disjoint_meet_is_bottom_not_all() {
    let left = direction(
        FederationScopeWorlds::Worlds(vec![scope_entity(0x60)]),
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
