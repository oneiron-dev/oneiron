use super::*;
use crate::config::VaultConfig;
use crate::test_util::{entity, open_test_vault_with};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn open_vault() -> (tempfile::TempDir, Vault) {
    open_test_vault_with(VaultConfig::device())
}

fn candidate(seed: u8, face: ChannelIdentityFace) -> ChannelIdentityCandidate {
    ChannelIdentityCandidate {
        identity_ref: entity(seed),
        shape: ChannelIdentityShape::DedicatedAddress,
        face,
        active: true,
    }
}

/// A candidate carried on the post-CID-1 fourth shape: an account the product
/// reads under a scoped grant and never mints.
fn delegated_candidate(seed: u8, face: ChannelIdentityFace) -> ChannelIdentityCandidate {
    ChannelIdentityCandidate {
        identity_ref: entity(seed),
        shape: ChannelIdentityShape::DelegatedGrant,
        face,
        active: true,
    }
}

/// One active candidate per face, so a query can only fail for policy reasons.
fn face_roster() -> Vec<ChannelIdentityCandidate> {
    vec![
        delegated_candidate(0x60, ChannelIdentityFace::DelegatedOwnerAccount),
        candidate(0x61, ChannelIdentityFace::AgentNamedAddress),
        candidate(0x62, ChannelIdentityFace::SideDomainAddress),
        candidate(0x63, ChannelIdentityFace::HouseIdentity),
        candidate(0x64, ChannelIdentityFace::CompanionIdentity),
        candidate(0x65, ChannelIdentityFace::NamedGroupParticipant),
    ]
}

fn face_seed(face: ChannelIdentityFace) -> u8 {
    match face {
        ChannelIdentityFace::DelegatedOwnerAccount => 0x60,
        ChannelIdentityFace::AgentNamedAddress => 0x61,
        ChannelIdentityFace::SideDomainAddress => 0x62,
        ChannelIdentityFace::HouseIdentity => 0x63,
        ChannelIdentityFace::CompanionIdentity => 0x64,
        ChannelIdentityFace::NamedGroupParticipant => 0x65,
    }
}

fn owner_writer() -> ChannelIdentitySelectionWriter {
    let actor = WriteActor::new(entity(0x66), EdgeActorClass::Human);
    ChannelIdentitySelectionWriter::from_authenticated_write(&actor).expect("owner writer")
}

fn agent_writer() -> ChannelIdentitySelectionWriter {
    let actor = WriteActor::new(entity(0x67), EdgeActorClass::Agent);
    ChannelIdentitySelectionWriter::from_authenticated_write(&actor).expect("agent writer")
}

/// A caller-authored row. `writer_kind`/`updated_by` are deliberately
/// mis-stamped here so the write door is seen to overwrite them.
fn authored_rule(
    rule_id: &str,
    relationship: RelationshipContext,
    scope: SelectionRuleScope,
    face: ChannelIdentityFace,
) -> ChannelIdentitySelectionRule {
    ChannelIdentitySelectionRule {
        rule_id: rule_id.to_owned(),
        relationship,
        scope,
        face,
        pinned_identity_ref: None,
        priority: 0,
        enabled: true,
        agent_amendable: true,
        updated_at: 10,
        updated_by: None,
        writer_kind: SelectionRuleWriterKind::SystemDefault,
    }
}

/// A row already stamped as an owner edit, for pure (non-vault) fixtures.
fn owner_rule(
    rule_id: &str,
    relationship: RelationshipContext,
    scope: SelectionRuleScope,
    face: ChannelIdentityFace,
) -> ChannelIdentitySelectionRule {
    ChannelIdentitySelectionRule {
        updated_by: Some(entity(0x66)),
        writer_kind: SelectionRuleWriterKind::Owner,
        ..authored_rule(rule_id, relationship, scope, face)
    }
}

fn stored_set(rows: Vec<ChannelIdentitySelectionRule>) -> ChannelIdentitySelectionRuleSet {
    ChannelIdentitySelectionRuleSet {
        schema_version: CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION,
        revision: 1,
        rows,
    }
}

fn compiled_with(rows: Vec<ChannelIdentitySelectionRule>) -> ChannelIdentitySelectionRuleSet {
    compile_channel_identity_selection(Some(&stored_set(rows))).expect("compiles")
}

fn query<'a>(
    relationship: RelationshipContext,
    scopes: &'a [SelectionRuleScope],
    candidates: &'a [ChannelIdentityCandidate],
) -> ChannelIdentitySelectionQuery<'a> {
    ChannelIdentitySelectionQuery {
        relationship,
        applicable_scopes: scopes,
        candidates,
        thread_pin: None,
    }
}

fn encode_value(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).expect("encode");
    bytes
}

fn map_entries(value: &mut Value) -> &mut Vec<(Value, Value)> {
    match value {
        Value::Map(entries) => entries,
        other => panic!("expected a map, got {other:?}"),
    }
}

fn entry_index(value: &Value, key: &str) -> usize {
    match value {
        Value::Map(entries) => entries
            .iter()
            .position(|(name, _)| name.as_str() == Some(key))
            .unwrap_or_else(|| panic!("missing key {key}")),
        other => panic!("expected a map, got {other:?}"),
    }
}

fn rows_array(value: &mut Value) -> &mut Vec<Value> {
    let index = entry_index(value, "rows");
    match &mut map_entries(value)[index].1 {
        Value::Array(rows) => rows,
        other => panic!("expected an array, got {other:?}"),
    }
}

fn set_rule_field(value: &mut Value, row: usize, key: &str, field: Value) {
    let rule = &mut rows_array(value)[row];
    let index = entry_index(rule, key);
    map_entries(rule)[index].1 = field;
}

/// The wire image of a stored set, as a mutable `rmpv` tree tests can corrupt.
fn stored_value(rows: Vec<ChannelIdentitySelectionRule>) -> Value {
    rule_set_value(&stored_set(rows))
}

fn assert_malformed(value: &Value) {
    let error = decode_rule_set(&encode_value(value)).expect_err("malformed record must fail");
    assert!(
        matches!(
            error,
            ChannelIdentitySelectionError::MalformedRuleSet(_)
                | ChannelIdentitySelectionError::MalformedScope
                | ChannelIdentitySelectionError::InvalidEntityRef
                | ChannelIdentitySelectionError::InvalidRule(_)
        ),
        "expected a typed decode failure, got {error:?}"
    );
}

fn poison_storage(vault: &Vault, bytes: &[u8]) {
    vault
        .with_write_txn(|wtxn| {
            vault
                .store
                .vault_meta
                .put(wtxn, CHANNEL_IDENTITY_SELECTION_KEY, bytes)
        })
        .expect("poison stored rule set");
}

// ---------------------------------------------------------------------------
// Compiled defaults
// ---------------------------------------------------------------------------

#[test]
fn compiled_defaults_are_the_six_canonical_rows() {
    let rows = builtin_channel_identity_selection_rules();
    let expected = [
        (
            "builtin.work_deal",
            RelationshipContext::WorkDeal,
            ChannelIdentityFace::DelegatedOwnerAccount,
            false,
        ),
        (
            "builtin.scheduling_logistics",
            RelationshipContext::SchedulingLogistics,
            ChannelIdentityFace::AgentNamedAddress,
            true,
        ),
        (
            "builtin.campaign_outreach",
            RelationshipContext::CampaignOutreach,
            ChannelIdentityFace::SideDomainAddress,
            true,
        ),
        (
            "builtin.transactional_system",
            RelationshipContext::TransactionalSystem,
            ChannelIdentityFace::HouseIdentity,
            true,
        ),
        (
            "builtin.personal_friends",
            RelationshipContext::PersonalFriends,
            ChannelIdentityFace::CompanionIdentity,
            false,
        ),
        (
            "builtin.group_space",
            RelationshipContext::GroupSpace,
            ChannelIdentityFace::NamedGroupParticipant,
            true,
        ),
    ];

    for (row, (rule_id, relationship, face, agent_amendable)) in rows.iter().zip(expected) {
        assert_eq!(row.rule_id, rule_id);
        assert_eq!(row.relationship, relationship);
        assert_eq!(row.face, face);
        assert_eq!(row.agent_amendable, agent_amendable);
        assert_eq!(row.scope, SelectionRuleScope::VaultDefault);
        assert_eq!(row.writer_kind, SelectionRuleWriterKind::SystemDefault);
        assert_eq!(row.updated_by, None);
        assert_eq!(row.pinned_identity_ref, None);
        assert_eq!(row.priority, 0);
        assert_eq!(row.updated_at, 0);
        assert!(row.enabled);
    }
    let compiled = compile_channel_identity_selection(None).expect("defaults compile");
    assert_eq!(compiled.revision, 0);
    assert_eq!(
        compiled.schema_version,
        CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION
    );
    assert_eq!(compiled.rows, rows.to_vec());
}

#[test]
fn compiled_defaults_encode_in_canonical_field_order() {
    let set = stored_set(builtin_channel_identity_selection_rules().to_vec());
    let bytes = encode_rule_set(&set).expect("defaults encode");

    // Hand-built wire image: the key order below IS the contract.
    let rows: Vec<Value> = set
        .rows
        .iter()
        .map(|row| {
            Value::Map(vec![
                (Value::from("rule_id"), Value::from(row.rule_id.as_str())),
                (
                    Value::from("relationship"),
                    Value::from(row.relationship.as_str()),
                ),
                (
                    Value::from("scope"),
                    Value::Map(vec![(Value::from("kind"), Value::from("vault_default"))]),
                ),
                (Value::from("face"), Value::from(row.face.as_str())),
                (Value::from("pinned_identity_ref"), Value::Nil),
                (Value::from("priority"), Value::from(0i32)),
                (Value::from("enabled"), Value::from(true)),
                (
                    Value::from("agent_amendable"),
                    Value::from(row.agent_amendable),
                ),
                (Value::from("updated_at"), Value::from(0u64)),
                (Value::from("updated_by"), Value::Nil),
                (Value::from("writer_kind"), Value::from("system_default")),
            ])
        })
        .collect();
    let expected = Value::Map(vec![
        (Value::from("schema_version"), Value::from(1u64)),
        (Value::from("revision"), Value::from(1u64)),
        (Value::from("rows"), Value::Array(rows)),
    ]);

    assert_eq!(bytes, encode_value(&expected));
    assert_eq!(decode_rule_set(&bytes).expect("round trip"), set);
}

#[test]
fn compiled_defaults_resolve_every_relationship_context() {
    let compiled = compile_channel_identity_selection(None).expect("defaults compile");
    let roster = face_roster();
    let expected = [
        (
            RelationshipContext::WorkDeal,
            ChannelIdentityFace::DelegatedOwnerAccount,
            "builtin.work_deal",
        ),
        (
            RelationshipContext::SchedulingLogistics,
            ChannelIdentityFace::AgentNamedAddress,
            "builtin.scheduling_logistics",
        ),
        (
            RelationshipContext::CampaignOutreach,
            ChannelIdentityFace::SideDomainAddress,
            "builtin.campaign_outreach",
        ),
        (
            RelationshipContext::TransactionalSystem,
            ChannelIdentityFace::HouseIdentity,
            "builtin.transactional_system",
        ),
        (
            RelationshipContext::PersonalFriends,
            ChannelIdentityFace::CompanionIdentity,
            "builtin.personal_friends",
        ),
        (
            RelationshipContext::GroupSpace,
            ChannelIdentityFace::NamedGroupParticipant,
            "builtin.group_space",
        ),
    ];

    for (relationship, face, rule_id) in expected {
        let decision =
            resolve_channel_identity_selection(&compiled, query(relationship, &[], &roster))
                .expect("default resolves");
        assert_eq!(decision.face, face);
        assert_eq!(decision.rule_id.as_deref(), Some(rule_id));
        assert_eq!(decision.identity_ref, entity(face_seed(face)));
        assert_eq!(decision.facet_ref, None);
        assert!(!decision.used_thread_pin);
    }
}

#[test]
fn wire_tokens_round_trip_for_every_axis() {
    for context in RelationshipContext::ALL {
        assert_eq!(RelationshipContext::parse(context.as_str()), Some(context));
    }
    for face in [
        ChannelIdentityFace::DelegatedOwnerAccount,
        ChannelIdentityFace::AgentNamedAddress,
        ChannelIdentityFace::SideDomainAddress,
        ChannelIdentityFace::HouseIdentity,
        ChannelIdentityFace::CompanionIdentity,
        ChannelIdentityFace::NamedGroupParticipant,
    ] {
        assert_eq!(ChannelIdentityFace::parse(face.as_str()), Some(face));
    }
    for kind in [
        SelectionRuleWriterKind::SystemDefault,
        SelectionRuleWriterKind::Owner,
        SelectionRuleWriterKind::Agent,
    ] {
        assert_eq!(SelectionRuleWriterKind::parse(kind.as_str()), Some(kind));
    }
    assert_eq!(RelationshipContext::parse("work_deals"), None);
    assert_eq!(ChannelIdentityFace::parse(""), None);
    assert_eq!(SelectionRuleWriterKind::parse("system"), None);
}

// ---------------------------------------------------------------------------
// Strict codec
// ---------------------------------------------------------------------------

fn every_scope_kind() -> Vec<SelectionRuleScope> {
    vec![
        SelectionRuleScope::VaultDefault,
        SelectionRuleScope::World {
            world_ref: entity(0x68),
        },
        SelectionRuleScope::Relationship {
            relationship_ref: entity(0x69),
        },
        SelectionRuleScope::Brief {
            brief_ref: "brief-01".to_owned(),
        },
        SelectionRuleScope::Space {
            space_ref: "space.alpha".to_owned(),
        },
    ]
}

#[test]
fn rule_set_round_trips_through_strict_messagepack() {
    let rows: Vec<ChannelIdentitySelectionRule> = every_scope_kind()
        .into_iter()
        .enumerate()
        .map(|(index, scope)| ChannelIdentitySelectionRule {
            priority: -3 + i32::try_from(index).expect("small index"),
            enabled: index % 2 == 0,
            agent_amendable: index % 3 == 0,
            updated_at: 900 + u64::try_from(index).expect("small index"),
            pinned_identity_ref: Some(entity(0x6A)),
            ..owner_rule(
                &format!("overlay.{index}"),
                RelationshipContext::WorkDeal,
                scope,
                ChannelIdentityFace::HouseIdentity,
            )
        })
        .collect();
    // Row 0 is the only VaultDefault row here and it is enabled, so the set has
    // exactly one canonical winner.
    let set = ChannelIdentitySelectionRuleSet {
        revision: 7,
        ..stored_set(rows)
    };

    let bytes = encode_rule_set(&set).expect("encodes");
    assert_eq!(decode_rule_set(&bytes).expect("decodes"), set);
}

#[test]
fn trailing_bytes_and_unknown_or_missing_keys_fail_typed() {
    let value = stored_value(vec![owner_rule(
        "overlay.a",
        RelationshipContext::WorkDeal,
        SelectionRuleScope::VaultDefault,
        ChannelIdentityFace::HouseIdentity,
    )]);

    let mut trailing = encode_value(&value);
    trailing.push(0xC0);
    assert!(matches!(
        decode_rule_set(&trailing).expect_err("trailing bytes"),
        ChannelIdentitySelectionError::MalformedRuleSet("trailing bytes after rule set map")
    ));

    let mut unknown = value.clone();
    map_entries(&mut unknown).push((Value::from("extra"), Value::from(1u64)));
    assert_malformed(&unknown);

    let mut unknown_rule_key = value.clone();
    let rule = &mut rows_array(&mut unknown_rule_key)[0];
    map_entries(rule).push((Value::from("extra"), Value::Nil));
    assert_malformed(&unknown_rule_key);

    let mut missing = value.clone();
    map_entries(&mut missing).pop();
    assert_malformed(&missing);

    let mut reordered = value.clone();
    map_entries(&mut reordered).swap(0, 1);
    assert_malformed(&reordered);

    let mut duplicated = value;
    let head = map_entries(&mut duplicated)[0].clone();
    map_entries(&mut duplicated)[1] = head;
    assert_malformed(&duplicated);

    assert_malformed(&Value::from("not a map"));
    // A truncated map header and an empty record are not MessagePack at all.
    for truncated in [&[0x81u8][..], &[][..]] {
        assert!(matches!(
            decode_rule_set(truncated).expect_err("not messagepack"),
            ChannelIdentitySelectionError::MalformedRuleSet("not valid MessagePack")
        ));
    }
    // `rmpv` reads the reserved marker as nil; a nil root is still not a map.
    assert!(matches!(
        decode_rule_set(&[0xC1]).expect_err("reserved marker"),
        ChannelIdentitySelectionError::MalformedRuleSet("rule set map")
    ));
}

#[test]
fn malformed_refs_and_scopes_fail_typed() {
    let base = stored_value(vec![owner_rule(
        "overlay.a",
        RelationshipContext::WorkDeal,
        SelectionRuleScope::VaultDefault,
        ChannelIdentityFace::HouseIdentity,
    )]);

    let mut short_ref = base.clone();
    set_rule_field(
        &mut short_ref,
        0,
        "updated_by",
        Value::Binary(vec![0x01; 8]),
    );
    assert_malformed(&short_ref);

    // The all-zero pattern is a reserved sentinel, never a live entity id.
    let mut sentinel = base.clone();
    set_rule_field(
        &mut sentinel,
        0,
        "pinned_identity_ref",
        Value::Binary(vec![0x00; 16]),
    );
    assert_malformed(&sentinel);

    let mut wrong_type = base.clone();
    set_rule_field(&mut wrong_type, 0, "updated_by", Value::from("owner"));
    assert_malformed(&wrong_type);

    let mut blank_brief = base.clone();
    set_rule_field(
        &mut blank_brief,
        0,
        "scope",
        Value::Map(vec![
            (Value::from("kind"), Value::from("brief")),
            (Value::from("brief_ref"), Value::from("")),
        ]),
    );
    assert_malformed(&blank_brief);

    let mut unknown_kind = base.clone();
    set_rule_field(
        &mut unknown_kind,
        0,
        "scope",
        Value::Map(vec![(Value::from("kind"), Value::from("galaxy"))]),
    );
    assert_malformed(&unknown_kind);

    let mut fat_default = base.clone();
    set_rule_field(
        &mut fat_default,
        0,
        "scope",
        Value::Map(vec![
            (Value::from("kind"), Value::from("vault_default")),
            (Value::from("world_ref"), Value::Binary(vec![0x6B; 16])),
        ]),
    );
    assert_malformed(&fat_default);

    let mut mismatched_payload = base.clone();
    set_rule_field(
        &mut mismatched_payload,
        0,
        "scope",
        Value::Map(vec![
            (Value::from("kind"), Value::from("world")),
            (Value::from("brief_ref"), Value::from("b")),
        ]),
    );
    assert_malformed(&mismatched_payload);

    let mut not_a_scope = base;
    set_rule_field(&mut not_a_scope, 0, "scope", Value::from("world"));
    assert_malformed(&not_a_scope);
}

#[test]
fn bad_enum_tokens_and_blank_or_mis_stamped_rows_fail_typed() {
    let base = stored_value(vec![owner_rule(
        "overlay.a",
        RelationshipContext::WorkDeal,
        SelectionRuleScope::VaultDefault,
        ChannelIdentityFace::HouseIdentity,
    )]);

    for (key, token) in [
        ("relationship", "work_deals"),
        ("face", "owner_account"),
        ("writer_kind", "root"),
    ] {
        let mut bad = base.clone();
        set_rule_field(&mut bad, 0, key, Value::from(token));
        assert_malformed(&bad);
    }

    let mut blank_id = base.clone();
    set_rule_field(&mut blank_id, 0, "rule_id", Value::from(""));
    assert_malformed(&blank_id);

    let mut spaced_id = base.clone();
    set_rule_field(&mut spaced_id, 0, "rule_id", Value::from("over lay"));
    assert_malformed(&spaced_id);

    // A system-default row that names a writer, and an owner row that does not:
    // both break the "only compiled law omits updated_by" stamp.
    let mut stamped_default = base.clone();
    set_rule_field(
        &mut stamped_default,
        0,
        "writer_kind",
        Value::from("system_default"),
    );
    assert_malformed(&stamped_default);

    let mut unstamped_owner = base.clone();
    set_rule_field(&mut unstamped_owner, 0, "updated_by", Value::Nil);
    assert_malformed(&unstamped_owner);

    let mut bad_priority = base.clone();
    set_rule_field(
        &mut bad_priority,
        0,
        "priority",
        Value::from(i64::from(i32::MAX) + 1),
    );
    assert_malformed(&bad_priority);

    let mut bad_enabled = base;
    set_rule_field(&mut bad_enabled, 0, "enabled", Value::from(1u64));
    assert_malformed(&bad_enabled);
}

#[test]
fn duplicate_rows_and_regressed_revisions_fail_typed() {
    let row = owner_rule(
        "overlay.a",
        RelationshipContext::WorkDeal,
        SelectionRuleScope::VaultDefault,
        ChannelIdentityFace::HouseIdentity,
    );

    let duplicate_ids = stored_set(vec![row.clone(), row.clone()]);
    assert!(matches!(
        encode_rule_set(&duplicate_ids).expect_err("duplicate ids"),
        ChannelIdentitySelectionError::DuplicateRuleId
    ));

    let duplicate_winners = stored_set(vec![
        row.clone(),
        ChannelIdentitySelectionRule {
            rule_id: "overlay.b".to_owned(),
            ..row.clone()
        },
    ]);
    assert!(matches!(
        encode_rule_set(&duplicate_winners).expect_err("duplicate canonical winner"),
        ChannelIdentitySelectionError::DuplicateCanonicalWinner
    ));

    // Revision 0 is reserved for the compiled defaults; a persisted record at
    // 0 has regressed below the floor it was written above.
    let regressed = ChannelIdentitySelectionRuleSet {
        revision: 0,
        ..stored_set(vec![row.clone()])
    };
    assert!(matches!(
        decode_rule_set(&encode_value(&rule_set_value(&regressed)))
            .expect_err("regressed revision"),
        ChannelIdentitySelectionError::RevisionRegressed {
            stored: 0,
            floor: 1
        }
    ));

    let wrong_schema = ChannelIdentitySelectionRuleSet {
        schema_version: 2,
        ..stored_set(vec![row])
    };
    assert!(matches!(
        decode_rule_set(&encode_value(&rule_set_value(&wrong_schema)))
            .expect_err("schema mismatch"),
        ChannelIdentitySelectionError::SchemaVersionMismatch {
            expected: 1,
            stored: 2
        }
    ));
}

#[test]
fn a_builtin_shadow_that_adds_a_second_canonical_winner_is_refused() {
    let clash = stored_set(vec![owner_rule(
        "overlay.clash",
        RelationshipContext::WorkDeal,
        SelectionRuleScope::VaultDefault,
        ChannelIdentityFace::HouseIdentity,
    )]);
    assert!(matches!(
        compile_channel_identity_selection(Some(&clash)).expect_err("clashes with the builtin"),
        ChannelIdentitySelectionError::DuplicateCanonicalWinner
    ));
}

// ---------------------------------------------------------------------------
// Precedence
// ---------------------------------------------------------------------------

#[test]
fn exact_scope_beats_vault_default() {
    let world = SelectionRuleScope::World {
        world_ref: entity(0x68),
    };
    let compiled = compiled_with(vec![owner_rule(
        "overlay.world",
        RelationshipContext::CampaignOutreach,
        world.clone(),
        ChannelIdentityFace::HouseIdentity,
    )]);
    let roster = face_roster();

    let scoped = resolve_channel_identity_selection(
        &compiled,
        query(RelationshipContext::CampaignOutreach, &[world], &roster),
    )
    .expect("scoped resolves");
    assert_eq!(scoped.face, ChannelIdentityFace::HouseIdentity);
    assert_eq!(scoped.rule_id.as_deref(), Some("overlay.world"));

    let unscoped = resolve_channel_identity_selection(
        &compiled,
        query(RelationshipContext::CampaignOutreach, &[], &roster),
    )
    .expect("default resolves");
    assert_eq!(unscoped.face, ChannelIdentityFace::SideDomainAddress);
    assert_eq!(
        unscoped.rule_id.as_deref(),
        Some("builtin.campaign_outreach")
    );
}

#[test]
fn the_most_specific_applicable_scope_wins() {
    let scopes = [
        SelectionRuleScope::World {
            world_ref: entity(0x68),
        },
        SelectionRuleScope::Space {
            space_ref: "space.alpha".to_owned(),
        },
        SelectionRuleScope::Brief {
            brief_ref: "brief-01".to_owned(),
        },
        SelectionRuleScope::Relationship {
            relationship_ref: entity(0x69),
        },
    ];
    let faces = [
        ChannelIdentityFace::HouseIdentity,
        ChannelIdentityFace::AgentNamedAddress,
        ChannelIdentityFace::CompanionIdentity,
        ChannelIdentityFace::DelegatedOwnerAccount,
    ];
    let rows: Vec<ChannelIdentitySelectionRule> = scopes
        .iter()
        .zip(faces)
        .enumerate()
        .map(|(index, (scope, face))| {
            owner_rule(
                &format!("overlay.s{index}"),
                RelationshipContext::GroupSpace,
                scope.clone(),
                face,
            )
        })
        .collect();
    let compiled = compiled_with(rows);
    let roster = face_roster();

    // Narrow each time the broader key is withdrawn: relationship, then brief,
    // then space, then world, then the compiled default.
    let expected = [
        (4usize, ChannelIdentityFace::DelegatedOwnerAccount),
        (3, ChannelIdentityFace::CompanionIdentity),
        (2, ChannelIdentityFace::AgentNamedAddress),
        (1, ChannelIdentityFace::HouseIdentity),
        (0, ChannelIdentityFace::NamedGroupParticipant),
    ];
    for (count, face) in expected {
        let decision = resolve_channel_identity_selection(
            &compiled,
            query(RelationshipContext::GroupSpace, &scopes[..count], &roster),
        )
        .expect("resolves");
        assert_eq!(decision.face, face, "with {count} applicable scopes");
    }
}

#[test]
fn precedence_is_deterministic_and_order_independent() {
    let world = SelectionRuleScope::World {
        world_ref: entity(0x68),
    };
    let low = owner_rule(
        "overlay.a-low",
        RelationshipContext::WorkDeal,
        world.clone(),
        ChannelIdentityFace::HouseIdentity,
    );
    let high = ChannelIdentitySelectionRule {
        priority: 5,
        face: ChannelIdentityFace::AgentNamedAddress,
        ..owner_rule(
            "overlay.b-high",
            RelationshipContext::WorkDeal,
            world.clone(),
            ChannelIdentityFace::AgentNamedAddress,
        )
    };
    // Same priority as `high`, but stamped later.
    let later = ChannelIdentitySelectionRule {
        priority: 5,
        updated_at: 99,
        ..owner_rule(
            "overlay.c-later",
            RelationshipContext::WorkDeal,
            world.clone(),
            ChannelIdentityFace::SideDomainAddress,
        )
    };
    // Same priority AND timestamp as `later`; only the id can break the tie,
    // and the lexically smallest id wins.
    let twin = ChannelIdentitySelectionRule {
        priority: 5,
        updated_at: 99,
        ..owner_rule(
            "overlay.b-twin",
            RelationshipContext::WorkDeal,
            world.clone(),
            ChannelIdentityFace::CompanionIdentity,
        )
    };
    let roster = face_roster();
    let scopes = [world];

    let faces = |rows: Vec<ChannelIdentitySelectionRule>| {
        let compiled = compiled_with(rows);
        resolve_channel_identity_selection(
            &compiled,
            query(RelationshipContext::WorkDeal, &scopes, &roster),
        )
        .expect("resolves")
        .face
    };

    assert_eq!(
        faces(vec![low.clone(), high.clone()]),
        ChannelIdentityFace::AgentNamedAddress
    );
    assert_eq!(
        faces(vec![high.clone(), low.clone()]),
        ChannelIdentityFace::AgentNamedAddress
    );
    assert_eq!(
        faces(vec![low.clone(), high.clone(), later.clone()]),
        ChannelIdentityFace::SideDomainAddress
    );
    assert_eq!(
        faces(vec![later.clone(), high.clone(), low.clone()]),
        ChannelIdentityFace::SideDomainAddress
    );
    assert_eq!(
        faces(vec![low.clone(), later.clone(), twin.clone()]),
        ChannelIdentityFace::CompanionIdentity
    );
    assert_eq!(
        faces(vec![twin, later, high, low]),
        ChannelIdentityFace::CompanionIdentity
    );
}

#[test]
fn disabled_rows_are_inert() {
    let world = SelectionRuleScope::World {
        world_ref: entity(0x68),
    };
    let disabled_exact = ChannelIdentitySelectionRule {
        enabled: false,
        priority: 100,
        ..owner_rule(
            "overlay.off",
            RelationshipContext::WorkDeal,
            world.clone(),
            ChannelIdentityFace::HouseIdentity,
        )
    };
    // A second vault-default row for the same context — inert, so it is not a
    // duplicate canonical winner either.
    let disabled_default = ChannelIdentitySelectionRule {
        enabled: false,
        ..owner_rule(
            "overlay.shadow",
            RelationshipContext::WorkDeal,
            SelectionRuleScope::VaultDefault,
            ChannelIdentityFace::CompanionIdentity,
        )
    };
    let compiled = compiled_with(vec![disabled_exact, disabled_default]);
    let roster = face_roster();

    let decision = resolve_channel_identity_selection(
        &compiled,
        query(RelationshipContext::WorkDeal, &[world], &roster),
    )
    .expect("resolves");
    assert_eq!(decision.face, ChannelIdentityFace::DelegatedOwnerAccount);
    assert_eq!(decision.rule_id.as_deref(), Some("builtin.work_deal"));
}

// ---------------------------------------------------------------------------
// Candidates
// ---------------------------------------------------------------------------

#[test]
fn a_relationship_with_no_row_fails_closed() {
    let empty = ChannelIdentitySelectionRuleSet {
        schema_version: CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION,
        revision: 0,
        rows: Vec::new(),
    };
    let roster = face_roster();
    assert!(matches!(
        resolve_channel_identity_selection(
            &empty,
            query(RelationshipContext::WorkDeal, &[], &roster)
        )
        .expect_err("no row"),
        ChannelIdentitySelectionError::NoRuleForRelationship
    ));
}

#[test]
fn a_face_with_no_active_candidate_never_falls_through() {
    let compiled = compile_channel_identity_selection(None).expect("defaults");
    let mut roster = face_roster();
    // Retire the side-domain face; the owner's delegated account stays active
    // and must NOT be reached for.
    roster[2].active = false;

    let error = resolve_channel_identity_selection(
        &compiled,
        query(RelationshipContext::CampaignOutreach, &[], &roster),
    )
    .expect_err("unresolved");
    assert!(matches!(
        error,
        ChannelIdentitySelectionError::NoCandidateForFace
    ));

    let missing = [candidate(0x61, ChannelIdentityFace::AgentNamedAddress)];
    assert!(matches!(
        resolve_channel_identity_selection(
            &compiled,
            query(RelationshipContext::WorkDeal, &[], &missing)
        )
        .expect_err("unresolved"),
        ChannelIdentitySelectionError::NoCandidateForFace
    ));
}

#[test]
fn same_face_candidates_tie_break_by_stable_id_order() {
    let compiled = compile_channel_identity_selection(None).expect("defaults");
    let roster = vec![
        candidate(0x6C, ChannelIdentityFace::HouseIdentity),
        candidate(0x63, ChannelIdentityFace::HouseIdentity),
        ChannelIdentityCandidate {
            active: false,
            ..candidate(0x61, ChannelIdentityFace::HouseIdentity)
        },
    ];
    let decision = resolve_channel_identity_selection(
        &compiled,
        query(RelationshipContext::TransactionalSystem, &[], &roster),
    )
    .expect("resolves");
    // Lowest id among the ACTIVE same-face candidates.
    assert_eq!(decision.identity_ref, entity(0x63));

    let reversed: Vec<ChannelIdentityCandidate> = roster.into_iter().rev().collect();
    let again = resolve_channel_identity_selection(
        &compiled,
        query(RelationshipContext::TransactionalSystem, &[], &reversed),
    )
    .expect("resolves");
    assert_eq!(again.identity_ref, entity(0x63));
}

#[test]
fn duplicate_candidates_fail_typed() {
    let compiled = compile_channel_identity_selection(None).expect("defaults");
    let roster = vec![
        candidate(0x63, ChannelIdentityFace::HouseIdentity),
        candidate(0x63, ChannelIdentityFace::SideDomainAddress),
    ];
    assert!(matches!(
        resolve_channel_identity_selection(
            &compiled,
            query(RelationshipContext::TransactionalSystem, &[], &roster)
        )
        .expect_err("duplicate candidate"),
        ChannelIdentitySelectionError::DuplicateCandidate
    ));
}

#[test]
fn a_malformed_query_scope_fails_typed() {
    let compiled = compile_channel_identity_selection(None).expect("defaults");
    let roster = face_roster();
    let scopes = [SelectionRuleScope::Brief {
        brief_ref: String::new(),
    }];
    assert!(matches!(
        resolve_channel_identity_selection(
            &compiled,
            query(RelationshipContext::WorkDeal, &scopes, &roster)
        )
        .expect_err("blank brief ref"),
        ChannelIdentitySelectionError::MalformedScope
    ));
}

// ---------------------------------------------------------------------------
// Row-level exact-identity override
// ---------------------------------------------------------------------------

#[test]
fn a_row_pinned_identity_is_validated_against_the_candidates() {
    let world = SelectionRuleScope::World {
        world_ref: entity(0x68),
    };
    let pinned_row = |identity: EntityId, face: ChannelIdentityFace| ChannelIdentitySelectionRule {
        pinned_identity_ref: Some(identity),
        ..owner_rule(
            "overlay.pin",
            RelationshipContext::CampaignOutreach,
            world.clone(),
            face,
        )
    };
    let scopes = [world.clone()];
    let roster = face_roster();

    let compiled = compiled_with(vec![pinned_row(
        entity(0x60),
        ChannelIdentityFace::DelegatedOwnerAccount,
    )]);
    let decision = resolve_channel_identity_selection(
        &compiled,
        query(RelationshipContext::CampaignOutreach, &scopes, &roster),
    )
    .expect("pinned row resolves");
    assert_eq!(decision.identity_ref, entity(0x60));
    assert_eq!(decision.face, ChannelIdentityFace::DelegatedOwnerAccount);

    let absent = compiled_with(vec![pinned_row(
        entity(0x6D),
        ChannelIdentityFace::DelegatedOwnerAccount,
    )]);
    assert!(matches!(
        resolve_channel_identity_selection(
            &absent,
            query(RelationshipContext::CampaignOutreach, &scopes, &roster)
        )
        .expect_err("pinned identity absent"),
        ChannelIdentitySelectionError::PinnedCandidateMissing
    ));

    let mut retired = face_roster();
    retired[0].active = false;
    assert!(matches!(
        resolve_channel_identity_selection(
            &compiled,
            query(RelationshipContext::CampaignOutreach, &scopes, &retired)
        )
        .expect_err("pinned identity inactive"),
        ChannelIdentitySelectionError::PinnedCandidateInactive
    ));

    // The row names an identity AND a face; a candidate that disagrees is a
    // contradiction, not a licence to switch faces.
    let mismatched = compiled_with(vec![pinned_row(
        entity(0x60),
        ChannelIdentityFace::SideDomainAddress,
    )]);
    assert!(matches!(
        resolve_channel_identity_selection(
            &mismatched,
            query(RelationshipContext::CampaignOutreach, &scopes, &roster)
        )
        .expect_err("face mismatch"),
        ChannelIdentitySelectionError::PinnedCandidateFaceMismatch
    ));
}

// ---------------------------------------------------------------------------
// Thread pins (ONE-1827 input)
// ---------------------------------------------------------------------------

#[test]
fn a_valid_thread_pin_wins_before_every_mutable_row() {
    let world = SelectionRuleScope::World {
        world_ref: entity(0x68),
    };
    let compiled = compiled_with(vec![ChannelIdentitySelectionRule {
        priority: 100,
        ..owner_rule(
            "overlay.loud",
            RelationshipContext::CampaignOutreach,
            world.clone(),
            ChannelIdentityFace::HouseIdentity,
        )
    }]);
    let roster = face_roster();
    let pin = ChannelIdentityThreadPin {
        thread_ref: "thread-0001".to_owned(),
        identity_ref: entity(0x61),
        facet_ref: Some(entity(0x6E)),
    };

    let decision = resolve_channel_identity_selection(
        &compiled,
        ChannelIdentitySelectionQuery {
            relationship: RelationshipContext::CampaignOutreach,
            applicable_scopes: &[world],
            candidates: &roster,
            thread_pin: Some(&pin),
        },
    )
    .expect("pin resolves");

    assert!(decision.used_thread_pin);
    assert_eq!(decision.identity_ref, entity(0x61));
    assert_eq!(decision.facet_ref, Some(entity(0x6E)));
    assert_eq!(decision.face, ChannelIdentityFace::AgentNamedAddress);
    assert_eq!(decision.rule_id, None);
}

#[test]
fn a_missing_inactive_or_malformed_pin_fails_typed() {
    let compiled = compile_channel_identity_selection(None).expect("defaults");
    let roster = face_roster();
    let resolve = |pin: &ChannelIdentityThreadPin, candidates: &[ChannelIdentityCandidate]| {
        resolve_channel_identity_selection(
            &compiled,
            ChannelIdentitySelectionQuery {
                relationship: RelationshipContext::CampaignOutreach,
                applicable_scopes: &[],
                candidates,
                thread_pin: Some(pin),
            },
        )
    };

    let missing = ChannelIdentityThreadPin {
        thread_ref: "thread-0001".to_owned(),
        identity_ref: entity(0x6D),
        facet_ref: None,
    };
    assert!(matches!(
        resolve(&missing, &roster).expect_err("pin missing"),
        ChannelIdentitySelectionError::PinnedCandidateMissing
    ));

    let mut retired = face_roster();
    retired[1].active = false;
    let inactive = ChannelIdentityThreadPin {
        identity_ref: entity(0x61),
        ..missing
    };
    assert!(matches!(
        resolve(&inactive, &retired).expect_err("pin inactive"),
        ChannelIdentitySelectionError::PinnedCandidateInactive
    ));

    let blank = ChannelIdentityThreadPin {
        thread_ref: String::new(),
        ..inactive
    };
    assert!(matches!(
        resolve(&blank, &roster).expect_err("pin malformed"),
        ChannelIdentitySelectionError::MalformedThreadPin
    ));
}

// ---------------------------------------------------------------------------
// Writers and the compare-and-swap door
// ---------------------------------------------------------------------------

#[test]
fn writer_kind_is_derived_from_the_authenticated_actor() {
    assert_eq!(owner_writer().kind(), SelectionRuleWriterKind::Owner);
    assert_eq!(owner_writer().actor_ref(), entity(0x66));
    assert_eq!(agent_writer().kind(), SelectionRuleWriterKind::Agent);

    let system = WriteActor::new(entity(0x6F), EdgeActorClass::System);
    assert!(matches!(
        ChannelIdentitySelectionWriter::from_authenticated_write(&system)
            .expect_err("system refused"),
        ChannelIdentitySelectionError::WriterClassNotAmendable
    ));
}

#[test]
fn accepted_changes_stamp_the_actor_and_advance_one_revision() {
    let (dir, vault) = open_vault();

    let fresh = vault.channel_identity_selection_rules().expect("fresh law");
    assert_eq!(fresh.revision, 0);
    assert_eq!(
        fresh.rows,
        builtin_channel_identity_selection_rules().to_vec()
    );
    assert_eq!(
        vault
            .stored_channel_identity_selection_rules()
            .expect("stored"),
        None
    );

    let world = SelectionRuleScope::World {
        world_ref: entity(0x68),
    };
    let updated = vault
        .update_channel_identity_selection_rules(
            0,
            &owner_writer(),
            ChannelIdentitySelectionPatch::Upsert(authored_rule(
                "overlay.world",
                RelationshipContext::CampaignOutreach,
                world,
                ChannelIdentityFace::HouseIdentity,
            )),
        )
        .expect("owner write lands");

    assert_eq!(updated.revision, 1);
    let row = updated
        .rows
        .iter()
        .find(|row| row.rule_id == "overlay.world")
        .expect("row present");
    // The caller mis-stamped both provenance fields; the door derived them.
    assert_eq!(row.writer_kind, SelectionRuleWriterKind::Owner);
    assert_eq!(row.updated_by, Some(entity(0x66)));

    let reread = vault.channel_identity_selection_rules().expect("reread");
    assert_eq!(reread, updated);
    let stored = vault
        .stored_channel_identity_selection_rules()
        .expect("stored")
        .expect("overlay persisted");
    assert_eq!(stored.revision, 1);
    assert_eq!(stored.rows.len(), 1, "only the overlay row is persisted");

    // Exactly one revision per accepted change.
    let second = vault
        .update_channel_identity_selection_rules(
            1,
            &owner_writer(),
            ChannelIdentitySelectionPatch::Remove {
                rule_id: "overlay.world".to_owned(),
            },
        )
        .expect("owner removal lands");
    assert_eq!(second.revision, 2);
    assert_eq!(
        second.rows,
        builtin_channel_identity_selection_rules().to_vec()
    );

    drop(vault);
    drop(dir);
}

#[test]
fn stale_expected_revisions_fail_compare_and_swap() {
    let (dir, vault) = open_vault();
    let patch = || {
        ChannelIdentitySelectionPatch::Upsert(authored_rule(
            "overlay.a",
            RelationshipContext::CampaignOutreach,
            SelectionRuleScope::Space {
                space_ref: "space.alpha".to_owned(),
            },
            ChannelIdentityFace::HouseIdentity,
        ))
    };

    assert!(matches!(
        vault
            .update_channel_identity_selection_rules(7, &owner_writer(), patch())
            .expect_err("stale expectation"),
        ChannelIdentitySelectionError::RevisionConflict {
            expected: 7,
            stored: 0
        }
    ));

    vault
        .update_channel_identity_selection_rules(0, &owner_writer(), patch())
        .expect("first write");
    assert!(matches!(
        vault
            .update_channel_identity_selection_rules(0, &owner_writer(), patch())
            .expect_err("replayed expectation"),
        ChannelIdentitySelectionError::RevisionConflict {
            expected: 0,
            stored: 1
        }
    ));
    assert_eq!(
        vault
            .channel_identity_selection_rules()
            .expect("law")
            .revision,
        1,
        "a refused write advances nothing"
    );

    drop(vault);
    drop(dir);
}

#[test]
fn owner_may_lock_a_row_that_the_agent_then_cannot_touch() {
    let (dir, vault) = open_vault();
    let space = SelectionRuleScope::Space {
        space_ref: "space.alpha".to_owned(),
    };
    let row = |agent_amendable: bool, face: ChannelIdentityFace| ChannelIdentitySelectionRule {
        agent_amendable,
        ..authored_rule(
            "overlay.shared",
            RelationshipContext::GroupSpace,
            space.clone(),
            face,
        )
    };

    vault
        .update_channel_identity_selection_rules(
            0,
            &owner_writer(),
            ChannelIdentitySelectionPatch::Upsert(row(true, ChannelIdentityFace::HouseIdentity)),
        )
        .expect("owner seeds an amendable row");

    let amended = vault
        .update_channel_identity_selection_rules(
            1,
            &agent_writer(),
            ChannelIdentitySelectionPatch::Upsert(row(
                true,
                ChannelIdentityFace::AgentNamedAddress,
            )),
        )
        .expect("agent amends an amendable row");
    let row_after = amended
        .rows
        .iter()
        .find(|candidate| candidate.rule_id == "overlay.shared")
        .expect("row present");
    assert_eq!(row_after.writer_kind, SelectionRuleWriterKind::Agent);
    assert_eq!(row_after.updated_by, Some(entity(0x67)));

    vault
        .update_channel_identity_selection_rules(
            2,
            &owner_writer(),
            ChannelIdentitySelectionPatch::Upsert(row(false, ChannelIdentityFace::HouseIdentity)),
        )
        .expect("owner locks the row");

    assert!(matches!(
        vault
            .update_channel_identity_selection_rules(
                3,
                &agent_writer(),
                ChannelIdentitySelectionPatch::Upsert(row(
                    true,
                    ChannelIdentityFace::SideDomainAddress
                )),
            )
            .expect_err("locked row"),
        ChannelIdentitySelectionError::RuleNotAgentAmendable
    ));
    assert!(matches!(
        vault
            .update_channel_identity_selection_rules(
                3,
                &agent_writer(),
                ChannelIdentitySelectionPatch::Remove {
                    rule_id: "overlay.shared".to_owned()
                },
            )
            .expect_err("locked row"),
        ChannelIdentitySelectionError::RuleNotAgentAmendable
    ));

    // The owner is never blocked.
    vault
        .update_channel_identity_selection_rules(
            3,
            &owner_writer(),
            ChannelIdentitySelectionPatch::Remove {
                rule_id: "overlay.shared".to_owned(),
            },
        )
        .expect("owner removes the locked row");

    drop(vault);
    drop(dir);
}

#[test]
fn an_agent_writer_cannot_mint_or_leave_a_locked_row() {
    let (dir, vault) = open_vault();
    let locked = ChannelIdentitySelectionRule {
        agent_amendable: false,
        ..authored_rule(
            "overlay.locked",
            RelationshipContext::GroupSpace,
            SelectionRuleScope::Space {
                space_ref: "space.alpha".to_owned(),
            },
            ChannelIdentityFace::HouseIdentity,
        )
    };

    assert!(matches!(
        vault
            .update_channel_identity_selection_rules(
                0,
                &agent_writer(),
                ChannelIdentitySelectionPatch::Upsert(locked),
            )
            .expect_err("agent minting a locked row"),
        ChannelIdentitySelectionError::AgentCannotLockRule
    ));
    assert_eq!(
        vault
            .stored_channel_identity_selection_rules()
            .expect("stored"),
        None
    );

    drop(vault);
    drop(dir);
}

#[test]
fn agents_cannot_amend_a_locked_builtin_but_owners_can() {
    let (dir, vault) = open_vault();
    let shadow = |agent_amendable: bool| ChannelIdentitySelectionRule {
        agent_amendable,
        enabled: false,
        ..authored_rule(
            "builtin.work_deal",
            RelationshipContext::WorkDeal,
            SelectionRuleScope::VaultDefault,
            ChannelIdentityFace::DelegatedOwnerAccount,
        )
    };

    assert!(matches!(
        vault
            .update_channel_identity_selection_rules(
                0,
                &agent_writer(),
                ChannelIdentitySelectionPatch::Upsert(shadow(true)),
            )
            .expect_err("locked builtin"),
        ChannelIdentitySelectionError::RuleNotAgentAmendable
    ));

    // An amendable builtin is fair game for an agent.
    vault
        .update_channel_identity_selection_rules(
            0,
            &agent_writer(),
            ChannelIdentitySelectionPatch::Upsert(ChannelIdentitySelectionRule {
                face: ChannelIdentityFace::HouseIdentity,
                ..authored_rule(
                    "builtin.scheduling_logistics",
                    RelationshipContext::SchedulingLogistics,
                    SelectionRuleScope::VaultDefault,
                    ChannelIdentityFace::HouseIdentity,
                )
            }),
        )
        .expect("agent amends an amendable builtin");

    // The owner may retire even a locked builtin: disabled, never deleted.
    let law = vault
        .update_channel_identity_selection_rules(
            1,
            &owner_writer(),
            ChannelIdentitySelectionPatch::Upsert(shadow(false)),
        )
        .expect("owner disables the builtin");
    assert_eq!(
        law.rows.len(),
        6,
        "the shadow replaces the builtin in place"
    );
    let roster = face_roster();
    assert!(matches!(
        resolve_channel_identity_selection(
            &law,
            query(RelationshipContext::WorkDeal, &[], &roster)
        )
        .expect_err("retired context"),
        ChannelIdentitySelectionError::NoRuleForRelationship
    ));

    drop(vault);
    drop(dir);
}

#[test]
fn builtins_are_not_removable_and_unknown_rows_are_not_found() {
    let (dir, vault) = open_vault();

    assert!(matches!(
        vault
            .update_channel_identity_selection_rules(
                0,
                &owner_writer(),
                ChannelIdentitySelectionPatch::Remove {
                    rule_id: "builtin.work_deal".to_owned()
                },
            )
            .expect_err("builtin removal"),
        ChannelIdentitySelectionError::BuiltinRuleNotRemovable
    ));
    assert!(matches!(
        vault
            .update_channel_identity_selection_rules(
                0,
                &owner_writer(),
                ChannelIdentitySelectionPatch::Remove {
                    rule_id: "overlay.nope".to_owned()
                },
            )
            .expect_err("unknown removal"),
        ChannelIdentitySelectionError::RuleNotFound
    ));

    // Removing an overlay shadow reverts to the compiled builtin.
    vault
        .update_channel_identity_selection_rules(
            0,
            &owner_writer(),
            ChannelIdentitySelectionPatch::Upsert(ChannelIdentitySelectionRule {
                face: ChannelIdentityFace::HouseIdentity,
                ..authored_rule(
                    "builtin.group_space",
                    RelationshipContext::GroupSpace,
                    SelectionRuleScope::VaultDefault,
                    ChannelIdentityFace::HouseIdentity,
                )
            }),
        )
        .expect("owner shadows a builtin");
    let reverted = vault
        .update_channel_identity_selection_rules(
            1,
            &owner_writer(),
            ChannelIdentitySelectionPatch::Remove {
                rule_id: "builtin.group_space".to_owned(),
            },
        )
        .expect("owner drops the shadow");
    assert_eq!(
        reverted.rows,
        builtin_channel_identity_selection_rules().to_vec()
    );

    drop(vault);
    drop(dir);
}

#[test]
fn an_amendment_that_would_make_the_law_ambiguous_is_refused() {
    let (dir, vault) = open_vault();
    assert!(matches!(
        vault
            .update_channel_identity_selection_rules(
                0,
                &owner_writer(),
                ChannelIdentitySelectionPatch::Upsert(authored_rule(
                    "overlay.second_winner",
                    RelationshipContext::WorkDeal,
                    SelectionRuleScope::VaultDefault,
                    ChannelIdentityFace::HouseIdentity,
                )),
            )
            .expect_err("second canonical winner"),
        ChannelIdentitySelectionError::DuplicateCanonicalWinner
    ));
    assert_eq!(
        vault
            .stored_channel_identity_selection_rules()
            .expect("stored"),
        None,
        "the refused write rolled back"
    );

    drop(vault);
    drop(dir);
}

#[test]
fn a_corrupt_stored_rule_set_fails_typed_rather_than_resolving() {
    let (dir, vault) = open_vault();

    poison_storage(&vault, b"not messagepack at all");
    assert!(matches!(
        vault
            .channel_identity_selection_rules()
            .expect_err("corrupt"),
        ChannelIdentitySelectionError::MalformedRuleSet(_)
    ));

    let regressed = ChannelIdentitySelectionRuleSet {
        revision: 0,
        ..stored_set(Vec::new())
    };
    poison_storage(&vault, &encode_value(&rule_set_value(&regressed)));
    assert!(matches!(
        vault
            .channel_identity_selection_rules()
            .expect_err("regressed"),
        ChannelIdentitySelectionError::RevisionRegressed { .. }
    ));
    // A corrupt record blocks the write door too; it never silently resets.
    assert!(
        vault
            .update_channel_identity_selection_rules(
                1,
                &owner_writer(),
                ChannelIdentitySelectionPatch::Remove {
                    rule_id: "overlay.a".to_owned()
                },
            )
            .is_err()
    );

    drop(vault);
    drop(dir);
}

// ---------------------------------------------------------------------------
// Worked example — world-scoped delegated outreach
// ---------------------------------------------------------------------------

/// The outreach world.
fn outreach_world() -> EntityId {
    entity(0x70)
}

/// The delegated owner mailbox: an account the product reads under a
/// scoped grant and never mints.
fn owner_delegated_identity() -> EntityId {
    entity(0x71)
}

#[test]
fn world_campaign_outreach_sends_as_owners_delegated_identity() {
    let (dir, vault) = open_vault();
    let world = SelectionRuleScope::World {
        world_ref: outreach_world(),
    };

    let law = vault
        .update_channel_identity_selection_rules(
            0,
            &owner_writer(),
            ChannelIdentitySelectionPatch::Upsert(ChannelIdentitySelectionRule {
                pinned_identity_ref: Some(owner_delegated_identity()),
                ..authored_rule(
                    "overlay.world.campaign_outreach",
                    RelationshipContext::CampaignOutreach,
                    world.clone(),
                    ChannelIdentityFace::DelegatedOwnerAccount,
                )
            }),
        )
        .expect("owner pins the world override");

    let roster = vec![
        candidate(0x62, ChannelIdentityFace::SideDomainAddress),
        delegated_candidate(0x71, ChannelIdentityFace::DelegatedOwnerAccount),
    ];

    let inside = resolve_channel_identity_selection(
        &law,
        query(RelationshipContext::CampaignOutreach, &[world], &roster),
    )
    .expect("override resolves");
    assert_eq!(inside.identity_ref, owner_delegated_identity());
    assert_eq!(inside.face, ChannelIdentityFace::DelegatedOwnerAccount);
    assert_eq!(inside.shape, ChannelIdentityShape::DelegatedGrant);
    assert_eq!(
        inside.rule_id.as_deref(),
        Some("overlay.world.campaign_outreach")
    );

    // Outside that world the side-domain default still holds.
    let outside = resolve_channel_identity_selection(
        &law,
        query(RelationshipContext::CampaignOutreach, &[], &roster),
    )
    .expect("default resolves");
    assert_eq!(outside.identity_ref, entity(0x62));
    assert_eq!(outside.face, ChannelIdentityFace::SideDomainAddress);
    assert_eq!(outside.shape, ChannelIdentityShape::DedicatedAddress);

    drop(vault);
    drop(dir);
}

#[test]
fn the_selection_module_carries_no_venture_or_person_names() {
    let source = include_str!("../channel_identity_selection.rs").to_ascii_lowercase();
    // Substring matches, so every token here must be one that cannot appear
    // inside an ordinary English word.
    for banned in [
        "client_name",
        "person_name",
        "product_name",
        "assistant_name",
        "provider_name",
        "mail_provider",
        "social_network",
        "@",
        "http",
    ] {
        assert!(
            !source.contains(banned),
            "shipped selection module must not name {banned}"
        );
    }
}
