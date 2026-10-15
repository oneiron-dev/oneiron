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

// ---------------------------------------------------------------------------
// Strict codec
// ---------------------------------------------------------------------------

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
        ChannelIdentitySelectionError::MalformedRuleSet(_)
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
            ChannelIdentitySelectionError::MalformedRuleSet(_)
        ));
    }
    // `rmpv` reads the reserved marker as nil; a nil root is still not a map.
    assert!(matches!(
        decode_rule_set(&[0xC1]).expect_err("reserved marker"),
        ChannelIdentitySelectionError::MalformedRuleSet(_)
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
    let amended = vault
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
    let roster = face_roster();
    let decision = resolve_channel_identity_selection(
        &amended,
        query(RelationshipContext::SchedulingLogistics, &[], &roster),
    )
    .expect("amended scheduling default resolves");
    assert_eq!(decision.face, ChannelIdentityFace::HouseIdentity);
    assert_eq!(decision.identity_ref, entity(0x63));

    // The owner may retire even a locked builtin: disabled, never deleted.
    let law = vault
        .update_channel_identity_selection_rules(
            1,
            &owner_writer(),
            ChannelIdentitySelectionPatch::Upsert(shadow(false)),
        )
        .expect("owner disables the builtin");
    let mut targeted = law
        .rows
        .iter()
        .filter(|row| row.rule_id == "builtin.work_deal");
    let retired = targeted.next().expect("retired builtin remains present");
    assert!(targeted.next().is_none(), "shadow replaces the builtin");
    assert_eq!(retired.relationship, RelationshipContext::WorkDeal);
    assert!(retired.scope.is_vault_default());
    assert!(!retired.enabled);
    assert!(!retired.agent_amendable);
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
