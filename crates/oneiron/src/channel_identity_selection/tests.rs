//! Selection-law tests (INB-01).
//!
//! Every venture, person, and product name in this lane lives here and only
//! here: the module under test is name-free by construction, and the worked
//! override from the design doc (an Antevon-world campaign row pinning the
//! delegated-owner face used for Yura's mailbox) is a fixture, not a default.

use super::*;

use crate::config::VaultConfig;
use crate::test_util::{entity, open_test_vault_with};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn test_vault() -> (tempfile::TempDir, Vault) {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    open_test_vault_with(cfg)
}

fn candidate(seed: u8, face: ChannelIdentityFace) -> ChannelIdentityCandidate {
    ChannelIdentityCandidate {
        identity_ref: entity(seed),
        shape: ChannelIdentityShape::DedicatedAddress,
        face,
        facet_ref: None,
        active: true,
    }
}

/// One live candidate per face, so a resolution failure is never a fixture gap.
fn face_roster() -> Vec<ChannelIdentityCandidate> {
    ChannelIdentityFace::ALL
        .into_iter()
        .enumerate()
        .map(|(index, face)| {
            let offset = u8::try_from(index).expect("six faces fit a u8");
            candidate(0x60 + offset, face)
        })
        .collect()
}

fn owner_writer() -> SelectionWriter {
    SelectionWriter::from_authenticated_write(WriteActor::new(entity(0x70), EdgeActorClass::Human))
        .expect("a human actor derives an owner writer")
}

fn agent_writer() -> SelectionWriter {
    SelectionWriter::from_authenticated_write(WriteActor::new(entity(0x71), EdgeActorClass::Agent))
        .expect("an agent actor derives an agent writer")
}

fn amendment(
    rule_id: &str,
    context: RelationshipContext,
    scope: SelectionRuleScope,
    face: ChannelIdentityFace,
) -> SelectionRuleAmendment {
    SelectionRuleAmendment {
        rule_id: rule_id.to_owned(),
        context,
        scope,
        face,
        priority: 0,
        agent_amendable: true,
        updated_at: 1_800_000_000,
    }
}

fn scoped_rule(
    rule_id: &str,
    scope: SelectionRuleScope,
    face: ChannelIdentityFace,
    priority: u32,
    updated_at: u64,
) -> SelectionRule {
    SelectionRule {
        rule_id: rule_id.to_owned(),
        context: RelationshipContext::CampaignOutreach,
        scope,
        face,
        priority,
        agent_amendable: true,
        updated_at,
        updated_by: Some(entity(0x70)),
        writer_kind: SelectionWriterKind::Owner,
    }
}

// ---------------------------------------------------------------------------
// MessagePack surgery helpers
// ---------------------------------------------------------------------------

fn encoded_defaults() -> Vec<u8> {
    encode_selection_rule_set(&SelectionRuleSet::compiled_defaults())
        .expect("compiled defaults encode")
}

fn rule_set_value() -> Value {
    let bytes = encoded_defaults();
    let mut cursor = Cursor::new(bytes.as_slice());
    rmpv::decode::read_value(&mut cursor).expect("compiled defaults are valid MessagePack")
}

fn encode_value(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).expect("fixture value encodes");
    out
}

fn map_entries(value: &mut Value) -> &mut Vec<(Value, Value)> {
    match value {
        Value::Map(entries) => entries,
        _ => panic!("expected a MessagePack map"),
    }
}

fn entry_index(entries: &[(Value, Value)], key: &str) -> usize {
    entries
        .iter()
        .position(|(candidate, _)| candidate.as_str() == Some(key))
        .expect("pinned key is present")
}

fn rules_array(value: &mut Value) -> &mut Vec<Value> {
    let entries = map_entries(value);
    let index = entry_index(entries.as_slice(), "rules");
    match &mut entries[index].1 {
        Value::Array(rows) => rows,
        _ => panic!("rules is an array"),
    }
}

fn set_rule_field(value: &mut Value, row: usize, key: &str, field: Value) {
    let rows = rules_array(value);
    let entries = map_entries(&mut rows[row]);
    let index = entry_index(entries.as_slice(), key);
    entries[index].1 = field;
}

fn assert_malformed(value: &Value) {
    assert!(matches!(
        decode_selection_rule_set(&encode_value(value)),
        Err(ChannelIdentitySelectionError::MalformedRuleSet(_))
    ));
}

// ---------------------------------------------------------------------------
// Compiled defaults
// ---------------------------------------------------------------------------

#[test]
fn compiled_defaults_are_the_six_canonical_rows() {
    let set = SelectionRuleSet::compiled_defaults();
    let expected = [
        ("work_deal", "delegated_owner_account"),
        ("scheduling_logistics", "agent_named_address"),
        ("campaign_outreach", "side_domain_address"),
        ("transactional_system", "house_identity"),
        ("personal_friends", "companion_identity"),
        ("group_space", "named_group_participant"),
    ];

    assert_eq!(set.revision(), 1);
    assert_eq!(set.rules().len(), expected.len());
    for (rule, (context, face)) in set.rules().iter().zip(expected) {
        assert_eq!(rule.context.as_str(), context);
        assert_eq!(rule.face.as_str(), face);
        assert_eq!(rule.scope, SelectionRuleScope::VaultDefault);
        assert_eq!(rule.writer_kind, SelectionWriterKind::SystemDefault);
        assert_eq!(rule.updated_by, None);
        assert_eq!(rule.rule_id, rule.context.builtin_rule_id());
        assert!(rule.agent_amendable);
    }
}

#[test]
fn compiled_defaults_resolve_every_relationship_context() -> SelectionResult<()> {
    let set = SelectionRuleSet::compiled_defaults();
    let roster = face_roster();

    for context in RelationshipContext::ALL {
        let outcome = set.resolve(ChannelIdentitySelectionRequest::new(context), &roster)?;
        assert_eq!(outcome.face, context.default_face());
        assert_eq!(
            outcome.source,
            ChannelIdentitySelectionSource::Rule {
                rule_id: context.builtin_rule_id().to_owned(),
            }
        );
    }
    Ok(())
}

#[test]
fn wire_tokens_round_trip_for_every_axis() {
    for context in RelationshipContext::ALL {
        assert_eq!(RelationshipContext::parse(context.as_str()), Some(context));
    }
    for face in ChannelIdentityFace::ALL {
        assert_eq!(ChannelIdentityFace::parse(face.as_str()), Some(face));
    }
    for kind in [
        SelectionWriterKind::SystemDefault,
        SelectionWriterKind::Owner,
        SelectionWriterKind::Agent,
    ] {
        assert_eq!(SelectionWriterKind::parse(kind.as_str()), Some(kind));
    }
    assert_eq!(RelationshipContext::parse("work_deals"), None);
    assert_eq!(ChannelIdentityFace::parse(""), None);
}

// ---------------------------------------------------------------------------
// Storage codec
// ---------------------------------------------------------------------------

#[test]
fn rule_set_round_trips_through_strict_messagepack() -> SelectionResult<()> {
    let set = SelectionRuleSet::compiled_defaults().upsert(
        owner_writer(),
        1,
        &amendment(
            "world.campaign",
            RelationshipContext::CampaignOutreach,
            SelectionRuleScope::World(entity(0x72)),
            ChannelIdentityFace::DelegatedOwnerAccount,
        ),
    )?;

    let bytes = encode_selection_rule_set(&set)?;
    assert_eq!(decode_selection_rule_set(&bytes)?, set);
    Ok(())
}

#[test]
fn trailing_bytes_and_unknown_keys_fail_typed() {
    let mut bytes = encoded_defaults();
    bytes.push(0xC0);
    assert!(matches!(
        decode_selection_rule_set(&bytes),
        Err(ChannelIdentitySelectionError::MalformedRuleSet(_))
    ));

    let mut value = rule_set_value();
    map_entries(&mut value).push((Value::from("extra"), Value::from(1_u64)));
    assert_malformed(&value);

    let mut value = rule_set_value();
    {
        let rows = rules_array(&mut value);
        map_entries(&mut rows[0]).push((Value::from("extra"), Value::Nil));
    }
    assert_malformed(&value);

    let mut value = rule_set_value();
    {
        let rows = rules_array(&mut value);
        let entries = map_entries(&mut rows[0]);
        let index = entry_index(entries.as_slice(), "face");
        entries.remove(index);
    }
    assert_malformed(&value);
}

#[test]
fn malformed_refs_and_scopes_fail_typed() {
    let mut value = rule_set_value();
    set_rule_field(&mut value, 0, "scope_kind", Value::from("world"));
    set_rule_field(
        &mut value,
        0,
        "scope_ref",
        Value::from("not-a-hex-entity-id"),
    );
    assert_malformed(&value);

    let mut value = rule_set_value();
    set_rule_field(&mut value, 0, "scope_kind", Value::from("world"));
    set_rule_field(&mut value, 0, "scope_ref", Value::from("0".repeat(32)));
    assert_malformed(&value);

    let mut value = rule_set_value();
    set_rule_field(&mut value, 0, "scope_kind", Value::from("counterparty"));
    assert_malformed(&value);

    let mut value = rule_set_value();
    set_rule_field(
        &mut value,
        0,
        "scope_ref",
        Value::from(entity(0x72).to_hex()),
    );
    assert_malformed(&value);

    let mut value = rule_set_value();
    set_rule_field(&mut value, 0, "context", Value::from("work_deals"));
    assert_malformed(&value);

    let mut value = rule_set_value();
    set_rule_field(&mut value, 0, "agent_amendable", Value::from(1_u64));
    assert_malformed(&value);
}

#[test]
fn blank_and_mis_stamped_rows_fail_typed() {
    let mut value = rule_set_value();
    set_rule_field(&mut value, 0, "rule_id", Value::from(""));
    assert!(matches!(
        decode_selection_rule_set(&encode_value(&value)),
        Err(ChannelIdentitySelectionError::InvalidRule(_))
    ));

    let mut value = rule_set_value();
    set_rule_field(&mut value, 0, "rule_id", Value::from("builtin work deal"));
    assert!(matches!(
        decode_selection_rule_set(&encode_value(&value)),
        Err(ChannelIdentitySelectionError::InvalidRule(_))
    ));

    // `system_default` provenance may never carry an author.
    let mut value = rule_set_value();
    set_rule_field(
        &mut value,
        0,
        "updated_by",
        Value::from(entity(0x70).to_hex()),
    );
    assert!(matches!(
        decode_selection_rule_set(&encode_value(&value)),
        Err(ChannelIdentitySelectionError::InvalidRule(_))
    ));

    // An owner-written row must name its author.
    let mut value = rule_set_value();
    set_rule_field(&mut value, 0, "writer_kind", Value::from("owner"));
    assert!(matches!(
        decode_selection_rule_set(&encode_value(&value)),
        Err(ChannelIdentitySelectionError::InvalidRule(_))
    ));
}

#[test]
fn duplicate_rows_and_regressed_revisions_fail_typed() {
    let mut value = rule_set_value();
    {
        let rows = rules_array(&mut value);
        let clone = rows[0].clone();
        rows.push(clone);
    }
    assert!(matches!(
        decode_selection_rule_set(&encode_value(&value)),
        Err(ChannelIdentitySelectionError::DuplicateRuleId)
    ));

    // Same context, same vault-default scope, distinct id: two canonical
    // winners for one relationship context.
    let mut value = rule_set_value();
    {
        let rows = rules_array(&mut value);
        let mut clone = rows[0].clone();
        let entries = map_entries(&mut clone);
        let index = entry_index(entries.as_slice(), "rule_id");
        entries[index].1 = Value::from("shadow.work_deal");
        rows.push(clone);
    }
    assert!(matches!(
        decode_selection_rule_set(&encode_value(&value)),
        Err(ChannelIdentitySelectionError::DuplicateCanonicalWinner)
    ));

    let mut value = rule_set_value();
    {
        let entries = map_entries(&mut value);
        let index = entry_index(entries.as_slice(), "revision");
        entries[index].1 = Value::from(0_u64);
    }
    assert!(matches!(
        decode_selection_rule_set(&encode_value(&value)),
        Err(ChannelIdentitySelectionError::RevisionRegressed { stored: 0 })
    ));

    let mut value = rule_set_value();
    {
        let entries = map_entries(&mut value);
        let index = entry_index(entries.as_slice(), "schema_version");
        entries[index].1 = Value::from(CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION + 1);
    }
    assert_malformed(&value);
}

// ---------------------------------------------------------------------------
// Precedence
// ---------------------------------------------------------------------------

#[test]
fn exact_scope_beats_vault_default() -> SelectionResult<()> {
    let world = entity(0x72);
    let set = SelectionRuleSet::compiled_defaults().upsert(
        owner_writer(),
        1,
        &amendment(
            "world.campaign",
            RelationshipContext::CampaignOutreach,
            SelectionRuleScope::World(world),
            ChannelIdentityFace::DelegatedOwnerAccount,
        ),
    )?;

    let unscoped = set.winning_rule(RelationshipContext::CampaignOutreach, None)?;
    assert_eq!(unscoped.face, ChannelIdentityFace::SideDomainAddress);

    let scoped = set.winning_rule(RelationshipContext::CampaignOutreach, Some(world))?;
    assert_eq!(scoped.face, ChannelIdentityFace::DelegatedOwnerAccount);

    // A different world falls back to the vault default rather than to the
    // more valuable delegated face.
    let elsewhere = set.winning_rule(RelationshipContext::CampaignOutreach, Some(entity(0x73)))?;
    assert_eq!(elsewhere.face, ChannelIdentityFace::SideDomainAddress);
    Ok(())
}

#[test]
fn precedence_is_deterministic_and_order_independent() -> SelectionResult<()> {
    let world = entity(0x72);
    let scope = SelectionRuleScope::World(world);
    let rows = vec![
        // Loses on priority.
        scoped_rule("a.low", scope, ChannelIdentityFace::HouseIdentity, 1, 900),
        // Ties on priority, loses on updated_at.
        scoped_rule(
            "b.old",
            scope,
            ChannelIdentityFace::CompanionIdentity,
            9,
            100,
        ),
        // Ties on priority and updated_at; loses the lexical tie-break.
        scoped_rule(
            "z.tied",
            scope,
            ChannelIdentityFace::AgentNamedAddress,
            9,
            900,
        ),
        // The winner: greatest priority, latest stamp, smallest id.
        scoped_rule(
            "c.winner",
            scope,
            ChannelIdentityFace::DelegatedOwnerAccount,
            9,
            900,
        ),
    ];

    for rotation in 0..rows.len() {
        let mut shuffled = rows.clone();
        shuffled.rotate_left(rotation);
        let set = SelectionRuleSet::from_rows(7, shuffled)?;
        let winner = set.winning_rule(RelationshipContext::CampaignOutreach, Some(world))?;
        assert_eq!(winner.rule_id, "c.winner");
        assert_eq!(winner.face, ChannelIdentityFace::DelegatedOwnerAccount);
    }

    let mut reversed = rows;
    reversed.reverse();
    let set = SelectionRuleSet::from_rows(7, reversed)?;
    assert_eq!(
        set.winning_rule(RelationshipContext::CampaignOutreach, Some(world))?
            .rule_id,
        "c.winner"
    );
    Ok(())
}

#[test]
fn a_context_with_no_row_fails_closed() -> SelectionResult<()> {
    let set = SelectionRuleSet::compiled_defaults().remove(
        owner_writer(),
        1,
        RelationshipContext::PersonalFriends.builtin_rule_id(),
    )?;

    assert!(matches!(
        set.resolve(
            ChannelIdentitySelectionRequest::new(RelationshipContext::PersonalFriends),
            &face_roster(),
        ),
        Err(ChannelIdentitySelectionError::NoRuleForContext)
    ));
    // Every other context still answers; nothing was promoted into the gap.
    assert_eq!(
        set.winning_rule(RelationshipContext::WorkDeal, None)?.face,
        ChannelIdentityFace::DelegatedOwnerAccount
    );
    Ok(())
}

#[test]
fn a_face_with_no_active_candidate_fails_closed() {
    let set = SelectionRuleSet::compiled_defaults();
    let mut roster = face_roster();
    for slot in &mut roster {
        if slot.face == ChannelIdentityFace::SideDomainAddress {
            slot.active = false;
        }
    }

    assert!(matches!(
        set.resolve(
            ChannelIdentitySelectionRequest::new(RelationshipContext::CampaignOutreach),
            &roster,
        ),
        Err(ChannelIdentitySelectionError::NoCandidateForFace)
    ));
}

#[test]
fn duplicate_candidates_fail_typed() {
    let set = SelectionRuleSet::compiled_defaults();
    let duplicated = vec![
        candidate(0x60, ChannelIdentityFace::SideDomainAddress),
        candidate(0x60, ChannelIdentityFace::DelegatedOwnerAccount),
    ];

    assert!(matches!(
        set.resolve(
            ChannelIdentitySelectionRequest::new(RelationshipContext::CampaignOutreach),
            &duplicated,
        ),
        Err(ChannelIdentitySelectionError::DuplicateCandidate)
    ));
}

// ---------------------------------------------------------------------------
// Writer rules
// ---------------------------------------------------------------------------

#[test]
fn writer_kind_is_derived_from_the_authenticated_actor() {
    assert_eq!(owner_writer().kind(), SelectionWriterKind::Owner);
    assert_eq!(owner_writer().actor_ref(), entity(0x70));
    assert_eq!(agent_writer().kind(), SelectionWriterKind::Agent);

    // `system_default` provenance belongs to the compiled table alone.
    assert!(matches!(
        SelectionWriter::from_authenticated_write(WriteActor::new(
            entity(0x74),
            EdgeActorClass::System,
        )),
        Err(ChannelIdentitySelectionError::WriterClassNotAmendable)
    ));
}

#[test]
fn accepted_changes_stamp_the_actor_and_advance_one_revision() -> SelectionResult<()> {
    let set = SelectionRuleSet::compiled_defaults();
    let next = set.upsert(
        agent_writer(),
        1,
        &amendment(
            "world.campaign",
            RelationshipContext::CampaignOutreach,
            SelectionRuleScope::World(entity(0x72)),
            ChannelIdentityFace::DelegatedOwnerAccount,
        ),
    )?;

    assert_eq!(next.revision(), 2);
    let row = next.rule("world.campaign").expect("row was inserted");
    assert_eq!(row.updated_by, Some(entity(0x71)));
    assert_eq!(row.writer_kind, SelectionWriterKind::Agent);
    assert_eq!(next.rules().len(), set.rules().len() + 1);

    // Editing in place replaces rather than appends, and advances once more.
    let third = next.upsert(
        owner_writer(),
        2,
        &amendment(
            "world.campaign",
            RelationshipContext::CampaignOutreach,
            SelectionRuleScope::World(entity(0x72)),
            ChannelIdentityFace::HouseIdentity,
        ),
    )?;
    assert_eq!(third.revision(), 3);
    assert_eq!(third.rules().len(), next.rules().len());
    let row = third.rule("world.campaign").expect("row was replaced");
    assert_eq!(row.updated_by, Some(entity(0x70)));
    assert_eq!(row.writer_kind, SelectionWriterKind::Owner);
    Ok(())
}

#[test]
fn stale_expected_revisions_fail_compare_and_swap() {
    let set = SelectionRuleSet::compiled_defaults();
    let change = amendment(
        "world.campaign",
        RelationshipContext::CampaignOutreach,
        SelectionRuleScope::World(entity(0x72)),
        ChannelIdentityFace::DelegatedOwnerAccount,
    );

    assert!(matches!(
        set.upsert(owner_writer(), 0, &change),
        Err(ChannelIdentitySelectionError::RevisionConflict {
            expected: 0,
            stored: 1
        })
    ));
    assert!(matches!(
        set.remove(
            owner_writer(),
            9,
            RelationshipContext::WorkDeal.builtin_rule_id()
        ),
        Err(ChannelIdentitySelectionError::RevisionConflict {
            expected: 9,
            stored: 1
        })
    ));
}

#[test]
fn owner_may_lock_a_row_that_the_agent_then_cannot_touch() -> SelectionResult<()> {
    let locked = SelectionRuleSet::compiled_defaults().upsert(
        owner_writer(),
        1,
        &SelectionRuleAmendment {
            agent_amendable: false,
            ..amendment(
                RelationshipContext::CampaignOutreach.builtin_rule_id(),
                RelationshipContext::CampaignOutreach,
                SelectionRuleScope::VaultDefault,
                ChannelIdentityFace::SideDomainAddress,
            )
        },
    )?;
    let row_id = RelationshipContext::CampaignOutreach.builtin_rule_id();
    assert!(!locked.rule(row_id).expect("row exists").agent_amendable);

    let agent_edit = amendment(
        row_id,
        RelationshipContext::CampaignOutreach,
        SelectionRuleScope::VaultDefault,
        ChannelIdentityFace::DelegatedOwnerAccount,
    );
    assert!(matches!(
        locked.upsert(agent_writer(), 2, &agent_edit),
        Err(ChannelIdentitySelectionError::RuleNotAgentAmendable)
    ));
    assert!(matches!(
        locked.remove(agent_writer(), 2, row_id),
        Err(ChannelIdentitySelectionError::RuleNotAgentAmendable)
    ));

    // The owner may still edit every row, including one it locked.
    let unlocked = locked.upsert(owner_writer(), 2, &agent_edit)?;
    assert_eq!(unlocked.revision(), 3);
    assert_eq!(
        unlocked.rule(row_id).expect("row exists").face,
        ChannelIdentityFace::DelegatedOwnerAccount
    );
    Ok(())
}

#[test]
fn an_agent_writer_cannot_mint_a_locked_row() {
    let set = SelectionRuleSet::compiled_defaults();
    let locking = SelectionRuleAmendment {
        agent_amendable: false,
        ..amendment(
            "world.campaign",
            RelationshipContext::CampaignOutreach,
            SelectionRuleScope::World(entity(0x72)),
            ChannelIdentityFace::DelegatedOwnerAccount,
        )
    };

    assert!(matches!(
        set.upsert(agent_writer(), 1, &locking),
        Err(ChannelIdentitySelectionError::AgentCannotLockRule)
    ));
}

#[test]
fn removing_an_unknown_row_fails_typed() {
    assert!(matches!(
        SelectionRuleSet::compiled_defaults().remove(owner_writer(), 1, "no.such.row"),
        Err(ChannelIdentitySelectionError::RuleNotFound)
    ));
}

// ---------------------------------------------------------------------------
// Thread pins
// ---------------------------------------------------------------------------

#[test]
fn a_valid_thread_pin_wins_before_every_mutable_row() -> SelectionResult<()> {
    let facet = entity(0x75);
    let roster = face_roster();
    let pinned = roster
        .iter()
        .find(|slot| slot.face == ChannelIdentityFace::CompanionIdentity)
        .copied()
        .expect("roster covers every face");

    let request = ChannelIdentitySelectionRequest::new(RelationshipContext::WorkDeal)
        .with_thread_pin(ChannelIdentityThreadPin {
            identity_ref: pinned.identity_ref,
            facet_ref: Some(facet),
        });

    let outcome = SelectionRuleSet::compiled_defaults().resolve(request, &roster)?;
    assert_eq!(outcome.identity_ref, pinned.identity_ref);
    assert_eq!(outcome.facet_ref, Some(facet));
    assert_eq!(outcome.face, ChannelIdentityFace::CompanionIdentity);
    assert_eq!(outcome.source, ChannelIdentitySelectionSource::ThreadPin);
    Ok(())
}

#[test]
fn a_missing_or_inactive_pin_fails_typed() {
    let set = SelectionRuleSet::compiled_defaults();
    let roster = face_roster();

    let absent = ChannelIdentitySelectionRequest::new(RelationshipContext::WorkDeal)
        .with_thread_pin(ChannelIdentityThreadPin {
            identity_ref: entity(0x76),
            facet_ref: None,
        });
    assert!(matches!(
        set.resolve(absent, &roster),
        Err(ChannelIdentitySelectionError::PinnedCandidateMissing)
    ));

    let mut retired = roster;
    retired[0].active = false;
    let stale = ChannelIdentitySelectionRequest::new(RelationshipContext::WorkDeal)
        .with_thread_pin(ChannelIdentityThreadPin {
            identity_ref: retired[0].identity_ref,
            facet_ref: None,
        });
    assert!(matches!(
        set.resolve(stale, &retired),
        Err(ChannelIdentitySelectionError::PinnedCandidateInactive)
    ));
}

// ---------------------------------------------------------------------------
// Vault door
// ---------------------------------------------------------------------------

#[test]
fn install_is_single_shot_and_reads_back() -> SelectionResult<()> {
    let (_dir, vault) = test_vault();

    assert!(matches!(
        vault.channel_identity_selection_rules(),
        Err(ChannelIdentitySelectionError::RuleSetMissing)
    ));

    let installed = vault.install_channel_identity_selection_defaults()?;
    assert_eq!(installed, SelectionRuleSet::compiled_defaults());
    assert_eq!(vault.channel_identity_selection_rules()?, installed);

    assert!(matches!(
        vault.install_channel_identity_selection_defaults(),
        Err(ChannelIdentitySelectionError::RuleSetAlreadyInstalled)
    ));
    Ok(())
}

#[test]
fn vault_amendments_persist_under_compare_and_swap() -> SelectionResult<()> {
    let (_dir, vault) = test_vault();
    vault.install_channel_identity_selection_defaults()?;

    let change = amendment(
        "world.campaign",
        RelationshipContext::CampaignOutreach,
        SelectionRuleScope::World(entity(0x72)),
        ChannelIdentityFace::DelegatedOwnerAccount,
    );

    assert!(matches!(
        vault.upsert_channel_identity_selection_rule(owner_writer(), 5, &change),
        Err(ChannelIdentitySelectionError::RevisionConflict {
            expected: 5,
            stored: 1
        })
    ));

    let next = vault.upsert_channel_identity_selection_rule(owner_writer(), 1, &change)?;
    assert_eq!(next.revision(), 2);
    assert_eq!(vault.channel_identity_selection_rules()?, next);

    // The consumed revision is now stale.
    assert!(matches!(
        vault.upsert_channel_identity_selection_rule(owner_writer(), 1, &change),
        Err(ChannelIdentitySelectionError::RevisionConflict {
            expected: 1,
            stored: 2
        })
    ));

    let after_remove =
        vault.remove_channel_identity_selection_rule(agent_writer(), 2, "world.campaign")?;
    assert_eq!(after_remove.revision(), 3);
    assert!(after_remove.rule("world.campaign").is_none());
    assert_eq!(vault.channel_identity_selection_rules()?, after_remove);
    Ok(())
}

#[test]
fn a_corrupt_stored_rule_set_fails_typed_rather_than_resolving() -> SelectionResult<()> {
    let (_dir, vault) = test_vault();
    vault.install_channel_identity_selection_defaults()?;

    let mut corrupt = encoded_defaults();
    corrupt.push(0xC0);
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .vault_meta
            .put(&mut wtxn, CHANNEL_IDENTITY_SELECTION_RULES_KEY, &corrupt)?;
        wtxn.commit()?;
    }

    assert!(matches!(
        vault.resolve_channel_identity_selection(
            ChannelIdentitySelectionRequest::new(RelationshipContext::WorkDeal),
            &face_roster(),
        ),
        Err(ChannelIdentitySelectionError::MalformedRuleSet(_))
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Worked override (fixture only)
// ---------------------------------------------------------------------------

/// ARCH-0063 R1's canon worked override: inside the Antevon world, campaign
/// outreach overrides the side-domain default and sends from Yura's mailbox —
/// a delegated-owner face. The names live here; the module carries none.
#[test]
fn antevon_campaigns_send_as_yura() -> SelectionResult<()> {
    let (_dir, vault) = test_vault();
    vault.install_channel_identity_selection_defaults()?;

    let antevon_world = entity(0x72);
    let side_domain = candidate(0x74, ChannelIdentityFace::SideDomainAddress);
    let yura_mailbox = ChannelIdentityCandidate {
        identity_ref: entity(0x73),
        shape: ChannelIdentityShape::DedicatedAddress,
        face: ChannelIdentityFace::DelegatedOwnerAccount,
        facet_ref: Some(entity(0x77)),
        active: true,
    };
    let candidates = [side_domain, yura_mailbox];

    // Before the override, the protective default holds.
    let default_outcome = vault.resolve_channel_identity_selection(
        ChannelIdentitySelectionRequest::new(RelationshipContext::CampaignOutreach)
            .in_world(antevon_world),
        &candidates,
    )?;
    assert_eq!(default_outcome.identity_ref, side_domain.identity_ref);

    vault.upsert_channel_identity_selection_rule(
        owner_writer(),
        1,
        &amendment(
            "antevon.campaign_outreach",
            RelationshipContext::CampaignOutreach,
            SelectionRuleScope::World(antevon_world),
            ChannelIdentityFace::DelegatedOwnerAccount,
        ),
    )?;

    let overridden = vault.resolve_channel_identity_selection(
        ChannelIdentitySelectionRequest::new(RelationshipContext::CampaignOutreach)
            .in_world(antevon_world),
        &candidates,
    )?;
    assert_eq!(overridden.identity_ref, yura_mailbox.identity_ref);
    assert_eq!(overridden.facet_ref, yura_mailbox.facet_ref);
    assert_eq!(overridden.face, ChannelIdentityFace::DelegatedOwnerAccount);
    assert_eq!(
        overridden.source,
        ChannelIdentitySelectionSource::Rule {
            rule_id: "antevon.campaign_outreach".to_owned(),
        }
    );

    // Outside that world the compiled default is untouched.
    let elsewhere = vault.resolve_channel_identity_selection(
        ChannelIdentitySelectionRequest::new(RelationshipContext::CampaignOutreach),
        &candidates,
    )?;
    assert_eq!(elsewhere.identity_ref, side_domain.identity_ref);
    Ok(())
}

/// Guards the purity invariant: the shipped module names no venture, person,
/// product, persona, or prompt.
#[test]
fn the_selection_module_carries_no_venture_or_person_names() {
    let source = include_str!("../channel_identity_selection.rs");
    for banned in ["Antevon", "antevon", "Yura", "yura", "Eiri", "eiri"] {
        assert!(
            !source.contains(banned),
            "production selection module must not name {banned}"
        );
    }
}
