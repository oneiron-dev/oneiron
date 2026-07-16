use super::*;
use crate::config::{HnswConfig, TextAnalyzerConfig, VaultConfig};
use crate::error::ErrorKind;
use crate::registry::{
    ENTITY_TYPE_PERSON, EntityClassification, TypeByteBand, entity_type_registry_entry,
    short_id_prefix,
};

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test-model-v1".to_owned());
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    config.text_analyzer = TextAnalyzerConfig::default();
    config
}

fn provenance(seed: u8) -> Value {
    Value::Map(vec![
        (Value::from("source"), Value::from("fixture")),
        (Value::from("seed"), Value::from(seed)),
    ])
}

fn generated_skill(version: &str) -> SkillRecord {
    SkillRecord::new(
        "oneiron.skill.generated",
        "Generated skill fixture",
        version,
        ClaimApprovalStatus::Auto,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        0.75,
        true,
        false,
        vec![SkillDependency::with_min_version(
            "oneiron.skill.base",
            ">=1.0.0",
        )],
        provenance(0xA1),
    )
}

fn human_skill(version: &str) -> SkillRecord {
    SkillRecord::new(
        "oneiron.skill.human",
        "Human-authored skill fixture",
        version,
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        provenance(0xB1),
    )
}

fn imported_skill(version: &str) -> SkillRecord {
    SkillRecord::new(
        "oneiron.skill.imported",
        "Imported skill fixture",
        version,
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        0.9,
        false,
        true,
        Vec::new(),
        provenance(0xD1),
    )
}

fn encode_value(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).expect("encode msgpack");
    out
}

fn skill_map(entries: Vec<(&'static str, Value)>) -> Vec<u8> {
    encode_value(&Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    ))
}

#[test]
fn generated_skill_record_round_trips_version_provenance_and_dependencies() -> Result<()> {
    let record = generated_skill("1.2.3");

    let encoded = encode_skill_record(&record)?;
    let decoded = decode_skill_record(&encoded)?;

    assert_eq!(decoded, record);
    assert!(decoded.generated);
    assert!(!decoded.human_authored);
    assert_eq!(decoded.dependencies[0].skill_id, "oneiron.skill.base");
    assert_eq!(
        decoded.dependencies[0].min_version.as_deref(),
        Some(">=1.0.0")
    );
    Ok(())
}

#[test]
fn human_authored_skill_record_round_trips_through_vault_helpers() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = EntityId::now();
    let record = human_skill("2026.07.01");

    vault.put_skill_record(&id, &record, TimeRange { start: 10, end: 10 }, 11)?;
    let decoded = vault.get_skill_record(&id)?.ok_or(Error::EntityNotFound)?;

    assert_eq!(decoded, record);
    assert_eq!(vault.get_entity_type(&id)?, Some(ENTITY_TYPE_SKILL));
    assert_eq!(short_id_prefix(ENTITY_TYPE_SKILL)?, "sk");
    let entry = entity_type_registry_entry(ENTITY_TYPE_SKILL).expect("SKILL registry row");
    assert_eq!(entry.kind, "SKILL");
    assert_eq!(entry.classification, EntityClassification::Core);
    assert_eq!(entry.band, TypeByteBand::Core);
    Ok(())
}

#[test]
fn skill_update_path_validates_provenance_and_preserves_prior_body() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = EntityId::now();
    let prior = human_skill("1.0.0");
    vault.put_skill_record(&id, &prior, TimeRange { start: 10, end: 10 }, 11)?;

    let mut updated = human_skill("1.1.0");
    updated.desc = "Human skill update".to_owned();
    updated.provenance = provenance(0xB2);
    vault.update_skill_record(&id, &updated, TimeRange { start: 12, end: 12 }, 13)?;
    assert_eq!(vault.get_skill_record(&id)?, Some(updated.clone()));

    let mut forged = generated_skill("1.2.0");
    forged.skill_id = updated.skill_id.clone();
    forged.provenance = provenance(0xC1);
    let err = vault
        .update_skill_record(&id, &forged, TimeRange { start: 14, end: 14 }, 15)
        .expect_err("generated provenance must not update human-authored skill");

    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
    assert_eq!(vault.get_skill_record(&id)?, Some(updated));
    Ok(())
}

#[test]
fn raw_skill_put_update_runs_same_provenance_gate() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = EntityId::now();
    let prior = generated_skill("1.0.0");
    vault.put_skill_record(&id, &prior, TimeRange { start: 10, end: 10 }, 11)?;

    let mut forged = generated_skill("1.0.0");
    forged.desc = "Body changed without version bump".to_owned();
    let forged_bytes = encode_skill_record(&forged)?;
    let err = vault
        .put_entity(
            &id,
            ENTITY_TYPE_SKILL,
            TimeRange { start: 12, end: 12 },
            13,
            &forged_bytes,
        )
        .expect_err("raw update must validate SKILL version provenance");

    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
    assert_eq!(vault.get_skill_record(&id)?, Some(prior));
    Ok(())
}

#[test]
fn raw_skill_put_upgrades_legacy_opaque_skill_body() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = EntityId::now();
    let occurred = TimeRange { start: 10, end: 10 };
    let legacy_body = b"legacy opaque skill body";
    let mut raw = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + legacy_body.len());
    raw.push(ENTITY_TYPE_SKILL);
    raw.extend_from_slice(&occurred.start.to_be_bytes());
    raw.extend_from_slice(&occurred.end.to_be_bytes());
    raw.extend_from_slice(&11_u64.to_be_bytes());
    raw.extend_from_slice(legacy_body);
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.entities.put(&mut wtxn, id.as_bytes(), &raw)?;
    wtxn.commit()?;

    let upgraded = human_skill("1.0.0");
    let upgraded_bytes = encode_skill_record(&upgraded)?;
    vault.put_entity(
        &id,
        ENTITY_TYPE_SKILL,
        TimeRange { start: 12, end: 12 },
        13,
        &upgraded_bytes,
    )?;

    assert_eq!(vault.get_skill_record(&id)?, Some(upgraded));
    Ok(())
}

#[test]
fn raw_skill_put_rejects_malformed_structured_prior_skill_body() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = EntityId::now();
    let occurred = TimeRange { start: 10, end: 10 };
    let malformed_structured_body = skill_map(vec![
        (KEY_SKILL_ID, Value::from("oneiron.skill.human")),
        (KEY_DESC, Value::from("Human-authored skill fixture")),
        (KEY_VERSION, Value::from("1.0.0")),
        (KEY_APPROVAL_STATUS, Value::from("approved")),
        (KEY_LIFECYCLE_STATUS, Value::from("active")),
        (KEY_SOURCE, Value::from("user_stated")),
        (KEY_CONFIDENCE, Value::F32(1.0)),
        (KEY_GENERATED, Value::Boolean(false)),
        (KEY_HUMAN_AUTHORED, Value::Boolean(true)),
        (KEY_DEPENDENCIES, Value::Array(Vec::new())),
        (KEY_PROVENANCE, Value::Map(Vec::new())),
    ]);
    let mut raw = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + malformed_structured_body.len());
    raw.push(ENTITY_TYPE_SKILL);
    raw.extend_from_slice(&occurred.start.to_be_bytes());
    raw.extend_from_slice(&occurred.end.to_be_bytes());
    raw.extend_from_slice(&11_u64.to_be_bytes());
    raw.extend_from_slice(&malformed_structured_body);
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.entities.put(&mut wtxn, id.as_bytes(), &raw)?;
    wtxn.commit()?;

    let upgraded = human_skill("1.1.0");
    let upgraded_bytes = encode_skill_record(&upgraded)?;
    let err = vault
        .put_entity(
            &id,
            ENTITY_TYPE_SKILL,
            TimeRange { start: 12, end: 12 },
            13,
            &upgraded_bytes,
        )
        .expect_err("malformed structured prior SKILL body must fail closed");

    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
    Ok(())
}

#[test]
fn skill_record_rejects_mismatched_flags_bad_provenance_and_bad_dependencies() {
    let mut mismatched = generated_skill("1.0.0");
    mismatched.source = ClaimSource::UserStated;
    assert_eq!(
        encode_skill_record(&mismatched)
            .expect_err("generated flag must match source")
            .kind(),
        ErrorKind::InvalidSkillBody
    );

    let mut nil_provenance = human_skill("1.0.0");
    nil_provenance.provenance = Value::Nil;
    assert_eq!(
        encode_skill_record(&nil_provenance)
            .expect_err("nil provenance must fail")
            .kind(),
        ErrorKind::InvalidSkillBody
    );

    let mut empty_provenance = human_skill("1.0.0");
    empty_provenance.provenance = Value::Map(Vec::new());
    assert_eq!(
        encode_skill_record(&empty_provenance)
            .expect_err("empty provenance metadata must fail")
            .kind(),
        ErrorKind::InvalidSkillBody
    );

    let mut scalar_provenance = human_skill("1.0.0");
    scalar_provenance.provenance = Value::from("fixture");
    assert_eq!(
        encode_skill_record(&scalar_provenance)
            .expect_err("scalar provenance metadata must fail")
            .kind(),
        ErrorKind::InvalidSkillBody
    );

    let mut duplicate = generated_skill("1.0.0");
    duplicate
        .dependencies
        .push(SkillDependency::new("oneiron.skill.base"));
    assert_eq!(
        encode_skill_record(&duplicate)
            .expect_err("duplicate dependencies must fail")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
}

// ─── ONE-1735 [SK-01]: lifecycle machine ────────────────────────────────

const TWO_FILE_TREE_HASH: &str = "c4f2fad6eeab4789a4560a3ee555ad9be4384b57c55f3a72b9244351a7508460";
const ONE_FILE_TREE_HASH: &str = "7e070ad60eac3f513daa2777987ec08ddcc2c8a9eaf3e42e204729c787a9cfb3";

const ALL_LIFECYCLE_STATES: [SkillLifecycle; 5] = [
    SkillLifecycle::Candidate,
    SkillLifecycle::Active,
    SkillLifecycle::Stale,
    SkillLifecycle::Quarantined,
    SkillLifecycle::Superseded,
];

fn activate(vault: &Vault, id: &EntityId, record: &SkillRecord) -> Result<SkillRecord> {
    let mut active = record.clone();
    active.lifecycle_status = SkillLifecycle::Active;
    vault.update_skill_record(id, &active, TimeRange { start: 20, end: 20 }, 21)?;
    Ok(active)
}

#[test]
fn skill_lifecycle_transition_table_is_pinned() {
    let expected_legal: [(SkillLifecycle, SkillLifecycle); 6] = [
        (SkillLifecycle::Candidate, SkillLifecycle::Active),
        (SkillLifecycle::Active, SkillLifecycle::Stale),
        (SkillLifecycle::Active, SkillLifecycle::Quarantined),
        (SkillLifecycle::Active, SkillLifecycle::Superseded),
        (SkillLifecycle::Stale, SkillLifecycle::Active),
        (SkillLifecycle::Quarantined, SkillLifecycle::Active),
    ];
    let mut legal_count = 0;
    for from in ALL_LIFECYCLE_STATES {
        for to in ALL_LIFECYCLE_STATES {
            let legal = from.can_transition(to);
            let expected = from == to || expected_legal.contains(&(from, to));
            assert_eq!(legal, expected, "transition {from:?} -> {to:?}");
            if legal {
                legal_count += 1;
            }
        }
    }
    // 5 self-loops + the 6 diagram moves (3 exits from active, admission,
    // and the two documented reversals). Superseded has no exits.
    assert_eq!(legal_count, 11);

    let canon_states = ALL_LIFECYCLE_STATES
        .iter()
        .filter(|state| state.loads_as_canon())
        .count();
    assert_eq!(canon_states, 1, "only active loads as canon");
    assert!(SkillLifecycle::Active.loads_as_canon());
}

#[test]
fn skill_lifecycle_strings_round_trip_and_retracted_never_parses() {
    for state in ALL_LIFECYCLE_STATES {
        assert_eq!(SkillLifecycle::parse(state.as_str()), Some(state));
    }
    // Terminal delete never happens: the claim-lifecycle `retracted`
    // string that leaked into pre-ONE-1735 skill bodies fails closed.
    assert_eq!(SkillLifecycle::parse("retracted"), None);

    let encoded = skill_map(vec![
        (KEY_SKILL_ID, Value::from("oneiron.skill.retracted")),
        (KEY_DESC, Value::from("Legacy retracted body")),
        (KEY_VERSION, Value::from("1.0.0")),
        (KEY_APPROVAL_STATUS, Value::from("approved")),
        (KEY_LIFECYCLE_STATUS, Value::from("retracted")),
        (KEY_SOURCE, Value::from("user_stated")),
        (KEY_CONFIDENCE, Value::F32(1.0)),
        (KEY_GENERATED, Value::Boolean(false)),
        (KEY_HUMAN_AUTHORED, Value::Boolean(true)),
        (KEY_DEPENDENCIES, Value::Array(Vec::new())),
        (KEY_PROVENANCE, provenance(0xE9)),
    ]);
    let err = decode_skill_record(&encoded).expect_err("retracted must fail closed");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
}

#[test]
fn new_skill_births_must_be_candidate_via_typed_door() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = EntityId::now();

    let mut born_active = human_skill("1.0.0");
    born_active.lifecycle_status = SkillLifecycle::Active;
    let err = vault
        .put_skill_record(&id, &born_active, TimeRange { start: 10, end: 10 }, 11)
        .expect_err("typed door must reject non-candidate births");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
    assert_eq!(vault.get_skill_record(&id)?, None);

    let candidate = human_skill("1.0.0");
    vault.put_skill_record(&id, &candidate, TimeRange { start: 10, end: 10 }, 11)?;
    let active = activate(&vault, &id, &candidate)?;

    // Existing records pass the typed door regardless of state (updates
    // are the batch gate's business, not the birth rule's).
    vault.put_skill_record(&id, &active, TimeRange { start: 22, end: 22 }, 23)?;
    assert_eq!(vault.get_skill_record(&id)?, Some(active));
    Ok(())
}

#[test]
fn stale_fold_one_1447_is_reversible_and_never_canon() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = EntityId::now();
    let candidate = human_skill("1.0.0");
    vault.put_skill_record(&id, &candidate, TimeRange { start: 10, end: 10 }, 11)?;
    let active = activate(&vault, &id, &candidate)?;

    // Source messages deleted → stale. A state flip, not a content
    // revision: same version, no bespoke flag.
    let mut stale = active.clone();
    stale.lifecycle_status = SkillLifecycle::Stale;
    vault.update_skill_record(&id, &stale, TimeRange { start: 30, end: 30 }, 31)?;

    // Visible (terminal delete never happens), but never canon.
    let stored = vault.get_skill_record(&id)?.ok_or(Error::EntityNotFound)?;
    assert_eq!(stored.lifecycle_status, SkillLifecycle::Stale);
    assert!(!stored.lifecycle_status.loads_as_canon());

    // Reversible.
    vault.update_skill_record(&id, &active, TimeRange { start: 40, end: 40 }, 41)?;
    let restored = vault.get_skill_record(&id)?.ok_or(Error::EntityNotFound)?;
    assert_eq!(restored.lifecycle_status, SkillLifecycle::Active);
    Ok(())
}

#[test]
fn quarantine_is_human_ratified_never_automatic_and_revivable() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = EntityId::now();
    let candidate = human_skill("1.0.0");
    vault.put_skill_record(&id, &candidate, TimeRange { start: 10, end: 10 }, 11)?;
    let active = activate(&vault, &id, &candidate)?;

    // Quarantined is a HUMAN-RATIFIED state: the proposal to quarantine is
    // a ROW (SK-05's floor-crossing proposal), never a lifecycle state.
    // The only lawful record shape is approval = approved, on every door;
    // auto/proposed/rejected entries are all rejected and leave the
    // record active.
    for approval in [
        ClaimApprovalStatus::Auto,
        ClaimApprovalStatus::Proposed,
        ClaimApprovalStatus::Rejected,
    ] {
        let mut entry = active.clone();
        entry.lifecycle_status = SkillLifecycle::Quarantined;
        entry.approval_status = approval;
        let err = vault
            .update_skill_record(&id, &entry, TimeRange { start: 30, end: 30 }, 31)
            .expect_err("non-ratified quarantine entry must be rejected");
        assert_eq!(err.kind(), ErrorKind::InvalidSkillBody, "{approval:?}");
        assert_eq!(
            vault.get_skill_record(&id)?.map(|r| r.lifecycle_status),
            Some(SkillLifecycle::Active),
            "{approval:?} entry must leave the record active"
        );
    }

    // Ratified entry: legal, excluded from canon.
    let mut quarantined = active.clone();
    quarantined.lifecycle_status = SkillLifecycle::Quarantined;
    quarantined.approval_status = ClaimApprovalStatus::Approved;
    vault.update_skill_record(&id, &quarantined, TimeRange { start: 32, end: 32 }, 33)?;
    let stored = vault.get_skill_record(&id)?.ok_or(Error::EntityNotFound)?;
    assert!(!stored.lifecycle_status.loads_as_canon());

    // Laundering flip (quarantined self-loop with approval demoted to
    // auto) violates the record-shape invariant on any door — it is not
    // even encodable.
    let mut laundered = quarantined;
    laundered.approval_status = ClaimApprovalStatus::Auto;
    let err = vault
        .update_skill_record(&id, &laundered, TimeRange { start: 34, end: 34 }, 35)
        .expect_err("quarantined+auto is not a lawful record shape");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
    let err = encode_skill_record(&laundered).expect_err("shape invariant holds at encode too");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);

    // Revivable: evidence kept, quarantined → active is a legal reversal.
    let mut revived = active;
    revived.approval_status = ClaimApprovalStatus::Approved;
    vault.update_skill_record(&id, &revived, TimeRange { start: 36, end: 36 }, 37)?;
    assert_eq!(
        vault.get_skill_record(&id)?.map(|r| r.lifecycle_status),
        Some(SkillLifecycle::Active)
    );
    Ok(())
}

#[test]
fn superseded_revision_is_frozen_and_never_resurrects() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = EntityId::now();
    let candidate = human_skill("1.0.0");
    vault.put_skill_record(&id, &candidate, TimeRange { start: 10, end: 10 }, 11)?;
    let active = activate(&vault, &id, &candidate)?;

    // A bare typed-door flip to superseded would orphan a frozen revision
    // with no successor — supersession is supersede_skill_record's act.
    let mut bare_flip = active.clone();
    bare_flip.lifecycle_status = SkillLifecycle::Superseded;
    let err = vault
        .update_skill_record(&id, &bare_flip, TimeRange { start: 28, end: 28 }, 29)
        .expect_err("typed update door must not flip a revision to superseded");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
    assert_eq!(
        vault.get_skill_record(&id)?.map(|r| r.lifecycle_status),
        Some(SkillLifecycle::Active),
        "rejected bare flip must leave the record active"
    );

    // Real supersession: an ADMITTED successor through the door.
    let successor_id = EntityId::now();
    let successor_candidate = human_skill("2.0.0");
    vault.put_skill_record(
        &successor_id,
        &successor_candidate,
        TimeRange { start: 30, end: 30 },
        31,
    )?;
    activate(&vault, &successor_id, &successor_candidate)?;
    vault.supersede_skill_record(&id, &successor_id, TimeRange { start: 32, end: 32 }, 33)?;
    let mut superseded = active.clone();
    superseded.lifecycle_status = SkillLifecycle::Superseded;
    assert_eq!(vault.get_skill_record(&id)?, Some(superseded.clone()));

    // No resurrection …
    let err = vault
        .update_skill_record(&id, &active, TimeRange { start: 40, end: 40 }, 41)
        .expect_err("superseded revision must never re-activate");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);

    // … and no edits either: the old revision is frozen history.
    let mut edited = superseded.clone();
    edited.desc = "Rewriting history".to_owned();
    edited.version = "1.0.1".to_owned();
    let err = vault
        .update_skill_record(&id, &edited, TimeRange { start: 42, end: 42 }, 43)
        .expect_err("superseded revision must be frozen");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
    assert_eq!(vault.get_skill_record(&id)?, Some(superseded));
    Ok(())
}

#[test]
fn supersede_door_flips_old_revision_and_writes_succession_edge() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let old_id = EntityId::now();
    let new_id = EntityId::now();
    let old_candidate = human_skill("1.0.0");
    vault.put_skill_record(
        &old_id,
        &old_candidate,
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    let old_active = activate(&vault, &old_id, &old_candidate)?;

    let new_candidate = human_skill("2.0.0");
    vault.put_skill_record(
        &new_id,
        &new_candidate,
        TimeRange { start: 12, end: 12 },
        13,
    )?;

    // A non-admitted successor cannot supersede: "superseded" means "new
    // version ADMITTED" — otherwise the skillId would be left with no
    // admitted canon revision at all.
    let err = vault
        .supersede_skill_record(&old_id, &new_id, TimeRange { start: 14, end: 14 }, 15)
        .expect_err("candidate successor must not supersede");
    assert_eq!(
        err.to_string(),
        "invalid SKILL body: superseding revision must be admitted (active) before it supersedes",
        "the successor-admission clause must fire"
    );
    assert_eq!(
        vault.get_skill_record(&old_id)?.map(|r| r.lifecycle_status),
        Some(SkillLifecycle::Active),
        "rejected supersession must leave the old revision active"
    );

    // A candidate old revision cannot be superseded (only active can):
    // here the successor (old_id) IS active, but the to-be-superseded
    // record (new_id) is still a candidate.
    let err = vault
        .supersede_skill_record(&new_id, &old_id, TimeRange { start: 16, end: 16 }, 17)
        .expect_err("candidate revision must not be superseded");
    assert_eq!(
        err.to_string(),
        "invalid SKILL body: only an active skill revision can be superseded",
        "the old-revision-state clause must fire"
    );

    activate(&vault, &new_id, &new_candidate)?;
    vault.supersede_skill_record(&old_id, &new_id, TimeRange { start: 20, end: 20 }, 21)?;

    let old_stored = vault
        .get_skill_record(&old_id)?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(old_stored.lifecycle_status, SkillLifecycle::Superseded);
    assert!(!old_stored.lifecycle_status.loads_as_canon());
    // Same version as before the flip: supersession is a state flip, not
    // a content revision.
    assert_eq!(old_stored.version, old_active.version);

    let edges = vault.edges_out(&new_id)?;
    assert_eq!(edges.len(), 1, "exactly one succession edge");
    assert_eq!(edges[0].kind, crate::edge::EdgeKind::Supersedes);
    assert_eq!(edges[0].target, old_id);

    // Frozen: superseding an already-superseded revision fails.
    let err = vault
        .supersede_skill_record(&old_id, &new_id, TimeRange { start: 22, end: 22 }, 23)
        .expect_err("superseded revision has no exits");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);

    // Self-supersession and cross-skill supersession fail.
    let err = vault
        .supersede_skill_record(&new_id, &new_id, TimeRange { start: 24, end: 24 }, 25)
        .expect_err("self-supersession is invalid");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
    let other_id = EntityId::now();
    vault.put_skill_record(
        &other_id,
        &generated_skill("1.0.0"),
        TimeRange { start: 26, end: 26 },
        27,
    )?;
    let err = vault
        .supersede_skill_record(&new_id, &other_id, TimeRange { start: 28, end: 28 }, 29)
        .expect_err("supersession links revisions of ONE skill");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
    Ok(())
}

// ─── ONE-1735 [SK-01]: fork lineage (one fork law, shared with ONE-1444) ──

#[test]
fn fork_creates_new_entity_with_lineage_edge_and_candidate_birth() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let parent_id = EntityId::now();
    let fork_id = EntityId::now();
    let parent =
        imported_skill("3.2.1").with_content_hash(SkillContentHash::parse_hex(TWO_FILE_TREE_HASH)?);
    vault.put_skill_record(&parent_id, &parent, TimeRange { start: 10, end: 10 }, 11)?;

    let fork = vault.fork_skill_record(
        &parent_id,
        &fork_id,
        "oneiron.skill.imported.local",
        TimeRange { start: 20, end: 20 },
        21,
    )?;

    assert_eq!(fork.forked_from, Some(parent_id));
    assert_eq!(fork.lifecycle_status, SkillLifecycle::Candidate);
    assert_eq!(fork.source, ClaimSource::UserStated);
    assert!(fork.human_authored);
    assert!(!fork.generated);
    // Identity is recomputed from the edited tree — an unedited fork must
    // not collide with the parent's canonical identity.
    assert_eq!(fork.content_hash, None);
    assert_eq!(vault.get_skill_record(&fork_id)?, Some(fork.clone()));

    let edges = vault.edges_out(&fork_id)?;
    assert_eq!(edges.len(), 1, "exactly one lineage edge");
    assert_eq!(edges[0].kind, crate::edge::EdgeKind::DerivedFrom);
    assert_eq!(edges[0].target, parent_id);

    // Parent untouched: still the imported entity, still its own identity.
    let stored_parent = vault
        .get_skill_record(&parent_id)?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(stored_parent, parent);

    // Fork provenance names its parent.
    let Value::Map(entries) = &fork.provenance else {
        panic!("fork provenance must be a map");
    };
    assert_eq!(entries.len(), 3);
    let fork_of_rows = entries
        .iter()
        .filter(|(k, v)| {
            k.as_str() == Some("forkOf") && v.as_str() == Some("oneiron.skill.imported")
        })
        .count();
    assert_eq!(
        fork_of_rows, 1,
        "fork provenance names its parent exactly once"
    );
    Ok(())
}

#[test]
fn fork_rejects_id_collisions_and_parent_shadowing() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let parent_id = EntityId::now();
    let parent = imported_skill("1.0.0");
    vault.put_skill_record(&parent_id, &parent, TimeRange { start: 10, end: 10 }, 11)?;

    let err = vault
        .fork_skill_record(
            &parent_id,
            &parent_id,
            "oneiron.skill.imported.local",
            TimeRange { start: 12, end: 12 },
            13,
        )
        .expect_err("fork onto the parent id must fail");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);

    let fork_id = EntityId::now();
    let err = vault
        .fork_skill_record(
            &parent_id,
            &fork_id,
            "oneiron.skill.imported",
            TimeRange { start: 14, end: 14 },
            15,
        )
        .expect_err("fork must take its own skillId");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
    assert_eq!(vault.get_skill_record(&fork_id)?, None);

    let missing_parent = EntityId::now();
    let err = vault
        .fork_skill_record(
            &missing_parent,
            &fork_id,
            "oneiron.skill.other",
            TimeRange { start: 16, end: 16 },
            17,
        )
        .expect_err("fork of a missing parent must fail");
    assert_eq!(err.kind(), ErrorKind::EntityNotFound);
    Ok(())
}

#[test]
fn forked_from_lineage_is_frozen_on_update() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let parent_id = EntityId::now();
    let fork_id = EntityId::now();
    vault.put_skill_record(
        &parent_id,
        &imported_skill("1.0.0"),
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    let fork = vault.fork_skill_record(
        &parent_id,
        &fork_id,
        "oneiron.skill.imported.local",
        TimeRange { start: 12, end: 12 },
        13,
    )?;

    let mut detached = fork.clone();
    detached.forked_from = None;
    detached.desc = "Detached fork".to_owned();
    detached.version = "2".to_owned();
    let err = vault
        .update_skill_record(&fork_id, &detached, TimeRange { start: 20, end: 20 }, 21)
        .expect_err("lineage must not be erasable");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
    assert_eq!(vault.get_skill_record(&fork_id)?, Some(fork));
    Ok(())
}

#[test]
fn imported_skill_content_never_changes_in_place_any_approval() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = EntityId::now();
    let candidate = imported_skill("1.0.0");
    vault.put_skill_record(&id, &candidate, TimeRange { start: 10, end: 10 }, 11)?;
    let active = activate(&vault, &id, &candidate)?;

    // Imported content changes in place through NO generic door: an
    // in-place "proposal" that replaces canon is a silent overwrite with
    // a label. Every approval flavor is rejected by the imported-content
    // clause; local edit = fork, upstream update = ONE-1736 hub-sync door.
    for approval in [
        ClaimApprovalStatus::Auto,
        ClaimApprovalStatus::Proposed,
        ClaimApprovalStatus::Approved,
    ] {
        let mut overwrite = active.clone();
        overwrite.desc = "Upstream rewrote this".to_owned();
        overwrite.version = "1.1.0".to_owned();
        overwrite.approval_status = approval;
        let err = vault
            .update_skill_record(&id, &overwrite, TimeRange { start: 30, end: 30 }, 31)
            .expect_err("imported content must never change in place");
        assert_eq!(err.kind(), ErrorKind::InvalidSkillBody, "{approval:?}");
        assert_eq!(
            err.to_string(),
            "invalid SKILL body: imported skill content never changes in place; local edits fork and upstream updates land through the hub-sync door",
            "{approval:?} must hit exactly the imported-content clause"
        );
        assert_eq!(
            vault.get_skill_record(&id)?,
            Some(active.clone()),
            "{approval:?} overwrite must leave the record untouched"
        );
    }

    // State-axis flips (lifecycle/approval only, no content) stay legal.
    let mut stale = active.clone();
    stale.lifecycle_status = SkillLifecycle::Stale;
    vault.update_skill_record(&id, &stale, TimeRange { start: 40, end: 40 }, 41)?;
    vault.update_skill_record(&id, &active, TimeRange { start: 42, end: 42 }, 43)?;
    assert_eq!(vault.get_skill_record(&id)?, Some(active));
    Ok(())
}

// ─── ONE-1735 [SK-01]: two-layer identity ──────────────────────────────

#[test]
fn canonical_tree_hash_is_order_independent_with_pinned_vector() -> Result<()> {
    let ordered = canonical_skill_tree_hash([
        ("SKILL.md", b"# demo skill\n".as_slice()),
        ("scripts/run.sh", b"echo hi\n".as_slice()),
    ])?;
    let reversed = canonical_skill_tree_hash([
        ("scripts/run.sh", b"echo hi\n".as_slice()),
        ("SKILL.md", b"# demo skill\n".as_slice()),
    ])?;
    assert_eq!(ordered, reversed, "input order must never matter");
    assert_eq!(ordered.to_hex(), TWO_FILE_TREE_HASH);

    let single = canonical_skill_tree_hash([("SKILL.md", b"# demo skill\n".as_slice())])?;
    assert_eq!(single.to_hex(), ONE_FILE_TREE_HASH);
    assert_ne!(single, ordered);
    Ok(())
}

#[test]
fn canonical_tree_hash_rejects_bad_trees_fail_closed() {
    let content = b"x".as_slice();
    for bad_path in [
        "",
        "/abs/path",
        "a//b",
        "./skill",
        "../skill",
        "a/./b",
        "a/../b",
        "a\\b",
        "a\0b",
        "C:/pkg/SKILL.md",
        "a:b",
    ] {
        let err = canonical_skill_tree_hash([(bad_path, content)])
            .expect_err("bad path must fail closed");
        assert_eq!(err.kind(), ErrorKind::InvalidSkillBody, "path {bad_path:?}");
    }
    let err = canonical_skill_tree_hash([("SKILL.md", content), ("SKILL.md", content)])
        .expect_err("duplicate paths must fail closed");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
    // ASCII case-fold aliases (default Windows/macOS filesystems) are
    // duplicates too — hashing both could authenticate a different tree
    // from the one that executes.
    let err = canonical_skill_tree_hash([("Foo.md", content), ("foo.md", content)])
        .expect_err("case-fold duplicate paths must fail closed");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
    let err = canonical_skill_tree_hash(std::iter::empty::<(&str, &[u8])>())
        .expect_err("an empty tree has no identity");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
}

#[test]
fn content_hash_and_fork_lineage_round_trip_and_stay_optional() -> Result<()> {
    let parent_id = EntityId::now();
    let record = human_skill("1.0.0")
        .with_content_hash(SkillContentHash::parse_hex(TWO_FILE_TREE_HASH)?)
        .with_forked_from(parent_id);
    let decoded = decode_skill_record(&encode_skill_record(&record)?)?;
    assert_eq!(decoded, record);
    assert_eq!(
        decoded.content_hash.map(|hash| hash.to_hex()).as_deref(),
        Some(TWO_FILE_TREE_HASH)
    );
    assert_eq!(decoded.forked_from, Some(parent_id));

    // Pre-ONE-1735 eleven-key bodies stay decodable: the identity and
    // lineage layers are absent, never defaulted to garbage.
    let legacy = skill_map(vec![
        (KEY_SKILL_ID, Value::from("oneiron.skill.legacy")),
        (KEY_DESC, Value::from("Legacy body without identity layer")),
        (KEY_VERSION, Value::from("1.0.0")),
        (KEY_APPROVAL_STATUS, Value::from("approved")),
        (KEY_LIFECYCLE_STATUS, Value::from("active")),
        (KEY_SOURCE, Value::from("user_stated")),
        (KEY_CONFIDENCE, Value::F32(1.0)),
        (KEY_GENERATED, Value::Boolean(false)),
        (KEY_HUMAN_AUTHORED, Value::Boolean(true)),
        (KEY_DEPENDENCIES, Value::Array(Vec::new())),
        (KEY_PROVENANCE, provenance(0xF1)),
    ]);
    let decoded = decode_skill_record(&legacy)?;
    assert_eq!(decoded.content_hash, None);
    assert_eq!(decoded.forked_from, None);
    Ok(())
}

#[test]
fn content_hash_wire_shape_is_strict() {
    let uppercase = TWO_FILE_TREE_HASH.to_ascii_uppercase();
    for bad in [
        "",
        "abc123",
        &TWO_FILE_TREE_HASH[..63],
        uppercase.as_str(),
        "zz2fad6eeab4789a4560a3ee555ad9be4384b57c55f3a72b9244351a7508460",
    ] {
        let err = SkillContentHash::parse_hex(bad).expect_err("bad hex must fail closed");
        assert_eq!(err.kind(), ErrorKind::InvalidSkillBody, "hex {bad:?}");
    }

    let mut base = vec![
        (KEY_SKILL_ID, Value::from("oneiron.skill.badhash")),
        (KEY_DESC, Value::from("Bad content hash shapes")),
        (KEY_VERSION, Value::from("1.0.0")),
        (KEY_APPROVAL_STATUS, Value::from("approved")),
        (KEY_LIFECYCLE_STATUS, Value::from("active")),
        (KEY_SOURCE, Value::from("user_stated")),
        (KEY_CONFIDENCE, Value::F32(1.0)),
        (KEY_GENERATED, Value::Boolean(false)),
        (KEY_HUMAN_AUTHORED, Value::Boolean(true)),
        (KEY_DEPENDENCIES, Value::Array(Vec::new())),
        (KEY_PROVENANCE, provenance(0xF2)),
    ];
    base.push((KEY_CONTENT_HASH, Value::F32(1.0)));
    let err = decode_skill_record(&skill_map(base.clone()))
        .expect_err("non-string contentHash must fail closed");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);

    base.pop();
    base.push((KEY_FORKED_FROM, Value::from("not-an-entity-id")));
    let err =
        decode_skill_record(&skill_map(base)).expect_err("malformed forkedFrom must fail closed");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
}

#[test]
fn declared_hash_cross_check_is_fail_closed() -> Result<()> {
    let record =
        human_skill("1.0.0").with_content_hash(SkillContentHash::parse_hex(TWO_FILE_TREE_HASH)?);

    cross_check_declared_content_hash(&record, TWO_FILE_TREE_HASH)?;
    // Hubs shout in different cases; the cross-check normalizes.
    cross_check_declared_content_hash(&record, &TWO_FILE_TREE_HASH.to_ascii_uppercase())?;

    let err = cross_check_declared_content_hash(&record, ONE_FILE_TREE_HASH)
        .expect_err("hash mismatch must fail closed");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);

    let hashless = human_skill("1.0.0");
    let err = cross_check_declared_content_hash(&hashless, TWO_FILE_TREE_HASH)
        .expect_err("a record without canonical identity cannot be cross-checked");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
    Ok(())
}

#[test]
fn skill_record_decoder_rejects_unpinned_dependency_shape() {
    let encoded = skill_map(vec![
        (KEY_SKILL_ID, Value::from("oneiron.skill.generated")),
        (KEY_DESC, Value::from("Generated skill fixture")),
        (KEY_VERSION, Value::from("1.0.0")),
        (KEY_APPROVAL_STATUS, Value::from("auto")),
        (KEY_LIFECYCLE_STATUS, Value::from("active")),
        (KEY_SOURCE, Value::from("generated")),
        (KEY_CONFIDENCE, Value::F32(0.75)),
        (KEY_GENERATED, Value::Boolean(true)),
        (KEY_HUMAN_AUTHORED, Value::Boolean(false)),
        (
            KEY_DEPENDENCIES,
            Value::Array(vec![Value::Map(vec![(
                Value::from(KEY_DEP_SKILL_ID),
                Value::from("oneiron.skill.base"),
            )])]),
        ),
        (KEY_PROVENANCE, provenance(0xA1)),
    ]);

    let err = decode_skill_record(&encoded)
        .expect_err("dependency without minVersion key must fail closed");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
}

// ─── ONE-1735 fix r1: local-create gates at the batch chokepoint ────────

#[test]
fn local_raw_and_batch_creates_must_be_born_candidate() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let mut born_active = human_skill("1.0.0");
    born_active.lifecycle_status = SkillLifecycle::Active;
    let body = encode_skill_record(&born_active)?;

    // Raw put_entity create (bypasses the typed door) hits the batch
    // chokepoint's local-create birth gate.
    let raw_id = EntityId::now();
    let err = vault
        .put_entity(
            &raw_id,
            ENTITY_TYPE_SKILL,
            TimeRange { start: 10, end: 10 },
            11,
            &body,
        )
        .expect_err("local raw create must be born candidate");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
    assert_eq!(vault.get_skill_record(&raw_id)?, None);

    // Batch-builder create: same gate.
    let batch_id = EntityId::now();
    let err = vault
        .batch()
        .put(
            &batch_id,
            ENTITY_TYPE_SKILL,
            TimeRange { start: 12, end: 12 },
            13,
            &body,
        )
        .commit()
        .expect_err("local batch create must be born candidate");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
    assert_eq!(vault.get_skill_record(&batch_id)?, None);
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_create_keeps_writing_already_lifecycled_records() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let mut born_active = human_skill("1.0.0");
    born_active.lifecycle_status = SkillLifecycle::Active;
    // Sync remat carries records admitted (and possibly forked) on another
    // device: the birth and lineage gates are LOCAL-only, so a dangling
    // forkedFrom (parent still on the remote) must replicate fine.
    born_active.forked_from = Some(EntityId::now());
    let body = encode_skill_record(&born_active)?;
    let id = EntityId::now();
    vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_SKILL,
            TimeRange { start: 10, end: 10 },
            11,
            &body,
        )
        .commit()?;
    assert_eq!(vault.get_skill_record(&id)?, Some(born_active));
    Ok(())
}

#[test]
fn forged_fork_lineage_rejected_at_local_create() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());

    // Nonexistent parent.
    let id = EntityId::now();
    let forged = human_skill("1.0.0").with_forked_from(EntityId::now());
    let err = vault
        .put_skill_record(&id, &forged, TimeRange { start: 10, end: 10 }, 11)
        .expect_err("forkedFrom must name a real parent");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
    assert_eq!(vault.get_skill_record(&id)?, None);

    // Wrong-type parent.
    let person = EntityId::now();
    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 10, end: 10 },
        11,
        b"actor fixture",
    )?;
    let forged = human_skill("1.0.0").with_forked_from(person);
    let err = vault
        .put_skill_record(&id, &forged, TimeRange { start: 12, end: 12 }, 13)
        .expect_err("forkedFrom parent must be a type-7 SKILL");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);

    // Self-parent.
    let forged = human_skill("1.0.0").with_forked_from(id);
    let err = vault
        .put_skill_record(&id, &forged, TimeRange { start: 14, end: 14 }, 15)
        .expect_err("forkedFrom cannot name the fork itself");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);

    // The raw/batch chokepoint enforces the same law without the typed door.
    let raw_id = EntityId::now();
    let dangling = encode_skill_record(&human_skill("1.0.0").with_forked_from(EntityId::now()))?;
    let err = vault
        .put_entity(
            &raw_id,
            ENTITY_TYPE_SKILL,
            TimeRange { start: 16, end: 16 },
            17,
            &dangling,
        )
        .expect_err("raw create must validate lineage too");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
    assert_eq!(vault.get_skill_record(&raw_id)?, None);

    // The fork door itself still passes: real parent, door-authored edge.
    let parent_id = EntityId::now();
    vault.put_skill_record(
        &parent_id,
        &imported_skill("1.0.0"),
        TimeRange { start: 20, end: 20 },
        21,
    )?;
    let fork_id = EntityId::now();
    vault.fork_skill_record(
        &parent_id,
        &fork_id,
        "oneiron.skill.imported.local",
        TimeRange { start: 22, end: 22 },
        23,
    )?;
    assert_eq!(
        vault.get_skill_record(&fork_id)?.map(|r| r.forked_from),
        Some(Some(parent_id))
    );
    Ok(())
}
