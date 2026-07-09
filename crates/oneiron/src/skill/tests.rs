use super::*;
use crate::config::{HnswConfig, TextAnalyzerConfig, VaultConfig};
use crate::error::ErrorKind;
use crate::registry::{
    EntityClassification, TypeByteBand, entity_type_registry_entry, short_id_prefix,
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
        ClaimLifecycleStatus::Active,
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
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        provenance(0xB1),
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
