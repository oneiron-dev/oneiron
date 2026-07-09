//! AGENT_DEF (ONE-1443) tests. Mapped 1:1 to the D9 acceptance-criteria plan:
//! CRUD round-trips, the shared SkillRecord-shaped lifecycle gate, generic-put
//! parity through the batch seams, the validation matrix (including the
//! scope/world cross-field invariant), and the host-agnostic pinned-key
//! contract.

use super::*;
use crate::error::ErrorKind;
use crate::registry::{
    ENTITY_TYPE_SKILL, EntityClassification, TypeByteBand, band_of, entity_type_registry_entry,
    is_structural_kind, short_id_prefix,
};
use crate::skill::{SkillRecord, encode_skill_record};
use crate::types::{HnswConfig, TextAnalyzerConfig, VaultConfig};

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
        (Value::from("definedVia"), Value::from("define_agent")),
        (Value::from("seed"), Value::from(seed)),
    ])
}

fn world_id() -> EntityId {
    EntityId::from_bytes([0x11; 16]).expect("non-reserved world id")
}

/// Fully-populated, human-authored fixture exercising every composition facet.
fn full_agent(version: &str) -> AgentDefinition {
    AgentDefinition::new(
        "oneiron.agent.scout",
        "Scout — a fully populated agent fixture",
        version,
        Some("You are Scout. Prefer terse answers.".to_owned()),
        vec![
            SkillDependency::with_min_version("oneiron.skill.search", ">=1.0.0"),
            SkillDependency::new("oneiron.skill.summarize"),
        ],
        vec!["linkedin_mcp".to_owned(), "gmail".to_owned()],
        vec![
            McpRef::with_min_version("code.fs", ">=0.2.0"),
            McpRef::new("code.http"),
        ],
        Some(ModelTierRef("fast".to_owned())),
        AgentScope::World(world_id()),
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        provenance(0xA1),
    )
}

/// Minimal human-authored fixture: empty lists, no optional keys, scope All.
fn minimal_agent(version: &str) -> AgentDefinition {
    AgentDefinition::new(
        "oneiron.agent.minimal",
        "Minimal agent fixture",
        version,
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        provenance(0xB1),
    )
}

/// Generated fixture: `source == Generated`, `generated == true`.
fn generated_agent(version: &str) -> AgentDefinition {
    AgentDefinition::new(
        "oneiron.agent.generated",
        "Generated agent fixture",
        version,
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
        ClaimSource::Generated,
        0.75,
        true,
        false,
        provenance(0xC1),
    )
}

fn encode_value(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).expect("encode msgpack");
    out
}

fn body_from(entries: Vec<(&'static str, Value)>) -> Vec<u8> {
    encode_value(&Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    ))
}

/// A canonical valid body (scope=all, all optional keys absent) that individual
/// wire-format tests clone and mutate.
fn valid_scope_all_entries() -> Vec<(&'static str, Value)> {
    vec![
        ("agentId", Value::from("oneiron.agent.wire")),
        ("desc", Value::from("Wire fixture")),
        ("version", Value::from("1.0.0")),
        ("skills", Value::Array(Vec::new())),
        ("connectors", Value::Array(Vec::new())),
        ("codeModeMcps", Value::Array(Vec::new())),
        ("scope", Value::from("all")),
        ("approvalStatus", Value::from("approved")),
        ("lifecycleStatus", Value::from("active")),
        ("source", Value::from("user_stated")),
        ("confidence", Value::F32(1.0)),
        ("generated", Value::Boolean(false)),
        ("humanAuthored", Value::Boolean(true)),
        ("provenance", provenance(0xD1)),
    ]
}

fn encoded_body_keys(def: &AgentDefinition) -> Vec<String> {
    let bytes = encode_agent_definition(def).expect("encode fixture");
    let mut cursor = bytes.as_slice();
    let value = rmpv::decode::read_value(&mut cursor).expect("decode map");
    let Value::Map(entries) = value else {
        panic!("body is not a map");
    };
    entries
        .into_iter()
        .map(|(key, _)| key.as_str().expect("string key").to_owned())
        .collect()
}

// AC-1 test 1: define_agent (vault alias) then get round-trips a fully-populated
// record — every composition facet plus the lifecycle block, bit-for-bit.
#[test]
fn define_agent_round_trips_fully_populated_record() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = EntityId::now();
    let def = full_agent("1.2.3");

    vault.define_agent(&id, &def, TimeRange { start: 10, end: 10 }, 11)?;
    let decoded = vault
        .get_agent_definition(&id)?
        .ok_or(Error::EntityNotFound)?;

    assert_eq!(decoded, def);
    assert_eq!(decoded.skills[0].min_version.as_deref(), Some(">=1.0.0"));
    assert_eq!(decoded.skills[1].min_version, None);
    assert_eq!(decoded.connectors, vec!["linkedin_mcp", "gmail"]);
    assert_eq!(decoded.code_mode_mcps[0].key, "code.fs");
    assert_eq!(
        decoded.model_tier.as_ref().map(ModelTierRef::as_str),
        Some("fast")
    );
    assert_eq!(decoded.scope, AgentScope::World(world_id()));
    assert_eq!(vault.get_entity_type(&id)?, Some(ENTITY_TYPE_AGENT_DEF));
    Ok(())
}

// AC-1 test 2: minimal record round-trips and elides absent optional keys.
#[test]
fn minimal_record_round_trips_and_elides_optional_keys() -> Result<()> {
    let def = minimal_agent("1.0.0");
    let encoded = encode_agent_definition(&def)?;
    let decoded = decode_agent_definition(&encoded)?;
    assert_eq!(decoded, def);

    let keys = encoded_body_keys(&def);
    assert!(!keys.iter().any(|k| k == "instructions"));
    assert!(!keys.iter().any(|k| k == "modelTier"));
    assert!(!keys.iter().any(|k| k == "world"));
    Ok(())
}

// AC-1 test 3: get on a missing id is Ok(None); get on another type errors.
#[test]
fn get_missing_is_none_and_wrong_type_errors() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    assert_eq!(vault.get_agent_definition(&EntityId::now())?, None);

    let skill_id = EntityId::now();
    let skill = SkillRecord::new(
        "oneiron.skill.human",
        "Human skill fixture",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        provenance(0xE1),
    );
    vault.put_skill_record(&skill_id, &skill, TimeRange { start: 10, end: 10 }, 11)?;

    let err = vault
        .get_agent_definition(&skill_id)
        .expect_err("SKILL entity must not decode as AGENT_DEF");
    assert_eq!(err.kind(), ErrorKind::InvalidAgentDefBody);
    Ok(())
}

// AC-1 test 4: update happy path — mutate composition + bump version.
#[test]
fn update_agent_definition_happy_path() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = EntityId::now();
    let prior = full_agent("1.0.0");
    vault.put_agent_definition(&id, &prior, TimeRange { start: 10, end: 10 }, 11)?;

    let mut updated = full_agent("1.1.0");
    updated.skills = vec![SkillDependency::new("oneiron.skill.new")];
    vault.update_agent_definition(&id, &updated, TimeRange { start: 12, end: 12 }, 13)?;

    assert_eq!(vault.get_agent_definition(&id)?, Some(updated));
    Ok(())
}

// AC-2 test 5: the immutability gate mirrors the SkillRecord update rules.
#[test]
fn update_gate_freezes_identity_and_authorship() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = EntityId::now();
    let prior = full_agent("1.0.0");
    vault.put_agent_definition(&id, &prior, TimeRange { start: 10, end: 10 }, 11)?;

    // agentId cannot change.
    let mut renamed = full_agent("1.1.0");
    renamed.agent_id = "oneiron.agent.renamed".to_owned();
    assert_eq!(
        vault
            .update_agent_definition(&id, &renamed, TimeRange { start: 12, end: 12 }, 13)
            .expect_err("agentId change must be rejected")
            .kind(),
        ErrorKind::InvalidAgentDefBody
    );

    // Authorship flags (and source) cannot change.
    let mut reauthored = full_agent("1.1.0");
    reauthored.generated = true;
    reauthored.human_authored = false;
    reauthored.source = ClaimSource::Generated;
    assert_eq!(
        vault
            .update_agent_definition(&id, &reauthored, TimeRange { start: 12, end: 12 }, 13)
            .expect_err("authorship change must be rejected")
            .kind(),
        ErrorKind::InvalidAgentDefBody
    );

    // Body change without a version bump is rejected.
    let mut same_version = full_agent("1.0.0");
    same_version.desc = "Changed without a version bump".to_owned();
    assert_eq!(
        vault
            .update_agent_definition(&id, &same_version, TimeRange { start: 12, end: 12 }, 13)
            .expect_err("body change without version bump must be rejected")
            .kind(),
        ErrorKind::InvalidAgentDefBody
    );

    // No-op update passes.
    vault.update_agent_definition(&id, &prior, TimeRange { start: 10, end: 10 }, 11)?;
    assert_eq!(vault.get_agent_definition(&id)?, Some(prior));
    Ok(())
}

// AC-2 test 6: the gate fires on the generic put_entity path (both batch seams),
// proving it is machinery and not method-local convention.
#[test]
fn generic_put_runs_validation_and_version_gate() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());

    // A valid raw put succeeds and reads back.
    let id = EntityId::now();
    let def = full_agent("1.0.0");
    vault.put_entity(
        &id,
        ENTITY_TYPE_AGENT_DEF,
        TimeRange { start: 10, end: 10 },
        11,
        &encode_agent_definition(&def)?,
    )?;
    assert_eq!(vault.get_agent_definition(&id)?, Some(def.clone()));

    // Malformed bodies are rejected by the validate_public_raw_put seam.
    let unknown_key = {
        let mut entries = valid_scope_all_entries();
        entries.push(("eiriRosterName", Value::from("Scout")));
        body_from(entries)
    };
    let duplicate_key = {
        let mut entries = valid_scope_all_entries();
        entries.push(("agentId", Value::from("dupe")));
        body_from(entries)
    };
    let trailing = {
        let mut bytes = body_from(valid_scope_all_entries());
        bytes.push(0x00);
        bytes
    };
    for (case, bad) in [
        ("not messagepack", b"not messagepack".to_vec()),
        ("unknown key", unknown_key),
        ("duplicate key", duplicate_key),
        ("trailing bytes", trailing),
    ] {
        let err = vault
            .put_entity(
                &EntityId::now(),
                ENTITY_TYPE_AGENT_DEF,
                TimeRange { start: 10, end: 10 },
                11,
                &bad,
            )
            .expect_err(case);
        assert_eq!(err.kind(), ErrorKind::InvalidAgentDefBody, "{case}");
    }

    // A raw second put that violates the version gate is rejected by apply_put.
    let mut forged = full_agent("1.0.0");
    forged.desc = "Body changed without a version bump".to_owned();
    let err = vault
        .put_entity(
            &id,
            ENTITY_TYPE_AGENT_DEF,
            TimeRange { start: 12, end: 12 },
            13,
            &encode_agent_definition(&forged)?,
        )
        .expect_err("raw update must run the AGENT_DEF version gate");
    assert_eq!(err.kind(), ErrorKind::InvalidAgentDefBody);
    assert_eq!(vault.get_agent_definition(&id)?, Some(def));
    Ok(())
}

// AC-2 test 7: the struct-level validation matrix — every arm is InvalidAgentDefBody.
#[test]
fn validation_matrix_rejects_malformed_records() {
    let reject = |def: AgentDefinition, case: &str| {
        assert_eq!(
            encode_agent_definition(&def).expect_err(case).kind(),
            ErrorKind::InvalidAgentDefBody,
            "{case}"
        );
    };

    let mut bad = full_agent("1.0.0");
    bad.confidence = 1.5;
    reject(bad, "confidence above the unit interval");

    let mut bad = full_agent("1.0.0");
    bad.confidence = f32::NAN;
    reject(bad, "confidence NaN");

    let mut bad = full_agent("1.0.0");
    bad.generated = true; // both generated and human_authored true
    reject(bad, "both authorship flags true");

    let mut bad = full_agent("1.0.0");
    bad.human_authored = false; // both false
    reject(bad, "both authorship flags false");

    let mut bad = generated_agent("1.0.0");
    bad.source = ClaimSource::UserStated; // generated flag mismatches source
    reject(bad, "generated flag mismatches source");

    let mut bad = full_agent("1.0.0");
    bad.agent_id = String::new();
    reject(bad, "empty agentId");

    let mut bad = full_agent("1.0.0");
    bad.agent_id = "a".repeat(257);
    reject(bad, "oversize agentId");

    let mut bad = full_agent("1.0.0");
    bad.desc = "d".repeat(4097);
    reject(bad, "oversize desc");

    let mut bad = full_agent("1.0.0");
    bad.version = "v".repeat(129);
    reject(bad, "oversize version");

    let mut bad = full_agent("1.0.0");
    bad.instructions = Some("i".repeat(16_385));
    reject(bad, "oversize instructions");

    let mut bad = full_agent("1.0.0");
    bad.provenance = Value::Map(Vec::new());
    reject(bad, "empty provenance map");

    let mut bad = full_agent("1.0.0");
    bad.provenance = Value::Nil;
    reject(bad, "nil provenance");

    let mut bad = full_agent("1.0.0");
    bad.skills = (0..65)
        .map(|i| SkillDependency::new(format!("oneiron.skill.{i}")))
        .collect();
    reject(bad, "over-cap skills list");

    let mut bad = full_agent("1.0.0");
    bad.skills = vec![SkillDependency::new("dup"), SkillDependency::new("dup")];
    reject(bad, "duplicate skill dependency");

    let mut bad = full_agent("1.0.0");
    bad.connectors = vec!["dup".to_owned(), "dup".to_owned()];
    reject(bad, "duplicate connector");

    let mut bad = full_agent("1.0.0");
    bad.code_mode_mcps = vec![McpRef::new("dup"), McpRef::new("dup")];
    reject(bad, "duplicate MCP ref");
}

// AC-2 test 7 (continued): wire-format arms the struct cannot express — unknown
// scope discriminant and the scope/world cross-field invariant, both directions.
#[test]
fn validation_matrix_rejects_scope_wire_violations() {
    let reject = |entries: Vec<(&'static str, Value)>, case: &str| {
        let err = decode_agent_definition(&body_from(entries)).expect_err(case);
        assert_eq!(err.kind(), ErrorKind::InvalidAgentDefBody, "{case}");
    };

    let mut entries = valid_scope_all_entries();
    for entry in &mut entries {
        if entry.0 == "scope" {
            entry.1 = Value::from("galaxy");
        }
    }
    reject(entries, "unknown scope discriminant");

    // scope=world with no world key.
    let mut entries = valid_scope_all_entries();
    for entry in &mut entries {
        if entry.0 == "scope" {
            entry.1 = Value::from("world");
        }
    }
    reject(entries, "scope world without a world key");

    // scope=world with malformed world hex.
    let mut entries = valid_scope_all_entries();
    for entry in &mut entries {
        if entry.0 == "scope" {
            entry.1 = Value::from("world");
        }
    }
    entries.push(("world", Value::from("not-hex")));
    reject(entries, "scope world with malformed world hex");

    // scope=all with a world key present.
    let mut entries = valid_scope_all_entries();
    entries.push(("world", Value::from(world_id().to_hex())));
    reject(entries, "scope all with a world key present");

    // scope=base with a world key present.
    let mut entries = valid_scope_all_entries();
    for entry in &mut entries {
        if entry.0 == "scope" {
            entry.1 = Value::from("base");
        }
    }
    entries.push(("world", Value::from(world_id().to_hex())));
    reject(entries, "scope base with a world key present");
}

// AC-2 test 7b: the optional-with-default decode branch — three distinct paths.
#[test]
fn optional_key_decode_matrix() -> Result<()> {
    // Missing all optional keys decodes with defaults.
    let decoded = decode_agent_definition(&body_from(valid_scope_all_entries()))?;
    assert_eq!(decoded.instructions, None);
    assert_eq!(decoded.model_tier, None);
    assert_eq!(decoded.scope, AgentScope::All);

    // Missing a required key errors.
    let mut entries = valid_scope_all_entries();
    entries.retain(|(key, _)| *key != "desc");
    assert_eq!(
        decode_agent_definition(&body_from(entries))
            .expect_err("missing required key desc")
            .kind(),
        ErrorKind::InvalidAgentDefBody
    );

    // An unknown key errors.
    let mut entries = valid_scope_all_entries();
    entries.push(("mysteryKey", Value::from(1_u64)));
    assert_eq!(
        decode_agent_definition(&body_from(entries))
            .expect_err("unknown key")
            .kind(),
        ErrorKind::InvalidAgentDefBody
    );
    Ok(())
}

// AC-2 test 8: registry/spec facts plus type-byte immutability.
#[test]
fn registry_row_and_type_byte_immutability() -> Result<()> {
    assert_eq!(ENTITY_TYPE_AGENT_DEF, 17);
    let entry = entity_type_registry_entry(ENTITY_TYPE_AGENT_DEF).expect("AGENT_DEF registry row");
    assert_eq!(entry.kind, "AGENT_DEF");
    assert_eq!(entry.classification, EntityClassification::Core);
    assert_eq!(entry.band, TypeByteBand::Core);
    assert_eq!(short_id_prefix(ENTITY_TYPE_AGENT_DEF)?, "ag");
    assert_eq!(band_of(ENTITY_TYPE_AGENT_DEF), TypeByteBand::Core);
    assert!(is_structural_kind(ENTITY_TYPE_AGENT_DEF));

    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = EntityId::now();
    vault.put_agent_definition(
        &id,
        &full_agent("1.0.0"),
        TimeRange { start: 10, end: 10 },
        11,
    )?;

    // Re-putting the id under a different type is rejected.
    let skill = SkillRecord::new(
        "oneiron.skill.human",
        "Human skill fixture",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        provenance(0xF1),
    );
    let err = vault
        .put_entity(
            &id,
            ENTITY_TYPE_SKILL,
            TimeRange { start: 12, end: 12 },
            13,
            &encode_skill_record(&skill)?,
        )
        .expect_err("type byte is immutable");
    assert!(matches!(err, Error::EntityTypeImmutable { .. }));
    Ok(())
}

// AC-3 test 9: host-agnostic pinned-key contract.
#[test]
fn pinned_key_contract_is_stable() {
    assert_eq!(
        AGENT_DEF_BODY_KEYS,
        [
            "agentId",
            "desc",
            "version",
            "instructions",
            "skills",
            "connectors",
            "codeModeMcps",
            "modelTier",
            "scope",
            "world",
            "approvalStatus",
            "lifecycleStatus",
            "source",
            "confidence",
            "generated",
            "humanAuthored",
            "provenance",
        ]
    );
    assert_eq!(MCP_REF_KEYS, ["key", "minVersion"]);

    // A host field smuggled into the body is rejected at decode.
    let mut entries = valid_scope_all_entries();
    entries.push(("eiriRosterName", Value::from("Scout")));
    assert_eq!(
        decode_agent_definition(&body_from(entries))
            .expect_err("host field must be rejected")
            .kind(),
        ErrorKind::InvalidAgentDefBody
    );
}

// Edge test 10: dangling refs are accepted at rest (no existence checks).
#[test]
fn dangling_refs_are_accepted_at_rest() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = EntityId::now();
    let mut def = full_agent("1.0.0");
    def.skills = vec![SkillDependency::new("oneiron.skill.does-not-exist")];
    def.connectors = vec!["connector_that_is_not_registered".to_owned()];
    def.code_mode_mcps = vec![McpRef::new("mcp.absent")];

    vault.put_agent_definition(&id, &def, TimeRange { start: 10, end: 10 }, 11)?;
    assert_eq!(vault.get_agent_definition(&id)?, Some(def));
    Ok(())
}

// Edge test 11: AgentScope maps to the runtime WorldScope for AGENT-3 dispatch.
#[test]
fn agent_scope_maps_to_world_scope() {
    assert_eq!(AgentScope::All.to_world_scope(), WorldScope::All);
    assert_eq!(AgentScope::Base.to_world_scope(), WorldScope::Base);
    assert_eq!(
        AgentScope::World(world_id()).to_world_scope(),
        WorldScope::World(world_id())
    );
}

// Edge test 12: retire path via lifecycle_status = Retracted (with version bump).
#[test]
fn retire_path_round_trips() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = EntityId::now();
    vault.put_agent_definition(
        &id,
        &full_agent("1.0.0"),
        TimeRange { start: 10, end: 10 },
        11,
    )?;

    let mut retired = full_agent("1.1.0");
    retired.lifecycle_status = ClaimLifecycleStatus::Retracted;
    vault.update_agent_definition(&id, &retired, TimeRange { start: 12, end: 12 }, 13)?;

    assert_eq!(vault.get_agent_definition(&id)?, Some(retired));
    Ok(())
}

// Edge test 13: the D5 tool-layer defaults produce a record that validates.
#[test]
fn tool_layer_defaults_validate() -> Result<()> {
    // Mirrors what the MCP/tool `define_agent` verb synthesizes when no
    // lifecycle args are supplied by the caller (D5 defaults table).
    let def = AgentDefinition::new(
        "oneiron.agent.tool",
        "Defined via the tool-layer verb",
        "0.1.0",
        None,
        vec![SkillDependency::new("oneiron.skill.search")],
        vec!["gmail".to_owned()],
        vec![McpRef::new("code.fs")],
        Some(ModelTierRef("fast".to_owned())),
        AgentScope::All,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Value::Map(vec![(
            Value::from("definedVia"),
            Value::from("define_agent"),
        )]),
    );
    encode_agent_definition(&def)?;
    Ok(())
}
