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
use crate::skill::{SkillLifecycle, SkillRecord, encode_skill_record};
use crate::test_util::embedding_test_config;

fn provenance(seed: u8) -> Value {
    Value::Map(vec![
        (Value::from("definedVia"), Value::from("define_agent")),
        (Value::from("seed"), Value::from(seed)),
    ])
}

fn world_id() -> EntityId {
    crate::test_util::entity(0x60)
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
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        provenance(0xA1),
        None,
        true,
        None,
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
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        provenance(0xB1),
        None,
        true,
        None,
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
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
        ClaimSource::Generated,
        0.75,
        true,
        false,
        provenance(0xC1),
        None,
        true,
        None,
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
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
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
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    assert_eq!(vault.get_agent_definition(&EntityId::now())?, None);

    let skill_id = EntityId::now();
    let skill = SkillRecord::new(
        "oneiron.skill.human",
        "Human skill fixture",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
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
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
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
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
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
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());

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
        entries.push(("rosterDisplayName", Value::from("Scout")));
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

    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
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
        SkillLifecycle::Candidate,
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
            "ceiling",
            "forkedFrom",
            "approvalStatus",
            "lifecycleStatus",
            "source",
            "confidence",
            "generated",
            "humanAuthored",
            "provenance",
            "logicalId",
            "enabled",
            "displayName",
        ]
    );
    assert_eq!(MCP_REF_KEYS, ["key", "minVersion"]);

    // A host field smuggled into the body is rejected at decode.
    let mut entries = valid_scope_all_entries();
    entries.push(("rosterDisplayName", Value::from("Scout")));
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
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
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
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
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

// ─── ONE-1890: seeded roster rows, row forks, and the new codec keys ────────

/// The canonical manifest's pinned row id for `logical_id`. Constructed from
/// manifest DATA, never from a compiled table.
fn pinned_row_id(logical_id: &str) -> EntityId {
    super::legacy_logical_id_row(logical_id)
        .expect("embedded manifest parses")
        .expect("logical id is in the canonical manifest")
}

/// The embedded manifest with its trailing `definitions` entries dropped —
/// the N-of-N+1 fixture for reconciliation tests. Every retained row stays a
/// canonical row, so the `sys.*` put-decode reservation still admits it.
fn truncated_manifest(rows: usize) -> SystemAgentDefinitionManifest {
    let mut json: serde_json::Value =
        serde_json::from_str(SYSTEM_AGENT_DEFINITIONS_V1_JSON).expect("embedded manifest is JSON");
    let definitions = json
        .get_mut("definitions")
        .and_then(serde_json::Value::as_array_mut)
        .expect("manifest carries a definitions array");
    definitions.truncate(rows);
    parse_system_agent_definition_manifest(&json.to_string()).expect("truncated manifest is valid")
}

fn manifest_json_with(mutate: impl FnOnce(&mut serde_json::Value)) -> String {
    let mut json: serde_json::Value =
        serde_json::from_str(SYSTEM_AGENT_DEFINITIONS_V1_JSON).expect("embedded manifest is JSON");
    mutate(&mut json);
    json.to_string()
}

fn open_unseeded() -> (tempfile::TempDir, crate::Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = crate::Vault::open_unseeded_for_test(dir.path(), embedding_test_config())
        .expect("open unseeded vault");
    (dir, vault)
}

fn reconcile(vault: &crate::Vault, manifest: &SystemAgentDefinitionManifest) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let result = reconcile_system_agent_definitions_in(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        true,
        manifest,
    );
    if result.is_ok() {
        wtxn.commit()?;
    } else {
        drop(wtxn);
    }
    result
}

// Done-means: the manifest's identity table is pinned, per-field namespaces
// are unique, and schema v1 requires actor id == row id.
#[test]
fn canonical_manifest_pins_the_six_baseline_rows() -> Result<()> {
    let manifest = parse_system_agent_definition_manifest(SYSTEM_AGENT_DEFINITIONS_V1_JSON)?;
    let expected = [
        ("sys.scout", 0xA1_u8, "Scout"),
        ("sys.keeper", 0xA2, "Keeper"),
        ("sys.creative", 0xA3, "Creative"),
        ("sys.herald", 0xA4, "Herald"),
        ("sys.guide", 0xA5, "Guide"),
        ("sys.default", 0xA6, "Default"),
    ];
    assert_eq!(manifest.definitions.len(), expected.len());
    for (seed, (logical_id, byte, display_name)) in manifest.definitions.iter().zip(expected) {
        assert_eq!(seed.logical_id, logical_id);
        assert_eq!(seed.display_name, display_name);
        assert_eq!(seed.entity_id.0.as_bytes(), &[byte; 16]);
        assert_eq!(seed.actor_entity_id.0, seed.entity_id.0);
        assert!(seed.enabled);
    }
    Ok(())
}

// Done-means: malformed manifests fail before any row commits; an actor id
// EQUAL to its row id is not rejected.
#[test]
fn manifest_rejects_duplicate_or_malformed_agent_definition() {
    let reject = |json: String, case: &str| {
        let err = parse_system_agent_definition_manifest(&json).expect_err(case);
        assert_eq!(err.kind(), ErrorKind::InvalidAgentDefBody, "{case}");
    };

    reject(
        manifest_json_with(|json| json["definitions"][0]["entity_id"] = "zzzz".into()),
        "malformed hex",
    );
    reject(
        manifest_json_with(|json| json["definitions"][0]["entity_id"] = "a1a1a1a1".into()),
        "wrong id width",
    );
    reject(
        manifest_json_with(|json| {
            json["definitions"][1]["logical_id"] = "sys.scout".into();
        }),
        "duplicate logical id",
    );
    reject(
        manifest_json_with(|json| {
            json["definitions"][1]["entity_id"] = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1".into();
            json["definitions"][1]["actor_entity_id"] = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1".into();
        }),
        "duplicate row id",
    );
    reject(
        manifest_json_with(|json| {
            json["definitions"][1]["actor_entity_id"] = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1".into();
        }),
        "duplicate actor id",
    );
    reject(
        manifest_json_with(|json| json["version"] = 2.into()),
        "wrong schema version",
    );
    reject(
        manifest_json_with(|json| json["definitions"][0]["nickname"] = "scout".into()),
        "unknown row key",
    );
    reject(
        manifest_json_with(|json| json["rosterName"] = "roster".into()),
        "unknown top-level key",
    );
    reject(
        manifest_json_with(|json| json["definitions"][0]["display_name"] = "  ".into()),
        "blank display name",
    );
    reject(
        manifest_json_with(|json| {
            json["definitions"][0]["actor_entity_id"] = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1".into();
        }),
        "actor id differs from row id",
    );

    // Equality is the schema-v1 REQUIREMENT, not a rejection.
    parse_system_agent_definition_manifest(SYSTEM_AGENT_DEFINITIONS_V1_JSON)
        .expect("actor id equal to row id is valid");
}

// Done-means: a fresh seeded vault carries all six rows, readable through the
// exact `Vault::get_agent_definition` API.
#[test]
fn fresh_vault_seeds_system_agent_definitions() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    for logical_id in [
        "sys.scout",
        "sys.keeper",
        "sys.creative",
        "sys.herald",
        "sys.guide",
        "sys.default",
    ] {
        let id = pinned_row_id(logical_id);
        let definition = vault
            .get_agent_definition(&id)?
            .expect("seeded row is readable through the canonical get");
        assert_eq!(definition.logical_id.as_deref(), Some(logical_id));
        assert_eq!(definition.agent_id, logical_id);
        assert!(definition.enabled);
        assert!(definition.display_name.is_some());
        assert_eq!(vault.get_entity_type(&id)?, Some(ENTITY_TYPE_AGENT_DEF));
        // The resolver reads the same stored row.
        assert_eq!(
            vault.get_seeded_agent_definition_by_logical_id(logical_id)?,
            Some((id, definition))
        );
    }
    assert_eq!(
        vault.get_seeded_agent_definition_by_logical_id("sys.unknown")?,
        None
    );
    Ok(())
}

// The resolver hands stored-row decode failures back rather than reporting a
// miss — the server row router's `Err` arm is a pass-through of exactly this.
#[test]
fn seeded_resolver_propagates_stored_decode_failure() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let keeper_id = pinned_row_id("sys.keeper");
    vault.with_write_txn(|wtxn| {
        // 0xC1 is the reserved, never-valid MessagePack marker.
        let mut corrupt = vault
            .store
            .entities
            .get(wtxn, keeper_id.as_bytes())?
            .expect("keeper row bytes")[..crate::batch::ENTITY_METADATA_HEADER_LEN]
            .to_vec();
        corrupt.push(0xC1);
        vault
            .store
            .entities
            .put(wtxn, keeper_id.as_bytes(), &corrupt)?;
        Ok(())
    })?;
    assert_eq!(
        vault
            .get_seeded_agent_definition_by_logical_id("sys.keeper")
            .expect_err("a corrupt stored row propagates")
            .kind(),
        ErrorKind::InvalidAgentDefBody
    );
    Ok(())
}

// Done-means: two independent fresh vaults produce byte-identical seeded rows
// (this is why `enabled` is always-encoded).
#[test]
fn seeded_agent_definition_ids_are_cross_vault_stable() -> Result<()> {
    let (_dir_a, vault_a) = crate::test_util::open_test_vault_with(embedding_test_config());
    let (_dir_b, vault_b) = crate::test_util::open_test_vault_with(embedding_test_config());
    for logical_id in ["sys.scout", "sys.herald", "sys.default"] {
        let (id_a, def_a) = vault_a
            .get_seeded_agent_definition_by_logical_id(logical_id)?
            .expect("row a");
        let (id_b, def_b) = vault_b
            .get_seeded_agent_definition_by_logical_id(logical_id)?
            .expect("row b");
        assert_eq!(id_a, id_b);
        assert_eq!(
            encode_agent_definition(&def_a)?,
            encode_agent_definition(&def_b)?,
            "{logical_id} must encode byte-identically across vaults"
        );
    }
    Ok(())
}

// Done-means: reseeding creates exactly the missing row and never rewrites an
// existing one — user edits, runtime display_name, and enabled=false survive.
#[test]
fn reseed_adds_missing_rows_without_overwrite() -> Result<()> {
    let (_dir, vault) = open_unseeded();
    reconcile(&vault, &truncated_manifest(5))?;
    assert_eq!(
        vault.get_agent_definition(&pinned_row_id("sys.default"))?,
        None
    );

    // A user edits one seeded row: new desc, new display name, disabled.
    let scout_id = pinned_row_id("sys.scout");
    let mut edited = vault
        .get_agent_definition(&scout_id)?
        .expect("scout row exists");
    edited.version = "2".to_owned();
    edited.desc = "user edited scout".to_owned();
    edited.display_name = Some("My Scout".to_owned());
    edited.enabled = false;
    vault.update_agent_definition(&scout_id, &edited, TimeRange { start: 5, end: 5 }, 6)?;
    let edited_bytes = vault.get_raw(&scout_id)?.expect("edited row bytes");

    reconcile(
        &vault,
        &parse_system_agent_definition_manifest(SYSTEM_AGENT_DEFINITIONS_V1_JSON)?,
    )?;

    let created = vault
        .get_agent_definition(&pinned_row_id("sys.default"))?
        .expect("the missing sixth row is created");
    assert_eq!(created.logical_id.as_deref(), Some("sys.default"));
    assert_eq!(
        vault.get_raw(&scout_id)?,
        Some(edited_bytes),
        "an existing row is left byte-for-byte unchanged"
    );
    Ok(())
}

// Done-means: a pre-1890 valid type-17 row squatting a pinned id with no
// `sys.*` logical id is a conflict, never adopted, and never resolved.
#[test]
fn legacy_foreign_occupant_is_conflict_not_adopted() -> Result<()> {
    let (_dir, vault) = open_unseeded();
    let scout_id = pinned_row_id("sys.scout");
    let mut occupant = full_agent("1.0.0");
    occupant.agent_id = "legacy.occupant".to_owned();
    vault.put_agent_definition(&scout_id, &occupant, TimeRange { start: 1, end: 1 }, 1)?;

    let err = reconcile(
        &vault,
        &parse_system_agent_definition_manifest(SYSTEM_AGENT_DEFINITIONS_V1_JSON)?,
    )
    .expect_err("a foreign occupant at a pinned id is a conflict");
    assert_eq!(err.kind(), ErrorKind::SeededAgentDefinitionConflict);
    assert!(matches!(
        err,
        Error::SeededAgentDefinitionConflict { id } if id == scout_id
    ));

    // No overwrite, no adoption, and the resolver never returns it.
    assert_eq!(
        vault
            .get_agent_definition(&scout_id)?
            .expect("occupant survives")
            .agent_id,
        "legacy.occupant"
    );
    assert_eq!(
        vault
            .get_seeded_agent_definition_by_logical_id("sys.scout")?
            .expect("resolver reads whatever row is stored")
            .1
            .logical_id,
        None
    );
    Ok(())
}

// Done-means: an occupant of another entity type at a pinned id is also a
// conflict — no overwrite, no replacement id.
#[test]
fn foreign_entity_type_at_pinned_id_is_conflict() -> Result<()> {
    let (_dir, vault) = open_unseeded();
    let keeper_id = pinned_row_id("sys.keeper");
    let skill = SkillRecord::new(
        "legacy.skill",
        "legacy skill body",
        "1",
        ClaimApprovalStatus::Proposed,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        provenance(0xE1),
    );
    vault.put_entity(
        &keeper_id,
        ENTITY_TYPE_SKILL,
        TimeRange { start: 1, end: 1 },
        1,
        &encode_skill_record(&skill)?,
    )?;

    let err = reconcile(
        &vault,
        &parse_system_agent_definition_manifest(SYSTEM_AGENT_DEFINITIONS_V1_JSON)?,
    )
    .expect_err("a non-AGENT_DEF occupant is a conflict");
    assert_eq!(err.kind(), ErrorKind::SeededAgentDefinitionConflict);
    assert_eq!(vault.get_entity_type(&keeper_id)?, Some(ENTITY_TYPE_SKILL));
    Ok(())
}

// Done-means: repeated/racing seeded opens converge on one row per pinned id,
// with no alternate ids, duplicate logical ids, or replacement writes.
#[test]
fn reseed_is_idempotent_under_concurrent_open() -> Result<()> {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut snapshots = Vec::new();
    for _ in 0..3 {
        let vault = crate::Vault::open(dir.path(), embedding_test_config())?;
        let mut rows = Vec::new();
        for id in vault.entities_by_type(ENTITY_TYPE_AGENT_DEF)? {
            rows.push((id, vault.get_raw(&id)?.expect("row bytes")));
        }
        rows.sort_by_key(|(id, _)| *id);
        snapshots.push(rows);
    }
    assert_eq!(
        snapshots[0].len(),
        6,
        "one row per pinned id, no alternates"
    );
    assert_eq!(
        snapshots[0], snapshots[1],
        "reopen performs no replacement write"
    );
    assert_eq!(snapshots[1], snapshots[2]);

    let vault = crate::Vault::open(dir.path(), embedding_test_config())?;
    let mut logical_ids = Vec::new();
    for (id, _) in &snapshots[0] {
        logical_ids.push(
            vault
                .get_agent_definition(id)?
                .expect("row decodes")
                .logical_id
                .expect("seeded rows carry a logical id"),
        );
    }
    logical_ids.sort();
    let unique = logical_ids.iter().collect::<std::collections::HashSet<_>>();
    assert_eq!(unique.len(), logical_ids.len(), "no duplicate logical ids");
    Ok(())
}

// Done-means: a pre-1890 vault_meta toggle is consumed ONCE into row state,
// the legacy keys are deleted in the same transaction, and reopening neither
// resurrects nor overwrites the row.
#[test]
fn legacy_toggle_is_consumed_once_into_row_state() -> Result<()> {
    let dir = tempfile::tempdir().expect("temp dir");
    let herald_id = pinned_row_id("sys.herald");
    let mut toggle_key = b"agent_def:system_toggle:v1:".to_vec();
    toggle_key.extend_from_slice(b"sys.herald");

    {
        let vault = crate::Vault::open_unseeded_for_test(dir.path(), embedding_test_config())?;
        vault.with_write_txn(|wtxn| {
            vault
                .store
                .vault_meta
                .put(wtxn, toggle_key.as_slice(), &[0x00])?;
            vault.store.vault_meta.put(
                wtxn,
                b"agent_def:default_reserved_actor_census:v1",
                &[0x00],
            )?;
            Ok(())
        })?;
    }

    let vault = crate::Vault::open(dir.path(), embedding_test_config())?;
    let herald = vault
        .get_agent_definition(&herald_id)?
        .expect("herald row is seeded");
    assert!(!herald.enabled, "the legacy off toggle became row state");
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault.store.vault_meta.get(&rtxn, toggle_key.as_slice())?,
        None
    );
    assert_eq!(
        vault
            .store
            .vault_meta
            .get(&rtxn, b"agent_def:default_reserved_actor_census:v1")?,
        None
    );
    drop(rtxn);
    let bytes = vault.get_raw(&herald_id)?.expect("herald row bytes");
    drop(vault);

    // Reopen: off is row state, not absence — reseed never resurrects it.
    let vault = crate::Vault::open(dir.path(), embedding_test_config())?;
    assert_eq!(vault.get_raw(&herald_id)?, Some(bytes));
    assert!(
        !vault
            .get_agent_definition(&herald_id)?
            .expect("herald row survives")
            .enabled
    );
    Ok(())
}

// Done-means: the old system fork test, replaced by a ROW fork — ordinary put
// path, `forked_from` = source row id, source ceiling copied, new entity id,
// source row untouched.
#[test]
fn seeded_row_forks_through_the_ordinary_row_path() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let (herald_id, herald) = vault
        .get_seeded_agent_definition_by_logical_id("sys.herald")?
        .expect("herald row is seeded");
    let herald_bytes = vault.get_raw(&herald_id)?.expect("herald row bytes");

    let fork_id = EntityId::now();
    let mut fork = herald.clone();
    fork.agent_id = "oneiron.agent.herald.custom".to_owned();
    fork.version = "1".to_owned();
    fork.forked_from = Some(herald_id);
    fork.ceiling = herald.ceiling;
    fork.logical_id = None;
    fork.display_name = None;
    fork.source = ClaimSource::UserStated;
    fork.provenance = Value::Map(vec![(
        Value::from("forkOf"),
        Value::from(herald_id.to_hex()),
    )]);
    vault.put_agent_definition(&fork_id, &fork, TimeRange { start: 10, end: 10 }, 11)?;

    let read = vault
        .get_agent_definition(&fork_id)?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(read, fork);
    assert_ne!(fork_id, herald_id);
    assert_eq!(read.forked_from, Some(herald_id));
    assert_eq!(read.ceiling, herald.ceiling);
    assert_eq!(read.code_mode_mcps, vec![McpRef::new("email")]);
    assert_eq!(
        vault.get_raw(&herald_id)?,
        Some(herald_bytes),
        "forking does not mutate the source row"
    );
    Ok(())
}

// Done-means: the `forkedFrom` wire contract — encode always writes 32
// lower-case hex, the six legacy preset strings decode to their pinned rows,
// unknown strings stay typed decode errors, and the update freeze holds.
#[test]
fn forked_from_entity_id_round_trips() -> Result<()> {
    let parent = pinned_row_id("sys.scout");
    let mut def = full_agent("1.0.0");
    def.forked_from = Some(parent);
    let encoded = encode_agent_definition(&def)?;
    assert_eq!(decode_agent_definition(&encoded)?, def);

    let mut cursor = encoded.as_slice();
    let Value::Map(entries) = rmpv::decode::read_value(&mut cursor).expect("decode map") else {
        panic!("body is a map");
    };
    let wire = entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("forkedFrom"))
        .and_then(|(_, value)| value.as_str())
        .expect("forkedFrom is encoded");
    assert_eq!(wire, parent.to_hex());
    assert_eq!(wire.len(), 32);
    assert!(
        wire.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    );

    // Compat decode: the six legacy preset strings map to their pinned rows.
    for logical_id in [
        "sys.scout",
        "sys.keeper",
        "sys.creative",
        "sys.herald",
        "sys.guide",
        "sys.default",
    ] {
        let mut legacy = valid_scope_all_entries();
        legacy.push(("forkedFrom", Value::from(logical_id)));
        assert_eq!(
            decode_agent_definition(&body_from(legacy))?.forked_from,
            Some(pinned_row_id(logical_id))
        );
    }

    // Unknown strings and non-strings stay typed decode errors.
    for bad in [
        Value::from("sys.unknown"),
        Value::from("nothex"),
        Value::from(1_u64),
    ] {
        let mut entries = valid_scope_all_entries();
        entries.push(("forkedFrom", bad));
        assert_eq!(
            decode_agent_definition(&body_from(entries))
                .expect_err("bad forkedFrom")
                .kind(),
            ErrorKind::InvalidAgentDefBody
        );
    }

    // The existing update freeze rejects a forkedFrom change.
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let id = EntityId::now();
    vault.put_agent_definition(
        &id,
        &full_agent("1.0.0"),
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    let mut grafted = full_agent("1.1.0");
    grafted.forked_from = Some(parent);
    assert_eq!(
        vault
            .update_agent_definition(&id, &grafted, TimeRange { start: 12, end: 12 }, 13)
            .expect_err("forkedFrom cannot change on update")
            .kind(),
        ErrorKind::InvalidAgentDefBody
    );
    Ok(())
}

// Done-means: `logicalId` is frozen-once-Some in all three directions.
#[test]
fn logical_id_cannot_change_on_update() {
    let named = |logical_id: Option<&str>, version: &str| {
        let mut def = full_agent(version);
        def.logical_id = logical_id.map(str::to_owned);
        def
    };
    let cases = [
        (
            named(Some("team.alpha"), "1.0.0"),
            named(Some("team.beta"), "2.0.0"),
        ),
        (named(None, "1.0.0"), named(Some("team.beta"), "2.0.0")),
        (named(Some("team.alpha"), "1.0.0"), named(None, "2.0.0")),
    ];
    for (prior, updated) in cases {
        let err = validate_agent_definition_update(&prior, &updated)
            .expect_err("logicalId is frozen once set");
        assert_eq!(err.kind(), ErrorKind::InvalidAgentDefBody);
        assert!(
            matches!(err, Error::InvalidAgentDefBody(reason) if reason == "logicalId cannot change on update")
        );
    }
}

// Done-means: the `sys.*` namespace is reserved at the put-decode chokepoint —
// an ordinary row cannot claim a seeded logical id.
#[test]
fn ordinary_put_cannot_claim_sys_logical_id() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let id = crate::test_util::entity(0x63);
    let mut squatter = full_agent("1.0.0");
    squatter.logical_id = Some("sys.scout".to_owned());
    let err = vault
        .put_agent_definition(&id, &squatter, TimeRange { start: 10, end: 10 }, 11)
        .expect_err("sys.* logical ids are reserved for seeded rows");
    assert_eq!(err.kind(), ErrorKind::InvalidAgentDefBody);
    assert!(
        matches!(err, Error::InvalidAgentDefBody(reason) if reason == "sys.* logical ids are reserved for seeded rows")
    );
    assert_eq!(vault.get_agent_definition(&id)?, None);

    // A non-`sys.` logical id is ordinary data.
    let mut ordinary = full_agent("1.0.0");
    ordinary.logical_id = Some("team.alpha".to_owned());
    vault.put_agent_definition(&id, &ordinary, TimeRange { start: 10, end: 10 }, 11)?;
    assert_eq!(vault.get_agent_definition(&id)?, Some(ordinary));
    Ok(())
}

// The three additive keys round-trip; `enabled` is the sole always-encode key.
#[test]
fn additive_body_keys_codec() -> Result<()> {
    let mut def = full_agent("1.0.0");
    def.logical_id = Some("team.alpha".to_owned());
    def.display_name = Some("Alpha".to_owned());
    def.enabled = false;
    assert_eq!(
        decode_agent_definition(&encode_agent_definition(&def)?)?,
        def
    );
    let keys = encoded_body_keys(&def);
    for key in ["logicalId", "enabled", "displayName"] {
        assert!(keys.iter().any(|k| k == key), "{key} must encode");
    }

    // Elide-the-default: absent optional keys, `enabled` always present.
    let plain = full_agent("1.0.0");
    assert!(plain.enabled);
    let keys = encoded_body_keys(&plain);
    assert!(!keys.iter().any(|k| k == "logicalId"));
    assert!(!keys.iter().any(|k| k == "displayName"));
    assert!(!keys.iter().any(|k| k == "ceiling"));
    assert!(!keys.iter().any(|k| k == "forkedFrom"));
    assert!(
        keys.iter().any(|k| k == "enabled"),
        "enabled is the sole always-encode key"
    );

    // A pre-1890 body carrying none of the three decodes to the defaults.
    let decoded = decode_agent_definition(&body_from(valid_scope_all_entries()))?;
    assert_eq!(decoded.logical_id, None);
    assert_eq!(decoded.display_name, None);
    assert!(decoded.enabled, "a missing enabled key decodes as true");
    assert_eq!(decoded.ceiling, AgentCeiling::Proposed);
    assert_eq!(decoded.forked_from, None);

    let reject = |entries: Vec<(&'static str, Value)>, case: &str| {
        let err = decode_agent_definition(&body_from(entries)).expect_err(case);
        assert_eq!(err.kind(), ErrorKind::InvalidAgentDefBody, "{case}");
    };
    let mut entries = valid_scope_all_entries();
    entries.push(("enabled", Value::from("yes")));
    reject(entries, "non-boolean enabled");
    let mut entries = valid_scope_all_entries();
    entries.push(("logicalId", Value::from("  ")));
    reject(entries, "blank logicalId");
    let mut entries = valid_scope_all_entries();
    entries.push(("displayName", Value::from(1_u64)));
    reject(entries, "non-string displayName");
    let mut entries = valid_scope_all_entries();
    entries.push(("enabled", Value::Boolean(true)));
    entries.push(("enabled", Value::Boolean(false)));
    reject(entries, "duplicate enabled key");

    // Ceiling still round-trips and still rejects an unknown vocabulary.
    let mut auto = full_agent("1.0.0");
    auto.ceiling = AgentCeiling::Auto;
    assert!(encoded_body_keys(&auto).iter().any(|k| k == "ceiling"));
    let mut entries = valid_scope_all_entries();
    entries.push(("ceiling", Value::from("sometimes")));
    reject(entries, "unknown ceiling vocabulary");
    Ok(())
}

// The landed update-immutability gates still hold.
#[test]
fn update_immutability_preserved() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let scratch_id = EntityId::now();
    vault.put_agent_definition(
        &scratch_id,
        &full_agent("1.0.0"),
        TimeRange { start: 10, end: 10 },
        11,
    )?;

    let mut renamed = full_agent("1.1.0");
    renamed.agent_id = "oneiron.agent.renamed".to_owned();
    assert_eq!(
        vault
            .update_agent_definition(&scratch_id, &renamed, TimeRange { start: 12, end: 12 }, 13)
            .expect_err("agentId cannot change on update")
            .kind(),
        ErrorKind::InvalidAgentDefBody
    );

    // From-scratch definitions are unbounded by any parent: either ceiling
    // authors fine (their only bound is the owner's manifest).
    let auto_id = EntityId::now();
    let mut auto_scratch = full_agent("1.0.0");
    auto_scratch.ceiling = AgentCeiling::Auto;
    vault.put_agent_definition(
        &auto_id,
        &auto_scratch,
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    assert_eq!(vault.get_agent_definition(&auto_id)?, Some(auto_scratch));
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
        AgentCeiling::Proposed,
        None,
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
        None,
        true,
        None,
    );
    encode_agent_definition(&def)?;
    Ok(())
}
