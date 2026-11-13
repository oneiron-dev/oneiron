//! `self.skills.package`: an agent with a read permit but no Grant naming the verb is
//! refused, the holder reads its lane's usable skill package with its stored record,
//! files, capabilities and format, and a revoked Grant is refused again. A second
//! skill excluded by the credential's record list answers none as withheld, and a
//! candidate skill in the lane answers none as unloadable. A skill whose package files hold a
//! token answers none to the masked holder, while its clean twin is served (#7149 review
//! round 1). The verb is called by name through the
//! string-keyed embedded door, and the output is read as JSON, so this file uses no
//! item the row adds.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test verb_self_skills_package`
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::authority::{ActSurface, MachineRole, SlipCaveat, VerifiedSlip};
use oneiron::claim::base_world_id;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError};
use oneiron::skill::{SkillLifecycle, SkillRecord, canonical_skill_tree_hash};
use oneiron::skill_hub::HubFile;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::skill_package::land_active_skill_with_files;
use oneiron::verbs::{
    AgentGrantMintRequest, AgentGrantRevokeRequest, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange,
    Vault, VaultConfig, WriteActor,
};
use serde_json::{Value, json};

const SKILL_PACKAGE_READ_TEST_NOW: u64 = 1_700_000_000;
const SKILL_PACKAGE_READ_TEST_VERB: &str = "self.skills.package";

// Fixture ids are `[seed; 16]`, in the batch's `0x70..=0x7F` range, off the
// pinned bytes a fresh vault holds.
const SKILL_PACKAGE_READ_HOLDER: u8 = 0x72;
const SKILL_PACKAGE_READ_GRANTLESS: u8 = 0x73;
const SKILL_PACKAGE_READ_CANDIDATE: u8 = 0x74;

/// An enabled, active agent definition the owner creates as `name`.
fn skill_package_read_definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "skill package read fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}

struct SkillPackageReadFixture {
    vault: Vault,
    owner: EntityId,
    holder: EntityId,
    grantless: EntityId,
    usable_skill: EntityId,
    candidate_skill: EntityId,
    excluded_skill: EntityId,
    _dir: tempfile::TempDir,
}

fn skill_package_read_fixture() -> SkillPackageReadFixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let holder = EntityId::from_bytes([SKILL_PACKAGE_READ_HOLDER; 16]).expect("holder id");
    vault
        .create_agent_definition_as(
            &owner_proof,
            &holder,
            &skill_package_read_definition("arif"),
            TimeRange {
                start: SKILL_PACKAGE_READ_TEST_NOW,
                end: SKILL_PACKAGE_READ_TEST_NOW,
            },
            SKILL_PACKAGE_READ_TEST_NOW,
        )
        .expect("owner creates the holder");
    let grantless = EntityId::from_bytes([SKILL_PACKAGE_READ_GRANTLESS; 16]).expect("grantless id");
    vault
        .create_agent_definition_as(
            &owner_proof,
            &grantless,
            &skill_package_read_definition("mina"),
            TimeRange {
                start: SKILL_PACKAGE_READ_TEST_NOW,
                end: SKILL_PACKAGE_READ_TEST_NOW,
            },
            SKILL_PACKAGE_READ_TEST_NOW,
        )
        .expect("owner creates the grantless agent");
    // Only the grantless agent takes the stock read permit, once: its ordinary
    // read is allowed, but with no Grant naming the verb the package read still
    // refuses. The holder instead uses a record-scoped credential plus its
    // live Grant; it receives no top policy permit.
    vault
        .install_read_permit_for_test(WriteActor::new(grantless, EdgeActorClass::Agent))
        .expect("grantless read permit");
    let usable_files = vec![HubFile::new(
        "SKILL.md",
        b"# Usable skill\n\nFollow the steps.\n".to_vec(),
    )];
    let usable_tree = canonical_skill_tree_hash(
        usable_files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )
    .expect("usable tree hash");
    let usable_record = SkillRecord::new(
        "skill-package-read.usable",
        "Usable skill package for read test",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("skill-package-read-fixture"),
        )]),
    )
    .with_content_hash(usable_tree);
    let usable_skill = land_active_skill_with_files(&vault, &usable_record, usable_files)
        .expect("land the usable skill");
    let candidate_skill =
        EntityId::from_bytes([SKILL_PACKAGE_READ_CANDIDATE; 16]).expect("candidate id");
    let candidate_tree =
        canonical_skill_tree_hash([("SKILL.md", b"# Candidate skill\n".as_slice())])
            .expect("candidate tree hash");
    let candidate_record = SkillRecord::new(
        "skill-package-read.candidate",
        "Candidate skill no reader loads",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("skill-package-read-fixture"),
        )]),
    )
    .with_content_hash(candidate_tree);
    vault
        .put_skill_record(
            &candidate_skill,
            &candidate_record,
            TimeRange {
                start: SKILL_PACKAGE_READ_TEST_NOW,
                end: SKILL_PACKAGE_READ_TEST_NOW,
            },
            SKILL_PACKAGE_READ_TEST_NOW,
        )
        .expect("owner stores the candidate skill");
    let excluded_files = vec![HubFile::new(
        "SKILL.md",
        b"# Excluded skill outside the lane.".to_vec(),
    )];
    let excluded_tree = canonical_skill_tree_hash(
        excluded_files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )
    .expect("excluded tree hash");
    let excluded_record = SkillRecord::new(
        "skill-package-read.excluded",
        "Excluded skill package outside the lane",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("skill-package-read-fixture"),
        )]),
    )
    .with_content_hash(excluded_tree);
    let excluded_skill = land_active_skill_with_files(&vault, &excluded_record, excluded_files)
        .expect("land the excluded skill");
    SkillPackageReadFixture {
        vault,
        owner,
        holder,
        grantless,
        usable_skill,
        candidate_skill,
        excluded_skill,
        _dir: dir,
    }
}

/// The owner grants `agent` the base world with `read` and this verb, rooted
/// and enrolled first as a serving start does. Returns the grant's row.
fn skill_package_read_mint_lane_grant(
    fixture: &SkillPackageReadFixture,
    agent: EntityId,
) -> EntityId {
    let issuer = fixture
        .vault
        .bootstrap_host_slip_issuer()
        .expect("host issuer");
    fixture
        .vault
        .ensure_host_root_slip(&issuer)
        .expect("host root");
    fixture
        .vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("install carries the owner's grant act");
    let owner_proof = fixture
        .vault
        .authenticate_owner(
            fixture.owner,
            &fixture.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let mut authority_scope = Scope::top();
    authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "read".to_owned(),
        SKILL_PACKAGE_READ_TEST_VERB.to_owned(),
    ]));
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("owner mints the skill package grant");
    assert!(minted.grant.confers, "the grant confers");
    minted.grant.grant_ref
}

fn skill_package_read_revoke_grant(fixture: &SkillPackageReadFixture, grant_ref: EntityId) {
    let owner_proof = fixture
        .vault
        .authenticate_owner(
            fixture.owner,
            &fixture.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let revoked = revoke_agent_grant_as(
        &fixture.vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref,
            seen: None,
        },
    )
    .expect("owner revokes the grant");
    assert!(revoked.changed, "the revoke lands");
}

/// A live holder credential narrowed to the two skill rows this lane may read.
/// The separate owner Grant still supplies live verb standing on every call.
fn skill_package_read_proof(fixture: &SkillPackageReadFixture) -> VerifiedSlip {
    skill_package_read_proof_for(fixture, &[fixture.usable_skill, fixture.candidate_skill])
}

/// A live holder credential narrowed to `records`.
fn skill_package_read_proof_for(
    fixture: &SkillPackageReadFixture,
    records: &[EntityId],
) -> VerifiedSlip {
    let issuer = fixture
        .vault
        .bootstrap_host_slip_issuer()
        .expect("host issuer");
    let root = fixture
        .vault
        .ensure_host_root_slip(&issuer)
        .expect("host root");
    let mut claims = root.claims;
    let first = EntityId::now();
    let second = EntityId::now();
    claims.slip_id[..16].copy_from_slice(first.as_bytes());
    claims.slip_id[16..].copy_from_slice(second.as_bytes());
    claims.holder_ref = fixture.holder.to_hex();
    claims.actor_class = Some("agent".to_owned());
    let mut slip = fixture
        .vault
        .mint_capability_slip(&issuer, claims)
        .expect("mint the holder credential");
    issuer
        .attenuate(
            &mut slip,
            SlipCaveat {
                records: Some(records.iter().map(EntityId::to_hex).collect()),
                ..SlipCaveat::default()
            },
        )
        .expect("narrow the credential to its skill records");
    let challenge = b"oneiron-request:skill-package-read";
    let signature = issuer
        .binding_proof(&slip, challenge)
        .expect("holder binding proof");
    fixture
        .vault
        .verify_capability_slip(&issuer.public_key(), &slip, challenge, &signature)
        .expect("verify the record-scoped holder credential")
}

fn skill_package_read_call(memory: &Memory<'_>, entity: &EntityId) -> Result<Value, MemoryError> {
    oneiron::task_verb::sdk::invoke(
        memory,
        SKILL_PACKAGE_READ_TEST_VERB,
        json!({ "entity": entity.to_hex() }),
    )
}

#[test]
fn skill_package_read_agent_with_no_grant_is_refused() {
    let fixture = skill_package_read_fixture();
    let memory = fixture
        .vault
        .memory(fixture.grantless, EdgeActorClass::Agent);
    let error = skill_package_read_call(&memory, &fixture.usable_skill)
        .expect_err("an agent with no grant is refused");
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "a no-grant refusal names FORBIDDEN, not the unknown-verb code; got {}: {}",
        error.code, error.message,
    );
    assert!(
        error.message.contains(SKILL_PACKAGE_READ_TEST_VERB),
        "the refusal names the verb; got {}",
        error.message,
    );
}

#[test]
fn skill_package_read_holder_reads_package_and_not_outside_rows() {
    let fixture = skill_package_read_fixture();
    skill_package_read_mint_lane_grant(&fixture, fixture.holder);
    let proof = skill_package_read_proof(&fixture);
    let memory = fixture
        .vault
        .memory(fixture.holder, EdgeActorClass::Agent)
        .with_read_proof(&proof);
    let out =
        skill_package_read_call(&memory, &fixture.usable_skill).expect("the holder reads its lane");
    let served = out
        .get("value")
        .and_then(Value::as_object)
        .expect("the value is the skill package");
    assert_eq!(
        served.get("entity").and_then(Value::as_str),
        Some(fixture.usable_skill.to_hex()).as_deref(),
        "the served entity is the usable skill; got {served:?}",
    );
    let record = served
        .get("record")
        .and_then(Value::as_object)
        .expect("the package carries its record");
    assert_eq!(
        record.get("skill_id").and_then(Value::as_str),
        Some("skill-package-read.usable"),
        "the record keeps its skill id; got {record:?}",
    );
    assert_eq!(
        record.get("desc").and_then(Value::as_str),
        Some("Usable skill package for read test"),
        "the record keeps its description; got {record:?}",
    );
    assert_eq!(
        record.get("version").and_then(Value::as_str),
        Some("1.0.0"),
        "the record keeps its version; got {record:?}",
    );
    assert_eq!(
        record.get("approval_status").and_then(Value::as_str),
        Some("approved"),
        "the record keeps its approval; got {record:?}",
    );
    assert_eq!(
        record.get("lifecycle_status").and_then(Value::as_str),
        Some("candidate"),
        "the stored package record reads candidate, while native admission is active; got {record:?}",
    );
    assert_eq!(
        record.get("source").and_then(Value::as_str),
        Some("user_stated"),
        "the record keeps its source; got {record:?}",
    );
    assert!(
        record
            .get("confidence")
            .and_then(Value::as_f64)
            .is_some_and(|confidence| (confidence - 1.0).abs() < f64::EPSILON),
        "the record keeps its confidence; got {record:?}",
    );
    assert_eq!(
        record.get("generated").and_then(Value::as_bool),
        Some(false),
        "the record keeps its generated flag; got {record:?}",
    );
    assert_eq!(
        record.get("human_authored").and_then(Value::as_bool),
        Some(true),
        "the record keeps its authorship; got {record:?}",
    );
    assert!(
        record
            .get("dependencies")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty),
        "the record keeps its empty dependencies; got {record:?}",
    );
    assert_eq!(
        record.get("provenance"),
        Some(&json!({ "source": "skill-package-read-fixture" })),
        "the record keeps its provenance; got {record:?}",
    );
    let content_hash = record
        .get("content_hash")
        .and_then(Value::as_str)
        .expect("the record keeps its content hash");
    assert_eq!(content_hash.len(), 64, "a 64-hex tree hash; got {record:?}");
    assert!(
        content_hash.chars().all(|c| c.is_ascii_hexdigit()),
        "lowercase hex tree hash; got {record:?}",
    );
    assert!(
        record.get("forked_from").is_some_and(Value::is_null),
        "no fork parent; got {record:?}",
    );
    assert!(
        record.get("governance_tier").is_some_and(Value::is_null),
        "no governance mark; got {record:?}",
    );
    assert_eq!(
        record.get("role").and_then(Value::as_str),
        Some("knowledge"),
        "the record keeps its role; got {record:?}",
    );
    assert!(
        record.get("call").is_some_and(Value::is_null),
        "a knowledge skill carries no call contract; got {record:?}",
    );
    let files = served
        .get("files")
        .and_then(Value::as_array)
        .expect("the package carries its files");
    assert_eq!(files.len(), 1, "one stored file; got {served:?}");
    assert_eq!(
        files[0].get("path").and_then(Value::as_str),
        Some("SKILL.md"),
        "the stored path; got {served:?}",
    );
    let stored: Vec<u8> = files[0]
        .get("content")
        .and_then(Value::as_array)
        .expect("file bytes")
        .iter()
        .map(|byte| byte.as_u64().expect("a byte") as u8)
        .collect();
    assert_eq!(
        stored, b"# Usable skill\n\nFollow the steps.\n",
        "the stored bytes; got {served:?}",
    );
    let capabilities = served
        .get("capabilities")
        .and_then(Value::as_object)
        .expect("the package carries its capabilities");
    for axis in ["bins", "env", "mcp", "allowed_tools"] {
        assert!(
            capabilities
                .get(axis)
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty),
            "the default capabilities carry no {axis}; got {served:?}",
        );
    }
    assert_eq!(
        served.get("format").and_then(Value::as_str),
        Some("folder"),
        "the stored folder format; got {served:?}",
    );
    assert!(
        out.get("narrowing").and_then(Value::as_object).is_some(),
        "the read keeps its narrowing receipt; got {out}",
    );
    let candidate =
        skill_package_read_call(&memory, &fixture.candidate_skill).expect("the candidate answers");
    assert!(
        candidate.get("value").is_some_and(Value::is_null),
        "the unloadable skill answers none; got {candidate}",
    );
    assert!(
        candidate
            .get("narrowing")
            .and_then(Value::as_object)
            .is_some(),
        "the unloadable read keeps its narrowing receipt; got {candidate}",
    );
    let excluded = skill_package_read_call(&memory, &fixture.excluded_skill)
        .expect("the excluded skill answers");
    assert!(
        excluded.get("value").is_some_and(Value::is_null),
        "the skill outside the credential record list is withheld as none; got {excluded}",
    );
    assert!(
        excluded
            .get("narrowing")
            .and_then(Value::as_object)
            .is_some(),
        "the withheld read keeps its narrowing receipt; got {excluded}",
    );
}

#[test]
fn skill_package_read_revoked_grant_is_refused_again() {
    let fixture = skill_package_read_fixture();
    let grant_ref = skill_package_read_mint_lane_grant(&fixture, fixture.holder);
    let proof = skill_package_read_proof(&fixture);
    let memory = fixture
        .vault
        .memory(fixture.holder, EdgeActorClass::Agent)
        .with_read_proof(&proof);
    let before = skill_package_read_call(&memory, &fixture.usable_skill)
        .expect("the holder reads before the revoke");
    assert!(
        before.get("value").and_then(Value::as_object).is_some(),
        "the pre-revoke read holds the row; got {before}",
    );
    skill_package_read_revoke_grant(&fixture, grant_ref);
    let error = skill_package_read_call(&memory, &fixture.usable_skill)
        .expect_err("the revoked grant is refused");
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "a revoked-grant refusal names FORBIDDEN; got {}: {}",
        error.code, error.message,
    );
}

/// A GitHub token shape the release scan reads, joined at run time so no token
/// literal sits in the source.
fn skill_package_read_key() -> Vec<u8> {
    ["gh", "p_", "0123456789abcdefghijklmnopqrstuvwxyz"]
        .concat()
        .into_bytes()
}

/// Lands an approved, active skill named `skill_id` whose `config.json` holds
/// `config`, through the package store's door.
fn skill_package_read_land_configured_skill(
    vault: &Vault,
    skill_id: &str,
    config: Vec<u8>,
) -> EntityId {
    let files = vec![
        HubFile::new(
            "SKILL.md",
            b"# Configured skill\n\nRead the config.\n".to_vec(),
        ),
        HubFile::new("config.json", config),
    ];
    let tree = canonical_skill_tree_hash(
        files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )
    .expect("configured tree hash");
    let record = SkillRecord::new(
        skill_id,
        "Skill package with a config file",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("skill-package-read-fixture"),
        )]),
    )
    .with_content_hash(tree);
    land_active_skill_with_files(vault, &record, files).expect("land the configured skill")
}

/// Whether `haystack` holds `needle`.
fn skill_package_read_holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// A caller that sees stored keys masked is served no package whose files hold
/// one (#7149 review round 1): the skill whose `config.json` holds a token
/// answers none, as `vault.skills.get` withholds it, and no answer carries the
/// token. Its clean twin, landed the same way with the same credential, is
/// served with its `config.json`, so the none is the withhold, not the lane.
#[test]
fn skill_package_read_holder_is_not_served_a_package_that_holds_a_key() {
    let fixture = skill_package_read_fixture();
    let key = skill_package_read_key();
    let mut keyed_config = b"{\"token\": \"".to_vec();
    keyed_config.extend_from_slice(&key);
    keyed_config.extend_from_slice(b"\"}\n");
    let keyed_skill = skill_package_read_land_configured_skill(
        &fixture.vault,
        "skill-package-read.keyed",
        keyed_config,
    );
    let clean_skill = skill_package_read_land_configured_skill(
        &fixture.vault,
        "skill-package-read.clean",
        b"{\"retries\": 3}\n".to_vec(),
    );
    skill_package_read_mint_lane_grant(&fixture, fixture.holder);
    let proof = skill_package_read_proof_for(&fixture, &[clean_skill, keyed_skill]);
    let memory = fixture
        .vault
        .memory(fixture.holder, EdgeActorClass::Agent)
        .with_read_proof(&proof);
    let clean = skill_package_read_call(&memory, &clean_skill).expect("the clean skill answers");
    let clean_files = clean
        .get("value")
        .and_then(|value| value.get("files"))
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("the clean twin is served with its files; got {clean}"));
    assert!(
        clean_files
            .iter()
            .any(|file| file.get("path").and_then(Value::as_str) == Some("config.json")),
        "the clean twin is served with its config file; got {clean}",
    );
    let keyed = skill_package_read_call(&memory, &keyed_skill).expect("the keyed skill answers");
    assert!(
        keyed.get("value").is_some_and(Value::is_null),
        "a package whose files hold a token answers none; got {keyed}",
    );
    assert!(
        !skill_package_read_holds(keyed.to_string().as_bytes(), &key),
        "no answer carries the token",
    );
}
