//! `vault.research.bind_authoring` through the generated verb dispatch
//! (`oneiron::task_verb::sdk::invoke`), as a client calls it: JSON in, JSON out, on the
//! caller's own `Memory`. The owner binds the fixed OF-366 claim-authoring campaign to a
//! `vault.research.create_root` root: the engine builds the config from the three splits
//! and the budget line, so the claim-authoring row `vault.research.evaluate_split` reads
//! holds exactly `CampaignConfig::of366` of them, and the general binding carries its
//! ruler. A root binds once, by either bind, and a refused authoring bind writes nothing.
//! The strategy pin must name the active, admitted Workflow revision; splits the OF-366
//! config refuses are BAD_REQUEST. An agent binds only with a live owner Grant listing the
//! verb AND from the root's own leased try; without either, or with a revoked Grant, it is
//! FORBIDDEN. On main the verb does not exist, so every case here fails.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test verb_vault_research_bind_authoring`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::attempt_queue::{AttemptId, AttemptQueue, ClaimAttempt, ClaimOutcome};
use oneiron::authority::{ActSurface, MachineRole};
use oneiron::autoreason_campaign::authoring::authoring_campaign;
use oneiron::autoreason_campaign::research::research_binding;
use oneiron::autoreason_campaign::{CampaignBudgetLine, CampaignConfig, CampaignDatasetRef};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, Memory, MemoryError};
use oneiron::skill::{SkillLifecycle, SkillRecord, SkillRole, canonical_skill_tree_hash};
use oneiron::skill_hub::HubFile;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::HostBinding;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::test_doors::skill_package::land_active_skill_with_files;
use oneiron::verbs::{
    AgentGrantMintRequest, AgentGrantRevokeRequest, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const VERB: &str = "vault.research.bind_authoring";
const CREATE_ROOT_VERB: &str = "vault.research.create_root";
const BIND_VERB: &str = "vault.research.bind";
const BRIEF: &str = "Author claims under the pinned claim-authoring strategy.";
const BUDGET_ID: &str = "claim-authoring-lease";
const RESERVE_PER_STEP: u64 = 2;

/// The vault clock's fixed time for every test here: no wall time, no sleeps.
const T0: u64 = 1_780_000_000;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

/// A rooted vault with its install enrolled, its embedded owner and proof. The owner's
/// Grant acts on `ThisInstall` need the full five-step install first.
fn rooted_vault() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("open vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("serving install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    Fixture {
        vault,
        _dir: dir,
        owner,
        owner_proof,
    }
}

fn owner_memory(fixture: &Fixture) -> Memory<'_> {
    fixture.vault.memory(fixture.owner, EdgeActorClass::Human)
}

/// A dispatchable agent definition the root runs: approved, active, enabled.
fn root_agent(fixture: &Fixture) -> EntityId {
    define_agent(&fixture.vault, "authoring-root-target").expect("define the root's agent")
}

/// A root the owner created through `vault.research.create_root`: its hex id and its
/// attempt id.
fn created_root(fixture: &Fixture, agent: EntityId, intent_key: &str) -> (String, AttemptId) {
    let receipt = invoke(
        &owner_memory(fixture),
        CREATE_ROOT_VERB,
        json!({ "agent": agent.to_hex(), "intent_key": intent_key, "briefing": BRIEF }),
    )
    .expect("the owner creates a root");
    let root_hex = receipt["root"]
        .as_str()
        .expect("the receipt names its root")
        .to_owned();
    let root = AttemptId::from_bytes(
        EntityId::from_hex(&root_hex)
            .expect("the root is an id")
            .as_bytes(),
    )
    .expect("the root is an attempt id");
    (root_hex, root)
}

/// The created root, leased by the host: a `Memory` of the root's own agent on that try.
fn leased_root_memory<'a>(fixture: &'a Fixture, agent: EntityId, root: AttemptId) -> Memory<'a> {
    let ClaimOutcome::Claimed(leased) = AttemptQueue::new(&fixture.vault)
        .claim(ClaimAttempt {
            lease_owner: "authoring-root-host".into(),
            now: fixture.vault.now_recorded_at(),
        })
        .expect("claim")
    else {
        panic!("the created root was not leased");
    };
    assert_eq!(leased.id, root, "the created root is the leased attempt");
    let binding = HostBinding::from_leased(&leased, None).expect("host binding");
    fixture
        .vault
        .memory(agent, EdgeActorClass::Agent)
        .with_task_host(binding)
}

/// A strategy skill record of `role` whose content hash names its one SKILL.md file.
fn strategy_record(name: &str, role: SkillRole) -> (SkillRecord, Vec<HubFile>) {
    let files = vec![HubFile::new(
        "SKILL.md",
        b"# claim-authoring strategy\nPick the authoring arm for one claim.\n".to_vec(),
    )];
    let tree = canonical_skill_tree_hash(
        files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )
    .expect("tree hash");
    let record = SkillRecord::new(
        name,
        "The claim-authoring strategy the campaign pins",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        0.9,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("bind-authoring-fixture"),
        )]),
    )
    .with_role(role, None)
    .with_content_hash(tree);
    (record, files)
}

/// An active, approved strategy skill `name` of `role`: its pin as the verb takes it.
fn active_strategy(fixture: &Fixture, name: &str, role: SkillRole) -> Value {
    let (record, files) = strategy_record(name, role);
    let skill = land_active_skill_with_files(&fixture.vault, &record, files)
        .expect("land the active strategy skill");
    json!({
        "skill": skill.to_hex(),
        "version": record.version,
        "content_hash": record.content_hash.expect("pinned content").to_hex(),
    })
}

/// A Workflow strategy skill left a Candidate, with no stored package: never
/// activated. Its lifecycle refuses it before any content check.
fn candidate_strategy(fixture: &Fixture) -> Value {
    let (mut record, _) = strategy_record("claim-authoring-candidate", SkillRole::Workflow);
    record.content_hash = None;
    let skill = fixture.vault.new_entity_id().expect("skill id");
    fixture
        .vault
        .put_skill_record(&skill, &record, TimeRange { start: 10, end: 10 }, 11)
        .expect("land the candidate strategy skill");
    json!({
        "skill": skill.to_hex(),
        "version": record.version,
        "content_hash": "00".repeat(32),
    })
}

fn dataset(id: &str) -> CampaignDatasetRef {
    CampaignDatasetRef {
        dataset_id: id.to_owned(),
        revision: "r1".to_owned(),
    }
}

/// The config the engine must build from the splits and budget line the specs name.
fn expected_config() -> CampaignConfig {
    CampaignConfig::of366(
        dataset("authoring-search"),
        dataset("authoring-held-out"),
        dataset("authoring-sealed"),
        CampaignBudgetLine {
            budget_id: BUDGET_ID.to_owned(),
            reserve_units_per_step: RESERVE_PER_STEP,
        },
    )
    .expect("the pinned OF-366 config")
}

fn incumbent() -> Value {
    let bytes: &[u8] = br#"{"arm":"single_pass"}"#;
    let digest: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    json!({ "config_ref": "claim-authoring:single-pass", "config_sha256": digest })
}

fn authoring_spec(root_hex: &str, skill: &Value) -> Value {
    json!({
        "root": root_hex,
        "splits": {
            "search": { "dataset_id": "authoring-search", "revision": "r1" },
            "held_out": { "dataset_id": "authoring-held-out", "revision": "r1" },
            "sealed": { "dataset_id": "authoring-sealed", "revision": "r1" },
        },
        "budget": { "budget_id": BUDGET_ID, "reserve_units_per_step": RESERVE_PER_STEP },
        "skill": skill,
        "incumbent": incumbent(),
        "holder": null,
        "share": null,
    })
}

/// A general config campaign over `root`, for the generic `vault.research.bind`.
fn generic_bind_spec(root_hex: &str) -> Value {
    json!({
        "root": root_hex,
        "config": {
            "campaign_id": "bind-authoring-generic",
            "search_axes": [{ "name": "parameter", "values": ["baseline", "alternative"] }],
            "metric_set": {
                "set_id": "fixture-quality",
                "revision": "r1",
                "axes": [{ "name": "quality", "direction": "higher", "role": "primary" }],
            },
            "splits": {
                "search": { "dataset_id": "fixture-search", "revision": "r1" },
                "held_out": { "dataset_id": "fixture-held-out", "revision": "r1" },
                "sealed": { "dataset_id": "fixture-sealed", "revision": "r1" },
            },
            "budget": { "budget_id": "fixture-lease", "max_units": 100, "exploration_units": 10 },
            "decide": { "kind": "dominance" },
        },
        "target": { "config": { "subject": "bind-authoring-generic" } },
        "holder": null,
        "confirmation": null,
        "share": null,
        "incumbent": incumbent(),
        "prior_ladder": [],
        "execution": null,
    })
}

/// The owner's live Grant naming `read` and this verb for `agent`; the grant's row.
fn grant_bind_authoring(fixture: &Fixture, agent: EntityId) -> EntityId {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), VERB.to_owned()]));
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope: scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("owner mints the bind_authoring Grant");
    assert!(minted.grant.confers, "the bind_authoring Grant confers");
    minted.grant.grant_ref
}

fn revoke_grant(fixture: &Fixture, grant_ref: EntityId) {
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

fn assert_forbidden(error: &MemoryError, what: &str) {
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "{what}: FORBIDDEN, not the unknown-verb code; got {}: {}",
        error.code, error.message,
    );
}

fn assert_refused_with(error: &MemoryError, needle: &str, what: &str) {
    assert!(
        error.message.contains(needle),
        "{what}: refused with \"{needle}\"; got {}: {}",
        error.code,
        error.message,
    );
}

/// Nothing of either bind landed at `root`.
fn assert_unbound(fixture: &Fixture, root: AttemptId, what: &str) {
    assert!(
        research_binding(&fixture.vault, root)
            .expect("read the binding")
            .is_none(),
        "{what}: no general binding landed",
    );
    assert!(
        authoring_campaign(&fixture.vault, root)
            .expect("read the authoring row")
            .is_none(),
        "{what}: no claim-authoring row landed",
    );
}

#[test]
fn owner_binds_the_fixed_authoring_campaign_once() {
    let fixture = rooted_vault();
    let target = root_agent(&fixture);
    let (root_hex, root) = created_root(&fixture, target, "owner-authoring-intent");
    let skill = active_strategy(&fixture, "claim-authoring-strategy", SkillRole::Workflow);
    let owner = owner_memory(&fixture);

    let receipt = invoke(&owner, VERB, authoring_spec(&root_hex, &skill))
        .expect("the owner binds the claim-authoring campaign");
    assert_eq!(
        receipt["skill"], skill,
        "the receipt names the pinned skill"
    );
    assert!(
        receipt["strategy"]["config_sha256"]
            .as_str()
            .is_some_and(|digest| !digest.is_empty()),
        "the receipt names the pinned strategy: {receipt}",
    );

    let config = expected_config();
    let campaign = authoring_campaign(&fixture.vault, root)
        .expect("read the authoring row")
        .expect("the claim-authoring row evaluate_split reads landed");
    assert_eq!(
        campaign.config, config,
        "the engine built the pinned OF-366 config from the splits and budget line",
    );
    assert_eq!(
        Some(campaign.skill.content_hash.as_str()),
        skill["content_hash"].as_str(),
        "the row pins the skill's content",
    );
    let binding = research_binding(&fixture.vault, root)
        .expect("read the binding")
        .expect("the general binding landed with it");
    assert_eq!(
        binding.config,
        config.as_general().expect("general projection"),
        "the general binding carries the OF-366 ruler",
    );
    assert_eq!(
        receipt["binding"]["run_id"].as_str(),
        Some(binding.run_id.as_str())
    );

    let again = invoke(&owner, VERB, authoring_spec(&root_hex, &skill))
        .expect_err("a second claim-authoring bind is refused");
    assert_refused_with(&again, "binds once", "the second authoring bind");
    let generic = invoke(&owner, BIND_VERB, generic_bind_spec(&root_hex))
        .expect_err("the generic bind cannot rebind an authoring root");
    assert_refused_with(&generic, "binds once", "the generic bind after it");
    assert_eq!(
        authoring_campaign(&fixture.vault, root)
            .expect("read the authoring row")
            .expect("still bound")
            .bound_at,
        campaign.bound_at,
        "the first bind stands",
    );
}

#[test]
fn generic_bound_root_refuses_the_authoring_bind_and_writes_no_authoring_row() {
    let fixture = rooted_vault();
    let target = root_agent(&fixture);
    let (root_hex, root) = created_root(&fixture, target, "generic-first-intent");
    let skill = active_strategy(&fixture, "claim-authoring-strategy", SkillRole::Workflow);
    let owner = owner_memory(&fixture);
    invoke(&owner, BIND_VERB, generic_bind_spec(&root_hex)).expect("the generic bind lands");

    let error = invoke(&owner, VERB, authoring_spec(&root_hex, &skill))
        .expect_err("a generic-bound root does not take the authoring bind");
    assert_refused_with(
        &error,
        "binds once",
        "the authoring bind after a generic one",
    );
    assert!(
        authoring_campaign(&fixture.vault, root)
            .expect("read the authoring row")
            .is_none(),
        "the refused bind wrote no claim-authoring row",
    );
}

#[test]
fn strategy_pin_must_name_the_active_admitted_workflow_revision() {
    let fixture = rooted_vault();
    let target = root_agent(&fixture);
    let (root_hex, root) = created_root(&fixture, target, "strategy-pin-intent");
    let owner = owner_memory(&fixture);

    let knowledge = active_strategy(&fixture, "claim-authoring-knowledge", SkillRole::Knowledge);
    let error = invoke(&owner, VERB, authoring_spec(&root_hex, &knowledge))
        .expect_err("a Knowledge skill is no strategy");
    assert_refused_with(&error, "is a Workflow skill", "a Knowledge strategy");
    assert_unbound(&fixture, root, "a Knowledge strategy");

    let candidate = candidate_strategy(&fixture);
    let error = invoke(&owner, VERB, authoring_spec(&root_hex, &candidate))
        .expect_err("a Candidate strategy is not admitted and active");
    assert_refused_with(&error, "not admitted and active", "a Candidate strategy");
    assert_unbound(&fixture, root, "a Candidate strategy");

    let workflow = active_strategy(&fixture, "claim-authoring-strategy", SkillRole::Workflow);
    let mut moved = workflow.clone();
    moved["content_hash"] = json!("00".repeat(32));
    let error = invoke(&owner, VERB, authoring_spec(&root_hex, &moved))
        .expect_err("a pin of other content is refused");
    assert_refused_with(&error, "moved since it was pinned", "another content hash");
    let mut moved = workflow.clone();
    moved["version"] = json!("2.0.0");
    let error = invoke(&owner, VERB, authoring_spec(&root_hex, &moved))
        .expect_err("a pin of another version is refused");
    assert_refused_with(&error, "moved since it was pinned", "another version");
    assert_unbound(&fixture, root, "a moved pin");

    invoke(&owner, VERB, authoring_spec(&root_hex, &workflow))
        .expect("the exact active Workflow revision binds");
}

#[test]
fn splits_the_of366_config_refuses_are_bad_request() {
    let fixture = rooted_vault();
    let target = root_agent(&fixture);
    let (root_hex, root) = created_root(&fixture, target, "bad-splits-intent");
    let skill = active_strategy(&fixture, "claim-authoring-strategy", SkillRole::Workflow);
    let mut spec = authoring_spec(&root_hex, &skill);
    spec["splits"]["held_out"] = spec["splits"]["search"].clone();
    let error = invoke(&owner_memory(&fixture), VERB, spec)
        .expect_err("a held-out split equal to the search split is refused");
    assert_eq!(
        error.code, MEMORY_CODE_BAD_REQUEST,
        "BAD_REQUEST; got {}: {}",
        error.code, error.message,
    );
    let mut spec = authoring_spec(&root_hex, &skill);
    spec["budget"]["reserve_units_per_step"] = json!(0);
    let error = invoke(&owner_memory(&fixture), VERB, spec)
        .expect_err("a zero per-step reserve is refused");
    assert_eq!(
        error.code, MEMORY_CODE_BAD_REQUEST,
        "BAD_REQUEST; got {}: {}",
        error.code, error.message,
    );
    assert_unbound(&fixture, root, "refused splits and budget");
    // An unknown verb is BAD_REQUEST too: the valid bind after the refusals is
    // what fails where the verb does not exist.
    invoke(
        &owner_memory(&fixture),
        VERB,
        authoring_spec(&root_hex, &skill),
    )
    .expect("the same root binds with valid splits and budget");
}

#[test]
fn granted_agent_outside_the_root_try_is_refused() {
    let fixture = rooted_vault();
    let target = root_agent(&fixture);
    let (root_hex, root) = created_root(&fixture, target, "outside-try-intent");
    let skill = active_strategy(&fixture, "claim-authoring-strategy", SkillRole::Workflow);
    grant_bind_authoring(&fixture, target);
    let bare = fixture.vault.memory(target, EdgeActorClass::Agent);
    let error = invoke(&bare, VERB, authoring_spec(&root_hex, &skill))
        .expect_err("a Grant alone does not make the agent the root's controller");
    assert_forbidden(&error, "a granted agent outside the root's leased try");
    assert_unbound(&fixture, root, "a granted agent outside the try");
}

#[test]
fn root_agent_without_a_grant_is_refused() {
    let fixture = rooted_vault();
    let target = root_agent(&fixture);
    let (root_hex, root) = created_root(&fixture, target, "no-grant-intent");
    let skill = active_strategy(&fixture, "claim-authoring-strategy", SkillRole::Workflow);
    let hosted = leased_root_memory(&fixture, target, root);
    let error = invoke(&hosted, VERB, authoring_spec(&root_hex, &skill))
        .expect_err("the root's own agent needs a Grant listing the verb");
    assert_forbidden(&error, "the root's agent with no Grant");
    assert_unbound(&fixture, root, "the root's agent with no Grant");
}

#[test]
fn granted_root_agent_binds_from_its_leased_try() {
    let fixture = rooted_vault();
    let target = root_agent(&fixture);
    let (root_hex, root) = created_root(&fixture, target, "granted-root-intent");
    let skill = active_strategy(&fixture, "claim-authoring-strategy", SkillRole::Workflow);
    grant_bind_authoring(&fixture, target);
    let hosted = leased_root_memory(&fixture, target, root);
    invoke(&hosted, VERB, authoring_spec(&root_hex, &skill))
        .expect("the root's granted agent binds from its leased try");
    assert!(
        authoring_campaign(&fixture.vault, root)
            .expect("read the authoring row")
            .is_some(),
        "the claim-authoring row landed",
    );
}

#[test]
fn revoked_grant_is_refused() {
    let fixture = rooted_vault();
    let target = root_agent(&fixture);
    let (root_hex, root) = created_root(&fixture, target, "revoked-intent");
    let skill = active_strategy(&fixture, "claim-authoring-strategy", SkillRole::Workflow);
    let grant = grant_bind_authoring(&fixture, target);
    revoke_grant(&fixture, grant);
    let hosted = leased_root_memory(&fixture, target, root);
    let error = invoke(&hosted, VERB, authoring_spec(&root_hex, &skill))
        .expect_err("a revoked Grant admits nothing");
    assert_forbidden(&error, "the root's agent with a revoked Grant");
    assert_unbound(&fixture, root, "a revoked Grant");
}
