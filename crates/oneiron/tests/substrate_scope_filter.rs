//! A grant narrowed to some projects reads its own scope on the substrate
//! reads whose rows record a project, instead of FORBIDDEN (DEC-0005 #scope:
//! "A request is a narrowing position, and an empty request narrows
//! nothing, so the answer is the ceiling"; FIX
//! [SUBSTRATE-READS-NO-SCOPE-FILTER]; row UNBUILT-08). This file holds the
//! learning dials (`vault.settings.learning`) and the learning cell
//! (`vault.learning.read`).
//!
//! Red at main: a holder whose grant names one project is refused both
//! reads outright. Guards (they hold there too): it reads no row of another
//! project or of the whole vault, no catalog line, which carries the
//! vault-wide value, and no cell reading that rests on what lies outside its
//! project.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test substrate_scope_filter`.
#![cfg(oneiron_test_support)]

use oneiron::learning::{
    Anchor, EstimateValue, LearningCell, LearningEvidence, LearningPredicate, Observation, Prior,
    PriorOrigin,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::{ENGINE_CONTROLS_VERBS, define_agent};
use oneiron::test_doors::steward::STEWARD_READ_VERB;
use oneiron::test_doors::substrate_reads::stand_project_steward_grant;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

const KEY: &str = "eval_floor_min_families";
const WINDOW_KEY: &str = "learning_window_half_life_days";
const CONSENT_SCOPE: &str = "substrate-scope-filter";
const NOW: u64 = 10;

/// A vault this process owns, so its embedded owner writes under its proof.
fn owned_vault(dir: &tempfile::TempDir) -> (Vault, EntityId) {
    let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("an owned vault");
    oneiron::test_support::provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    (vault, owner)
}

fn read(vault: &Vault, actor: EntityId, verb: &str, input: Value) -> MemoryResult<Value> {
    invoke(&vault.memory(actor, EdgeActorClass::Agent), verb, input)
}

/// The owner pins `key` at `value` for `project`, or for the whole vault.
fn pin(vault: &Vault, owner: EntityId, key: &str, project: Option<EntityId>, value: f64) {
    let mut row = json!({
        "key": key,
        "mode": "pin",
        "value": value,
        "why": "substrate scope filter test",
    });
    if let Some(project) = project {
        row["project"] = json!(project.to_hex());
    }
    invoke(
        &vault.memory(owner, EdgeActorClass::Human),
        "vault.settings.learning.put",
        row,
    )
    .expect("the owner pins the key");
}

/// `agent`'s edit-cost cell at `executor` in `project`, or the vault's.
fn edit_cost_cell(agent: EntityId, executor: &str, project: Option<EntityId>) -> LearningCell {
    LearningCell::new(LearningPredicate::EditCost, agent)
        .executor(executor)
        .consent_scope(CONSENT_SCOPE)
        .project(project)
}

/// `vault.learning.read` of [`edit_cost_cell`], as a reader names it.
fn read_edit_cost_cell(
    vault: &Vault,
    agent: EntityId,
    executor: &str,
    project: Option<EntityId>,
) -> MemoryResult<Value> {
    let mut input = json!({
        "cell": {
            "subject": agent.to_hex(),
            "predicate": "learning.edit_cost",
            "executor": executor,
            "consent_scope": CONSENT_SCOPE,
        },
    });
    if let Some(project) = project {
        input["project_ref"] = json!(project.to_hex());
    }
    read(vault, agent, "vault.learning.read", input)
}

fn assert_forbidden(answer: MemoryResult<Value>, what: &str) {
    match answer {
        Err(error) => assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{what}: {error:?}"),
        Ok(value) => panic!("{what}: expected FORBIDDEN; seen answer={value}"),
    }
}

/// A holder of `engine.controls` narrowed to one project reads that
/// project's dial rows: not another project's, not the vault's, and no
/// catalog line.
#[test]
fn project_scoped_holder_reads_own_project_learning_dials() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner) = owned_vault(&dir);
    let agent = define_agent(&vault).expect("an agent");
    let (own_project, other_project) = (EntityId::now(), EntityId::now());
    pin(&vault, owner, KEY, Some(own_project), 3.0);
    pin(&vault, owner, KEY, Some(other_project), 5.0);
    pin(&vault, owner, KEY, None, 7.0);
    stand_project_steward_grant(&vault, agent, &ENGINE_CONTROLS_VERBS, own_project)
        .expect("an engine.controls grant narrowed to one project");

    let answer = read(&vault, agent, "vault.settings.learning", json!({}));
    let view = answer.unwrap_or_else(|error| {
        panic!(
            "actor=agent {agent:?}, grant=project {own_project:?}; expected its own project's dial rows, not a refusal; seen {error:?}"
        )
    });
    let rows: Vec<(Option<&str>, Option<f64>)> = view["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|row| (row["project"].as_str(), row["value"].as_f64()))
        .collect();
    let own = own_project.to_hex();
    assert_eq!(
        rows,
        vec![(Some(own.as_str()), Some(3.0))],
        "actor=agent {agent:?}, grant=project {own_project:?}; expected only its own project's row, none of project {other_project:?} or the vault's; seen rows={rows:?}"
    );
    let catalog = view["catalog"].as_array().map_or(0, Vec::len);
    assert_eq!(
        catalog, 0,
        "actor=agent {agent:?}; expected no catalog line, each carries the vault-wide value; seen view={view}"
    );
}

/// A Steward `read` holder narrowed to one project reads that project's
/// learning cell, and is refused another project's cell and the vault's.
#[test]
fn project_scoped_reader_reads_own_project_learning_cell() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, _owner) = owned_vault(&dir);
    let agent = define_agent(&vault).expect("an agent");
    let (own_project, other_project) = (EntityId::now(), EntityId::now());
    stand_project_steward_grant(&vault, agent, &[STEWARD_READ_VERB], own_project)
        .expect("a read grant narrowed to one project");
    let cell = |project| read_edit_cost_cell(&vault, agent, "fresh", project);

    let own = cell(Some(own_project)).unwrap_or_else(|error| {
        panic!(
            "actor=agent {agent:?}, grant=project {own_project:?}; expected its own project's cell, not a refusal; seen {error:?}"
        )
    });
    let reading = (
        own["view"]["own"].as_bool(),
        own["view"]["estimate"]["prior"]["origin"].as_str(),
    );
    assert_eq!(
        reading,
        (Some(false), Some("shipped")),
        "actor=agent {agent:?}; expected the empty cell over the shipped prior; seen view={own}"
    );
    assert_forbidden(cell(Some(other_project)), "another project's cell");
    assert_forbidden(cell(None), "the vault's cell");
}

/// A narrowed reader is refused its own project's cell when the reading
/// rests on what lies outside the project: a prior the cell took from
/// elsewhere (here a stored parent prior, as a project cell keeps the
/// vault's cell's reading it borrowed before its first own run), however
/// many own runs it holds since, or a window a vault row set. Red at main
/// (the fresh cell is refused there too) and at this PR's first head
/// 308e715348a1 (it admitted any cell with own runs, and any window).
#[test]
fn project_scoped_reader_reads_no_cell_resting_outside_its_project() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner) = owned_vault(&dir);
    let agent = define_agent(&vault).expect("an agent");
    let own_project = EntityId::now();
    stand_project_steward_grant(&vault, agent, &[STEWARD_READ_VERB], own_project)
        .expect("a read grant narrowed to one project");

    let kept = edit_cost_cell(agent, "kept", Some(own_project));
    let prior = Prior {
        origin: PriorOrigin::Parent,
        value: EstimateValue::Mean {
            mean: 0.9,
            spread: 0.1,
        },
        weight_runs: 3.0,
        from: Some("the vault's cell".to_owned()),
    };
    oneiron::learning::put_cell_prior(&vault, &kept, &prior, NOW).expect("a parent prior");
    let run = LearningEvidence::anchored(
        EntityId::now().to_hex(),
        NOW,
        Anchor::OwnerVerdict,
        Observation::Magnitude(0.5),
    );
    oneiron::learning::record_evidence(&vault, &kept, &run, NOW)
        .expect("an own run")
        .expect("the cell holds its own run");
    assert_forbidden(
        read_edit_cost_cell(&vault, agent, "kept", Some(own_project)),
        "own runs over a prior from outside the project",
    );

    let fresh = || read_edit_cost_cell(&vault, agent, "fresh", Some(own_project));
    fresh().unwrap_or_else(|error| {
        panic!(
            "actor=agent {agent:?}, grant=project {own_project:?}; expected a fresh cell of its project over the shipped prior; seen {error:?}"
        )
    });
    pin(&vault, owner, WINDOW_KEY, None, 30.0);
    assert_forbidden(fresh(), "a reading under the window the vault's row set");
}
