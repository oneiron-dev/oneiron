//! A grant narrowed to some projects reads its own scope on the substrate
//! reads whose rows record a project, instead of FORBIDDEN (DEC-0005 #scope:
//! "A request is a narrowing position, and an empty request narrows
//! nothing, so the answer is the ceiling"; FIX
//! [SUBSTRATE-READS-NO-SCOPE-FILTER]; row UNBUILT-08). This file holds the
//! learning dials (`vault.settings.learning`) and the learning cell
//! (`vault.learning.read`), whose rows record their project (PR A), and the
//! agent health cards (`vault.agent_health.cards`) and failure evidence
//! (`vault.diagnostics.evidence`), whose rows lie where the attempts they
//! name ran (PR B).
//!
//! Red at the base: a holder whose grant names one project is refused each
//! read outright. Guards (they hold there too): it reads no row of another
//! project or of the whole vault, no catalog line, which carries the
//! vault-wide value, no cell reading that rests on what lies outside its
//! project, and no card that merged a finding naming no attempt.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test substrate_scope_filter`.
#![cfg(oneiron_test_support)]

use oneiron::attempt_queue::AttemptId;
use oneiron::learning::{
    Anchor, EstimateValue, LearningCell, LearningEvidence, LearningPredicate, Observation, Prior,
    PriorOrigin,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::{ENGINE_CONTROLS_VERBS, define_agent};
use oneiron::test_doors::steward::STEWARD_READ_VERB;
use oneiron::test_doors::substrate_reads::{
    dispatch_into_child_projects, land_agent_health_finding, stand_project_steward_grant,
};
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

/// A vault no owner has rooted, so the child projects the test door makes
/// are born unsigned, as a fresh vault's are.
fn unrooted_vault(dir: &tempfile::TempDir) -> Vault {
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("a vault");
    oneiron::test_support::provision_engine_machines(&vault);
    vault
}

/// An attempt id as the entity id hex a `run_ref` carries.
fn hex(attempt: AttemptId) -> String {
    EntityId::from_bytes(*attempt.as_bytes())
        .expect("an attempt id is an entity id")
        .to_hex()
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

/// A Steward `read` holder narrowed to one project reads the agent health
/// cards whose every finding names a run in that project: not a card of a
/// run in another project or in the vault's root project, not a card whose
/// finding names no run, and not a card that merged a finding of its own
/// project with one that names no run.
#[test]
fn project_scoped_steward_reads_own_project_cards() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = unrooted_vault(&dir);
    let reader = define_agent(&vault).expect("a reader");
    let (root_run, children) =
        dispatch_into_child_projects(&vault, 2).expect("runs in two child projects");
    let [(own_project, own_run), (other_project, other_run)] = children[..] else {
        panic!("expected two child projects; seen {}", children.len());
    };
    let (inside, other, root, unbound, mixed) = (
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
    );
    for (subject, run, now) in [
        (inside, Some(own_run), 10),
        (other, Some(other_run), 11),
        (root, Some(root_run), 12),
        (unbound, None, 13),
        (mixed, Some(own_run), 14),
        (mixed, None, 15),
    ] {
        land_agent_health_finding(&vault, subject, run, now).expect("a finding on its card");
    }
    stand_project_steward_grant(&vault, reader, &[STEWARD_READ_VERB], own_project)
        .expect("a read grant narrowed to one project");

    let answer = read(
        &vault,
        reader,
        "vault.agent_health.cards",
        json!({ "from": 0, "to": u64::MAX }),
    );
    let cards = answer.unwrap_or_else(|error| {
        panic!(
            "actor=agent {reader:?}, grant=project {own_project:?}; expected its own project's cards, not a refusal; seen {error:?}"
        )
    });
    let subjects: Vec<Value> = cards
        .as_array()
        .expect("cards")
        .iter()
        .map(|card| card["subject"].clone())
        .collect();
    assert_eq!(
        subjects,
        vec![json!(inside)],
        "actor=agent {reader:?}, grant=project {own_project:?}; expected only the card of its own project's run, none of project {other_project:?}, the root project's run, a run-less finding or the mixed card {mixed:?}; seen subjects={subjects:?}"
    );
}

/// A Steward `read` holder narrowed to one project reads the failure
/// evidence of a run in that project, with that run's own checks, and is
/// refused another project's run, the root project's run, an unknown
/// attempt, and another run's checks under its own run.
#[test]
fn project_scoped_reader_reads_own_project_failure_evidence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = unrooted_vault(&dir);
    let reader = define_agent(&vault).expect("a reader");
    let (root_run, children) =
        dispatch_into_child_projects(&vault, 2).expect("runs in two child projects");
    let [(own_project, own_run), (_, other_run)] = children[..] else {
        panic!("expected two child projects; seen {}", children.len());
    };
    stand_project_steward_grant(&vault, reader, &[STEWARD_READ_VERB], own_project)
        .expect("a read grant narrowed to one project");
    let evidence = |attempt: AttemptId, run: Option<AttemptId>| {
        let mut input = json!({ "attempt": attempt });
        if let Some(run) = run {
            input["run_ref"] = json!(hex(run));
        }
        read(&vault, reader, "vault.diagnostics.evidence", input)
    };

    for (what, answer) in [
        ("its own project's run", evidence(own_run, None)),
        ("its own run's checks", evidence(own_run, Some(own_run))),
    ] {
        if let Err(error) = answer {
            assert_ne!(
                error.code, MEMORY_CODE_FORBIDDEN,
                "actor=agent {reader:?}, grant=project {own_project:?}; expected {what} admitted; seen {error:?}"
            );
        }
    }
    assert_forbidden(evidence(other_run, None), "another project's run");
    assert_forbidden(evidence(root_run, None), "the root project's run");
    assert_forbidden(evidence(AttemptId::now(), None), "an unknown attempt");
    assert_forbidden(
        evidence(own_run, Some(other_run)),
        "another run's checks under its own run",
    );
}
