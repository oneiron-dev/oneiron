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
//! project or of the whole vault, and no catalog line, which carries the
//! vault-wide value. What it reads of a cell or of a spawn choice's
//! learning is made of its own project's runs alone: a row outside the
//! project never moves it, and never turns it into a refusal.
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
use oneiron::test_doors::substrate_reads::{record_settled_team_run, stand_project_steward_grant};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

const KEY: &str = "eval_floor_min_families";
const WINDOW_KEY: &str = "learning_window_half_life_days";
const CONSENT_SCOPE: &str = "substrate-scope-filter";
const NOW: u64 = 10;
/// A judge revision, and the one a conversion maps its scores onto.
const JUDGE: &str = "substrate-scope-filter-judge@1";
const NEXT_JUDGE: &str = "substrate-scope-filter-judge@2";
/// An evidence time after any read's clock: a run at it fades by nothing,
/// whenever it is read, so two readings of one cell compare exactly.
const LATER: u64 = 4_102_444_800;
/// One day, in seconds.
const DAY: u64 = 86_400;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
}

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

/// A narrowed reader reads its own project's cell as the cell's own runs
/// alone make it: over the pack's shipped prior, at the catalog's window,
/// each judge's score as the judge gave it. No row outside the project moves
/// that answer or turns it into a refusal: not a prior the cell took from
/// elsewhere (a stored parent prior, as a project cell keeps the vault's
/// reading it borrowed before its first own run), not a run in the vault's
/// cell that an empty cell of the project would borrow, not a judge
/// conversion fitted on other cells' overlap, and not a window a vault row
/// set. Red at main (the cell is refused there), at this PR's first head
/// 308e715348a1 (it showed the parent prior), and at 387cd85a1b4 (it refused
/// a cell over the parent prior, and an empty cell once the vault's cell had
/// a run).
#[test]
fn project_scoped_reader_reads_its_cell_from_its_own_runs_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner) = owned_vault(&dir);
    let agent = define_agent(&vault).expect("an agent");
    let own_project = EntityId::now();
    stand_project_steward_grant(&vault, agent, &[STEWARD_READ_VERB], own_project)
        .expect("a read grant narrowed to one project");
    let reading = |executor: &str| {
        let view = read_edit_cost_cell(&vault, agent, executor, Some(own_project))
            .unwrap_or_else(|error| {
                panic!(
                    "actor=agent {agent:?}, grant=project {own_project:?}, executor={executor}; expected its own project's cell, not a refusal; seen {error:?}"
                )
            });
        json!({
            "estimate": view["view"]["estimate"],
            "own": view["view"]["own"],
            "borrowed_from": view["view"]["borrowed_from"],
        })
    };

    // One own run, judged by JUDGE, over a parent prior; and an empty cell.
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
    let mut run = LearningEvidence::anchored(
        EntityId::now().to_hex(),
        LATER,
        Anchor::OwnerVerdict,
        Observation::Magnitude(0.5),
    );
    run.judge = Some(JUDGE.to_owned());
    oneiron::learning::record_evidence(&vault, &kept, &run, NOW)
        .expect("an own run")
        .expect("the cell holds its own run");
    let (kept_before, empty_before) = (reading("kept"), reading("empty"));
    let shown = (
        kept_before["estimate"]["prior"]["origin"].as_str(),
        kept_before["estimate"]["runs"].as_f64(),
        kept_before["own"].as_bool(),
        kept_before["borrowed_from"].is_null(),
    );
    assert_eq!(
        shown,
        (Some("shipped"), Some(1.0), Some(true), true),
        "actor=agent {agent:?}; expected its one own run over the shipped prior, never the parent prior; seen {kept_before}"
    );
    let empty = (
        empty_before["estimate"]["prior"]["origin"].as_str(),
        empty_before["own"].as_bool(),
        empty_before["borrowed_from"].is_null(),
    );
    assert_eq!(
        empty,
        (Some("shipped"), Some(false), true),
        "actor=agent {agent:?}; expected the empty cell over the shipped prior; seen {empty_before}"
    );

    // Rows outside the project: a run in the vault's cell the empty cell
    // would borrow, a conversion of JUDGE's scores fitted elsewhere, and a
    // window the vault's row sets.
    let vault_run = LearningEvidence::anchored(
        EntityId::now().to_hex(),
        LATER,
        Anchor::OwnerVerdict,
        Observation::Magnitude(0.8),
    );
    oneiron::learning::record_evidence(
        &vault,
        &edit_cost_cell(agent, "empty", None),
        &vault_run,
        NOW,
    )
    .expect("a run in the vault's cell")
    .expect("the vault's cell holds its run");
    oneiron::learning::record_judge_conversion(
        &vault,
        JUDGE,
        NEXT_JUDGE,
        &[(0.0, 0.0), (1.0, 0.0)],
        NOW,
    )
    .expect("a judge conversion");
    pin(&vault, owner, WINDOW_KEY, None, 1.0);

    for (what, before, after) in [
        (
            "its cell over the parent prior",
            kept_before,
            reading("kept"),
        ),
        ("its empty cell", empty_before, reading("empty")),
    ] {
        assert_eq!(
            after, before,
            "actor=agent {agent:?}, grant=project {own_project:?}; expected {what} read as before the vault's run, the judge conversion and the vault's window; seen after={after} before={before}"
        );
    }
}

/// The owner pins the spawn width at `width` for `project`.
fn pin_width(vault: &Vault, owner: EntityId, project: EntityId, width: u32) {
    invoke(
        &vault.memory(owner, EdgeActorClass::Human),
        "vault.settings.learning.put",
        json!({
            "key": "width",
            "mode": "pin",
            "choice": { "width": width },
            "why": "substrate scope filter test",
            "project": project.to_hex(),
        }),
    )
    .expect("the owner pins the width");
}

/// The learned value beside the one width row `holder` reads.
fn learned_width(vault: &Vault, holder: EntityId) -> Value {
    let view = read(vault, holder, "vault.settings.learning", json!({ "key": "width" }))
        .unwrap_or_else(|error| {
            panic!(
                "actor=agent {holder:?}; expected its own project's width row, not a refusal; seen {error:?}"
            )
        });
    let rows = view["rows"].as_array().expect("rows");
    assert_eq!(
        rows.len(),
        1,
        "actor=agent {holder:?}; expected its own project's width row alone; seen view={view}"
    );
    rows[0]["learned"].clone()
}

/// A narrowed holder reads a spawn choice row of its own project beside what
/// that project's own team runs learned under it, faded at the catalog's
/// window: a project with no run of its own reads no runs, never the
/// vault's. A run of the vault's and a window the vault's row sets leave
/// both answers as they were. Red at main (the dials are refused there) and
/// at 387cd85a1b4 (it faded the runs at the vault's window, and dropped the
/// learned value once the vault had a run).
#[test]
fn project_scoped_holder_reads_choice_learning_of_its_own_runs_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner) = owned_vault(&dir);
    let (busy_holder, quiet_holder) = (
        define_agent(&vault).expect("an agent"),
        define_agent(&vault).expect("a second agent"),
    );
    let (busy_project, quiet_project) = (EntityId::now(), EntityId::now());
    for (holder, project) in [(busy_holder, busy_project), (quiet_holder, quiet_project)] {
        pin_width(&vault, owner, project, 2);
        stand_project_steward_grant(&vault, holder, &ENGINE_CONTROLS_VERBS, project)
            .expect("an engine.controls grant narrowed to one project");
    }
    let day_ago = unix_now() - DAY;
    record_settled_team_run(&vault, Some(busy_project), 2, day_ago).expect("a run of the project");

    let (busy_before, quiet_before) = (
        learned_width(&vault, busy_holder),
        learned_width(&vault, quiet_holder),
    );
    assert_eq!(
        quiet_before,
        json!({ "values": [], "own_runs": 0.0, "origin": "shipped" }),
        "actor=agent {quiet_holder:?}, grant=project {quiet_project:?}; expected no runs learned, the project has none; seen {quiet_before}"
    );
    // One run a day old, faded at the catalog's 90-day half-life.
    let faded = 0.5_f64.powf(1.0 / 90.0);
    let busy_runs = busy_before["own_runs"].as_f64().unwrap_or(f64::NAN);
    assert!(
        (busy_runs - faded).abs() < 1e-3 && busy_before["origin"] == json!("shipped"),
        "actor=agent {busy_holder:?}, grant=project {busy_project:?}; expected its one run faded at the catalog's window ({faded}); seen {busy_before}"
    );

    record_settled_team_run(&vault, None, 2, day_ago).expect("a run of the vault's");
    pin(&vault, owner, WINDOW_KEY, None, 1.0);

    let quiet_after = learned_width(&vault, quiet_holder);
    assert_eq!(
        quiet_after, quiet_before,
        "actor=agent {quiet_holder:?}; expected the same learned value after the vault's run and window; seen after={quiet_after} before={quiet_before}"
    );
    let busy_after = learned_width(&vault, busy_holder);
    let after_runs = busy_after["own_runs"].as_f64().unwrap_or(f64::NAN);
    assert!(
        (after_runs - busy_runs).abs() < 1e-3
            && busy_after["origin"] == busy_before["origin"]
            && busy_after["values"].as_array().map(Vec::len)
                == busy_before["values"].as_array().map(Vec::len),
        "actor=agent {busy_holder:?}; expected the same learned value after the vault's run and window; seen after={busy_after} before={busy_before}"
    );
}
