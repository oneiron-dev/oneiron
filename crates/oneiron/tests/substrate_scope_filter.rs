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
//! vault-wide value.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test substrate_scope_filter`.
#![cfg(oneiron_test_support)]

use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::{ENGINE_CONTROLS_VERBS, define_agent};
use oneiron::test_doors::steward::STEWARD_READ_VERB;
use oneiron::test_doors::substrate_reads::stand_project_steward_grant;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

const KEY: &str = "eval_floor_min_families";

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

/// The owner pins `KEY` at `value` for `project`, or for the whole vault.
fn pin(vault: &Vault, owner: EntityId, project: Option<EntityId>, value: f64) {
    let mut row = json!({
        "key": KEY,
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
    pin(&vault, owner, Some(own_project), 3.0);
    pin(&vault, owner, Some(other_project), 5.0);
    pin(&vault, owner, None, 7.0);
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
    let cell = |project: Option<EntityId>| {
        let mut input = json!({
            "cell": { "subject": agent.to_hex(), "predicate": "learning.reliability" },
        });
        if let Some(project) = project {
            input["project_ref"] = json!(project.to_hex());
        }
        read(&vault, agent, "vault.learning.read", input)
    };

    // Admitted: whatever the empty cell answers, it is not the refusal.
    if let Err(error) = cell(Some(own_project)) {
        assert_ne!(
            error.code, MEMORY_CODE_FORBIDDEN,
            "actor=agent {agent:?}, grant=project {own_project:?}; expected its own project's cell admitted; seen {error:?}"
        );
    }
    assert_forbidden(cell(Some(other_project)), "another project's cell");
    assert_forbidden(cell(None), "the vault's cell");
}
