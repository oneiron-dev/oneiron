//! DESIGN 15-setting-primitive, stage 6.0 part 3: a move carries its settings.
//! - on a key whose rows meet, a project reads the rows of every parent line it names, met;
//! - a move away from a line with a tighter row carries that row onto the project as one carried
//!   row, which the project and its sub-projects read, receipted `tighter` by the engine;
//! - the new parent's tighter row narrows further, a looser one widens nothing, and a second move
//!   meets its rows with the carried row;
//! - a move that leaves no line with a row writes nothing;
//! - only a move writes a carried row: the owner's clear releases it as a looser move, an agent
//!   holder's clear asks and lands once approved, and a set with a value is refused;
//! - a key that reads one row reads only the project's own row, so lines never reach it;
//! - a project's lines start at itself.
//!
//! The move hook runs in the doors that store a project's parents (the project write door, the
//! re-parent and the seal); these tests drive it through the test door with the lines before and
//! after the move named, since the lines are its only input from the project graph.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_moves`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::check_in::HolderAnswer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{EngineControlClass, Scope, ScopeAxis};
use oneiron::memory::Memory;
use oneiron::setting::{ChangeDirection, Setter, SettingChange, SettingMode};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::setting::{carry_settings_between, project_lines, setting_change};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const GET: &str = "vault.settings.get";
const SET: &str = "vault.settings.set";
const T0: u64 = 1_790_000_000;
const CAP: &str = "test.ordered_cap";

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    _issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned: the
    /// writer lease is what lets the owner's handle call the owner verbs by name.
    fn rooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
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
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            _issuer: issuer,
            owner,
            owner_proof,
        }
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    fn as_agent(&self, agent: EntityId) -> Memory<'_> {
        self.vault.memory(agent, EdgeActorClass::Agent)
    }

    /// An agent the owner creates, Grants `read`, `vault.settings.set` and `vault.settings.get`,
    /// and gives the work-budget class: a holder of `test.ordered_cap`.
    fn holder(&self) -> EntityId {
        let agent = self.vault.new_entity_id().expect("agent id");
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: agent,
                definition: serde_json::from_value(json!({
                    "agent_id": format!("setting-agent-{}", agent.to_hex()),
                    "desc": "setting moves fixture",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("agent spec"),
            },
        )
        .expect("the owner creates the agent");
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(
            ["read", SET, GET]
                .into_iter()
                .map(str::to_owned)
                .collect::<BTreeSet<_>>(),
        );
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.owner_proof,
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
        .expect("the owner mints the Grant");
        assert!(minted.grant.confers, "the Grant confers");
        self.vault
            .grant_engine_controls(
                &self.owner_proof,
                agent,
                &[EngineControlClass::WorkBudget].into_iter().collect(),
            )
            .expect("the owner's engine.controls grant");
        agent
    }

    /// Runs the move hook for `project`, from the lines `before` to the lines `after`.
    fn carry(&self, project: EntityId, before: &[EntityId], after: &[EntityId]) -> usize {
        carry_settings_between(&self.vault, project, before, after).expect("the move hook runs")
    }
}

fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    invoke(memory, verb, input).unwrap_or_else(|error| panic!("{verb} answers: {error:?}"))
}

fn refused(memory: &Memory<'_>, verb: &str, input: Value) -> String {
    format!(
        "{:?}",
        invoke(memory, verb, input).expect_err("the call is refused")
    )
}

fn project(id: EntityId) -> Value {
    json!({ "kind": "project", "id": id.to_hex() })
}

/// The `at` of a reader that knows `lines`: a project, then its ancestors nearest first.
fn at(lines: &[EntityId]) -> Value {
    Value::Array(lines.iter().copied().map(project).collect())
}

fn set(key: &str, scope: Value, value: Value) -> Value {
    json!({ "key": key, "scope": scope, "value": value })
}

fn clear(key: &str, scope: Value) -> Value {
    json!({ "key": key, "scope": scope })
}

/// The clear of the row a move carried onto `scope`.
fn clear_carried(key: &str, scope: Value) -> Value {
    json!({ "key": key, "scope": scope, "carried": true })
}

fn get(memory: &Memory<'_>, key: &str, lines: &[EntityId]) -> Value {
    call(memory, GET, json!({ "key": key, "at": at(lines) }))
}

fn status(outcome: &Value) -> &str {
    outcome["status"].as_str().unwrap_or_default()
}

/// The change row that wrote the row deciding the read `read`.
fn deciding_change(fx: &Fixture, read: &Value) -> SettingChange {
    let revision = read["revision"]
        .as_u64()
        .expect("a deciding row's revision");
    setting_change(&fx.vault, revision)
        .expect("the change stream reads")
        .expect("the change stands")
}

/// The direction the change of `outcome` recorded.
fn direction(fx: &Fixture, outcome: &Value) -> Option<ChangeDirection> {
    let sequence = outcome["sequence"]
        .as_u64()
        .expect("an applied change's sequence");
    setting_change(&fx.vault, sequence)
        .expect("the change stream reads")
        .expect("the change stands")
        .direction
}

/// The owner approves the check-in `outcome` names; its handle.
fn approve(fx: &Fixture, outcome: &Value) -> String {
    let handle = outcome["check_in"].as_str().expect("a handle").to_owned();
    let id = EntityId::from_hex(&handle).expect("hex id");
    let row = fx
        .vault
        .pending_check_in(&id)
        .expect("read")
        .expect("the pending check-in");
    oneiron::test_doors::check_in::answer_verified(
        &fx.vault,
        &fx.owner_proof,
        &id,
        &row.effect_digest,
        HolderAnswer::Approve,
    )
    .expect("the owner approves");
    handle
}

fn carried_from(id: EntityId) -> Value {
    json!({ "from": "carried", "scope": project(id) })
}

fn row_from(id: EntityId) -> Value {
    json!({ "from": "row", "scope": project(id) })
}

#[test]
fn a_read_meets_the_rows_of_every_parent_line_it_names() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let (child, first, second) = (EntityId::now(), EntityId::now(), EntityId::now());

    call(&me, SET, set(CAP, project(first), json!(6)));
    call(&me, SET, set(CAP, project(second), json!(4)));
    let read = get(&me, CAP, &[child, first, second]);
    assert_eq!(
        (read["value"].clone(), read["source"].clone()),
        (json!(4), row_from(second)),
        "the second parent line narrows too: {read}"
    );
    call(&me, SET, set(CAP, project(first), json!(3)));
    let read = get(&me, CAP, &[child, first, second]);
    assert_eq!(
        (read["value"].clone(), read["source"].clone()),
        (json!(3), row_from(first)),
        "{read}"
    );
    call(&me, SET, set(CAP, project(child), json!(5)));
    assert_eq!(
        get(&me, CAP, &[child, first, second])["value"],
        json!(3),
        "the project's own looser row widens nothing its lines hold"
    );
}

#[test]
fn a_move_away_from_a_tighter_line_carries_its_row_to_the_project_and_its_sub_projects() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let (moved, sub, old, new, top) = (
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
    );
    call(&me, SET, set(CAP, project(old), json!(3)));
    call(&me, SET, set(CAP, project(top), json!(8)));
    assert_eq!(get(&me, CAP, &[moved, old, top])["value"], json!(3));

    assert_eq!(
        fx.carry(moved, &[moved, old, top], &[moved, new, top]),
        1,
        "one carried row: the line it left held one row; the line it keeps carries nothing"
    );
    let read = get(&me, CAP, &[moved, new, top]);
    assert_eq!(
        (read["value"].clone(), read["source"].clone()),
        (json!(3), carried_from(moved)),
        "the move loosened nothing: {read}"
    );
    let change = deciding_change(&fx, &read);
    assert_eq!(
        (
            change.mode,
            change.setter,
            change.direction,
            change.by,
            change.scope.clone()
        ),
        (
            SettingMode::Carried,
            Setter::Engine { ask: None },
            Some(ChangeDirection::Tighter),
            None,
            oneiron::setting::SettingScope::Project(moved)
        )
    );
    assert!(
        change
            .why
            .as_deref()
            .is_some_and(|why| why.contains(&moved.to_hex())),
        "the change row names the move: {change:?}"
    );
    let below = get(&me, CAP, &[sub, moved, new, top]);
    assert_eq!(
        (below["value"].clone(), below["source"].clone()),
        (json!(3), carried_from(moved)),
        "a sub-project reads its parent's carried row: {below}"
    );
}

#[test]
fn the_new_line_narrows_a_carried_row_further_and_a_second_move_meets_with_it() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let (moved, old, new, other) = (
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
    );
    call(&me, SET, set(CAP, project(old), json!(3)));
    assert_eq!(fx.carry(moved, &[moved, old], &[moved, new]), 1);

    call(&me, SET, set(CAP, project(new), json!(5)));
    assert_eq!(
        get(&me, CAP, &[moved, new])["value"],
        json!(3),
        "a looser new line widens nothing"
    );
    call(&me, SET, set(CAP, project(new), json!(2)));
    let read = get(&me, CAP, &[moved, new]);
    assert_eq!(
        (read["value"].clone(), read["source"].clone()),
        (json!(2), row_from(new)),
        "{read}"
    );

    // A second move, away from a looser line: the carried row stays as it is.
    call(&me, SET, set(CAP, project(new), json!(7)));
    assert_eq!(fx.carry(moved, &[moved, new], &[moved, other]), 0);
    assert_eq!(get(&me, CAP, &[moved, other])["value"], json!(3));
    // A third, away from a tighter one: the carried row narrows to the meet.
    call(&me, SET, set(CAP, project(other), json!(1)));
    assert_eq!(fx.carry(moved, &[moved, other], &[moved]), 1);
    let read = get(&me, CAP, &[moved]);
    assert_eq!(
        (read["value"].clone(), read["source"].clone()),
        (json!(1), carried_from(moved)),
        "{read}"
    );
    assert_eq!(
        deciding_change(&fx, &read).direction,
        Some(ChangeDirection::Tighter)
    );
}

#[test]
fn a_move_that_leaves_no_line_with_a_row_writes_nothing() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let (moved, kept, left, joined) = (
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
    );
    call(&me, SET, set(CAP, project(kept), json!(2)));
    call(&me, SET, set(CAP, project(moved), json!(4)));
    assert_eq!(
        fx.carry(moved, &[moved, left, kept], &[moved, joined, kept]),
        0,
        "the line it left holds no row"
    );
    assert_eq!(fx.carry(moved, &[moved, kept], &[moved, kept]), 0);
    assert_eq!(
        fx.carry(moved, &[moved, kept], &[moved, joined, kept]),
        0,
        "joining a parent leaves no line"
    );
    assert_eq!(
        fx.carry(moved, &[moved, kept], &[kept]),
        0,
        "the project's own row is no line it leaves"
    );
    let read = get(&me, CAP, &[moved, joined, kept]);
    assert_eq!(
        (read["value"].clone(), read["source"].clone()),
        (json!(2), row_from(kept)),
        "{read}"
    );
}

#[test]
fn the_owner_releases_a_carried_row_and_an_agent_holder_asks_to() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let agent = fx.holder();
    let them = fx.as_agent(agent);
    let (moved, old, new) = (EntityId::now(), EntityId::now(), EntityId::now());
    call(&me, SET, set(CAP, project(old), json!(3)));
    assert_eq!(fx.carry(moved, &[moved, old], &[moved, new]), 1);

    let made = refused(
        &me,
        SET,
        json!({ "key": CAP, "scope": project(moved), "value": 2, "carried": true }),
    );
    assert!(
        made.contains("only a move writes a carried row"),
        "no caller writes a carried row, the owner included: {made}"
    );
    let both = refused(
        &me,
        SET,
        json!({ "key": CAP, "scope": project(moved), "pin": true, "carried": true }),
    );
    assert!(both.contains("not both"), "{both}");

    let ask = clear_carried(CAP, project(moved));
    let pending = call(&them, SET, ask.clone());
    assert_eq!(
        status(&pending),
        "pending",
        "an agent holder's release is a loose move over the engine's row: {pending}"
    );
    assert_eq!(
        get(&me, CAP, &[moved, new])["value"],
        json!(3),
        "nothing moved yet"
    );
    let handle = approve(&fx, &pending);
    let mut spend = ask;
    spend["check_in_ref"] = json!(handle);
    let released = call(&them, SET, spend);
    assert_eq!(status(&released), "applied", "{released}");
    assert_eq!(direction(&fx, &released), Some(ChangeDirection::Looser));
    let read = get(&me, CAP, &[moved, new]);
    assert_eq!(
        (read["value"].clone(), read["source"].clone()),
        (json!(10), json!({ "from": "default" })),
        "released: {read}"
    );

    // Carried again, and released by the owner at once.
    assert_eq!(fx.carry(moved, &[moved, old], &[moved, new]), 1);
    let owners = call(&me, SET, clear_carried(CAP, project(moved)));
    assert_eq!(status(&owners), "applied", "{owners}");
    assert_eq!(direction(&fx, &owners), Some(ChangeDirection::Looser));
    assert_eq!(get(&me, CAP, &[moved, new])["value"], json!(10));
    // A plain clear names the value row, not the carried one.
    assert_eq!(fx.carry(moved, &[moved, old], &[moved, new]), 1);
    call(&me, SET, clear(CAP, project(moved)));
    assert_eq!(get(&me, CAP, &[moved, new])["value"], json!(3));
}

#[test]
fn a_key_that_reads_one_row_reads_only_the_projects_own_row() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let key = "test.owner_number";
    let (child, parent) = (EntityId::now(), EntityId::now());

    call(&me, SET, set(key, project(parent), json!(3)));
    let read = get(&me, key, &[child, parent]);
    assert_eq!(
        (read["value"].clone(), read["source"].clone()),
        (json!(7), json!({ "from": "default" })),
        "a parent line does not reach a key that reads one row: {read}"
    );
    call(&me, SET, set(key, project(child), json!(5)));
    assert_eq!(get(&me, key, &[child, parent])["value"], json!(5));
    assert_eq!(
        fx.carry(child, &[child, parent], &[child]),
        0,
        "nothing is carried for a key that reads one row"
    );
    assert_eq!(get(&me, key, &[child])["value"], json!(5));
}

#[test]
fn a_projects_lines_start_at_itself() {
    let fx = Fixture::rooted();
    let root = fx.vault.root_project().expect("the vault's root project");
    assert_eq!(
        project_lines(&fx.vault, root).expect("lines"),
        vec![root],
        "the root has no parent line"
    );
    let unknown = EntityId::now();
    assert_eq!(
        project_lines(&fx.vault, unknown).expect("lines"),
        vec![unknown],
        "a project with no stored row is its own only line"
    );
}
