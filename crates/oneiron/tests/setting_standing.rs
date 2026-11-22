//! DESIGN 15-setting-primitive, stage 6.0 follow-up: the owner's standing approval (owner
//! principle, 16 Nov 00:44; Engine RULING 00:45 converting AUTH-1).
//! - by default an agent holder's widening asks the user; with a live owner Grant that lists the
//!   key's standing line `settings.widen:<key>` it lands at once, receipted `looser`, and the
//!   change names the Grant (`standing`);
//! - the standing line alone holds the key, and never pins;
//! - a line for one scope reaches that scope only, and a scope line reaches every key there;
//! - revoking the Grant ends it: the next widening asks again;
//! - standing approval is the owner's yes over the owner's own value row, on a key that reads one
//!   row and on one whose rows meet, and never reaches under the owner's pin.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_standing`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::Memory;
use oneiron::setting::{
    ChangeDirection, Setter, SettingScope, set_line, widen_line, widen_line_at, widen_scope_line,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::setting::setting_change;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, AgentGrantRevokeRequest,
    create_agent_definition_as, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const GET: &str = "vault.settings.get";
const LIST: &str = "vault.settings.list";
const SET: &str = "vault.settings.set";
const T0: u64 = 1_790_000_000;

/// Default 10, lower is tighter, at the vault or a project; its rows meet.
const BUDGET: &str = "test.work_budget";
/// Default 10, lower is tighter, at the vault, a world or a project; its rows meet.
const CAP: &str = "test.ordered_cap";
/// Default 7, no order, only the owner sets it, at the vault, a world or a project; one row
/// decides a read.
const OWNER_NUMBER: &str = "test.owner_number";

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

    /// An enabled, active agent definition the owner creates.
    fn agent(&self) -> EntityId {
        let id = self.vault.new_entity_id().expect("agent id");
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: id,
                definition: serde_json::from_value(json!({
                    "agent_id": format!("setting-agent-{}", id.to_hex()),
                    "desc": "setting standing approval fixture",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("agent spec"),
            },
        )
        .expect("the owner creates the agent");
        id
    }

    /// The owner's live Grant for `agent` naming `read` and `verbs`, by its id.
    fn grant(&self, agent: EntityId, verbs: &[&str]) -> EntityId {
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(
            std::iter::once("read")
                .chain(verbs.iter().copied())
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
        minted.grant.grant_ref
    }

    /// The owner revokes the Grant `grant`.
    fn revoke(&self, grant: EntityId) {
        let revoked = revoke_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantRevokeRequest {
                grant_ref: grant,
                seen: None,
            },
        )
        .expect("the owner revokes the Grant");
        assert!(revoked.changed, "{revoked:?}");
    }
}

fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    invoke(memory, verb, input).unwrap_or_else(|error| panic!("{verb} answers: {error:?}"))
}

fn vault_scope() -> Value {
    json!({ "kind": "vault" })
}

fn project(id: EntityId) -> Value {
    json!({ "kind": "project", "id": id.to_hex() })
}

fn set(key: &str, scope: Value, value: Value) -> Value {
    json!({ "key": key, "scope": scope, "value": value })
}

fn clear(key: &str, scope: Value) -> Value {
    json!({ "key": key, "scope": scope })
}

fn get(memory: &Memory<'_>, key: &str, at: Value) -> Value {
    call(memory, GET, json!({ "key": key, "at": at }))
}

/// The rows of `key` the list shows.
fn rows(memory: &Memory<'_>, key: &str) -> Vec<Value> {
    let listed = call(memory, LIST, json!({ "prefix": key }));
    listed["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .find(|entry| entry["key"] == json!(key))
        .and_then(|entry| entry["rows"].as_array().cloned())
        .unwrap_or_else(|| panic!("{key} is listed: {listed}"))
}

/// The status of a change's answer.
fn status(outcome: &Value) -> &str {
    outcome["status"].as_str().unwrap_or_default()
}

/// The setter and the direction the change of `outcome` recorded.
fn receipt(fx: &Fixture, outcome: &Value) -> (Setter, Option<ChangeDirection>) {
    let sequence = outcome["sequence"]
        .as_u64()
        .unwrap_or_else(|| panic!("an applied change's sequence: {outcome}"));
    let change = setting_change(&fx.vault, sequence)
        .expect("the change stream reads")
        .expect("the change stands");
    (change.setter, change.direction)
}

#[test]
fn a_standing_line_lands_an_agents_widening_at_once_receipted_looser_under_its_grant() {
    let fx = Fixture::rooted();

    let holder = fx.agent();
    fx.grant(holder, &[SET, GET, &set_line(BUDGET)]);
    let asked = call(
        &fx.as_agent(holder),
        SET,
        set(BUDGET, vault_scope(), json!(20)),
    );
    assert_eq!(
        status(&asked),
        "pending",
        "by default a holder's widening asks the user: {asked}"
    );

    let trusted = fx.agent();
    let grant = fx.grant(trusted, &[SET, GET, &widen_line(BUDGET)]);
    let widened = call(
        &fx.as_agent(trusted),
        SET,
        set(BUDGET, vault_scope(), json!(20)),
    );
    assert_eq!(status(&widened), "applied", "{widened}");
    assert_eq!(
        receipt(&fx, &widened),
        (Setter::Standing { grant }, Some(ChangeDirection::Looser)),
        "receipted looser, under the Grant that holds the standing line"
    );
    assert_eq!(get(&fx.as_owner(), BUDGET, json!([]))["value"], json!(20));
    let listed = rows(&fx.as_owner(), BUDGET);
    assert_eq!(listed[0]["setter"]["as"], json!("standing"), "{listed:?}");
    assert_eq!(
        listed[0]["setter"]["grant"],
        json!(grant.to_hex()),
        "{listed:?}"
    );
    assert_eq!(listed[0]["by"], json!(trusted.to_hex()), "{listed:?}");
}

#[test]
fn the_standing_line_alone_holds_the_key_and_never_pins() {
    let fx = Fixture::rooted();
    let trusted = fx.agent();
    let grant = fx.grant(trusted, &[SET, GET, &widen_line(BUDGET)]);
    let them = fx.as_agent(trusted);

    let tightened = call(&them, SET, set(BUDGET, vault_scope(), json!(5)));
    assert_eq!(status(&tightened), "applied", "{tightened}");
    assert_eq!(
        receipt(&fx, &tightened),
        (Setter::Standing { grant }, Some(ChangeDirection::Tighter))
    );
    let pin = call(
        &them,
        SET,
        json!({ "key": BUDGET, "scope": vault_scope(), "pin": true, "value": 30 }),
    );
    assert_eq!(status(&pin), "pending", "a pin is the owner's: {pin}");
    assert_eq!(
        get(&fx.as_owner(), BUDGET, json!([]))["value"],
        json!(5),
        "nothing pinned"
    );
}

#[test]
fn a_line_for_one_scope_reaches_that_scope_only_and_a_scope_line_reaches_every_key_there() {
    let fx = Fixture::rooted();
    let (room, other) = (EntityId::now(), EntityId::now());

    let scoped = fx.agent();
    let at_room = widen_line_at(CAP, &SettingScope::Project(room)).expect("a project line");
    fx.grant(scoped, &[SET, GET, &at_room]);
    let them = fx.as_agent(scoped);
    let added = call(&them, SET, set(CAP, project(room), json!(4)));
    assert_eq!(status(&added), "applied", "{added}");
    let raised = call(&them, SET, set(CAP, project(room), json!(8)));
    assert_eq!(status(&raised), "applied", "{raised}");
    assert_eq!(receipt(&fx, &raised).1, Some(ChangeDirection::Looser));
    let cleared = call(&them, SET, clear(CAP, project(room)));
    assert_eq!(
        status(&cleared),
        "applied",
        "a clear drops a bound: {cleared}"
    );
    assert_eq!(receipt(&fx, &cleared).1, Some(ChangeDirection::Looser));
    let elsewhere = call(&them, SET, set(CAP, project(other), json!(4)));
    assert_eq!(
        status(&elsewhere),
        "pending",
        "the line names one project: elsewhere the agent holds nothing: {elsewhere}"
    );
    let wider = call(&them, SET, set(CAP, vault_scope(), json!(4)));
    assert_eq!(status(&wider), "pending", "and not the vault: {wider}");

    let roomwide = fx.agent();
    let every_key = widen_scope_line(&SettingScope::Project(room)).expect("a project line");
    fx.grant(roomwide, &[SET, GET, &every_key]);
    let them = fx.as_agent(roomwide);
    call(&them, SET, set(BUDGET, project(room), json!(4)));
    let budget = call(&them, SET, set(BUDGET, project(room), json!(8)));
    assert_eq!(status(&budget), "applied", "{budget}");
    assert_eq!(receipt(&fx, &budget).1, Some(ChangeDirection::Looser));
    assert_eq!(
        get(&fx.as_owner(), BUDGET, json!([project(room)]))["value"],
        json!(8)
    );
    let owners_key = call(&them, SET, set(OWNER_NUMBER, project(room), json!(3)));
    assert_eq!(
        status(&owners_key),
        "applied",
        "every key at the scope, an owner-only key with no order included: {owners_key}"
    );
    assert_eq!(
        receipt(&fx, &owners_key).1,
        Some(ChangeDirection::Unordered)
    );
    let vault_budget = call(&them, SET, set(BUDGET, vault_scope(), json!(30)));
    assert_eq!(
        status(&vault_budget),
        "pending",
        "the scope line names one project: {vault_budget}"
    );
}

#[test]
fn revoking_the_grant_ends_the_standing_approval_and_the_next_widening_asks() {
    let fx = Fixture::rooted();
    let agent = fx.agent();
    fx.grant(agent, &[SET, GET, &set_line(BUDGET)]);
    let standing = fx.grant(agent, &[&widen_line(BUDGET)]);
    let them = fx.as_agent(agent);

    let widened = call(&them, SET, set(BUDGET, vault_scope(), json!(20)));
    assert_eq!(status(&widened), "applied", "{widened}");
    assert_eq!(
        receipt(&fx, &widened).0,
        Setter::Standing { grant: standing }
    );

    fx.revoke(standing);
    let asked = call(&them, SET, set(BUDGET, vault_scope(), json!(40)));
    assert_eq!(
        status(&asked),
        "pending",
        "the line is checked live in each write: {asked}"
    );
    let tightened = call(&them, SET, set(BUDGET, vault_scope(), json!(15)));
    assert_eq!(status(&tightened), "applied", "still a holder: {tightened}");
    assert!(
        matches!(receipt(&fx, &tightened).0, Setter::KeyGrant { .. }),
        "the set line holds it now"
    );
    assert_eq!(get(&fx.as_owner(), BUDGET, json!([]))["value"], json!(15));
}

#[test]
fn standing_approval_is_the_owners_yes_over_the_owners_row_and_never_reaches_under_the_owners_pin()
{
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let room = EntityId::now();

    let holder = fx.agent();
    fx.grant(holder, &[SET, GET, &set_line(OWNER_NUMBER), &set_line(CAP)]);
    let trusted = fx.agent();
    fx.grant(
        trusted,
        &[SET, GET, &widen_line(OWNER_NUMBER), &widen_line(CAP)],
    );

    // A key that reads one row: the owner's own row at the vault.
    call(&me, SET, set(OWNER_NUMBER, vault_scope(), json!(5)));
    let asked = call(
        &fx.as_agent(holder),
        SET,
        set(OWNER_NUMBER, vault_scope(), json!(8)),
    );
    assert_eq!(
        status(&asked),
        "pending",
        "a holder asks before it replaces the owner's row: {asked}"
    );
    let replaced = call(
        &fx.as_agent(trusted),
        SET,
        set(OWNER_NUMBER, vault_scope(), json!(8)),
    );
    assert_eq!(status(&replaced), "applied", "{replaced}");
    assert_eq!(get(&me, OWNER_NUMBER, json!([]))["value"], json!(8));

    // A key whose rows meet: the owner's own row at a project.
    call(&me, SET, set(CAP, project(room), json!(4)));
    let asked = call(&fx.as_agent(holder), SET, set(CAP, project(room), json!(9)));
    assert_eq!(status(&asked), "pending", "{asked}");
    let raised = call(
        &fx.as_agent(trusted),
        SET,
        set(CAP, project(room), json!(9)),
    );
    assert_eq!(status(&raised), "applied", "{raised}");
    assert_eq!(receipt(&fx, &raised).1, Some(ChangeDirection::Looser));
    assert_eq!(get(&me, CAP, json!([project(room)]))["value"], json!(9));

    // The owner's pin is the owner's opt-out from every standing approval.
    call(
        &me,
        SET,
        json!({ "key": OWNER_NUMBER, "scope": vault_scope(), "pin": true, "value": 6 }),
    );
    let under_pin = call(
        &fx.as_agent(trusted),
        SET,
        set(OWNER_NUMBER, project(room), json!(12)),
    );
    assert_eq!(
        status(&under_pin),
        "pending",
        "never a row under the owner's pin: {under_pin}"
    );
    assert_eq!(
        get(&me, OWNER_NUMBER, json!([project(room)]))["value"],
        json!(6),
        "the pin decides"
    );
}
