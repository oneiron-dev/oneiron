//! DESIGN 15-setting-primitive, stage 4, lane SETTING-KEYED-A, PR K3c: the vault's merge queue
//! review policy (FIX 8268, `MERGE_QUEUE_REVIEW_POLICY`) becomes one setting,
//! `merge_queue.review_policy`, whose value is `land_on_green` (the default), a `review` with its
//! lens catalog and limits, or `held`, what a row that does not read reads as.
//! - the owner sets and clears it with `vault.settings.set`, and the queue's one policy point
//!   reads it: inherited work lands on green, waits for review, or holds;
//! - a catalog that does not validate, a field the policy has not, and `held` itself are refused,
//!   and the policy in force stays;
//! - a row that does not read holds inherited work until the owner sets the key again;
//! - the verbs `vault.code.merge_queue.review_policy.{get,set}` are gone. A Grant that lists the
//!   key's line (`settings.set:merge_queue.review_policy`) makes the agent a holder: it sets the
//!   key where no owner row stands, and asks before it replaces the owner's (AUTH-1 = A). A Grant
//!   that lists only the old verb, or no line, asks.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_keyed_a_5`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::Memory;
use oneiron::setting::{SettingScope, get_line, set_line};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::merge_queue_review_policy::queue_review_mode;
use oneiron::test_doors::setting::plant_undecodable_row;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::critic_lens::OF366_SEED_LENS_CATALOG_JSON;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const GET: &str = "vault.settings.get";
const SET: &str = "vault.settings.set";
const T0: u64 = 1_790_000_000;

const KEY: &str = "merge_queue.review_policy";
const OLD_GET: &str = "vault.code.merge_queue.review_policy.get";
const OLD_SET: &str = "vault.code.merge_queue.review_policy.set";

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
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
            owner,
            owner_proof,
        }
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// An enabled, active agent the owner creates, with the owner's live Grant listing `verbs`
    /// (vault-wide, no repo bounds).
    fn granted_agent(&self, verbs: &[&str]) -> EntityId {
        let id = self.vault.new_entity_id().expect("agent id");
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: id,
                definition: serde_json::from_value(json!({
                    "agent_id": format!("keyed-a-review-policy-agent-{}", id.to_hex()),
                    "desc": "setting keyed-a fixture",
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
                agent: id,
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
        id
    }

    fn mode(&self) -> (&'static str, Option<(u32, u32)>) {
        queue_review_mode(&self.vault).expect("the queue's policy point reads")
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

fn set(value: Value) -> Value {
    json!({ "key": KEY, "scope": { "kind": "vault" }, "value": value })
}

fn get(memory: &Memory<'_>) -> Value {
    call(memory, GET, json!({ "key": KEY }))
}

fn seed_catalog() -> Value {
    serde_json::from_str(OF366_SEED_LENS_CATALOG_JSON).expect("the seed catalog is JSON")
}

/// A `review` value: the seed catalog with these limits.
fn review(critics: u32, votes: u32) -> Value {
    json!({ "review": {
        "catalog": seed_catalog(),
        "thresholds": { "critics": critics, "votes": votes },
    } })
}

#[test]
fn the_owner_sets_the_review_policy_as_a_setting_and_the_queue_reads_it() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();

    let fresh = get(&me);
    assert_eq!(fresh["value"], json!("land_on_green"), "{fresh}");
    assert_eq!(fresh["source"], json!({ "from": "default" }), "{fresh}");
    assert_eq!(
        fx.mode(),
        ("land_on_green", None),
        "no policy lands on green"
    );

    let applied = call(&me, SET, set(review(3, 10)));
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    assert_eq!(get(&me)["value"], review(3, 10));
    assert_eq!(
        fx.mode(),
        ("review", Some((3, 10))),
        "inherited work waits for the policy's critics"
    );

    let defaults = json!({ "review": { "catalog": seed_catalog() } });
    let applied = call(&me, SET, set(defaults));
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    assert_eq!(
        fx.mode(),
        ("review", Some((2, 64))),
        "omitted limits are today's defaults"
    );

    let cleared = call(&me, SET, set(Value::Null));
    assert_eq!(cleared["status"], json!("applied"), "{cleared}");
    assert_eq!(get(&me)["source"], json!({ "from": "default" }));
    assert_eq!(fx.mode(), ("land_on_green", None), "a clear releases it");

    call(&me, SET, set(review(2, 64)));
    let chosen = call(&me, SET, set(json!("land_on_green")));
    assert_eq!(chosen["status"], json!("applied"), "{chosen}");
    assert_eq!(
        fx.mode(),
        ("land_on_green", None),
        "the owner may also choose the default by name"
    );
}

#[test]
fn a_policy_that_does_not_validate_is_refused_and_held_is_never_set() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let applied = call(&me, SET, set(review(3, 10)));
    assert_eq!(applied["status"], json!("applied"), "{applied}");

    let mut wrong_version = seed_catalog();
    wrong_version["schema_version"] = json!(2);
    let mut no_lens = seed_catalog();
    no_lens["lenses"] = json!([]);
    for (what, value, needle) in [
        (
            "a catalog of another schema version",
            json!({ "review": { "catalog": wrong_version } }),
            "lens catalog",
        ),
        (
            "a catalog with no lens",
            json!({ "review": { "catalog": no_lens } }),
            "lens catalog",
        ),
        (
            "a field the policy has not",
            json!({ "review": { "catalog": seed_catalog(), "floor": 1 } }),
            "floor",
        ),
        ("held", json!("held"), "does not read"),
    ] {
        let refusal = refused(&me, SET, set(value));
        assert!(refusal.contains(needle), "{what}: {refusal}");
    }

    assert_eq!(get(&me)["value"], review(3, 10), "the value in force stays");
    assert_eq!(
        fx.mode(),
        ("review", Some((3, 10))),
        "the policy in force stays"
    );
}

#[test]
fn a_row_that_does_not_read_holds_inherited_work_until_the_owner_sets_it_again() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    call(&me, SET, set(review(3, 10)));

    plant_undecodable_row(&fx.vault, KEY, SettingScope::Vault).expect("a damaged row");
    let damaged = get(&me);
    assert_eq!(damaged["value"], json!("held"), "{damaged}");
    assert_eq!(damaged["source"]["from"], json!("unreadable"), "{damaged}");
    assert_eq!(
        fx.mode(),
        ("held", None),
        "inherited work holds; it never falls to land on green"
    );

    let repaired = call(&me, SET, set(json!("land_on_green")));
    assert_eq!(repaired["status"], json!("applied"), "{repaired}");
    assert_eq!(fx.mode(), ("land_on_green", None));
}

#[test]
fn the_review_policy_verbs_are_gone_and_a_grant_line_makes_the_agent_a_holder() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    for (verb, input) in [(OLD_GET, json!({})), (OLD_SET, json!({ "policy": null }))] {
        assert!(
            invoke(&me, verb, input).is_err(),
            "{verb} is no longer a verb: the policy is one setting"
        );
    }

    let holder = fx.granted_agent(&[GET, SET, &set_line(KEY), &get_line(KEY)]);
    let holder = fx.vault.memory(holder, EdgeActorClass::Agent);
    let applied = call(&holder, SET, set(review(3, 10)));
    assert_eq!(
        applied["status"],
        json!("applied"),
        "with no owner row in its place the line sets it: {applied}"
    );
    assert_eq!(
        get(&holder)["value"],
        review(3, 10),
        "the get line reads it"
    );
    assert_eq!(fx.mode(), ("review", Some((3, 10))));

    let owners = call(&me, SET, set(json!("land_on_green")));
    assert_eq!(owners["status"], json!("applied"), "{owners}");
    let pending = call(&holder, SET, set(review(4, 10)));
    assert_eq!(
        pending["status"],
        json!("pending"),
        "replacing the owner's row asks (AUTH-1 = A): {pending}"
    );
    assert_eq!(fx.mode(), ("land_on_green", None), "the owner's row stands");

    for verbs in [&[GET, SET, OLD_GET, OLD_SET][..], &[GET, SET][..]] {
        call(&me, SET, set(Value::Null));
        let agent = fx.granted_agent(verbs);
        let agent = fx.vault.memory(agent, EdgeActorClass::Agent);
        let pending = call(&agent, SET, set(review(3, 10)));
        assert_eq!(
            pending["status"],
            json!("pending"),
            "a Grant without the key's line asks ({verbs:?}): {pending}"
        );
        assert_eq!(fx.mode(), ("land_on_green", None), "nothing applied");
    }
}
