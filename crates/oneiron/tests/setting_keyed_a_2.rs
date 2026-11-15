//! DESIGN 15-setting-primitive, stage 4, lane SETTING-KEYED-A, PR K2a: the origin's two
//! choice tables become catalogue keys at a served repository's scope.
//! - `origin.lfs_path_rules` (was `ORIGIN_LFS_PATH_POLICY`, moved whole): reads no rules and
//!   revision 0 at a repository the owner never set; a set names the revision it read and a
//!   stale one is refused; the rules' check refuses a path that is not repository-relative;
//!   another repository still reads none; restore class `content`.
//! - `origin.mirror` (the choice half of `ORIGIN_MIRROR_TARGET`; the rest stays as the mirror's
//!   state row): the mirror read (`served_origin_mirror`) joins the owner's setup with that
//!   state. The key's hook keeps what the old setter did: a custody record not bound to
//!   `origin:mirror-push` refuses the set; a strategy change moves `strategy_revision` and keeps
//!   the target generation; a new URL takes a fresh generation and keeps the revision; a row at
//!   the vault scope is refused; a clear removes the mirror.
//! - an agent's change to either key waits on a check-in: both are owner acts.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_keyed_a_2`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::Memory;
use oneiron::memory::origin_doors::OriginRegisterRequest;
use oneiron::origin::mirror_strategy::OriginMirrorSyncStrategy;
use oneiron::origin::secret_publication::RepoDestinationVisibility;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::payment_credential::register_bound_secret;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const GET: &str = "vault.settings.get";
const LIST: &str = "vault.settings.list";
const SET: &str = "vault.settings.set";
const T0: u64 = 1_790_000_000;

const LFS: &str = "origin.lfs_path_rules";
const MIRROR: &str = "origin.mirror";
const REPO: &str = "demo";
const TOKEN: &str = "demo-mirror-token";
const PUSH_EFFECTOR: &str = "origin:mirror-push";

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

    /// Registers the served repository `name` as the owner; its repo id.
    fn register(&self, name: &str) -> EntityId {
        self.as_owner()
            .origin_register_as(
                &self.owner_proof,
                OriginRegisterRequest {
                    repo: name.to_owned(),
                    default_branch: "main".to_owned(),
                },
            )
            .expect("the owner registers the origin")
            .repo_id
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// An enabled, active agent the owner creates, with the owner's live Grant naming the
    /// setting verbs.
    fn granted_agent(&self) -> EntityId {
        let id = self.vault.new_entity_id().expect("agent id");
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: id,
                definition: serde_json::from_value(json!({
                    "agent_id": format!("keyed-a-origin-agent-{}", id.to_hex()),
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
            ["read", GET, SET]
                .into_iter()
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

fn repo(id: EntityId) -> Value {
    json!({ "kind": "repo", "id": id.to_hex() })
}

fn set_at(key: &str, scope: Value, value: Value) -> Value {
    json!({ "key": key, "scope": scope, "value": value })
}

fn setup(url: &str, strategy: &str) -> Value {
    json!({
        "url": url,
        "secret_ref": TOKEN,
        "every_secs": 900,
        "sync_strategy": strategy,
        "visibility": "public",
    })
}

#[test]
fn lfs_path_rules_are_a_repository_setting_with_a_revision() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let repo_id = fx.register("assets");
    let at = json!([repo(repo_id)]);

    let unset = call(&me, GET, json!({ "key": LFS, "at": at }));
    assert_eq!(unset["value"], json!([]), "{unset}");
    assert_eq!(unset["revision"], json!(0));

    let rules = json!([
        { "match": { "prefix": "vendor" }, "class": "build-required" },
        { "match": { "exact": "art/logo.psd" }, "class": "repository-large" },
    ]);
    let mut first = set_at(LFS, repo(repo_id), rules.clone());
    first["expected_revision"] = json!(0);
    let applied = call(&me, SET, first.clone());
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    let read = call(&me, GET, json!({ "key": LFS, "at": at }));
    assert_eq!(read["value"], rules, "{read}");
    assert_eq!(read["revision"], json!(1));

    refused(&me, SET, first);
    refused(
        &me,
        SET,
        set_at(
            LFS,
            repo(repo_id),
            json!([{ "match": { "exact": "../escape.bin" }, "class": "repository-large" }]),
        ),
    );
    assert_eq!(
        call(&me, GET, json!({ "key": LFS, "at": at }))["value"],
        rules,
        "a refused change leaves the owner's rules"
    );

    let elsewhere = fx.register("other");
    let other = call(&me, GET, json!({ "key": LFS, "at": [repo(elsewhere)] }));
    assert_eq!(other["value"], json!([]), "{other}");
    assert_eq!(other["revision"], json!(0));

    let listed = call(&me, LIST, json!({ "prefix": "origin." }));
    let keys = listed["keys"].as_array().expect("keys");
    let entry = |name: &str| {
        keys.iter()
            .find(|entry| entry["key"] == json!(name))
            .unwrap_or_else(|| panic!("{name} is in the catalogue: {listed}"))
            .clone()
    };
    let lfs = entry(LFS);
    assert_eq!(lfs["restore"], json!("content"), "{lfs}");
    assert!(
        lfs["scopes"]
            .as_array()
            .expect("scopes")
            .contains(&json!("repo")),
        "{lfs}"
    );
    let mirror = entry(MIRROR);
    assert_eq!(mirror["restore"], json!("live"), "{mirror}");
    assert_eq!(mirror["default"], Value::Null, "{mirror}");
    assert!(
        mirror["scopes"]
            .as_array()
            .expect("scopes")
            .contains(&json!("repo")),
        "{mirror}"
    );
}

#[test]
fn the_mirror_is_the_owners_setup_joined_with_its_state() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let repo_id = fx.register(REPO);
    assert!(
        fx.vault
            .served_origin_mirror(REPO)
            .expect("mirror read")
            .is_none()
    );

    let unbound = refused(
        &me,
        SET,
        set_at(
            MIRROR,
            repo(repo_id),
            setup("https://git.example.com/you/demo.git", "schedule"),
        ),
    );
    assert!(
        fx.vault
            .served_origin_mirror(REPO)
            .expect("mirror read")
            .is_none(),
        "{unbound}"
    );

    register_bound_secret(&fx.vault, TOKEN, b"push-token", PUSH_EFFECTOR).expect("custody");
    let first_url = "https://git.example.com/you/demo.git";
    let applied = call(
        &me,
        SET,
        set_at(MIRROR, repo(repo_id), setup(first_url, "schedule")),
    );
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    let first = fx
        .vault
        .served_origin_mirror(REPO)
        .expect("mirror read")
        .expect("the owner's mirror");
    assert_eq!(first.repo, REPO);
    assert_eq!(first.url, first_url);
    assert_eq!(first.secret_ref, TOKEN);
    assert_eq!(first.user, "x-access-token");
    assert_eq!(first.every_secs, 900);
    assert_eq!(first.sync_strategy, OriginMirrorSyncStrategy::Schedule);
    assert_eq!(first.strategy_revision, 1);
    assert_eq!(first.audience.visibility, RepoDestinationVisibility::Public);
    assert!(first.last.is_none() && first.pushed.is_empty());
    let generation = first.target_generation.expect("a target generation");

    call(
        &me,
        SET,
        set_at(MIRROR, repo(repo_id), setup(first_url, "ask_me")),
    );
    let switched = fx
        .vault
        .served_origin_mirror(REPO)
        .expect("mirror read")
        .expect("the owner's mirror");
    assert_eq!(switched.sync_strategy, OriginMirrorSyncStrategy::AskMe);
    assert_eq!(switched.strategy_revision, 2, "the strategy moved");
    assert_eq!(
        switched.target_generation,
        Some(generation),
        "the destination did not"
    );

    let second_url = "https://git.example.com/you/demo-two.git";
    call(
        &me,
        SET,
        set_at(MIRROR, repo(repo_id), setup(second_url, "ask_me")),
    );
    let moved = fx
        .vault
        .served_origin_mirror(REPO)
        .expect("mirror read")
        .expect("the owner's mirror");
    assert_eq!(moved.url, second_url);
    assert_eq!(moved.strategy_revision, 2, "the strategy did not move");
    let fresh = moved.target_generation.expect("a target generation");
    assert_ne!(fresh, generation, "a new URL takes a fresh generation");

    let vault_wide = refused(
        &me,
        SET,
        json!({ "key": MIRROR, "scope": { "kind": "vault" }, "value": setup(first_url, "ask_me") }),
    );
    assert!(vault_wide.contains("per served repository"), "{vault_wide}");
    let mut wrong_token = setup(first_url, "ask_me");
    wrong_token["secret_ref"] = json!("no-such-token");
    refused(&me, SET, set_at(MIRROR, repo(repo_id), wrong_token));
    let kept = fx
        .vault
        .served_origin_mirror(REPO)
        .expect("mirror read")
        .expect("the owner's mirror");
    assert_eq!(
        kept.url, second_url,
        "a refused change leaves the owner's mirror"
    );
    assert_eq!(kept.target_generation, Some(fresh));
    refused(
        &me,
        SET,
        set_at(
            MIRROR,
            repo(repo_id),
            json!({ "url": "http://git.example.com/x.git", "secret_ref": TOKEN, "every_secs": 900 }),
        ),
    );
    refused(
        &me,
        SET,
        set_at(
            MIRROR,
            repo(repo_id),
            json!({ "url": second_url, "secret_ref": TOKEN, "every_secs": 59 }),
        ),
    );

    let cleared = call(&me, SET, set_at(MIRROR, repo(repo_id), Value::Null));
    assert_eq!(cleared["status"], json!("applied"), "{cleared}");
    assert!(
        fx.vault
            .served_origin_mirror(REPO)
            .expect("mirror read")
            .is_none()
    );
}

#[test]
fn an_agents_change_to_the_origin_keys_waits_on_a_check_in() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let repo_id = fx.register(REPO);
    register_bound_secret(&fx.vault, TOKEN, b"push-token", PUSH_EFFECTOR).expect("custody");
    let agent = fx.granted_agent();
    let them = fx.vault.memory(agent, EdgeActorClass::Agent);

    for (key, value) in [
        (
            LFS,
            json!([{ "match": { "prefix": "vendor" }, "class": "build-required" }]),
        ),
        (
            MIRROR,
            setup("https://git.example.com/you/demo.git", "full_auto"),
        ),
    ] {
        let pending = call(&them, SET, set_at(key, repo(repo_id), value));
        assert_eq!(pending["status"], json!("pending"), "{key}: {pending}");
        let read = call(&me, GET, json!({ "key": key, "at": [repo(repo_id)] }));
        assert_eq!(
            read["source"],
            json!({ "from": "default" }),
            "{key}: nothing applied"
        );
    }
    assert!(
        fx.vault
            .served_origin_mirror(REPO)
            .expect("mirror read")
            .is_none()
    );
}
