//! `vault.task_types.promote` over HTTP (lead COORD-E2E-TREE-PIN = A, 24 Nov
//! 2026 22:45; ARCH-0079 #seed-pin): an owner-only door, proved by the
//! owner's device key like every owner yes.
//!
//! - The owner's device slip forks the team-shape head, pins a tree on the
//!   fork and promotes it: `vault.task_types.get` reads that tree in force
//!   at once, on a new team-shape head. The owner reverts through the same
//!   door, and the seeded tree is in force again on a third head.
//! - A live full-vault slip held by a person who does not own the vault, or
//!   by an agent, is refused (403, `vault.task_types.promote is the vault
//!   owner's`) and the head and tree in force stay as they were.
//!
//! On main the verb does not exist, so every case is red there. The
//! team-shape head is the shipped skill, seeded as a later engine's open
//! seeds it. Deterministic: one in-process vault, server and router per case
//! (`oneshot`); no model is configured and none is called.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! vault_task_types_promote`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::task_type::TaskTypeTree;
use oneiron::test_doors::bootstrap_skills::seed_bootstrap_skills_adding;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The shipped team-shape skill.
const TEAM_SHAPE: &str = include_str!("../../../skills/team-shape/SKILL.md");
const PROMOTE: &str = "vault.task_types.promote";
/// The holders that are not the owner, each on a live full-vault slip.
const NON_OWNER_CLASSES: [&str; 2] = ["human", "agent"];

fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

fn next_holder_key() -> SigningKey {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    SigningKey::from_bytes(&[NEXT.fetch_add(1, Ordering::Relaxed); 32])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One self-hosted vault with its embedded owner, the shipped team-shape
/// head, and its served router.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    _host: AiHost,
    app: Router,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    owner: EntityId,
}

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("this install's signing key");
    seed_bootstrap_skills_adding(&vault, &[("team-shape", TEAM_SHAPE)])
        .expect("the shipped team-shape skill");
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("vault-task-types-promote".into()),
            ..Default::default()
        },
    )
    .expect("create server");
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let root = vault
        .ensure_host_root_slip(&issuer)
        .expect("the host root slip");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    let (server, host) = AiHost::attach(server, None).await;
    let app = build_app(Arc::new(server));
    Fixture {
        _dir: dir,
        vault,
        _host: host,
        app,
        issuer,
        root,
        owner,
    }
}

/// A credential a case presents: a slip and its holder's key.
struct Caller {
    slip: CapabilitySlip,
    key: SigningKey,
}

/// A live, logged, reusable full-vault slip the host mints `holder` at
/// `class`: owner grade whoever holds it.
fn full_slip(fx: &Fixture, holder: EntityId, class: &str) -> Caller {
    let key = next_holder_key();
    let mut claims = fx.root.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some(class.to_owned());
    claims.binding_key = key.verifying_key().to_bytes();
    let slip = fx
        .vault
        .mint_capability_slip(&fx.issuer, claims)
        .expect("a live full-vault slip");
    Caller { slip, key }
}

/// The owner's own full slip, on one of his devices.
fn owner_device(fx: &Fixture) -> Caller {
    full_slip(fx, fx.owner, "human")
}

/// A full-vault slip held by someone who does not own the vault: a live
/// person (`class` "human") or a registered agent (`class` "agent").
fn non_owner(fx: &Fixture, class: &str) -> Caller {
    let holder = if class == "human" {
        let person = EntityId::now();
        fx.vault
            .put_entity(
                &person,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"human",
            )
            .expect("a live person");
        person
    } else {
        fx.vault
            .ensure_agent_principal("task-types-promote-agent")
            .expect("a registered agent principal")
    };
    assert_ne!(holder, fx.owner, "the {class} holder is not the owner");
    full_slip(fx, holder, class)
}

/// `caller`'s call to facade `verb` with `input`: its status and JSON body.
async fn call(fx: &Fixture, caller: &Caller, verb: &str, input: Value) -> (StatusCode, Value) {
    let timestamp = fx.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let transcript = caller
        .slip
        .binding_transcript(challenge.as_bytes())
        .expect("binding transcript");
    let signature = hex(&caller.key.sign(&transcript).to_bytes());
    let request = Request::post(format!("/v1/core/facade/{verb}"))
        .header(
            "authorization",
            format!("Bearer {}", caller.slip.to_token().expect("slip token")),
        )
        .header(
            "x-oneiron-binding",
            json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string(),
        )
        .header("content-type", "application/json")
        .body(Body::from(input.to_string()))
        .expect("facade request");
    let response = fx.app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body)
}

/// The owner's 200 answer at `verb`.
async fn owner_call(fx: &Fixture, verb: &str, input: Value) -> Value {
    let (status, body) = call(fx, &owner_device(fx), verb, input).await;
    assert_eq!(status, StatusCode::OK, "{verb} answered {body}");
    body
}

/// The team-shape head and tree in force, read through
/// `vault.task_types.get`.
async fn in_force(fx: &Fixture) -> (String, Value) {
    let read = owner_call(fx, "vault.task_types.get", json!({})).await;
    let head = read["in_force_skill_ref"]
        .as_str()
        .expect("a team-shape head in force")
        .to_owned();
    (head, read["tree"].clone())
}

/// The owner forks the head in force and pins a tree with one child
/// `research` under the root on the fork: the fork and the version stored.
async fn staged_pin(fx: &Fixture) -> (String, u64) {
    let (head, _) = in_force(fx).await;
    let fork = owner_call(
        fx,
        "vault.skills.fork",
        json!({"parent": head, "skill_id": "team-shape-owner-staging"}),
    )
    .await;
    let fork = fork["entity"]
        .as_str()
        .expect("the fork's entity")
        .to_owned();
    let pinned = owner_call(
        fx,
        "vault.task_types.pin",
        json!({
            "fork_ref": fork,
            "tree_version": TaskTypeTree::seeded().version + 1,
            "nodes": [
                {"node_id": "root", "name": "Any task"},
                {"node_id": "research", "parent": "root", "name": "Research work"}
            ]
        }),
    )
    .await;
    assert_eq!(pinned["in_force"], json!(false), "a pin stores a candidate");
    let version = pinned["stored"]["tree_version"]
        .as_u64()
        .expect("the stored version");
    (fork, version)
}

fn node_ids(tree: &Value) -> Vec<String> {
    let mut ids: Vec<String> = tree["nodes"]
        .as_array()
        .expect("the tree's nodes")
        .iter()
        .map(|node| node["node_id"].as_str().expect("a node id").to_owned())
        .collect();
    ids.sort();
    ids
}

#[test]
fn the_owners_device_puts_a_pinned_tree_in_force_at_once_and_reverts_it() {
    run_on_engine_stack("task-types-promote-owner", || async {
        let fx = setup().await;
        let (seeded_head, seeded_tree) = in_force(&fx).await;
        let (fork, version) = staged_pin(&fx).await;
        let promoted = owner_call(
            &fx,
            PROMOTE,
            json!({"fork_ref": fork, "tree_version": version}),
        )
        .await;
        assert_eq!(promoted["superseded_skill_ref"], json!(seeded_head));
        let pinned_head = promoted["in_force_skill_ref"]
            .as_str()
            .expect("the new head")
            .to_owned();
        assert_ne!(pinned_head, seeded_head);
        let (head, tree) = in_force(&fx).await;
        assert_eq!(head, pinned_head, "the pin is in force at once");
        assert_eq!(tree["tree_version"], json!(version));
        assert_eq!(node_ids(&tree), ["research", "root"]);

        let reverted = owner_call(&fx, PROMOTE, json!({"restore_ref": seeded_head})).await;
        assert_eq!(reverted["superseded_skill_ref"], json!(pinned_head));
        let (head, tree) = in_force(&fx).await;
        assert_eq!(reverted["in_force_skill_ref"], json!(head));
        assert!(head != pinned_head && head != seeded_head, "a third head");
        assert_eq!(tree["tree_version"], seeded_tree["tree_version"]);
        assert_eq!(node_ids(&tree), node_ids(&seeded_tree));
    });
}

#[test]
fn a_non_owner_full_slip_cannot_promote_a_tree() {
    run_on_engine_stack("task-types-promote-non-owner", || async {
        for class in NON_OWNER_CLASSES {
            let fx = setup().await;
            let before = in_force(&fx).await;
            let (fork, version) = staged_pin(&fx).await;
            let caller = non_owner(&fx, class);
            let (status, body) = call(
                &fx,
                &caller,
                PROMOTE,
                json!({"fork_ref": fork, "tree_version": version}),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{class}: {body}");
            assert_eq!(body["error"]["code"], "FORBIDDEN", "{class}");
            assert_eq!(
                body["error"]["message"],
                format!("{PROMOTE} is the vault owner's"),
                "{class}"
            );
            assert_eq!(in_force(&fx).await, before, "{class}: nothing changed");
        }
    });
}
