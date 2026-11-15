//! The `vault.skill_hubs` doors: per-hub admission, trust as data, ref round-trip, refusals,
//! and one sibling-import proof of content identity.
//!
//! What this file proves, through `POST /v1/core/facade/<verb>` on the real router:
//! - P3's door half: `publishers.admit` / `publishers.revoke` on one hub do not change another
//!   (per-hub grants, per-hub revoke receipts).
//! - Hub trust configures presentation data only: `put` mints no grant, `get` echoes the tier
//!   as inert data, and authority still comes only from a per-hub grant.
//! - `refs.set` / `refs.get` round-trip a ref policy and pin, and moving a pin trusts nothing new.
//! - The refusal table: each of the 9 rows refuses a person on their own credential with the
//!   door's own 403, and the two network rows answer their transport refusals with no hub near.
//! - P1 + P2 through the sibling `vault.skills.import` against `local-dir` hubs, offline: same
//!   content via two hubs is one entity with two provenance rows and two import receipts, one
//!   changed byte is a different entity, and each import lands at once with its receipt.
//!
//! Canon oneiron/agents/oneiron-arch-0053-skills-agent-self-knowledge-v1.md:263, mirror
//! generated/llms-full.txt:345795: "Canonical identity = SHA-256 over the canonicalized file tree
//! (recomputable from any source; cross-checks against skills.sh's own per-skill hash). ... Same
//! content via two hubs = one entity, two provenance rows." And :265 (mirror :345797): "Every hub
//! object installs at once after the fit rung, code included, with a receipt on the changed line."
//! P1 and P2 import no bytes through the 9 `vault.skill_hubs` rows without a real network hub;
//! they are proven here through the sibling `vault.skills.import` row against `local-dir` hubs.
//! And :268 (mirror :345800): "No trust chaining. A dependency from another hub never inherits
//! trust; refusal-first dependency handling." The admit/revoke half is door-reachable and tested
//! here; the dependency half runs inside the engine's import doors, not behind a facade verb.
//!
//! Driving (fixture, router, slips, request helpers) follows the house file
//! `vault_skills_doors.rs` of open PR #8510: one form per helper.
//!
//! Run: `cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support --test vault_skill_hubs_doors`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof};
use oneiron::federation::ScopeAxis;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use tower::ServiceExt;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    person: EntityId,
    person_slip: CapabilitySlip,
    person_token: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every person credential here binds; the holder proves it per request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5B; 32])
}

/// A live PERSON entity, as `graduation_demote_holder_door.rs` places one.
fn seed_person(vault: &Vault) -> EntityId {
    let who = EntityId::now();
    vault
        .put_entity(
            &who,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    who
}

/// A human credential this host mints `who`, holding `read` and `write`:
/// a person's own slip, not owner-grade.
fn mint_person_credential(
    owner_slip: &CapabilitySlip,
    vault: &Vault,
    issuer: &HostSlipIssuer,
    who: EntityId,
) -> CapabilitySlip {
    let mut claims = owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = who.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    vault
        .mint_capability_slip(issuer, claims)
        .expect("a credential")
}

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-skill-hubs-doors".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let who = seed_person(&vault);
    let person_slip = mint_person_credential(&owner_slip, &vault, &issuer, who);
    let person_token = person_slip.to_token().expect("person slip token");
    let app = build_app(server);
    Fixture {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
        person: who,
        person_slip,
        person_token,
    }
}

fn owner_binding(fixture: &Fixture) -> String {
    let timestamp = fixture.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = hex(&fixture
        .issuer
        .binding_proof(&fixture.owner_slip, challenge.as_bytes())
        .expect("owner holder proof"));
    json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
}

fn person_binding(fixture: &Fixture) -> String {
    holder_proof(
        &fixture.person_slip,
        &holder_key(),
        fixture.vault.now_recorded_at(),
    )
    .expect("holder proof")
    .to_string()
}

async fn post(
    fixture: &Fixture,
    path: &str,
    token: &str,
    binding: String,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::post(path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-oneiron-binding", binding)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("facade request");
    let response = fixture
        .app
        .clone()
        .oneshot(request)
        .await
        .expect("facade response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("facade response body");
    let body: Value = serde_json::from_slice(&bytes).expect("facade response JSON");
    (status, body)
}

async fn post_as_owner(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.owner_token.clone();
    post(fixture, path, &token, owner_binding(fixture), body).await
}

async fn post_as_person(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.person_token.clone();
    post(fixture, path, &token, person_binding(fixture), body).await
}

/// The owner registers one HTTP hub and answers the configured hub id.
async fn owner_puts_hub(fixture: &Fixture, hub: &str, endpoint: &str) -> Value {
    let (status, body) = post_as_owner(
        fixture,
        "/v1/core/facade/vault.skill_hubs.put",
        json!({
            "hub": hub,
            "kind": "http-index",
            "endpoint": endpoint,
            "trust_tier": "community",
            "sync_policy": "pinned-ref",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "put hub {hub}: {body}");
    assert_eq!(
        body["hub"].as_str(),
        Some(hub),
        "put echoes its hub: {body}"
    );
    assert_eq!(
        body["consent"]["outcome"].as_str(),
        Some("approved"),
        "put lands an approval: {body}"
    );
    body
}

/// The door's own owner refusal: 403 `FORBIDDEN`, naming the verb.
fn assert_owner_refusal(status: StatusCode, body: &Value, verb: &str) {
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("FORBIDDEN")),
        "{verb} refuses a person: {body}"
    );
    assert_eq!(
        body["error"]["message"].as_str(),
        Some(format!("{verb} is the vault owner's")).as_deref(),
        "{verb} names its owner: {body}"
    );
}

/// One `git` invocation in `root`, as the engine's own local-hub fixtures run it:
/// hermetic env, no hooks, fixture identity. Answers trimmed stdout.
fn git(root: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .current_dir(root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .env("HOME", root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "init.templateDir=",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
        ])
        .args(args)
        .output()
        .expect("local git fixture");
    assert!(output.status.success(), "local git fixture command failed");
    String::from_utf8(output.stdout)
        .expect("git UTF-8")
        .trim()
        .to_owned()
}

/// A valid SKILL tree under `root`/`ref_string`: one `SKILL.md` with frontmatter
/// plus one reference file, the shape `transport_tests::files` proves valid.
fn write_skill_tree(root: &Path, ref_string: &str, name: &str, version: &str, body: &str) {
    let skill =
        format!("---\nname: {name}\ndescription: fixture\nversion: {version}\n---\n{body}\n");
    for (rel, content) in [
        ("SKILL.md", skill.as_bytes()),
        ("references/source.txt", b"source fixture\n".as_slice()),
    ] {
        let path = root.join(ref_string).join(rel);
        std::fs::create_dir_all(path.parent().expect("file parent")).expect("mkdir");
        std::fs::write(path, content).expect("write fixture");
    }
}

/// A fresh git repo at `root` holding `ref_string`'s tree, committed once.
/// Answers the full commit the import pins.
fn commit_skill_tree(
    root: &Path,
    ref_string: &str,
    name: &str,
    version: &str,
    body: &str,
) -> String {
    git(root, &["init", "--quiet"]);
    write_skill_tree(root, ref_string, name, version, body);
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "one"]);
    git(root, &["rev-parse", "HEAD"])
}

/// The owner registers one `local-dir` hub on `dir` and answers its record.
async fn owner_puts_local_hub(fixture: &Fixture, hub: &str, dir: &Path) -> Value {
    let endpoint = dir.to_str().expect("hub path is UTF-8");
    let (status, body) = post_as_owner(
        fixture,
        "/v1/core/facade/vault.skill_hubs.put",
        json!({
            "hub": hub,
            "kind": "local-dir",
            "endpoint": endpoint,
            "trust_tier": "community",
            "sync_policy": "pinned-commit",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "put hub {hub}: {body}");
    assert_eq!(
        body["hub"].as_str(),
        Some(hub),
        "put echoes its hub: {body}"
    );
    body
}

/// The owner imports `ref_string` at `commit` from `hub` and answers the import.
/// `publisher` is admitted on that hub by the import itself.
async fn owner_imports(
    fixture: &Fixture,
    hub: &str,
    ref_string: &str,
    commit: &str,
    publisher: &str,
) -> Value {
    let (status, body) = post_as_owner(
        fixture,
        "/v1/core/facade/vault.skills.import",
        json!({
            "hub_ref": {
                "hub_id": hub,
                "ref_string": ref_string,
                "pin": {"type": "commit", "value": commit},
            },
            "publisher": publisher,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "import from {hub}: {body}");
    body
}

/// The owner reads every hub source and import receipt of `entity`.
async fn owner_receipts(fixture: &Fixture, entity: &str) -> Value {
    let (status, body) = post_as_owner(
        fixture,
        "/v1/core/facade/vault.skills.receipts",
        json!({"entity": entity}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "receipts for {entity}: {body}");
    body
}

/// The owner reads one skill with its files.
async fn owner_gets_skill(fixture: &Fixture, entity: &str) -> Value {
    let (status, body) = post_as_owner(
        fixture,
        "/v1/core/facade/vault.skills.get",
        json!({"entity": entity}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get skill {entity}: {body}");
    body
}

#[test]
fn publisher_admission_is_per_hub() {
    run_on_engine_stack("skill-hubs-per-hub", per_hub_case);
}

/// P3's door half (the per-hub admit/revoke half of "A dependency from another hub never
/// inherits trust"; not the dependency half, which runs inside the engine's import doors): one
/// identity admitted on two hubs holds two grants, and a revoke on one hub changes only that
/// hub's grant.
async fn per_hub_case() {
    let fixture = setup().await;
    let hub_a = EntityId::now().to_hex();
    let hub_b = EntityId::now().to_hex();
    owner_puts_hub(&fixture, &hub_a, "https://hub-a.invalid/index.json").await;
    owner_puts_hub(&fixture, &hub_b, "https://hub-b.invalid/index.json").await;
    let identity = "publisher:cross-hub";
    let (status, admitted_a) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.publishers.admit",
        json!({"hub": hub_a.clone(), "identity": identity}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admit on hub A: {admitted_a}");
    let grant_a = admitted_a["grant_ref"].as_str().expect("hub A grant ref");
    assert_eq!(grant_a.len(), 64, "a bound digest: {grant_a}");
    assert_eq!(
        (admitted_a["hub"].as_str(), admitted_a["identity"].as_str()),
        (Some(hub_a.as_str()), Some(identity)),
        "admit echoes hub and identity: {admitted_a}"
    );
    let (status, admitted_b) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.publishers.admit",
        json!({"hub": hub_b.clone(), "identity": identity}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admit on hub B: {admitted_b}");
    let grant_b = admitted_b["grant_ref"].as_str().expect("hub B grant ref");
    assert_ne!(
        grant_a, grant_b,
        "one identity holds a different grant per hub"
    );
    let (status, revoked_a) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.publishers.revoke",
        json!({"hub": hub_a.clone(), "identity": identity}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke on hub A: {revoked_a}");
    assert_eq!(
        revoked_a["outcome"].as_str(),
        Some("revoked"),
        "revoke lands revoked: {revoked_a}"
    );
    assert_eq!(
        revoked_a["grant_ref"].as_str(),
        Some(grant_a),
        "revoke names hub A's grant: {revoked_a}"
    );
    let decision_a = revoked_a["decision"].as_str().expect("hub A decision");
    // Hub B's grant stood through hub A's revoke, so its revoke lands a fresh decision.
    let (status, revoked_b) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.publishers.revoke",
        json!({"hub": hub_b.clone(), "identity": identity}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke on hub B: {revoked_b}");
    assert_eq!(
        revoked_b["grant_ref"].as_str(),
        Some(grant_b),
        "revoke names hub B's grant: {revoked_b}"
    );
    let decision_b = revoked_b["decision"].as_str().expect("hub B decision");
    assert_ne!(
        decision_a, decision_b,
        "hub B's revoke is its own live decision, not hub A's"
    );
    // A second revoke on hub A answers hub A's own receipt again, changing nothing further.
    let (status, revoked_a_again) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.publishers.revoke",
        json!({"hub": hub_a.clone(), "identity": identity}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "repeat revoke on hub A: {revoked_a_again}"
    );
    assert_eq!(
        revoked_a_again["decision"].as_str(),
        Some(decision_a),
        "a repeat revoke replays its own receipt: {revoked_a_again}"
    );
}

#[test]
fn hub_trust_config_mints_no_grant() {
    run_on_engine_stack("skill-hubs-trust", trust_case);
}

/// A `verified` tier configures presentation data only: `put` mints no grant, `get` echoes the
/// tier as stored data, and authority still comes only from a per-hub admission grant.
async fn trust_case() {
    let fixture = setup().await;
    let (status, defaulted) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.default.get",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "default hub reads: {defaulted}");
    assert_eq!(
        defaulted["record"]["trust_tier"].as_str(),
        Some("verified"),
        "the seeded first hub is verified data: {defaulted}"
    );
    let seeded_hub = defaulted["hub"].as_str().expect("seeded hub id");
    let (status, seeded) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.get",
        json!({"hub": seeded_hub}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seeded hub reads: {seeded}");
    assert_eq!(
        &seeded, &defaulted["record"],
        "get serves the same record default.get names"
    );
    let hub = EntityId::now().to_hex();
    let (status, configured) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.put",
        json!({
            "hub": hub.clone(),
            "kind": "http-index",
            "endpoint": "https://hub-trust.invalid/index.json",
            "trust_tier": "verified",
            "sync_policy": "pinned-ref",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "put a verified hub: {configured}");
    assert!(
        configured["consent"]["grant_ref"].is_null(),
        "configuring trust mints no grant: {configured}"
    );
    let (status, record) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.get",
        json!({"hub": hub.clone()}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "verified hub reads: {record}");
    assert_eq!(
        record["trust_tier"].as_str(),
        Some("verified"),
        "the tier is stored data: {record}"
    );
    // Authority arrives only through admission, on this hub alone.
    let (status, admitted) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.publishers.admit",
        json!({"hub": hub.clone(), "identity": "publisher:trust-proof"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "admit on the verified hub: {admitted}"
    );
    let grant = admitted["grant_ref"].as_str().expect("admission grant ref");
    assert_eq!(grant.len(), 64, "admission mints the bound digest: {grant}");
    let (status, revoked) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.publishers.revoke",
        json!({"hub": hub.clone(), "identity": "publisher:trust-proof"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "revoke on the verified hub: {revoked}"
    );
    assert_eq!(
        (revoked["outcome"].as_str(), revoked["grant_ref"].as_str()),
        (Some("revoked"), Some(grant)),
        "revoke withdraws the admission grant: {revoked}"
    );
}

#[test]
fn hub_ref_policy_round_trip_trusts_nothing_new() {
    run_on_engine_stack("skill-hubs-refs", refs_case);
}

/// `refs.set` stores one ref policy and pin without fetching or trusting; `refs.get` reads it back,
/// and a moved pin still marks nothing seen or trusted.
async fn refs_case() {
    let fixture = setup().await;
    let hub = EntityId::now().to_hex();
    owner_puts_hub(&fixture, &hub, "https://hub-refs.invalid/index.json").await;
    let (status, missing) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.refs.get",
        json!({"hub": hub.clone(), "ref_string": "skills"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "an unset ref reads: {missing}");
    assert!(missing.is_null(), "an unset ref reads null: {missing}");
    let (status, tracked) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.refs.set",
        json!({
            "hub_ref": {
                "hub_id": hub.clone(),
                "ref_string": "skills",
                "pin": {"type": "tag", "value": "v1"},
            },
            "sync_policy": "pinned-ref",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "refs.set lands: {tracked}");
    assert_eq!(
        tracked["sync_policy"].as_str(),
        Some("pinned-ref"),
        "set echoes its policy: {tracked}"
    );
    assert_eq!(
        tracked["hub_ref"]["pin"],
        json!({"type": "tag", "value": "v1"}),
        "set echoes its pin: {tracked}"
    );
    assert!(
        tracked["latest_seen"].is_null() && tracked["latest_trusted"].is_null(),
        "a set pin marks nothing seen or trusted: {tracked}"
    );
    let (status, reread) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.refs.get",
        json!({"hub": hub.clone(), "ref_string": "skills"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a set ref reads: {reread}");
    assert_eq!(&reread, &tracked, "get reads back what set stored");
    let (status, moved) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.refs.set",
        json!({
            "hub_ref": {
                "hub_id": hub.clone(),
                "ref_string": "skills",
                "pin": {"type": "tag", "value": "v2"},
            },
            "sync_policy": "pinned-ref",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a moved pin lands: {moved}");
    let (status, reread_moved) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.refs.get",
        json!({"hub": hub.clone(), "ref_string": "skills"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a moved pin reads: {reread_moved}");
    assert_eq!(
        reread_moved["hub_ref"]["pin"],
        json!({"type": "tag", "value": "v2"}),
        "get reads the moved pin: {reread_moved}"
    );
    assert!(
        reread_moved["latest_trusted"].is_null(),
        "a moved pin trusts nothing new: {reread_moved}"
    );
}

#[test]
fn unreachable_rows_answer_their_refusals() {
    run_on_engine_stack("skill-hubs-refusals", refusals_case);
}

/// The table: each of the 9 rows refuses a person on their own credential and changes nothing, and
/// the two network rows answer their offline refusals to the owner.
async fn refusals_case() {
    let fixture = setup().await;
    let hub = EntityId::now().to_hex();
    owner_puts_hub(&fixture, &hub, "https://hub-closed.invalid/index.json").await;
    let person_hub = EntityId::now().to_hex();
    let person_calls = [
        (
            "vault.skill_hubs.put",
            json!({
                "hub": person_hub.clone(),
                "kind": "http-index",
                "endpoint": "https://person.invalid/index.json",
                "trust_tier": "community",
                "sync_policy": "pinned-ref",
            }),
        ),
        ("vault.skill_hubs.get", json!({"hub": hub.clone()})),
        ("vault.skill_hubs.default.get", json!({})),
        (
            "vault.skill_hubs.publishers.admit",
            json!({"hub": hub.clone(), "identity": "publisher:person"}),
        ),
        (
            "vault.skill_hubs.publishers.revoke",
            json!({"hub": hub.clone(), "identity": "publisher:person"}),
        ),
        (
            "vault.skill_hubs.refs.get",
            json!({"hub": hub.clone(), "ref_string": "skills"}),
        ),
        (
            "vault.skill_hubs.refs.set",
            json!({
                "hub_ref": {
                    "hub_id": hub.clone(),
                    "ref_string": "skills",
                    "pin": {"type": "tag", "value": "v9"},
                },
                "sync_policy": "pinned-ref",
            }),
        ),
        (
            "vault.skill_hubs.clawhub.search",
            json!({"hub": hub.clone(), "q": "watcher"}),
        ),
        (
            "vault.skill_hubs.clawhub.import",
            json!({"hub": hub.clone(), "slug": "watcher", "publisher": "publisher:person"}),
        ),
    ];
    assert_eq!(
        fixture.person_slip.claims.holder_ref,
        fixture.person.to_hex(),
        "the person's credential binds the person"
    );
    for (verb, input) in person_calls {
        let path = format!("/v1/core/facade/{verb}");
        let (status, body) = post_as_person(&fixture, &path, input).await;
        assert_owner_refusal(status, &body, verb);
    }
    // Nothing the person tried landed.
    let (status, body) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.get",
        json!({"hub": person_hub.clone()}),
    )
    .await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("NOT_FOUND")),
        "the person's hub was never configured: {body}"
    );
    assert_eq!(
        body["error"]["message"].as_str(),
        Some("entity not found"),
        "a missing hub reads missing: {body}"
    );
    let (status, body) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.refs.get",
        json!({"hub": hub.clone(), "ref_string": "skills"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "refs read after the person: {body}");
    assert!(
        body.is_null(),
        "the person's refs.set stored nothing: {body}"
    );
    let (status, body) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.publishers.revoke",
        json!({"hub": hub.clone(), "identity": "publisher:person"}),
    )
    .await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("BAD_REQUEST")),
        "the person's admit minted no grant: {body}"
    );
    assert_eq!(
        body["error"]["message"].as_str(),
        Some("consent grant not found"),
        "revoking a never-admitted publisher: {body}"
    );
    // No hub is reachable in a test: the owner meets the transport refusals, never a fake backend.
    let dark_hub = EntityId::now().to_hex();
    owner_puts_hub(&fixture, &dark_hub, "http://127.0.0.1:1/index.json").await;
    let (status, body) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.clawhub.search",
        json!({"hub": dark_hub.clone(), "q": "watcher"}),
    )
    .await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("BAD_REQUEST")),
        "search with no hub reachable: {body}"
    );
    assert_eq!(
        body["error"]["message"].as_str(),
        Some("invalid SKILL body: ClawHub search transport failed"),
        "search names its transport failure: {body}"
    );
    let (status, body) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.clawhub.import",
        json!({"hub": dark_hub.clone(), "slug": "watcher", "publisher": "publisher:owner"}),
    )
    .await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("BAD_REQUEST")),
        "import with no hub reachable: {body}"
    );
    assert_eq!(
        body["error"]["message"].as_str(),
        Some("invalid SKILL body: ClawHub download transport failed"),
        "import names its transport failure: {body}"
    );
    // Both ClawHub rows need an HTTP hub before they touch the network.
    let (status, defaulted) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.default.get",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "default hub reads: {defaulted}");
    let seeded_hub = defaulted["hub"].as_str().expect("seeded hub id");
    let (status, body) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.clawhub.search",
        json!({"hub": seeded_hub, "q": "watcher"}),
    )
    .await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("BAD_REQUEST")),
        "search on a non-HTTP hub: {body}"
    );
    assert_eq!(
        body["error"]["message"].as_str(),
        Some("ClawHub search requires a configured HTTP hub"),
        "search names its hub kind: {body}"
    );
    let (status, body) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skill_hubs.clawhub.import",
        json!({"hub": seeded_hub, "slug": "watcher", "publisher": "publisher:owner"}),
    )
    .await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("BAD_REQUEST")),
        "import on a non-HTTP hub: {body}"
    );
    assert_eq!(
        body["error"]["message"].as_str(),
        Some("invalid SKILL body: ClawHub import requires a configured HTTP hub"),
        "import names its hub kind: {body}"
    );
}

#[test]
fn same_content_via_two_hubs_is_one_entity_with_two_receipts() {
    run_on_engine_stack("skill-hubs-import-dedup", import_dedup_case);
}

/// P1 + P2 through the sibling `vault.skills.import` against `local-dir` hubs, offline: same
/// content via two hubs is one entity with two provenance rows and two import receipts naming
/// each source; one changed byte is a different entity whose receipt and files name the change.
/// P1 is arch-0053 :263, P2 is :265; the read doors are `vault.skills.receipts` (sources and
/// receipts) and `vault.skills.get` (files).
async fn import_dedup_case() {
    let fixture = setup().await;
    let ref_string = "skills/example";
    let name = "fixture.skill";
    let version = "1";
    let dir_a = tempfile::tempdir().expect("hub dir A");
    let commit_a = commit_skill_tree(dir_a.path(), ref_string, name, version, "first version");
    let dir_b = tempfile::tempdir().expect("hub dir B");
    let commit_b = commit_skill_tree(dir_b.path(), ref_string, name, version, "first version");
    let hub_a = EntityId::now().to_hex();
    let hub_b = EntityId::now().to_hex();
    owner_puts_local_hub(&fixture, &hub_a, dir_a.path()).await;
    owner_puts_local_hub(&fixture, &hub_b, dir_b.path()).await;
    let publisher = "publisher:job-b";
    let imported_a = owner_imports(&fixture, &hub_a, ref_string, &commit_a, publisher).await;
    let entity_a = imported_a["entity"]
        .as_str()
        .expect("first import entity")
        .to_owned();
    let imported_b = owner_imports(&fixture, &hub_b, ref_string, &commit_b, publisher).await;
    let entity_b = imported_b["entity"]
        .as_str()
        .expect("second import entity")
        .to_owned();
    assert_eq!(
        entity_a, entity_b,
        "same content via two hubs is one entity"
    );
    let receipts = owner_receipts(&fixture, &entity_a).await;
    let sources = receipts["sources"].as_array().expect("provenance rows");
    assert_eq!(sources.len(), 2, "two provenance rows: {receipts}");
    let source_hubs: Vec<&str> = sources
        .iter()
        .filter_map(|source| source["hub_id"].as_str())
        .collect();
    assert!(
        source_hubs.contains(&hub_a.as_str()) && source_hubs.contains(&hub_b.as_str()),
        "each row names its hub: {receipts}"
    );
    let imports = receipts["imports"].as_array().expect("import receipts");
    assert_eq!(imports.len(), 2, "two import receipts: {receipts}");
    let mut hashes = Vec::new();
    for import in imports {
        assert_eq!(
            import["entity"].as_str(),
            Some(entity_a.as_str()),
            "each receipt names the one entity: {receipts}"
        );
        assert!(
            import["hub_id"].as_str() == Some(hub_a.as_str())
                || import["hub_id"].as_str() == Some(hub_b.as_str()),
            "each receipt names its source hub: {receipts}"
        );
        assert_eq!(
            import["pin_type"].as_str(),
            Some("commit"),
            "each receipt names its commit pin: {receipts}"
        );
        assert_eq!(
            import["publisher"].as_str(),
            Some(publisher),
            "each receipt names its publisher: {receipts}"
        );
        hashes.push(
            import["content_hash"]
                .as_str()
                .expect("receipt hash")
                .to_owned(),
        );
    }
    assert_eq!(
        hashes[0], hashes[1],
        "one content hash for one tree: {receipts}"
    );
    // One changed byte is a different entity with its own receipt on the new hash.
    let dir_c = tempfile::tempdir().expect("hub dir C");
    let commit_c = commit_skill_tree(dir_c.path(), ref_string, name, version, "first versioN");
    let hub_c = EntityId::now().to_hex();
    owner_puts_local_hub(&fixture, &hub_c, dir_c.path()).await;
    let imported_c = owner_imports(&fixture, &hub_c, ref_string, &commit_c, publisher).await;
    let entity_c = imported_c["entity"]
        .as_str()
        .expect("changed import entity")
        .to_owned();
    assert_ne!(entity_c, entity_a, "one changed byte is a different entity");
    let receipts_c = owner_receipts(&fixture, &entity_c).await;
    let imports_c = receipts_c["imports"].as_array().expect("changed receipts");
    assert_eq!(
        imports_c.len(),
        1,
        "the changed tree has its own receipt: {receipts_c}"
    );
    assert_eq!(
        imports_c[0]["hub_id"].as_str(),
        Some(hub_c.as_str()),
        "the changed receipt names its hub: {receipts_c}"
    );
    assert_ne!(
        imports_c[0]["content_hash"].as_str(),
        Some(hashes[0].as_str()),
        "the changed receipt names the new hash: {receipts_c}"
    );
    // The read doors name what changed: the new hash above, and the changed file below.
    let skill_a = owner_gets_skill(&fixture, &entity_a).await;
    let skill_c = owner_gets_skill(&fixture, &entity_c).await;
    let body_a = skill_file(&skill_a, "SKILL.md");
    let body_c = skill_file(&skill_c, "SKILL.md");
    assert!(
        body_a.contains("first version"),
        "the first entity keeps its bytes: {body_a}"
    );
    assert!(
        body_c.contains("first versioN"),
        "the changed entity names its byte: {body_c}"
    );
    assert_ne!(body_a, body_c, "the two entities hold different bytes");
}

/// One file of a `vault.skills.get` answer, as text.
fn skill_file(skill: &Value, path: &str) -> String {
    let files = skill["files"].as_array().expect("skill files");
    let found = files
        .iter()
        .find(|file| file["path"].as_str() == Some(path))
        .unwrap_or_else(|| panic!("the skill holds {path}: {skill}"));
    let content: Vec<u8> = serde_json::from_value(found["content"].clone()).expect("file bytes");
    String::from_utf8(content).expect("file text")
}
