//! WAVE11-REPO-REGISTRANT-UNRECORDED (restriction wave 11 C55): a local
//! repository registration an agent makes as the owner's delegate names that
//! agent as its registrant, and a later config update keeps it.
//!
//! Red/green facade tests: every act below drives the real route
//! `POST /v1/core/facade/vault.repo.anchor.bind` with a real paired agent
//! credential, or with the owner's host-root credential. The fixture is
//! `restriction_wave11_owner_delegates.rs`'s: the owner mints each Grant over
//! HTTP, and Setting rows are set engine-direct in setup. The base without
//! this build answers no registrant, so the agent cases are a real red.
//!
//! - The owner's answer names the registrant; a delegate's answer names it
//!   only when that delegate is the registrant.
//! - The owner's own registration names none, and an agent's update of it
//!   adds none.
//!
//! Each case owns its vault. Deterministic: in-process vault and router
//! (`oneshot`, no TCP ports, no sleeps, no models).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --features oneiron/test-support
//! --test restriction_wave11_repo_registrant`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingMode, SettingScope};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::REPO_ANCHOR_BIND_VERB;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The owner key that lets an agent register a local folder.
const REGISTRATION_KEY: &str = "codebase.registration.agent_may_register";

/// One paired agent credential: its registered principal, its holder
/// signing key, its redeemed slip and the token it presents.
struct Agent {
    principal: EntityId,
    holder: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("restriction-wave11-owner-delegates".into()),
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
    let app = build_app(server);
    Fixture {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
    }
}

/// Pairs one agent the way `token agent` does: a registered named PERSON
/// principal, a principal-bound link narrowed to `core:read`/`core:write`,
/// redeemed over the real pairing route with the holder-signed binding
/// transcript.
async fn pair_agent(fixture: &Fixture, name: &str, seed: [u8; 32]) -> Agent {
    let vault = &fixture.vault;
    let principal = vault.ensure_agent_principal(name).expect("agent principal");
    let holder = SigningKey::from_bytes(&seed);
    let binding_key = holder.verifying_key().to_bytes();
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:write".to_owned(),
    ]));
    let link = vault
        .issue_pairing_link_for_principal(
            &fixture.issuer,
            scope,
            3600,
            PairingPrincipal {
                holder_ref: Some(principal.to_hex()),
                actor_class: Some("agent".to_owned()),
                org_ref: None,
                write_facet: None,
                ..Default::default()
            },
        )
        .expect("pairing link");
    let transcript = pairing_binding_transcript(&link.code, &binding_key, &principal.to_hex())
        .expect("pairing transcript");
    let signature: String = hex(&holder.sign(&transcript).to_bytes());
    let request = Request::post("/v1/core/pairing/redeem")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "code": link.code,
                "holder_ref": principal.to_hex(),
                "binding_key": hex(&binding_key),
                "signature": signature,
            })
            .to_string(),
        ))
        .expect("pairing redeem request");
    let response = fixture
        .app
        .clone()
        .oneshot(request)
        .await
        .expect("pairing redeem response");
    assert_eq!(response.status(), StatusCode::OK, "pairing redeem status");
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("pairing redeem body");
    let body: Value = serde_json::from_slice(&bytes).expect("pairing redeem JSON");
    let token = body["token"].as_str().expect("paired token").to_owned();
    let slip = CapabilitySlip::from_token(&token).expect("paired slip");
    assert_eq!(
        slip.claims.holder_ref,
        principal.to_hex(),
        "redeemed slip binds its agent"
    );
    assert_eq!(
        slip.claims.actor_class.as_deref(),
        Some("agent"),
        "redeemed slip binds its class"
    );
    Agent {
        principal,
        holder,
        slip,
        token,
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

fn agent_binding(fixture: &Fixture, agent: &Agent) -> String {
    let timestamp = fixture.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let transcript = agent
        .slip
        .binding_transcript(challenge.as_bytes())
        .expect("agent binding transcript");
    let signature: String = hex(&agent.holder.sign(&transcript).to_bytes());
    json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
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

async fn agent_post(
    fixture: &Fixture,
    agent: &Agent,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let binding = agent_binding(fixture, agent);
    post(fixture, path, &agent.token, binding, body).await
}

/// The owner mints the agent a conferring Grant listing `verbs` over HTTP
/// and returns its grant ref.
async fn mint_grant(fixture: &Fixture, agent_hex: &str, verbs: &[&str]) -> String {
    let mut values = vec!["read".to_owned()];
    values.extend(verbs.iter().map(|verb| (*verb).to_owned()));
    let (status, body) = post(
        fixture,
        "/v1/core/facade/vault.agents.grants.mint",
        &fixture.owner_token,
        owner_binding(fixture),
        json!({
            "agent": agent_hex,
            "authority_scope": {
                "worlds": {"kind": "all"},
                "facets": {"kind": "all"},
                "bands": {"kind": "all"},
                "audience": {"kind": "all"},
                "verbs": {"kind": "some", "values": values},
                "sensitivity": {"kind": "at_most", "value": "restricted"},
            },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "mint the grant: {body}");
    assert_eq!(
        body["grant"]["agent"].as_str(),
        Some(agent_hex),
        "minted grant binds its agent: {body}"
    );
    assert_eq!(
        body["grant"]["confers"].as_bool(),
        Some(true),
        "minted grant confers: {body}"
    );
    body["grant"]["grant_ref"]
        .as_str()
        .expect("minted grant ref")
        .to_owned()
}

/// The owner sets one Setting row engine-direct: setup, never the act under
/// test. Asserts the row applied.
fn set_row(vault: &Vault, key: &str, item: Option<&str>, scope: SettingScope, value: Value) {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("embedded owner actor");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let outcomes = oneiron::test_doors::setting::set_settings_in_one_write(
        vault,
        &proof,
        &[SetSetting {
            key: key.to_owned(),
            item: item.map(str::to_owned),
            scope,
            mode: SettingMode::Value,
            value: Some(value),
            expected_revision: None,
            why: None,
            check_in_ref: None,
            weight_runs: None,
        }],
        false,
    )
    .expect("set the row");
    assert!(
        matches!(outcomes[..], [SetSettingOutcome::Applied { .. }]),
        "the row applied: {outcomes:?}"
    );
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git output")
        .trim()
        .to_owned()
}

/// A committed local Git repository; answers its canonical folder.
fn git_repo() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("temporary repo directory");
    git(dir.path(), &["init", "--quiet"]);
    git(dir.path(), &["symbolic-ref", "HEAD", "refs/heads/main"]);
    std::fs::write(
        dir.path().join("math.rs"),
        "pub fn add_one(value: u32) -> u32 {\n    value + 1\n}\n",
    )
    .expect("write a file");
    git(dir.path(), &["add", "--", "math.rs"]);
    git(
        dir.path(),
        &[
            "-c",
            "user.name=owen",
            "-c",
            "user.email=owen@example.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "one file",
        ],
    );
    let folder = dir
        .path()
        .canonicalize()
        .expect("canonical folder")
        .to_str()
        .expect("UTF-8 repo path")
        .to_owned();
    (dir, folder)
}

/// Pairs an agent the owner lets register: its Grant lists the verb and its
/// row of the registration key is on.
async fn registering_agent(fixture: &Fixture, name: &str, seed: [u8; 32]) -> Agent {
    let agent = pair_agent(fixture, name, seed).await;
    let _grant = mint_grant(fixture, &agent.principal.to_hex(), &[REPO_ANCHOR_BIND_VERB]).await;
    set_row(
        &fixture.vault,
        REGISTRATION_KEY,
        None,
        SettingScope::Agent(agent.principal),
        json!(true),
    );
    agent
}

fn bind_path() -> String {
    format!("/v1/core/facade/{REPO_ANCHOR_BIND_VERB}")
}

/// The owner binds `body` on his host-root credential.
async fn owner_bind(fixture: &Fixture, body: Value) -> (StatusCode, Value) {
    post(
        fixture,
        &bind_path(),
        &fixture.owner_token,
        owner_binding(fixture),
        body,
    )
    .await
}

/// The registrant an answer names, if any.
fn registrant(body: &Value) -> Option<&str> {
    body["registration"]
        .get("registrant")
        .map(|registrant| registrant.as_str().expect("registrant is 32 hex"))
}

/// An agent's registration names the agent, in its own answer and in the
/// owner's later answer for the same anchor.
#[test]
fn an_agent_registration_names_the_agent() {
    run_on_engine_stack("w11-registrant-agent", || async {
        let fixture = setup();
        let agent = registering_agent(&fixture, "registrant-a", [0xE1; 32]).await;
        let agent_hex = agent.principal.to_hex();
        let project = fixture.vault.root_project().expect("root project");
        let (_repo_dir, folder) = git_repo();

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &bind_path(),
            json!({"local_folder": folder, "project": project.to_hex()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "delegate registration: {body}");
        assert_eq!(body["changed"].as_bool(), Some(true), "{body}");
        assert_eq!(
            registrant(&body),
            Some(agent_hex.as_str()),
            "the agent's answer names it: {body}"
        );
        let anchor = body["anchor"]["repo"]
            .as_str()
            .expect("registered anchor")
            .to_owned();

        let (status, body) = owner_bind(
            &fixture,
            json!({"local_folder": folder, "project": project.to_hex(), "anchor": anchor}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner repeat: {body}");
        assert_eq!(
            body["anchor"]["repo"].as_str(),
            Some(anchor.as_str()),
            "{body}"
        );
        assert_eq!(
            registrant(&body),
            Some(agent_hex.as_str()),
            "the owner's answer names the agent: {body}"
        );
    });
}

/// The owner's own registration names no registrant, and an agent's later
/// update of it (a new whitelist) adds none.
#[test]
fn an_owner_registration_names_no_registrant() {
    run_on_engine_stack("w11-registrant-owner", || async {
        let fixture = setup();
        let agent = registering_agent(&fixture, "registrant-update", [0xE2; 32]).await;
        let project = fixture.vault.root_project().expect("root project");
        let (_repo_dir, folder) = git_repo();

        let (status, body) = owner_bind(
            &fixture,
            json!({"local_folder": folder, "project": project.to_hex()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner registration: {body}");
        assert_eq!(registrant(&body), None, "the owner's registration: {body}");
        let anchor = body["anchor"]["repo"]
            .as_str()
            .expect("registered anchor")
            .to_owned();

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &bind_path(),
            json!({
                "local_folder": folder,
                "project": project.to_hex(),
                "anchor": anchor,
                "editable": ["math.rs"],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "delegate update: {body}");
        assert_eq!(body["changed"].as_bool(), Some(true), "{body}");
        assert_eq!(
            body["registration"]["editable"],
            json!(["math.rs"]),
            "the update applied: {body}"
        );
        assert_eq!(registrant(&body), None, "an update adds none: {body}");

        let (status, body) = owner_bind(
            &fixture,
            json!({"local_folder": folder, "project": project.to_hex(), "anchor": anchor}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner repeat: {body}");
        assert_eq!(registrant(&body), None, "still the owner's: {body}");
    });
}

/// A second agent that updates the first one's registration sees no
/// registrant in its own answer; the owner still sees the first agent.
#[test]
fn a_second_agent_sees_no_other_registrant() {
    run_on_engine_stack("w11-registrant-second", || async {
        let fixture = setup();
        let first = registering_agent(&fixture, "registrant-first", [0xE3; 32]).await;
        let second = registering_agent(&fixture, "registrant-second", [0xE4; 32]).await;
        let first_hex = first.principal.to_hex();
        let project = fixture.vault.root_project().expect("root project");
        let (_repo_dir, folder) = git_repo();

        let (status, body) = agent_post(
            &fixture,
            &first,
            &bind_path(),
            json!({"local_folder": folder, "project": project.to_hex()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "first registration: {body}");
        let anchor = body["anchor"]["repo"]
            .as_str()
            .expect("registered anchor")
            .to_owned();

        let (status, body) = agent_post(
            &fixture,
            &second,
            &bind_path(),
            json!({
                "local_folder": folder,
                "project": project.to_hex(),
                "anchor": anchor,
                "editable": ["math.rs"],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "second agent's update: {body}");
        assert_eq!(
            body["registration"]["editable"],
            json!(["math.rs"]),
            "the update applied: {body}"
        );
        assert_eq!(
            registrant(&body),
            None,
            "the second agent's answer names no other agent: {body}"
        );

        let (status, body) = owner_bind(
            &fixture,
            json!({"local_folder": folder, "project": project.to_hex(), "anchor": anchor}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner repeat: {body}");
        assert_eq!(
            registrant(&body),
            Some(first_hex.as_str()),
            "the update kept the first agent: {body}"
        );
    });
}
