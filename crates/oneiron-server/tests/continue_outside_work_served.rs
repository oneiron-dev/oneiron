//! The continue rows serve this node's own runner seats (census L10-17, PR 2):
//! `vault.runners.continue` and `vault.runners.continue.check`.
//!
//! The owner, or an agent whose live Grant names `vault.runners.continue`,
//! starts an outside session the local CLI pushed to a custody repo this node
//! serves, on this node's own `[models.dreamer] runner_seats`; the engine
//! checks the caller before the repo answers anything, and again in its own
//! transaction. The check writes nothing. The
//! policy is the node's own: a caller-supplied policy is refused as an unknown
//! field, and a node with no seats answers `no_runner_seat`.
//!
//! Red/green facade test: it drives the real routes
//! `POST /v1/core/facade/vault.runners.continue` and
//! `POST /v1/core/facade/vault.runners.continue.check` with real paired
//! credentials, in process (`oneshot`, no TCP ports, no sleeps, no models).
//! The agent is a vault-registered named PERSON (`ensure_agent_principal`),
//! paired over real `POST /v1/core/pairing/redeem` with its holder-signed
//! binding transcript; its Grant is minted over real
//! `POST /v1/core/facade/vault.agents.grants.mint`. The custody repo is seeded
//! with `git` and the conversation imported through the engine's own import,
//! as the engine test does. Each case owns its vault.
//!
//! On PR 1's head (no rows) each case's first call to a continue row answers
//! 404 (no route), so all four fail on an assertion; with this PR all pass.
//! Case 5 (blind review F1): before the engine judged the caller first, the
//! agent with no Grant got a not-found for a repo this node does not serve.
//!
//! Deterministic: in-process vault and router, one seat, no provider calls.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --features oneiron/test-support
//! --test continue_outside_work_served`.
#![cfg(oneiron_test_support)]
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own git subprocesses; the rule covers the server's crates"
)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

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
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::ingest::history::{
    HistoryConversation, HistoryMessage, HistoryRole, HistorySkips, HistorySource,
    HistoryThreadKind,
};
use oneiron::origin::smart_http::{ORIGIN_REPO_DIR_SUFFIX, origin_serving_root};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::history_import_rows::imported_message_rows;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::build_app;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::server::SyncServer;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tower::ServiceExt;

/// The verb the agent's Grant must name.
const GRANT_VERB: &str = "vault.runners.continue";
/// The engine's authority refusal when no live Grant names the act.
const AUTHORITY_REFUSAL_MESSAGE: &str = "no live Grant of this agent names this act";
/// The ref the hand-off commit is pushed to.
const CONTINUE_REF: &str = "refs/heads/oneiron/continue/s1";
/// When the conversation is imported, as Unix seconds.
const IMPORTED_AT: u64 = 1_700_100_000;

/// The node's own runner seats: claude-code under its vendor login, the next seat when spent.
const RUNNER_SEATS: &str = r#"[dreamer.runner_seats]
on_spent = "next_seat"

[[dreamer.runner_seats.seats]]
runner = "claude-code"
auth = "vendor_login"
egress_profile_ref = "egress/test-default"
"#;

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
    commit: String,
    /// The hand-off ref's first commit: held by the store, not the tip.
    earlier_commit: String,
    conversation: EntityId,
    _ai_host: Option<AiHost>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn git_output(cwd: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .current_dir(cwd)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Oneiron")
        .env("GIT_AUTHOR_EMAIL", "oneiron@example.invalid")
        .env("GIT_COMMITTER_NAME", "Oneiron")
        .env("GIT_COMMITTER_EMAIL", "oneiron@example.invalid")
        .args(args)
        .output()
        .expect("run git")
}

fn git(cwd: &Path, args: &[&str]) -> String {
    let output = git_output(cwd, args);
    assert!(
        output.status.success(),
        "git {args:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A custody repo `demo` with two commits; the bare store holds the
/// hand-off push of the second (`commit_c`) on [`CONTINUE_REF`]. Answers
/// the bare path, the first commit and the hand-off commit.
fn seed_custody_repo(vault: &Vault) -> (PathBuf, String, String) {
    let root = origin_serving_root(vault).expect("serving root");
    let bare_name = format!("demo{ORIGIN_REPO_DIR_SUFFIX}");
    git(
        &root,
        &["init", "--bare", "--initial-branch=main", &bare_name],
    );
    let bare = root.join(&bare_name);
    let source = tempfile::tempdir().expect("source repo directory");
    git(source.path(), &["init", "--initial-branch=main"]);
    std::fs::write(source.path().join("README.md"), "outside work\n").expect("write readme");
    git(source.path(), &["add", "--", "README.md"]);
    git(source.path(), &["commit", "-m", "first"]);
    let commit_p = git(source.path(), &["rev-parse", "--verify", "HEAD"]);
    std::fs::write(source.path().join("WORK.md"), "hand-off\n").expect("write hand-off");
    git(source.path(), &["add", "--", "WORK.md"]);
    git(source.path(), &["commit", "-m", "hand-off"]);
    let commit_c = git(source.path(), &["rev-parse", "--verify", "HEAD"]);
    git(
        source.path(),
        &[
            "push",
            bare.to_str().expect("bare path is UTF-8"),
            &format!("HEAD:{CONTINUE_REF}"),
        ],
    );
    (bare, commit_p, commit_c)
}

/// A two-message conversation imported for the owner. Answers its id.
fn import_conversation(vault: &Vault, owner_proof: &AuthenticatedOwner) -> EntityId {
    let conversation = HistoryConversation {
        native_id: "continue-s1".to_owned(),
        kind: HistoryThreadKind::Main,
        parent: None,
        title: Some("outside session".to_owned()),
        started_at_ms: Some(1_699_990_000_000),
        own_started_at_ms: Some(1_699_990_000_000),
        cwd: None,
        messages: vec![
            HistoryMessage {
                native_id: "m1".to_owned(),
                parent_id: None,
                role: HistoryRole::User,
                text: "continue this work on the node".to_owned(),
                at_ms: Some(1_700_000_000_000),
                said_by: None,
                tools: Vec::new(),
                alias: None,
            },
            HistoryMessage {
                native_id: "m2".to_owned(),
                parent_id: None,
                role: HistoryRole::Assistant,
                text: "handing off to the node".to_owned(),
                at_ms: Some(1_700_000_060_000),
                said_by: None,
                tools: Vec::new(),
                alias: None,
            },
        ],
        skipped: HistorySkips::default(),
        sharing: None,
    };
    let report = vault
        .import_history(
            owner_proof,
            HistorySource::ClaudeCode,
            &conversation,
            IMPORTED_AT,
        )
        .expect("import");
    assert_eq!(
        report.new, 2,
        "precondition: both messages land: {report:?}"
    );
    imported_message_rows(vault, HistorySource::ClaudeCode, "m1")
        .expect("landed rows read")
        .expect("message m1 landed")
        .conversation
}

async fn setup(seats: bool) -> (Fixture, Agent) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("continue-outside-work-served".into()),
            ..Default::default()
        },
    )
    .expect("create server");
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("authenticated owner");
    let (_bare, earlier_commit, commit) = seed_custody_repo(&vault);
    let conversation = import_conversation(&vault, &owner_proof);
    let (server, ai_host) = if seats {
        let models = ModelsConfig::from_toml(RUNNER_SEATS, None).expect("node runner seats");
        let (server, ai_host) = AiHost::attach(server, Some(&models)).await;
        (server, Some(ai_host))
    } else {
        (server, None)
    };
    let server = Arc::new(server);
    let app = build_app(server);
    let agent = pair_agent(&vault, &app, &issuer, "continue-agent", [0x51; 32]).await;
    (
        Fixture {
            _dir: dir,
            vault,
            app,
            issuer,
            owner_slip,
            owner_token,
            commit,
            earlier_commit,
            conversation,
            _ai_host: ai_host,
        },
        agent,
    )
}

/// Pairs one agent the way `token agent` does: a registered named PERSON
/// principal, a principal-bound link narrowed to the agent verb scope the
/// end-to-end suite pairs (`core:read`, `core:write`), redeemed over the
/// real pairing route with the holder-signed binding transcript.
async fn pair_agent(
    vault: &Vault,
    app: &Router,
    issuer: &HostSlipIssuer,
    name: &str,
    seed: [u8; 32],
) -> Agent {
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
            issuer,
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
    assert!(
        link.pin.is_none(),
        "fresh vault keeps no checkpoint pin on its links"
    );
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
    let response = app
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

/// The scope the owner gives the agent's Grant: everything, with `read` (so
/// the Grant confers) and the continue verb among its explicit verbs.
fn continue_grant_scope() -> Value {
    json!({
        "worlds": {"kind": "all"},
        "facets": {"kind": "all"},
        "bands": {"kind": "all"},
        "audience": {"kind": "all"},
        "verbs": {"kind": "some", "values": ["read", GRANT_VERB]},
        "sensitivity": {"kind": "at_most", "value": "restricted"},
    })
}

/// The owner mints the agent a Grant naming the continue verb over actual
/// HTTP, reads it back from the mint answer (its agent, its verbs, that it
/// confers) and from the stored grant row itself (`vault.get`: kind
/// `FEDERATION_GRANT` under the grant ref), and returns its grant ref.
async fn mint_continue_grant(fixture: &Fixture, agent_hex: &str) -> String {
    let (status, body) = post(
        fixture,
        "/v1/core/facade/vault.agents.grants.mint",
        &fixture.owner_token,
        owner_binding(fixture),
        json!({
            "agent": agent_hex,
            "authority_scope": continue_grant_scope(),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "mint continue grant: {body}");
    assert_eq!(
        body["grant"]["agent"].as_str(),
        Some(agent_hex),
        "minted grant binds its agent: {body}"
    );
    let verbs = body["grant"]["authority_scope"]["verbs"]["values"]
        .as_array()
        .expect("minted grant verbs");
    assert!(
        verbs.iter().any(|verb| verb.as_str() == Some(GRANT_VERB)),
        "minted grant names the continue verb: {body}"
    );
    assert_eq!(
        body["grant"]["confers"].as_bool(),
        Some(true),
        "minted grant confers: {body}"
    );
    let grant = body["grant"]["grant_ref"]
        .as_str()
        .expect("minted grant ref")
        .to_owned();
    let (status, body) = get_grant_as_owner(fixture, &grant).await;
    assert_eq!(status, StatusCode::OK, "read the minted grant back: {body}");
    assert_eq!(
        body["value"]["kind"].as_str(),
        Some("FEDERATION_GRANT"),
        "{body}"
    );
    assert_eq!(
        body["value"]["id_hex"].as_str(),
        Some(grant.as_str()),
        "{body}"
    );
    grant
}

/// The owner reads one entity row over actual HTTP: the persisted
/// read-back behind the mint answer.
async fn get_grant_as_owner(fixture: &Fixture, grant: &str) -> (StatusCode, Value) {
    post(
        fixture,
        "/v1/core/facade/vault.get",
        &fixture.owner_token,
        owner_binding(fixture),
        json!({"entity_ref": grant}),
    )
    .await
}

async fn continue_as(
    fixture: &Fixture,
    token: &str,
    binding: String,
    body: Value,
) -> (StatusCode, Value) {
    post(
        fixture,
        "/v1/core/facade/vault.runners.continue",
        token,
        binding,
        body,
    )
    .await
}

async fn check_as(
    fixture: &Fixture,
    token: &str,
    binding: String,
    body: Value,
) -> (StatusCode, Value) {
    post(
        fixture,
        "/v1/core/facade/vault.runners.continue.check",
        token,
        binding,
        body,
    )
    .await
}

/// The check body for the seeded repo on the node's seat runner.
fn check_body() -> Value {
    json!({"repo": "demo", "runner": "claude-code"})
}

/// The continue body for the fixture's pushed hand-off and conversation.
fn continue_body(fixture: &Fixture) -> Value {
    json!({
        "repo": "demo",
        "git_ref": CONTINUE_REF,
        "commit": fixture.commit.as_str(),
        "conversation": fixture.conversation.to_hex(),
        "runner": "claude-code",
    })
}

/// A refusal's status and body with the body's per-request id taken out, so
/// two refusals of one caller compare equal when nothing else differs.
fn refusal_answer(status: StatusCode, mut body: Value) -> (StatusCode, Value) {
    if let Some(error) = body.get_mut("error").and_then(Value::as_object_mut) {
        error.remove("request_id");
    }
    (status, body)
}

/// The value is a 32 lower-hex id.
fn assert_hex32(value: &Value, what: &str) {
    let text = value.as_str().expect("an id is text");
    assert_eq!(text.len(), 32, "{what} is 32 hex chars: {text}");
    assert!(
        text.bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
        "{what} is lower hex: {text}"
    );
}

/// Case 1: the owner checks ready on seat 0 and continues the pushed
/// hand-off on the node's own seat; a repeat answers the same work.
#[test]
fn the_owner_continues_an_outside_session_on_the_nodes_own_seats() {
    run_on_engine_stack("continue-owner", || async {
        let (fixture, _agent) = setup(true).await;
        let owner_token = fixture.owner_token.clone();
        let (status, body) = check_as(
            &fixture,
            &owner_token,
            owner_binding(&fixture),
            check_body(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner check: {body}");
        assert_eq!(body["outcome"].as_str(), Some("ready"), "{body}");
        assert_eq!(body["seat"].as_u64(), Some(0), "{body}");
        assert_eq!(body["runner"].as_str(), Some("claude-code"), "{body}");

        let input = continue_body(&fixture);
        let (status, body) = continue_as(
            &fixture,
            &owner_token,
            owner_binding(&fixture),
            input.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner continue: {body}");
        assert_eq!(body["outcome"].as_str(), Some("bound"), "{body}");
        assert_eq!(body["seat"].as_u64(), Some(0), "{body}");
        assert_eq!(body["existing"].as_bool(), Some(false), "{body}");
        let binding = body["binding"].as_str().expect("binding id").to_owned();
        let task = body["task"].as_str().expect("task id").to_owned();
        let checkout = body["checkout"].as_str().expect("checkout id").to_owned();
        assert_hex32(&body["attempt"], "attempt");
        assert_hex32(&body["task"], "task");
        assert_hex32(&body["checkout"], "checkout");

        let (status, body) =
            continue_as(&fixture, &owner_token, owner_binding(&fixture), input).await;
        assert_eq!(status, StatusCode::OK, "owner repeat: {body}");
        assert_eq!(body["outcome"].as_str(), Some("bound"), "{body}");
        assert_eq!(body["existing"].as_bool(), Some(true), "{body}");
        assert_eq!(body["binding"].as_str(), Some(binding.as_str()), "{body}");
        assert_eq!(body["task"].as_str(), Some(task.as_str()), "{body}");
        assert_eq!(body["checkout"].as_str(), Some(checkout.as_str()), "{body}");
    });
}

/// Case 2: an agent whose Grant names the verb checks ready and continues.
#[test]
fn an_agent_whose_grant_names_the_verb_continues() {
    run_on_engine_stack("continue-granted", || async {
        let (fixture, agent) = setup(true).await;
        let agent_hex = agent.principal.to_hex();
        let _grant = mint_continue_grant(&fixture, &agent_hex).await;

        let (status, body) = check_as(
            &fixture,
            &agent.token,
            agent_binding(&fixture, &agent),
            check_body(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "granted agent check: {body}");
        assert_eq!(body["outcome"].as_str(), Some("ready"), "{body}");
        assert_eq!(body["seat"].as_u64(), Some(0), "{body}");

        let (status, body) = continue_as(
            &fixture,
            &agent.token,
            agent_binding(&fixture, &agent),
            continue_body(&fixture),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "granted agent continue: {body}");
        assert_eq!(body["outcome"].as_str(), Some("bound"), "{body}");
        assert_eq!(body["existing"].as_bool(), Some(false), "{body}");
    });
}

/// Case 3: the paired agent with no Grant is refused on both rows.
#[test]
fn an_agent_without_the_grant_is_refused() {
    run_on_engine_stack("continue-refused", || async {
        let (fixture, agent) = setup(true).await;
        let (status, body) = check_as(
            &fixture,
            &agent.token,
            agent_binding(&fixture, &agent),
            check_body(),
        )
        .await;
        assert!(
            status.is_client_error() && status != StatusCode::NOT_FOUND,
            "ungranted check is refused 4xx, not 404: {status} {body}"
        );
        assert!(
            body.to_string().contains(AUTHORITY_REFUSAL_MESSAGE),
            "ungranted check names the missing Grant: {body}"
        );

        let (status, body) = continue_as(
            &fixture,
            &agent.token,
            agent_binding(&fixture, &agent),
            continue_body(&fixture),
        )
        .await;
        assert!(
            status.is_client_error() && status != StatusCode::NOT_FOUND,
            "ungranted continue is refused 4xx, not 404: {status} {body}"
        );
        assert!(
            body.to_string().contains(AUTHORITY_REFUSAL_MESSAGE),
            "ungranted continue names the missing Grant: {body}"
        );
    });
}

/// Case 4: the seat policy is the node's own. Without seats the owner is
/// answered `no_runner_seat`; a caller-supplied policy is refused, and the
/// same body without it binds.
#[test]
fn the_seat_policy_is_the_nodes_own() {
    run_on_engine_stack("continue-policy", || async {
        let (bare, _agent) = setup(false).await;
        let bare_token = bare.owner_token.clone();
        let (status, body) = check_as(&bare, &bare_token, owner_binding(&bare), check_body()).await;
        assert_eq!(status, StatusCode::OK, "seatless check: {body}");
        assert_eq!(body["outcome"].as_str(), Some("no_runner_seat"), "{body}");
        let (status, body) = continue_as(
            &bare,
            &bare_token,
            owner_binding(&bare),
            continue_body(&bare),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "seatless continue: {body}");
        assert_eq!(body["outcome"].as_str(), Some("no_runner_seat"), "{body}");

        let (fixture, _agent) = setup(true).await;
        let owner_token = fixture.owner_token.clone();
        let mut smuggled = continue_body(&fixture);
        smuggled["policy"] = json!({"seats": [], "on_spent": "stop"});
        let (status, body) =
            continue_as(&fixture, &owner_token, owner_binding(&fixture), smuggled).await;
        assert!(
            status.is_client_error() && status != StatusCode::NOT_FOUND,
            "a caller policy is refused 4xx, not 404: {status} {body}"
        );
        let (status, body) = continue_as(
            &fixture,
            &owner_token,
            owner_binding(&fixture),
            continue_body(&fixture),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the same body binds: {body}");
        assert_eq!(body["outcome"].as_str(), Some("bound"), "{body}");
    });
}

/// Case 5: the Grant refusal is the whole answer the paired agent with no
/// Grant gets. A repo this node does not serve, a commit that is not the
/// ref's tip and a commit the store does not hold each answer it as the
/// right hand-off does, so the agent learns nothing of the repo.
#[test]
fn an_agent_without_the_grant_learns_nothing_of_the_repo() {
    run_on_engine_stack("continue-refused-repo", || async {
        let (fixture, agent) = setup(true).await;
        let binding = || agent_binding(&fixture, &agent);
        let (status, body) = check_as(&fixture, &agent.token, binding(), check_body()).await;
        assert!(
            body.to_string().contains(AUTHORITY_REFUSAL_MESSAGE),
            "precondition: the check answers the Grant refusal: {status} {body}"
        );
        let refusal = refusal_answer(status, body);
        let (status, body) = check_as(
            &fixture,
            &agent.token,
            binding(),
            json!({"repo": "absent", "runner": "claude-code"}),
        )
        .await;
        assert_eq!(
            refusal_answer(status, body),
            refusal,
            "a repo this node does not serve answers the check's Grant refusal"
        );

        let (status, body) =
            continue_as(&fixture, &agent.token, binding(), continue_body(&fixture)).await;
        assert!(
            body.to_string().contains(AUTHORITY_REFUSAL_MESSAGE),
            "precondition: the continue answers the Grant refusal: {status} {body}"
        );
        let refusal = refusal_answer(status, body);
        let shapes = [
            ("a repo this node does not serve", "repo", json!("absent")),
            (
                "a commit that is not the ref's tip",
                "commit",
                json!(fixture.earlier_commit.as_str()),
            ),
            (
                "a commit the store does not hold",
                "commit",
                json!("0".repeat(40)),
            ),
        ];
        for (shape, field, value) in shapes {
            let mut input = continue_body(&fixture);
            input[field] = value;
            let (status, body) = continue_as(&fixture, &agent.token, binding(), input).await;
            assert_eq!(
                refusal_answer(status, body),
                refusal,
                "{shape} answers the continue's Grant refusal"
            );
        }
    });
}
