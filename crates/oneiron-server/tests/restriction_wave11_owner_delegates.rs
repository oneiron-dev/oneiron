//! Restriction wave 11 owner delegates: an agent the owner lets through an
//! owner Setting key takes the owner act as the owner's delegate, and the
//! act's record names the agent.
//!
//! Red/green facade tests: every act below drives the real route
//! `POST /v1/core/facade/<verb>` with a real paired agent credential (the
//! `model_binding_proposer_grant` template: `ensure_agent_principal`,
//! pairing redemption, per-request holder proofs). The owner acts on its
//! host-root credential, and the owner mints each Grant over HTTP. Setting
//! rows are set engine-direct in setup; the delegate acts themselves are
//! always HTTP, so the base without this build answers 403 (a real red).
//!
//! Each case owns its vault. Deterministic: in-process vault and router
//! (`oneshot`, no TCP ports, no sleeps, no models).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --features oneiron/test-support
//! --test restriction_wave11_owner_delegates`.
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
use oneiron::attempt_queue::{AttemptId, AttemptQueue, ForceCancelGrounds};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::campaign::compliance::{
    COMPLIANCE_INSTALL_VERB, COMPLIANCE_REJECT_VERB, embedded_seed_pack,
};
use oneiron::dispatch_byoa::{
    RUNNER_SEAT_QUOTAS_VERB, RUNNER_SEAT_TOP_UP_VERB, RUNNER_WORK_RESUME_VERB, RunnerSeat, SeatAuth,
};
use oneiron::dreamer_runner::PROGRAM_HOLD_RELEASE_VERB;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingMode, SettingScope};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::run_doors::CANCEL_FORCE_VERB;
use oneiron::task_verb::sdk::REPO_ANCHOR_BIND_VERB;
use oneiron::test_doors::held_program::plant_held_turn_program_for_test;
use oneiron::test_doors::live_task::plant_task_with_live_attempt_for_test;
use oneiron::test_doors::spent_seat::{plant_spent_seat_credit_for_test, topped_up_by_for_test};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The four owner keys that open the doors below.
const FORCE_CANCEL_KEY: &str = "attempt_queue.agent_may_force_cancel";
const RUNNER_SEATS_KEY: &str = "dispatch_byoa.runner_seats.agent_may_manage";
const REGISTRATION_KEY: &str = "codebase.registration.agent_may_register";
const COMPLIANCE_KEY: &str = "campaign.compliance.agent_may_decide";
/// Approve stays the owner's stamp and names no delegate verb.
const COMPLIANCE_APPROVE_VERB: &str = "vault.campaign.compliance.approve";

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
        }],
        false,
    )
    .expect("set the row");
    assert!(
        matches!(outcomes[..], [SetSettingOutcome::Applied { .. }]),
        "the row applied: {outcomes:?}"
    );
}

/// Today's owner refusal for `verb`, with the suggestion naming `key`: the
/// same status, code and message the facade gives an agent today.
fn assert_owner_refusal(status: StatusCode, body: &Value, verb: &str, key: &str) {
    assert_eq!(status, StatusCode::FORBIDDEN, "refused: {body}");
    assert_eq!(body["error"]["code"].as_str(), Some("FORBIDDEN"), "{body}");
    assert_eq!(
        body["error"]["message"].as_str(),
        Some(format!("{verb} is the vault owner's")).as_deref(),
        "{body}"
    );
    let suggestions = body["error"]["suggestions"]
        .as_array()
        .expect("refusal suggestions");
    assert!(
        suggestions.iter().any(|suggestion| suggestion.as_str()
            == Some(format!("The owner lets an agent do this with the setting `{key}`.").as_str())),
        "the refusal names the key: {body}"
    );
}

/// One owner-chosen seat both requests and planters name alike.
fn seat() -> RunnerSeat {
    RunnerSeat {
        runner: "claude-code".to_owned(),
        auth: SeatAuth::VendorLogin,
        egress_profile_ref: "delegate-test".to_owned(),
        credential_handles: Vec::new(),
    }
}

fn seat_json() -> Value {
    json!({
        "runner": "claude-code",
        "auth": "vendor_login",
        "egress_profile_ref": "delegate-test",
        "credential_handles": [],
    })
}

fn policy_json() -> Value {
    json!({
        "seats": [seat_json()],
        "on_spent": "stop",
    })
}

/// The seed pack loosened as the compliance tests loosen it: the next
/// version with every `source_hygiene` row dropped. Answers the active
/// version and the pack to install.
fn loosen_pack() -> (u32, Value) {
    let seed = embedded_seed_pack().expect("seed pack");
    let prior = seed.pack_version;
    let mut pack = serde_json::to_value(&seed).expect("pack JSON");
    let rows = pack["rows"].as_array().expect("pack rows").clone();
    let kept: Vec<Value> = rows
        .iter()
        .filter(|row| row["rule_kind"].as_str() != Some("source_hygiene"))
        .cloned()
        .collect();
    assert!(
        !kept.is_empty() && kept.len() < rows.len(),
        "loosening drops some rows"
    );
    pack["pack_version"] = json!(prior + 1);
    pack["rows"] = Value::Array(kept);
    (prior, pack)
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

/// Force cancel with the agent's row on and its Grant listing the verb: the
/// TASK stops, and the receipt names the agent on `owner_delegate` grounds.
#[test]
fn force_cancel_agent_row_on_stands() {
    run_on_engine_stack("w11-cancel-on", || async {
        let fixture = setup();
        let agent = pair_agent(&fixture, "cancel-delegate", [0xA1; 32]).await;
        let agent_hex = agent.principal.to_hex();
        let task_ref = plant_task_with_live_attempt_for_test(&fixture.vault).expect("plant a TASK");
        let _grant = mint_grant(&fixture, &agent_hex, &[CANCEL_FORCE_VERB]).await;
        set_row(
            &fixture.vault,
            FORCE_CANCEL_KEY,
            None,
            SettingScope::Agent(agent.principal),
            json!(true),
        );

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{CANCEL_FORCE_VERB}"),
            json!({"task_ref": task_ref.to_hex()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "delegate force: {body}");
        assert_eq!(
            body["task_ref"].as_str(),
            Some(task_ref.to_hex()).as_deref(),
            "{body}"
        );
        assert_eq!(body["effected"].as_bool(), Some(true), "{body}");
        assert_eq!(body["forced"].as_u64(), Some(1), "{body}");
        let branch = &body["branches"][0];
        let cancellation = &branch["cancel_state"]["cancellation"];
        assert_eq!(
            cancellation["grounds"].as_str(),
            Some("owner_delegate"),
            "{body}"
        );
        assert_eq!(
            cancellation["actor"].as_str(),
            Some(agent_hex.as_str()),
            "{body}"
        );

        let attempt = AttemptId::from_bytes(
            EntityId::from_hex(branch["branch"].as_str().expect("branch hex"))
                .expect("branch id")
                .as_bytes(),
        )
        .expect("attempt id");
        let record = AttemptQueue::new(&fixture.vault)
            .get(attempt)
            .expect("read the attempt")
            .expect("the stopped attempt");
        let stored = record
            .cancel_state
            .cancellation
            .expect("the stored cancellation");
        assert_eq!(stored.grounds, Some(ForceCancelGrounds::OwnerDelegate));
        assert_eq!(stored.actor, agent_hex);
    });
}

/// Force cancel with the key off: today's 403, same code and message, with
/// the suggestion naming the key.
#[test]
fn force_cancel_default_off_refused() {
    run_on_engine_stack("w11-cancel-off", || async {
        let fixture = setup();
        let agent = pair_agent(&fixture, "cancel-stranger", [0xA2; 32]).await;
        let task_ref = plant_task_with_live_attempt_for_test(&fixture.vault).expect("plant a TASK");

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{CANCEL_FORCE_VERB}"),
            json!({"task_ref": task_ref.to_hex()}),
        )
        .await;
        assert_owner_refusal(status, &body, CANCEL_FORCE_VERB, FORCE_CANCEL_KEY);
    });
}

/// Program-hold Stop with the agent's row on and its Grant listing the
/// verb: the hold releases, and the stopped try names the agent on
/// `owner_delegate` grounds.
#[test]
fn program_hold_release_stop_agent_row_on_stands() {
    run_on_engine_stack("w11-release-on", || async {
        let fixture = setup();
        let agent = pair_agent(&fixture, "release-delegate", [0xB1; 32]).await;
        let agent_hex = agent.principal.to_hex();
        let (attempt_hex, reason, parked_at) = plant_held_turn_program_for_test(
            &fixture.vault,
            agent.principal,
            EdgeActorClass::Agent,
        )
        .expect("plant a held program");
        let _grant = mint_grant(&fixture, &agent_hex, &[PROGRAM_HOLD_RELEASE_VERB]).await;
        set_row(
            &fixture.vault,
            FORCE_CANCEL_KEY,
            None,
            SettingScope::Agent(agent.principal),
            json!(true),
        );

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{PROGRAM_HOLD_RELEASE_VERB}"),
            json!({
                "attempt": attempt_hex,
                "reason": reason,
                "parked_at": parked_at,
                "action": "stop",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "delegate Stop: {body}");
        assert_eq!(body["effected"].as_bool(), Some(true), "{body}");

        let attempt = AttemptId::from_bytes(
            EntityId::from_hex(&attempt_hex)
                .expect("attempt id")
                .as_bytes(),
        )
        .expect("attempt id");
        let record = AttemptQueue::new(&fixture.vault)
            .get(attempt)
            .expect("read the attempt")
            .expect("the stopped attempt");
        let stored = record
            .cancel_state
            .cancellation
            .expect("the stored cancellation");
        assert_eq!(stored.grounds, Some(ForceCancelGrounds::OwnerDelegate));
        assert_eq!(stored.actor, agent_hex);
    });
}

/// Program-hold release with the key off: today's 403, same code and
/// message, with the suggestion naming the key.
#[test]
fn program_hold_release_default_off_refused() {
    run_on_engine_stack("w11-release-off", || async {
        let fixture = setup();
        let agent = pair_agent(&fixture, "release-stranger", [0xB2; 32]).await;
        let (attempt_hex, reason, parked_at) = plant_held_turn_program_for_test(
            &fixture.vault,
            agent.principal,
            EdgeActorClass::Agent,
        )
        .expect("plant a held program");

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{PROGRAM_HOLD_RELEASE_VERB}"),
            json!({
                "attempt": attempt_hex,
                "reason": reason,
                "parked_at": parked_at,
                "action": "stop",
            }),
        )
        .await;
        assert_owner_refusal(status, &body, PROGRAM_HOLD_RELEASE_VERB, FORCE_CANCEL_KEY);
    });
}

/// Seat quotas with the agent's `quotas` row on and its Grant listing the
/// verb: the seats read.
#[test]
fn seats_quotas_agent_row_on_stands() {
    run_on_engine_stack("w11-quotas-on", || async {
        let fixture = setup();
        let agent = pair_agent(&fixture, "quotas-delegate", [0xC1; 32]).await;
        let agent_hex = agent.principal.to_hex();
        let _grant = mint_grant(&fixture, &agent_hex, &[RUNNER_SEAT_QUOTAS_VERB]).await;
        set_row(
            &fixture.vault,
            RUNNER_SEATS_KEY,
            Some("quotas"),
            SettingScope::Agent(agent.principal),
            json!(true),
        );

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{RUNNER_SEAT_QUOTAS_VERB}"),
            json!({"seats": [seat_json()]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "delegate quotas: {body}");
        assert_eq!(
            body["quotas"][0]["runner"].as_str(),
            Some("claude-code"),
            "{body}"
        );
        assert_eq!(
            body["quotas"][0]["available"].as_bool(),
            Some(true),
            "{body}"
        );
    });
}

/// Seat quotas with the key off: today's 403, same code and message, with
/// the suggestion naming the key.
#[test]
fn seats_quotas_default_off_refused() {
    run_on_engine_stack("w11-quotas-off", || async {
        let fixture = setup();
        let agent = pair_agent(&fixture, "quotas-stranger", [0xC2; 32]).await;

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{RUNNER_SEAT_QUOTAS_VERB}"),
            json!({"seats": [seat_json()]}),
        )
        .await;
        assert_owner_refusal(status, &body, RUNNER_SEAT_QUOTAS_VERB, RUNNER_SEATS_KEY);
    });
}

/// Seat quotas with the row on but no Grant: still refused. The binding,
/// the Grant and the key all stand together.
#[test]
fn seats_quotas_row_on_without_grant_refused() {
    run_on_engine_stack("w11-quotas-no-grant", || async {
        let fixture = setup();
        let agent = pair_agent(&fixture, "quotas-ungranted", [0xC3; 32]).await;
        set_row(
            &fixture.vault,
            RUNNER_SEATS_KEY,
            Some("quotas"),
            SettingScope::Agent(agent.principal),
            json!(true),
        );

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{RUNNER_SEAT_QUOTAS_VERB}"),
            json!({"seats": [seat_json()]}),
        )
        .await;
        assert_owner_refusal(status, &body, RUNNER_SEAT_QUOTAS_VERB, RUNNER_SEATS_KEY);
    });
}

/// Item `quotas` on, item `top_up` off: quotas read, top-up is refused.
/// One item never opens another act.
#[test]
fn seats_item_quotas_on_top_up_off_refuses_top_up() {
    run_on_engine_stack("w11-seats-item", || async {
        let fixture = setup();
        let agent = pair_agent(&fixture, "seats-item", [0xC4; 32]).await;
        let agent_hex = agent.principal.to_hex();
        let _grant = mint_grant(
            &fixture,
            &agent_hex,
            &[RUNNER_SEAT_QUOTAS_VERB, RUNNER_SEAT_TOP_UP_VERB],
        )
        .await;
        set_row(
            &fixture.vault,
            RUNNER_SEATS_KEY,
            Some("quotas"),
            SettingScope::Agent(agent.principal),
            json!(true),
        );

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{RUNNER_SEAT_TOP_UP_VERB}"),
            json!({
                "seat": seat_json(),
                "expected_spent_attempt": EntityId::now().to_hex(),
            }),
        )
        .await;
        assert_owner_refusal(status, &body, RUNNER_SEAT_TOP_UP_VERB, RUNNER_SEATS_KEY);

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{RUNNER_SEAT_QUOTAS_VERB}"),
            json!({"seats": [seat_json()]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "quotas still read: {body}");
    });
}

/// Seat top-up with the agent's `top_up` row on and its Grant listing the
/// verb: the spent credit clears, and the record names the agent beside
/// the vault's owner and the delegate's Grant.
#[test]
fn seats_top_up_agent_row_on_clears() {
    run_on_engine_stack("w11-topup-on", || async {
        let fixture = setup();
        let agent = pair_agent(&fixture, "topup-delegate", [0xC5; 32]).await;
        let agent_hex = agent.principal.to_hex();
        let spent = EntityId::now().to_hex();
        plant_spent_seat_credit_for_test(
            &fixture.vault,
            &seat(),
            *EntityId::from_hex(&spent).expect("spent id").as_bytes(),
        )
        .expect("plant a spent credit");
        let grant = mint_grant(&fixture, &agent_hex, &[RUNNER_SEAT_TOP_UP_VERB]).await;
        set_row(
            &fixture.vault,
            RUNNER_SEATS_KEY,
            Some("top_up"),
            SettingScope::Agent(agent.principal),
            json!(true),
        );

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{RUNNER_SEAT_TOP_UP_VERB}"),
            json!({
                "seat": seat_json(),
                "expected_spent_attempt": spent,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "delegate top-up: {body}");
        assert_eq!(body["effect"].as_str(), Some("cleared"), "{body}");
        assert!(
            body["quota"]["topped_up_at"].is_number(),
            "the quota shows the top-up: {body}"
        );

        let (_owner, decision, _at, delegate) = topped_up_by_for_test(&fixture.vault, &seat())
            .expect("read the top-up")
            .expect("a top-up stands");
        assert_eq!(
            delegate.as_deref(),
            Some(agent_hex.as_str()),
            "the record names the agent"
        );
        assert_eq!(decision, grant, "the record names the delegate's Grant");
    });
}

/// Seat top-up with the key off: today's 403, same code and message, with
/// the suggestion naming the key.
#[test]
fn seats_top_up_default_off_refused() {
    run_on_engine_stack("w11-topup-off", || async {
        let fixture = setup();
        let agent = pair_agent(&fixture, "topup-stranger", [0xC6; 32]).await;

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{RUNNER_SEAT_TOP_UP_VERB}"),
            json!({
                "seat": seat_json(),
                "expected_spent_attempt": EntityId::now().to_hex(),
            }),
        )
        .await;
        assert_owner_refusal(status, &body, RUNNER_SEAT_TOP_UP_VERB, RUNNER_SEATS_KEY);
    });
}

/// Work resume with the agent's `resume` row on and its Grant listing the
/// verb: the door admits the delegate and answers the work as it stands.
#[test]
fn seats_resume_agent_row_on_reaches_gone() {
    run_on_engine_stack("w11-resume-on", || async {
        let fixture = setup();
        let agent = pair_agent(&fixture, "resume-delegate", [0xC7; 32]).await;
        let agent_hex = agent.principal.to_hex();
        let _grant = mint_grant(&fixture, &agent_hex, &[RUNNER_WORK_RESUME_VERB]).await;
        set_row(
            &fixture.vault,
            RUNNER_SEATS_KEY,
            Some("resume"),
            SettingScope::Agent(agent.principal),
            json!(true),
        );

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{RUNNER_WORK_RESUME_VERB}"),
            json!({
                "binding": EntityId::now().to_hex(),
                "expected_attempt": EntityId::now().to_hex(),
                "policy": policy_json(),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "delegate resume admitted: {body}");
        assert_eq!(
            body.as_str(),
            Some("gone"),
            "nothing holds the work: {body}"
        );
    });
}

/// Work resume with the key off: today's 403, same code and message, with
/// the suggestion naming the key.
#[test]
fn seats_resume_default_off_refused() {
    run_on_engine_stack("w11-resume-off", || async {
        let fixture = setup();
        let agent = pair_agent(&fixture, "resume-stranger", [0xC8; 32]).await;

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{RUNNER_WORK_RESUME_VERB}"),
            json!({
                "binding": EntityId::now().to_hex(),
                "expected_attempt": EntityId::now().to_hex(),
                "policy": policy_json(),
            }),
        )
        .await;
        assert_owner_refusal(status, &body, RUNNER_WORK_RESUME_VERB, RUNNER_SEATS_KEY);
    });
}

/// Repo registration with the agent's row on and its Grant listing the
/// verb: the local folder registers in a PROJECT the agent reads.
#[test]
fn anchor_bind_local_folder_agent_row_on_stands() {
    run_on_engine_stack("w11-anchor-on", || async {
        let fixture = setup();
        let agent = pair_agent(&fixture, "anchor-delegate", [0xD1; 32]).await;
        let agent_hex = agent.principal.to_hex();
        let project = fixture.vault.root_project().expect("root project");
        let (_repo_dir, folder) = git_repo();
        let _grant = mint_grant(&fixture, &agent_hex, &[REPO_ANCHOR_BIND_VERB]).await;
        set_row(
            &fixture.vault,
            REGISTRATION_KEY,
            None,
            SettingScope::Agent(agent.principal),
            json!(true),
        );

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{REPO_ANCHOR_BIND_VERB}"),
            json!({
                "local_folder": folder,
                "project": project.to_hex(),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "delegate registration: {body}");
        assert_eq!(body["changed"].as_bool(), Some(true), "{body}");
        assert_eq!(
            body["anchor"]["project"].as_str(),
            Some(project.to_hex()).as_deref(),
            "{body}"
        );
    });
}

/// Repo registration with the key off: today's 403, same code and message,
/// with the suggestion naming the key.
#[test]
fn anchor_bind_default_off_refused() {
    run_on_engine_stack("w11-anchor-off", || async {
        let fixture = setup();
        let agent = pair_agent(&fixture, "anchor-stranger", [0xD2; 32]).await;
        let project = fixture.vault.root_project().expect("root project");
        let (_repo_dir, folder) = git_repo();

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{REPO_ANCHOR_BIND_VERB}"),
            json!({
                "local_folder": folder,
                "project": project.to_hex(),
            }),
        )
        .await;
        assert_owner_refusal(status, &body, REPO_ANCHOR_BIND_VERB, REGISTRATION_KEY);
    });
}

/// A served repo never admits the delegate, even with the row on and the
/// Grant listing the verb: the owner's refusal, naming the local folder.
#[test]
fn anchor_bind_served_repo_never_admits_delegate() {
    run_on_engine_stack("w11-anchor-served", || async {
        let fixture = setup();
        let agent = pair_agent(&fixture, "anchor-served", [0xD3; 32]).await;
        let agent_hex = agent.principal.to_hex();
        let project = fixture.vault.root_project().expect("root project");
        let _grant = mint_grant(&fixture, &agent_hex, &[REPO_ANCHOR_BIND_VERB]).await;
        set_row(
            &fixture.vault,
            REGISTRATION_KEY,
            None,
            SettingScope::Agent(agent.principal),
            json!(true),
        );

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{REPO_ANCHOR_BIND_VERB}"),
            json!({
                "repo": "served-name",
                "project": project.to_hex(),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "served arm refused: {body}");
        assert_eq!(body["error"]["code"].as_str(), Some("FORBIDDEN"), "{body}");
        assert_eq!(
            body["error"]["message"].as_str(),
            Some(format!("{REPO_ANCHOR_BIND_VERB} is the vault owner's")).as_deref(),
            "{body}"
        );
        let suggestions = body["error"]["suggestions"]
            .as_array()
            .expect("refusal suggestions");
        assert!(
            suggestions.iter().any(|suggestion| suggestion
                .as_str()
                .is_some_and(|text| text.contains("local_folder"))),
            "the refusal names the local folder: {body}"
        );
        assert!(
            suggestions.iter().all(|suggestion| suggestion
                .as_str()
                .is_none_or(|text| !text.contains(REGISTRATION_KEY))),
            "no setting opens this arm: {body}"
        );
    });
}

/// Compliance install with the agent's row on and its Grant listing the
/// verb: the loosening installs pending, and the receipt names the agent.
#[test]
fn compliance_install_agent_row_on_stands() {
    run_on_engine_stack("w11-install-on", || async {
        let fixture = setup();
        let agent = pair_agent(&fixture, "install-delegate", [0xE1; 32]).await;
        let agent_hex = agent.principal.to_hex();
        let (prior, pack) = loosen_pack();
        let _grant = mint_grant(&fixture, &agent_hex, &[COMPLIANCE_INSTALL_VERB]).await;
        set_row(
            &fixture.vault,
            COMPLIANCE_KEY,
            None,
            SettingScope::Agent(agent.principal),
            json!(true),
        );

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{COMPLIANCE_INSTALL_VERB}"),
            json!({"prior_version": prior, "pack": pack}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "delegate install: {body}");
        assert_eq!(body["operation"].as_str(), Some("install"), "{body}");
        assert_eq!(
            body["disposition"].as_str(),
            Some("pending_owner_stamp"),
            "{body}"
        );
        assert_eq!(
            body["actor_ref"].as_str(),
            Some(agent_hex.as_str()),
            "{body}"
        );
        assert_eq!(
            body["proposal_hash"].as_str().map(str::len),
            Some(64),
            "{body}"
        );
    });
}

/// Compliance install with the key off: today's 403, same code and message,
/// with the suggestion naming the key.
#[test]
fn compliance_install_default_off_refused() {
    run_on_engine_stack("w11-install-off", || async {
        let fixture = setup();
        let agent = pair_agent(&fixture, "install-stranger", [0xE2; 32]).await;
        let (prior, pack) = loosen_pack();

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{COMPLIANCE_INSTALL_VERB}"),
            json!({"prior_version": prior, "pack": pack}),
        )
        .await;
        assert_owner_refusal(status, &body, COMPLIANCE_INSTALL_VERB, COMPLIANCE_KEY);
    });
}

/// Compliance reject with the agent's row on and its Grant listing the
/// verb: the pending proposal rejects, and the receipt names the agent.
#[test]
fn compliance_reject_agent_row_on_stands() {
    run_on_engine_stack("w11-reject-on", || async {
        let fixture = setup();
        let agent = pair_agent(&fixture, "reject-delegate", [0xE3; 32]).await;
        let agent_hex = agent.principal.to_hex();
        let (prior, pack) = loosen_pack();
        let _grant = mint_grant(
            &fixture,
            &agent_hex,
            &[COMPLIANCE_INSTALL_VERB, COMPLIANCE_REJECT_VERB],
        )
        .await;
        set_row(
            &fixture.vault,
            COMPLIANCE_KEY,
            None,
            SettingScope::Agent(agent.principal),
            json!(true),
        );

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{COMPLIANCE_INSTALL_VERB}"),
            json!({"prior_version": prior, "pack": pack}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "delegate install: {body}");
        let proposal = body["proposal_hash"]
            .as_str()
            .expect("proposal hash")
            .to_owned();

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{COMPLIANCE_REJECT_VERB}"),
            json!({"prior_version": prior, "proposal_hash": proposal}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "delegate reject: {body}");
        assert_eq!(body["operation"].as_str(), Some("reject"), "{body}");
        assert_eq!(body["disposition"].as_str(), Some("rejected"), "{body}");
        assert_eq!(
            body["actor_ref"].as_str(),
            Some(agent_hex.as_str()),
            "{body}"
        );
    });
}

/// Compliance reject with the key off: today's 403, same code and message,
/// with the suggestion naming the key.
#[test]
fn compliance_reject_default_off_refused() {
    run_on_engine_stack("w11-reject-off", || async {
        let fixture = setup();
        let agent = pair_agent(&fixture, "reject-stranger", [0xE4; 32]).await;
        let (prior, pack) = loosen_pack();
        let _grant = mint_grant(
            &fixture,
            agent.principal.to_hex().as_str(),
            &[COMPLIANCE_INSTALL_VERB, COMPLIANCE_REJECT_VERB],
        )
        .await;
        set_row(
            &fixture.vault,
            COMPLIANCE_KEY,
            None,
            SettingScope::Agent(agent.principal),
            json!(true),
        );

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{COMPLIANCE_INSTALL_VERB}"),
            json!({"prior_version": prior, "pack": pack}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "delegate install: {body}");
        let proposal = body["proposal_hash"]
            .as_str()
            .expect("proposal hash")
            .to_owned();

        set_row(
            &fixture.vault,
            COMPLIANCE_KEY,
            None,
            SettingScope::Agent(agent.principal),
            json!(false),
        );
        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{COMPLIANCE_REJECT_VERB}"),
            json!({"prior_version": prior, "proposal_hash": proposal}),
        )
        .await;
        assert_owner_refusal(status, &body, COMPLIANCE_REJECT_VERB, COMPLIANCE_KEY);
    });
}

/// Compliance approve stays the owner's stamp: with the row on and a Grant
/// listing install and reject, the agent's approve is still refused, with
/// no suggestion naming the key.
#[test]
fn compliance_approve_stays_owner_with_key_on() {
    run_on_engine_stack("w11-approve-owner", || async {
        let fixture = setup();
        let agent = pair_agent(&fixture, "approve-delegate", [0xE5; 32]).await;
        let agent_hex = agent.principal.to_hex();
        let (prior, pack) = loosen_pack();
        let _grant = mint_grant(
            &fixture,
            &agent_hex,
            &[COMPLIANCE_INSTALL_VERB, COMPLIANCE_REJECT_VERB],
        )
        .await;
        set_row(
            &fixture.vault,
            COMPLIANCE_KEY,
            None,
            SettingScope::Agent(agent.principal),
            json!(true),
        );

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{COMPLIANCE_INSTALL_VERB}"),
            json!({"prior_version": prior, "pack": pack}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "delegate install: {body}");
        let proposal = body["proposal_hash"]
            .as_str()
            .expect("proposal hash")
            .to_owned();

        let (status, body) = agent_post(
            &fixture,
            &agent,
            &format!("/v1/core/facade/{COMPLIANCE_APPROVE_VERB}"),
            json!({"prior_version": prior, "proposal_hash": proposal}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "approve refused: {body}");
        assert_eq!(body["error"]["code"].as_str(), Some("FORBIDDEN"), "{body}");
        assert_eq!(
            body["error"]["message"].as_str(),
            Some(format!("{COMPLIANCE_APPROVE_VERB} is the vault owner's")).as_deref(),
            "{body}"
        );
        let suggestions = body["error"]["suggestions"]
            .as_array()
            .expect("refusal suggestions");
        assert!(
            suggestions.iter().all(|suggestion| suggestion
                .as_str()
                .is_none_or(|text| !text.contains(COMPLIANCE_KEY))),
            "no setting opens approve: {body}"
        );
    });
}

/// Agent A's row on, agent B's off: B is refused; the Vault row on opens
/// every agent, so B reads.
#[test]
fn agent_b_off_refused_vault_row_on_allowed() {
    run_on_engine_stack("w11-vault-row", || async {
        let fixture = setup();
        let agent_a = pair_agent(&fixture, "quotas-a", [0xF1; 32]).await;
        let agent_b = pair_agent(&fixture, "quotas-b", [0xF2; 32]).await;
        let _grant_a = mint_grant(
            &fixture,
            agent_a.principal.to_hex().as_str(),
            &[RUNNER_SEAT_QUOTAS_VERB],
        )
        .await;
        let _grant_b = mint_grant(
            &fixture,
            agent_b.principal.to_hex().as_str(),
            &[RUNNER_SEAT_QUOTAS_VERB],
        )
        .await;
        set_row(
            &fixture.vault,
            RUNNER_SEATS_KEY,
            Some("quotas"),
            SettingScope::Agent(agent_a.principal),
            json!(true),
        );

        let (status, body) = agent_post(
            &fixture,
            &agent_b,
            &format!("/v1/core/facade/{RUNNER_SEAT_QUOTAS_VERB}"),
            json!({"seats": [seat_json()]}),
        )
        .await;
        assert_owner_refusal(status, &body, RUNNER_SEAT_QUOTAS_VERB, RUNNER_SEATS_KEY);

        set_row(
            &fixture.vault,
            RUNNER_SEATS_KEY,
            Some("quotas"),
            SettingScope::Vault,
            json!(true),
        );
        let (status, body) = agent_post(
            &fixture,
            &agent_b,
            &format!("/v1/core/facade/{RUNNER_SEAT_QUOTAS_VERB}"),
            json!({"seats": [seat_json()]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the Vault row opens B: {body}");
    });
}
