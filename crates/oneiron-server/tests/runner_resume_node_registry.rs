//! The owner's served resume of parked runner work keeps the node's registry
//! (FIX [RUNNER-RESUME-DROPS-NODE-REGISTRY]): entered as the SDK enters it, HTTP
//! `POST /v1/core/facade/vault.runners.seats.resume` through the in-process router
//! (`oneshot`, no TCP ports, no sleeps), on a node whose `[models.dreamer]`
//! `runner_seats` register one official Codex ChatGPT-plan seat with a `machine_ref`.
//!
//! The promise: a work bound on an official seat and parked on a spend resumes
//! under that same seat. The successor attempt carries the seat's stamp — the
//! ChatGPT-plan Codex route with the login machine's digest — so only the
//! login's machine lists and claims it. Resuming under the bare CLI registry
//! instead drops the stamp (`official_seat` None) and any host may claim the
//! successor, running another machine's login's work.
//!
//! Canon `oneiron-docs/generated/llms-full.txt:374869`: "A login seat is one
//! person's signed-in vendor CLI ... A login seat is a row: vendor, account,
//! machine, login store path, plan window." Canon
//! `oneiron-docs/generated/llms-full.txt:40812`: "a ChatGPT-plan login for the
//! Codex app-server stays on the person's own machine or self-hosted runtime ...
//! until OpenAI approves (OC2)" (also SWC-003,
//! `oneiron-docs/generated/llms-full.txt:41032`).
//!
//! Red on main: the door rebuilds `ProviderAdapterRegistry::standard()`, so the
//! resume dispatches the successor under the plain `CodexRunner` with
//! `official_seat` None, and the first test fails at "the successor carries
//! the official seat" (an unrelated machine would list and take it too).
//! Green on the head: the door resumes under this node's registry, the stamp
//! rides the successor, and only the login's machine claims it. The control
//! (no `runner_seats` on the node) is green on both: a plain run carries no
//! stamp and any machine lists it.
//!
//! Each test owns a fresh vault. Seeding is public engine API only
//! (`bind_runner_work_in_txn` + queue claim + `route_runner_terminal` with an
//! explicit `SeatSpent`); observation is `AttemptQueue::get` +
//! `decode_byoa_attempt_payload` + the host claim doors. No model, runner,
//! live run, or test door is used; every type named is public from outside the
//! crate.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test runner_resume_node_registry`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use engine_stack::run_on_engine_stack;
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::checkout::CheckoutId;
use oneiron::dispatch_byoa::{
    BYOA_ATTEMPT_KIND, BindRunnerWork, ByoEndpointBackendFactory, ByoEndpointBinding,
    ByoEndpointSpec, ByoaDispatcher, ByoaEgressLease, ByoaEgressPort, ByoaError, ByoaExhaust,
    ByoaResult, ByoaStream, ByoaTerminalDisposition, CaptureByoaExhaust, OfficialSeatRoute,
    OfficialSeatStamp, OnSeatSpent, ProviderAdapterRegistry, RunnerSeat, RunnerSeatChoice,
    RunnerSeatPolicy, RunnerWorkBound, SeatAuth, SeatRoute, SeatSpent, decode_byoa_attempt_payload,
};
use oneiron::llm::SpentKind;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::runtime::seat_login::RunnerSeatPolicySettings;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const RESUME_PATH: &str = "/v1/core/facade/vault.runners.seats.resume";

/// The machine holding the login, as the node config names it.
const MACHINE: &str = "owner-machine";
/// A machine that must never take the login's work.
const OTHER_MACHINE: &str = "someone-else";
/// The seat's egress label (a label only; seeding leases nothing).
const EGRESS: &str = "egress/test-default";

/// The node's `[models]` body: one `codex` seat plus the ONE official seat it
/// names — a Codex ChatGPT-plan login on the owner's machine, OpenAI's
/// hosted-plan approval recorded so the seat stamps its runs.
const NODE_MODELS_TOML: &str = r#"
[dreamer]
enabled = false

[dreamer.runner_seats]
on_spent = "stop"

[[dreamer.runner_seats.seats]]
runner = "codex"
auth = "vendor_login"
egress_profile_ref = "egress/test-default"

[[dreamer.runner_seats.official]]
route = "codex_app_server_chatgpt_plan"
account_ref = "owner-codex"
machine_ref = "owner-machine"
openai_hosted_plan_approved = true
"#;

/// The endpoint seam the seeding path never reaches: every seeded seat is a
/// CLI runner, whose dispatch resolves no backend.
struct StubEndpoints;

impl ByoEndpointBackendFactory for StubEndpoints {
    fn resolve_backend(&self, _spec: &ByoEndpointSpec) -> ByoaResult<ByoEndpointBinding> {
        Err(ByoaError::Backend(
            "runner door tests run CLI seats only".to_owned(),
        ))
    }
}

/// The default-deny egress port: seeding mints rows, and no traffic moves.
struct DenyEgress;

impl ByoaEgressPort for DenyEgress {
    fn open(&mut self, profile_ref: &str, _intent_ref: &str) -> ByoaResult<ByoaEgressLease> {
        Err(ByoaError::EgressDenied {
            profile_ref: profile_ref.to_owned(),
            reason: "runner door tests lease no egress".to_owned(),
        })
    }
}

struct Fixture {
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    _host: Option<AiHost>,
    _dir: tempfile::TempDir,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

/// The served app over a fresh vault: with `models_toml` the AI host attaches
/// under that node config (so the fixed door resumes under its registry),
/// without it the server stays bare (no `runner_seats`, the control).
async fn setup(models_toml: Option<&str>) -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("runner-resume-node-registry".into()),
            ..Default::default()
        },
    )
    .expect("create server");
    let (server, host) = match models_toml {
        Some(text) => {
            let models = ModelsConfig::from_toml(text, None).expect("node models");
            let (server, host) = AiHost::attach(server, Some(&models)).await;
            (server, Some(host))
        }
        None => (server, None),
    };
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let app = build_app(Arc::new(server));
    Fixture {
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
        _host: host,
        _dir: dir,
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

/// A vendor-login seat on the registry's runner.
fn login_seat(runner: &str) -> RunnerSeat {
    RunnerSeat {
        runner: runner.to_owned(),
        auth: SeatAuth::VendorLogin,
        egress_profile_ref: EGRESS.to_owned(),
        credential_handles: Vec::new(),
    }
}

fn seat_json(runner: &str) -> Value {
    json!({
        "runner": runner,
        "auth": "vendor_login",
        "egress_profile_ref": EGRESS,
    })
}

/// A non-empty terminal exhaust: an entirely empty one is refused at capture.
fn seed_exhaust() -> ByoaExhaust {
    let mut writer = ByoaStream::writer(None, None);
    writer
        .append(b"runner resume registry test output")
        .expect("exhaust bytes");
    let stdout = writer.finish().expect("exhaust stream");
    ByoaExhaust {
        stdout,
        ..Default::default()
    }
}

/// Claims the oldest queued BYOA attempt: each seed dispatches exactly one
/// before it claims, so the claim takes that attempt.
fn claim_runner_attempt(vault: &Vault, now: u64) -> AttemptRecord {
    let outcome = AttemptQueue::new(vault)
        .claim_kind(
            BYOA_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "runner-resume-test".to_owned(),
                now,
            },
        )
        .expect("the queued runner attempt claims");
    match outcome {
        ClaimOutcome::Claimed(record) => record,
        _ => panic!("a runner attempt is queued to claim"),
    }
}

/// Binds a fresh work on `seat` and parks it on the explicit spend. Answers
/// the binding hex and the spent attempt hex.
fn bind_parked_work(
    vault: &Vault,
    registry: &ProviderAdapterRegistry,
    policy: &RunnerSeatPolicy,
    seat: usize,
    step_key: &str,
    spent: SeatSpent,
    now: u64,
) -> (String, String) {
    let dispatcher = ByoaDispatcher::new(vault, StubEndpoints, DenyEgress);
    let checkout = CheckoutId::from_bytes([7_u8; 16]).expect("checkout id");
    let bound = vault
        .try_with_write_txn_grouped(|wtxn| {
            dispatcher.bind_runner_work_in_txn(
                wtxn,
                registry,
                policy,
                BindRunnerWork {
                    parent_attempt_id: AttemptId::now(),
                    step_key: step_key.to_owned(),
                    task: "runner resume registry test task".to_owned(),
                    staged_input: None,
                    checkout_id: checkout,
                    task_ref: None,
                    run_id: None,
                    choice: RunnerSeatChoice::Seat(seat),
                    now,
                },
            )
        })
        .expect("the bind lands");
    let (binding, attempt) = match bound {
        RunnerWorkBound::Bound {
            binding,
            attempt,
            existing,
            ..
        } => {
            assert!(!existing, "a fresh step binds new");
            (binding, attempt)
        }
        _ => panic!("a fresh step binds on its seat"),
    };
    let claimed = claim_runner_attempt(vault, now);
    assert_eq!(claimed.id, attempt, "the claim takes the bound attempt");
    let mut router = ByoaDispatcher::new(vault, StubEndpoints, DenyEgress);
    let capture = CaptureByoaExhaust {
        attempt_id: attempt,
        lease_owner: "runner-resume-test".to_owned(),
        attempt_count: claimed.attempt_count,
        disposition: ByoaTerminalDisposition::Completed,
        exhaust: seed_exhaust(),
        reason: None,
        now,
    };
    let route = router
        .route_runner_terminal(registry, policy, seat, capture, Some(spent))
        .expect("the spent route lands");
    match route {
        SeatRoute::Park { .. } => {}
        _ => panic!("a Stop policy parks the spent work"),
    }
    (binding.to_hex(), hex(attempt.as_bytes()))
}

/// The successor attempt id behind a resume answer's hex.
fn attempt_id_of(hex_text: &str) -> AttemptId {
    let entity = EntityId::from_hex(hex_text).expect("successor hex");
    AttemptId::from_bytes(entity.as_bytes()).expect("successor id")
}

/// The official seat stamp a successor attempt row carries, if any.
fn official_seat_of(vault: &Vault, id: AttemptId) -> Option<OfficialSeatStamp> {
    let record = AttemptQueue::new(vault)
        .get(id)
        .expect("the successor reads")
        .expect("a successor row");
    let payload = decode_byoa_attempt_payload(&record.payload).expect("a BYOA payload");
    payload.official_seat
}

/// The served resume keeps the official seat on the login's machine: a work
/// bound on the node's official Codex seat, parked on a spend, resumes over
/// the door onto that same seat; the successor carries the ChatGPT-plan stamp
/// with the login machine's digest, so another machine neither lists nor
/// claims it while the login's machine does.
///
/// Red on main at "the successor carries the official seat": the door resumes
/// under the bare CLI registry, the successor rides the plain `CodexRunner`
/// with `official_seat` None, and any machine may claim it.
#[test]
fn resume_keeps_the_official_seat_on_the_login_machine() {
    run_on_engine_stack("runner-resume-node-registry", || async {
        let fixture = setup(Some(NODE_MODELS_TOML)).await;
        // The same settings object the node attached: the node's registry is
        // what the fixed door resumes under.
        let models = ModelsConfig::from_toml(NODE_MODELS_TOML, None).expect("node models");
        let settings: RunnerSeatPolicySettings =
            models.dreamer.runner_seats.clone().expect("runner seats");
        let registry = settings.registry().expect("the node registry builds");
        let policy = settings.policy().expect("the node policy folds");
        let now = now_secs();
        let spent = SeatSpent {
            kind: Some(SpentKind::Window),
            retry_after: Some(1800),
            resets_at: Vec::new(),
        };
        let (binding_hex, spent_hex) = bind_parked_work(
            &fixture.vault,
            &registry,
            &policy,
            0,
            "resume-official-seat",
            spent,
            now,
        );

        let (status, resumed) = post_as_owner(
            &fixture,
            RESUME_PATH,
            json!({
                "binding": binding_hex,
                "expected_attempt": spent_hex,
                "policy": {"seats": [seat_json("codex")]},
                "choice": {"seat": 0},
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner resumes the parked work: {resumed}"
        );
        assert_eq!(
            resumed["resumed"]["seat"].as_u64(),
            Some(0),
            "the work resumes on its official seat: {resumed}"
        );
        let successor_hex = resumed["resumed"]["attempt"]
            .as_str()
            .expect("successor attempt")
            .to_owned();
        assert_eq!(
            successor_hex.len(),
            32,
            "the successor is a fresh attempt id: {resumed}"
        );
        assert_eq!(
            resumed["resumed"]["existing"].as_bool(),
            Some(false),
            "the successor is newly dispatched: {resumed}"
        );

        // The successor carries the official seat, bound to the login machine.
        let successor = attempt_id_of(&successor_hex);
        let stamp = official_seat_of(&fixture.vault, successor)
            .expect("the successor carries the official seat");
        assert_eq!(
            stamp.route,
            OfficialSeatRoute::CodexAppServerChatGptPlan,
            "the successor rides the ChatGPT-plan Codex seat"
        );
        assert!(
            stamp.machine_digest.is_some(),
            "the seat names the login machine"
        );
        let login = vec![MACHINE.to_owned()];
        let other = vec![OTHER_MACHINE.to_owned()];
        assert!(stamp.runs_on(&login), "the seat runs on the login machine");
        assert!(!stamp.runs_on(&other), "the seat runs nowhere else");

        // Only the login's machine lists and claims the successor.
        let vault: &Vault = &fixture.vault;
        let dispatcher = ByoaDispatcher::new(vault, StubEndpoints, DenyEgress);
        let now = now_secs();
        let listed_login = dispatcher
            .ready_host_cli_attempts(now, &login, |_| true)
            .expect("the login machine lists");
        let listed_other = dispatcher
            .ready_host_cli_attempts(now, &other, |_| true)
            .expect("another machine lists");
        assert!(
            listed_login.contains(&successor),
            "the login machine lists the successor"
        );
        assert!(
            !listed_other.contains(&successor),
            "another machine does not list the successor"
        );
        let no_take = dispatcher
            .claim_host_cli_attempt(successor, "runner-resume-test", now, &other, |_| true)
            .expect("another machine claims");
        assert!(
            no_take.is_none(),
            "another machine does not take the successor"
        );
        let fence = dispatcher
            .claim_host_cli_attempt(successor, "runner-resume-test", now, &login, |_| true)
            .expect("the login machine claims")
            .expect("the login machine takes the successor");
        assert_eq!(
            fence.attempt_id, successor,
            "the fence guards the successor"
        );
    });
}

/// Control: on a node without `runner_seats`, a login-seat work resumes as
/// today — the successor queues on the next plain runner and carries no
/// official seat, so any machine lists it. Green on main and on the head.
#[test]
fn resume_on_a_node_without_runner_seats_keeps_the_plain_runners() {
    run_on_engine_stack("runner-resume-plain-control", || async {
        let fixture = setup(None).await;
        let registry = ProviderAdapterRegistry::standard();
        let policy = RunnerSeatPolicy {
            seats: vec![login_seat("claude-code"), login_seat("codex")],
            on_spent: OnSeatSpent::Stop,
        };
        let now = now_secs();
        let spent = SeatSpent {
            kind: Some(SpentKind::Window),
            retry_after: Some(1800),
            resets_at: Vec::new(),
        };
        let (binding_hex, spent_hex) = bind_parked_work(
            &fixture.vault,
            &registry,
            &policy,
            0,
            "resume-plain-control",
            spent,
            now,
        );

        let (status, resumed) = post_as_owner(
            &fixture,
            RESUME_PATH,
            json!({
                "binding": binding_hex,
                "expected_attempt": spent_hex,
                "policy": {"seats": [seat_json("claude-code"), seat_json("codex")]},
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner resumes the parked work: {resumed}"
        );
        assert_eq!(
            resumed["resumed"]["seat"].as_u64(),
            Some(1),
            "the work moves to the next seat: {resumed}"
        );
        let successor_hex = resumed["resumed"]["attempt"]
            .as_str()
            .expect("successor attempt")
            .to_owned();

        // A plain run carries no official seat, so any machine lists it.
        let successor = attempt_id_of(&successor_hex);
        assert!(
            official_seat_of(&fixture.vault, successor).is_none(),
            "a plain successor carries no official seat"
        );
        let vault: &Vault = &fixture.vault;
        let dispatcher = ByoaDispatcher::new(vault, StubEndpoints, DenyEgress);
        let listed = dispatcher
            .ready_host_cli_attempts(now_secs(), &[OTHER_MACHINE.to_owned()], |_| true)
            .expect("another machine lists");
        assert!(
            listed.contains(&successor),
            "any machine lists a plain successor"
        );
    });
}
