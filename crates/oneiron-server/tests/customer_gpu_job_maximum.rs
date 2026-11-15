//! Customer GPU jobs on the host (row L10-31; CROSS-ARCH-0023 lifecycle,
//! C2): the `[gpu_jobs]` section, the `vault.gpu.jobs.*` verbs over the real
//! facade routes, and the GPU job worker's step, on a scripted fake backend.
//!
//! - A job is quoted, started by the owner, told to checkpoint at 50, 80 and
//!   95 percent, warned at 95, stopped at its maximum after a checkpoint taken
//!   after the warning, settled at its quote, and resumed once from that
//!   checkpoint.
//! - Starting and cancelling are the owner's acts; an agent whose Grant names
//!   the verbs may quote and read status, and is refused start and cancel.
//! - An offer whose backend is not registered refuses its start before any
//!   reservation.
//! - `serve` refuses a section with a price shape other than our list, a zero
//!   price, or an unknown key.
//!
//! The owner acts on its host-root credential on a profiled install; the
//! agent is paired over the real pairing route (as
//! `model_binding_proposer_grant.rs` does). The worker's pass runs through
//! the `gpu_backend` test door, so no test waits on `step_secs`.
//! Deterministic: in-process vault and router (`oneshot`), no TCP ports, no
//! sleeps.
//!
//! Red: at #8059's head plus this file alone, the target does not build (no
//! `test_doors::gpu_backend`, no `gpu_jobs` config).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --features oneiron/test-support
//! --test customer_gpu_job_maximum`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

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
use oneiron::gpu_job::{
    GpuConnectorError, GpuJobConnector, GpuJobSignal, GpuJobSpec, GpuResourceRef,
    GpuResourceStatus, GpuTermination,
};
use oneiron::llm::run_admission::CheckpointRef;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::test_doors::gpu_backend::{
    gpu_jobs_section, grant_gpu_allocation, register_gpu_backend, step_gpu_jobs,
};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The `[gpu_jobs]` section: one offer on the fake backend at 2 credit-micros
/// a second, with 20 seconds of startup, teardown and rounding.
const SECTION: &str = r#"
default_maximum_secs = 3600
step_secs = 30

[offers.h100-test]
class = "h100"
provider = "example-cloud"
region = "test-region"
backend = "fake"
price_per_second = 2
cost_unit = "credit-micros"
catalog_revision = "gpu-prices-1"
startup_secs = 10
teardown_secs = 5
rounding_secs = 5
"#;

/// A second offer whose backend no registration names.
const UNBACKED_OFFER: &str = r#"
[offers.a100-test]
class = "a100"
provider = "example-cloud"
region = "test-region"
backend = "missing"
price_per_second = 1
cost_unit = "credit-micros"
catalog_revision = "gpu-prices-1"
startup_secs = 10
teardown_secs = 5
rounding_secs = 5
"#;

const IMAGE: &str = "registry.example.com/trainer@sha256:00";

/// What the fake provider answers, and every call it took.
#[derive(Default)]
struct FakeState {
    calls: Vec<String>,
    created: HashMap<String, GpuResourceRef>,
    signals: Vec<GpuJobSignal>,
    status: Option<GpuResourceStatus>,
    termination: Option<GpuTermination>,
}

/// A GPU backend whose answers the test scripts.
#[derive(Default)]
struct FakeGpu(Mutex<FakeState>);

impl FakeGpu {
    fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.0.lock().expect("fake GPU state")
    }

    fn called(&self, name: &str) -> usize {
        self.state()
            .calls
            .iter()
            .filter(|call| call.starts_with(name))
            .count()
    }

    fn report(&self, used_secs: u64, checkpoint: Option<&str>) {
        self.state().status = Some(GpuResourceStatus::Running {
            used_secs,
            checkpoint: checkpoint.map(|name| CheckpointRef(name.to_owned())),
        });
    }
}

impl GpuJobConnector for FakeGpu {
    fn create(&self, key: &str, _spec: &GpuJobSpec) -> Result<GpuResourceRef, GpuConnectorError> {
        let mut state = self.state();
        state.calls.push(format!("create {key}"));
        let resource = GpuResourceRef(format!("resource-{key}"));
        state.created.insert(key.to_owned(), resource.clone());
        Ok(resource)
    }

    fn find(&self, key: &str) -> Result<Option<GpuResourceRef>, GpuConnectorError> {
        let mut state = self.state();
        state.calls.push(format!("find {key}"));
        Ok(state.created.get(key).cloned())
    }

    fn status(&self, resource: &GpuResourceRef) -> Result<GpuResourceStatus, GpuConnectorError> {
        let mut state = self.state();
        state.calls.push(format!("status {}", resource.0));
        Ok(state.status.clone().unwrap_or(GpuResourceStatus::Pending))
    }

    fn signal(
        &self,
        resource: &GpuResourceRef,
        signal: GpuJobSignal,
    ) -> Result<(), GpuConnectorError> {
        let mut state = self.state();
        state.calls.push(format!("signal {}", resource.0));
        state.signals.push(signal);
        Ok(())
    }

    fn terminate(&self, resource: &GpuResourceRef) -> Result<GpuTermination, GpuConnectorError> {
        let mut state = self.state();
        state.calls.push(format!("terminate {}", resource.0));
        Ok(state.termination.unwrap_or(GpuTermination::Pending))
    }
}

/// One paired agent credential.
struct Agent {
    principal: EntityId,
    holder: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    server: Arc<SyncServer>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    gpu: Arc<FakeGpu>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A served vault with `section` as its `[gpu_jobs]`, the fake registered as
/// backend `fake`, and a paid allocation on its host account.
fn setup(section: &str) -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("customer-gpu-job-maximum".into()),
                gpu_jobs: gpu_jobs_section(section).expect("the [gpu_jobs] section"),
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
    // The owner's acts are carried by this install's live machine profile.
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let gpu = Arc::new(FakeGpu::default());
    register_gpu_backend(
        &server,
        "fake",
        Arc::clone(&gpu) as Arc<dyn GpuJobConnector>,
    );
    grant_gpu_allocation(&server, 1_000_000, "credit-micros").expect("a paid allocation");
    let app = build_app(Arc::clone(&server));
    Fixture {
        _dir: dir,
        vault,
        server,
        app,
        issuer,
        owner_slip,
        owner_token,
        gpu,
    }
}

/// Pairs one agent as `token agent` does, over the real pairing route.
async fn pair_agent(fixture: &Fixture, name: &str, seed: [u8; 32]) -> Agent {
    let principal = fixture
        .vault
        .ensure_agent_principal(name)
        .expect("agent principal");
    let holder = SigningKey::from_bytes(&seed);
    let binding_key = holder.verifying_key().to_bytes();
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:write".to_owned(),
    ]));
    let link = fixture
        .vault
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
    verb: &str,
    token: &str,
    binding: String,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::post(format!("/v1/core/facade/{verb}"))
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

/// `verb` as the owner, on its own proof.
async fn as_owner(fixture: &Fixture, verb: &str, body: Value) -> (StatusCode, Value) {
    let binding = owner_binding(fixture);
    post(fixture, verb, &fixture.owner_token, binding, body).await
}

/// `verb` as `agent`, on its own credential.
async fn as_agent(
    fixture: &Fixture,
    agent: &Agent,
    verb: &str,
    body: Value,
) -> (StatusCode, Value) {
    let binding = agent_binding(fixture, agent);
    post(fixture, verb, &agent.token, binding, body).await
}

fn quote_input(offer: &str, maximum_secs: u64, resume_job: Option<&str>) -> Value {
    json!({
        "offer": offer,
        "job_type": "fine-tune",
        "image": IMAGE,
        "maximum_secs": maximum_secs,
        "inputs": {"dataset": "owen-notes"},
        "resume_job": resume_job,
    })
}

/// The owner's quote, asserted answered.
async fn owner_quote(fixture: &Fixture, offer: &str, resume_job: Option<&str>) -> Value {
    let (status, quote) = as_owner(
        fixture,
        "vault.gpu.jobs.quote",
        quote_input(offer, 100, resume_job),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner quote: {quote}");
    quote
}

async fn owner_status(fixture: &Fixture, job: &str) -> Value {
    let (status, body) = as_owner(fixture, "vault.gpu.jobs.status", json!({"job": job})).await;
    assert_eq!(status, StatusCode::OK, "owner status: {body}");
    body
}

/// The provider reports `used_secs` (and a checkpoint), then the worker
/// steps once; answers the job's status after it.
async fn step_at(fixture: &Fixture, job: &str, used_secs: u64, checkpoint: Option<&str>) -> Value {
    fixture.gpu.report(used_secs, checkpoint);
    for (stepped, outcome) in step_gpu_jobs(&fixture.server) {
        assert!(outcome.is_ok(), "step of {}: {outcome:?}", stepped.to_hex());
    }
    owner_status(fixture, job).await
}

fn percents(status: &Value) -> Vec<u64> {
    status["signalled_percents"]
        .as_array()
        .expect("signalled percents")
        .iter()
        .map(|percent| percent.as_u64().expect("a percent"))
        .collect()
}

fn refusal(body: &Value) -> String {
    body["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn gpu_job_warns_checkpoints_and_stops_at_its_maximum() {
    run_on_engine_stack("gpu-job-maximum", || async {
        let fixture = setup(SECTION);
        let quote = owner_quote(&fixture, "h100-test", None).await;
        assert_eq!(quote["maximum_secs"].as_u64(), Some(100), "{quote}");
        assert_eq!(quote["quantity"].as_u64(), Some(120), "{quote}");
        assert_eq!(quote["units"].as_u64(), Some(240), "{quote}");

        let (status, started) = as_owner(
            &fixture,
            "vault.gpu.jobs.start",
            json!({"quote": quote, "resume": false}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner start: {started}");
        assert_eq!(started["state"].as_str(), Some("running"), "{started}");
        let job = started["job"].as_str().expect("job id").to_owned();
        assert_eq!(fixture.gpu.called("create"), 1);

        let status = step_at(&fixture, &job, 50, None).await;
        assert_eq!(percents(&status), [50], "{status}");
        let status = step_at(&fixture, &job, 80, None).await;
        assert_eq!(percents(&status), [50, 80], "{status}");
        assert_eq!(
            status["warning_delivered"].as_bool(),
            Some(false),
            "{status}"
        );
        let status = step_at(&fixture, &job, 95, None).await;
        assert_eq!(percents(&status), [50, 80, 95], "{status}");
        assert_eq!(
            status["warning_delivered"].as_bool(),
            Some(true),
            "the 95 percent warning reached the owner's inbox: {status}"
        );
        assert_eq!(
            fixture.gpu.state().signals,
            [
                GpuJobSignal::CheckpointDue { percent: 50 },
                GpuJobSignal::CheckpointDue { percent: 80 },
                GpuJobSignal::CheckpointDue { percent: 95 },
            ],
            "the job is told to checkpoint at 50, 80 and 95 percent, once each"
        );

        let status = step_at(&fixture, &job, 97, Some("ck-1")).await;
        assert_eq!(
            status["checkpoint"].as_str(),
            Some("ck-1"),
            "a checkpoint taken after the warning counts: {status}"
        );

        fixture.gpu.state().termination = Some(GpuTermination::Confirmed { billed_secs: 100 });
        let mut status = step_at(&fixture, &job, 100, Some("ck-1")).await;
        for _ in 0..2 {
            if status["state"].as_str() == Some("stopped") {
                break;
            }
            status = step_at(&fixture, &job, 100, Some("ck-1")).await;
        }
        assert_eq!(status["state"].as_str(), Some("stopped"), "{status}");
        assert!(
            fixture.gpu.called("terminate") >= 1,
            "the chunk was terminated"
        );
        assert_eq!(
            status["stop"]["checkpoint"].as_str(),
            Some("ck-1"),
            "{status}"
        );
        assert_eq!(
            status["settled_units"].as_u64(),
            Some(240),
            "100 billed seconds and 20 overhead seconds at 2, never above the quote: {status}"
        );

        let resume_quote = owner_quote(&fixture, "h100-test", Some(&job)).await;
        assert_eq!(
            resume_quote["job"].as_str(),
            Some(job.as_str()),
            "{resume_quote}"
        );
        let (status, resumed) = as_owner(
            &fixture,
            "vault.gpu.jobs.start",
            json!({"quote": resume_quote, "resume": true}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner resume: {resumed}");
        assert_eq!(resumed["state"].as_str(), Some("running"), "{resumed}");
        assert_eq!(resumed["chunks"].as_u64(), Some(2), "{resumed}");
        assert_eq!(
            fixture.gpu.called("create"),
            2,
            "the resume created one chunk"
        );

        let again = owner_quote(&fixture, "h100-test", Some(&job)).await;
        let (status, body) = as_owner(
            &fixture,
            "vault.gpu.jobs.start",
            json!({"quote": again, "resume": true}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a second resume of one stop is refused: {body}"
        );
        assert_eq!(fixture.gpu.called("create"), 2, "nothing more was created");
    });
}

#[test]
fn starting_a_gpu_job_is_the_owners_act() {
    run_on_engine_stack("gpu-job-owner-act", || async {
        let fixture = setup(SECTION);
        let agent = pair_agent(&fixture, "gpu-job-agent", [0x61; 32]).await;
        let (status, body) = as_owner(
            &fixture,
            "vault.agents.grants.mint",
            json!({
                "agent": agent.principal.to_hex(),
                "authority_scope": {
                    "worlds": {"kind": "all"},
                    "facets": {"kind": "all"},
                    "bands": {"kind": "all"},
                    "audience": {"kind": "all"},
                    "verbs": {"kind": "some", "values": [
                        "read",
                        "vault.gpu.jobs.quote",
                        "vault.gpu.jobs.status",
                        "vault.gpu.jobs.start",
                        "vault.gpu.jobs.cancel",
                    ]},
                    "sensitivity": {"kind": "at_most", "value": "restricted"},
                },
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner mints the agent's Grant: {body}"
        );

        let (status, quote) = as_agent(
            &fixture,
            &agent,
            "vault.gpu.jobs.quote",
            quote_input("h100-test", 100, None),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "an agent whose Grant names quote quotes: {quote}"
        );

        let (status, body) = as_agent(
            &fixture,
            &agent,
            "vault.gpu.jobs.start",
            json!({"quote": quote, "resume": false}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "starting is the owner's act: {body}"
        );
        assert_eq!(
            fixture.gpu.called("create"),
            0,
            "the agent's start created nothing"
        );

        let (status, started) = as_owner(
            &fixture,
            "vault.gpu.jobs.start",
            json!({"quote": quote, "resume": false}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner starts on that quote: {started}"
        );
        let job = started["job"].as_str().expect("job id").to_owned();

        let (status, body) = as_agent(
            &fixture,
            &agent,
            "vault.gpu.jobs.status",
            json!({"job": job}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "an agent whose Grant names status reads it: {body}"
        );
        assert_eq!(body["state"].as_str(), Some("running"), "{body}");

        let (status, body) = as_agent(
            &fixture,
            &agent,
            "vault.gpu.jobs.cancel",
            json!({"job": job}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "cancelling is the owner's act: {body}"
        );
        assert_eq!(
            fixture.gpu.called("terminate"),
            0,
            "the agent's cancel ended nothing"
        );

        let (status, body) = as_owner(&fixture, "vault.gpu.jobs.cancel", json!({"job": job})).await;
        assert_eq!(status, StatusCode::OK, "the owner cancels: {body}");
        assert!(
            matches!(body["state"].as_str(), Some("ending" | "ended")),
            "{body}"
        );
        assert_eq!(
            fixture.gpu.called("terminate"),
            1,
            "the owner's cancel terminates"
        );
    });
}

#[test]
fn an_offer_without_a_backend_refuses_before_any_reservation() {
    run_on_engine_stack("gpu-job-no-backend", || async {
        let fixture = setup(&format!("{SECTION}{UNBACKED_OFFER}"));
        let quote = owner_quote(&fixture, "a100-test", None).await;
        let (status, body) = as_owner(
            &fixture,
            "vault.gpu.jobs.start",
            json!({"quote": quote, "resume": false}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(
            refusal(&body).contains("gpu_jobs.no_backend"),
            "the refusal names the missing backend: {body}"
        );
        assert!(
            fixture.gpu.state().calls.is_empty(),
            "no provider was called"
        );
        let (status, body) = as_owner(&fixture, "vault.gpu.jobs.list", json!({})).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["jobs"].as_array().map(Vec::len),
            Some(0),
            "no job was written: {body}"
        );
    });
}

#[test]
fn the_gpu_jobs_section_is_checked() {
    let settings = gpu_jobs_section(SECTION).expect("the good section");
    assert!(settings.offer("h100-test").is_some());
    assert_eq!(
        (settings.default_maximum_secs, settings.step_secs),
        (3600, 30)
    );

    let shaped = SECTION.replace(
        "price_per_second = 2",
        "price_per_second = 2\nprice_shape = \"cost_plus\"",
    );
    let refused = gpu_jobs_section(&shaped).expect_err("a cost-plus GPU offer");
    assert!(
        format!("{refused:#}").contains("at_oneiron_list"),
        "{refused:#}"
    );

    let free = SECTION.replace("price_per_second = 2", "price_per_second = 0");
    let refused = gpu_jobs_section(&free).expect_err("a zero price");
    assert!(
        format!("{refused:#}").contains("price_per_second"),
        "{refused:#}"
    );

    let unknown = SECTION.replace("price_per_second = 2", "price_per_second = 2\nprice = 2");
    let refused = gpu_jobs_section(&unknown).expect_err("an unknown key");
    assert!(format!("{refused:#}").contains("price"), "{refused:#}");
}
