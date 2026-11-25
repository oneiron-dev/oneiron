//! CPU-only units (pass 32 row M3-D; pass 34 9.2, "the first proof that
//! nothing in the rig needs a GPU"): a CPU-class offer posted in
//! `cpu_seconds` beside a GPU-class offer in `gpu_seconds`, each funded by its
//! own allocation on the one host account, over the real `vault.gpu.jobs.*`
//! facade routes and the job worker's step, on two scripted fake backends.
//!
//! - A CPU-class offer resolves and quotes in `cpu_seconds`.
//! - A CPU job holds only on the `cpu_seconds` allocation and a GPU job only
//!   on the `gpu_seconds` one: with each allocation exactly one job's
//!   reservation, both start, and a second job of either kind is refused
//!   while the other unit's allocation is untouched.
//! - A CPU job that exits early settles in `cpu_seconds` and gives back its
//!   unused part to the CPU allocation alone: a CPU job of exactly the room
//!   left starts, one second more is refused, and a second GPU job is still
//!   refused.
//! - With no `cpu_seconds` allocation, a CPU start is refused before any
//!   provider call, and it never draws on the `gpu_seconds` allocation.
//!
//! No engine code lists units or classes; these tests pin what main's
//! run admission already does (slot choice by native unit within the
//! funding wallet, no fallback), so there is no red run.
//!
//! The owner acts on its host-root credential on a profiled install. The
//! worker's pass runs through the `gpu_backend` test door, so no test waits on
//! `step_secs`. Deterministic: in-process vault and router (`oneshot`), no
//! TCP ports, no sleeps.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --features oneiron/test-support
//! --test customer_cpu_job_seconds`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::gpu_job::{
    GpuConnectorError, GpuJobConnector, GpuJobSignal, GpuJobSpec, GpuResourceRef,
    GpuResourceStatus, GpuTermination,
};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::test_doors::gpu_backend::{
    gpu_jobs_section, grant_allocation, register_gpu_backend, step_gpu_jobs,
};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// One CPU-class and one GPU-class offer, each at 1 of its own unit a
/// second, each with 20 seconds of startup, teardown and rounding, on its own
/// fake backend.
const SECTION: &str = r#"
default_maximum_secs = 3600
step_secs = 30

[offers.cpu-test]
class = "cpu-16"
provider = "example-cloud"
region = "test-region"
backend = "fake-cpu"
price_per_second = 1
cost_unit = "cpu_seconds"
catalog_revision = "cpu-prices-1"
startup_secs = 10
teardown_secs = 5
rounding_secs = 5

[offers.gpu-test]
class = "h100"
provider = "example-cloud"
region = "test-region"
backend = "fake-gpu"
price_per_second = 1
cost_unit = "gpu_seconds"
catalog_revision = "gpu-prices-1"
startup_secs = 10
teardown_secs = 5
rounding_secs = 5
"#;

const IMAGE: &str = "registry.example.com/trainer@sha256:00";

/// The reservation of one 100-second job on either offer: 100 run seconds
/// plus 20 overhead seconds, at 1 a second.
const ONE_JOB: u64 = 120;

/// What one fake provider answers, and every call it took.
#[derive(Default)]
struct FakeState {
    calls: Vec<String>,
    created: HashMap<String, GpuResourceRef>,
    status: Option<GpuResourceStatus>,
    termination: Option<GpuTermination>,
}

/// A backend whose answers the test scripts. It runs no device: the
/// connector is the same trait for a CPU class as for a GPU class.
#[derive(Default)]
struct FakeBackend(Mutex<FakeState>);

impl FakeBackend {
    fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.0.lock().expect("fake backend state")
    }

    fn called(&self, name: &str) -> usize {
        self.state()
            .calls
            .iter()
            .filter(|call| call.starts_with(name))
            .count()
    }
}

impl GpuJobConnector for FakeBackend {
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
        _signal: GpuJobSignal,
    ) -> Result<(), GpuConnectorError> {
        self.state().calls.push(format!("signal {}", resource.0));
        Ok(())
    }

    fn terminate(&self, resource: &GpuResourceRef) -> Result<GpuTermination, GpuConnectorError> {
        let mut state = self.state();
        state.calls.push(format!("terminate {}", resource.0));
        Ok(state.termination.unwrap_or(GpuTermination::Pending))
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    server: Arc<SyncServer>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    cpu: Arc<FakeBackend>,
    gpu: Arc<FakeBackend>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A served vault with [`SECTION`] as its `[gpu_jobs]`, one fake per offer's
/// backend, and on its host account an allocation of each `(id, units,
/// unit)` in `allocations`.
fn setup(allocations: &[(&str, u64, &str)]) -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("customer-cpu-job-seconds".into()),
                gpu_jobs: gpu_jobs_section(SECTION).expect("the [gpu_jobs] section"),
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
    let cpu = Arc::new(FakeBackend::default());
    let gpu = Arc::new(FakeBackend::default());
    register_gpu_backend(
        &server,
        "fake-cpu",
        Arc::clone(&cpu) as Arc<dyn GpuJobConnector>,
    );
    register_gpu_backend(
        &server,
        "fake-gpu",
        Arc::clone(&gpu) as Arc<dyn GpuJobConnector>,
    );
    for &(id, units, unit) in allocations {
        grant_allocation(&server, id, units, unit).expect("an allocation");
    }
    let app = build_app(Arc::clone(&server));
    Fixture {
        _dir: dir,
        vault,
        server,
        app,
        issuer,
        owner_slip,
        owner_token,
        cpu,
        gpu,
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

/// `verb` as the owner, on its own proof.
async fn as_owner(fixture: &Fixture, verb: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::post(format!("/v1/core/facade/{verb}"))
        .header("authorization", format!("Bearer {}", fixture.owner_token))
        .header("x-oneiron-binding", owner_binding(fixture))
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

/// The owner's quote of a `maximum_secs` job on `offer`, asserted answered.
async fn owner_quote(fixture: &Fixture, offer: &str, maximum_secs: u64) -> Value {
    let (status, quote) = as_owner(
        fixture,
        "vault.gpu.jobs.quote",
        json!({
            "offer": offer,
            "job_type": "batch",
            "image": IMAGE,
            "maximum_secs": maximum_secs,
            "inputs": {"dataset": "sample-dataset"},
            "resume_job": null,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner quote on {offer}: {quote}");
    quote
}

/// The owner quotes a `maximum_secs` job on `offer` and starts it on that
/// quote.
async fn owner_start(fixture: &Fixture, offer: &str, maximum_secs: u64) -> (StatusCode, Value) {
    let quote = owner_quote(fixture, offer, maximum_secs).await;
    as_owner(
        fixture,
        "vault.gpu.jobs.start",
        json!({"quote": quote, "resume": false}),
    )
    .await
}

/// A start the owner expects to run; answers the job id.
async fn started(fixture: &Fixture, offer: &str, maximum_secs: u64) -> String {
    let (status, body) = owner_start(fixture, offer, maximum_secs).await;
    assert_eq!(status, StatusCode::OK, "start on {offer}: {body}");
    assert_eq!(body["state"].as_str(), Some("running"), "{body}");
    body["job"].as_str().expect("job id").to_owned()
}

/// A start the account refuses for want of room in the offer's unit.
async fn refused_for_budget(fixture: &Fixture, offer: &str, maximum_secs: u64) -> Value {
    let (status, body) = owner_start(fixture, offer, maximum_secs).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "start on {offer} is refused: {body}"
    );
    assert_eq!(
        body["error"]["code"].as_str(),
        Some("BUDGET_SPENT"),
        "the refusal is the account's: {body}"
    );
    body
}

async fn owner_status(fixture: &Fixture, job: &str) -> Value {
    let (status, body) = as_owner(fixture, "vault.gpu.jobs.status", json!({"job": job})).await;
    assert_eq!(status, StatusCode::OK, "owner status: {body}");
    body
}

/// One pass of the job worker over every live job, each asserted stepped.
fn step_all(fixture: &Fixture) {
    for (stepped, outcome) in step_gpu_jobs(&fixture.server) {
        assert!(outcome.is_ok(), "step of {}: {outcome:?}", stepped.to_hex());
    }
}

fn refusal(body: &Value) -> String {
    body["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn a_cpu_class_offer_quotes_in_cpu_seconds() {
    let settings = gpu_jobs_section(SECTION).expect("a CPU-class offer beside a GPU one");
    assert!(settings.offer("cpu-test").is_some());
    assert!(settings.offer("gpu-test").is_some());

    run_on_engine_stack("cpu-job-quote", || async {
        let fixture = setup(&[]);
        let quote = owner_quote(&fixture, "cpu-test", 100).await;
        assert_eq!(quote["unit"].as_str(), Some("cpu_seconds"), "{quote}");
        assert_eq!(quote["quantity"].as_u64(), Some(ONE_JOB), "{quote}");
        assert_eq!(quote["units"].as_u64(), Some(ONE_JOB), "{quote}");
        let quote = owner_quote(&fixture, "gpu-test", 100).await;
        assert_eq!(quote["unit"].as_str(), Some("gpu_seconds"), "{quote}");
    });
}

#[test]
fn cpu_and_gpu_jobs_hold_and_settle_only_on_their_own_units() {
    run_on_engine_stack("cpu-job-own-unit", || async {
        let fixture = setup(&[
            ("cpu-allocation", ONE_JOB, "cpu_seconds"),
            ("gpu-allocation", ONE_JOB, "gpu_seconds"),
        ]);

        let cpu_job = started(&fixture, "cpu-test", 100).await;
        assert_eq!(fixture.cpu.called("create"), 1);
        assert_eq!(fixture.gpu.called("create"), 0);
        // The CPU job holds the whole CPU allocation, so the GPU job starts
        // only if it holds on the GPU one.
        let _gpu_job = started(&fixture, "gpu-test", 100).await;
        assert_eq!(fixture.gpu.called("create"), 1);

        refused_for_budget(&fixture, "cpu-test", 100).await;
        refused_for_budget(&fixture, "gpu-test", 100).await;
        assert_eq!(fixture.cpu.called("create"), 1, "no second CPU resource");
        assert_eq!(fixture.gpu.called("create"), 1, "no second GPU resource");

        // The CPU job exits after 30 seconds; the provider confirms 30
        // billed. It settles 30 plus 20 overhead seconds in cpu_seconds.
        fixture.cpu.state().status = Some(GpuResourceStatus::Exited { used_secs: 30 });
        fixture.cpu.state().termination = Some(GpuTermination::Confirmed { billed_secs: 30 });
        let mut status = owner_status(&fixture, &cpu_job).await;
        for _ in 0..3 {
            if status["state"].as_str() == Some("ended") {
                break;
            }
            step_all(&fixture);
            status = owner_status(&fixture, &cpu_job).await;
        }
        assert_eq!(status["state"].as_str(), Some("ended"), "{status}");
        assert_eq!(
            status["settled_units"].as_u64(),
            Some(50),
            "30 billed and 20 overhead seconds at 1 cpu_second: {status}"
        );

        // 70 cpu_seconds came back to the CPU allocation: a job reserving
        // 71 is refused, one reserving exactly 70 starts.
        refused_for_budget(&fixture, "cpu-test", 51).await;
        let _ = started(&fixture, "cpu-test", 50).await;
        assert_eq!(fixture.cpu.called("create"), 2);
        // The GPU allocation got nothing back.
        refused_for_budget(&fixture, "gpu-test", 1).await;
        assert_eq!(fixture.gpu.called("create"), 1);
    });
}

#[test]
fn a_cpu_job_with_no_cpu_seconds_allocation_never_draws_gpu_seconds() {
    run_on_engine_stack("cpu-job-no-cpu-allocation", || async {
        let fixture = setup(&[("gpu-allocation", ONE_JOB, "gpu_seconds")]);

        let body = refused_for_budget(&fixture, "cpu-test", 100).await;
        assert!(
            refusal(&body).contains("cpu_seconds"),
            "the refusal names the CPU unit it found no allocation in: {body}"
        );
        assert!(
            fixture.cpu.state().calls.is_empty(),
            "no provider was called: {:?}",
            fixture.cpu.state().calls
        );
        let (status, listed) = as_owner(&fixture, "vault.gpu.jobs.list", json!({})).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(
            listed["jobs"].as_array().map(Vec::len),
            Some(0),
            "no job was written: {listed}"
        );

        // The whole GPU allocation is still there for a GPU job.
        let _ = started(&fixture, "gpu-test", 100).await;
        assert_eq!(fixture.gpu.called("create"), 1);
    });
}
