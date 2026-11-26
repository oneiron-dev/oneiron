//! `[gpu_jobs.host_allocation]` (R6-VAULT-MACHINE-FUNDING = A; Engine TASK 25 Nov 23:35, R6-B6):
//! a self-hosted server funds its own host account from its config at start.
//!
//! - With no section the host account is empty: the owner's start answers that the host has
//!   delivered no allocation, and no provider is called.
//! - With it, the start reserves the whole quote on the granted allocation, so a second start of
//!   the same size does not fit beside it. The job settles there: once its cancel is billed, a
//!   start that needs the whole allocation again does not fit, and a smaller one fits in what the
//!   settle released.
//! - Each start grants the units again (Engine 23:46: one process, one budget). The same install
//!   again grants nothing more, since its account already holds the allocation; a restarted server
//!   on the same vault starts with the full units again, even though the first start's job held
//!   them all.
//! - The section is checked when it is read, and a managed server's start refuses it.
//!
//! The owner acts on its host-root credential on a profiled install, over the real facade routes,
//! as `customer_gpu_job_maximum.rs` does. Deterministic: in-process vault and router
//! (`oneshot`), a scripted fake backend, no TCP ports, no sleeps.
//!
//! Red: at main 14c829000266 plus this file, the target does not build: there is no
//! `test_doors::gpu_backend::install_host_allocation`, and `[gpu_jobs]` refuses the key
//! `host_allocation`. Without the section (the first test), main answers the same refusal.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test gpu_host_allocation`.
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
    gpu_jobs_section, install_host_allocation, refuse_managed_host_allocation,
    register_gpu_backend, step_gpu_jobs,
};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The `[gpu_jobs]` section: one offer on the fake backend at 2 credit-micros a second, with 20
/// seconds of startup, teardown and rounding.
const SECTION: &str = r#"
default_maximum_secs = 3600
step_secs = 30

[offers.own-gpu]
class = "rtx3090"
provider = "own"
region = "home"
backend = "fake"
price_per_second = 2
cost_unit = "credit-micros"
catalog_revision = "own-prices-1"
startup_secs = 10
teardown_secs = 5
rounding_secs = 5
"#;

/// One quote of 100 seconds: 120 seconds at 2 credit-micros, reserved whole.
const QUOTE_UNITS: u64 = 240;

const IMAGE: &str = "registry.example.com/harmless@sha256:00";

/// `SECTION` with `[gpu_jobs.host_allocation]` of `units` `unit` as the allocation `id`.
fn with_allocation(id: &str, units: u64, unit: &str) -> String {
    format!("{SECTION}\n[host_allocation]\nid = \"{id}\"\nunits = {units}\nunit = \"{unit}\"\n")
}

/// `SECTION` with an allocation of `units` credit-micros, the offer's unit, as `id`.
fn allocation(id: &str, units: u64) -> String {
    with_allocation(id, units, "credit-micros")
}

/// What the fake provider answers, and every call it took.
#[derive(Default)]
struct FakeState {
    calls: Vec<String>,
    created: HashMap<String, GpuResourceRef>,
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
        self.state().calls.push(format!("status {}", resource.0));
        Ok(GpuResourceStatus::Pending)
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

/// The vault owner's host-root credential.
struct Owner {
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    slip: CapabilitySlip,
    token: String,
}

/// One served start of the vault: its server with `[gpu_jobs]` as given, the fake registered as
/// backend `fake`, and its router. Nothing is granted: the test installs the section.
struct Served {
    server: Arc<SyncServer>,
    app: Router,
    gpu: Arc<FakeGpu>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn open_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    (dir, vault)
}

/// A server start on `vault` with `section` as its `[gpu_jobs]`. Each call is one start: a new
/// server, so a new host account, on the same vault.
fn serve(vault: &Arc<Vault>, section: &str) -> Served {
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(vault),
            SyncServerConfig {
                auth_secret: Some("gpu-host-allocation".into()),
                gpu_jobs: gpu_jobs_section(section).expect("the [gpu_jobs] section"),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let gpu = Arc::new(FakeGpu::default());
    register_gpu_backend(
        &server,
        "fake",
        Arc::clone(&gpu) as Arc<dyn GpuJobConnector>,
    );
    let app = build_app(Arc::clone(&server));
    Served { server, app, gpu }
}

/// The owner's credential, on this install's live machine profile.
fn owner_of(vault: &Arc<Vault>) -> Owner {
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let token = slip.to_token().expect("owner slip token");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    Owner {
        vault: Arc::clone(vault),
        issuer,
        slip,
        token,
    }
}

fn owner_binding(owner: &Owner) -> String {
    let timestamp = owner.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = hex(&owner
        .issuer
        .binding_proof(&owner.slip, challenge.as_bytes())
        .expect("owner holder proof"));
    json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
}

/// `verb` as the owner, on its own proof, over the real facade route.
async fn as_owner(served: &Served, owner: &Owner, verb: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::post(format!("/v1/core/facade/{verb}"))
        .header("authorization", format!("Bearer {}", owner.token))
        .header("x-oneiron-binding", owner_binding(owner))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("facade request");
    let response = served
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

/// The owner's quote of a job of `maximum_secs` on the one offer, asserted answered.
async fn owner_quote(served: &Served, owner: &Owner, maximum_secs: u64) -> Value {
    let (status, quote) = as_owner(
        served,
        owner,
        "vault.gpu.jobs.quote",
        json!({
            "offer": "own-gpu",
            "job_type": "field-harmless",
            "image": IMAGE,
            "maximum_secs": maximum_secs,
            "inputs": {"dataset": "none"},
            "resume_job": null,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner quote: {quote}");
    quote
}

/// The owner presses start on `quote`.
async fn owner_start(served: &Served, owner: &Owner, quote: Value) -> (StatusCode, Value) {
    as_owner(
        served,
        owner,
        "vault.gpu.jobs.start",
        json!({"quote": quote, "resume": false}),
    )
    .await
}

async fn owner_status(served: &Served, owner: &Owner, job: &str) -> Value {
    let (status, body) =
        as_owner(served, owner, "vault.gpu.jobs.status", json!({"job": job})).await;
    assert_eq!(status, StatusCode::OK, "owner status: {body}");
    body
}

fn refusal(body: &Value) -> String {
    body["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// The start refused because the host account holds no allocation.
fn assert_no_allocation(status: StatusCode, body: &Value) {
    assert_ne!(status, StatusCode::OK, "the start refused: {body}");
    assert!(
        refusal(body).contains("the host has delivered no allocation"),
        "the refusal says no allocation funds it: {body}"
    );
}

#[test]
fn a_start_answers_no_allocation_without_the_section() {
    run_on_engine_stack("gpu-host-allocation-absent", || async {
        let (_dir, vault) = open_vault();
        let served = serve(&vault, SECTION);
        let owner = owner_of(&vault);
        assert!(
            !install_host_allocation(&served.server).expect("no section is no refusal"),
            "no section grants nothing"
        );

        let quote = owner_quote(&served, &owner, 100).await;
        let (status, body) = owner_start(&served, &owner, quote).await;
        assert_no_allocation(status, &body);
        assert!(
            served.gpu.state().calls.is_empty(),
            "no provider was called"
        );
    });
}

#[test]
fn the_config_allocation_holds_the_start_and_takes_its_settlement() {
    run_on_engine_stack("gpu-host-allocation-settle", || async {
        let (_dir, vault) = open_vault();
        let served = serve(&vault, &allocation("own-1", QUOTE_UNITS));
        let owner = owner_of(&vault);
        assert!(
            install_host_allocation(&served.server).expect("the grant"),
            "the account was granted the allocation now"
        );

        let quote = owner_quote(&served, &owner, 100).await;
        assert_eq!(quote["units"].as_u64(), Some(QUOTE_UNITS), "{quote}");
        let (status, started) = owner_start(&served, &owner, quote).await;
        assert_eq!(status, StatusCode::OK, "owner start: {started}");
        assert_eq!(started["state"].as_str(), Some("running"), "{started}");
        let job = started["job"].as_str().expect("job id").to_owned();
        assert_eq!(served.gpu.called("create"), 1);

        // The job holds the whole allocation, so a second of the same size does not fit.
        let second = owner_quote(&served, &owner, 100).await;
        let (status, body) = owner_start(&served, &owner, second).await;
        assert_ne!(status, StatusCode::OK, "{body}");
        let refused = refusal(&body);
        assert!(
            refused.starts_with("the run admission refused the job"),
            "the reservation was refused: {body}"
        );
        assert!(
            !refused.contains("no allocation"),
            "the allocation is there, and held: {body}"
        );
        assert_eq!(
            served.gpu.called("create"),
            1,
            "the refused start created nothing"
        );

        // The cancel is billed 30 seconds; the job settles on the allocation.
        served.gpu.state().termination = Some(GpuTermination::Confirmed { billed_secs: 30 });
        let (status, body) = as_owner(
            &served,
            &owner,
            "vault.gpu.jobs.cancel",
            json!({"job": job}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the owner cancels: {body}");
        let mut ended = owner_status(&served, &owner, &job).await;
        for _ in 0..3 {
            if ended["state"].as_str() == Some("ended") {
                break;
            }
            for (stepped, outcome) in step_gpu_jobs(&served.server) {
                assert!(outcome.is_ok(), "step of {}: {outcome:?}", stepped.to_hex());
            }
            ended = owner_status(&served, &owner, &job).await;
        }
        assert_eq!(ended["state"].as_str(), Some("ended"), "{ended}");
        let settled = ended["settled_units"].as_u64().expect("settled units");
        assert!(
            settled > 0 && settled < QUOTE_UNITS,
            "the billed time settled, below the quote: {ended}"
        );

        // The settlement stays on the allocation: the whole quote no longer fits.
        let whole = owner_quote(&served, &owner, 100).await;
        let (status, body) = owner_start(&served, &owner, whole).await;
        assert_ne!(
            status,
            StatusCode::OK,
            "what the job was billed stays charged: {body}"
        );
        // The rest of the hold was released: a job that fits in it starts.
        let small = owner_quote(&served, &owner, 10).await;
        let small_units = small["units"].as_u64().expect("quote units");
        assert!(
            small_units <= QUOTE_UNITS - settled,
            "the small quote fits in what is left: {small}"
        );
        let (status, body) = owner_start(&served, &owner, small).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "what the settle released funds a smaller job: {body}"
        );
        assert_eq!(served.gpu.called("create"), 2);
    });
}

#[test]
fn a_restarted_server_grants_the_units_again() {
    run_on_engine_stack("gpu-host-allocation-restart", || async {
        let (_dir, vault) = open_vault();
        let first = serve(&vault, &allocation("own-1", QUOTE_UNITS));
        let owner = owner_of(&vault);
        assert!(
            install_host_allocation(&first.server).expect("the first start's grant"),
            "the first start grants the allocation"
        );
        assert!(
            !install_host_allocation(&first.server).expect("a second install is no refusal"),
            "the same account is not granted it twice"
        );
        let quote = owner_quote(&first, &owner, 100).await;
        let (status, body) = owner_start(&first, &owner, quote).await;
        assert_eq!(status, StatusCode::OK, "the first start's job: {body}");
        let second = owner_quote(&first, &owner, 100).await;
        let (status, body) = owner_start(&first, &owner, second).await;
        assert_ne!(
            status,
            StatusCode::OK,
            "the second install added nothing: the job holds it all: {body}"
        );
        drop(first);

        let restarted = serve(&vault, &allocation("own-1", QUOTE_UNITS));
        assert!(
            install_host_allocation(&restarted.server).expect("the restart's grant"),
            "a restarted server grants the units again"
        );
        let quote = owner_quote(&restarted, &owner, 100).await;
        let (status, body) = owner_start(&restarted, &owner, quote).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the restart's full units fund a whole quote: {body}"
        );
        assert_eq!(restarted.gpu.called("create"), 1);
    });
}

#[test]
fn the_section_is_checked_and_a_managed_start_refuses_it() {
    let settings = gpu_jobs_section(&allocation("own-1", 3600)).expect("the good section");
    let granted = settings
        .host_allocation
        .as_ref()
        .expect("the allocation the section names");
    assert_eq!(
        (
            granted.reference.id.as_str(),
            granted.reference.generation,
            granted.units,
            granted.unit.as_str(),
        ),
        ("own-1", 1, 3600, "credit-micros")
    );
    let without = gpu_jobs_section(SECTION).expect("no allocation section");
    assert!(without.host_allocation.is_none(), "absent by default");

    let refusals = [
        (allocation("own-1", 0), "units"),
        (allocation("own 1", 10), "plain name"),
        (allocation("gpu-line:00ff", 10), "GPU line"),
        (with_allocation("own-1", 10, "cpu_seconds"), "cost_unit"),
        (
            allocation("own-1", 10).replace("units = 10", "units = 10\nwallet = \"w\""),
            "wallet",
        ),
    ];
    for (section, named) in refusals {
        let refused = gpu_jobs_section(&section).expect_err(named);
        assert!(
            format!("{refused:#}").contains(named),
            "{named}: {refused:#}"
        );
    }

    let refused =
        refuse_managed_host_allocation(&settings).expect_err("a managed start refuses it");
    assert!(format!("{refused:#}").contains("managed"), "{refused:#}");
    refuse_managed_host_allocation(&without).expect("a managed start without the section");
}
