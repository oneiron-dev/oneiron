//! Work orders on the server (pass 34, row Q1; rulings EM-19 and pass 33's one issuer, 8.7): an
//! order is made on the vault's issuer only, and the node, the start gate and the order name a
//! refusal with one code.
//!
//! Run on the fleet, not on a workstation:
//! ```sh
//! RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support --test work_orders
//! ```
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/execution_nodes.rs"]
mod execution_nodes;
#[path = "support/mesh_machines.rs"]
mod mesh_machines;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use execution_nodes::{NodeFiles, PROBE_TEMPLATE};
use mesh_machines::Machines;
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::gpu_job::{
    GpuConnectorError, GpuJobConnector, GpuJobSignal, GpuJobSpec, GpuOffer, GpuResourceRef,
    GpuResourceStatus, GpuTermination, PriceShape,
};
use oneiron::job_workload::{TEMPLATE_CHANGED, TEMPLATE_NOT_OFFERED, WorkloadStartRefusal};
use oneiron::llm::ModelLocality;
use oneiron::llm::run_admission::{KeyCustody, LeaseUnit, OfferRoute, PaidConnector, Payer};
use oneiron::memory::verb_grant_caller::VerbGrantCaller;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND};
use oneiron::test_support::test_host_issuer;
use oneiron::work_order::{
    Blocker, CancelWhy, MACHINES_PLACE_VERB, ORDER_VERB, ORDERS_CANCEL_VERB, ORDERS_GET_VERB,
    ORDERS_WAIT_VERB, OrderState, OrderedBy, WaitUntil, WorkOrderView, WorkOrderWaitAnswer,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::config::gpu_jobs::{AtMaximum, GpuOfferSettings};
use oneiron_server::gpu_execution_node::ExecutionNodeSettings;
use oneiron_server::gpu_execution_node::issuer::{VAULT_MACHINE_BACKEND, job_refusal_code};
#[cfg(target_os = "linux")]
use oneiron_server::gpu_execution_node::jobs::journal_file::JournalWriterLock;
use oneiron_server::gpu_execution_node::wire::{JOB_ALPN, JobAnswer, JobRefusal, JobState};
use oneiron_server::test_doors::gpu_backend::{
    gpu_jobs_section, grant_gpu_allocation, register_gpu_backend,
};
use oneiron_server::work_order_host::{dispatches_offer, facts_of_answer};
use oneiron_server::{build_app, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

fn offer(name: &str) -> GpuOffer {
    GpuOffer {
        name: name.to_owned(),
        class: "machine".to_owned(),
        provider: "vault-machines".to_owned(),
        region: "home".to_owned(),
        connector: PaidConnector {
            connector: "vault-machines".to_owned(),
            route: OfferRoute::new("vault-machines", "https://machines.example.com")
                .expect("route"),
            locality: ModelLocality::ThirdParty,
            payer: Payer::Local,
            credential_binding: None,
            catalog_revision: None,
            custody: KeyCustody::T0,
            unit_cost: 1,
            cost_unit: LeaseUnit::new("credit-micros").expect("unit"),
            rates: Vec::new(),
        },
        price_shape: PriceShape::AtOneironList,
        list_cost_per_second: None,
        startup_secs: 0,
        teardown_secs: 0,
        rounding_secs: 0,
        at_maximum: AtMaximum::Stop,
    }
}

#[test]
fn an_order_on_a_replica_that_is_not_the_issuer_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::default()).expect("vault"));
    let issuer = EntityId::now();
    let mut config = SyncServerConfig::default();
    config.gpu_jobs.vault_machine.enabled = true;
    config.gpu_jobs.vault_machine.issuer = Some(issuer);
    config.gpu_jobs.offers.insert(
        "home".to_owned(),
        GpuOfferSettings {
            backend: VAULT_MACHINE_BACKEND.to_owned(),
            offer: offer("home"),
            at_maximum: Some(AtMaximum::Stop),
        },
    );
    config.gpu_jobs.offers.insert(
        "cloud".to_owned(),
        GpuOfferSettings {
            backend: "skypilot".to_owned(),
            offer: offer("cloud"),
            at_maximum: None,
        },
    );
    let server = SyncServer::new(vault, config).expect("boot a replica that is not the issuer");
    let refused = dispatches_offer(&server, "home").expect_err("the replica makes no order");
    assert_eq!(refused.code(), "not_the_issuer");
    assert_eq!(
        refused,
        Blocker::NotTheIssuer {
            issuer: Some(issuer.to_hex())
        }
    );
    // An order on an offer whose backend is not the vault's own machines is not the issuer's
    // alone.
    assert!(dispatches_offer(&server, "cloud").is_ok());
}

/// FIX row WORK-ORDER-NODES-CACHED-OFF-RUNTIME: a first call off the runtime does not cut the
/// loop off from every machine for good.
#[cfg(feature = "mesh")]
#[test]
fn a_loop_first_asked_off_the_runtime_calls_machines_once_a_runtime_is_at_hand() {
    use oneiron_server::gpu_execution_node::issuer::NodeCallError;
    use oneiron_server::test_doors::work_order_host::node_call_now;

    fn unreachable_reason(answer: Result<JobAnswer, NodeCallError>) -> String {
        match answer {
            Err(NodeCallError::Unreachable { reason }) => reason,
            other => panic!("no mesh reaches the machine, so it is unreachable: {other:?}"),
        }
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::default()).expect("vault"));
    let server =
        Arc::new(SyncServer::new(vault, SyncServerConfig::default()).expect("boot the server"));
    let machine = EntityId::now();
    // Off any runtime the loop has no client that calls machines.
    assert_eq!(
        unreachable_reason(node_call_now(&server, machine)),
        "this server calls no machines"
    );
    // The next call, on the runtime, goes through the mesh client, which reads the listener at
    // each call: none is bound in this test.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("runtime");
    let on_runtime = Arc::clone(&server);
    let answer = runtime.block_on(async move {
        tokio::task::spawn_blocking(move || node_call_now(&on_runtime, machine))
            .await
            .expect("the blocking call ends")
    });
    assert_eq!(unreachable_reason(answer), "no mesh listener is bound");
}

#[test]
fn the_node_the_gate_and_the_order_name_a_refusal_with_one_code() {
    // Every node refusal keeps its code on the order.
    let node_refusals = [
        JobRefusal::NotEnabled,
        JobRefusal::PeerNotProven,
        JobRefusal::NotIssuer,
        JobRefusal::OwnGrantEnded,
        JobRefusal::IssuerStandingEnded,
        JobRefusal::Paused {
            why: "maintenance".to_owned(),
        },
        JobRefusal::Drained {
            why: "three fast failures".to_owned(),
        },
        JobRefusal::NotReleasable {
            state: JobState::Held,
        },
        JobRefusal::HistoryLost,
        JobRefusal::KeyConflict,
        JobRefusal::NotTheKeysIssuer,
        JobRefusal::SubmitSignatureInvalid,
        JobRefusal::DevicesUnreadable {
            why: "nvml".to_owned(),
        },
        JobRefusal::OutputNotFetchable {
            why: "not a returnable output".to_owned(),
        },
        JobRefusal::NotAcknowledgeable {
            state: JobState::Running,
        },
        JobRefusal::LogNotReadable {
            why: "payload cleaned".to_owned(),
        },
    ];
    for refusal in &node_refusals {
        assert_eq!(
            Blocker::from(refusal).code(),
            job_refusal_code(refusal),
            "{refusal:?}"
        );
    }
    // Every gate refusal keeps its code, and a node's reason the gate passes on is named by
    // the node's own code.
    let gate_refusals = [
        WorkloadStartRefusal::MachineMissing,
        WorkloadStartRefusal::WorkloadUnknown,
        WorkloadStartRefusal::WorkloadNotApproved,
        WorkloadStartRefusal::WorkloadWaiting,
        WorkloadStartRefusal::ComputeGrantEnded,
        WorkloadStartRefusal::WorkloadRevoked,
        WorkloadStartRefusal::WorkloadExpired,
        WorkloadStartRefusal::StarterNotNamed,
        WorkloadStartRefusal::RequestAbovePin,
        WorkloadStartRefusal::MachineNotApproved,
        WorkloadStartRefusal::MachineUnreachable {
            reason: "timeout".to_owned(),
        },
        WorkloadStartRefusal::MachineRefuses {
            reason: "the node says something new".to_owned(),
        },
    ];
    for refusal in &gate_refusals {
        assert_eq!(Blocker::from(refusal).code(), refusal.code(), "{refusal:?}");
    }
    for (reason, code) in [
        (TEMPLATE_CHANGED, TEMPLATE_CHANGED),
        (TEMPLATE_NOT_OFFERED, TEMPLATE_NOT_OFFERED),
        ("paused: maintenance", "paused"),
        ("drained", "drained"),
    ] {
        let gate = WorkloadStartRefusal::MachineRefuses {
            reason: reason.to_owned(),
        };
        assert_eq!(Blocker::from(&gate).code(), code, "{reason}");
    }
    // The order's reasons for a machine whose node refused are the node's codes too.
    let machine = EntityId::now();
    let paused = JobRefusal::Paused {
        why: "maintenance".to_owned(),
    };
    let facts = facts_of_answer(machine, Some(&JobAnswer::Refused(paused.clone())), 1);
    assert_eq!(
        facts.refusal.as_ref().map(Blocker::code),
        Some(job_refusal_code(&paused))
    );
}

const GPU_START: &str = "vault.gpu.jobs.start";
const OFFER: &str = "h100-test";
const MAXIMUM_SECS: u64 = 100;
const FAR_EXPIRY_MS: u64 = 4_102_444_800_000; // 2100-01-01
const GPU_JOBS: &str = r#"
[offers.h100-test]
class = "h100"
provider = "example-cloud"
region = "test-region"
backend = "fake"
price_per_second = 2
cost_unit = "credit-micros"
catalog_revision = "gpu-prices-1"
startup_secs = 0
teardown_secs = 0
rounding_secs = 0
"#;

// Placement asks a node for facts, but dispatch goes to this offer's fake provider.
struct FakeGpu;

impl GpuJobConnector for FakeGpu {
    fn create(&self, key: &str, _: &GpuJobSpec) -> Result<GpuResourceRef, GpuConnectorError> {
        Ok(GpuResourceRef(format!("resource-{key}")))
    }

    fn find(&self, _: &str) -> Result<Option<GpuResourceRef>, GpuConnectorError> {
        Ok(None)
    }

    fn status(&self, _: &GpuResourceRef) -> Result<GpuResourceStatus, GpuConnectorError> {
        Ok(GpuResourceStatus::Pending)
    }

    fn signal(&self, _: &GpuResourceRef, _: GpuJobSignal) -> Result<(), GpuConnectorError> {
        Ok(())
    }

    fn terminate(&self, _: &GpuResourceRef) -> Result<GpuTermination, GpuConnectorError> {
        Ok(GpuTermination::Confirmed { billed_secs: 0 })
    }
}

struct Agent {
    principal: EntityId,
    holder: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

struct HttpFixture {
    vault: Arc<Vault>,
    app: Router,
    issuer: Arc<HostSlipIssuer>,
    owner_slip: CapabilitySlip,
    owner_token: String,
}

fn setup() -> (tempfile::TempDir, HttpFixture) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("work-order-fixture".into()),
                gpu_jobs: gpu_jobs_section(GPU_JOBS).expect("the fake offer"),
                ..Default::default()
            },
        )
        .expect("server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let fixture = HttpFixture::new(vault, server, issuer);
    (dir, fixture)
}

struct Rack {
    http: HttpFixture,
    mesh: Machines,
    #[cfg(target_os = "linux")]
    _writer: JournalWriterLock,
    _files: NodeFiles,
    machine: EntityId,
    template_digest: String,
}

impl Rack {
    async fn start() -> Self {
        let files = NodeFiles::new().expect("temporary node files");
        // The fake paid backend never launches on the node. Hold the journal lock
        // so the mesh offer answers without a job service probing the test host.
        #[cfg(target_os = "linux")]
        let writer = JournalWriterLock::take(&files.state_dir(1)).expect("hold the node journal");
        let mesh = Machines::start_with(2, |index, machines| {
            if index == 0 {
                SyncServerConfig {
                    gpu_jobs: gpu_jobs_section(GPU_JOBS).expect("the fake offer"),
                    ..Default::default()
                }
            } else {
                files.enabled(1, machines[0])
            }
        })
        .await
        .expect("issuer and execution node");
        mesh.grant(0, 1, &[JOB_ALPN]).expect("issuer grants node");
        mesh.grant(1, 0, &[JOB_ALPN]).expect("node grants issuer");
        mesh.grant_own(1, &[JOB_ALPN])
            .expect("node's own job grant");
        let template_digest = ExecutionNodeSettings::read(&files.path(1))
            .expect("read node file")
            .expect("node settings")
            .template_digest(PROBE_TEMPLATE)
            .expect("node's template digest");
        let issuer = mesh.machine(0);
        register_gpu_backend(&issuer.served.server, "fake", Arc::new(FakeGpu));
        grant_gpu_allocation(&issuer.served.server, 1_000_000, "credit-micros")
            .expect("host allocation");
        let http = HttpFixture::new(
            Arc::clone(&issuer.device.vault),
            Arc::clone(&issuer.served.server),
            test_host_issuer(),
        );
        let machine = mesh.machine(1).device.machine;
        Self {
            http,
            mesh,
            #[cfg(target_os = "linux")]
            _writer: writer,
            _files: files,
            machine,
            template_digest,
        }
    }

    async fn approve(&self, workload: &str, starters: &[EntityId]) {
        let approval = ok(self
            .http
            .as_owner(
                "vault.jobs.workloads.approve",
                json!({
                    "workload": workload,
                    "machines": [self.machine],
                    "starters": starters,
                    "expires_at_ms": FAR_EXPIRY_MS,
                }),
            )
            .await);
        assert_eq!(approval["changed"], true, "{approval}");
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl HttpFixture {
    fn new(vault: Arc<Vault>, server: Arc<SyncServer>, issuer: HostSlipIssuer) -> Self {
        let issuer = Arc::new(issuer);
        let owner_slip = vault
            .ensure_host_root_slip(&issuer)
            .expect("owner root slip");
        let owner_token = owner_slip.to_token().expect("owner token");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        vault.hold_checkpoint_root_signer(issuer.clone());
        Self {
            vault,
            app: build_app(server),
            issuer,
            owner_slip,
            owner_token,
        }
    }

    fn pair_agent(&self, name: &str, seed: u8) -> Agent {
        let principal = self
            .vault
            .ensure_agent_principal(name)
            .expect("agent principal");
        let holder = SigningKey::from_bytes(&[seed; 32]);
        let key = holder.verifying_key().to_bytes();
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(BTreeSet::from([
            "core:read".to_owned(),
            "core:write".to_owned(),
        ]));
        let holder_ref = principal.to_hex();
        let link = self
            .vault
            .issue_pairing_link_for_principal(
                &self.issuer,
                scope,
                3600,
                PairingPrincipal {
                    holder_ref: Some(holder_ref.clone()),
                    actor_class: Some("agent".to_owned()),
                    ..Default::default()
                },
            )
            .expect("pairing link");
        let transcript =
            pairing_binding_transcript(&link.code, &key, &holder_ref).expect("pairing transcript");
        // The mesh fixture's replica has no root seed in its server, so redeem on
        // the vault with the fixture's issuer. Facade calls still use this paired slip.
        let slip = self
            .vault
            .redeem_pairing_link(
                &self.issuer,
                &link.code,
                &holder_ref,
                key,
                &holder.sign(&transcript).to_bytes(),
            )
            .expect("redeem agent pairing");
        let token = slip.to_token().expect("agent token");
        Agent {
            principal,
            holder,
            slip,
            token,
        }
    }

    async fn post(
        &self,
        verb: &str,
        token: &str,
        body: Value,
        sign: impl FnOnce(&[u8]) -> String,
    ) -> (StatusCode, Value) {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature = sign(challenge.as_bytes());
        let request = Request::post(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {token}"))
            .header(
                "x-oneiron-binding",
                json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string(),
            )
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("facade request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("facade response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("facade body");
        let body = serde_json::from_slice(&bytes).expect("facade JSON");
        (status, body)
    }

    async fn as_owner(&self, verb: &str, body: Value) -> (StatusCode, Value) {
        self.post(verb, &self.owner_token, body, |challenge| {
            hex(&self
                .issuer
                .binding_proof(&self.owner_slip, challenge)
                .expect("owner holder proof"))
        })
        .await
    }

    async fn as_agent(&self, agent: &Agent, verb: &str, body: Value) -> (StatusCode, Value) {
        self.post(verb, &agent.token, body, |challenge| {
            let transcript = agent
                .slip
                .binding_transcript(challenge)
                .expect("agent binding transcript");
            hex(&agent.holder.sign(&transcript).to_bytes())
        })
        .await
    }

    async fn mint(&self, agent: &Agent, verbs: &[&str]) -> EntityId {
        self.mint_with_classes(agent, verbs, &[]).await
    }

    async fn mint_with_classes(&self, agent: &Agent, verbs: &[&str], classes: &[&str]) -> EntityId {
        let verbs: Vec<&str> = std::iter::once("read")
            .chain(verbs.iter().copied())
            .collect();
        let body = ok(self
            .as_owner(
                "vault.agents.grants.mint",
                json!({
                    "agent": agent.principal,
                    "authority_scope": {
                        "worlds": {"kind": "all"},
                        "facets": {"kind": "all"},
                        "bands": {"kind": "all"},
                        "audience": {"kind": "all"},
                        "verbs": {"kind": "some", "values": verbs},
                        "sensitivity": {"kind": "at_most", "value": "restricted"},
                    },
                    "verb_classes": classes,
                }),
            )
            .await);
        assert_eq!(body["grant"]["confers"], true, "{body}");
        serde_json::from_value(body["grant"]["grant_ref"].clone()).expect("minted Grant id")
    }

    async fn revoke(&self, grant: EntityId) {
        let body = ok(self
            .as_owner("vault.agents.grants.revoke", json!({"grant_ref": grant}))
            .await);
        assert_eq!(body["changed"], true, "{body}");
    }

    async fn allow(&self, grant: EntityId) {
        let body = ok(self
            .as_owner(
                "vault.gpu.jobs.allow",
                json!({"grant": grant, "maximum_secs": MAXIMUM_SECS}),
            )
            .await);
        assert_eq!(body["maximum_secs"], MAXIMUM_SECS, "{body}");
    }

    async fn pin(&self, template_digest: &str, tag: &str) -> String {
        let body = ok(self.as_owner("vault.jobs.workloads.pin", json!({"pin": {
            "template": PROBE_TEMPLATE,
            "template_digest": template_digest,
            "commit": "a".repeat(40),
            "contract_sha256": "b".repeat(64),
            "contract_path": "contract.json",
            "entry": "tools/units/run.sh",
            "args": [tag],
            "request": {"cpu_threads": 0, "memory_mib": 0, "disk_mib": 0, "devices": [], "maximum_secs": MAXIMUM_SECS},
            "scope": "host", "network": "none", "outputs": [],
        }})).await);
        body["workload"]["digest"]
            .as_str()
            .expect("pinned workload digest")
            .to_owned()
    }

    async fn pin_without_machine(&self) -> String {
        self.pin(&"0".repeat(64), "no machine").await
    }
}

fn ok((status, body): (StatusCode, Value)) -> Value {
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

fn order_view(reply: (StatusCode, Value)) -> WorkOrderView {
    serde_json::from_value(ok(reply)).expect("work order view")
}

fn wait_answer(reply: (StatusCode, Value)) -> WorkOrderWaitAnswer {
    serde_json::from_value(ok(reply)).expect("work order wait answer")
}

fn order_input(workload: &str, intent_key: &str) -> Value {
    json!({"workload": workload, "charge": {"kind": "offer", "name": OFFER},
        "wait": {"kind": "open"}, "intent_key": intent_key})
}

fn open_without_attempt(view: &WorkOrderView) {
    assert!(
        matches!(view.order.state, OrderState::Open { .. }),
        "{view:?}"
    );
    assert!(view.order.attempts.is_empty(), "{view:?}");
}

fn under_grant(view: &WorkOrderView, agent: &Agent, grant: EntityId) {
    assert_eq!(
        view.order.ordered_by,
        OrderedBy::Agent {
            actor: Some(agent.principal),
            class: EdgeActorClass::Agent,
            grant,
        }
    );
}

#[test]
fn an_order_ends_when_its_own_grant_is_revoked_while_another_grant_names_the_verb() {
    run_on_engine_stack("order-revoked-grant", || async {
        let (_dir, http) = setup();
        let agent = http.pair_agent("revoked-grant", 0x61);
        let verbs = &[ORDER_VERB, GPU_START, ORDERS_GET_VERB];
        let a = http.mint(&agent, verbs).await;
        let b = http.mint(&agent, verbs).await;
        assert!(a < b, "the first Grant must stand first");
        http.allow(a).await;
        let workload = http.pin_without_machine().await;
        let first = order_view(
            http.as_agent(&agent, ORDER_VERB, order_input(&workload, "under A"))
                .await,
        );
        under_grant(&first, &agent, a);
        open_without_attempt(&first);

        http.revoke(a).await;
        http.allow(b).await;
        // B still admits a fresh order, and that door runs the next pass.
        let next = order_view(
            http.as_agent(&agent, ORDER_VERB, order_input(&workload, "under B"))
                .await,
        );
        under_grant(&next, &agent, b);
        open_without_attempt(&next);
        let ended = order_view(
            http.as_agent(&agent, ORDERS_GET_VERB, json!({"order": first.order.id}))
                .await,
        );
        assert_eq!(
            ended.order.state,
            OrderState::Cancelled {
                why: CancelWhy::AuthorityEnded
            }
        );
        assert!(ended.order.attempts.is_empty(), "{ended:?}");
    });
}

#[test]
fn an_agent_offer_order_needs_the_grant_that_starts_its_jobs() {
    run_on_engine_stack("order-start-grant", || async {
        let rack = Rack::start().await;
        let http = &rack.http;
        let agent = http.pair_agent("start-grant", 0x62);
        let weak = http.mint(&agent, &[ORDER_VERB]).await;
        let workload = http.pin(&rack.template_digest, "start grant").await;
        let input = order_input(&workload, "start-grant-order");
        let (status, refused) = http.as_agent(&agent, ORDER_VERB, input.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
        assert_eq!(refused["error"]["code"], MEMORY_CODE_FORBIDDEN, "{refused}");
        assert_eq!(
            refused["error"]["reasonCodes"],
            json!([Blocker::GrantNotLive.code()]),
            "{refused}"
        );

        http.revoke(weak).await;
        let grant = http.mint(&agent, &[ORDER_VERB, GPU_START]).await;
        http.allow(grant).await;
        rack.approve(&workload, &[grant]).await;
        let ordered = order_view(http.as_agent(&agent, ORDER_VERB, input).await);
        under_grant(&ordered, &agent, grant);
        assert!(
            matches!(ordered.order.state, OrderState::Running { .. }),
            "{ordered:?}"
        );
        assert_eq!(ordered.order.attempts.len(), 1, "{ordered:?}");
        rack.mesh.stop().await;
    });
}

fn rank_options(view: &WorkOrderView) -> &[String] {
    &view
        .order
        .attempts
        .first()
        .unwrap_or_else(|| panic!("no ranked attempt: {view:?}"))
        .ranked
        .options
}

#[test]
fn an_agent_reads_no_other_orders_id_in_a_rank_decision() {
    run_on_engine_stack("order-rank-visibility", || async {
        let rack = Rack::start().await;
        let http = &rack.http;
        let a = http.pair_agent("rank-a", 0x63);
        let b = http.pair_agent("rank-b", 0x64);
        let verbs = &[ORDER_VERB, GPU_START, ORDERS_GET_VERB];
        let grant_a = http.mint(&a, verbs).await;
        let grant_b = http.mint(&b, verbs).await;
        http.allow(grant_a).await;
        http.allow(grant_b).await;

        // Each agent gets a fresh (non-replay) order answer with a shared rank
        // decision. The first agent in each pair then repeats its queued call.
        for (first, second, tag) in [(&a, &b, "a first"), (&b, &a, "b first")] {
            let workload = http.pin(&rack.template_digest, tag).await;
            let input = order_input(&workload, tag);
            let queued = order_view(http.as_agent(first, ORDER_VERB, input.clone()).await);
            open_without_attempt(&queued);
            rack.approve(&workload, &[grant_a, grant_b]).await;
            let fresh = order_view(http.as_agent(second, ORDER_VERB, input.clone()).await);
            assert!(!fresh.replayed);
            assert_ne!(fresh.order.id, queued.order.id);
            assert_eq!(rank_options(&fresh), [fresh.order.id.to_hex()]);
            let replay = order_view(http.as_agent(first, ORDER_VERB, input).await);
            assert!(replay.replayed);
            assert_eq!(replay.order.id, queued.order.id);
            assert_eq!(rank_options(&replay), [queued.order.id.to_hex()]);

            let mut both = [queued.order.id.to_hex(), fresh.order.id.to_hex()];
            both.sort();
            for (agent, id) in [(first, queued.order.id), (second, fresh.order.id)] {
                let query = json!({"order": id});
                let own = order_view(http.as_agent(agent, ORDERS_GET_VERB, query.clone()).await);
                assert_eq!(own.order.id, id);
                assert_eq!(rank_options(&own), [id.to_hex()]);
                let owner = order_view(http.as_owner(ORDERS_GET_VERB, query).await);
                let mut options = rank_options(&owner).to_vec();
                options.sort();
                assert_eq!(options, both, "the owner sees both runnable orders");
            }
        }
        rack.mesh.stop().await;
    });
}

#[test]
fn a_wait_on_an_order_another_agent_made_is_not_found() {
    run_on_engine_stack("order-wait-visibility", || async {
        let (_dir, http) = setup();
        let x = http.pair_agent("waiting-agent", 0x65);
        let y = http.pair_agent("ordering-agent", 0x66);
        http.mint(&x, &[ORDERS_WAIT_VERB]).await;
        let grant = http
            .mint(&y, &[ORDER_VERB, GPU_START, ORDERS_WAIT_VERB])
            .await;
        http.allow(grant).await;
        let workload = http.pin_without_machine().await;
        let ordered = order_view(
            http.as_agent(&y, ORDER_VERB, order_input(&workload, "private order"))
                .await,
        );
        let wait = json!({"order": ordered.order.id, "until": WaitUntil::Terminal});
        let (other_status, other) = http.as_agent(&x, ORDERS_WAIT_VERB, wait.clone()).await;
        let (missing_status, missing) = http
            .as_agent(
                &x,
                ORDERS_WAIT_VERB,
                json!({
                    "order": EntityId::now(), "until": WaitUntil::Terminal,
                }),
            )
            .await;
        assert_eq!(other_status, StatusCode::NOT_FOUND, "{other}");
        assert_eq!(missing_status, other_status, "{missing}");
        assert_eq!(other["error"]["code"], MEMORY_CODE_NOT_FOUND, "{other}");
        // Per-call request and receipt ids can differ, but the refusal cannot.
        for field in ["code", "message", "suggestions", "reasonCodes"] {
            assert_eq!(
                other["error"][field], missing["error"][field],
                "{field}: {other} vs {missing}"
            );
        }
        let requester = wait_answer(http.as_agent(&y, ORDERS_WAIT_VERB, wait.clone()).await);
        let owner = wait_answer(http.as_owner(ORDERS_WAIT_VERB, wait).await);
        assert_eq!(requester, owner);
        assert_eq!(requester.view.order.id, ordered.order.id);
        assert!(!requester.reached);
        open_without_attempt(&requester.view);
    });
}

#[test]
fn the_host_wait_answers_at_once_and_reached_turns_true_at_the_end() {
    run_on_engine_stack("order-wait-milestones", || async {
        let (_dir, http) = setup();
        let y = http.pair_agent("cancelling-agent", 0x67);
        let grant = http
            .mint(
                &y,
                &[ORDER_VERB, GPU_START, ORDERS_WAIT_VERB, ORDERS_CANCEL_VERB],
            )
            .await;
        http.allow(grant).await;
        let workload = http.pin_without_machine().await;
        let ordered = order_view(
            http.as_agent(&y, ORDER_VERB, order_input(&workload, "cancel while open"))
                .await,
        );
        let id = ordered.order.id;
        let terminal = json!({"order": id, "until": WaitUntil::Terminal});
        // Nothing can finish this order while the call is in flight. A parked
        // HTTP wait would hang, so bound this first request.
        let before = wait_answer(
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                http.as_agent(&y, ORDERS_WAIT_VERB, terminal.clone()),
            )
            .await
            .expect("the HTTP wait must not park"),
        );
        assert!(!before.reached);
        assert_eq!(before.view.order.id, id);
        open_without_attempt(&before.view);

        let ended = order_view(
            http.as_agent(&y, ORDERS_CANCEL_VERB, json!({"order": id}))
                .await,
        );
        assert_eq!(
            ended.order.state,
            OrderState::Cancelled {
                why: CancelWhy::Asked {
                    by: Some(y.principal)
                }
            }
        );
        assert!(ended.order.attempts.is_empty());
        let after = wait_answer(http.as_agent(&y, ORDERS_WAIT_VERB, terminal).await);
        assert!(after.reached);
        assert_eq!(after.view, ended);
        let started = wait_answer(
            http.as_agent(
                &y,
                ORDERS_WAIT_VERB,
                json!({"order": id, "until": WaitUntil::Started}),
            )
            .await,
        );
        assert_eq!(
            started, after,
            "a terminal order also reaches started without an attempt"
        );
    });
}

#[test]
fn a_place_read_under_one_grant_answers_for_the_grant_that_orders() {
    run_on_engine_stack("place-order-grant", || async {
        let rack = Rack::start().await;
        let http = &rack.http;
        let agent = http.pair_agent("split-place-grants", 0x68);
        http.mint(&agent, &[MACHINES_PLACE_VERB]).await;
        let workload = http.pin(&rack.template_digest, "place grant").await;
        let input = json!({"workload": workload});
        let (status, refused) = http
            .as_agent(&agent, MACHINES_PLACE_VERB, input.clone())
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
        assert_eq!(refused["error"]["code"], MEMORY_CODE_FORBIDDEN, "{refused}");
        assert!(
            refused["error"]["message"]
                .as_str()
                .expect("message")
                .contains(ORDER_VERB),
            "{refused}"
        );

        let order_grant = http.mint(&agent, &[ORDER_VERB, GPU_START]).await;
        http.allow(order_grant).await;
        rack.approve(&workload, &[order_grant]).await;
        let placed = ok(http.as_agent(&agent, MACHINES_PLACE_VERB, input).await);
        assert_eq!(placed["candidates"], json!([rack.machine]), "{placed}");
        rack.mesh.stop().await;
    });
}

#[test]
fn an_order_survives_an_outranking_start_grant() {
    run_on_engine_stack("order-outranking-grant", || async {
        let rack = Rack::start().await;
        let http = &rack.http;
        let agent = http.pair_agent("outranking-grant", 0x69);
        let start_class = "order-fixture-start";
        // GAP: the mint has no chosen-id input, so it cannot mint B < A after
        // ordering. Mint B first with an empty (undefined) verb class; make it
        // stand for start, but not order, by defining that class after ordering.
        let b = http.mint_with_classes(&agent, &[], &[start_class]).await;
        let a = http
            .mint(&agent, &[ORDER_VERB, GPU_START, ORDERS_GET_VERB])
            .await;
        assert!(
            b < a,
            "B must outrank A for GPU start once the class is defined"
        );
        http.allow(a).await;
        let workload = http.pin(&rack.template_digest, "outranked grant").await;
        let ordered = order_view(
            http.as_agent(&agent, ORDER_VERB, order_input(&workload, "under A"))
                .await,
        );
        open_without_attempt(&ordered);
        under_grant(&ordered, &agent, a);
        let id = ordered.order.id;
        let memory = http.vault.memory(agent.principal, EdgeActorClass::Agent);
        assert_eq!(
            memory
                .verb_grant_caller_admits(None, GPU_START)
                .expect("start standing before class edit"),
            VerbGrantCaller::Agent {
                actor: agent.principal,
                grant: a
            }
        );

        let config = ok(http
            .as_owner("vault.agents.verb_classes.get", json!({}))
            .await);
        let mut classes = config["classes"].as_array().expect("verb classes").clone();
        classes.push(json!({"name": start_class, "verbs": [GPU_START]}));
        ok(http
            .as_owner(
                "vault.agents.verb_classes.configure",
                json!({
                    "expected_body_hash": config["body_hash"], "classes": classes,
                }),
            )
            .await);
        assert_eq!(
            memory
                .verb_grant_caller_admits(None, GPU_START)
                .expect("start standing after class edit"),
            VerbGrantCaller::Agent {
                actor: agent.principal,
                grant: b
            }
        );
        assert_eq!(
            memory
                .verb_grant_caller_admits(None, ORDER_VERB)
                .expect("order standing after class edit"),
            VerbGrantCaller::Agent {
                actor: agent.principal,
                grant: a
            }
        );

        let trigger = http.pin_without_machine().await;
        order_view(
            http.as_owner(ORDER_VERB, order_input(&trigger, "recheck authority"))
                .await,
        );
        let waiting = order_view(
            http.as_agent(&agent, ORDERS_GET_VERB, json!({"order": id}))
                .await,
        );
        open_without_attempt(&waiting);
        under_grant(&waiting, &agent, a);

        rack.approve(&workload, &[a]).await;
        order_view(
            http.as_owner(
                ORDER_VERB,
                order_input(&trigger, "place the original order"),
            )
            .await,
        );
        let running = order_view(
            http.as_agent(&agent, ORDERS_GET_VERB, json!({"order": id}))
                .await,
        );
        assert!(
            matches!(running.order.state, OrderState::Running { .. }),
            "{running:?}"
        );
        under_grant(&running, &agent, a);
        assert_eq!(running.order.attempts.len(), 1, "{running:?}");
        let job = http
            .vault
            .gpu_job(&running.order.attempts[0].job)
            .expect("read the paid job")
            .expect("the attempt has a paid job");
        let allowance = http
            .vault
            .gpu_job_allowance(&a)
            .expect("read A's allowance")
            .expect("A still has an allowance");
        assert_eq!(allowance.maximum_secs, MAXIMUM_SECS);
        assert_eq!(job.started_by, Some(agent.principal));
        assert_eq!(
            job.chunk()
                .expect("the first paid chunk")
                .quote
                .maximum_secs,
            allowance.maximum_secs
        );
        // B has no allowance and could not have paid for the quote.
        assert!(
            http.vault
                .gpu_job_allowance(&b)
                .expect("B's allowance")
                .is_none()
        );
        rack.mesh.stop().await;
    });
}

/// Row P1: the PLACE slot's decider is asked through this host's decision ladder, as one read of
/// the decider's agent. A host with no decision model keeps the rule's pick, and the attempt
/// records that the named decider was asked and why the rule stood.
#[test]
fn a_named_decider_with_no_decision_model_on_the_host_keeps_the_rule() {
    use oneiron::work_order::DecidedBy;
    use oneiron::work_order::decider::{DECIDER_VERB, DeciderMiss};
    run_on_engine_stack("order-decider-no-model", || async {
        let rack = Rack::start().await;
        let http = &rack.http;
        let decider_agent = http.pair_agent("slot-decider", 0x6d);
        let decider = http.mint(&decider_agent, &[DECIDER_VERB]).await;
        let set = ok(http
            .as_owner(
                "vault.settings.set",
                json!({
                    "key": "policy.slots.decider",
                    "item": "place",
                    "scope": {"kind": "vault"},
                    "value": decider,
                }),
            )
            .await);
        assert_eq!(set["status"], "applied", "{set}");

        let agent = http.pair_agent("decided-orders", 0x6e);
        let grant = http
            .mint(&agent, &[ORDER_VERB, GPU_START, ORDERS_GET_VERB])
            .await;
        http.allow(grant).await;
        let workload = http.pin(&rack.template_digest, "decided placement").await;
        rack.approve(&workload, &[grant]).await;
        // One machine and an open wait: two lawful options, so the decider is asked.
        let ordered = order_view(
            http.as_agent(
                &agent,
                ORDER_VERB,
                order_input(&workload, "decider, no model"),
            )
            .await,
        );
        let placed = order_view(
            http.as_agent(&agent, ORDERS_GET_VERB, json!({"order": ordered.order.id}))
                .await,
        );
        assert!(
            matches!(placed.order.state, OrderState::Running { .. }),
            "{placed:?}"
        );
        let attempt = &placed.order.attempts[0];
        assert_eq!(attempt.machine, Some(rack.machine));
        assert!(
            matches!(
                &attempt.placed.by,
                DecidedBy::RuleKept { decider: by, miss: DeciderMiss::NoModel, .. }
                    if *by == decider
            ),
            "{:?}",
            attempt.placed.by
        );
        rack.mesh.stop().await;
    });
}
