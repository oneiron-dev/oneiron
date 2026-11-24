#![cfg(all(oneiron_test_support, feature = "mesh"))]
//! DESIGN 33 tests T34–T36f for the vault machine connector (except T36c).
//!
//! Run on the fleet, not on a workstation:
//! ```sh
//! RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support --test vault_machine_connector
//! ```

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/mesh_machines.rs"]
mod mesh_machines;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use ed25519_dalek::{Signature, Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use mesh_machines::Machines;
use oneiron::consent::AuthenticatedOwner;
use oneiron::gpu_job::{
    GpuConnectorError, GpuEndReason, GpuJob, GpuJobActor, GpuJobConnector, GpuJobEnd, GpuJobError,
    GpuJobPermits, GpuJobRequest, GpuJobSignal, GpuJobSpec, GpuJobStart, GpuJobState,
    GpuJobStepReport, GpuOffer, GpuResourceRef, GpuResourceStatus, GpuTermination, MeterVerdict,
    PriceShape,
};
use oneiron::job_dispatch::{BootMark, DispatchClose, DispatchPhase, JobDispatch, JobObservation};
use oneiron::job_workload::{
    WorkloadApproveRequest, WorkloadCaller, WorkloadPinRequest, WorkloadRef, WorkloadStartRefusal,
};
use oneiron::llm::ModelLocality;
use oneiron::llm::run_admission::{
    BudgetLine, KeyCustody, LeaseUnit, MemoryReceipts, OfferRoute, PaidConnector, Payer,
    RunAdmission, RunDeclaration, RunEvent,
};
use oneiron::machine_signature::{
    MachineSignatureError, MachineSignatures, machine_signature_transcript,
};
use oneiron::test_doors::steward;
use oneiron::{EntityId, Vault};
use oneiron_server::config::SyncServerConfig;
use oneiron_server::config::gpu_jobs::VaultMachineSettings;
use oneiron_server::gpu_execution_node::issuer::{
    IssuerClock, JobNodeClient, LoggedOrphanKeys, NodeCallError, VAULT_MACHINE_BACKEND,
    VaultMachineConnector, VaultMachineNotRegistered, VaultMachineParts, not_the_issuer,
    refusal_code_for_caller, vault_machine_backend, vault_machine_inputs,
};
use oneiron_server::gpu_execution_node::wire::{
    DeviceRelease, JOB_ALPN, JOB_STATUS_ALPN, JobAnswer, JobEnd, JobReceipt, JobRefusal,
    JobRequest, JobState, JobStatusAnswer, JobStatusRequest, KeyEntry, KeyPage, NetworkMode,
    NodeAnswer, OutputsState, ScopeClass, SignedJobReceipt, TemplateOffer,
};
use oneiron_server::server::SyncServer;
use serde::Serialize;
use serde_json::json;

const NOW_MS: u64 = 1_800_000_000_000;
const FAR_EXPIRY_MS: u64 = 4_102_444_800_000;
const MAXIMUM_SECS: u64 = 1_800;
const TEMPLATE: &str = "fixture-workload";
const TEMPLATE_DIGEST: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const CONTRACT_SHA256: &str = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

struct FakeSigners {
    local: EntityId,
    keys: Arc<BTreeMap<EntityId, SigningKey>>,
}

impl FakeSigners {
    fn new(issuer: EntityId, node: EntityId) -> Self {
        Self {
            local: issuer,
            keys: Arc::new(BTreeMap::from([
                (issuer, SigningKey::from_bytes(&[11; 32])),
                (node, SigningKey::from_bytes(&[12; 32])),
            ])),
        }
    }

    fn as_machine(&self, local: EntityId) -> Arc<dyn MachineSignatures> {
        Arc::new(Self {
            local,
            keys: Arc::clone(&self.keys),
        })
    }
}

impl MachineSignatures for FakeSigners {
    fn sign(
        &self,
        domain: &[u8],
        message: &[u8],
    ) -> Result<(EntityId, [u8; 64]), MachineSignatureError> {
        let key = self
            .keys
            .get(&self.local)
            .ok_or(MachineSignatureError::NoMachineKey)?;
        let signature = key.sign(&machine_signature_transcript(domain, message));
        Ok((self.local, signature.to_bytes()))
    }

    fn verify(
        &self,
        machine: EntityId,
        domain: &[u8],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), MachineSignatureError> {
        let key = self
            .keys
            .get(&machine)
            .ok_or(MachineSignatureError::UnknownMachine { machine })?;
        key.verifying_key()
            .verify_strict(
                &machine_signature_transcript(domain, message),
                &Signature::from_bytes(signature),
            )
            .map_err(|_| MachineSignatureError::Mismatch { machine })
    }
}

struct ScriptedClock(Mutex<BootMark>);

impl ScriptedClock {
    fn new(now_ms: u64) -> Self {
        Self(Mutex::new(BootMark {
            boot_id: "boot-a".to_owned(),
            boot_ns: 1_000_000_000,
            wall_ms: now_ms,
        }))
    }

    fn advance_secs(&self, secs: u64) {
        let mut mark = self.0.lock().expect("scripted clock lock");
        mark.wall_ms += secs * 1_000;
        mark.boot_ns += secs * 1_000_000_000;
    }

    #[allow(dead_code)] // Control for scenarios that cross an issuer boot.
    fn reboot(&self, boot_id: &str) {
        let mut mark = self.0.lock().expect("scripted clock lock");
        mark.boot_id = boot_id.to_owned();
        mark.boot_ns = 0;
    }
}

impl IssuerClock for ScriptedClock {
    fn now_ms(&self) -> u64 {
        self.0.lock().expect("scripted clock lock").wall_ms
    }

    fn boot_mark(&self) -> BootMark {
        self.0.lock().expect("scripted clock lock").clone()
    }
}

#[derive(Clone, Debug)]
struct Call {
    node: EntityId,
    kind: &'static str,
    key: Option<String>,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct NodeState {
    journal: BTreeMap<String, SignedJobReceipt>,
    generation: u64,
    seq: u64,
    calls: Vec<Call>,
    unreachable: bool,
    drop_next: Option<&'static str>,
    refuse_submits: Option<String>,
}

impl NodeState {
    fn epoch(&self) -> String {
        format!("epoch-{}", self.generation)
    }

    fn record(
        &mut self,
        node: EntityId,
        kind: &'static str,
        key: Option<&str>,
        request: &impl Serialize,
    ) -> Result<(), NodeCallError> {
        self.calls.push(Call {
            node,
            kind,
            key: key.map(str::to_owned),
            bytes: oneiron_organ_protocol::to_vec(request).expect("encode the recorded request"),
        });
        if self.unreachable {
            return Err(NodeCallError::Unreachable {
                reason: "scripted node is offline".to_owned(),
            });
        }
        if self.drop_next == Some(kind) {
            self.drop_next = None;
            return Err(NodeCallError::Timeout);
        }
        Ok(())
    }

    fn known_or_absent(&self, key: &str) -> JobStatusAnswer {
        match self.journal.get(key) {
            Some(receipt) => JobStatusAnswer::Known(receipt.clone()),
            None => JobStatusAnswer::Absent {
                epoch: self.epoch(),
            },
        }
    }
}

struct ScriptedNode {
    machine: EntityId,
    issuer: EntityId,
    signer: Arc<dyn MachineSignatures>,
    clock: Arc<ScriptedClock>,
    state: Mutex<NodeState>,
}

impl ScriptedNode {
    fn state(&self) -> MutexGuard<'_, NodeState> {
        self.state.lock().expect("scripted node lock")
    }

    fn calls(&self) -> Vec<Call> {
        self.state().calls.clone()
    }

    fn unreachable(&self, yes: bool) {
        self.state().unreachable = yes;
    }

    fn drop_next(&self, kind: &'static str) {
        self.state().drop_next = Some(kind);
    }

    fn refuse_submits(&self, reason: Option<&str>) {
        self.state().refuse_submits = reason.map(str::to_owned);
    }

    fn forget_journal(&self) {
        let mut node = self.state();
        node.journal.clear();
        node.generation += 1;
        node.seq = 0;
    }

    fn advance(
        &self,
        key: &str,
        state: JobState,
        measured_secs: Option<u64>,
        end: Option<JobEnd>,
        started: bool,
    ) {
        let mut node = self.state();
        let mut receipt = node
            .journal
            .get(key)
            .expect("advance a known key")
            .receipt
            .clone();
        receipt.state = state;
        receipt.measured_secs = measured_secs;
        receipt.end = end;
        receipt.started = started;
        if started {
            receipt.device_id = Some("scripted-gpu".to_owned());
            receipt.release = DeviceRelease::Held;
        }
        self.publish(&mut node, receipt);
    }

    fn blank(&self, key: &str) -> JobReceipt {
        JobReceipt {
            key: key.to_owned(),
            machine: self.machine,
            epoch: String::new(),
            device_id: None,
            issuer: self.issuer,
            starter: None,
            hold: None,
            workload: None,
            state: JobState::Held,
            started: false,
            end: None,
            occupied: None,
            measured_secs: None,
            cutoff_at_ms: None,
            release: DeviceRelease::NotHeld,
            outputs: OutputsState::Pending,
            scope: None,
            other_compute_pids: Vec::new(),
            seq: 0,
            boot_id: "node-boot".to_owned(),
            reported_at_ms: 0,
        }
    }

    fn publish(&self, node: &mut NodeState, mut receipt: JobReceipt) -> SignedJobReceipt {
        node.seq += 1;
        receipt.seq = node.seq;
        receipt.epoch = node.epoch();
        receipt.reported_at_ms = self.clock.now_ms();
        let signed =
            SignedJobReceipt::sign(receipt, self.signer.as_ref()).expect("sign node receipt");
        node.journal
            .insert(signed.receipt.key.clone(), signed.clone());
        signed
    }

    fn stop(&self, node: &mut NodeState, key: &str) -> SignedJobReceipt {
        let mut receipt = match node.journal.get(key) {
            Some(known) if matches!(known.receipt.state, JobState::Ending | JobState::Ended) => {
                return known.clone();
            }
            Some(known) => known.receipt.clone(),
            None => self.blank(key),
        };
        if receipt.state == JobState::Running {
            receipt.state = JobState::Ending;
        } else {
            receipt.state = JobState::Ended;
            receipt.started = false;
            receipt.end = Some(JobEnd::Withdrawn);
            receipt.measured_secs = None;
            receipt.device_id = None;
            receipt.release = DeviceRelease::NotHeld;
        }
        self.publish(node, receipt)
    }
}

impl JobNodeClient for ScriptedNode {
    fn job(&self, machine: EntityId, request: &JobRequest) -> Result<JobAnswer, NodeCallError> {
        let mut node = self.state();
        let (kind, key) = match request {
            JobRequest::Node => ("node", None),
            JobRequest::Reserve(req) => ("reserve", Some(req.key.as_str())),
            JobRequest::Release { key } => ("release", Some(key.as_str())),
            JobRequest::Submit(req) => ("submit", Some(req.submit.key.as_str())),
        };
        node.record(machine, kind, key, request)?;
        Ok(match request {
            JobRequest::Node => JobAnswer::Node(NodeAnswer {
                enabled: true,
                paused: None,
                drained: None,
                templates: vec![TemplateOffer {
                    name: TEMPLATE.to_owned(),
                    digest: TEMPLATE_DIGEST.to_owned(),
                    scopes: vec![ScopeClass::Host],
                    network: vec![NetworkMode::None],
                    returnable: vec!["verdict.json".to_owned()],
                }],
                disk_free_bytes: 10 << 30,
                disk_reserved_bytes: 0,
                disk_reserve_bytes: 0,
                epoch: Some(node.epoch()),
                swept: true,
                boot_id: "node-boot".to_owned(),
                engine_version: "scripted".to_owned(),
            }),
            JobRequest::Reserve(req) => {
                if let Some(receipt) = node.journal.get(&req.key) {
                    return Ok(JobAnswer::Receipt(receipt.clone()));
                }
                let mut receipt = self.blank(&req.key);
                receipt.starter = Some(req.starter);
                receipt.workload = Some(req.pin.digest().expect("digest the reserved workload"));
                JobAnswer::Receipt(self.publish(&mut node, receipt))
            }
            JobRequest::Release { key } => match node.journal.get(key).map(|r| r.receipt.state) {
                Some(JobState::Held) => JobAnswer::Receipt(self.stop(&mut node, key)),
                Some(state) => JobAnswer::Refused(JobRefusal::NotReleasable { state }),
                None => JobAnswer::Refused(JobRefusal::KeyConflict),
            },
            JobRequest::Submit(signed) => {
                if signed.verify(self.signer.as_ref()).is_err() {
                    return Ok(JobAnswer::Refused(JobRefusal::SubmitSignatureInvalid));
                }
                let submit = &signed.submit;
                if submit.issuer != self.issuer {
                    return Ok(JobAnswer::Refused(JobRefusal::NotIssuer));
                }
                let (mut receipt, refusal) = match node.journal.get(&submit.key) {
                    Some(known) if known.receipt.state != JobState::Held => {
                        return Ok(JobAnswer::Receipt(known.clone()));
                    }
                    Some(known) => (known.receipt.clone(), node.refuse_submits.clone()),
                    None => {
                        let mut receipt = self.blank(&submit.key);
                        receipt.starter = Some(submit.starter);
                        receipt.workload =
                            Some(submit.pin.digest().expect("digest the submitted workload"));
                        (receipt, Some("not_reserved".to_owned()))
                    }
                };
                if let Some(reason) = refusal {
                    receipt.state = JobState::Ended;
                    receipt.end = Some(JobEnd::Refused { reason });
                } else {
                    receipt.state = JobState::Accepted;
                    receipt.hold = Some(submit.hold.clone());
                }
                JobAnswer::Receipt(self.publish(&mut node, receipt))
            }
        })
    }

    fn job_status(
        &self,
        machine: EntityId,
        request: &JobStatusRequest,
    ) -> Result<JobStatusAnswer, NodeCallError> {
        let mut node = self.state();
        let (kind, key) = match request {
            JobStatusRequest::Find { key } => ("find", Some(key.as_str())),
            JobStatusRequest::Status { key } => ("status", Some(key.as_str())),
            JobStatusRequest::Signal { key, .. } => ("signal", Some(key.as_str())),
            JobStatusRequest::Stop { key } => ("stop", Some(key.as_str())),
            JobStatusRequest::Keys { .. } => ("keys", None),
            JobStatusRequest::Fetch { key, .. } => ("fetch", Some(key.as_str())),
            JobStatusRequest::Ack { key } => ("ack", Some(key.as_str())),
        };
        node.record(machine, kind, key, request)?;
        Ok(match request {
            JobStatusRequest::Find { key } | JobStatusRequest::Status { key } => {
                node.known_or_absent(key)
            }
            JobStatusRequest::Stop { key } => JobStatusAnswer::Known(self.stop(&mut node, key)),
            JobStatusRequest::Keys { after } => JobStatusAnswer::Keys(KeyPage {
                entries: node
                    .journal
                    .iter()
                    .filter(|(key, _)| after.as_deref().is_none_or(|after| key.as_str() > after))
                    .map(|(key, receipt)| KeyEntry {
                        key: key.clone(),
                        state: receipt.receipt.state,
                        ended: (receipt.receipt.state == JobState::Ended).then(|| receipt.clone()),
                    })
                    .collect(),
                next: None,
            }),
            JobStatusRequest::Signal { .. } | JobStatusRequest::Ack { .. } => {
                JobStatusAnswer::Acknowledged
            }
            // The script never produces an output to fetch.
            JobStatusRequest::Fetch { .. } => JobStatusAnswer::Refused(JobRefusal::NotEnabled),
        })
    }
}

struct Rig {
    mesh: Machines,
    issuer: EntityId,
    owner: AuthenticatedOwner,
    offer: GpuOffer,
    permits: GpuJobPermits,
    signers: FakeSigners,
    clock: Arc<ScriptedClock>,
    node: Arc<ScriptedNode>,
    connector: VaultMachineConnector,
}

struct JobRun {
    job: GpuJob,
    admission: RunAdmission,
    receipts: Arc<MemoryReceipts>,
}

impl JobRun {
    fn key(&self) -> &str {
        &self
            .job
            .chunk()
            .expect("the job has a chunk")
            .idempotency_key
    }

    fn settled(&self) -> Vec<u64> {
        self.receipts
            .rows()
            .into_iter()
            .filter_map(|row| match row.event {
                RunEvent::Settled { units, .. } => Some(units),
                _ => None,
            })
            .collect()
    }
}

fn settings(issuer: EntityId) -> VaultMachineSettings {
    VaultMachineSettings {
        enabled: true,
        issuer: Some(issuer),
        ..VaultMachineSettings::default()
    }
}

fn make_connector(
    vault: &Arc<Vault>,
    issuer: EntityId,
    signers: &FakeSigners,
    clock: &Arc<ScriptedClock>,
    node: &Arc<ScriptedNode>,
) -> VaultMachineConnector {
    VaultMachineConnector::new(VaultMachineParts {
        vault: Arc::clone(vault),
        issuer,
        client: node.clone(),
        signer: signers.as_machine(issuer),
        clock: clock.clone(),
        orphans: Arc::new(LoggedOrphanKeys),
        settings: settings(issuer),
    })
}

fn offer() -> GpuOffer {
    GpuOffer {
        name: "scripted-gpu".to_owned(),
        class: "fixture".to_owned(),
        provider: "vault".to_owned(),
        region: "test".to_owned(),
        connector: PaidConnector {
            connector: VAULT_MACHINE_BACKEND.to_owned(),
            route: OfferRoute::new(VAULT_MACHINE_BACKEND, "https://gpu.invalid")
                .expect("fixture route"),
            locality: ModelLocality::ThirdParty,
            payer: Payer::Local,
            credential_binding: None,
            catalog_revision: None,
            custody: KeyCustody::T0,
            unit_cost: 1,
            cost_unit: LeaseUnit::new("credit-micros").expect("fixture billing unit"),
            rates: Vec::new(),
        },
        price_shape: PriceShape::AtOneironList,
        list_cost_per_second: None,
        startup_secs: 0,
        teardown_secs: 0,
        rounding_secs: 0,
    }
}

impl Rig {
    async fn start() -> Self {
        let mesh = Machines::start_granted(2, &[JOB_ALPN, JOB_STATUS_ALPN])
            .await
            .expect("two machines with both job protocol grants");
        let issuer = mesh.machine(0).device.machine;
        let machine = mesh.machine(1).device.machine;
        let vault = &mesh.machine(0).device.vault;
        let owner = steward::owner(vault).expect("owner proof on the issuer");
        let signers = FakeSigners::new(issuer, machine);
        let clock = Arc::new(ScriptedClock::new(NOW_MS));
        let node = Arc::new(ScriptedNode {
            machine,
            issuer,
            signer: signers.as_machine(machine),
            clock: clock.clone(),
            state: Mutex::new(NodeState::default()),
        });
        let connector = make_connector(vault, issuer, &signers, &clock, &node);
        Self {
            mesh,
            issuer,
            owner,
            offer: offer(),
            permits: GpuJobPermits::new(),
            signers,
            clock,
            node,
            connector,
        }
    }

    fn vault(&self) -> &Arc<Vault> {
        &self.mesh.machine(0).device.vault
    }

    fn approve(&self, tag: &str, expires_at_ms: u64) -> String {
        let request: WorkloadPinRequest = serde_json::from_value(json!({
            "pin": {
                "template": TEMPLATE,
                "template_digest": TEMPLATE_DIGEST,
                "commit": COMMIT,
                "contract_sha256": CONTRACT_SHA256,
                "contract_path": "fixture/contract.json",
                "entry": "fixture/run.py",
                "args": ["--case", tag],
                "request": {
                    "gpus": 1, "vram_mib": 22_528, "memory_mib": 22_528,
                    "disk_mib": 2_048, "maximum_secs": MAXIMUM_SECS,
                },
                "scope": "host",
                "network": "none",
                "outputs": [{"name": "verdict.json", "returnable": true}],
            }
        }))
        .expect("a valid workload pin request");
        let caller = WorkloadCaller::Owner(&self.owner);
        let now = self.clock.now_ms();
        let pinned = self
            .vault()
            .pin_job_workload(caller, &request, now)
            .expect("pin a workload");
        assert!(pinned.changed, "the fixture writes a new workload pin");
        let digest = pinned.workload.digest;
        let approved = self
            .vault()
            .approve_job_workload(
                caller,
                &WorkloadApproveRequest {
                    workload: digest.clone(),
                    machines: vec![self.node.machine.to_hex()],
                    starters: Vec::new(),
                    expires_at_ms,
                },
                now,
            )
            .expect("approve the workload for the node");
        assert!(approved.changed, "the fixture writes an approval");
        digest
    }

    fn start_job(&self, workload: &str) -> JobRun {
        self.start_job_with(workload, &self.connector)
    }

    fn start_job_with(&self, workload: &str, connector: &dyn GpuJobConnector) -> JobRun {
        let now = self.clock.now_ms();
        let quote = self
            .offer
            .quote(
                &GpuJobRequest {
                    job_type: "pinned_workload".to_owned(),
                    image: workload.to_owned(),
                    maximum_secs: Some(MAXIMUM_SECS),
                    inputs: json!({"machine": self.node.machine.to_hex()}),
                },
                None,
                MAXIMUM_SECS,
                now,
            )
            .expect("quote the pinned workload");
        let receipts = Arc::new(MemoryReceipts::default());
        let declaration = RunDeclaration::declared(BudgetLine {
            limit_units: quote.units,
            reserve_units: quote.units,
            unit: quote.unit.clone(),
        })
        .with_connector(VAULT_MACHINE_BACKEND.to_owned());
        let admission = RunAdmission::new(
            GpuJob::admission_ref_of(&quote.job),
            declaration,
            None,
            receipts.clone(),
        );
        let job = self
            .vault()
            .start_gpu_job(
                GpuJobStart {
                    actor: GpuJobActor::Owner(&self.owner),
                    offer: &self.offer,
                    quote: &quote,
                    resume: None,
                    admission: &admission,
                },
                &self.permits,
                connector,
                now,
            )
            .expect("start the quoted workload as owner");
        JobRun {
            job,
            admission,
            receipts,
        }
    }

    fn step(&self, run: &JobRun) -> Result<GpuJobStepReport, GpuJobError> {
        self.step_with(run, &self.connector)
    }

    fn step_with(
        &self,
        run: &JobRun,
        connector: &dyn GpuJobConnector,
    ) -> Result<GpuJobStepReport, GpuJobError> {
        self.vault().gpu_job_step(
            &run.job.id,
            &self.offer,
            &run.admission,
            &self.permits,
            connector,
            self.clock.now_ms(),
        )
    }

    fn settle(&self, run: &JobRun) -> GpuJob {
        for _ in 0..3 {
            let report = self.step(run).expect("step a job whose node has ended it");
            if matches!(report.state, GpuJobState::Ended { .. }) {
                return self
                    .vault()
                    .gpu_job(&run.job.id)
                    .expect("read the settled job")
                    .expect("settled job row");
            }
        }
        panic!(
            "job {} did not settle after a terminal receipt",
            run.job.id.to_hex()
        );
    }

    fn dispatch(&self, run: &JobRun) -> JobDispatch {
        self.vault()
            .job_dispatch(run.key())
            .expect("read JOB_DISPATCH")
            .expect("dispatch row")
    }

    fn observation(&self, run: &JobRun) -> JobObservation {
        self.vault()
            .job_observation(run.key())
            .expect("read JOB_OBSERVATION")
            .expect("observation row")
    }
}

fn with_rig(test: impl FnOnce(&Rig) + Send + 'static) {
    run_on_engine_stack("vault-machine-connector", || async move {
        let rig = Rig::start().await;
        tokio::task::block_in_place(|| test(&rig));
        rig.mesh.stop().await;
    });
}

fn revoke(vault: &Vault, owner: &AuthenticatedOwner, workload: &str, now_ms: u64) {
    let revoked = vault
        .revoke_job_workload(
            WorkloadCaller::Owner(owner),
            &WorkloadRef {
                workload: workload.to_owned(),
            },
            now_ms,
        )
        .expect("the owner revokes the approval");
    assert!(revoked.changed, "the revoke was written");
}

struct RevokeBeforeCreate<'a> {
    inner: &'a VaultMachineConnector,
    vault: &'a Vault,
    owner: &'a AuthenticatedOwner,
    now_ms: u64,
}

impl GpuJobConnector for RevokeBeforeCreate<'_> {
    fn create(&self, key: &str, spec: &GpuJobSpec) -> Result<GpuResourceRef, GpuConnectorError> {
        let id = EntityId::from_hex(&spec.job).expect("the spec names a job id");
        let reserved = self
            .vault
            .gpu_job(&id)
            .expect("read the job")
            .expect("job already reserved");
        assert_eq!(
            reserved.state,
            GpuJobState::Reserved,
            "the revoke comes after reservation"
        );
        revoke(self.vault, self.owner, &spec.image, self.now_ms);
        self.inner.create(key, spec)
    }

    fn find(&self, key: &str) -> Result<Option<GpuResourceRef>, GpuConnectorError> {
        self.inner.find(key)
    }

    fn status(&self, resource: &GpuResourceRef) -> Result<GpuResourceStatus, GpuConnectorError> {
        self.inner.status(resource)
    }

    fn signal(
        &self,
        resource: &GpuResourceRef,
        signal: GpuJobSignal,
    ) -> Result<(), GpuConnectorError> {
        self.inner.signal(resource, signal)
    }

    fn terminate(&self, resource: &GpuResourceRef) -> Result<GpuTermination, GpuConnectorError> {
        self.inner.terminate(resource)
    }
}

#[test]
fn a_create_that_times_out_resends_the_same_bytes_to_the_machine_in_the_job_row() {
    with_rig(|rig| {
        let workload = rig.approve("retry", FAR_EXPIRY_MS);
        rig.node.drop_next("submit");
        let run = rig.start_job(&workload);
        let row = rig.dispatch(&run);
        let resource = GpuResourceRef(format!("{}#{}", rig.node.machine.to_hex(), run.key()));
        assert_eq!(
            row.machine, rig.node.machine,
            "the dispatch row fixes the target"
        );
        assert_eq!(
            row.phase,
            DispatchPhase::Reserved,
            "only the reserve reached the node"
        );
        assert_eq!(
            run.job.state,
            GpuJobState::Running,
            "find recovered the local resource"
        );
        assert_eq!(
            run.job.chunk().and_then(|chunk| chunk.resource.as_ref()),
            Some(&resource),
            "the resource names the dispatch machine and key",
        );

        // Lose the retry as well so the same key is still Held at restart.
        rig.node.drop_next("submit");
        let result = rig.step(&run);
        assert!(
            result.is_ok(),
            "a Held receipt triggers a submit retry, and a lost retry leaves the job pending: {result:?}",
        );
        let before = rig.node.calls();
        let submits: Vec<_> = before.iter().filter(|call| call.kind == "submit").collect();
        assert_eq!(
            submits.len(),
            2,
            "create and the first step each send a submit"
        );
        assert_eq!(
            submits[0].key.as_deref(),
            Some(run.key()),
            "the submit uses the durable key"
        );
        assert_eq!(
            submits[0].bytes, submits[1].bytes,
            "the retry resends the exact body"
        );

        let restarted =
            make_connector(rig.vault(), rig.issuer, &rig.signers, &rig.clock, &rig.node);
        rig.node.drop_next("submit");
        let result = rig.step_with(&run, &restarted);
        assert!(
            result.is_ok(),
            "restart also retries the unanswered submit, which leaves the job pending: {result:?}",
        );
        let calls = rig.node.calls();
        let restart_calls = &calls[before.len()..];
        let keys_at = restart_calls
            .iter()
            .position(|call| call.kind == "keys")
            .expect("restart reconciles the node");
        let submit_at = restart_calls
            .iter()
            .position(|call| call.kind == "submit")
            .expect("restart sends the submit");
        assert!(keys_at < submit_at, "restart reconciles before re-sending");
        assert_eq!(
            restart_calls[submit_at].bytes, submits[0].bytes,
            "restart repeats the original signed body",
        );
        assert!(
            calls.iter().all(|call| call.node == rig.node.machine),
            "all calls target the machine named by the quote: {calls:?}",
        );
    });
}

#[test]
fn an_absent_key_after_a_held_receipt_is_history_lost_and_is_never_sent_again() {
    with_rig(|rig| {
        let workload = rig.approve("lost-journal", FAR_EXPIRY_MS);
        rig.node.drop_next("submit");
        let run = rig.start_job(&workload);
        assert!(
            rig.dispatch(&run).held.is_some(),
            "the issuer stored a Held receipt"
        );
        rig.node.forget_journal();
        let before = rig.node.calls().len();
        for _ in 0..3 {
            let result = rig.step(&run);
            assert!(
                matches!(
                    &result,
                    Err(GpuJobError::Connector(GpuConnectorError::Unavailable { reason }))
                        if reason == "history_lost"
                ),
                "the missing Held key is history_lost: {result:?}",
            );
            assert!(
                rig.dispatch(&run).history_lost_at_ms.is_some(),
                "loss is durable before another step",
            );
        }
        let calls = rig.node.calls();
        assert!(
            calls[before..]
                .iter()
                .all(|call| !matches!(call.kind, "reserve" | "submit")),
            "no dispatch request follows history loss",
        );
    });
}

#[test]
fn a_cancel_always_sends_a_stop_before_the_job_ends() {
    with_rig(|rig| {
        let workload = rig.approve("cancel-offline-create", FAR_EXPIRY_MS);
        rig.node.unreachable(true);
        let run = rig.start_job(&workload);
        let resource = GpuResourceRef(rig.dispatch(&run).resource());
        assert_eq!(
            run.job.state,
            GpuJobState::Running,
            "an unreachable node does not end the job"
        );
        assert_eq!(
            run.job.chunk().and_then(|chunk| chunk.resource.as_ref()),
            Some(&resource),
            "the engine recovered the resource locally",
        );
        let before_cancel = rig.node.calls().len();

        rig.node.unreachable(false);
        let cancelled = rig
            .vault()
            .cancel_gpu_job(
                GpuJobActor::Owner(&rig.owner),
                &run.job.id,
                &rig.permits,
                &rig.connector,
                rig.clock.now_ms(),
            )
            .expect("cancel with the recovered resource");
        let calls = rig.node.calls();
        assert!(
            calls[before_cancel..]
                .iter()
                .any(|call| call.kind == "stop" && call.key.as_deref() == Some(run.key())),
            "cancel sends Stop even though the node missed create",
        );
        assert_eq!(
            cancelled.state,
            GpuJobState::Ended {
                reason: GpuEndReason::Cancelled
            },
            "cancel ends the job after Stop",
        );
        assert_eq!(
            cancelled.chunk().and_then(|chunk| chunk.billed_secs),
            Some(0),
            "a confirmed withdrawal bills zero, not a missing resource",
        );
        assert_eq!(
            cancelled.chunk().and_then(|chunk| chunk.resource.as_ref()),
            Some(&resource),
            "cancel did not take the no-resource path",
        );
    });
}

#[test]
fn billed_seconds_never_pass_the_issuers_bracket_and_a_job_between_two_polls_is_billed() {
    with_rig(|rig| {
        let workload = rig.approve("metering", FAR_EXPIRY_MS);
        let inflated = rig.start_job(&workload);
        rig.clock.advance_secs(100);
        rig.node.advance(
            inflated.key(),
            JobState::Ended,
            Some(500),
            Some(JobEnd::Exited { code: 0 }),
            true,
        );
        let ended = rig.settle(&inflated);
        assert_eq!(
            ended.chunk().and_then(|chunk| chunk.billed_secs),
            Some(100),
            "the node cannot bill beyond the issuer's 100 seconds",
        );
        assert_eq!(
            rig.observation(&inflated).meter,
            Some(MeterVerdict::Bracketed { billed_secs: 100 }),
            "the observation records the bracket",
        );

        let short = rig.start_job(&workload);
        rig.step(&short).expect("poll before the short job starts");
        let accepted: SignedJobReceipt =
            oneiron_organ_protocol::from_slice(&rig.observation(&short).receipt)
                .expect("decode the pre-run observation");
        assert_eq!(
            accepted.receipt.state,
            JobState::Accepted,
            "the first poll saw Accepted, not Running",
        );
        rig.clock.advance_secs(60);
        rig.node.advance(
            short.key(),
            JobState::Ended,
            Some(40),
            Some(JobEnd::Exited { code: 0 }),
            true,
        );
        let ended = rig.settle(&short);
        assert_eq!(
            ended.chunk().and_then(|chunk| chunk.billed_secs),
            Some(40),
            "Accepted to Ended bills occupied time without a Running poll",
        );
        assert_eq!(
            rig.observation(&short).meter,
            Some(MeterVerdict::Agreed),
            "40 measured seconds fit inside the 60-second bracket",
        );
    });
}

#[test]
fn a_job_that_never_started_settles_nothing_and_shows_the_nodes_reason() {
    with_rig(|rig| {
        let workload = rig.approve("never-started", FAR_EXPIRY_MS);
        rig.node.refuse_submits(Some("no_device"));
        let refused = rig.start_job(&workload);
        assert_eq!(
            refused.job.state,
            GpuJobState::Held {
                reason: "no_device".to_owned()
            },
            "create preserves the node's refusal",
        );
        assert_eq!(
            refused.settled(),
            vec![0],
            "a refused submit settles zero units"
        );
        let row = rig.dispatch(&refused);
        assert_eq!(
            row.phase,
            DispatchPhase::Closed,
            "the refusal closes the dispatch"
        );
        assert_eq!(
            row.closed,
            Some(DispatchClose::NodeRefused {
                reason: "no_device".to_owned()
            }),
            "the dispatch keeps the node's refusal reason",
        );

        rig.node.refuse_submits(None);
        let launch_refused = rig.start_job(&workload);
        assert_eq!(
            rig.dispatch(&launch_refused).phase,
            DispatchPhase::Submitted,
            "the second submit was accepted",
        );
        rig.node.advance(
            launch_refused.key(),
            JobState::Ended,
            None,
            Some(JobEnd::LaunchRefused {
                reason: "commit_missing".to_owned(),
            }),
            false,
        );
        let ended = rig.settle(&launch_refused);
        assert_eq!(
            ended.chunk().and_then(|chunk| chunk.billed_secs),
            Some(0),
            "a refused launch bills zero seconds",
        );
        assert_eq!(
            launch_refused.settled(),
            vec![0],
            "a refused launch settles zero units"
        );
        let terminal = rig
            .observation(&launch_refused)
            .terminal
            .expect("typed terminal for launch refusal");
        assert_eq!(
            terminal.end,
            GpuJobEnd::LaunchRefused {
                reason: "commit_missing".to_owned()
            },
            "the observation keeps the launch refusal's reason",
        );
    });
}

#[test]
fn a_grant_revoked_between_the_reservation_and_the_dispatch_sends_nothing() {
    with_rig(|rig| {
        let workload = rig.approve("revoked-before-create", FAR_EXPIRY_MS);
        let connector = RevokeBeforeCreate {
            inner: &rig.connector,
            vault: rig.vault(),
            owner: &rig.owner,
            now_ms: rig.clock.now_ms(),
        };
        let run = rig.start_job_with(&workload, &connector);
        assert_eq!(
            run.job.state,
            GpuJobState::Held {
                reason: "workload_revoked".to_owned()
            },
            "create surfaces the live approval recheck refusal",
        );
        assert_eq!(
            run.settled(),
            vec![0],
            "the refused dispatch settles zero units"
        );
        assert!(
            rig.node.calls().is_empty(),
            "a revoke before create prevents all network calls, including reconcile",
        );
        assert!(
            rig.vault()
                .job_dispatch(run.key())
                .expect("read the dispatch table")
                .is_none(),
            "before-send refusal left no dispatch row",
        );
    });
}

#[test]
fn a_revoked_grant_or_workload_stops_its_running_job_and_an_expired_one_does_not() {
    with_rig(|rig| {
        let workload = rig.approve("revoked-after-submit", FAR_EXPIRY_MS);
        let revoked = rig.start_job(&workload);
        rig.clock.advance_secs(10);
        rig.node
            .advance(revoked.key(), JobState::Running, Some(10), None, true);
        assert_eq!(
            rig.step(&revoked).expect("poll the running job").used_secs,
            10,
            "the issuer saw the node running",
        );
        revoke(rig.vault(), &rig.owner, &workload, rig.clock.now_ms());
        let before_revoke_step = rig.node.calls().len();
        rig.step(&revoked).expect("step after the workload revoke");
        let calls = rig.node.calls();
        assert!(
            calls[before_revoke_step..]
                .iter()
                .any(|call| call.kind == "stop" && call.key.as_deref() == Some(revoked.key())),
            "a revoke sends Stop for that running key",
        );
        assert_eq!(
            rig.dispatch(&revoked).closed,
            Some(DispatchClose::Revoked {
                code: "workload_revoked".to_owned()
            }),
            "the dispatch records what caused the stop",
        );
        rig.clock.advance_secs(2);
        rig.node.advance(
            revoked.key(),
            JobState::Ended,
            Some(12),
            Some(JobEnd::Stopped),
            true,
        );
        rig.settle(&revoked);
        assert_eq!(
            rig.observation(&revoked)
                .terminal
                .expect("typed terminal for the stopped job")
                .end,
            GpuJobEnd::Revoked,
            "a stop due to revoke is reported as Revoked",
        );

        let workload = rig.approve("expires-during-run", rig.clock.now_ms() + 20 * 60 * 1_000);
        let expired = rig.start_job(&workload);
        rig.clock.advance_secs(10);
        rig.node
            .advance(expired.key(), JobState::Running, Some(10), None, true);
        assert_eq!(
            rig.step(&expired).expect("poll before expiry").used_secs,
            10,
            "the second job was running before expiry",
        );
        let before_expiry = rig.node.calls().len();
        rig.clock.advance_secs(25 * 60);
        for _ in 0..2 {
            assert_eq!(
                rig.step(&expired).expect("poll after expiry").state,
                GpuJobState::Running,
                "expiry alone leaves the running job live",
            );
        }
        let calls = rig.node.calls();
        assert!(
            calls[before_expiry..]
                .iter()
                .all(|call| call.kind != "stop"),
            "expiry sent no Stop"
        );
    });
}

#[test]
fn a_start_on_a_replica_that_is_not_the_issuer_reserves_nothing() {
    with_rig(|rig| {
        let replica = &rig.mesh.machine(1).device;
        let mut config = SyncServerConfig::default();
        config.gpu_jobs.vault_machine = settings(rig.issuer);
        let server = Arc::new(
            SyncServer::new(Arc::clone(&replica.vault), config)
                .expect("boot the replica with machine 0 configured as issuer"),
        );

        let refusal = not_the_issuer(&server, "vault_machine")
            .expect_err("the start gate refuses the replica");
        assert_eq!(
            refusal.issuer,
            Some(rig.issuer),
            "the refusal names the configured issuer"
        );
        assert_eq!(
            refusal.code(),
            "not_the_issuer",
            "the start gate has a stable refusal code"
        );
        assert!(
            not_the_issuer(&server, "skypilot").is_ok(),
            "the issuer gate does not apply to other backends",
        );
        let refusal = vault_machine_backend(&server, rig.signers.as_machine(replica.machine))
            .err()
            .expect("the connector is not built on this replica");
        assert_eq!(
            refusal,
            VaultMachineNotRegistered::NotTheIssuer {
                issuer: Some(rig.issuer),
                local: replica.machine
            },
            "registration confirms which machine is allowed to issue jobs",
        );
        assert!(
            replica
                .vault
                .gpu_jobs()
                .expect("read replica GPU jobs")
                .is_empty(),
            "the rejected start gate did not reserve a job",
        );
    });
}

#[test]
fn a_caller_who_may_not_read_machines_gets_a_refusal_that_names_none() {
    for (refusal, visible, hidden) in [
        (
            WorkloadStartRefusal::MachineRefuses {
                reason: "no_device".to_owned(),
            },
            "machine_refuses",
            "not_available_to_this_caller",
        ),
        (
            WorkloadStartRefusal::MachineUnreachable {
                reason: "node is offline".to_owned(),
            },
            "machine_unreachable",
            "not_available_to_this_caller",
        ),
        (
            WorkloadStartRefusal::WorkloadRevoked,
            "workload_revoked",
            "workload_revoked",
        ),
    ] {
        assert_eq!(
            refusal_code_for_caller(&refusal, false),
            hidden,
            "restricted caller: {refusal:?}",
        );
        assert_eq!(
            refusal_code_for_caller(&refusal, true),
            visible,
            "caller may read machines: {refusal:?}",
        );
    }
    let hex = EntityId::from_bytes([42; 16])
        .expect("fixture entity id")
        .to_hex();
    assert_eq!(
        vault_machine_inputs(&json!({})),
        Err("machine_missing"),
        "machine is required"
    );
    assert_eq!(
        vault_machine_inputs(&json!({"machine": "zz"})),
        Err("machine_missing"),
        "machine must be an id in hex",
    );
    assert_eq!(
        vault_machine_inputs(&json!({"machine": hex, "device_id": 3})),
        Err("device_id_invalid"),
        "a device selector must be a string",
    );
}
