//! The scripted node and the issuer rig of pass 33's `vault_machine` tests (rows R5 and R4):
//! two machines on the real mesh, the issuer's connector against a node whose journal the test
//! writes, signed with fixed keys, on a clock the test moves.
//!
//! A test file that uses it declares `engine_stack` and `mesh_machines` beside it.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use ed25519_dalek::{Signature, Signer, SigningKey};
use oneiron::consent::AuthenticatedOwner;
use oneiron::gpu_job::{
    GpuJob, GpuJobActor, GpuJobConnector, GpuJobError, GpuJobPermits, GpuJobRequest, GpuJobStart,
    GpuJobState, GpuJobStepReport, GpuOffer, PriceShape,
};
use oneiron::job_dispatch::{BootMark, JobDispatch, JobObservation};
use oneiron::job_workload::{WorkloadApproveRequest, WorkloadCaller, WorkloadPinRequest};
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
use oneiron_server::config::gpu_jobs::VaultMachineSettings;
use oneiron_server::gpu_execution_node::issuer::{
    IssuerClock, JobNodeClient, LoggedOrphanKeys, NodeCallError, OrphanKeys, VAULT_MACHINE_BACKEND,
    VaultMachineConnector, VaultMachineParts,
};
use oneiron_server::gpu_execution_node::wire::{
    DeviceRelease, JOB_ALPN, JOB_STATUS_ALPN, JobAnswer, JobEnd, JobReceipt, JobRefusal,
    JobRequest, JobState, JobStatusAnswer, JobStatusRequest, KeyEntry, KeyPage, NetworkMode,
    NodeAnswer, OutputsState, ScopeClass, SignedJobReceipt, TemplateOffer,
};
use serde::Serialize;
use serde_json::json;

use crate::engine_stack::run_on_engine_stack;
use crate::mesh_machines::Machines;

pub const NOW_MS: u64 = 1_800_000_000_000;
pub const FAR_EXPIRY_MS: u64 = 4_102_444_800_000;
pub const MAXIMUM_SECS: u64 = 1_800;
pub const TEMPLATE: &str = "fixture-workload";
pub const TEMPLATE_DIGEST: &str =
    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
pub const CONTRACT_SHA256: &str =
    "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";
pub const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

pub struct FakeSigners {
    pub local: EntityId,
    pub keys: Arc<BTreeMap<EntityId, SigningKey>>,
}

impl FakeSigners {
    pub fn new(issuer: EntityId, node: EntityId) -> Self {
        Self {
            local: issuer,
            keys: Arc::new(BTreeMap::from([
                (issuer, SigningKey::from_bytes(&[11; 32])),
                (node, SigningKey::from_bytes(&[12; 32])),
            ])),
        }
    }

    pub fn as_machine(&self, local: EntityId) -> Arc<dyn MachineSignatures> {
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

pub struct ScriptedClock(Mutex<BootMark>);

impl ScriptedClock {
    pub fn new(now_ms: u64) -> Self {
        Self(Mutex::new(BootMark {
            boot_id: "boot-a".to_owned(),
            boot_ns: 1_000_000_000,
            wall_ms: now_ms,
        }))
    }

    pub fn advance_secs(&self, secs: u64) {
        let mut mark = self.0.lock().expect("scripted clock lock");
        mark.wall_ms += secs * 1_000;
        mark.boot_ns += secs * 1_000_000_000;
    }

    pub fn reboot(&self, boot_id: &str) {
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
pub struct Call {
    pub node: EntityId,
    pub kind: &'static str,
    pub key: Option<String>,
    pub bytes: Vec<u8>,
}

#[derive(Default)]
pub struct NodeState {
    pub journal: BTreeMap<String, SignedJobReceipt>,
    pub generation: u64,
    pub seq: u64,
    pub calls: Vec<Call>,
    pub unreachable: bool,
    pub drop_next: Option<&'static str>,
    pub refuse_submits: Option<String>,
    /// The outputs the issuer may fetch, by key and name.
    pub outputs: BTreeMap<(String, String), Vec<u8>>,
}

impl NodeState {
    pub fn epoch(&self) -> String {
        format!("epoch-{}", self.generation)
    }

    pub fn record(
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

    pub fn known_or_absent(&self, key: &str) -> JobStatusAnswer {
        match self.journal.get(key) {
            Some(receipt) => JobStatusAnswer::Known(receipt.clone()),
            None => JobStatusAnswer::Absent {
                epoch: self.epoch(),
            },
        }
    }
}

pub struct ScriptedNode {
    pub machine: EntityId,
    pub issuer: EntityId,
    pub signer: Arc<dyn MachineSignatures>,
    pub clock: Arc<ScriptedClock>,
    pub state: Mutex<NodeState>,
}

impl ScriptedNode {
    pub fn state(&self) -> MutexGuard<'_, NodeState> {
        self.state.lock().expect("scripted node lock")
    }

    pub fn calls(&self) -> Vec<Call> {
        self.state().calls.clone()
    }

    pub fn unreachable(&self, yes: bool) {
        self.state().unreachable = yes;
    }

    pub fn drop_next(&self, kind: &'static str) {
        self.state().drop_next = Some(kind);
    }

    pub fn refuse_submits(&self, reason: Option<&str>) {
        self.state().refuse_submits = reason.map(str::to_owned);
    }

    pub fn forget_journal(&self) {
        let mut node = self.state();
        node.journal.clear();
        node.generation += 1;
        node.seq = 0;
    }

    /// Publishes `key`'s receipt as `change` leaves it: the node's next report of the key.
    pub fn revise(&self, key: &str, change: impl FnOnce(&mut JobReceipt)) -> SignedJobReceipt {
        let mut node = self.state();
        let mut receipt = node
            .journal
            .get(key)
            .expect("revise a known key")
            .receipt
            .clone();
        change(&mut receipt);
        self.publish(&mut node, receipt)
    }

    /// Publishes `receipt` for a key the node holds, whatever the issuer knows of it.
    pub fn put(&self, receipt: JobReceipt) -> SignedJobReceipt {
        let mut node = self.state();
        self.publish(&mut node, receipt)
    }

    /// Answers `signed` again for its key, as a node that went back in its journal would.
    pub fn replay(&self, signed: SignedJobReceipt) {
        self.state()
            .journal
            .insert(signed.receipt.key.clone(), signed);
    }

    /// Lets the issuer fetch `bytes` as `key`'s output `name`.
    pub fn put_output(&self, key: &str, name: &str, bytes: &[u8]) {
        self.state()
            .outputs
            .insert((key.to_owned(), name.to_owned()), bytes.to_vec());
    }

    pub fn advance(
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

    pub fn blank(&self, key: &str) -> JobReceipt {
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

    pub fn publish(&self, node: &mut NodeState, mut receipt: JobReceipt) -> SignedJobReceipt {
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

    pub fn stop(&self, node: &mut NodeState, key: &str) -> SignedJobReceipt {
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
            // Only an output the test put is fetched.
            JobStatusRequest::Fetch { key, name } => {
                match node.outputs.get(&(key.clone(), name.clone())) {
                    Some(bytes) => JobStatusAnswer::Output {
                        bytes: bytes.clone(),
                    },
                    None => JobStatusAnswer::Refused(JobRefusal::NotEnabled),
                }
            }
        })
    }
}

pub struct Rig {
    pub mesh: Machines,
    pub issuer: EntityId,
    pub owner: AuthenticatedOwner,
    pub offer: GpuOffer,
    pub permits: GpuJobPermits,
    pub signers: FakeSigners,
    pub clock: Arc<ScriptedClock>,
    pub node: Arc<ScriptedNode>,
    pub connector: VaultMachineConnector,
}

pub struct JobRun {
    pub job: GpuJob,
    pub admission: RunAdmission,
    pub receipts: Arc<MemoryReceipts>,
}

impl JobRun {
    pub fn key(&self) -> &str {
        &self
            .job
            .chunk()
            .expect("the job has a chunk")
            .idempotency_key
    }

    pub fn settled(&self) -> Vec<u64> {
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

pub fn settings(issuer: EntityId) -> VaultMachineSettings {
    VaultMachineSettings {
        enabled: true,
        issuer: Some(issuer),
        ..VaultMachineSettings::default()
    }
}

pub fn make_connector(
    vault: &Arc<Vault>,
    issuer: EntityId,
    signers: &FakeSigners,
    clock: &Arc<ScriptedClock>,
    node: &Arc<ScriptedNode>,
) -> VaultMachineConnector {
    make_connector_with(
        vault,
        issuer,
        signers,
        clock,
        node,
        Arc::new(LoggedOrphanKeys),
    )
}

/// [`make_connector`] with `orphans` as the reconcile's hook for the keys it does not know.
pub fn make_connector_with(
    vault: &Arc<Vault>,
    issuer: EntityId,
    signers: &FakeSigners,
    clock: &Arc<ScriptedClock>,
    node: &Arc<ScriptedNode>,
    orphans: Arc<dyn OrphanKeys>,
) -> VaultMachineConnector {
    VaultMachineConnector::new(VaultMachineParts {
        vault: Arc::clone(vault),
        issuer,
        client: node.clone(),
        signer: signers.as_machine(issuer),
        clock: clock.clone(),
        orphans,
        settings: settings(issuer),
    })
}

pub fn offer() -> GpuOffer {
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
    pub async fn start() -> Self {
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

    pub fn vault(&self) -> &Arc<Vault> {
        &self.mesh.machine(0).device.vault
    }

    pub fn approve(&self, tag: &str, expires_at_ms: u64) -> String {
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

    pub fn start_job(&self, workload: &str) -> JobRun {
        self.start_job_with(workload, &self.connector)
    }

    pub fn start_job_with(&self, workload: &str, connector: &dyn GpuJobConnector) -> JobRun {
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

    pub fn step(&self, run: &JobRun) -> Result<GpuJobStepReport, GpuJobError> {
        self.step_with(run, &self.connector)
    }

    pub fn step_with(
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

    pub fn settle(&self, run: &JobRun) -> GpuJob {
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

    pub fn job(&self, run: &JobRun) -> GpuJob {
        self.vault()
            .gpu_job(&run.job.id)
            .expect("read the job")
            .expect("job row")
    }

    pub fn dispatch(&self, run: &JobRun) -> JobDispatch {
        self.vault()
            .job_dispatch(run.key())
            .expect("read JOB_DISPATCH")
            .expect("dispatch row")
    }

    pub fn observation(&self, run: &JobRun) -> JobObservation {
        self.vault()
            .job_observation(run.key())
            .expect("read JOB_OBSERVATION")
            .expect("observation row")
    }
}

pub fn with_rig(test: impl FnOnce(&Rig) + Send + 'static) {
    run_on_engine_stack("vault-machine-connector", || async move {
        let rig = Rig::start().await;
        tokio::task::block_in_place(|| test(&rig));
        rig.mesh.stop().await;
    });
}
