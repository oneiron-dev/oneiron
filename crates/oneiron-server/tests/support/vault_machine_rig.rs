//! The scripted node and the issuer rig of pass 33's `vault_machine` tests (rows R5 and R4):
//! two machines on the real mesh, the issuer's connector against a node whose journal the test
//! writes, signed with fixed keys, on a clock the test moves.
//!
//! A test file that uses it declares `engine_stack` and `mesh_machines` beside it.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, mpsc};

use ed25519_dalek::{Signature, Signer, SigningKey};
use oneiron::consent::AuthenticatedOwner;
use oneiron::gpu_job::{
    GpuJob, GpuJobActor, GpuJobConnector, GpuJobError, GpuJobPermits, GpuJobRequest, GpuJobStart,
    GpuJobState, GpuJobStepReport, GpuOffer, PriceShape,
};
use oneiron::job_dispatch::{BootMark, JobDispatch, JobObservation};
use oneiron::job_workload::{
    NoScreenModel, WorkloadApproveRequest, WorkloadCaller, WorkloadPinRequest,
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
use oneiron::{EdgeActorClass, EntityId, Vault};
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

pub(crate) const NOW_MS: u64 = 1_800_000_000_000;
pub(crate) const FAR_EXPIRY_MS: u64 = 4_102_444_800_000;
pub(crate) const MAXIMUM_SECS: u64 = 1_800;
pub(crate) const TEMPLATE: &str = "fixture-workload";
pub(crate) const TEMPLATE_DIGEST: &str =
    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
pub(crate) const CONTRACT_SHA256: &str =
    "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";
pub(crate) const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

pub(crate) struct FakeSigners {
    pub(crate) local: EntityId,
    pub(crate) keys: Arc<BTreeMap<EntityId, SigningKey>>,
}

impl FakeSigners {
    pub(crate) fn new(issuer: EntityId, node: EntityId) -> Self {
        Self {
            local: issuer,
            keys: Arc::new(BTreeMap::from([
                (issuer, SigningKey::from_bytes(&[11; 32])),
                (node, SigningKey::from_bytes(&[12; 32])),
            ])),
        }
    }

    pub(crate) fn as_machine(&self, local: EntityId) -> Arc<dyn MachineSignatures> {
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

pub(crate) struct ScriptedClock(Mutex<BootMark>);

impl ScriptedClock {
    pub(crate) fn new(now_ms: u64) -> Self {
        Self(Mutex::new(BootMark {
            boot_id: "boot-a".to_owned(),
            boot_ns: 1_000_000_000,
            wall_ms: now_ms,
        }))
    }

    pub(crate) fn advance_secs(&self, secs: u64) {
        let mut mark = self.0.lock().expect("scripted clock lock");
        mark.wall_ms += secs * 1_000;
        mark.boot_ns += secs * 1_000_000_000;
    }

    pub(crate) fn reboot(&self, boot_id: &str) {
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
pub(crate) struct Call {
    pub(crate) node: EntityId,
    pub(crate) kind: &'static str,
    pub(crate) key: Option<String>,
    pub(crate) bytes: Vec<u8>,
}

pub(crate) struct HeldCall {
    kind: &'static str,
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
}

#[derive(Default)]
pub(crate) struct NodeState {
    pub(crate) journal: BTreeMap<String, SignedJobReceipt>,
    pub(crate) generation: u64,
    pub(crate) seq: u64,
    pub(crate) calls: Vec<Call>,
    pub(crate) unreachable: bool,
    pub(crate) drop_next: Option<&'static str>,
    pub(crate) hold_next: Option<HeldCall>,
    lose_next_answer: Option<&'static str>,
    repeat_key_cursor: u32,
    pub(crate) refuse_submits: Option<String>,
    /// The outputs the issuer may fetch, by key and name.
    pub(crate) outputs: BTreeMap<(String, String), Vec<u8>>,
}

impl NodeState {
    pub(crate) fn epoch(&self) -> String {
        format!("epoch-{}", self.generation)
    }

    pub(crate) fn record(
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

    pub(crate) fn known_or_absent(&self, key: &str) -> JobStatusAnswer {
        match self.journal.get(key) {
            Some(receipt) => JobStatusAnswer::Known(receipt.clone()),
            None => JobStatusAnswer::Absent {
                epoch: self.epoch(),
            },
        }
    }
}

pub(crate) struct ScriptedNode {
    pub(crate) machine: EntityId,
    pub(crate) issuer: EntityId,
    pub(crate) signer: Arc<dyn MachineSignatures>,
    pub(crate) clock: Arc<ScriptedClock>,
    pub(crate) state: Mutex<NodeState>,
}

impl ScriptedNode {
    pub(crate) fn state(&self) -> MutexGuard<'_, NodeState> {
        self.state.lock().expect("scripted node lock")
    }

    pub(crate) fn calls(&self) -> Vec<Call> {
        self.state().calls.clone()
    }

    pub(crate) fn unreachable(&self, yes: bool) {
        self.state().unreachable = yes;
    }

    pub(crate) fn drop_next(&self, kind: &'static str) {
        self.state().drop_next = Some(kind);
    }

    pub(crate) fn hold_next(&self, kind: &'static str) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (entered, wait_for_entry) = mpsc::channel();
        let (release_call, release) = mpsc::channel();
        self.state().hold_next = Some(HeldCall {
            kind,
            entered,
            release,
        });
        (wait_for_entry, release_call)
    }

    pub(crate) fn lose_next_answer(&self, kind: &'static str) {
        self.state().lose_next_answer = Some(kind);
    }

    pub(crate) fn repeat_key_cursor(&self, pages: u32) {
        self.state().repeat_key_cursor = pages;
    }

    fn enter_call(
        &self,
        machine: EntityId,
        kind: &'static str,
        key: Option<&str>,
        request: &impl Serialize,
    ) -> Result<(MutexGuard<'_, NodeState>, bool), NodeCallError> {
        let mut node = self.state();
        node.record(machine, kind, key, request)?;
        let lose_answer = node.lose_next_answer == Some(kind);
        if lose_answer {
            node.lose_next_answer = None;
        }
        if node
            .hold_next
            .as_ref()
            .is_some_and(|hold| hold.kind == kind)
        {
            let hold = node.hold_next.take().expect("the matching call is held");
            drop(node);
            hold.entered.send(()).expect("the test waits for entry");
            hold.release.recv().expect("the test releases the call");
            node = self.state();
        }
        Ok((node, lose_answer))
    }

    pub(crate) fn refuse_submits(&self, reason: Option<&str>) {
        self.state().refuse_submits = reason.map(str::to_owned);
    }

    pub(crate) fn forget_journal(&self) {
        let mut node = self.state();
        node.journal.clear();
        node.generation += 1;
        node.seq = 0;
    }

    /// Publishes `key`'s receipt as `change` leaves it: the node's next report of the key.
    pub(crate) fn revise(
        &self,
        key: &str,
        change: impl FnOnce(&mut JobReceipt),
    ) -> SignedJobReceipt {
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
    pub(crate) fn put(&self, receipt: JobReceipt) -> SignedJobReceipt {
        let mut node = self.state();
        self.publish(&mut node, receipt)
    }

    /// Answers `signed` again for its key, as a node that went back in its journal would.
    pub(crate) fn replay(&self, signed: SignedJobReceipt) {
        self.state()
            .journal
            .insert(signed.receipt.key.clone(), signed);
    }

    /// Lets the issuer fetch `bytes` as `key`'s output `name`.
    pub(crate) fn put_output(&self, key: &str, name: &str, bytes: &[u8]) {
        self.state()
            .outputs
            .insert((key.to_owned(), name.to_owned()), bytes.to_vec());
    }

    pub(crate) fn advance(
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

    pub(crate) fn blank(&self, key: &str) -> JobReceipt {
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
            slice: None,
        }
    }

    pub(crate) fn publish(
        &self,
        node: &mut NodeState,
        mut receipt: JobReceipt,
    ) -> SignedJobReceipt {
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

    pub(crate) fn stop(&self, node: &mut NodeState, key: &str) -> SignedJobReceipt {
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
        let (kind, key) = match request {
            JobRequest::Node => ("node", None),
            JobRequest::Availability => ("availability", None),
            JobRequest::Reserve(req) => ("reserve", Some(req.key.as_str())),
            JobRequest::Release { key } => ("release", Some(key.as_str())),
            JobRequest::Submit(req) => ("submit", Some(req.submit.key.as_str())),
        };
        let (mut node, lose_answer) = self.enter_call(machine, kind, key, request)?;
        let answer = (|| match request {
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
                    require: Vec::new(),
                    kind: Default::default(),
                }],
                scopes: Vec::new(),
                disk_free_bytes: 10 << 30,
                disk_reserved_bytes: 0,
                disk_reserve_bytes: 0,
                epoch: Some(node.epoch()),
                swept: true,
                boot_id: "node-boot".to_owned(),
                engine_version: "scripted".to_owned(),
                readiness: None,
            }),
            // The connector never asks for a GPU reading; the script has none.
            JobRequest::Availability => JobAnswer::Refused(JobRefusal::DevicesUnreadable {
                why: "the scripted node has no GPUs".to_owned(),
            }),
            JobRequest::Reserve(req) => {
                if let Some(receipt) = node.journal.get(&req.key) {
                    return JobAnswer::Receipt(receipt.clone());
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
                    return JobAnswer::Refused(JobRefusal::SubmitSignatureInvalid);
                }
                let submit = &signed.submit;
                if submit.issuer != self.issuer {
                    return JobAnswer::Refused(JobRefusal::NotIssuer);
                }
                let (mut receipt, refusal) = match node.journal.get(&submit.key) {
                    Some(known) if known.receipt.state != JobState::Held => {
                        return JobAnswer::Receipt(known.clone());
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
        })();
        if lose_answer {
            Err(NodeCallError::Timeout)
        } else {
            Ok(answer)
        }
    }

    fn job_status(
        &self,
        machine: EntityId,
        request: &JobStatusRequest,
    ) -> Result<JobStatusAnswer, NodeCallError> {
        let (kind, key) = match request {
            JobStatusRequest::Find { key } => ("find", Some(key.as_str())),
            JobStatusRequest::Status { key } => ("status", Some(key.as_str())),
            JobStatusRequest::Signal { key, .. } => ("signal", Some(key.as_str())),
            JobStatusRequest::Stop { key } => ("stop", Some(key.as_str())),
            JobStatusRequest::Keys { .. } => ("keys", None),
            JobStatusRequest::Fetch { key, .. } => ("fetch", Some(key.as_str())),
            JobStatusRequest::Ack { key } => ("ack", Some(key.as_str())),
            JobStatusRequest::Tail(tail) => ("tail", Some(tail.key.as_str())),
        };
        let (mut node, lose_answer) = self.enter_call(machine, kind, key, request)?;
        let answer = match request {
            JobStatusRequest::Find { key } | JobStatusRequest::Status { key } => {
                node.known_or_absent(key)
            }
            JobStatusRequest::Stop { key } => JobStatusAnswer::Known(self.stop(&mut node, key)),
            JobStatusRequest::Keys { .. } if node.repeat_key_cursor > 0 => {
                node.repeat_key_cursor -= 1;
                JobStatusAnswer::Keys(KeyPage {
                    entries: Vec::new(),
                    next: Some("cursor-r".to_owned()),
                })
            }
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
                    None => JobStatusAnswer::Refused(JobRefusal::OutputNotFetchable {
                        why: "the test put no such output".to_owned(),
                    }),
                }
            }
            // The scripted node keeps no log.
            JobStatusRequest::Tail(_) => JobStatusAnswer::Refused(JobRefusal::LogNotReadable {
                why: "the scripted node keeps no log".to_owned(),
            }),
        };
        if lose_answer {
            Err(NodeCallError::Timeout)
        } else {
            Ok(answer)
        }
    }
}

pub(crate) struct Rig {
    pub(crate) mesh: Machines,
    pub(crate) issuer: EntityId,
    pub(crate) owner: AuthenticatedOwner,
    pub(crate) offer: GpuOffer,
    pub(crate) permits: GpuJobPermits,
    pub(crate) signers: FakeSigners,
    pub(crate) clock: Arc<ScriptedClock>,
    pub(crate) node: Arc<ScriptedNode>,
    pub(crate) connector: VaultMachineConnector,
}

pub(crate) struct JobRun {
    pub(crate) job: GpuJob,
    pub(crate) admission: RunAdmission,
    pub(crate) receipts: Arc<MemoryReceipts>,
}

impl JobRun {
    pub(crate) fn key(&self) -> &str {
        &self
            .job
            .chunk()
            .expect("the job has a chunk")
            .idempotency_key
    }

    pub(crate) fn settled(&self) -> Vec<u64> {
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

pub(crate) fn settings(issuer: EntityId) -> VaultMachineSettings {
    VaultMachineSettings {
        enabled: true,
        issuer: Some(issuer),
        ..VaultMachineSettings::default()
    }
}

pub(crate) fn make_connector(
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
pub(crate) fn make_connector_with(
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

pub(crate) fn offer() -> GpuOffer {
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
    async fn start(offer: GpuOffer) -> Self {
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
            offer,
            permits: GpuJobPermits::new(),
            signers,
            clock,
            node,
            connector,
        }
    }

    pub(crate) fn vault(&self) -> &Arc<Vault> {
        &self.mesh.machine(0).device.vault
    }

    pub(crate) fn approve(&self, tag: &str, expires_at_ms: u64) -> String {
        self.approve_for_starters(tag, expires_at_ms, Vec::new())
    }

    /// [`Self::approve`] for the Grants (hex ids) in `starters`; with none, the owner alone
    /// starts it, since the owner pins it under no Grant.
    pub(crate) fn approve_for_starters(
        &self,
        tag: &str,
        expires_at_ms: u64,
        starters: Vec<String>,
    ) -> String {
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
                    "cpu_threads": 0,
                    "memory_mib": 22_528,
                    "disk_mib": 2_048,
                    "devices": [{
                        "kind": "gpu",
                        "count": 1,
                        "memory_mib": 22_528,
                        "features": ["cuda"],
                        "sharing": "exclusive",
                    }],
                    "maximum_secs": MAXIMUM_SECS,
                },
                "scope": "host",
                "network": "none",
                "outputs": [{"name": "verdict.json", "returnable": true}],
            }
        }))
        .expect("a valid workload pin request");
        let caller = WorkloadCaller::Owner(&self.owner);
        let now = self.clock.now_ms();
        let owner_id = self.owner.revalidate(self.vault()).expect("the owner's id");
        let pinned = self
            .vault()
            .memory(owner_id, EdgeActorClass::Human)
            .pin_job_workload(&request, &NoScreenModel, now)
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
                    starters,
                    expires_at_ms,
                },
                now,
            )
            .expect("approve the workload for the node");
        assert!(approved.changed, "the fixture writes an approval");
        digest
    }

    pub(crate) fn start_job(&self, workload: &str) -> JobRun {
        self.start_job_with(workload, &self.connector)
    }

    pub(crate) fn start_job_with(&self, workload: &str, connector: &dyn GpuJobConnector) -> JobRun {
        let inputs = json!({"machine": self.node.machine.to_hex()});
        self.start_job_with_inputs(workload, inputs, connector)
    }

    /// [`Self::start_job_with`] on a quote whose inputs are `inputs`.
    pub(crate) fn start_job_with_inputs(
        &self,
        workload: &str,
        inputs: serde_json::Value,
        connector: &dyn GpuJobConnector,
    ) -> JobRun {
        self.start_job_as(GpuJobActor::Owner(&self.owner), workload, inputs, connector)
    }

    /// [`Self::start_job_with_inputs`] started by `actor`.
    pub(crate) fn start_job_as(
        &self,
        actor: GpuJobActor<'_>,
        workload: &str,
        inputs: serde_json::Value,
        connector: &dyn GpuJobConnector,
    ) -> JobRun {
        let now = self.clock.now_ms();
        let quote = self
            .offer
            .quote(
                &GpuJobRequest {
                    job_type: "pinned_workload".to_owned(),
                    image: workload.to_owned(),
                    maximum_secs: Some(MAXIMUM_SECS),
                    inputs,
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
                    actor,
                    offer: &self.offer,
                    quote: &quote,
                    resume: None,
                    admission: &admission,
                },
                &self.permits,
                connector,
                now,
            )
            .expect("start the quoted workload");
        JobRun {
            job,
            admission,
            receipts,
        }
    }

    pub(crate) fn step(&self, run: &JobRun) -> Result<GpuJobStepReport, GpuJobError> {
        self.step_with(run, &self.connector)
    }

    pub(crate) fn step_with(
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

    pub(crate) fn settle(&self, run: &JobRun) -> GpuJob {
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

    pub(crate) fn job(&self, run: &JobRun) -> GpuJob {
        self.vault()
            .gpu_job(&run.job.id)
            .expect("read the job")
            .expect("job row")
    }

    pub(crate) fn dispatch(&self, run: &JobRun) -> JobDispatch {
        self.vault()
            .job_dispatch(run.key())
            .expect("read JOB_DISPATCH")
            .expect("dispatch row")
    }

    pub(crate) fn observation(&self, run: &JobRun) -> JobObservation {
        self.vault()
            .job_observation(run.key())
            .expect("read JOB_OBSERVATION")
            .expect("observation row")
    }
}

pub(crate) fn with_rig(test: impl FnOnce(&Rig) + Send + 'static) {
    with_rig_offer(offer(), test);
}

/// Runs the scripted node rig with the test's offer instead of the default offer.
pub(crate) fn with_rig_offer(offer: GpuOffer, test: impl FnOnce(&Rig) + Send + 'static) {
    run_on_engine_stack("vault-machine-connector", || async move {
        let rig = Rig::start(offer).await;
        tokio::task::block_in_place(|| test(&rig));
        rig.mesh.stop().await;
    });
}
