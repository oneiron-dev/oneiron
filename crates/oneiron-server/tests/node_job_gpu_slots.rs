//! FIX row [GPU-SLOTS-NODE-LEASE-INTEGRATION-TEST], the node's half: the
//! node's job journal (pass 33 row R3a) on the real GPU slot table (row
//! LE-FLEET, `gpu_execution_node/slots.rs`) through `NodeDevices`, over a
//! scripted driver whose compute processes each test sets.
//!
//! - The launch commit leases the GPU under the job's key, confirms it free
//!   and keeps it (design 7.5 step 4).
//! - A process the node did not launch refuses the launch, and the table
//!   holds nothing for the key.
//! - An engine restart takes the running job's GPU again before the gate
//!   opens (7.7).
//! - The release check gives the GPU back, or keeps it out while a compute
//!   entry it cannot attribute stays (7.6).
//!
//! The job's units, clock, stager and signer are R3a's scripted parts. No
//! privilege, no network, no GPU. The issuer's machine pick through
//! `select_gpu_slot` (R5, Q1 PLACE) is the row's other half and is not here.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support --test node_job_gpu_slots`.
#![cfg(all(oneiron_test_support, unix))]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::job_workload::{DeviceClaim, DeviceKind, Sharing};
use oneiron::machine_capacity::GpuDevice;
use oneiron_server::gpu_execution_node::jobs::{NodeDevices, NodeJobs, NodeKey};
use oneiron_server::gpu_execution_node::wire::{
    DeviceRelease, HoldRef, JobAnswer, JobEnd, JobReceipt, JobReserve, JobState, JobSubmit,
    NetworkMode, OutputDecl, ResourceRequest, ScopeKind, SignedJobSubmit, SlotSelector, Starter,
    WorkloadPin,
};
use oneiron_server::gpu_execution_node::{
    GpuComputeProcess, GpuDeviceOffer, GpuDeviceProbe, GpuDeviceState, GpuProbeError, GpuSlotTable,
};
use oneiron_server::test_doors::node_jobs::{ScriptedNode, ScriptedSigner};

const TEMPLATE: &str = "open-models";
const DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const DEVICE: &str = "GPU-scripted-0";
const NOW_MS: u64 = 1_800_000_000_000;
const WAIT: Duration = Duration::from_secs(10);
/// The job's own process on the GPU while its unit runs.
const JOB_PID: u32 = 4_242;
/// A process the node did not launch.
const FOREIGN_PID: u32 = 7_777;
/// The launch refusal of a key whose GPU another key or process holds.
const GPU_UNAVAILABLE: &str = "device_refused: device_unavailable: claim 0";

/// A driver with one GPU, whose compute processes the test sets.
#[derive(Default)]
struct ScriptedDriver {
    processes: Mutex<Vec<GpuComputeProcess>>,
}

impl ScriptedDriver {
    /// The compute entries on the GPU from now on; `None` is an entry the
    /// driver gives no process id for.
    fn set_processes(&self, pids: &[Option<u32>]) {
        *self
            .processes
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = pids
            .iter()
            .map(|pid| GpuComputeProcess {
                device_id: DEVICE.to_owned(),
                pid: *pid,
            })
            .collect();
    }
}

impl GpuDeviceProbe for ScriptedDriver {
    fn devices(&self) -> Result<Vec<GpuDevice>, GpuProbeError> {
        Ok(vec![GpuDevice {
            device_id: DEVICE.to_owned(),
            model: "NVIDIA GeForce RTX 4090".to_owned(),
            memory_total_mib: 24_564,
        }])
    }

    fn compute_processes(&self) -> Result<Vec<GpuComputeProcess>, GpuProbeError> {
        Ok(self
            .processes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone())
    }
}

/// One server's slot table over the machine's driver, offering its GPU.
fn slot_table(driver: &Arc<ScriptedDriver>) -> Arc<GpuSlotTable> {
    let probe: Arc<dyn GpuDeviceProbe> = Arc::<ScriptedDriver>::clone(driver);
    Arc::new(GpuSlotTable::new(
        probe,
        GpuDeviceOffer {
            offered: BTreeSet::from([DEVICE.to_owned()]),
            ..GpuDeviceOffer::default()
        },
    ))
}

/// What the table says the GPU is doing now, from a fresh reading.
fn gpu_state(table: &GpuSlotTable) -> GpuDeviceState {
    table
        .availability(NOW_MS)
        .expect("the driver reads")
        .devices
        .into_iter()
        .find(|listed| listed.device.device_id == DEVICE)
        .map(|listed| listed.state)
        .expect("the GPU is listed")
}

fn launched(key: &str) -> GpuDeviceState {
    GpuDeviceState::Launched {
        key: key.to_owned(),
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    node: ScriptedNode,
    issuer: EntityId,
    driver: Arc<ScriptedDriver>,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temp dir");
    let node = ScriptedNode::new(dir.path(), EntityId::now(), TEMPLATE, DIGEST, NOW_MS);
    Fixture {
        _dir: dir,
        node,
        issuer: EntityId::now(),
        driver: Arc::new(ScriptedDriver::default()),
    }
}

fn pin() -> WorkloadPin {
    WorkloadPin {
        template: TEMPLATE.to_owned(),
        template_digest: DIGEST.to_owned(),
        commit: "a".repeat(40),
        contract_sha256: "b".repeat(64),
        contract_path: "contract.json".to_owned(),
        entry: "tools/units/run.sh".to_owned(),
        args: vec!["seed=7".to_owned()],
        request: ResourceRequest {
            cpu_threads: 0,
            memory_mib: 2 * 1024,
            disk_mib: 1024,
            devices: vec![DeviceClaim {
                kind: DeviceKind::Gpu,
                count: 1,
                memory_mib: 22 * 1024,
                features: Vec::new(),
                sharing: Sharing::Exclusive,
            }],
            maximum_secs: 1_800,
        },
        scope: ScopeKind::Host,
        network: NetworkMode::None,
        outputs: vec![OutputDecl {
            name: "verdict.json".to_owned(),
            returnable: true,
        }],
    }
}

impl Fixture {
    /// The node's job service with the real slot table as its devices.
    fn open(&self, table: &Arc<GpuSlotTable>) -> NodeJobs {
        let mut parts = self.node.parts();
        let devices: Arc<dyn NodeDevices> = Arc::<GpuSlotTable>::clone(table);
        parts.devices = devices;
        NodeJobs::open(self.node.paths.clone(), parts).expect("open the node's journal")
    }

    fn reserve(&self, key: &str) -> JobReserve {
        JobReserve {
            key: key.to_owned(),
            pin: pin(),
            slot: SlotSelector::default(),
            issuer: self.issuer,
            starter: Starter::Owner,
            issued_at_ms: NOW_MS,
            not_after_ms: NOW_MS + 300_000,
        }
    }

    fn submit(&self, key: &str) -> SignedJobSubmit {
        let pin = pin();
        let submit = JobSubmit {
            key: key.to_owned(),
            job: EntityId::now(),
            chunk: 0,
            maximum_secs: pin.request.maximum_secs,
            pin,
            slot: SlotSelector::default(),
            issued_at_ms: NOW_MS,
            not_after_ms: NOW_MS + 300_000,
            issuer: self.issuer,
            starter: Starter::Owner,
            hold: HoldRef {
                reservation: format!("hold-{key}"),
                generation: 1,
            },
            authority_heads: Vec::new(),
            continues: None,
        };
        SignedJobSubmit::sign(submit, ScriptedSigner::new(self.issuer).as_ref())
            .expect("the issuer signs")
    }

    /// Reserves and submits `key`. The reserve holds the key and its disk
    /// only; the GPU is taken in the launch commit once the staging ends.
    fn reserve_and_submit(&self, jobs: &NodeJobs, key: &str) {
        assert_eq!(
            receipt(jobs.reserve(self.issuer, self.reserve(key))).state,
            JobState::Held
        );
        assert_eq!(
            receipt(jobs.submit(self.issuer, self.submit(key))).state,
            JobState::Accepted
        );
    }

    /// Reserves, submits and launches `key`, and waits until its unit runs
    /// with the job's process on the GPU.
    fn run(&self, jobs: &NodeJobs, key: &str) -> NodeKey {
        self.reserve_and_submit(jobs, key);
        wait_for(jobs, key, |entry| entry.state == JobState::Launching);
        self.driver.set_processes(&[Some(JOB_PID)]);
        jobs.tick();
        wait_for(jobs, key, |entry| entry.state == JobState::Running)
    }

    /// Ends `key`'s unit cleanly with `left` on the GPU afterwards, and
    /// runs the end handling once.
    fn end(&self, jobs: &NodeJobs, key: &str, left: &[Option<u32>]) {
        self.node.clock.advance_ms(30_000);
        self.driver.set_processes(left);
        self.node.units.exit(key, 0);
        jobs.tick();
    }
}

fn receipt(answer: JobAnswer) -> JobReceipt {
    match answer {
        JobAnswer::Receipt(signed) => signed.receipt,
        other => panic!("expected a receipt, got {other:?}"),
    }
}

fn entry(jobs: &NodeJobs, key: &str) -> Option<NodeKey> {
    jobs.keys().into_iter().find(|entry| entry.key == key)
}

/// Waits until the key exists and `done` holds for it.
fn wait_for(jobs: &NodeJobs, key: &str, done: impl Fn(&NodeKey) -> bool) -> NodeKey {
    // testkit-lint: allow(wall-clock) bounds a wait on the node's own worker threads
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(found) = entry(jobs, key)
            && done(&found)
        {
            return found;
        }
        assert!(
            // testkit-lint: allow(wall-clock) bounds a wait on the node's own worker threads
            Instant::now() < deadline,
            "key {key} did not reach the state: {:?}",
            entry(jobs, key)
        );
        // testkit-lint: allow(sleep) the poll interval; the worker threads signal nothing
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Waits until the key's launch is refused, and gives the reason.
fn launch_refusal(jobs: &NodeJobs, key: &str) -> String {
    let ended = wait_for(jobs, key, |entry| entry.end.is_some());
    match ended.end {
        Some(JobEnd::LaunchRefused { reason }) => reason,
        other => panic!("expected a refused launch of {key}, got {other:?}"),
    }
}

fn released(entry: &NodeKey) -> bool {
    matches!(entry.release, DeviceRelease::Confirmed { .. })
}

/// Design 7.5 step 4 on the real table: the launch commit leases the GPU
/// under the job's key, confirms it free and keeps it. While the job runs,
/// the table names the key on the GPU, and a second key's launch cannot
/// take it.
#[test]
fn the_launch_commit_takes_the_gpu_from_the_slot_table_under_the_key_and_keeps_it() {
    let fixture = fixture();
    let table = slot_table(&fixture.driver);
    assert_eq!(gpu_state(&table), GpuDeviceState::Free);
    let jobs = fixture.open(&table);

    fixture.run(&jobs, "job-gpu/a");
    assert_eq!(gpu_state(&table), launched("job-gpu/a"));

    // The reserve takes no GPU, so the second key is held; its launch
    // commit finds the GPU taken and refuses.
    fixture.reserve_and_submit(&jobs, "job-gpu/b");
    assert_eq!(launch_refusal(&jobs, "job-gpu/b"), GPU_UNAVAILABLE);
    assert_eq!(gpu_state(&table), launched("job-gpu/a"));
    assert_eq!(fixture.node.units.starts("job-gpu/b"), 0);
}

/// A compute process the node did not launch, on the GPU when the launch
/// commit reads it, refuses the launch. The table holds nothing for the
/// key, and once the process is gone the next key takes the GPU.
#[test]
fn a_process_the_node_did_not_launch_refuses_the_launch_and_the_table_holds_nothing_for_the_key() {
    let fixture = fixture();
    let table = slot_table(&fixture.driver);
    let jobs = fixture.open(&table);

    // The process comes while the key stages, after its reserve.
    fixture.node.stager.hold();
    fixture.reserve_and_submit(&jobs, "job-gpu/busy");
    assert!(
        fixture.node.stager.wait_entered(1, WAIT),
        "the staging began"
    );
    fixture.driver.set_processes(&[Some(FOREIGN_PID)]);
    fixture.node.stager.let_go();
    assert_eq!(launch_refusal(&jobs, "job-gpu/busy"), GPU_UNAVAILABLE);
    let refused = entry(&jobs, "job-gpu/busy").expect("the key is journaled");
    assert!(refused.launch.is_none(), "{refused:?}");
    assert_eq!(refused.release, DeviceRelease::NotHeld);
    assert_eq!(fixture.node.units.starts("job-gpu/busy"), 0);
    assert_eq!(
        gpu_state(&table),
        GpuDeviceState::Busy {
            pids: vec![FOREIGN_PID]
        }
    );

    fixture.driver.set_processes(&[]);
    assert_eq!(gpu_state(&table), GpuDeviceState::Free);
    fixture.run(&jobs, "job-gpu/next");
    assert_eq!(gpu_state(&table), launched("job-gpu/next"));
}

/// Design 7.7 on the real table: after an engine restart (a new service
/// over a new table, with the job still running on the GPU), the journal
/// takes the GPU again under the job's key before the gate opens, so no new
/// key takes it. The job's end gives it back.
#[test]
fn an_engine_restart_takes_the_running_jobs_gpu_again_before_any_new_key_can() {
    let fixture = fixture();
    let table = slot_table(&fixture.driver);
    let jobs = fixture.open(&table);
    fixture.run(&jobs, "job-gpu/survivor");
    drop(jobs);
    drop(table);

    // The new server's table did not launch the job: its process reads as
    // another's until the journal takes the GPU again.
    let table = slot_table(&fixture.driver);
    assert_eq!(
        gpu_state(&table),
        GpuDeviceState::Busy {
            pids: vec![JOB_PID]
        }
    );
    let jobs = fixture.open(&table);
    assert_eq!(gpu_state(&table), launched("job-gpu/survivor"));
    let survivor = entry(&jobs, "job-gpu/survivor").expect("the key is journaled");
    assert_eq!(survivor.state, JobState::Running);
    assert_eq!(fixture.node.units.starts("job-gpu/survivor"), 1);

    fixture.reserve_and_submit(&jobs, "job-gpu/newcomer");
    assert_eq!(launch_refusal(&jobs, "job-gpu/newcomer"), GPU_UNAVAILABLE);
    assert_eq!(gpu_state(&table), launched("job-gpu/survivor"));

    fixture.end(&jobs, "job-gpu/survivor", &[]);
    wait_for(&jobs, "job-gpu/survivor", released);
    assert_eq!(gpu_state(&table), GpuDeviceState::Free);
}

/// Design 7.6 on the real table: the job's end and a clean release check
/// finish the key's slot, the GPU reads free, and the next key leases it.
#[test]
fn the_release_check_gives_the_gpu_back_to_the_slot_table_and_the_next_key_takes_it() {
    let fixture = fixture();
    let table = slot_table(&fixture.driver);
    let jobs = fixture.open(&table);
    fixture.run(&jobs, "job-gpu/first");
    assert_eq!(gpu_state(&table), launched("job-gpu/first"));

    fixture.end(&jobs, "job-gpu/first", &[]);
    let first = wait_for(&jobs, "job-gpu/first", released);
    assert!(first.other_compute_pids.is_empty(), "{first:?}");
    assert_eq!(gpu_state(&table), GpuDeviceState::Free);

    fixture.run(&jobs, "job-gpu/second");
    assert_eq!(gpu_state(&table), launched("job-gpu/second"));
}

/// Design 7.6 on the real table: a compute entry with no process id, left
/// on the GPU after the unit is gone, cannot be told from the job's own
/// leftover. The GPU stays quarantined under the key and no new key can
/// reserve it. Once the entry is gone, the next release check clears the
/// quarantine and finishes the slot.
#[test]
fn a_compute_entry_left_with_no_process_id_keeps_the_gpu_quarantined_until_a_clean_release_check() {
    let fixture = fixture();
    let table = slot_table(&fixture.driver);
    let jobs = fixture.open(&table);
    fixture.run(&jobs, "job-gpu/leftover");

    fixture.end(&jobs, "job-gpu/leftover", &[None]);
    let kept = wait_for(&jobs, "job-gpu/leftover", |entry| {
        matches!(entry.release, DeviceRelease::Unconfirmed { .. })
    });
    assert!(
        matches!(
            gpu_state(&table),
            GpuDeviceState::Quarantined { key: Some(key), why }
                if key == "job-gpu/leftover" && why.starts_with("device_probe_unattributed")
        ),
        "{:?} for {kept:?}",
        gpu_state(&table)
    );
    let refused = receipt(jobs.reserve(fixture.issuer, fixture.reserve("job-gpu/waiting")));
    assert!(
        matches!(&refused.end, Some(JobEnd::Refused { reason }) if reason == "device_unavailable: claim 0"),
        "{:?}",
        refused.end
    );

    fixture.driver.set_processes(&[]);
    jobs.tick();
    wait_for(&jobs, "job-gpu/leftover", released);
    assert_eq!(gpu_state(&table), GpuDeviceState::Free);
    fixture.run(&jobs, "job-gpu/after");
    assert_eq!(gpu_state(&table), launched("job-gpu/after"));
}
