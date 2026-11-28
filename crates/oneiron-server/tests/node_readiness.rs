//! Pass 34 row Q4 (`34-compute-general/DESIGN.md` sections 1.2, 2.4 and
//! 7.3; the tests of section 10): the node's idle readiness check, the
//! DRAIN slot's default rule, the node's incidents, and the breadcrumb lines
//! a host reset leaves on the `Lost` receipt. Against a scripted unit
//! manager, a scripted device table and a scripted clock: no privilege and
//! no network. A second `NodeJobs` on the same directory is an engine
//! restart, and a new boot id is a host reset.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --test node_readiness`.
#![cfg(all(oneiron_test_support, unix))]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use oneiron::authority::{ActSurface, MachineOwnership, MachineRole};
use oneiron::job_workload::{
    BoundReport, BoundStrength, DeviceClaim, DeviceKind, ScopeCapabilities, Sharing,
};
use oneiron::machine_policy::machine_part_item;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::test_doors::steward;
use oneiron::{EntityId, Vault};
use oneiron_server::gpu_execution_node::jobs::{
    DRAIN_RULE_DEFAULT, IncidentKind, JobKeyId, NodeClock, NodeDevices, NodeJobs, NodeKey,
};
use oneiron_server::gpu_execution_node::node::{DISABLED_MARKER_EXTENSION, marker_beside};
use oneiron_server::gpu_execution_node::wire::{
    DeviceRelease, HoldRef, JobAnswer, JobEnd, JobReceipt, JobReserve, JobState, JobStatusAnswer,
    JobSubmit, NetworkMode, OutputDecl, ReadinessCheck, ReadinessState, ResourceRequest, ScopeKind,
    SignedJobSubmit, SlotSelector, Starter, WorkloadPin,
};
use oneiron_server::gpu_execution_node::{
    DeviceSample, DrainClearBy, ExecutionNode, GpuComputeProcess, GpuDevice, GpuDeviceOffer,
    GpuDeviceProbe, GpuDeviceState, GpuProbeError, GpuSlotTable, NodeControls, parse_sample_lines,
};
use oneiron_server::test_doors::node_jobs::{
    ScriptedDevices, ScriptedJobUnits, ScriptedNode, ScriptedSigner,
};
use serde_json::json;

const TEMPLATE: &str = "open-models";
const DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const DEVICE: &str = "GPU-scripted-0";
const NOW_MS: u64 = 1_800_000_000_000;
/// `jobs.readiness.every_secs`' default, 900 s, in milliseconds.
const PERIOD_MS: u64 = 900_000;
const WAIT: Duration = Duration::from_secs(10);
const DRIVER_DOWN: &str = "driver not answering";

struct Fixture {
    dir: tempfile::TempDir,
    node: ScriptedNode,
    issuer: EntityId,
}

fn fixture() -> Fixture {
    Fixture::new(tempfile::tempdir().expect("temp dir"), EntityId::now())
}

/// The process id of another booker's compute process on the GPU.
const BOOKER_PID: u32 = 4_242;

/// The slot table's driver: it exposes the fixture's scripted probe
/// failure, and it lists the compute processes the test puts on the GPU.
struct OfferProbe {
    devices: Arc<ScriptedDevices>,
    processes: Arc<Mutex<Vec<GpuComputeProcess>>>,
}

impl GpuDeviceProbe for OfferProbe {
    fn devices(&self) -> Result<Vec<GpuDevice>, GpuProbeError> {
        self.devices
            .probe()
            .map_err(|reason| GpuProbeError::Unavailable { reason })?;
        Ok(vec![GpuDevice {
            device_id: DEVICE.to_owned(),
            model: "scripted".to_owned(),
            memory_total_mib: 24 * 1024,
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

/// Uses a real node file, owner policy and slot table with scripted units and a fake clock.
struct OfferFixture {
    fixture: Fixture,
    node: ExecutionNode,
    vault: Arc<Vault>,
    machine: EntityId,
    slots: Arc<GpuSlotTable>,
    withheld_file: PathBuf,
    /// The compute processes the driver lists on the GPU.
    processes: Arc<Mutex<Vec<GpuComputeProcess>>>,
}

impl OfferFixture {
    /// Opens an owner carrier vault and configures the node to offer one scripted GPU.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault = Arc::new(
            steward::open_owner_carrier_vault(&dir.path().join("vault"))
                .expect("open the owner's vault"),
        );
        let machine = vault
            .local_machine()
            .expect("read the local machine")
            .expect("a local machine")
            .id;
        let owner = steward::owner(&vault).expect("the owner proof");
        vault
            .set_machine_role(
                &owner,
                ActSurface::ThisInstall,
                machine,
                MachineRole::Owned(MachineOwnership::Yours),
                None,
            )
            .expect("the owner answers that the machine is theirs");
        let fixture = Fixture::new(dir, machine);
        let file = fixture.dir.path().join("execution-node.toml");
        let paths = &fixture.node.paths;
        fs::create_dir_all(&paths.work_dir).expect("the work directory");
        fs::write(
            &file,
            format!(
                r#"[execution_node]
enabled = true
issuers = ["{issuer}"]
state_dir = {state:?}
work_dir = {work:?}
disk_reserve_gib = 0
state_floor_mib = 0
"#,
                issuer = fixture.issuer.to_hex(),
                state = paths.state_dir,
                work = paths.work_dir,
            ),
        )
        .expect("the node file");
        let withheld_file = fixture.dir.path().join("gpu-withheld");
        fs::write(&withheld_file, "").expect("the empty withheld list");
        let processes = Arc::new(Mutex::new(Vec::new()));
        let slots = Arc::new(GpuSlotTable::new(
            Arc::new(OfferProbe {
                devices: Arc::clone(&fixture.node.devices),
                processes: Arc::clone(&processes),
            }),
            GpuDeviceOffer {
                offered: BTreeSet::from([DEVICE.to_owned()]),
                withheld_file: Some(withheld_file.clone()),
                ..GpuDeviceOffer::default()
            },
        ));
        let node = ExecutionNode::new(file, Arc::clone(&vault), Arc::clone(&slots));
        Self {
            fixture,
            node,
            vault,
            machine,
            slots,
            withheld_file,
            processes,
        }
    }

    /// Attaches the real admission and slots to the scripted job service.
    fn open(&self) -> NodeJobs {
        let mut parts = self.fixture.node.parts();
        parts.admission = Arc::new(self.node.clone());
        parts.devices = self.slots.clone();
        NodeJobs::open(self.fixture.node.paths.clone(), parts).expect("open the job service")
    }

    /// Sets the owner's offer and verifies that the node reads it from its own vault.
    fn owner_offers(&self, offered: bool) {
        let owner = steward::owner(&self.vault).expect("the owner proof");
        let outcome = self
            .vault
            .set_setting(
                SettingCaller::Owner(&owner),
                SetSetting {
                    item: Some(machine_part_item(self.machine, DEVICE)),
                    ..SetSetting::vault_value(
                        "machines.devices.offered",
                        json!({ "offered": offered, "max_claimants": 1 }),
                    )
                },
            )
            .expect("the owner's change");
        assert!(matches!(outcome, SetSettingOutcome::Applied { .. }));
        let snapshot = self.node.snapshot();
        let policy = snapshot.policy.expect("the node reads owner policy");
        assert_eq!(policy.devices[DEVICE].offered, offered);
    }

    /// Asserts that this tick found the failed driver and drained the real slot table.
    fn assert_driver_failure(&self, jobs: &NodeJobs) {
        let readiness = jobs.readiness();
        assert_eq!(
            readiness.checked_at_ms,
            Some(self.fixture.node.clock.wall_ms())
        );
        assert!(matches!(
            readiness.state,
            ReadinessState::NotReady { check: ReadinessCheck::Devices, why }
                if why.contains(DRIVER_DOWN)
        ));
        assert!(self.slots.drained().expect("read the drain").is_some());
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
            memory_mib: 22 * 1024,
            disk_mib: 2 * 1024,
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

fn sample(temperature_c: i32, power_mw: u64, memory_used_mib: u64) -> DeviceSample {
    DeviceSample {
        device_id: DEVICE.to_owned(),
        temperature_c: Some(temperature_c),
        power_mw: Some(power_mw),
        memory_used_mib: Some(memory_used_mib),
    }
}

impl Fixture {
    /// Sets up the scripted parts and their shared state directory.
    fn new(dir: tempfile::TempDir, machine: EntityId) -> Self {
        let node = ScriptedNode::new(dir.path(), machine, TEMPLATE, DIGEST, NOW_MS);
        Self {
            dir,
            node,
            issuer: EntityId::now(),
        }
    }

    /// A reserve of `key`, issued now on the node's clock.
    fn reserve(&self, key: &str) -> JobReserve {
        let now = self.node.clock.wall_ms();
        JobReserve {
            key: key.to_owned(),
            pin: pin(),
            slot: SlotSelector::default(),
            issuer: self.issuer,
            starter: Starter::Owner,
            issued_at_ms: now,
            not_after_ms: now + 300_000,
        }
    }

    fn submit(&self, key: &str) -> SignedJobSubmit {
        let now = self.node.clock.wall_ms();
        let pin = pin();
        let submit = JobSubmit {
            key: key.to_owned(),
            job: EntityId::now(),
            chunk: 0,
            maximum_secs: pin.request.maximum_secs,
            pin,
            slot: SlotSelector::default(),
            issued_at_ms: now,
            not_after_ms: now + 300_000,
            issuer: self.issuer,
            starter: Starter::Owner,
            hold: HoldRef {
                reservation: format!("hold-{key}"),
                generation: 1,
            },
            authority_heads: Vec::new(),
            warm: Vec::new(),
            continues: None,
        };
        SignedJobSubmit::sign(submit, ScriptedSigner::new(self.issuer).as_ref())
            .expect("the issuer signs")
    }

    /// Reserves and submits `key`, and waits until its unit runs.
    fn run(&self, jobs: &NodeJobs, key: &str) -> NodeKey {
        assert_eq!(
            receipt(jobs.reserve(self.issuer, self.reserve(key))).state,
            JobState::Held
        );
        assert_eq!(
            receipt(jobs.submit(self.issuer, self.submit(key))).state,
            JobState::Accepted
        );
        wait_for(jobs, key, |entry| entry.state == JobState::Launching);
        jobs.tick();
        wait_for(jobs, key, |entry| entry.state == JobState::Running)
    }

    /// One period on, and one tick: the next readiness check, when no
    /// attempt runs.
    fn check(&self, jobs: &NodeJobs) -> ReadinessState {
        self.node.clock.advance_ms(PERIOD_MS);
        jobs.tick();
        jobs.readiness().state
    }
}

fn receipt(answer: JobAnswer) -> JobReceipt {
    match answer {
        JobAnswer::Receipt(signed) => signed.receipt,
        other => panic!("expected a receipt, got {other:?}"),
    }
}

fn known(answer: JobStatusAnswer) -> JobReceipt {
    match answer {
        JobStatusAnswer::Known(signed) => signed.receipt,
        other => panic!("expected a known key, got {other:?}"),
    }
}

fn kinds(jobs: &NodeJobs) -> Vec<IncidentKind> {
    jobs.incidents(None, usize::MAX)
        .into_iter()
        .map(|incident| incident.kind)
        .collect()
}

fn not_ready(check: ReadinessCheck, why: &str) -> ReadinessState {
    ReadinessState::NotReady {
        check,
        why: why.to_owned(),
    }
}

/// Waits until the key exists and `done` holds for it: the node's staging
/// worker and launch commit run on threads of their own and signal nothing
/// a test could await, so the wait polls.
fn wait_for(jobs: &NodeJobs, key: &str, done: impl Fn(&NodeKey) -> bool) -> NodeKey {
    // testkit-lint: allow(wall-clock) bounds a wait on the node's own worker threads
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(found) = jobs.keys().into_iter().find(|entry| entry.key == key)
            && done(&found)
        {
            return found;
        }
        assert!(
            // testkit-lint: allow(wall-clock) the same bound
            Instant::now() < deadline,
            "key {key} did not reach the state"
        );
        // testkit-lint: allow(sleep) the poll interval; the worker threads signal nothing
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Section 10, Q4: a machine whose idle check fails takes no new work,
/// with the check named, and once a check passes it takes work again with
/// nobody asked (`machines.drain.clear_by` = `after_readiness_check`, the
/// default). Each change is one incident, and both outlast a restart.
#[test]
fn a_machine_that_fails_its_idle_check_takes_no_new_work_and_recovers_without_a_person() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    assert_eq!(jobs.readiness().state, ReadinessState::Unchecked);

    // The driver stops answering while the machine is idle. The first tick checks it.
    fixture
        .node
        .devices
        .set_idle_probe_failure(Some(DRIVER_DOWN));
    jobs.tick();
    let failed_at = fixture.node.clock.wall_ms();
    let readiness = jobs.readiness();
    assert_eq!(
        readiness.state,
        not_ready(ReadinessCheck::Devices, DRIVER_DOWN)
    );
    assert_eq!(readiness.failed_in_a_row, 1);
    assert_eq!(readiness.failing_since_ms, Some(failed_at));
    assert_eq!(
        jobs.attachment().readiness(),
        Some(readiness),
        "Node reports the readiness fact"
    );

    // No new work: a reserve is refused as drained, naming the check.
    let refused = receipt(jobs.reserve(fixture.issuer, fixture.reserve("job-q4/refused")));
    assert!(
        matches!(&refused.end, Some(JobEnd::Refused { reason })
            if reason == "node_drained: readiness devices: driver not answering"),
        "{:?}",
        refused.end
    );

    // A second failed check: the streak grows from the same start, and the
    // same failure makes no second incident.
    assert_eq!(
        fixture.check(&jobs),
        not_ready(ReadinessCheck::Devices, DRIVER_DOWN)
    );
    let readiness = jobs.readiness();
    assert_eq!(readiness.failed_in_a_row, 2);
    assert_eq!(readiness.failing_since_ms, Some(failed_at));

    // The driver answers again: the next check passes and clears the drain.
    fixture.node.devices.set_idle_probe_failure(None);
    assert_eq!(fixture.check(&jobs), ReadinessState::Ready);
    let readiness = jobs.readiness();
    assert_eq!(readiness.failed_in_a_row, 0);
    assert_eq!(readiness.failing_since_ms, None);
    assert_eq!(
        readiness
            .results
            .iter()
            .map(|result| result.state.clone())
            .collect::<Vec<_>>(),
        vec![
            not_ready(ReadinessCheck::Devices, DRIVER_DOWN),
            not_ready(ReadinessCheck::Devices, DRIVER_DOWN),
            ReadinessState::Ready,
        ]
    );
    assert_eq!(fixture.node.devices.drained(), None);
    assert_eq!(fixture.node.devices.drain_clears(), 1);
    let held = receipt(jobs.reserve(fixture.issuer, fixture.reserve("job-q4/held")));
    assert_eq!(held.state, JobState::Held);

    let rule = Some(DRAIN_RULE_DEFAULT.to_owned());
    let incidents = vec![
        IncidentKind::ReadinessFailed {
            check: ReadinessCheck::Devices,
            why: DRIVER_DOWN.to_owned(),
            failed_in_a_row: 1,
        },
        IncidentKind::Drained {
            why: "readiness devices: driver not answering".to_owned(),
            rule: rule.clone(),
        },
        IncidentKind::ReadinessPassed { after_failures: 2 },
        IncidentKind::DrainCleared { rule },
    ];
    assert_eq!(kinds(&jobs), incidents);

    // The record and the incidents outlast an engine restart.
    drop(jobs);
    let jobs = fixture.node.open();
    assert_eq!(jobs.readiness(), readiness);
    jobs.tick();
    assert_eq!(kinds(&jobs), incidents);
}

/// The first tick checks before a period has elapsed, including after a restart.
#[test]
fn the_first_tick_after_the_engine_starts_checks_the_machine() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    fixture
        .node
        .devices
        .set_idle_probe_failure(Some(DRIVER_DOWN));
    jobs.tick();
    let failed = jobs.readiness();
    assert_eq!(
        failed.state,
        not_ready(ReadinessCheck::Devices, DRIVER_DOWN)
    );
    assert_eq!(failed.checked_at_ms, Some(NOW_MS));
    assert!(fixture.node.devices.drained().is_some());

    drop(jobs);
    fixture.node.devices.set_idle_probe_failure(None);
    fixture.node.clock.advance_ms(1_000);
    let jobs = fixture.node.open();
    assert_eq!(jobs.readiness(), failed);
    jobs.tick();
    let ready = jobs.readiness();
    assert_eq!(ready.state, ReadinessState::Ready);
    assert_eq!(ready.checked_at_ms, Some(NOW_MS + 1_000));
    assert_eq!(fixture.node.devices.drained(), None);
}

/// Both a disable at the box and the following enable make a check due.
#[test]
fn enabling_a_disabled_node_checks_it_at_the_next_tick() {
    let rig = OfferFixture::new();
    let jobs = rig.open();
    jobs.tick();
    assert_eq!(jobs.readiness().state, ReadinessState::Ready);
    assert_eq!(jobs.readiness().results.len(), 1);

    let marker = marker_beside(rig.node.file(), DISABLED_MARKER_EXTENSION);
    fs::write(&marker, "disabled\n").expect("disable at the box");
    rig.fixture.node.clock.advance_ms(1_000);
    jobs.tick();
    let disabled = jobs.readiness();
    assert_eq!(disabled.state, ReadinessState::Ready);
    assert_eq!(disabled.results.len(), 2);
    assert_eq!(disabled.checked_at_ms, Some(NOW_MS + 1_000));

    rig.fixture
        .node
        .devices
        .set_idle_probe_failure(Some(DRIVER_DOWN));
    fs::remove_file(marker).expect("enable at the box");
    rig.fixture.node.clock.advance_ms(1_000);
    jobs.tick();
    rig.assert_driver_failure(&jobs);
}

/// An owner's newly offered GPU and another booker's withheld list each make a check due.
#[test]
fn an_owner_offer_or_a_withheld_list_change_checks_at_the_next_tick() {
    let rig = OfferFixture::new();
    rig.owner_offers(false);
    let jobs = rig.open();
    jobs.tick();
    assert_eq!(jobs.readiness().state, ReadinessState::Ready);

    let fixture = &rig.fixture;
    fixture
        .node
        .devices
        .set_idle_probe_failure(Some(DRIVER_DOWN));
    rig.owner_offers(true);
    fixture.node.clock.advance_ms(1_000);
    jobs.tick();
    rig.assert_driver_failure(&jobs);

    fixture.node.devices.set_idle_probe_failure(None);
    assert_eq!(fixture.check(&jobs), ReadinessState::Ready);
    assert_eq!(rig.slots.drained().expect("read the drain"), None);

    fixture
        .node
        .devices
        .set_idle_probe_failure(Some(DRIVER_DOWN));
    fs::write(&rig.withheld_file, format!("{DEVICE}\n")).expect("the booker withholds the GPU");
    fixture.node.clock.advance_ms(1_000);
    jobs.tick();
    rig.assert_driver_failure(&jobs);
}

#[test]
fn a_withheld_list_that_is_not_a_regular_file_never_blocks_the_tick() {
    let rig = OfferFixture::new();
    let jobs = rig.open();
    fs::remove_file(&rig.withheld_file).expect("remove the withheld list");
    let made = oneiron_spawn::command("mkfifo")
        .arg(&rig.withheld_file)
        .status()
        .expect("mkfifo");
    assert!(made.success(), "mkfifo");

    let slots = Arc::clone(&rig.slots);
    let now_ms = rig.fixture.node.clock.wall_ms();
    let (finished, outcome) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        jobs.tick();
        let _ = finished.send(slots.availability(now_ms));
    });
    let error = outcome
        .recv_timeout(Duration::from_secs(20))
        .expect("the tick and availability returned without a writer on the FIFO")
        .expect_err("a FIFO is not a valid withheld list");
    let expected = format!("{}: not a regular file", rig.withheld_file.display());
    assert!(
        matches!(&error, GpuProbeError::WithheldUnreadable { reason } if reason == &expected),
        "{error}"
    );
}

/// The device probe judges the withheld list it was given, not the file as
/// it reads now: with an unreadable file, the given list still answers.
#[test]
fn the_device_probe_judges_the_withheld_list_it_was_given() {
    let rig = OfferFixture::new();
    fs::write(&rig.withheld_file, [0xff, 0xfe]).expect("the withheld list is not UTF-8");
    let now_ms = rig.fixture.node.clock.wall_ms();
    let error = rig
        .slots
        .availability(now_ms)
        .expect_err("the file does not read");
    assert!(
        matches!(error, GpuProbeError::WithheldUnreadable { .. }),
        "{error}"
    );
    rig.slots
        .availability_with_withheld(now_ms, BTreeSet::new())
        .expect("the given empty list reads");
}

/// Another booker taking the GPU is not a failure: its process computes on
/// the GPU, and the GPU joins the withheld list. The check that change
/// makes due reads the GPU as withheld, not busy, passes, and leaves the
/// machine undrained, so the node does not drain each time the fleet takes
/// the card.
#[test]
fn a_gpu_another_booker_takes_while_its_process_runs_passes_the_check_it_makes_due() {
    let rig = OfferFixture::new();
    let jobs = rig.open();
    jobs.tick();
    assert_eq!(jobs.readiness().state, ReadinessState::Ready);
    assert_eq!(jobs.readiness().results.len(), 1);

    rig.processes
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(GpuComputeProcess {
            device_id: DEVICE.to_owned(),
            pid: Some(BOOKER_PID),
        });
    fs::write(&rig.withheld_file, format!("{DEVICE}\n")).expect("the booker withholds the GPU");
    rig.fixture.node.clock.advance_ms(1_000);
    jobs.tick();
    let readiness = jobs.readiness();
    assert_eq!(readiness.state, ReadinessState::Ready);
    assert_eq!(readiness.checked_at_ms, Some(NOW_MS + 1_000));
    assert_eq!(readiness.results.len(), 2);
    assert_eq!(readiness.failed_in_a_row, 0);
    assert_eq!(rig.slots.drained().expect("read the drain"), None);
    assert!(
        !kinds(&jobs)
            .iter()
            .any(|kind| matches!(kind, IncidentKind::Drained { .. })),
        "a withheld GPU drains nothing: {:?}",
        kinds(&jobs)
    );
    let availability = rig
        .slots
        .availability(rig.fixture.node.clock.wall_ms())
        .expect("read the GPUs");
    assert_eq!(availability.devices.len(), 1);
    assert_eq!(availability.devices[0].state, GpuDeviceState::Withheld);
}

/// With the same offer, checks still wait for the configured period.
#[test]
fn with_no_change_no_second_check_runs_before_the_period() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    jobs.tick();
    let first = jobs.readiness();
    assert_eq!(first.state, ReadinessState::Ready);
    assert_eq!(first.checked_at_ms, Some(NOW_MS));
    assert_eq!(first.results.len(), 1);

    fixture.node.clock.advance_ms(1_000);
    jobs.tick();
    assert_eq!(jobs.readiness(), first);
    fixture
        .node
        .devices
        .set_idle_probe_failure(Some(DRIVER_DOWN));
    fixture.node.clock.advance_ms(PERIOD_MS - 2_000);
    jobs.tick();
    assert_eq!(jobs.readiness(), first);
    assert_eq!(fixture.node.devices.drained(), None);

    fixture.node.clock.advance_ms(1_000);
    jobs.tick();
    let second = jobs.readiness();
    assert_eq!(
        second.state,
        not_ready(ReadinessCheck::Devices, DRIVER_DOWN)
    );
    assert_eq!(second.checked_at_ms, Some(NOW_MS + PERIOD_MS));
    assert_eq!(second.results.len(), 2);
}

/// Section 10, Q4: the breadcrumb lines a running key's ticks wrote, with
/// its device's temperature, power draw and memory in use, are on the
/// `Lost` receipt a host reset leaves; the reset is an incident.
#[test]
fn the_last_breadcrumb_before_a_reset_is_on_the_lost_receipt() {
    let fixture = fixture();
    let cool = sample(61, 150_000, 18_432);
    let hot = sample(93, 301_250, 22_016);
    fixture.node.devices.set_sample(cool.clone());
    let jobs = fixture.node.open();
    let key = "job-q4/reset";
    fixture.run(&jobs, key);

    // The card heats up under the run; the next tick writes its line.
    fixture.node.clock.advance_ms(30_000);
    fixture.node.devices.set_sample(hot.clone());
    jobs.tick();
    let last_tick_at = fixture.node.clock.wall_ms();

    // A hard reset: the units are gone, and the machine boots again.
    drop(jobs);
    fixture.node.units.clear();
    fixture.node.clock.reboot("boot-after-reset");
    let jobs = fixture.node.open();
    let lost = known(jobs.find(fixture.issuer, key));
    let Some(JobEnd::Lost {
        reason,
        breadcrumbs,
        ..
    }) = &lost.end
    else {
        panic!("expected a lost key, got {:?}", lost.end);
    };
    assert_eq!(reason, "host_reset");
    let last = breadcrumbs
        .last()
        .expect("the reset left the key's breadcrumb lines");
    assert_eq!(last.boot_id, "boot-1");
    assert_eq!(last.wall_ms, last_tick_at);
    assert_eq!(last.devices, vec![hot]);
    assert_eq!(
        breadcrumbs.first().map(|first| first.devices.clone()),
        Some(vec![cool]),
        "the earlier lines are kept too"
    );
    assert!(
        kinds(&jobs).contains(&IncidentKind::HostReset {
            previous_boot: "boot-1".to_owned()
        }),
        "{:?}",
        kinds(&jobs)
    );
}

/// `machines.drain.clear_by` = `person_at_box`: a passed check leaves the
/// drain for the person, and their clear at the box is recorded as not the
/// rule's.
#[test]
fn with_the_clear_left_to_a_person_a_passing_check_keeps_the_drain() {
    let fixture = fixture();
    fixture
        .node
        .admission
        .set_drain_clear_by(DrainClearBy::PersonAtBox);
    let jobs = fixture.node.open();
    fixture
        .node
        .devices
        .set_idle_probe_failure(Some(DRIVER_DOWN));
    assert_eq!(
        fixture.check(&jobs),
        not_ready(ReadinessCheck::Devices, DRIVER_DOWN)
    );
    assert!(fixture.node.devices.drained().is_some());

    fixture.node.devices.set_idle_probe_failure(None);
    assert_eq!(fixture.check(&jobs), ReadinessState::Ready);
    assert!(
        fixture.node.devices.drained().is_some(),
        "the check passed and the drain waits for the person"
    );
    let refused = receipt(jobs.reserve(fixture.issuer, fixture.reserve("job-q4/waits")));
    assert!(
        matches!(&refused.end, Some(JobEnd::Refused { reason }) if reason.starts_with("node_drained")),
        "{:?}",
        refused.end
    );

    // The person clears it at the box.
    NodeDevices::clear_drain(fixture.node.devices.as_ref()).expect("the clear");
    jobs.tick();
    assert_eq!(
        kinds(&jobs).last(),
        Some(&IncidentKind::DrainCleared { rule: None })
    );
    let held = receipt(jobs.reserve(fixture.issuer, fixture.reserve("job-q4/cleared")));
    assert_eq!(held.state, JobState::Held);
}

/// A check never runs while an attempt runs; the first tick after the
/// attempt ends checks.
#[test]
fn no_check_runs_while_an_attempt_runs() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let key = "job-q4/running";
    fixture.run(&jobs, key);
    fixture
        .node
        .devices
        .set_idle_probe_failure(Some(DRIVER_DOWN));
    fixture.node.clock.advance_ms(PERIOD_MS + 1_000);
    jobs.tick();
    assert_eq!(jobs.readiness().state, ReadinessState::Unchecked);
    assert_eq!(fixture.node.devices.drained(), None);

    fixture.node.units.exit(key, 0);
    jobs.tick();
    wait_for(&jobs, key, |entry| entry.state == JobState::Ended);
    jobs.tick();
    assert_eq!(
        jobs.readiness().state,
        not_ready(ReadinessCheck::Devices, DRIVER_DOWN)
    );
}

/// No readiness check runs while a device release is still owed: the end
/// record moved the key to `Ended` but its unit is still stopping, so the
/// check waits, and the first tick after the unit is gone runs it.
#[test]
fn no_check_runs_while_a_device_release_is_owed() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    jobs.tick();
    let first = jobs.readiness();
    assert_eq!(first.state, ReadinessState::Ready);
    assert_eq!(first.results.len(), 1);

    let key = "job-q4/release-owed";
    let running = fixture.run(&jobs, key);
    assert!(
        running
            .launch
            .as_ref()
            .is_some_and(|launch| !launch.devices.is_empty()),
        "the run holds a device lease"
    );
    fixture.node.admission.set_controls(NodeControls {
        enabled: true,
        paused: Some("paused at the box".to_owned()),
        ..NodeControls::default()
    });
    fixture.node.units.exit_while_stopping(key);
    jobs.tick();
    let ended = wait_for(&jobs, key, |entry| entry.state == JobState::Ended);
    assert_eq!(jobs.readiness(), first);
    assert_eq!(ended.release, DeviceRelease::Held);

    fixture.node.units.finish_stopping(key);
    jobs.tick();
    let released = wait_for(&jobs, key, |entry| {
        matches!(entry.release, DeviceRelease::Confirmed { .. })
    });
    assert!(
        matches!(released.release, DeviceRelease::Confirmed { .. }),
        "the unit is gone and the release passed"
    );
    let idle = jobs.readiness();
    assert_eq!(idle.state, ReadinessState::Ready);
    assert_eq!(idle.results.len(), 2);
}

/// An offer seen during an attempt remains unchecked until an idle tick.
#[test]
fn a_change_while_an_attempt_runs_is_checked_at_the_first_idle_tick() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    jobs.tick();
    let first = jobs.readiness();
    assert_eq!(first.state, ReadinessState::Ready);

    let key = "job-q4/offer-while-running";
    fixture.run(&jobs, key);
    fixture.node.admission.set_controls(NodeControls {
        enabled: true,
        paused: Some("paused at the box".to_owned()),
        ..NodeControls::default()
    });
    fixture
        .node
        .devices
        .set_idle_probe_failure(Some(DRIVER_DOWN));
    fixture.node.clock.advance_ms(1_000);
    jobs.tick();
    assert_eq!(jobs.readiness(), first);
    assert_eq!(fixture.node.devices.drained(), None);

    fixture.node.units.exit(key, 0);
    jobs.tick();
    wait_for(&jobs, key, |entry| entry.state == JobState::Ended);
    let idle = jobs.readiness();
    assert_eq!(idle.state, not_ready(ReadinessCheck::Devices, DRIVER_DOWN));
    assert_eq!(idle.checked_at_ms, Some(NOW_MS + 1_000));
    assert_eq!(idle.results.len(), 2);
    assert!(fixture.node.devices.drained().is_some());
}

#[test]
fn a_change_that_goes_back_while_an_attempt_runs_is_still_checked_at_the_first_idle_tick() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    jobs.tick();
    let first = jobs.readiness();
    assert_eq!(first.state, ReadinessState::Ready);
    assert_eq!(first.results.len(), 1);

    let key = "job-q4/offer-goes-back-while-running";
    fixture.run(&jobs, key);
    fixture.node.admission.set_controls(NodeControls {
        enabled: true,
        paused: Some("paused at the box".to_owned()),
        ..NodeControls::default()
    });
    fixture.node.clock.advance_ms(1_000);
    jobs.tick();
    assert_eq!(jobs.readiness(), first);
    assert_eq!(fixture.node.devices.drained(), None);

    fixture.node.admission.set_controls(NodeControls {
        enabled: true,
        ..NodeControls::default()
    });
    fixture
        .node
        .devices
        .set_idle_probe_failure(Some(DRIVER_DOWN));
    fixture.node.units.exit(key, 0);
    jobs.tick();
    wait_for(&jobs, key, |entry| entry.state == JobState::Ended);
    let idle = jobs.readiness();
    assert_eq!(idle.state, not_ready(ReadinessCheck::Devices, DRIVER_DOWN));
    assert_eq!(idle.checked_at_ms, Some(NOW_MS + 1_000));
    assert_eq!(idle.results.len(), 2);
    assert!(fixture.node.devices.drained().is_some());
}

/// Each check names itself when it fails, the first failure in the order
/// is the one named, and a pass after any of them clears the drain.
#[test]
fn each_failed_check_names_itself_and_a_pass_clears_the_drain() {
    let fixture = fixture();
    let jobs = fixture.node.open();

    let no_cutoff = ScopeCapabilities {
        cutoff_without_engine: BoundReport {
            strength: BoundStrength::None,
            evidence: "scripted".to_owned(),
        },
        ..ScriptedJobUnits::kernel_scope()
    };
    fixture.node.units.set_probe(no_cutoff);
    assert_eq!(
        fixture.check(&jobs),
        not_ready(
            ReadinessCheck::Scope,
            "the launch scope lacks cutoff_without_engine"
        )
    );
    fixture
        .node
        .units
        .set_probe(ScriptedJobUnits::kernel_scope());

    fixture.node.admission.set_disk(1024, 2048);
    assert_eq!(
        fixture.check(&jobs),
        not_ready(ReadinessCheck::Disk, "disk_short")
    );
    fixture.node.admission.set_disk(1 << 20, 0);

    let mirror = fixture.dir.path().join("mirror");
    fixture
        .node
        .admission
        .set_template_mirror(TEMPLATE, mirror.clone());
    assert!(matches!(
        fixture.check(&jobs),
        ReadinessState::NotReady {
            check: ReadinessCheck::Mirrors,
            ..
        }
    ));
    std::fs::create_dir_all(&mirror).expect("the mirror");

    // The wall clock steps past the submit skew (120 s) between two checks.
    fixture.node.clock.step_wall_ms(121_000);
    assert!(matches!(
        fixture.check(&jobs),
        ReadinessState::NotReady {
            check: ReadinessCheck::Clock,
            ..
        }
    ));

    fixture
        .node
        .units
        .start_outside_the_journal(&JobKeyId::for_key("job-q4/foreign"));
    assert!(matches!(
        fixture.check(&jobs),
        ReadinessState::NotReady {
            check: ReadinessCheck::Units,
            ..
        }
    ));
    fixture.node.units.clear();

    // The first failure drained the machine with its own why, and later
    // failures kept that drain; the pass clears it.
    assert_eq!(
        fixture.node.devices.drained().as_deref(),
        Some("readiness scope: the launch scope lacks cutoff_without_engine")
    );
    assert_eq!(fixture.check(&jobs), ReadinessState::Ready);
    assert_eq!(fixture.node.devices.drained(), None);

    // Two failures at once: the devices come before the disk.
    fixture
        .node
        .devices
        .set_idle_probe_failure(Some(DRIVER_DOWN));
    fixture.node.admission.set_disk(1024, 2048);
    assert_eq!(
        fixture.check(&jobs),
        not_ready(ReadinessCheck::Devices, DRIVER_DOWN)
    );
}

/// The driver's sample lines: each figure it gives, `None` for the rest,
/// and a line of another shape is refused.
#[test]
fn a_sample_line_reads_each_figure_the_driver_gives() {
    let samples = parse_sample_lines("GPU-a, 64, 123.45, 1024\nGPU-b, [N/A], [Not Supported], 0\n")
        .expect("two lines");
    assert_eq!(
        samples,
        vec![
            DeviceSample {
                device_id: "GPU-a".to_owned(),
                temperature_c: Some(64),
                power_mw: Some(123_450),
                memory_used_mib: Some(1024),
            },
            DeviceSample {
                device_id: "GPU-b".to_owned(),
                temperature_c: None,
                power_mw: None,
                memory_used_mib: Some(0),
            },
        ]
    );
    assert!(parse_sample_lines("GPU-a, 64").is_err());
}
