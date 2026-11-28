//! Pass 33 row R4, the node's half (`33-exec-node/DESIGN.md` 7.1, 7.6 step
//! 5, 7.9; tests T27-T33d): the node answers `oneiron/job-status/1` —
//! `Find`, `Stop`, `Keys` in pages, `Signal`, `Fetch`, `Ack` — keeps an
//! output until its custody is acknowledged, books disk at the reserve, and
//! counts machine failures for its drain. Against R3a's scripted unit
//! manager, device table and clock, and for the drain the real GPU slot
//! table over a fake driver. No privilege and no network: the handlers are
//! called directly, a second `NodeJobs` on the same directory is an engine
//! restart, and a new boot id is a host reset.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --test node_job_status`.
#![cfg(all(oneiron_test_support, unix))]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::job_workload::{DeviceClaim, DeviceKind, Sharing};
use oneiron::machine_capacity::GpuDevice;
use oneiron_server::gpu_execution_node::jobs::{
    JobKeyId, KEYS_PAGE_MAX_BYTES, NodeDevices, NodeJobs, NodeKey,
};
use oneiron_server::gpu_execution_node::wire::{
    DeviceRelease, HoldRef, JobAnswer, JobEnd, JobReceipt, JobRefusal, JobReserve, JobState,
    JobStatusAnswer, JobSubmit, KeyPage, NetworkMode, OutputDecl, OutputsState, ResourceRequest,
    ScopeKind, SignedJobSubmit, SlotSelector, Starter, WorkloadPin,
};
use oneiron_server::gpu_execution_node::{
    GpuComputeProcess, GpuDeviceOffer, GpuDeviceProbe, GpuProbeError, GpuSlotTable,
};
use oneiron_server::test_doors::node_jobs::{ScriptedNode, ScriptedSigner};

const TEMPLATE: &str = "open-models";
const DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const DEVICE: &str = "GPU-scripted-0";
const NOW_MS: u64 = 1_800_000_000_000;
const WAIT: Duration = Duration::from_secs(10);
const VERDICT: &[u8] = br#"{"verdict":"pass","score":0.91}"#;

struct Fixture {
    _dir: tempfile::TempDir,
    node: ScriptedNode,
    issuer: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temp dir");
    let node = ScriptedNode::new(dir.path(), EntityId::now(), TEMPLATE, DIGEST, NOW_MS);
    Fixture {
        _dir: dir,
        node,
        issuer: EntityId::now(),
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
        outputs: vec![
            OutputDecl {
                name: "verdict.json".to_owned(),
                returnable: true,
            },
            OutputDecl {
                name: "trace.bin".to_owned(),
                returnable: false,
            },
        ],
    }
}

impl Fixture {
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

    /// The key's `out/` on the payload disk, made as the job would.
    fn out_dir(&self, key: &str) -> std::path::PathBuf {
        let out = JobKeyId::for_key(key)
            .payload_dir(&self.node.paths.work_dir)
            .join("out");
        std::fs::create_dir_all(&out).expect("out dir");
        out
    }

    /// Runs `key` to a clean end with a verdict and a trace written, and
    /// waits until its outputs are hashed.
    fn run_to_hashed(&self, jobs: &NodeJobs, key: &str) -> NodeKey {
        self.run(jobs, key);
        let out = self.out_dir(key);
        std::fs::write(out.join("verdict.json"), VERDICT).expect("verdict");
        std::fs::write(out.join("trace.bin"), b"trace").expect("trace");
        self.node.clock.advance_ms(30_000);
        self.node.units.exit(key, 0);
        jobs.tick();
        wait_for(jobs, key, |entry| entry.outputs != OutputsState::Pending)
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

fn page(answer: JobStatusAnswer) -> KeyPage {
    match answer {
        JobStatusAnswer::Keys(page) => page,
        other => panic!("expected a page of keys, got {other:?}"),
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
            // testkit-lint: allow(wall-clock) the same bound
            Instant::now() < deadline,
            "key {key} did not reach the state: {:?}",
            entry(jobs, key)
        );
        // testkit-lint: allow(sleep) the poll interval; the worker threads signal nothing
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn not_fetchable(answer: &JobStatusAnswer) -> bool {
    matches!(
        answer,
        JobStatusAnswer::Refused(JobRefusal::OutputNotFetchable { .. })
    )
}

/// T27, the node's half: a stop is answered `Ending` until the unit is seen
/// empty; then the device stays held while its probe fails, and goes back
/// only after a clean probe.
#[test]
fn a_stop_is_confirmed_only_when_the_unit_is_empty_and_the_lease_waits_for_a_clean_probe() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let key = "job-27/chunk-0";
    fixture.run(&jobs, key);

    // The service manager does not take the stop: the key is ending, never
    // ended, while its unit is not seen empty.
    fixture.node.units.set_answering(false);
    let stopping = known(jobs.stop(fixture.issuer, key));
    assert_eq!(stopping.state, JobState::Ending);
    assert_eq!(stopping.end, None);
    jobs.tick();
    let still = known(jobs.find(fixture.issuer, key));
    assert_eq!(
        still.state,
        JobState::Ending,
        "no end before the unit is empty"
    );
    assert_eq!(fixture.node.devices.taken_by(DEVICE).as_deref(), Some(key));

    // The stop is taken and the unit is empty, but the device probe fails:
    // the key ends as stopped, and the device stays out.
    fixture.node.units.set_answering(true);
    fixture.node.devices.set_probe_fails(true);
    jobs.tick();
    jobs.tick();
    let ended = known(jobs.find(fixture.issuer, key));
    assert_eq!(ended.state, JobState::Ended);
    assert_eq!(ended.end, Some(JobEnd::Stopped));
    assert!(
        matches!(ended.release, DeviceRelease::Unconfirmed { .. }),
        "{:?}",
        ended.release
    );
    assert_eq!(
        fixture.node.devices.taken_by(DEVICE).as_deref(),
        Some(key),
        "a failed probe is never an empty device"
    );
    // A second key cannot launch on it meanwhile.
    let second = "job-27b/chunk-0";
    receipt(jobs.reserve(fixture.issuer, fixture.reserve(second)));
    receipt(jobs.submit(fixture.issuer, fixture.submit(second)));
    let refused = wait_for(&jobs, second, |entry| entry.state == JobState::Ended);
    // Refused at placement (the slot table withholds the device) or at the
    // launch: either way before any start.
    assert!(
        matches!(
            &refused.end,
            Some(JobEnd::Refused { .. } | JobEnd::LaunchRefused { .. })
        ),
        "no new job takes a device that waits for its probe: {:?}",
        refused.end
    );
    assert_eq!(fixture.node.units.starts(second), 0);

    // A clean probe gives the device back.
    fixture.node.devices.set_probe_fails(false);
    jobs.tick();
    let released = wait_for(&jobs, key, |entry| {
        matches!(entry.release, DeviceRelease::Confirmed { .. })
    });
    assert_eq!(released.end, Some(JobEnd::Stopped));
    assert_eq!(fixture.node.devices.taken_by(DEVICE), None);
}

/// T28: a stop before the launch commit closes the key as `Withdrawn`: not
/// started, no seconds, no unit, no disk, and a late submit starts nothing.
#[test]
fn a_cancel_before_launch_withdraws_and_bills_nothing() {
    let fixture = fixture();
    let jobs = fixture.node.open();

    // Held: the reserve arrived, the submit did not.
    let held = "job-28/chunk-0";
    receipt(jobs.reserve(fixture.issuer, fixture.reserve(held)));
    assert_eq!(jobs.booked_disk_mib(), 2 * 1024);
    let withdrawn = known(jobs.stop(fixture.issuer, held));
    assert_eq!(withdrawn.state, JobState::Ended);
    assert_eq!(withdrawn.end, Some(JobEnd::Withdrawn));
    assert!(!withdrawn.started);
    assert_eq!(withdrawn.measured_secs, None);
    assert_eq!(withdrawn.occupied, None);
    let late = receipt(jobs.submit(fixture.issuer, fixture.submit(held)));
    assert_eq!(
        late.end,
        Some(JobEnd::Withdrawn),
        "a closed key stays closed"
    );

    // Staging: the submit was accepted and staging holds.
    let staging = "job-28/chunk-1";
    fixture.node.stager.hold();
    receipt(jobs.reserve(fixture.issuer, fixture.reserve(staging)));
    receipt(jobs.submit(fixture.issuer, fixture.submit(staging)));
    assert!(fixture.node.stager.wait_entered(1, WAIT), "staging began");
    let withdrawn = known(jobs.stop(fixture.issuer, staging));
    fixture.node.stager.let_go();
    assert_eq!(withdrawn.end, Some(JobEnd::Withdrawn));
    assert!(!withdrawn.started);
    assert_eq!(withdrawn.measured_secs, None);
    // testkit-lint: allow(sleep) proves an absence: no worker signals that it started nothing
    std::thread::sleep(Duration::from_millis(300));
    jobs.tick();
    assert_eq!(fixture.node.units.total_starts(), 0, "no unit ever started");
    assert_eq!(fixture.node.devices.leases_given(), 0, "no device was held");
    assert_eq!(jobs.booked_disk_mib(), 0, "a withdrawn key books no disk");

    // A key the node never saw: the stop closes it, and its reserve after
    // it finds the closed key.
    let unseen = "job-28/chunk-2";
    let closed = known(jobs.stop(fixture.issuer, unseen));
    assert_eq!(closed.end, Some(JobEnd::Withdrawn));
    let after = receipt(jobs.reserve(fixture.issuer, fixture.reserve(unseen)));
    assert_eq!(after.end, Some(JobEnd::Withdrawn));
    assert_eq!(fixture.node.units.total_starts(), 0);
}

/// T29, the node's half: every receipt of a key carries the journal's
/// sequence, which only grows, across an engine restart and a host reset.
/// The issuer keeps the receipt with the highest sequence (row R4's issuer
/// half).
#[test]
fn an_older_report_never_replaces_a_newer_one_also_after_a_node_reboot() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let key = "job-29/chunk-0";
    fixture.run(&jobs, key);
    let running = known(jobs.find(fixture.issuer, key));
    assert_eq!(running.state, JobState::Running);

    // An engine restart: the same history, the same sequence.
    drop(jobs);
    let jobs = fixture.node.open();
    let again = known(jobs.find(fixture.issuer, key));
    assert_eq!(again.state, JobState::Running);
    assert!(again.seq >= running.seq);
    assert_eq!(again.epoch, running.epoch);

    // A host reset: a new boot, the key lost, and a higher sequence.
    drop(jobs);
    fixture.node.units.clear();
    fixture.node.clock.reboot("boot-after-reset");
    let jobs = fixture.node.open();
    let lost = known(jobs.find(fixture.issuer, key));
    assert_eq!(lost.state, JobState::Ended);
    assert!(lost.seq > running.seq, "{} <= {}", lost.seq, running.seq);
    assert_eq!(lost.boot_id, "boot-after-reset");
    assert_eq!(lost.epoch, running.epoch, "the same history");

    // The page of keys carries the same newest receipt.
    let listed = page(jobs.keys_page(fixture.issuer, None));
    let entry = listed
        .entries
        .iter()
        .find(|entry| entry.key == key)
        .expect("the key is listed");
    let ended = entry
        .ended
        .as_ref()
        .expect("an ended key carries its receipt");
    assert_eq!(ended.receipt.seq, lost.seq);
}

/// T30, the node's half: a host reset under a running key is `Lost` with
/// unknown seconds (never zero), counted as started, and counted against
/// the machine.
#[test]
fn a_node_reset_reports_lost_with_unknown_seconds_and_bills_nothing() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let key = "job-30/chunk-0";
    fixture.run(&jobs, key);
    fixture.node.clock.advance_ms(60_000);
    jobs.tick();
    let ticking = known(jobs.find(fixture.issuer, key));
    assert!(ticking.measured_secs.is_some_and(|secs| secs >= 60));

    drop(jobs);
    fixture.node.units.clear();
    fixture.node.clock.reboot("boot-after-reset");
    let jobs = fixture.node.open();
    let lost = known(jobs.find(fixture.issuer, key));
    assert!(
        matches!(&lost.end, Some(JobEnd::Lost { reason, .. }) if reason == "host_reset"),
        "{:?}",
        lost.end
    );
    assert_eq!(
        lost.measured_secs, None,
        "unknown is not zero on the receipt"
    );
    assert!(
        lost.started,
        "a lost run is never reported as never started"
    );
    for _ in 0..3 {
        jobs.tick();
    }
    let counted = fixture
        .node
        .devices
        .finished()
        .into_iter()
        .find(|(finished, _)| finished == key)
        .map(|(_, end)| end);
    assert!(
        matches!(
            counted,
            Some(oneiron_server::gpu_execution_node::GpuLeaseEnd::Failed { .. })
        ),
        "a lost box counts against the machine: {counted:?}"
    );
}

/// A driver with one GPU and no compute process on it.
struct OneGpu;

impl GpuDeviceProbe for OneGpu {
    fn devices(&self) -> Result<Vec<GpuDevice>, GpuProbeError> {
        Ok(vec![GpuDevice {
            device_id: DEVICE.to_owned(),
            model: "NVIDIA GeForce RTX 4090".to_owned(),
            memory_total_mib: 24_564,
        }])
    }

    fn compute_processes(&self) -> Result<Vec<GpuComputeProcess>, GpuProbeError> {
        Ok(Vec::new())
    }
}

/// T32, the node's half, on the real GPU slot table: three ends in a row
/// whose cause is the machine's drain it; a caller's stop neither counts
/// nor resets, a run past 5 s resets; and only a person's clear opens the
/// node again.
#[test]
fn three_machine_failures_in_a_row_drain_the_node_until_a_person_clears_it() {
    let fixture = fixture();
    let table = Arc::new(GpuSlotTable::new(
        Arc::new(OneGpu),
        GpuDeviceOffer {
            offered: BTreeSet::from([DEVICE.to_owned()]),
            drain_after_failures: 3,
            ..GpuDeviceOffer::default()
        },
    ));
    let mut parts = fixture.node.parts();
    parts.devices = Arc::clone(&table) as Arc<dyn NodeDevices>;
    let jobs = NodeJobs::open(fixture.node.paths.clone(), parts).expect("open the node's journal");
    let finish = |key: &str, run_ms: u64, stop: bool| {
        fixture.run(&jobs, key);
        fixture.node.clock.advance_ms(run_ms);
        if stop {
            known(jobs.stop(fixture.issuer, key));
        } else {
            fixture.node.units.exit(key, 1);
        }
        jobs.tick();
        wait_for(&jobs, key, |entry| {
            matches!(entry.release, DeviceRelease::Confirmed { .. })
        });
    };

    finish("job-32/a", 1_000, false);
    finish("job-32/b", 1_000, false);
    // A run past 5 s resets the count.
    finish("job-32/long", 10_000, false);
    finish("job-32/c", 1_000, false);
    // The caller's stop neither counts nor resets.
    finish("job-32/stopped", 1_000, true);
    finish("job-32/d", 1_000, false);
    assert_eq!(
        table.drained().expect("drain readable"),
        None,
        "two in a row"
    );
    finish("job-32/e", 1_000, false);
    let drained = table.drained().expect("drain readable");
    assert!(drained.is_some(), "three in a row drain the node");

    let refused = receipt(jobs.reserve(fixture.issuer, fixture.reserve("job-32/after")));
    assert!(
        matches!(&refused.end, Some(JobEnd::Refused { reason }) if reason.starts_with("node_drained")),
        "{:?}",
        refused.end
    );
    // No request on the wire clears it; a person at the box does.
    table.clear_drain().expect("the clear");
    let held = receipt(jobs.reserve(fixture.issuer, fixture.reserve("job-32/cleared")));
    assert_eq!(held.state, JobState::Held);
}

/// T33: the disk is booked at the reserve, so two reserves never both count
/// the same free bytes; a key that ended unlaunched gives its booking back.
#[test]
fn two_reserves_cannot_both_count_the_same_free_disk() {
    let fixture = fixture();
    // Room for one 2 GiB request past a 1 GiB reserve, not for two.
    fixture.node.admission.set_disk(4 * 1024, 1024);
    let jobs = fixture.node.open();

    let concurrent: Vec<JobReceipt> = std::thread::scope(|scope| {
        let handles: Vec<_> = ["job-33/a", "job-33/b"]
            .into_iter()
            .map(|key| scope.spawn(|| receipt(jobs.reserve(fixture.issuer, fixture.reserve(key)))))
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("reserve thread"))
            .collect()
    });
    let held: Vec<&JobReceipt> = concurrent
        .iter()
        .filter(|answer| answer.state == JobState::Held)
        .collect();
    let refused: Vec<&JobReceipt> = concurrent
        .iter()
        .filter(|answer| matches!(&answer.end, Some(JobEnd::Refused { .. })))
        .collect();
    assert_eq!((held.len(), refused.len()), (1, 1), "{concurrent:?}");
    assert_eq!(jobs.booked_disk_mib(), 2 * 1024);

    // The held key withdraws: its booking ends, and the next reserve fits.
    known(jobs.stop(fixture.issuer, &held[0].key));
    assert_eq!(jobs.booked_disk_mib(), 0);
    let next = receipt(jobs.reserve(fixture.issuer, fixture.reserve("job-33/c")));
    assert_eq!(next.state, JobState::Held);
}

/// T33b, the node's half: only a hashed, returnable output of an ended key
/// is handed out, read beneath `out/` without following a link, and only
/// while its bytes match the receipt's digest.
#[test]
fn a_returnable_output_is_fetched_and_checked_and_no_other_file_can_be() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let key = "job-33b/chunk-0";

    // Before the end nothing is handed out.
    fixture.run(&jobs, key);
    assert!(not_fetchable(&jobs.fetch(
        fixture.issuer,
        key,
        "verdict.json"
    )));

    let out = fixture.out_dir(key);
    std::fs::write(out.join("verdict.json"), VERDICT).expect("verdict");
    std::fs::write(out.join("trace.bin"), b"trace").expect("trace");
    std::fs::write(out.join("notes.txt"), b"undeclared").expect("notes");
    fixture.node.clock.advance_ms(30_000);
    fixture.node.units.exit(key, 0);
    jobs.tick();
    let hashed = wait_for(&jobs, key, |entry| entry.outputs != OutputsState::Pending);
    let OutputsState::Hashed(digests) = &hashed.outputs else {
        panic!("outputs hashed: {:?}", hashed.outputs);
    };
    let verdict = digests
        .iter()
        .find(|digest| digest.name == "verdict.json")
        .expect("the verdict's digest");
    assert!(verdict.returnable);

    // The returnable output, whole, with the digest the receipt names.
    match jobs.fetch(fixture.issuer, key, "verdict.json") {
        JobStatusAnswer::Output { bytes } => {
            assert_eq!(bytes, VERDICT);
            assert_eq!(
                oneiron_hex::encode(&<sha2::Sha256 as sha2::Digest>::digest(&bytes)),
                verdict.sha256
            );
        }
        other => panic!("expected the output, got {other:?}"),
    }
    // A declared output that is not returnable, an undeclared file, a path,
    // another issuer and an unknown key get nothing.
    assert!(not_fetchable(&jobs.fetch(fixture.issuer, key, "trace.bin")));
    assert!(not_fetchable(&jobs.fetch(fixture.issuer, key, "notes.txt")));
    assert!(not_fetchable(&jobs.fetch(
        fixture.issuer,
        key,
        "../../state/journal"
    )));
    assert_eq!(
        jobs.fetch(EntityId::now(), key, "verdict.json"),
        JobStatusAnswer::Refused(JobRefusal::NotTheKeysIssuer)
    );
    assert!(matches!(
        jobs.fetch(fixture.issuer, "job-unknown", "verdict.json"),
        JobStatusAnswer::Absent { .. }
    ));

    // A file swapped for a link, or changed after its hashing, is refused.
    std::fs::remove_file(out.join("verdict.json")).expect("remove");
    std::os::unix::fs::symlink(out.join("trace.bin"), out.join("verdict.json")).expect("link");
    assert!(not_fetchable(&jobs.fetch(
        fixture.issuer,
        key,
        "verdict.json"
    )));
    std::fs::remove_file(out.join("verdict.json")).expect("remove link");
    std::fs::write(out.join("verdict.json"), b"{\"verdict\":\"fail\"}").expect("rewrite");
    assert!(not_fetchable(&jobs.fetch(
        fixture.issuer,
        key,
        "verdict.json"
    )));
}

/// T33d: an output nobody acknowledged is never cleaned, however long it
/// waits, and keeps its disk booked; after the `Ack` it stays for the keep
/// time, then the tick cleans it and the booking is gone.
#[test]
fn an_unacknowledged_output_is_never_cleaned_by_a_timer() {
    let fixture = fixture();
    fixture.node.admission.set_receipt_keep_days(30);
    let jobs = fixture.node.open();
    let key = "job-33d/chunk-0";
    fixture.run_to_hashed(&jobs, key);
    let payload = JobKeyId::for_key(key).payload_dir(&fixture.node.paths.work_dir);

    // A year passes with no `Ack`: the payload stays and keeps its booking.
    fixture.node.clock.advance_ms(365 * 86_400_000);
    for _ in 0..3 {
        jobs.tick();
    }
    assert!(payload.join("out").join("verdict.json").exists());
    assert_eq!(jobs.booked_disk_mib(), 2 * 1024);
    assert!(matches!(
        jobs.fetch(fixture.issuer, key, "verdict.json"),
        JobStatusAnswer::Output { .. }
    ));
    // Only the key's issuer acknowledges it.
    assert_eq!(
        jobs.acknowledge(EntityId::now(), key),
        JobStatusAnswer::Refused(JobRefusal::NotTheKeysIssuer)
    );

    // The issuer acknowledges custody: the booking ends at once, the files
    // stay for the keep time, and a repeat answers the same.
    assert_eq!(
        jobs.acknowledge(fixture.issuer, key),
        JobStatusAnswer::Acknowledged
    );
    assert_eq!(
        jobs.acknowledge(fixture.issuer, key),
        JobStatusAnswer::Acknowledged
    );
    assert_eq!(jobs.booked_disk_mib(), 0);
    fixture.node.clock.advance_ms(29 * 86_400_000);
    jobs.tick();
    assert!(payload.join("out").join("verdict.json").exists());

    // Past the keep time the tick cleans it, once.
    fixture.node.clock.advance_ms(2 * 86_400_000);
    jobs.tick();
    assert!(!payload.exists());
    let cleaned = entry(&jobs, key).expect("the journal keeps the key");
    assert!(cleaned.cleaned);
    assert!(not_fetchable(&jobs.fetch(
        fixture.issuer,
        key,
        "verdict.json"
    )));
    jobs.tick();

    // The acknowledgement and the cleaning outlast a restart.
    drop(jobs);
    let jobs = fixture.node.open();
    let kept = entry(&jobs, key).expect("the key after a restart");
    assert!(kept.cleaned);
    assert!(kept.acknowledged_at_ms.is_some());
}

/// `Ack` of a live key is refused and changes nothing.
#[test]
fn an_acknowledgement_of_a_live_key_is_refused() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let key = "job-ack/chunk-0";
    fixture.run(&jobs, key);
    assert_eq!(
        jobs.acknowledge(fixture.issuer, key),
        JobStatusAnswer::Refused(JobRefusal::NotAcknowledgeable {
            state: JobState::Running
        })
    );
    assert_eq!(entry(&jobs, key).expect("the key").acknowledged_at_ms, None);
}

/// `Keys`: the asker's keys only, live and ended, each ended one with its
/// terminal receipt, in pages under the message bound that end on a page
/// with no `next`.
#[test]
fn keys_lists_the_askers_keys_in_pages_that_end_without_next() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let other = EntityId::now();

    // Many closed keys of this issuer, one live key, and none of another
    // issuer's in the listing.
    let mut expected = BTreeSet::new();
    for index in 0..4_000 {
        let key = format!("job-keys/chunk-{index:04}");
        known(jobs.stop(fixture.issuer, &key));
        expected.insert(key);
    }
    let live = "job-keys/live";
    receipt(jobs.reserve(fixture.issuer, fixture.reserve(live)));
    expected.insert(live.to_owned());
    known(jobs.stop(other, "job-keys/other-issuer"));

    let mut seen = BTreeSet::new();
    let mut after: Option<String> = None;
    let mut pages = 0;
    loop {
        let listed = page(jobs.keys_page(fixture.issuer, after.as_deref()));
        pages += 1;
        let encoded = oneiron_organ_protocol::to_vec(&listed.entries).expect("encode");
        assert!(encoded.len() <= KEYS_PAGE_MAX_BYTES + 16);
        for entry in &listed.entries {
            assert!(seen.insert(entry.key.clone()), "{} twice", entry.key);
            match entry.state {
                JobState::Ended => {
                    let ended = entry.ended.as_ref().expect("its terminal receipt");
                    assert_eq!(ended.receipt.key, entry.key);
                    assert_eq!(ended.receipt.end, Some(JobEnd::Withdrawn));
                }
                _ => assert!(entry.ended.is_none()),
            }
        }
        match listed.next {
            Some(next) => after = Some(next),
            None => break,
        }
        assert!(pages < 1_000);
    }
    assert_eq!(seen, expected);
    assert!(pages >= 2, "{} keys in {pages} page(s)", seen.len());
    assert!(!seen.contains("job-keys/other-issuer"));
    let other_page = page(jobs.keys_page(other, None));
    assert_eq!(other_page.entries.len(), 1);
    assert_eq!(other_page.next, None);
}

/// `Signal`: a checkpoint notice reaches a running workload only when its
/// template names a signal; it never ends or changes the key.
#[test]
fn a_checkpoint_notice_reaches_the_workload_only_when_its_template_names_a_signal() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let key = "job-signal/chunk-0";
    fixture.run(&jobs, key);
    let before = known(jobs.find(fixture.issuer, key));

    assert_eq!(
        jobs.signal(fixture.issuer, key, "checkpoint"),
        JobStatusAnswer::Acknowledged
    );
    assert!(
        fixture.node.units.signals(key).is_empty(),
        "no signal named: a no-op"
    );

    fixture
        .node
        .admission
        .set_template_signal(TEMPLATE, Some("USR1"));
    assert_eq!(
        jobs.signal(fixture.issuer, key, "checkpoint"),
        JobStatusAnswer::Acknowledged
    );
    assert_eq!(fixture.node.units.signals(key), vec!["USR1".to_owned()]);
    let after = known(jobs.find(fixture.issuer, key));
    assert_eq!(after.state, JobState::Running);
    assert_eq!(after.seq, before.seq, "a notice journals nothing");
    assert_eq!(after.cutoff_at_ms, before.cutoff_at_ms);
    assert_eq!(
        jobs.signal(EntityId::now(), key, "checkpoint"),
        JobStatusAnswer::Refused(JobRefusal::NotTheKeysIssuer)
    );
}
