//! Row GPU-QUIET-LEASE, the node's part (ANSWER GPU-QUIET-LEASE-FLEET = A):
//! a run of a quiet template has the host to itself, and while it holds the
//! lease the node keeps the fleet's quiet marker for the host
//! (`execution_node.quiet_tag`, the fleet's
//! `<fleet-home>/agent-traces/quiet-hosts/<host>`), in the format the referee's
//! booker writes: one line naming the holder, then `(<host>)`.
//!
//! - The marker is written at the quiet key's reserve, kept fresh while the
//!   key runs, and removed once its outputs are hashed.
//! - While the lease is held, every other reserve answers `Busy` and writes
//!   nothing, and no payload is cleaned; a quiet reserve waits while another
//!   key is live or unhashed.
//! - Another holder's marker keeps every reserve `Busy` and is never
//!   touched.
//! - A marker whose key is gone is cleared at the next start: one an engine
//!   left between the marker and the reserve's record, and one whose key
//!   ended while the engine was down.
//! - The lease follows the quiet key's reserve record: a template that stops
//!   being quiet while its key runs does not end it.
//! - A reserve the node refuses answers `Busy` and journals nothing while the
//!   host is quiet, as an admitted one does.
//! - A key whose release check left its device out keeps a quiet reserve
//!   waiting, also when its workload never started.
//!
//! Against R3a's scripted unit manager, devices and clock. No privilege, no
//! network, no GPU. The card's power limit (`gpu_power_watts`) is the job
//! unit's root steps' act; its tests are in `gpu_execution_node/gpu_power.rs`.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support --test node_quiet_lease`.
#![cfg(all(oneiron_test_support, unix))]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use oneiron::EntityId;
use oneiron::job_workload::{DeviceClaim, DeviceKind, Sharing};
use oneiron_server::gpu_execution_node::jobs::quiet_lease::QuietLease;
use oneiron_server::gpu_execution_node::jobs::{JobKeyId, NodeJobs, NodeKey};
use oneiron_server::gpu_execution_node::wire::{
    DeviceRelease, HoldRef, JobAnswer, JobEnd, JobReceipt, JobReserve, JobState, JobStatusAnswer,
    JobSubmit, NetworkMode, OutputDecl, OutputsState, ResourceRequest, ScopeKind, SignedJobSubmit,
    SlotSelector, Starter, WorkloadPin,
};
use oneiron_server::test_doors::node_jobs::{ScriptedNode, ScriptedSigner, ScriptedStart};

/// The node's everyday template.
const BATCH: &str = "open-models";
/// The template whose runs take the quiet lease.
const TIMING: &str = "timing";
const DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const NOW_MS: u64 = 1_800_000_000_000;
const DAY_MS: u64 = 86_400_000;
const WAIT: Duration = Duration::from_secs(10);
/// The marker the referee's booker writes for a series it runs by hand.
const BOOKER_TAG: &str = "open-models granite compare-4.2-8b om-granite-compare-20261128-series-a3 booker 186158 (sel)\n";

struct Fixture {
    _dir: tempfile::TempDir,
    node: ScriptedNode,
    machine: EntityId,
    issuer: EntityId,
    tag: PathBuf,
}

/// A node holding both templates, `timing` quiet, with its marker at
/// `<dir>/quiet-hosts/node-host`.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temp dir");
    let machine = EntityId::now();
    let node = ScriptedNode::new(dir.path(), machine, BATCH, DIGEST, NOW_MS);
    node.admission.set_template_digest(TIMING, DIGEST);
    let hosts = dir.path().join("quiet-hosts");
    std::fs::create_dir_all(&hosts).expect("quiet-hosts dir");
    let tag = hosts.join("node-host");
    node.admission.set_quiet_lease(QuietLease {
        tag: Some(tag.clone()),
        templates: BTreeSet::from([TIMING.to_owned()]),
    });
    Fixture {
        _dir: dir,
        node,
        machine,
        issuer: EntityId::now(),
        tag,
    }
}

fn pin(template: &str) -> WorkloadPin {
    WorkloadPin {
        template: template.to_owned(),
        template_digest: DIGEST.to_owned(),
        commit: "a".repeat(40),
        contract_sha256: "b".repeat(64),
        contract_path: "contract.json".to_owned(),
        entry: "tools/units/run.sh".to_owned(),
        args: vec!["seed=7".to_owned()],
        request: ResourceRequest {
            cpu_threads: 0,
            memory_mib: 4 * 1024,
            disk_mib: 1024,
            devices: vec![DeviceClaim {
                kind: DeviceKind::Gpu,
                count: 1,
                memory_mib: 20 * 1024,
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

/// `template`'s pin with no device claim.
fn pin_without_devices(template: &str) -> WorkloadPin {
    let mut pin = pin(template);
    pin.request.devices.clear();
    pin
}

impl Fixture {
    fn reserve(&self, key: &str, template: &str) -> JobReserve {
        self.reserve_pin(key, pin(template))
    }

    fn reserve_pin(&self, key: &str, pin: WorkloadPin) -> JobReserve {
        JobReserve {
            key: key.to_owned(),
            pin,
            slot: SlotSelector::default(),
            issuer: self.issuer,
            starter: Starter::Owner,
            issued_at_ms: NOW_MS,
            not_after_ms: NOW_MS + 300_000,
        }
    }

    fn submit(&self, key: &str, template: &str) -> SignedJobSubmit {
        let pin = pin(template);
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

    /// Submits the held `key` and waits until its unit runs.
    fn launch(&self, jobs: &NodeJobs, key: &str, template: &str) -> NodeKey {
        assert_eq!(
            receipt(jobs.submit(self.issuer, self.submit(key, template))).state,
            JobState::Accepted
        );
        wait_for(jobs, key, |entry| entry.state == JobState::Launching);
        jobs.tick();
        wait_for(jobs, key, |entry| entry.state == JobState::Running)
    }

    /// Reserves, submits and launches `key`.
    fn run(&self, jobs: &NodeJobs, key: &str, template: &str) -> NodeKey {
        assert_eq!(
            receipt(jobs.reserve(self.issuer, self.reserve(key, template))).state,
            JobState::Held
        );
        self.launch(jobs, key, template)
    }

    /// Ends the running `key` cleanly and waits until its outputs are hashed.
    fn end_to_hashed(&self, jobs: &NodeJobs, key: &str) -> NodeKey {
        self.node.clock.advance_ms(30_000);
        self.node.units.exit(key, 0);
        jobs.tick();
        wait_for(jobs, key, |entry| entry.outputs != OutputsState::Pending)
    }

    /// The marker this node writes for `key` of `template`, up to its host.
    fn own_tag_start(&self, key: &str, template: &str) -> String {
        format!(
            "oneiron execution-node {} template {template} key {} (",
            self.machine.to_ulid(),
            JobKeyId::for_key(key).as_str()
        )
    }

    fn tag_text(&self) -> Option<String> {
        match std::fs::read_to_string(&self.tag) {
            Ok(text) => Some(text),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("the marker does not read: {error}"),
        }
    }

    /// Asserts the marker is this node's for `key`: one line, naming the
    /// holder first and the host last, in parentheses.
    fn assert_own_tag(&self, key: &str, template: &str) {
        let text = self.tag_text().expect("the quiet marker is there");
        assert!(
            text.starts_with(&self.own_tag_start(key, template)),
            "marker {text:?}"
        );
        assert!(text.ends_with(")\n"), "marker {text:?}");
        assert_eq!(text.lines().count(), 1, "marker {text:?}");
    }
}

fn receipt(answer: JobAnswer) -> JobReceipt {
    match answer {
        JobAnswer::Receipt(signed) => signed.receipt,
        other => panic!("expected a receipt, got {other:?}"),
    }
}

fn is_busy(answer: &JobAnswer) -> bool {
    matches!(answer, JobAnswer::Busy { .. })
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

/// The marker is taken at the quiet key's reserve, before its record, and
/// is the node's own line. While the key runs, each tick moves the marker's
/// time on (a marker counts for 3 hours from its last touch) and writes it
/// again when a sweep removed it. Once the key's outputs are hashed, the
/// next tick removes it.
#[test]
fn a_quiet_run_writes_the_marker_at_its_start_and_removes_it_at_its_end() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let key = "timing-1/chunk-0";

    assert_eq!(
        receipt(jobs.reserve(fixture.issuer, fixture.reserve(key, TIMING))).state,
        JobState::Held
    );
    fixture.assert_own_tag(key, TIMING);
    fixture.launch(&jobs, key, TIMING);
    fixture.assert_own_tag(key, TIMING);

    // Each tick moves the marker's time on.
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&fixture.tag)
        .and_then(|file| file.set_modified(old))
        .expect("age the marker");
    jobs.tick();
    let touched = std::fs::metadata(&fixture.tag)
        .and_then(|facts| facts.modified())
        .expect("the marker's time");
    assert!(touched > old, "the tick did not refresh the marker");

    // A sweep removed it: the next tick writes it again.
    std::fs::remove_file(&fixture.tag).expect("remove the marker");
    jobs.tick();
    fixture.assert_own_tag(key, TIMING);

    // The run ends and its outputs are hashed: the lease ends, and the
    // marker goes with it.
    fixture.end_to_hashed(&jobs, key);
    jobs.tick();
    assert_eq!(fixture.tag_text(), None);
    jobs.tick();
    assert_eq!(fixture.tag_text(), None);
}

/// While a quiet run holds the lease, no other key is reserved (the answer
/// is `Busy`, nothing is journaled) and no payload is cleaned, not even one
/// whose keep time passed. A quiet reserve waits while another key is live
/// or unhashed. After the lease the waiting work goes on.
#[test]
fn while_a_quiet_run_holds_the_lease_no_other_work_starts_on_the_host() {
    let fixture = fixture();
    fixture.node.admission.set_receipt_keep_days(1);
    let jobs = fixture.node.open();
    let batch = "batch-1/chunk-0";
    let timing = "timing-2/chunk-0";

    // Another key runs: the quiet reserve waits and writes nothing.
    fixture.run(&jobs, batch, BATCH);
    assert!(is_busy(
        &jobs.reserve(fixture.issuer, fixture.reserve(timing, TIMING))
    ));
    assert!(entry(&jobs, timing).is_none());
    assert_eq!(fixture.tag_text(), None);

    // Once that key's outputs are hashed, the host is free.
    fixture.end_to_hashed(&jobs, batch);
    assert_eq!(
        jobs.acknowledge(fixture.issuer, batch),
        JobStatusAnswer::Acknowledged
    );
    fixture.run(&jobs, timing, TIMING);
    fixture.assert_own_tag(timing, TIMING);

    // During the lease: another reserve is busy and journals nothing, and
    // the acknowledged payload past its keep time stays.
    let other = "batch-2/chunk-0";
    assert!(is_busy(
        &jobs.reserve(fixture.issuer, fixture.reserve(other, BATCH))
    ));
    assert!(is_busy(&jobs.reserve(
        fixture.issuer,
        fixture.reserve("timing-3/chunk-0", TIMING)
    )));
    assert!(entry(&jobs, other).is_none());
    fixture.node.clock.advance_ms(2 * DAY_MS);
    jobs.tick();
    let batch_payload = JobKeyId::for_key(batch).payload_dir(&fixture.node.paths.work_dir);
    assert!(!entry(&jobs, batch).expect("the batch key").cleaned);

    // The lease ends with the quiet key's hashing: the cleaning and the
    // waiting reserve go on.
    fixture.end_to_hashed(&jobs, timing);
    jobs.tick();
    assert!(entry(&jobs, batch).expect("the batch key").cleaned);
    assert!(!batch_payload.exists());
    assert_eq!(
        receipt(jobs.reserve(fixture.issuer, fixture.reserve(other, BATCH))).state,
        JobState::Held
    );
    assert_eq!(fixture.tag_text(), None);
}

/// A marker another holder wrote (the referee's booker running a timing
/// series by hand) keeps every reserve of this node `Busy`, quiet or not,
/// and no tick moves or removes it. Once its holder removes it, a quiet run
/// takes the host.
#[test]
fn another_holders_marker_keeps_every_reserve_busy_and_is_never_touched() {
    let fixture = fixture();
    std::fs::write(&fixture.tag, BOOKER_TAG).expect("the booker's marker");
    let jobs = fixture.node.open();
    let batch = "batch-1/chunk-0";
    let timing = "timing-1/chunk-0";

    assert!(is_busy(
        &jobs.reserve(fixture.issuer, fixture.reserve(batch, BATCH))
    ));
    assert!(is_busy(
        &jobs.reserve(fixture.issuer, fixture.reserve(timing, TIMING))
    ));
    jobs.tick();
    jobs.tick();
    assert!(entry(&jobs, batch).is_none());
    assert!(entry(&jobs, timing).is_none());
    assert_eq!(fixture.tag_text().as_deref(), Some(BOOKER_TAG));

    // The booker's series ends and it removes its own marker.
    std::fs::remove_file(&fixture.tag).expect("the booker removes its marker");
    assert_eq!(
        receipt(jobs.reserve(fixture.issuer, fixture.reserve(timing, TIMING))).state,
        JobState::Held
    );
    fixture.assert_own_tag(timing, TIMING);
}

/// No stale marker after a crash. An engine that stopped between the marker
/// and the reserve's record left a marker naming a key the journal does not
/// hold: the first tick after the start removes it. A quiet run whose unit
/// ended while the engine was down keeps the marker until its outputs are
/// hashed after the start, and then it goes.
#[test]
fn a_marker_whose_key_is_gone_is_cleared_at_the_next_start() {
    let fixture = fixture();
    let never_recorded = "timing-0/chunk-0";
    std::fs::write(
        &fixture.tag,
        format!(
            "{}node-host)\n",
            fixture.own_tag_start(never_recorded, TIMING)
        ),
    )
    .expect("the marker a stopped engine left");
    let jobs = fixture.node.open();
    jobs.tick();
    assert_eq!(fixture.tag_text(), None);
    assert!(entry(&jobs, never_recorded).is_none());

    // A quiet run, then the engine stops mid-run.
    let key = "timing-1/chunk-0";
    fixture.run(&jobs, key, TIMING);
    fixture.assert_own_tag(key, TIMING);
    drop(jobs);

    // While the engine is down the unit ends.
    fixture.node.clock.advance_ms(30_000);
    fixture.node.units.exit(key, 0);

    // The start keeps the marker until the run's outputs are hashed, then
    // removes it.
    let jobs = fixture.node.open();
    for _ in 0..5 {
        jobs.tick();
        if entry(&jobs, key).is_some_and(|found| found.outputs != OutputsState::Pending) {
            break;
        }
        fixture.assert_own_tag(key, TIMING);
    }
    wait_for(&jobs, key, |found| found.outputs != OutputsState::Pending);
    jobs.tick();
    assert_eq!(fixture.tag_text(), None);
    assert_eq!(
        receipt(jobs.reserve(fixture.issuer, fixture.reserve("batch-1/chunk-0", BATCH))).state,
        JobState::Held
    );
}

/// The lease follows the quiet key's reserve record: once the run holds it,
/// a node file whose template is no longer quiet does not end it. The marker
/// stays and other work waits until the run's outputs are hashed.
#[test]
fn a_template_edited_during_the_run_does_not_end_its_lease() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let timing = "timing-1/chunk-0";
    let batch = "batch-1/chunk-0";
    fixture.run(&jobs, timing, TIMING);
    assert!(entry(&jobs, timing).expect("the quiet key").quiet);

    // The owner edits the node file: `timing` is no longer quiet.
    fixture.node.admission.set_quiet_lease(QuietLease {
        tag: Some(fixture.tag.clone()),
        templates: BTreeSet::new(),
    });
    jobs.tick();
    fixture.assert_own_tag(timing, TIMING);
    assert!(is_busy(
        &jobs.reserve(fixture.issuer, fixture.reserve(batch, BATCH))
    ));
    assert!(entry(&jobs, batch).is_none());

    // The run's hashing ends the lease, as before the edit.
    fixture.end_to_hashed(&jobs, timing);
    jobs.tick();
    assert_eq!(fixture.tag_text(), None);
    assert_eq!(
        receipt(jobs.reserve(fixture.issuer, fixture.reserve(batch, BATCH))).state,
        JobState::Held
    );
}

/// While the host is quiet, a reserve the node refuses (here one with no
/// time to run) answers `Busy` and journals nothing, as an admitted one
/// does: during a quiet run's lease, and while another holder's marker is
/// on the host. Once the host is free, the refusal is journaled.
#[test]
fn a_reserve_the_node_refuses_writes_nothing_while_the_host_is_quiet() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let timing = "timing-1/chunk-0";
    let refused = "batch-0/chunk-0";
    let mut no_time = fixture.reserve(refused, BATCH);
    no_time.pin.request.maximum_secs = 0;

    fixture.run(&jobs, timing, TIMING);
    assert!(is_busy(&jobs.reserve(fixture.issuer, no_time.clone())));
    assert!(entry(&jobs, refused).is_none());

    fixture.end_to_hashed(&jobs, timing);
    jobs.tick();
    std::fs::write(&fixture.tag, BOOKER_TAG).expect("the booker's marker");
    assert!(is_busy(&jobs.reserve(fixture.issuer, no_time.clone())));
    assert!(entry(&jobs, refused).is_none());

    std::fs::remove_file(&fixture.tag).expect("the booker removes its marker");
    let answer = receipt(jobs.reserve(fixture.issuer, no_time));
    assert!(
        matches!(&answer.end, Some(JobEnd::Refused { reason }) if reason == "maximum_zero"),
        "{:?}",
        answer.end
    );
}

/// A key whose release check left its device out keeps a quiet reserve
/// waiting, also when its prepare step refused and its workload never
/// started: a process may still hold the card. A quiet run with no device
/// claim of its own waits too. A clean probe frees the host.
#[test]
fn a_key_whose_release_left_its_device_out_keeps_the_host_from_a_quiet_run() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let refused = "batch-1/chunk-0";
    fixture
        .node
        .units
        .set_next_start(ScriptedStart::RefuseInPrepare(
            "scope_unavailable".to_owned(),
        ));
    fixture.node.devices.set_probe_fails(true);
    assert_eq!(
        receipt(jobs.reserve(fixture.issuer, fixture.reserve(refused, BATCH))).state,
        JobState::Held
    );
    assert_eq!(
        receipt(jobs.submit(fixture.issuer, fixture.submit(refused, BATCH))).state,
        JobState::Accepted
    );
    wait_for(&jobs, refused, |entry| entry.state == JobState::Launching);
    jobs.tick();
    let held_out = wait_for(&jobs, refused, |entry| {
        entry.is_ended() && matches!(entry.release, DeviceRelease::Unconfirmed { .. })
    });
    assert!(!held_out.started());

    let timing = "timing-1/chunk-0";
    let quiet = fixture.reserve_pin(timing, pin_without_devices(TIMING));
    assert!(is_busy(&jobs.reserve(fixture.issuer, quiet.clone())));
    assert!(entry(&jobs, timing).is_none());
    assert_eq!(fixture.tag_text(), None);

    // A clean probe releases the device: the host is free.
    fixture.node.devices.set_probe_fails(false);
    jobs.tick();
    wait_for(&jobs, refused, |entry| {
        matches!(entry.release, DeviceRelease::Confirmed { .. })
    });
    assert_eq!(
        receipt(jobs.reserve(fixture.issuer, quiet)).state,
        JobState::Held
    );
    fixture.assert_own_tag(timing, TIMING);
}
