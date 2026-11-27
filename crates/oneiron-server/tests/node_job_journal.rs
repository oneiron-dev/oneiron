//! Pass 33 row R3a (`33-exec-node/DESIGN.md` sections 7.2-7.7, tests
//! T13-T16c): the node's job journal, the states of a key, the launch
//! commit and recovery, against a scripted unit manager, a scripted device
//! table and a scripted clock. No privilege and no network: the node's
//! handlers are called directly, a second `NodeJobs` on the same directory
//! is an engine restart, and a new boot id is a host reset.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --test node_job_journal`.
#![cfg(all(oneiron_test_support, unix))]

use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::job_workload::{
    BoundReport, BoundRequirement, BoundStrength, DeviceClaim, DeviceKind, ScopeBound, Sharing,
};
use oneiron_server::gpu_execution_node::jobs::job_unit::RECEIPT_FILE_NAME;
use oneiron_server::gpu_execution_node::jobs::{
    JobKeyId, JobUnitPhase, NodeControls, NodeGate, NodeJobs, NodeKey,
};
use oneiron_server::gpu_execution_node::wire::{
    DeviceRelease, HoldRef, JobAnswer, JobEnd, JobReceipt, JobRefusal, JobReserve, JobState,
    JobStatusAnswer, JobSubmit, NetworkMode, OutputDecl, OutputsState, ResourceRequest, ScopeKind,
    SignedJobSubmit, SlotSelector, Starter, WorkloadPin,
};
use oneiron_server::test_doors::node_jobs::{
    ScriptedJobUnits, ScriptedNode, ScriptedSigner, ScriptedStart, fail_journal_sync,
};

const TEMPLATE: &str = "open-models";
const DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const DEVICE: &str = "GPU-scripted-0";
const NOW_MS: u64 = 1_800_000_000_000;
const WAIT: Duration = Duration::from_secs(10);
const MIB: u64 = 1024 * 1024;

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

fn pin(entry: &str) -> WorkloadPin {
    WorkloadPin {
        template: TEMPLATE.to_owned(),
        template_digest: DIGEST.to_owned(),
        commit: "a".repeat(40),
        contract_sha256: "b".repeat(64),
        contract_path: "contract.json".to_owned(),
        entry: entry.to_owned(),
        args: vec!["seed=7".to_owned()],
        request: ResourceRequest {
            cpu_threads: 0,
            memory_mib: 22 * 1024,
            disk_mib: 2 * 1024,
            devices: vec![gpu_claim(22 * 1024)],
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

/// One exclusive GPU of at least `memory_mib`.
fn gpu_claim(memory_mib: u64) -> DeviceClaim {
    DeviceClaim {
        kind: DeviceKind::Gpu,
        count: 1,
        memory_mib,
        features: Vec::new(),
        sharing: Sharing::Exclusive,
    }
}

/// `pin` with `devices` in place of its device claims.
fn with_devices(mut pin: WorkloadPin, devices: Vec<DeviceClaim>) -> WorkloadPin {
    pin.request.devices = devices;
    pin
}

fn requirement(bound: ScopeBound, kernel: bool) -> BoundRequirement {
    BoundRequirement { bound, kernel }
}

impl Fixture {
    fn reserve(&self, key: &str, pin: &WorkloadPin) -> JobReserve {
        JobReserve {
            key: key.to_owned(),
            pin: pin.clone(),
            slot: SlotSelector::default(),
            issuer: self.issuer,
            starter: Starter::Owner,
            issued_at_ms: NOW_MS,
            not_after_ms: NOW_MS + 300_000,
        }
    }

    fn submit(&self, key: &str, pin: &WorkloadPin) -> SignedJobSubmit {
        let submit = JobSubmit {
            key: key.to_owned(),
            job: EntityId::now(),
            chunk: 0,
            pin: pin.clone(),
            slot: SlotSelector::default(),
            maximum_secs: pin.request.maximum_secs,
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

    /// Reserves and submits `key`, and waits until its unit runs.
    fn run(&self, jobs: &NodeJobs, key: &str) -> NodeKey {
        self.run_pin(jobs, key, &pin("tools/units/run.sh"))
    }

    /// Reserves and submits `key` with `pin`, and waits until its unit runs.
    fn run_pin(&self, jobs: &NodeJobs, key: &str, pin: &WorkloadPin) -> NodeKey {
        assert_eq!(
            receipt(jobs.reserve(self.issuer, self.reserve(key, pin))).state,
            JobState::Held
        );
        assert_eq!(
            receipt(jobs.submit(self.issuer, self.submit(key, pin))).state,
            JobState::Accepted
        );
        wait_for(jobs, key, |entry| entry.state == JobState::Launching);
        jobs.tick();
        wait_for(jobs, key, |entry| entry.state == JobState::Running)
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

fn entry(jobs: &NodeJobs, key: &str) -> Option<NodeKey> {
    jobs.keys().into_iter().find(|entry| entry.key == key)
}

/// Waits until the key exists and `done` holds for it. The node's staging
/// worker and launch commit run on threads of their own and signal nothing
/// a test could await, and the staging limit runs on the real monotonic
/// clock, so the wait polls.
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

/// Waits until every staging worker of the key has had time to finish: a
/// worker that should start nothing leaves no state to poll for.
fn settle() {
    // testkit-lint: allow(sleep) proves an absence: no worker signals that it started nothing
    std::thread::sleep(Duration::from_millis(300));
}

#[test]
fn a_reserve_or_a_submit_repeated_under_one_key_starts_one_unit() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let pin = pin("tools/units/run.sh");
    let key = "job-1/chunk-0";

    // Concurrent reserves: one record, one state, the same sequence.
    let reserves: Vec<JobReceipt> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| receipt(jobs.reserve(fixture.issuer, fixture.reserve(key, &pin))))
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("reserve thread"))
            .collect()
    });
    assert!(
        reserves
            .iter()
            .all(|held| held.state == JobState::Held && held.seq == reserves[0].seq)
    );

    // Concurrent submits of the same signed bytes, then a submit whose reply
    // was dropped, then the same submit again: one unit start.
    let signed = fixture.submit(key, &pin);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                let answer = receipt(jobs.submit(fixture.issuer, signed.clone()));
                assert_ne!(answer.state, JobState::Held);
                assert!(
                    answer.end.is_none(),
                    "a repeated submit is never refused: {answer:?}"
                );
            });
        }
    });
    let _dropped_reply = jobs.submit(fixture.issuer, signed.clone());
    wait_for(&jobs, key, |entry| entry.state == JobState::Launching);
    jobs.tick();
    wait_for(&jobs, key, |entry| entry.state == JobState::Running);
    let again = receipt(jobs.submit(fixture.issuer, signed.clone()));
    assert_eq!(again.state, JobState::Running);

    // An engine restart in the same boot: the unit lives on, and the same
    // reserve and submit answer the key's receipt and start nothing.
    drop(jobs);
    let jobs = fixture.node.open();
    assert!(jobs.swept());
    assert_eq!(
        receipt(jobs.reserve(fixture.issuer, fixture.reserve(key, &pin))).state,
        JobState::Running
    );
    assert_eq!(
        receipt(jobs.submit(fixture.issuer, signed)).state,
        JobState::Running
    );
    jobs.tick();
    settle();
    assert_eq!(fixture.node.units.starts(key), 1);
    assert_eq!(fixture.node.devices.leases_given(), 1);
}

#[test]
fn a_different_pin_under_a_known_key_neither_starts_nor_replaces() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let first = pin("tools/units/run.sh");
    let other = pin("tools/units/other.sh");
    let key = "job-2/chunk-0";
    let held = receipt(jobs.reserve(fixture.issuer, fixture.reserve(key, &first)));
    let first_digest = first.digest().expect("digest");
    assert_eq!(held.workload.as_deref(), Some(first_digest.as_str()));

    assert_eq!(
        jobs.submit(fixture.issuer, fixture.submit(key, &other)),
        JobAnswer::Refused(JobRefusal::KeyConflict)
    );
    let again = receipt(jobs.reserve(fixture.issuer, fixture.reserve(key, &other)));
    assert_eq!(again.state, JobState::Held);
    assert_eq!(again.workload.as_deref(), Some(first_digest.as_str()));
    assert_eq!(again.seq, held.seq, "nothing was written");
    settle();
    assert_eq!(fixture.node.units.total_starts(), 0);

    // The first pin still runs, once.
    assert_eq!(
        receipt(jobs.submit(fixture.issuer, fixture.submit(key, &first))).state,
        JobState::Accepted
    );
    wait_for(&jobs, key, |entry| entry.state == JobState::Launching);
    assert_eq!(fixture.node.units.starts(key), 1);
}

#[test]
fn a_submit_without_a_journaled_reserve_is_refused_and_the_key_is_closed() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let pin = pin("tools/units/run.sh");
    let key = "job-3/chunk-0";
    let refused = receipt(jobs.submit(fixture.issuer, fixture.submit(key, &pin)));
    assert_eq!(refused.state, JobState::Ended);
    assert_eq!(
        refused.end,
        Some(JobEnd::Refused {
            reason: "not_reserved".to_owned()
        })
    );
    assert!(!refused.started);

    // A reserve that arrives later finds the closed key, also after a
    // restart: nothing starts.
    let late = receipt(jobs.reserve(fixture.issuer, fixture.reserve(key, &pin)));
    assert_eq!(late.state, JobState::Ended);
    drop(jobs);
    let jobs = fixture.node.open();
    assert_eq!(
        receipt(jobs.reserve(fixture.issuer, fixture.reserve(key, &pin))).state,
        JobState::Ended
    );
    assert_eq!(
        receipt(jobs.submit(fixture.issuer, fixture.submit(key, &pin))).state,
        JobState::Ended
    );
    settle();
    assert_eq!(fixture.node.units.total_starts(), 0);
    assert_eq!(fixture.node.devices.leases_given(), 0);
}

#[test]
fn a_stop_before_a_late_submit_closes_the_key_and_the_submit_starts_nothing() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let pin = pin("tools/units/run.sh");

    // A held key, stopped, then submitted.
    let held = "job-4/chunk-0";
    receipt(jobs.reserve(fixture.issuer, fixture.reserve(held, &pin)));
    let stopped = known(jobs.stop(fixture.issuer, held));
    assert_eq!(stopped.state, JobState::Ended);
    assert!(matches!(stopped.end, Some(JobEnd::Withdrawn)));
    let late = receipt(jobs.submit(fixture.issuer, fixture.submit(held, &pin)));
    assert_eq!(late.state, JobState::Ended);
    assert!(matches!(late.end, Some(JobEnd::Withdrawn)));

    // A key the node never saw, stopped, then reserved and submitted: the
    // stop wrote the closed key, so neither starts anything.
    let unseen = "job-5/chunk-0";
    let closed = known(jobs.stop(fixture.issuer, unseen));
    assert_eq!(closed.state, JobState::Ended);
    assert!(!closed.started);
    assert_eq!(
        receipt(jobs.reserve(fixture.issuer, fixture.reserve(unseen, &pin))).state,
        JobState::Ended
    );
    assert_eq!(
        receipt(jobs.submit(fixture.issuer, fixture.submit(unseen, &pin))).state,
        JobState::Ended
    );
    settle();
    assert_eq!(fixture.node.units.total_starts(), 0);
    assert_eq!(fixture.node.devices.leases_given(), 0);
}

#[test]
fn a_stop_during_staging_and_a_launch_commit_never_both_win() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let pin = pin("tools/units/run.sh");

    // A stop while the key stages: Withdrawn, and no unit ever.
    fixture.node.stager.hold();
    let staging = "job-6/chunk-0";
    receipt(jobs.reserve(fixture.issuer, fixture.reserve(staging, &pin)));
    receipt(jobs.submit(fixture.issuer, fixture.submit(staging, &pin)));
    assert!(fixture.node.stager.wait_entered(1, WAIT));
    let stopped = known(jobs.stop(fixture.issuer, staging));
    assert!(matches!(stopped.end, Some(JobEnd::Withdrawn)));
    fixture.node.stager.let_go();
    settle();
    assert_eq!(fixture.node.units.starts(staging), 0);
    assert_eq!(fixture.node.devices.leases_given(), 0);

    // A stop racing the launch commit, many times: each key ends either
    // Withdrawn with no unit, or Stopped with its one unit stopped; a key
    // that reached the launch commit is never Withdrawn.
    for round in 0..20 {
        let key = format!("job-7/round-{round}");
        fixture.node.stager.hold();
        receipt(jobs.reserve(fixture.issuer, fixture.reserve(&key, &pin)));
        receipt(jobs.submit(fixture.issuer, fixture.submit(&key, &pin)));
        assert!(fixture.node.stager.wait_entered(round + 2, WAIT));
        std::thread::scope(|scope| {
            scope.spawn(|| fixture.node.stager.let_go());
            scope.spawn(|| known(jobs.stop(fixture.issuer, &key)));
        });
        settle();
        jobs.tick();
        let ended = wait_for(&jobs, &key, |entry| entry.state == JobState::Ended);
        match ended.end {
            Some(JobEnd::Withdrawn) => {
                assert!(ended.launch.is_none());
                assert_eq!(fixture.node.units.starts(&key), 0);
            }
            Some(JobEnd::Stopped) => {
                assert!(ended.launch.is_some());
                assert_eq!(fixture.node.units.starts(&key), 1);
                assert_eq!(fixture.node.units.phase(&key), JobUnitPhase::Inactive);
            }
            other => panic!("round {round}: {other:?}"),
        }
        jobs.tick();
        wait_for(&jobs, &key, |entry| !entry.holds_device());
    }
}

#[test]
fn a_known_key_is_answered_before_a_drained_node_refuses() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let pin = pin("tools/units/run.sh");
    let key = "job-8/chunk-0";
    fixture.run(&jobs, key);
    fixture.node.admission.set_controls(NodeControls {
        enabled: true,
        paused: None,
        drained: Some("three machine failures".to_owned()),
        stop_requested: false,
    });
    assert_eq!(
        receipt(jobs.reserve(fixture.issuer, fixture.reserve(key, &pin))).state,
        JobState::Running
    );
    assert_eq!(
        receipt(jobs.submit(fixture.issuer, fixture.submit(key, &pin))).state,
        JobState::Running
    );
    let fresh = receipt(jobs.reserve(fixture.issuer, fixture.reserve("job-9/chunk-0", &pin)));
    assert_eq!(fresh.state, JobState::Ended);
    assert!(
        matches!(&fresh.end, Some(JobEnd::Refused { reason }) if reason.starts_with("node_drained")),
        "{fresh:?}"
    );
    // The receipt that answers the known key is signed by this node.
    let JobAnswer::Receipt(signed) = jobs.reserve(fixture.issuer, fixture.reserve(key, &pin))
    else {
        panic!("expected a receipt");
    };
    signed
        .verify(fixture.node.signer.as_ref())
        .expect("the node's own signature");
}

#[test]
fn a_reply_is_never_sent_before_its_record_is_on_disk() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let pin = pin("tools/units/run.sh");
    let key = "job-10/chunk-0";

    // The sync fails: no receipt goes out, and the key is unknown after a
    // restart.
    fail_journal_sync(&jobs, true);
    assert!(matches!(
        jobs.reserve(fixture.issuer, fixture.reserve(key, &pin)),
        JobAnswer::Busy { .. }
    ));
    assert!(entry(&jobs, key).is_none());
    fail_journal_sync(&jobs, false);
    drop(jobs);
    let jobs = fixture.node.open();
    assert!(matches!(
        jobs.find(fixture.issuer, key),
        JobStatusAnswer::Absent { .. }
    ));

    // A record that is on disk survives a torn tail after it.
    let held = receipt(jobs.reserve(fixture.issuer, fixture.reserve(key, &pin)));
    drop(jobs);
    let journal = fixture.node.paths.state_dir.join("journal");
    let mut bytes = std::fs::read(&journal).expect("journal");
    bytes.extend_from_slice(&[0x40, 0, 0, 0, 1, 2, 3]);
    std::fs::write(&journal, &bytes).expect("torn tail");
    let jobs = fixture.node.open();
    let found = known(jobs.find(fixture.issuer, key));
    assert_eq!(found.state, JobState::Held);
    assert_eq!(found.seq, held.seq);
}

#[test]
fn a_disable_a_withhold_or_a_template_edit_before_the_start_refuses_the_launch() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let pin = pin("tools/units/run.sh");
    let cases: [(&str, &dyn Fn(), &str); 3] = [
        (
            "job-11/disabled",
            &|| {
                fixture.node.admission.set_controls(NodeControls {
                    enabled: false,
                    ..NodeControls::default()
                });
            },
            "node_disabled",
        ),
        (
            "job-11/withheld",
            &|| fixture.node.devices.set_offered(DEVICE, false),
            "device_refused",
        ),
        (
            "job-11/template",
            &|| {
                fixture
                    .node
                    .admission
                    .set_template_digest(TEMPLATE, &"2".repeat(64))
            },
            "template_changed",
        ),
    ];
    for (round, (key, change, reason)) in cases.into_iter().enumerate() {
        fixture.node.stager.hold();
        receipt(jobs.reserve(fixture.issuer, fixture.reserve(key, &pin)));
        receipt(jobs.submit(fixture.issuer, fixture.submit(key, &pin)));
        assert!(
            fixture
                .node
                .stager
                .wait_entered(u32::try_from(round).expect("round") + 1, WAIT)
        );
        change();
        fixture.node.stager.let_go();
        let ended = wait_for(&jobs, key, |entry| entry.state == JobState::Ended);
        assert!(
            matches!(&ended.end, Some(JobEnd::LaunchRefused { reason: found }) if found.starts_with(reason)),
            "{key}: {:?}",
            ended.end
        );
        assert!(!ended.started());
        assert_eq!(fixture.node.units.starts(key), 0);
        // Put the node back for the next case.
        fixture.node.admission.set_controls(NodeControls {
            enabled: true,
            ..NodeControls::default()
        });
        fixture.node.devices.set_offered(DEVICE, true);
        fixture.node.admission.set_template_digest(TEMPLATE, DIGEST);
    }
    assert_eq!(fixture.node.devices.leases_given(), 0);
}

#[test]
fn a_scope_that_cannot_give_a_bound_the_launch_needs_refuses_the_launch() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let pin = pin("tools/units/run.sh");
    let mut no_cutoff = ScriptedJobUnits::kernel_scope();
    no_cutoff.cutoff_without_engine = BoundReport {
        strength: BoundStrength::None,
        evidence: "scripted: no timer outlives the engine".to_owned(),
    };
    let mut supervised_memory = ScriptedJobUnits::kernel_scope();
    supervised_memory.memory_cap = BoundReport {
        strength: BoundStrength::Supervised {
            worst_lateness_ms: 1_000,
        },
        evidence: "scripted: a supervisor reads the usage".to_owned(),
    };
    let mut open_network = ScriptedJobUnits::kernel_scope();
    open_network.network_closed = BoundReport {
        strength: BoundStrength::None,
        evidence: "scripted: no network namespace".to_owned(),
    };
    let default_require = vec![
        requirement(ScopeBound::FileWall, false),
        requirement(ScopeBound::NetworkClosed, false),
    ];
    let cases = [
        // The minimum contract holds whatever the template requires.
        (
            "job-12/minimum",
            no_cutoff,
            default_require.clone(),
            "no_scope: cutoff_without_engine",
        ),
        // A kernel bound is not given by a supervisor.
        (
            "job-12/kernel",
            supervised_memory.clone(),
            vec![
                requirement(ScopeBound::FileWall, false),
                requirement(ScopeBound::MemoryCap, true),
            ],
            "no_scope: memory_cap:kernel",
        ),
        // The template's default list keeps a workload off the network.
        (
            "job-12/network",
            open_network.clone(),
            default_require,
            "no_scope: network_closed",
        ),
    ];
    for (key, scope, require, reason) in cases {
        fixture.node.units.set_probe(scope);
        fixture.node.admission.set_template_requires(require);
        receipt(jobs.reserve(fixture.issuer, fixture.reserve(key, &pin)));
        receipt(jobs.submit(fixture.issuer, fixture.submit(key, &pin)));
        let ended = wait_for(&jobs, key, |entry| entry.state == JobState::Ended);
        assert!(
            matches!(&ended.end, Some(JobEnd::LaunchRefused { reason: found }) if found == reason),
            "{key}: {:?}",
            ended.end
        );
        assert!(!ended.started());
        assert_eq!(fixture.node.units.starts(key), 0);
    }
    assert_eq!(fixture.node.devices.leases_given(), 0);
    // A bound the template does not require does not block: the same
    // supervised memory cap launches under the default list.
    fixture.node.units.set_probe(supervised_memory);
    fixture.node.admission.set_template_requires(vec![
        requirement(ScopeBound::FileWall, false),
        requirement(ScopeBound::NetworkClosed, false),
    ]);
    let running = fixture.run(&jobs, "job-12/unrequired");
    assert!(running.started());
}

#[test]
fn a_key_with_no_device_claim_takes_no_device_and_launches_on_memory_alone() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let mut cpu = with_devices(pin("tools/units/run.sh"), Vec::new());
    cpu.request.memory_mib = 2 * 1024;
    let key = "job-20/cpu";
    let running = fixture.run_pin(&jobs, key, &cpu);
    let launch = running.launch.as_ref().expect("launched");
    assert!(launch.devices.is_empty());
    assert_eq!(launch.host_memory_mib, 2 * 1024);
    assert_eq!(fixture.node.devices.leases_given(), 0);
    assert_eq!(fixture.node.devices.taken_by(DEVICE), None);
    assert_eq!(fixture.node.floor.leased_bytes(), 2 * 1024 * MIB);

    // A GPU job runs beside it, on the device the CPU job left free.
    let gpu = "job-20/gpu";
    fixture.run(&jobs, gpu);
    assert_eq!(fixture.node.devices.taken_by(DEVICE).as_deref(), Some(gpu));
    assert_eq!(fixture.node.floor.leased_bytes(), 24 * 1024 * MIB);

    // The CPU job's end gives its memory back with no device probe, and
    // the GPU job keeps its device.
    fixture.node.units.exit(key, 0);
    jobs.tick();
    let ended = wait_for(&jobs, key, |entry| {
        matches!(entry.release, DeviceRelease::Confirmed { .. })
    });
    assert_eq!(ended.end, Some(JobEnd::Exited { code: 0 }));
    assert_eq!(known(jobs.find(fixture.issuer, key)).device_id, None);
    assert!(
        fixture
            .node
            .devices
            .finished()
            .iter()
            .all(|(finished, _)| finished != key)
    );
    assert_eq!(fixture.node.devices.taken_by(DEVICE).as_deref(), Some(gpu));
    assert_eq!(fixture.node.floor.leased_bytes(), 22 * 1024 * MIB);
}

#[test]
fn a_claim_no_device_of_the_machine_meets_is_refused_at_reserve() {
    let fixture = fixture();
    fixture.node.devices.add_device("GPU-scripted-1", 24 * 1024);
    let jobs = fixture.node.open();
    let base = pin("tools/units/run.sh");
    let fp8 = DeviceClaim {
        features: vec!["fp8".to_owned()],
        ..gpu_claim(1024)
    };
    let npu = DeviceClaim {
        kind: DeviceKind::Npu,
        ..gpu_claim(0)
    };
    let cases = [
        ("job-21/feature", vec![fp8.clone()], "no_device: claim 0"),
        (
            "job-21/kind",
            vec![gpu_claim(1024), npu],
            "no_device: claim 1",
        ),
        (
            "job-21/count",
            vec![DeviceClaim {
                count: 3,
                ..gpu_claim(1024)
            }],
            "no_device: claim 0",
        ),
        (
            "job-21/memory",
            vec![gpu_claim(48 * 1024)],
            "no_device: claim 0",
        ),
        // Two devices meet it, but a key holds one device in this slice.
        (
            "job-21/two",
            vec![DeviceClaim {
                count: 2,
                ..gpu_claim(1024)
            }],
            "devices_above_one",
        ),
    ];
    for (key, devices, reason) in cases {
        let refused_pin = with_devices(base.clone(), devices);
        let refused = receipt(jobs.reserve(fixture.issuer, fixture.reserve(key, &refused_pin)));
        assert_eq!(refused.state, JobState::Ended, "{key}");
        assert!(
            matches!(&refused.end, Some(JobEnd::Refused { reason: found }) if found == reason),
            "{key}: {:?}",
            refused.end
        );
        assert!(!refused.started);
    }
    // Once the device reports the feature, the same claim is held.
    fixture.node.devices.set_features(DEVICE, &["fp8"]);
    let met = with_devices(base, vec![fp8]);
    assert_eq!(
        receipt(jobs.reserve(fixture.issuer, fixture.reserve("job-21/feature-met", &met))).state,
        JobState::Held
    );
    assert_eq!(fixture.node.devices.leases_given(), 0);
}

#[test]
fn a_unified_memory_device_adds_its_claim_memory_to_the_floor_and_a_short_floor_takes_nothing() {
    let fixture = fixture();
    fixture.node.devices.set_unified(DEVICE, true);
    let jobs = fixture.node.open();
    let large = pin("tools/units/run.sh");
    // 22 GiB for the run and 22 GiB for the device's share of the host's
    // memory: past the 26 GiB floor. The device leased first goes back.
    let key = "job-22/large";
    receipt(jobs.reserve(fixture.issuer, fixture.reserve(key, &large)));
    receipt(jobs.submit(fixture.issuer, fixture.submit(key, &large)));
    let ended = wait_for(&jobs, key, |entry| entry.state == JobState::Ended);
    assert_eq!(
        ended.end,
        Some(JobEnd::LaunchRefused {
            reason: "memory_busy".to_owned()
        })
    );
    assert_eq!(fixture.node.devices.leases_given(), 1);
    assert_eq!(fixture.node.devices.taken_by(DEVICE), None);
    assert_eq!(fixture.node.floor.leased_bytes(), 0);
    assert_eq!(fixture.node.units.total_starts(), 0);

    // 22 GiB and 2 GiB fit the floor, but not a 23 GiB template ceiling:
    // the sum rule refuses before any lease.
    let small = with_devices(large, vec![gpu_claim(2 * 1024)]);
    fixture
        .node
        .admission
        .set_memory_ceiling_mib(Some(23 * 1024));
    let ceiling = "job-22/ceiling";
    receipt(jobs.reserve(fixture.issuer, fixture.reserve(ceiling, &small)));
    receipt(jobs.submit(fixture.issuer, fixture.submit(ceiling, &small)));
    let refused = wait_for(&jobs, ceiling, |entry| entry.state == JobState::Ended);
    assert_eq!(
        refused.end,
        Some(JobEnd::LaunchRefused {
            reason: "request_above_ceiling: host_memory_mib".to_owned()
        })
    );
    assert_eq!(fixture.node.devices.leases_given(), 1);

    // Within the ceiling, the floor holds both.
    fixture
        .node
        .admission
        .set_memory_ceiling_mib(Some(24 * 1024));
    let running = fixture.run_pin(&jobs, "job-22/small", &small);
    let launch = running.launch.expect("launched");
    assert_eq!(launch.host_memory_mib, 24 * 1024);
    assert_eq!(fixture.node.floor.leased_bytes(), 24 * 1024 * MIB);
    assert_eq!(
        fixture.node.devices.taken_by(DEVICE).as_deref(),
        Some("job-22/small")
    );
}

#[test]
fn a_device_that_turned_busy_during_staging_refuses_the_launch_and_no_card_was_held_before_it() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let pin = pin("tools/units/run.sh");
    let key = "job-12/chunk-0";
    fixture.node.stager.hold();
    receipt(jobs.reserve(fixture.issuer, fixture.reserve(key, &pin)));
    receipt(jobs.submit(fixture.issuer, fixture.submit(key, &pin)));
    assert!(fixture.node.stager.wait_entered(1, WAIT));
    // During staging no card and no memory is held for the key.
    assert_eq!(fixture.node.devices.taken_by(DEVICE), None);
    assert_eq!(fixture.node.devices.leases_given(), 0);
    assert_eq!(fixture.node.floor.leased_bytes(), 0);
    fixture.node.devices.set_foreign_pids(DEVICE, vec![4242]);
    fixture.node.stager.let_go();
    let ended = wait_for(&jobs, key, |entry| entry.state == JobState::Ended);
    assert_eq!(
        ended.end,
        Some(JobEnd::LaunchRefused {
            reason: "device_busy".to_owned()
        })
    );
    let refused = known(jobs.find(fixture.issuer, key));
    assert!(!refused.started);
    assert_eq!(refused.measured_secs, None);
    assert_eq!(refused.release, DeviceRelease::NotHeld);
    assert_eq!(fixture.node.devices.taken_by(DEVICE), None);
    assert_eq!(fixture.node.floor.leased_bytes(), 0);
    assert_eq!(fixture.node.units.total_starts(), 0);
}

#[test]
fn a_job_unit_outlives_an_engine_restart_and_no_job_takes_its_device_before_the_gate_opens() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let pin = pin("tools/units/run.sh");
    let first = "job-13/chunk-0";
    fixture.run(&jobs, first);
    let memory = pin.request.memory_mib * 1024 * 1024;
    assert_eq!(fixture.node.floor.leased_bytes(), memory);

    // The engine stops; the unit runs on. The restarted engine cannot ask
    // the service manager yet: the gate stays closed.
    drop(jobs);
    fixture.node.units.set_answering(false);
    let jobs = fixture.node.open();
    assert_eq!(jobs.gate(), NodeGate::Recovering);
    assert!(matches!(
        jobs.reserve(fixture.issuer, fixture.reserve("job-14/chunk-0", &pin)),
        JobAnswer::Busy { .. }
    ));
    assert!(matches!(
        jobs.find(fixture.issuer, first),
        JobStatusAnswer::Busy { .. }
    ));

    // The service manager answers: the key adopts its unit and its leases
    // before the gate opens.
    fixture.node.units.set_answering(true);
    jobs.tick();
    assert!(jobs.swept());
    assert_eq!(
        fixture.node.devices.taken_by(DEVICE).as_deref(),
        Some(first)
    );
    assert_eq!(fixture.node.floor.leased_bytes(), memory);
    assert_eq!(
        known(jobs.find(fixture.issuer, first)).state,
        JobState::Running
    );

    // A second job cannot take the adopted job's device.
    let second = "job-14/chunk-0";
    receipt(jobs.reserve(fixture.issuer, fixture.reserve(second, &pin)));
    receipt(jobs.submit(fixture.issuer, fixture.submit(second, &pin)));
    let refused = wait_for(&jobs, second, |entry| entry.state == JobState::Ended);
    assert!(
        matches!(refused.end, Some(JobEnd::LaunchRefused { .. })),
        "{:?}",
        refused.end
    );
    assert_eq!(fixture.node.units.starts(second), 0);
    assert_eq!(fixture.node.units.starts(first), 1);

    // The adopted job ends and gives its device back.
    fixture.node.clock.advance_ms(30_000);
    fixture.node.units.exit(first, 0);
    jobs.tick();
    let ended = wait_for(&jobs, first, |entry| {
        matches!(entry.release, DeviceRelease::Confirmed { .. })
    });
    assert_eq!(ended.end, Some(JobEnd::Exited { code: 0 }));
    assert_eq!(fixture.node.devices.taken_by(DEVICE), None);
    assert_eq!(fixture.node.floor.leased_bytes(), 0);
}

#[test]
fn a_launching_record_with_no_unit_is_lost_and_never_started_again() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let pin = pin("tools/units/run.sh");
    let key = "job-15/chunk-0";
    fixture.node.units.set_next_start(ScriptedStart::NotTaken);
    receipt(jobs.reserve(fixture.issuer, fixture.reserve(key, &pin)));
    receipt(jobs.submit(fixture.issuer, fixture.submit(key, &pin)));
    wait_for(&jobs, key, |entry| entry.state == JobState::Launching);

    // The engine restarts with the key in `launching` and no unit and no end
    // record: the key is lost, and never started again.
    drop(jobs);
    fixture.node.units.set_next_start(ScriptedStart::Run);
    let jobs = fixture.node.open();
    let lost = known(jobs.find(fixture.issuer, key));
    assert_eq!(lost.state, JobState::Ended);
    assert!(
        matches!(&lost.end, Some(JobEnd::Lost { reason, .. }) if reason == "launch_uncertain"),
        "{:?}",
        lost.end
    );
    assert_eq!(lost.measured_secs, None, "unknown is not zero");
    assert!(
        lost.started,
        "a lost launch is never reported as never started"
    );
    for _ in 0..3 {
        jobs.tick();
    }
    drop(jobs);
    let jobs = fixture.node.open();
    jobs.tick();
    assert_eq!(
        receipt(jobs.submit(fixture.issuer, fixture.submit(key, &pin))).state,
        JobState::Ended
    );
    settle();
    assert_eq!(fixture.node.units.total_starts(), 0);
    // The device came back only after a clean probe.
    let released = wait_for(&jobs, key, |entry| {
        matches!(entry.release, DeviceRelease::Confirmed { .. })
    });
    assert!(released.is_ended());
    assert_eq!(fixture.node.devices.taken_by(DEVICE), None);
}

#[test]
fn a_unit_that_ended_while_the_engine_was_down_is_ended_from_its_end_record() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let key = "job-16/chunk-0";
    let running = fixture.run(&jobs, key);
    let launch = running.launch.expect("launched");

    // The workload writes its verdict and exits with 3 while the engine is
    // down; the end step wrote the end record.
    drop(jobs);
    let out = JobKeyId::for_key(key)
        .payload_dir(&fixture.node.paths.work_dir)
        .join("out");
    std::fs::create_dir_all(&out).expect("out dir");
    std::fs::write(out.join("verdict.json"), b"{\"pass\":true}").expect("verdict");
    fixture.node.clock.advance_ms(7_500);
    fixture.node.units.exit(key, 3);

    let jobs = fixture.node.open();
    let ended = known(jobs.find(fixture.issuer, key));
    assert_eq!(ended.state, JobState::Ended);
    assert_eq!(ended.end, Some(JobEnd::Exited { code: 3 }));
    let occupied = ended.occupied.expect("occupied");
    assert_eq!(occupied.start_boot_ns, launch.launch_boot_ns);
    let end_boot_ns = occupied.end_boot_ns.expect("the end step's time");
    assert_eq!(
        ended.measured_secs,
        Some((end_boot_ns - launch.launch_boot_ns).div_ceil(1_000_000_000))
    );

    // The release check and the hashing follow at the tick.
    jobs.tick();
    let sealed = known(jobs.find(fixture.issuer, key));
    assert!(matches!(sealed.release, DeviceRelease::Confirmed { .. }));
    let OutputsState::Hashed(outputs) = &sealed.outputs else {
        panic!("outputs: {:?}", sealed.outputs);
    };
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].name, "verdict.json");
    assert_eq!(outputs[0].bytes, 13);
    assert!(outputs[0].returnable);
    assert_eq!(fixture.node.units.starts(key), 1);
}

#[test]
fn a_lost_journal_answers_history_lost_and_admits_nothing() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let pin = pin("tools/units/run.sh");
    let key = "job-17/chunk-0";
    fixture.run(&jobs, key);
    drop(jobs);

    // The journal is gone; its epoch and the key's control directory stay.
    std::fs::remove_file(fixture.node.paths.state_dir.join("journal")).expect("remove journal");
    let jobs = fixture.node.open();
    assert!(matches!(jobs.gate(), NodeGate::HistoryLost { .. }));
    assert_eq!(jobs.find(fixture.issuer, key), JobStatusAnswer::HistoryLost);
    assert_eq!(
        jobs.find(fixture.issuer, "job-18/never-seen"),
        JobStatusAnswer::HistoryLost
    );
    assert_eq!(
        jobs.reserve(fixture.issuer, fixture.reserve("job-18/chunk-0", &pin)),
        JobAnswer::Refused(JobRefusal::HistoryLost)
    );
    // Every job unit was stopped.
    assert_eq!(fixture.node.units.phase(key), JobUnitPhase::Inactive);
    jobs.tick();
    assert!(matches!(jobs.gate(), NodeGate::HistoryLost { .. }));

    // The epoch gone too, with the control directory still there: the same.
    drop(jobs);
    std::fs::remove_file(fixture.node.paths.state_dir.join("epoch")).expect("remove epoch");
    let jobs = fixture.node.open();
    assert!(matches!(jobs.gate(), NodeGate::HistoryLost { .. }));
    assert_eq!(jobs.find(fixture.issuer, key), JobStatusAnswer::HistoryLost);
    settle();
    assert_eq!(fixture.node.units.starts(key), 1);
}

#[test]
fn a_second_job_service_on_one_state_dir_is_refused_until_the_first_is_gone() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let second = fixture.node.try_open();
    assert!(
        matches!(&second, Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "{second:?}"
    );
    drop(jobs);
    assert!(fixture.node.try_open().is_ok());
}

#[test]
fn a_damaged_record_length_is_a_lost_history_never_a_torn_tail() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let pin = pin("tools/units/run.sh");
    let key = "job-19/chunk-0";
    receipt(jobs.reserve(fixture.issuer, fixture.reserve(key, &pin)));
    assert_eq!(known(jobs.stop(fixture.issuer, key)).state, JobState::Ended);
    drop(jobs);

    // The last record's length now points past the end of the file: its
    // length check fails, so the stop is not cut off as a torn write.
    let journal = fixture.node.paths.state_dir.join("journal");
    let mut bytes = std::fs::read(&journal).expect("journal");
    let header = 8 + 4 + 16;
    let mut offset = header;
    let mut last = header;
    while offset < bytes.len() {
        let length = u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("length"));
        last = offset;
        offset += 4 + 4 + usize::try_from(length).expect("length") + 16;
    }
    bytes[last + 1] ^= 0x40;
    std::fs::write(&journal, &bytes).expect("damaged length");
    let jobs = fixture.node.open();
    assert!(matches!(jobs.gate(), NodeGate::HistoryLost { .. }));
    assert_eq!(
        jobs.submit(fixture.issuer, fixture.submit(key, &pin)),
        JobAnswer::Refused(JobRefusal::HistoryLost)
    );
}

#[test]
fn a_submit_after_the_issuers_grant_ended_writes_nothing() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let pin = pin("tools/units/run.sh");
    // A held key past its window, and a key the node never saw: each would
    // be closed by a new record, so each waits for the issuer's authority.
    let held = "job-30/held";
    let unknown = "job-30/never-reserved";
    receipt(jobs.reserve(fixture.issuer, fixture.reserve(held, &pin)));
    fixture.node.clock.advance_ms(600_000);
    fixture
        .node
        .admission
        .set_issuer_refusal(Some("issuer_standing_ended"));
    for key in [held, unknown] {
        assert_eq!(
            jobs.submit(fixture.issuer, fixture.submit(key, &pin)),
            JobAnswer::Refused(JobRefusal::IssuerStandingEnded),
            "{key}"
        );
    }
    assert_eq!(
        entry(&jobs, held).map(|entry| entry.state),
        Some(JobState::Held)
    );
    assert_eq!(entry(&jobs, unknown), None);
}

#[test]
fn a_recovery_that_cannot_read_a_launched_units_phase_keeps_the_gate_closed() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let pin = pin("tools/units/run.sh");
    let key = "job-31/chunk-0";
    fixture.node.units.set_next_start(ScriptedStart::NotTaken);
    receipt(jobs.reserve(fixture.issuer, fixture.reserve(key, &pin)));
    receipt(jobs.submit(fixture.issuer, fixture.submit(key, &pin)));
    wait_for(&jobs, key, |entry| entry.state == JobState::Launching);

    // The engine restarts; the service manager lists its units but cannot
    // say this unit's phase, so the key's row of the table cannot be
    // applied and the gate stays closed.
    drop(jobs);
    fixture.node.units.set_next_start(ScriptedStart::Run);
    fixture.node.units.set_status_answering(false);
    let jobs = fixture.node.open();
    assert_eq!(jobs.gate(), NodeGate::Recovering);
    assert!(matches!(
        jobs.find(fixture.issuer, key),
        JobStatusAnswer::Busy { .. }
    ));

    // It answers again: the key is lost, and only then does the gate open.
    fixture.node.units.set_status_answering(true);
    jobs.tick();
    assert_eq!(jobs.gate(), NodeGate::Open);
    let lost = known(jobs.find(fixture.issuer, key));
    assert!(
        matches!(&lost.end, Some(JobEnd::Lost { reason, .. }) if reason == "launch_uncertain"),
        "{:?}",
        lost.end
    );
}

#[test]
fn the_handle_the_node_attaches_never_keeps_the_job_service_alive() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let attachment = jobs.attachment();
    let pin = pin("tools/units/run.sh");
    let key = "job-32/chunk-0";
    assert_eq!(
        receipt(attachment.reserve(fixture.issuer, fixture.reserve(key, &pin))).state,
        JobState::Held
    );
    assert!(attachment.swept());

    // The server drops its service: the handle answers as a node with no
    // keys attached, and the journal's directory opens again.
    drop(jobs);
    assert_eq!(
        attachment.reserve(fixture.issuer, fixture.reserve("job-32/chunk-1", &pin)),
        JobAnswer::Refused(JobRefusal::NotEnabled)
    );
    assert!(!attachment.swept());
    let reopened = fixture.node.open();
    assert_eq!(reopened.gate(), NodeGate::Open);
    assert_eq!(
        entry(&reopened, key).map(|entry| entry.state),
        Some(JobState::Held)
    );
}

#[test]
fn a_closed_job_service_begins_no_launch_and_its_next_opening_takes_up_the_staging_key() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let attachment = jobs.attachment();
    let pin = pin("tools/units/run.sh");
    let key = "job-40/chunk-0";

    // The key stages when the server stops serving the service.
    fixture.node.stager.hold();
    receipt(jobs.reserve(fixture.issuer, fixture.reserve(key, &pin)));
    receipt(jobs.submit(fixture.issuer, fixture.submit(key, &pin)));
    assert!(fixture.node.stager.wait_entered(1, WAIT));
    jobs.close();

    // The node answers as one with no keys, though the staging worker still
    // holds the service.
    assert_eq!(
        attachment.reserve(fixture.issuer, fixture.reserve("job-40/chunk-1", &pin)),
        JobAnswer::Refused(JobRefusal::NotEnabled)
    );
    assert!(!attachment.swept());

    // The worker returns at its next step, though its staging is still
    // held: the journal's writer lock frees (the opening waits for it), and
    // the closed service leased, started and wrote nothing.
    drop(jobs);
    let reopened = fixture.node.open();
    assert_eq!(fixture.node.units.starts(key), 0);
    assert_eq!(fixture.node.devices.leases_given(), 0);
    assert_eq!(
        entry(&reopened, key).map(|entry| entry.state),
        Some(JobState::Staging)
    );

    // The next opening takes up the staging, and the key launches once.
    assert!(fixture.node.stager.wait_entered(2, WAIT));
    fixture.node.stager.let_go();
    wait_for(&reopened, key, |entry| entry.state == JobState::Launching);
    reopened.tick();
    wait_for(&reopened, key, |entry| entry.state == JobState::Running);
    assert_eq!(fixture.node.units.starts(key), 1);
    assert_eq!(fixture.node.devices.leases_given(), 1);
}

#[test]
fn a_quarantined_device_takes_no_new_reserve_until_its_clean_release() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let pin = pin("tools/units/run.sh");
    let first = "job-33/chunk-0";
    fixture.run(&jobs, first);

    // The release check cannot probe the device: the journal quarantines
    // it, and so does the slot table, so a reserve finds no device.
    fixture.node.devices.set_probe_fails(true);
    fixture.node.units.exit(first, 0);
    jobs.tick();
    let held_out = wait_for(&jobs, first, |entry| {
        matches!(entry.release, DeviceRelease::Unconfirmed { .. })
    });
    assert!(held_out.is_ended());
    assert!(fixture.node.devices.quarantined(DEVICE).is_some());
    let refused = receipt(jobs.reserve(fixture.issuer, fixture.reserve("job-33/chunk-1", &pin)));
    assert!(
        matches!(&refused.end, Some(JobEnd::Refused { reason }) if reason == "device_unavailable: claim 0"),
        "{:?}",
        refused.end
    );

    // The slot table keeps quarantines in memory: after a restart the
    // journal's quarantine is back before the gate opens.
    drop(jobs);
    fixture.node.devices.forget_quarantines();
    let jobs = fixture.node.open();
    assert_eq!(jobs.gate(), NodeGate::Open);
    assert!(fixture.node.devices.quarantined(DEVICE).is_some());

    // A clean probe releases the device and ends its quarantine.
    fixture.node.devices.set_probe_fails(false);
    jobs.tick();
    wait_for(&jobs, first, |entry| {
        matches!(entry.release, DeviceRelease::Confirmed { .. })
    });
    assert_eq!(fixture.node.devices.quarantined(DEVICE), None);
    assert_eq!(
        receipt(jobs.reserve(fixture.issuer, fixture.reserve("job-33/chunk-2", &pin))).state,
        JobState::Held
    );
}

#[test]
fn a_launch_the_prepare_step_refused_books_no_disk_once_ended() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let pin = pin("tools/units/run.sh");
    let refused = "job-34/refused";
    fixture
        .node
        .units
        .set_next_start(ScriptedStart::RefuseInPrepare(
            "scope_unavailable".to_owned(),
        ));
    receipt(jobs.reserve(fixture.issuer, fixture.reserve(refused, &pin)));
    receipt(jobs.submit(fixture.issuer, fixture.submit(refused, &pin)));
    wait_for(&jobs, refused, |entry| entry.state == JobState::Launching);
    jobs.tick();
    let ended = wait_for(&jobs, refused, |entry| entry.state == JobState::Ended);
    assert!(
        matches!(&ended.end, Some(JobEnd::LaunchRefused { .. })),
        "{:?}",
        ended.end
    );
    assert!(!ended.started());
    assert_eq!(jobs.booked_disk_mib(), 0);

    // A key whose workload ran keeps its disk booked for its outputs.
    fixture.node.units.set_next_start(ScriptedStart::Run);
    let ran = "job-34/ran";
    fixture.run(&jobs, ran);
    fixture.node.units.exit(ran, 0);
    jobs.tick();
    wait_for(&jobs, ran, |entry| entry.state == JobState::Ended);
    assert_eq!(jobs.booked_disk_mib(), pin.request.disk_mib);
}

#[test]
fn a_fold_that_never_reaches_the_submits_heads_refuses_the_launch_as_authority_stale() {
    let fixture = fixture();
    fixture.node.admission.set_staging_limit_secs(1);
    fixture.node.authority.set_stale(true);
    let jobs = fixture.node.open();
    let pin = pin("tools/units/run.sh");
    let key = "job-35/chunk-0";
    receipt(jobs.reserve(fixture.issuer, fixture.reserve(key, &pin)));
    receipt(jobs.submit(fixture.issuer, fixture.submit(key, &pin)));
    let ended = wait_for(&jobs, key, |entry| entry.state == JobState::Ended);
    assert_eq!(
        ended.end,
        Some(JobEnd::LaunchRefused {
            reason: "authority_stale".to_owned()
        })
    );
    assert_eq!(fixture.node.units.total_starts(), 0);
    assert_eq!(fixture.node.devices.leases_given(), 0);
}

#[test]
fn a_sealed_keys_missing_receipt_file_is_written_again_from_the_journal() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let key = "job-36/chunk-0";
    fixture.run(&jobs, key);
    fixture.node.units.exit(key, 0);
    jobs.tick();
    wait_for(&jobs, key, |entry| entry.outputs != OutputsState::Pending);
    let file = JobKeyId::for_key(key)
        .control_dir(&fixture.node.paths.state_dir)
        .join(RECEIPT_FILE_NAME);
    assert!(file.exists());

    // The engine stopped after the `hashed` record and before the file.
    drop(jobs);
    std::fs::remove_file(&file).expect("receipt file removed");
    let jobs = fixture.node.open();
    jobs.tick();
    let bytes = std::fs::read(&file).expect("receipt file written again");
    assert!(!bytes.is_empty());
}

#[test]
fn a_launched_keys_staged_code_is_removed_at_its_release_and_never_while_a_process_may_read_it() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let pin = pin("tools/units/run.sh");
    let payload_dir = |key: &str| JobKeyId::for_key(key).payload_dir(&fixture.node.paths.work_dir);
    let unstaged = |key: &str| {
        fixture
            .node
            .stager
            .unstaged()
            .into_iter()
            .filter(|(unstaged, _)| unstaged == key)
            .collect::<Vec<_>>()
    };

    // The prepare step refused the launch: the workload never ran, its
    // disk is no longer booked, and its staged code goes at the release.
    let refused = "job-37/refused";
    fixture
        .node
        .units
        .set_next_start(ScriptedStart::RefuseInPrepare(
            "scope_unavailable".to_owned(),
        ));
    receipt(jobs.reserve(fixture.issuer, fixture.reserve(refused, &pin)));
    receipt(jobs.submit(fixture.issuer, fixture.submit(refused, &pin)));
    wait_for(&jobs, refused, |entry| entry.state == JobState::Launching);
    jobs.tick();
    wait_for(&jobs, refused, |entry| {
        matches!(entry.release, DeviceRelease::Confirmed { .. })
    });
    assert_eq!(jobs.booked_disk_mib(), 0);
    assert_eq!(
        unstaged(refused),
        vec![(refused.to_owned(), payload_dir(refused))]
    );

    // A workload that ran keeps its code while it runs, and while the
    // release check cannot tell that no process of its unit is left.
    fixture.node.units.set_next_start(ScriptedStart::Run);
    let ran = "job-37/ran";
    fixture.run(&jobs, ran);
    jobs.tick();
    assert!(unstaged(ran).is_empty());
    fixture.node.devices.set_probe_fails(true);
    fixture.node.units.exit(ran, 0);
    jobs.tick();
    wait_for(&jobs, ran, |entry| {
        matches!(entry.release, DeviceRelease::Unconfirmed { .. })
    });
    jobs.tick();
    assert!(unstaged(ran).is_empty());

    // The clean probe releases the key: its code is removed once, before
    // `released`, and its outputs' disk stays booked until the issuer's
    // acknowledgement.
    fixture.node.devices.set_probe_fails(false);
    jobs.tick();
    wait_for(&jobs, ran, |entry| {
        matches!(entry.release, DeviceRelease::Confirmed { .. })
    });
    jobs.tick();
    assert_eq!(unstaged(ran), vec![(ran.to_owned(), payload_dir(ran))]);
    assert_eq!(jobs.booked_disk_mib(), pin.request.disk_mib);
}
