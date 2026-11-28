//! Pass 34 row W1 (`34-compute-general/DESIGN.md` 2.5 and section 10): a
//! session's run continues through paid chunks. A renewal is a submit whose
//! key names the run's first key (`continues`); the node journals it on the
//! first key, moves the run's cutoff forward, and answers each chunk key's
//! receipt as its chunk's paid slice of the one run. Against the scripted
//! unit manager, device table and clock of the node's job tests: no
//! privilege and no network; a second `NodeJobs` on the same directory is an
//! engine restart.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --test node_job_sessions`.
#![cfg(all(oneiron_test_support, unix))]

use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::gpu_job::MeterVerdict;
use oneiron::job_dispatch::machine_records::MachineJobOutcome;
use oneiron::job_workload::{DeviceClaim, DeviceKind, Sharing};
use oneiron_server::gpu_execution_node::issuer::guard::machine_job_outcome;
use oneiron_server::gpu_execution_node::jobs::{
    JobKeyId, NodeClock, NodeControls, NodeJobs, NodeKey,
};
use oneiron_server::gpu_execution_node::wire::{
    HoldRef, JobAnswer, JobEnd, JobReceipt, JobRefusal, JobReserve, JobState, JobStatusAnswer,
    JobSubmit, NetworkMode, OutputDecl, OutputsState, ResourceRequest, ScopeKind, SignedJobSubmit,
    SlotSelector, Starter, WorkloadPin,
};
use oneiron_server::test_doors::node_jobs::{ScriptedNode, ScriptedSigner};

const TEMPLATE: &str = "open-models-session";
const DIGEST: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const NOW_MS: u64 = 1_800_000_000_000;
const WAIT: Duration = Duration::from_secs(10);
const NANOS_PER_SEC: u64 = 1_000_000_000;
/// Each chunk's paid time.
const CHUNK_SECS: u64 = 600;
/// The session template's longest run.
const SESSION_MAX_SECS: u64 = 3_600;

struct Fixture {
    _dir: tempfile::TempDir,
    node: ScriptedNode,
    issuer: EntityId,
    pin: WorkloadPin,
}

/// A node whose template is a session template.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temp dir");
    let node = ScriptedNode::new(dir.path(), EntityId::now(), TEMPLATE, DIGEST, NOW_MS);
    node.admission
        .set_template_session(TEMPLATE, Some(SESSION_MAX_SECS));
    Fixture {
        _dir: dir,
        node,
        issuer: EntityId::now(),
        pin: pin(),
    }
}

fn pin() -> WorkloadPin {
    WorkloadPin {
        template: TEMPLATE.to_owned(),
        template_digest: DIGEST.to_owned(),
        commit: "a".repeat(40),
        contract_sha256: "b".repeat(64),
        contract_path: "contract.json".to_owned(),
        entry: "tools/agents/session.sh".to_owned(),
        args: Vec::new(),
        request: ResourceRequest {
            cpu_threads: 0,
            memory_mib: 8 * 1024,
            disk_mib: 2 * 1024,
            devices: vec![DeviceClaim {
                kind: DeviceKind::Gpu,
                count: 1,
                memory_mib: 8 * 1024,
                features: Vec::new(),
                sharing: Sharing::Exclusive,
            }],
            maximum_secs: CHUNK_SECS,
        },
        scope: ScopeKind::Host,
        network: NetworkMode::None,
        outputs: vec![OutputDecl {
            name: "transcript.jsonl".to_owned(),
            returnable: true,
        }],
    }
}

impl Fixture {
    fn signed(&self, key: &str, chunk: u32, continues: Option<&str>) -> SignedJobSubmit {
        let wall_ms = self.node.clock.wall_ms();
        let submit = JobSubmit {
            key: key.to_owned(),
            job: EntityId::now(),
            chunk,
            pin: self.pin.clone(),
            slot: SlotSelector::default(),
            maximum_secs: CHUNK_SECS,
            issued_at_ms: wall_ms,
            not_after_ms: wall_ms + 300_000,
            issuer: self.issuer,
            starter: Starter::Owner,
            hold: HoldRef {
                reservation: format!("hold-{key}"),
                generation: 1,
            },
            authority_heads: Vec::new(),
            continues: continues.map(str::to_owned),
            warm: Vec::new(),
        };
        SignedJobSubmit::sign(submit, ScriptedSigner::new(self.issuer).as_ref())
            .expect("the issuer signs")
    }

    /// The renewal of `first`'s run under `key`, its chunk `chunk`.
    fn renewal(&self, key: &str, chunk: u32, first: &str) -> SignedJobSubmit {
        self.signed(key, chunk, Some(first))
    }

    /// Reserves and submits the session's first key and waits until its
    /// unit runs. Returns the launch's boot-clock time.
    fn launch(&self, jobs: &NodeJobs, key: &str) -> u64 {
        let reserve = JobReserve {
            key: key.to_owned(),
            pin: self.pin.clone(),
            slot: SlotSelector::default(),
            issuer: self.issuer,
            starter: Starter::Owner,
            issued_at_ms: NOW_MS,
            not_after_ms: NOW_MS + 300_000,
        };
        assert_eq!(
            receipt(jobs.reserve(self.issuer, reserve)).state,
            JobState::Held
        );
        assert_eq!(
            receipt(jobs.submit(self.issuer, self.signed(key, 0, None))).state,
            JobState::Accepted
        );
        wait_for(jobs, key, |entry| entry.state == JobState::Launching);
        jobs.tick();
        let running = wait_for(jobs, key, |entry| entry.state == JobState::Running);
        running
            .launch
            .expect("a running key launched")
            .launch_boot_ns
    }

    fn advance_secs(&self, secs: u64) {
        self.node.clock.advance_ms(secs * 1_000);
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

/// The run's cutoff as the journal holds it.
fn cutoff(jobs: &NodeJobs, key: &str) -> u64 {
    entry(jobs, key)
        .and_then(|entry| entry.launch)
        .expect("the run launched")
        .cutoff_boot_ns
}

fn refused(reason: &str) -> Option<JobEnd> {
    Some(JobEnd::Refused {
        reason: reason.to_owned(),
    })
}

/// Waits until the key exists and `done` holds for it: the node's staging
/// worker and launch commit run on threads of their own and signal nothing
/// a test could await, so the wait polls.
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

/// Waits until every staging worker has had time to finish: a key that
/// should start nothing leaves no state to poll for.
fn settle() {
    // testkit-lint: allow(sleep) proves an absence: no worker signals that it started nothing
    std::thread::sleep(Duration::from_millis(300));
}

/// I1 for sessions: the chunk's key is a paid slice of the run, so it never
/// starts a unit, gets no control directory and holds no key of its own. A
/// renewal under a job template is refused and starts nothing either.
#[test]
fn a_continuing_key_never_starts_a_process() {
    let f = fixture();
    let jobs = f.node.open();
    let launched = f.launch(&jobs, "session-0");
    f.advance_secs(60);

    let chunk = receipt(jobs.submit(f.issuer, f.renewal("session-1", 1, "session-0")));
    // Its paid time begins where the first chunk's ends: not yet.
    assert_eq!(chunk.state, JobState::Accepted, "{chunk:?}");
    assert!(!chunk.started);
    let slice = chunk.slice.expect("a chunk's receipt names its slice");
    assert_eq!((slice.first_key.as_str(), slice.renewal), ("session-0", 1));
    assert_eq!(slice.from_boot_ns, launched + CHUNK_SECS * NANOS_PER_SEC);
    assert_eq!(slice.to_boot_ns, launched + 2 * CHUNK_SECS * NANOS_PER_SEC);

    jobs.tick();
    settle();
    jobs.tick();
    assert_eq!(f.node.units.total_starts(), 1, "one run, one start");
    assert_eq!(f.node.units.starts("session-1"), 0);
    assert!(
        entry(&jobs, "session-1").is_none(),
        "the chunk's key holds no key of its own"
    );
    assert!(
        !JobKeyId::for_key("session-1")
            .control_dir(&f.node.paths.state_dir)
            .exists(),
        "the chunk's key has no control directory"
    );

    // A job template's run takes no renewal.
    f.node.admission.set_template_session(TEMPLATE, None);
    let job_run = receipt(jobs.submit(f.issuer, f.renewal("session-2", 2, "session-0")));
    assert_eq!(job_run.end, refused("template_not_session"));
    assert!(!job_run.started);
    settle();
    assert_eq!(f.node.units.total_starts(), 1);
    assert_eq!(
        cutoff(&jobs, "session-0"),
        launched + 2 * CHUNK_SECS * NANOS_PER_SEC,
        "the refused renewal moved nothing"
    );
}

/// I5 for sessions: with no paid renewal the run's cutoff stays at the end
/// of its first chunk, the scope is never asked to move it, a renewal that
/// comes inside the stop grace continues nothing, and the cutoff ends the
/// run there with its first chunk's seconds.
#[test]
fn a_session_without_a_paid_renewal_ends_at_the_end_of_its_chunk() {
    let f = fixture();
    let jobs = f.node.open();
    let launched = f.launch(&jobs, "session-0");
    let first_cutoff = launched + CHUNK_SECS * NANOS_PER_SEC;
    assert_eq!(cutoff(&jobs, "session-0"), first_cutoff);

    f.advance_secs(CHUNK_SECS - 10);
    jobs.tick();
    assert_eq!(
        f.node.units.renewed_cutoff("session-0"),
        None,
        "no renewal: the scope's cutoff stays where the launch armed it"
    );
    // Ten seconds before the cutoff, inside the default stop grace: the
    // cutoff is already stopping the run.
    let late = receipt(jobs.submit(f.issuer, f.renewal("session-1", 1, "session-0")));
    assert_eq!(late.end, refused("continues_ended"));
    assert_eq!(late.measured_secs, None);
    assert_eq!(cutoff(&jobs, "session-0"), first_cutoff);
    assert_eq!(f.node.units.renewed_cutoff("session-0"), None);

    f.advance_secs(10);
    f.node.units.cut_off("session-0");
    jobs.tick();
    let ended = wait_for(&jobs, "session-0", |entry| entry.state == JobState::Ended);
    assert_eq!(ended.end, Some(JobEnd::TimeLimit));
    let run = known(jobs.find(f.issuer, "session-0"));
    assert_eq!(run.measured_secs, Some(CHUNK_SECS));
    assert_eq!(run.slice, None, "a run never renewed answers as a job");
}

/// No gap and no overlap at a takeover: three chunks, the run ends inside
/// the third; each chunk's slice begins where the one before ends, the two
/// passed chunks end `Continued` with their whole paid time, the third
/// carries the run's end, and the chunks' seconds add up to the run's. A
/// stop in another session bills its current slice what it occupied and a
/// renewed slice that never began nothing.
#[test]
fn every_second_of_a_renewed_session_is_billed_to_exactly_one_chunk() {
    let f = fixture();
    let jobs = f.node.open();
    let launched = f.launch(&jobs, "session-0");

    f.advance_secs(300);
    let first = receipt(jobs.submit(f.issuer, f.renewal("session-1", 1, "session-0")));
    assert_eq!(first.state, JobState::Accepted);
    assert_eq!(
        f.node.units.renewed_cutoff("session-0"),
        Some(launched + 2 * CHUNK_SECS * NANOS_PER_SEC),
        "the scope's cutoff moved forward by the paid chunk"
    );
    f.advance_secs(600);
    receipt(jobs.submit(f.issuer, f.renewal("session-2", 2, "session-0")));
    assert_eq!(
        f.node.units.renewed_cutoff("session-0"),
        Some(launched + 3 * CHUNK_SECS * NANOS_PER_SEC)
    );
    // Now 1,300 s after the launch: inside the third chunk. A slice passes
    // only once the node saw the run alive past its end: before the next
    // tick the second chunk is still the current one.
    f.advance_secs(400);
    let unproved = known(jobs.find(f.issuer, "session-1"));
    assert_eq!(
        unproved.state,
        JobState::Running,
        "no tick has seen the run past 1,200 s yet"
    );
    assert_eq!(
        unproved.measured_secs,
        Some(600),
        "a live slice that a later one follows is at most its chunk long"
    );
    jobs.tick();
    let live: Vec<JobReceipt> = ["session-0", "session-1", "session-2"]
        .iter()
        .map(|key| known(jobs.find(f.issuer, key)))
        .collect();
    assert_eq!(live[0].end, Some(JobEnd::Continued));
    assert_eq!(live[1].end, Some(JobEnd::Continued));
    assert_eq!(live[2].state, JobState::Running);
    assert_eq!(
        live.iter()
            .map(|chunk| chunk.measured_secs)
            .collect::<Vec<_>>(),
        vec![Some(600), Some(600), Some(100)]
    );

    // The run ends 250.5 s into its third chunk.
    f.node.clock.advance_ms(150_500);
    f.node.units.exit("session-0", 0);
    jobs.tick();
    wait_for(&jobs, "session-0", |entry| entry.state == JobState::Ended);
    let chunks: Vec<JobReceipt> = ["session-0", "session-1", "session-2"]
        .iter()
        .map(|key| known(jobs.find(f.issuer, key)))
        .collect();
    let ends: Vec<Option<JobEnd>> = chunks.iter().map(|chunk| chunk.end.clone()).collect();
    assert_eq!(
        ends,
        vec![
            Some(JobEnd::Continued),
            Some(JobEnd::Continued),
            Some(JobEnd::Exited { code: 0 })
        ]
    );
    let slices: Vec<(u64, u64)> = chunks
        .iter()
        .map(|chunk| {
            let slice = chunk.slice.as_ref().expect("each chunk names its slice");
            (slice.from_boot_ns, slice.to_boot_ns)
        })
        .collect();
    assert_eq!(slices[0].0, launched);
    assert_eq!(slices[0].1, slices[1].0, "no gap and no overlap");
    assert_eq!(slices[1].1, slices[2].0, "no gap and no overlap");
    let billed: u64 = chunks
        .iter()
        .map(|chunk| chunk.measured_secs.expect("each chunk measured"))
        .sum();
    // 1,450.5 s occupied: 600 + 600 + 251, the run's own seconds rounded up.
    assert_eq!(billed, 1_451);
    let occupied_ns = chunks[2]
        .occupied
        .as_ref()
        .and_then(|occupied| occupied.end_boot_ns)
        .expect("the run's end")
        - launched;
    assert_eq!(billed, occupied_ns.div_ceil(NANOS_PER_SEC));

    // A stop: another session, renewed once, stopped through its chunk key
    // 300 s into its first chunk.
    let g = fixture();
    let jobs = g.node.open();
    let launched = g.launch(&jobs, "other-0");
    g.advance_secs(100);
    receipt(jobs.submit(g.issuer, g.renewal("other-1", 1, "other-0")));
    g.advance_secs(200);
    let stopping = known(jobs.stop(g.issuer, "other-1"));
    assert_ne!(stopping.state, JobState::Ended, "{stopping:?}");
    jobs.tick();
    let ended = wait_for(&jobs, "other-0", |entry| entry.state == JobState::Ended);
    assert_eq!(ended.end, Some(JobEnd::Stopped));
    let current = known(jobs.find(g.issuer, "other-0"));
    let never_began = known(jobs.find(g.issuer, "other-1"));
    assert_eq!(current.end, Some(JobEnd::Stopped));
    assert_eq!(current.measured_secs, Some(300));
    assert_eq!(never_began.state, JobState::Ended);
    assert!(!never_began.started, "the renewed slice never began");
    assert_eq!(never_began.end, Some(JobEnd::Withdrawn));
    assert_eq!(
        never_began.outputs,
        OutputsState::Pending,
        "the run's outputs are its last slice's alone"
    );
    assert_eq!(never_began.measured_secs, None);
    assert_eq!(
        current.slice.map(|slice| slice.from_boot_ns),
        Some(launched)
    );
}

/// A late renewal continues nothing: once the run ended, a renewal is the
/// chunk key's `Refused` end, never started, with no seconds; asked again it
/// answers the same receipt. A renewal naming a run the node never had is
/// refused the same way.
#[test]
fn a_renewal_after_the_chunk_ended_is_refused_at_zero_seconds() {
    let f = fixture();
    let jobs = f.node.open();
    f.launch(&jobs, "session-0");
    f.advance_secs(100);
    f.node.units.exit("session-0", 0);
    jobs.tick();
    wait_for(&jobs, "session-0", |entry| entry.state == JobState::Ended);

    let signed = f.renewal("session-1", 1, "session-0");
    let late = receipt(jobs.submit(f.issuer, signed.clone()));
    assert_eq!(late.state, JobState::Ended);
    assert_eq!(late.end, refused("continues_ended"));
    assert!(!late.started);
    assert_eq!(late.measured_secs, None);
    assert_eq!(late.occupied, None);
    let again = receipt(jobs.submit(f.issuer, signed));
    assert_eq!(again.seq, late.seq, "nothing more was journaled");
    assert_eq!(again.end, late.end);

    // A run whose workload exited before any tick read its end takes no
    // renewal either: the node reads the end first.
    let g = fixture();
    let raced_jobs = g.node.open();
    g.launch(&raced_jobs, "quick-0");
    g.advance_secs(30);
    g.node.units.exit("quick-0", 0);
    let raced = receipt(raced_jobs.submit(g.issuer, g.renewal("quick-1", 1, "quick-0")));
    assert_eq!(raced.end, refused("continues_ended"));
    assert_eq!(
        entry(&raced_jobs, "quick-0").map(|entry| entry.state),
        Some(JobState::Ended)
    );

    let unknown = receipt(jobs.submit(f.issuer, f.renewal("stray-1", 1, "no-such-run")));
    assert_eq!(unknown.end, refused("continues_unknown"));
    assert!(!unknown.started);
    assert_eq!(f.node.units.total_starts(), 1);
    assert_eq!(
        known(jobs.find(f.issuer, "session-0")).measured_secs,
        Some(100),
        "the run's own seconds are unchanged"
    );
}

/// A renewal the scope never took holds the next one back only while the
/// run lives (blind review round 1 of #10501): once the run ended at its old
/// cutoff, the next renewal is the chunk key's `Refused` end, not a `Busy`
/// that no tick ever clears.
#[test]
fn a_renewal_after_an_untaken_renewal_and_the_runs_end_is_refused() {
    let f = fixture();
    let jobs = f.node.open();
    f.launch(&jobs, "session-0");
    f.advance_secs(60);
    f.node.units.set_renewing(false);
    let chunk = receipt(jobs.submit(f.issuer, f.renewal("session-1", 1, "session-0")));
    assert_eq!(chunk.state, JobState::Accepted, "the renewal is journaled");
    assert_eq!(f.node.units.renewed_cutoff("session-0"), None);
    assert!(
        matches!(
            jobs.submit(f.issuer, f.renewal("session-2", 2, "session-0")),
            JobAnswer::Busy { .. }
        ),
        "while the run lives, the next renewal waits for the scope"
    );

    f.advance_secs(CHUNK_SECS - 60);
    f.node.units.cut_off("session-0");
    jobs.tick();
    let ended = wait_for(&jobs, "session-0", |entry| entry.state == JobState::Ended);
    assert_eq!(ended.end, Some(JobEnd::TimeLimit));
    let late = receipt(jobs.submit(f.issuer, f.renewal("session-2", 2, "session-0")));
    assert_eq!(late.state, JobState::Ended);
    assert_eq!(late.end, refused("continues_ended"));
    assert!(!late.started);
    assert_eq!(late.measured_secs, None);

    // The same after an engine restart, which forgets every armed cutoff
    // (EM-22, R3A's review of #10501, P1-1).
    let g = fixture();
    let jobs = g.node.open();
    g.launch(&jobs, "other-0");
    g.advance_secs(60);
    receipt(jobs.submit(g.issuer, g.renewal("other-1", 1, "other-0")));
    g.advance_secs(60);
    g.node.units.exit("other-0", 0);
    jobs.tick();
    wait_for(&jobs, "other-0", |entry| entry.state == JobState::Ended);
    drop(jobs);
    let jobs = g.node.open();
    jobs.tick();
    let after_restart = receipt(jobs.submit(g.issuer, g.renewal("other-2", 2, "other-0")));
    assert_eq!(after_restart.end, refused("continues_ended"));
}

/// A renewal waits for the node's fold to hold the issuer's authority heads
/// only while it would pass (EM-22, R3A's review of #10501, P2-1): with a
/// fold that lags it answers `Busy` and writes nothing, and once the run's
/// stop is too near it is refused, so the wait ends.
#[test]
fn a_renewal_waits_for_the_fold_only_while_it_would_pass() {
    let f = fixture();
    let jobs = f.node.open();
    f.launch(&jobs, "session-0");
    f.advance_secs(60);
    f.node.authority.set_stale(true);
    assert!(matches!(
        jobs.submit(f.issuer, f.renewal("session-1", 1, "session-0")),
        JobAnswer::Busy { .. }
    ));
    assert_eq!(
        entry(&jobs, "session-0").map(|entry| entry.renewals.len()),
        Some(0),
        "nothing journaled"
    );
    f.advance_secs(CHUNK_SECS - 60 - 20);
    let late = receipt(jobs.submit(f.issuer, f.renewal("session-1", 1, "session-0")));
    assert_eq!(late.end, refused("continues_ended"));
    assert!(!late.started);

    // A refusal that a wait can undo waits too (Sol review r4, finding 2):
    // a node paused while its fold lags answers Busy, and once it resumes
    // and the fold holds the heads, the same renewal is taken.
    let g = fixture();
    let jobs = g.node.open();
    g.launch(&jobs, "other-0");
    g.advance_secs(60);
    g.node.authority.set_stale(true);
    let controls = |paused: Option<&str>| NodeControls {
        enabled: true,
        paused: paused.map(str::to_owned),
        drained: None,
        stop_requested: false,
    };
    g.node.admission.set_controls(controls(Some("owner pause")));
    let renewal = g.renewal("other-1", 1, "other-0");
    assert!(matches!(
        jobs.submit(g.issuer, renewal.clone()),
        JobAnswer::Busy { .. }
    ));
    g.node.admission.set_controls(controls(None));
    g.node.authority.set_stale(false);
    assert_eq!(
        receipt(jobs.submit(g.issuer, renewal)).state,
        JobState::Accepted
    );
}

/// The node journals no renewal that the scope's handoff could not take
/// before the old cutoff timer fires (EM-22, R3B's review of #10502): 20 s
/// before the run's stop time is too late, 50 s is in time.
#[test]
fn a_renewal_closer_to_the_stop_than_the_scopes_handoff_is_refused() {
    let grace_secs = 10;
    let f = fixture();
    let jobs = f.node.open();
    let launched = f.launch(&jobs, "session-0");
    f.advance_secs(CHUNK_SECS - grace_secs - 20);
    let late = receipt(jobs.submit(f.issuer, f.renewal("session-1", 1, "session-0")));
    assert_eq!(late.end, refused("continues_ended"));
    assert_eq!(
        cutoff(&jobs, "session-0"),
        launched + CHUNK_SECS * NANOS_PER_SEC
    );
    assert_eq!(f.node.units.renewed_cutoff("session-0"), None);

    let g = fixture();
    let jobs = g.node.open();
    let launched = g.launch(&jobs, "other-0");
    g.advance_secs(CHUNK_SECS - grace_secs - 50);
    let in_time = receipt(jobs.submit(g.issuer, g.renewal("other-1", 1, "other-0")));
    assert_eq!(in_time.state, JobState::Accepted);
    assert_eq!(
        g.node.units.renewed_cutoff("other-0"),
        Some(launched + 2 * CHUNK_SECS * NANOS_PER_SEC)
    );
}

/// A renewal sent twice moves the cutoff once and answers its first
/// receipt; the same chunk key naming another run is a key conflict.
#[test]
fn a_renewal_sent_twice_answers_its_first_receipt() {
    let f = fixture();
    let jobs = f.node.open();
    let launched = f.launch(&jobs, "session-0");
    f.advance_secs(60);
    let signed = f.renewal("session-1", 1, "session-0");
    let first = receipt(jobs.submit(f.issuer, signed.clone()));
    let again = receipt(jobs.submit(f.issuer, signed));
    assert_eq!(again.seq, first.seq);
    assert_eq!(again.slice, first.slice);
    assert_eq!(
        cutoff(&jobs, "session-0"),
        launched + 2 * CHUNK_SECS * NANOS_PER_SEC,
        "the cutoff moved by one chunk, once"
    );
    assert_eq!(
        entry(&jobs, "session-0").map(|entry| entry.renewals.len()),
        Some(1)
    );
    assert_eq!(
        jobs.submit(f.issuer, f.renewal("session-1", 1, "another-run")),
        JobAnswer::Refused(JobRefusal::KeyConflict)
    );
}

/// After an engine restart the node adopts the session by its first key
/// (no second start), keeps its renewals, and asks the scope for the
/// cutoff a renewal moved, also one the scope did not take before.
#[test]
fn a_restarted_node_adopts_a_session_by_its_first_key_and_asks_its_cutoff_again() {
    let f = fixture();
    let jobs = f.node.open();
    let launched = f.launch(&jobs, "session-0");
    f.advance_secs(60);
    f.node.units.set_renewing(false);
    let chunk = receipt(jobs.submit(f.issuer, f.renewal("session-1", 1, "session-0")));
    assert_eq!(chunk.state, JobState::Accepted, "the renewal is journaled");
    assert_eq!(f.node.units.renewed_cutoff("session-0"), None);
    drop(jobs);

    f.node.units.set_renewing(true);
    let jobs = f.node.open();
    jobs.tick();
    jobs.tick();
    let renewed = launched + 2 * CHUNK_SECS * NANOS_PER_SEC;
    assert_eq!(f.node.units.renewed_cutoff("session-0"), Some(renewed));
    assert_eq!(cutoff(&jobs, "session-0"), renewed);
    assert_eq!(f.node.units.total_starts(), 1, "adopted, not started again");
    let after = known(jobs.find(f.issuer, "session-1"));
    assert_eq!(after.slice.map(|slice| slice.renewal), Some(1));
    assert_eq!(
        entry(&jobs, "session-0").map(|entry| entry.state),
        Some(JobState::Running)
    );
}

/// The issuer's drain guard judges a renewed session by its run, not by its
/// last slice (EM-22, R4's review of #10501): a run that went past a paid
/// boundary and ends 2 s into the next chunk is past the fast-exit window,
/// and only the slice that holds the run's end may acknowledge its payload.
#[test]
fn a_renewed_sessions_last_slice_never_counts_as_a_fast_exit() {
    let f = fixture();
    let jobs = f.node.open();
    f.launch(&jobs, "session-0");
    f.advance_secs(300);
    receipt(jobs.submit(f.issuer, f.renewal("session-1", 1, "session-0")));
    f.advance_secs(CHUNK_SECS - 300 + 2);
    f.node.units.exit("session-0", 0);
    jobs.tick();
    wait_for(&jobs, "session-0", |entry| entry.state == JobState::Ended);
    let last = known(jobs.find(f.issuer, "session-1"));
    assert_eq!(last.end, Some(JobEnd::Exited { code: 0 }));
    assert_eq!(last.measured_secs, Some(2), "2 s of its own slice");
    assert_eq!(
        machine_job_outcome(&last, &MeterVerdict::Agreed, 5),
        MachineJobOutcome::RanPastFastExit
    );
    let passed = known(jobs.find(f.issuer, "session-0"));
    assert_eq!(passed.end, Some(JobEnd::Continued));
    assert_eq!(
        jobs.acknowledge(f.issuer, "session-0"),
        JobStatusAnswer::Refused(JobRefusal::NotAcknowledgeable {
            state: JobState::Ended
        }),
        "a slice the run went past holds none of its outputs"
    );
}
