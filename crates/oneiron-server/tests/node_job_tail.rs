//! Pass 34 row Q3, the node's half (`34-compute-general/DESIGN.md` 7.2 and
//! section 10): `Tail` on `oneiron/job-status/1` reads a key's stdout and
//! stderr by logical offset while the key runs and after it ended, across a
//! cap that dropped bytes between the head and the tail, and only for the
//! key's issuer; a rotation a writer left unfinished is refused once the key
//! ended. The log files are written here as the unit's log writer
//! (row R3b) writes them. Against R3a's scripted unit manager, device table
//! and clock: no privilege and no network; a second `NodeJobs` on the same
//! directory is an engine restart.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --test node_job_tail`.
#![cfg(all(oneiron_test_support, unix))]

use std::io::Write as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::job_workload::{DeviceClaim, DeviceKind, Sharing};
use oneiron_server::gpu_execution_node::jobs::{JobKeyId, NodeJobs, NodeKey};
use oneiron_server::gpu_execution_node::wire::{
    HoldRef, JobAnswer, JobReceipt, JobRefusal, JobReserve, JobState, JobStatusAnswer, JobSubmit,
    LogStream, LogTail, LogTailRequest, LogTruncation, NetworkMode, OutputDecl, OutputsState,
    ResourceRequest, ScopeKind, SignedJobSubmit, SlotSelector, Starter, TAIL_MAX_BYTES,
    WorkloadPin,
};
use oneiron_server::test_doors::node_jobs::{ScriptedNode, ScriptedSigner};

const TEMPLATE: &str = "open-models";
const DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const NOW_MS: u64 = 1_800_000_000_000;
const WAIT: Duration = Duration::from_secs(10);

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
        outputs: vec![OutputDecl {
            name: "verdict.json".to_owned(),
            returnable: true,
        }],
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
            continues: None,
        };
        SignedJobSubmit::sign(submit, ScriptedSigner::new(self.issuer).as_ref())
            .expect("the issuer signs")
    }

    /// Reserves and submits `key`, and waits until its unit runs.
    fn run(&self, jobs: &NodeJobs, key: &str) {
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
        wait_for(jobs, key, |entry| entry.state == JobState::Running);
    }

    /// Ends `key` with exit 0 and waits until its end is handled.
    fn end(&self, jobs: &NodeJobs, key: &str) {
        self.node.clock.advance_ms(30_000);
        self.node.units.exit(key, 0);
        jobs.tick();
        wait_for(jobs, key, |entry| {
            entry.state == JobState::Ended && entry.outputs != OutputsState::Pending
        });
    }

    /// The key's `log/` on the payload disk, made as the unit makes it.
    fn log_dir(&self, key: &str) -> PathBuf {
        let log = JobKeyId::for_key(key)
            .payload_dir(&self.node.paths.work_dir)
            .join("log");
        std::fs::create_dir_all(&log).expect("log dir");
        log
    }

    /// `Tail` of `key`'s `stream` from `offset`, asked by the key's issuer.
    fn ask(
        &self,
        jobs: &NodeJobs,
        key: &str,
        stream: LogStream,
        offset: u64,
        max: u32,
    ) -> JobStatusAnswer {
        jobs.tail(
            self.issuer,
            &LogTailRequest {
                key: key.to_owned(),
                stream,
                offset,
                max,
            },
        )
    }

    /// As [`Fixture::ask`] on stdout, answered with bytes.
    fn tail(&self, jobs: &NodeJobs, key: &str, offset: u64, max: u32) -> LogTail {
        match self.ask(jobs, key, LogStream::Stdout, offset, max) {
            JobStatusAnswer::Tail(tail) => tail,
            other => panic!("expected log bytes from {offset}, got {other:?}"),
        }
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
            // testkit-lint: allow(wall-clock) the same bound
            Instant::now() < deadline,
            "key {key} did not reach the state: {:?}",
            entry(jobs, key)
        );
        // testkit-lint: allow(sleep) the poll interval; the worker threads signal nothing
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn page(bytes: &[u8], next_offset: u64, ended: bool, dropped: Option<u64>) -> LogTail {
    LogTail {
        bytes: bytes.to_vec(),
        next_offset,
        ended,
        truncated: dropped.map(|dropped| LogTruncation { dropped }),
    }
}

fn append(path: &std::path::Path, bytes: &[u8]) {
    std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .expect("append to the log");
}

fn not_readable(answer: &JobStatusAnswer) -> bool {
    matches!(
        answer,
        JobStatusAnswer::Refused(JobRefusal::LogNotReadable { .. })
    )
}

/// Q3 (section 10): a reader keeps its own offset. After a lost answer it
/// asks again from the offset it holds and gets the same bytes; an engine
/// restart changes nothing; when the cap drops bytes, a reader past them
/// goes on unchanged and a reader behind them is told how many it lost.
#[test]
fn a_log_tail_resumes_from_an_offset_after_a_dropped_connection() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let key = "job-q3/chunk-0";

    // Before the launch the stream is empty and has not ended.
    receipt(jobs.reserve(fixture.issuer, fixture.reserve(key)));
    assert_eq!(fixture.tail(&jobs, key, 0, 1024), page(b"", 0, false, None));
    receipt(jobs.submit(fixture.issuer, fixture.submit(key)));
    wait_for(&jobs, key, |entry| entry.state == JobState::Launching);
    jobs.tick();
    wait_for(&jobs, key, |entry| entry.state == JobState::Running);

    let log = fixture.log_dir(key);
    let stdout = log.join("stdout");
    std::fs::write(&stdout, b"step 1\nstep 2\n").expect("stdout");
    assert_eq!(
        fixture.tail(&jobs, key, 0, 7),
        page(b"step 1\n", 7, false, None)
    );

    // The answer from 7 is lost with the connection: the reader asks again
    // from the offset it holds and gets the same bytes, none twice.
    let lost = fixture.tail(&jobs, key, 7, 1024);
    let again = fixture.tail(&jobs, key, 7, 1024);
    assert_eq!(lost, again);
    assert_eq!(again, page(b"step 2\n", 14, false, None));

    // An engine restart under the running key: the reader resumes from 14.
    drop(jobs);
    let jobs = fixture.node.open();
    append(&stdout, b"step 3\n");
    assert_eq!(
        fixture.tail(&jobs, key, 14, 1024),
        page(b"step 3\n", 21, false, None)
    );
    // An offset past the end answers nothing, from the end.
    assert_eq!(
        fixture.tail(&jobs, key, 900, 1024),
        page(b"", 21, false, None)
    );

    // The cap keeps the head, "step 1\n", and the newest tail: 14 bytes
    // between them are dropped, as the writer records.
    std::fs::write(log.join("stdout.dropped"), br#"{"at":7,"dropped":14}"#).expect("record");
    std::fs::write(&stdout, b"step 1\nstep 4\n").expect("rotated stdout");
    // The reader past the gap goes on unchanged.
    assert_eq!(
        fixture.tail(&jobs, key, 21, 1024),
        page(b"step 4\n", 28, false, None)
    );
    // A reader behind it is told how many bytes it lost, and gets what
    // follows them.
    assert_eq!(
        fixture.tail(&jobs, key, 7, 1024),
        page(b"step 4\n", 28, false, Some(14))
    );
    assert_eq!(
        fixture.tail(&jobs, key, 10, 1024),
        page(b"step 4\n", 28, false, Some(11))
    );
    // The head is read up to the gap, never across it.
    assert_eq!(
        fixture.tail(&jobs, key, 0, 1024),
        page(b"step 1\n", 7, false, None)
    );
    // While the writer rotates, the node asks the reader to come back.
    std::fs::write(
        log.join("stdout.dropped"),
        br#"{"at":7,"dropped":14,"rotating":true}"#,
    )
    .expect("rotating record");
    assert!(matches!(
        fixture.ask(&jobs, key, LogStream::Stdout, 21, 1024),
        JobStatusAnswer::Busy { .. }
    ));
    std::fs::write(log.join("stdout.dropped"), br#"{"at":7,"dropped":14}"#).expect("record");

    // stderr is its own stream.
    std::fs::write(log.join("stderr"), b"warning: slow disk\n").expect("stderr");
    assert_eq!(
        fixture.ask(&jobs, key, LogStream::Stderr, 0, 1024),
        JobStatusAnswer::Tail(page(b"warning: slow disk\n", 19, false, None))
    );

    // The key ends: a read that reaches the end says the stream is whole;
    // one that does not, does not.
    fixture.end(&jobs, key);
    assert_eq!(
        fixture.tail(&jobs, key, 28, 1024),
        page(b"", 28, true, None)
    );
    assert_eq!(
        fixture.tail(&jobs, key, 21, 1024),
        page(b"step 4\n", 28, true, None)
    );
    assert_eq!(
        fixture.tail(&jobs, key, 21, 4),
        page(b"step", 25, false, None)
    );
}

/// FIX EXEC-LOG-TAIL-ROTATING-AFTER-END: a writer killed inside a rotation
/// (the unit's KILL after the stop grace) leaves its drop record `rotating`,
/// and once the key ended no writer is left to finish it. While the key runs
/// that record asks the reader to come back; after the end it is refused,
/// not answered `Busy` for good. The other stream still reads.
/// Red at main 9edd639c: the ended key's read answers `Busy`.
#[test]
fn a_rotation_an_ended_key_left_unfinished_is_refused_not_busy() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let key = "job-q3c/chunk-0";
    fixture.run(&jobs, key);
    let log = fixture.log_dir(key);
    std::fs::write(log.join("stdout"), b"step 1\nstep 4\n").expect("stdout");
    std::fs::write(
        log.join("stdout.dropped"),
        br#"{"at":7,"dropped":14,"rotating":true}"#,
    )
    .expect("rotating record");
    std::fs::write(log.join("stderr"), b"warning: slow disk\n").expect("stderr");
    assert!(matches!(
        fixture.ask(&jobs, key, LogStream::Stdout, 0, 1024),
        JobStatusAnswer::Busy { .. }
    ));

    fixture.end(&jobs, key);
    let answer = fixture.ask(&jobs, key, LogStream::Stdout, 0, 1024);
    assert!(
        matches!(
            &answer,
            JobStatusAnswer::Refused(JobRefusal::LogNotReadable { why })
                if why.starts_with("log_writer_ended_inside_rotation")
        ),
        "an ended key's unfinished rotation is refused: {answer:?}"
    );
    assert_eq!(
        fixture.ask(&jobs, key, LogStream::Stderr, 0, 1024),
        JobStatusAnswer::Tail(page(b"warning: slow disk\n", 19, true, None))
    );
}

/// Only the key's issuer reads its log, and the log is the workload's own
/// file: a link, a drop record that does not fit its file, or a cleaned
/// payload is refused, and one answer never passes the transport bound.
#[test]
fn a_log_is_read_only_by_the_keys_issuer_and_never_through_a_link() {
    let fixture = fixture();
    fixture.node.admission.set_receipt_keep_days(1);
    let jobs = fixture.node.open();
    let key = "job-q3b/chunk-0";
    fixture.run(&jobs, key);
    let log = fixture.log_dir(key);
    let stdout = log.join("stdout");
    std::fs::write(&stdout, vec![b'x'; 2 * 1024 * 1024]).expect("a long stdout");

    // One answer holds at most one transport piece, whatever `max` says.
    let bounded = fixture.tail(&jobs, key, 0, u32::MAX);
    assert_eq!(bounded.bytes.len(), TAIL_MAX_BYTES as usize);
    assert_eq!(bounded.next_offset, u64::from(TAIL_MAX_BYTES));

    // Another issuer and an unknown key get nothing.
    let request = LogTailRequest {
        key: key.to_owned(),
        stream: LogStream::Stdout,
        offset: 0,
        max: 1024,
    };
    assert_eq!(
        jobs.tail(EntityId::now(), &request),
        JobStatusAnswer::Refused(JobRefusal::NotTheKeysIssuer)
    );
    assert!(matches!(
        fixture.ask(&jobs, "job-unknown", LogStream::Stdout, 0, 1024),
        JobStatusAnswer::Absent { .. }
    ));

    // A drop record past its file, or one that is not a record, is refused.
    std::fs::write(log.join("stdout.dropped"), br#"{"at":4194304,"dropped":1}"#).expect("record");
    assert!(not_readable(&fixture.ask(
        &jobs,
        key,
        LogStream::Stdout,
        0,
        1024
    )));
    std::fs::write(log.join("stdout.dropped"), b"not a record").expect("record");
    assert!(not_readable(&fixture.ask(
        &jobs,
        key,
        LogStream::Stdout,
        0,
        1024
    )));
    std::fs::remove_file(log.join("stdout.dropped")).expect("remove the record");

    // The log swapped for a link to a file the engine can read is refused.
    let elsewhere = fixture.node.paths.work_dir.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("dir");
    std::fs::write(elsewhere.join("secret"), b"not the log").expect("secret");
    std::fs::remove_file(&stdout).expect("remove stdout");
    std::os::unix::fs::symlink(elsewhere.join("secret"), &stdout).expect("link");
    assert!(not_readable(&fixture.ask(
        &jobs,
        key,
        LogStream::Stdout,
        0,
        1024
    )));
    std::fs::remove_file(&stdout).expect("remove the link");
    std::fs::write(&stdout, b"done\n").expect("stdout");

    // After the end and the issuer's `Ack`, the log is read until the keep
    // time cleans the payload; then it is refused.
    fixture.end(&jobs, key);
    assert_eq!(
        fixture.tail(&jobs, key, 0, 1024),
        page(b"done\n", 5, true, None)
    );
    assert_eq!(
        jobs.acknowledge(fixture.issuer, key),
        JobStatusAnswer::Acknowledged
    );
    fixture.node.clock.advance_ms(2 * 86_400_000);
    jobs.tick();
    wait_for(&jobs, key, |entry| entry.cleaned);
    assert!(not_readable(&fixture.ask(
        &jobs,
        key,
        LogStream::Stdout,
        0,
        1024
    )));
}
