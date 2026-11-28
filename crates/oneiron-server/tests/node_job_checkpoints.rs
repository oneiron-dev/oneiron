//! Pass 34 row C1, part A (gap 10; `34-compute-general/DESIGN.md` 4.6, 4.7,
//! 6.2): a resumable template names a checkpoint directory under `out/`;
//! while the key runs, and once more at its end, the node finds the latest
//! complete checkpoint that `LATEST` names, digests its manifest, journals
//! it, and the node's signed receipt carries it. Against R3a's scripted unit
//! manager, device table and clock: the handlers and the tick are called
//! directly, and a second `NodeJobs` on the same directory is an engine
//! restart. Every expected digest is computed here from the manifest format,
//! not by the node's own code.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --test node_job_checkpoints`.
#![cfg(all(oneiron_test_support, unix))]

use std::path::Path;
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::job_workload::{DeviceClaim, DeviceKind, Sharing};
use oneiron_server::gpu_execution_node::ExecutionNodeSettings;
use oneiron_server::gpu_execution_node::jobs::{JobKeyId, NodeJobs, NodeKey};
use oneiron_server::gpu_execution_node::wire::{
    CheckpointRecord, HoldRef, JobAnswer, JobReceipt, JobReserve, JobState, JobStatusAnswer,
    JobSubmit, NetworkMode, OutputDecl, OutputsState, ResourceRequest, ScopeKind, SignedJobSubmit,
    SlotSelector, Starter, WorkloadPin,
};
use oneiron_server::test_doors::node_jobs::{ScriptedNode, ScriptedSigner};
use sha2::{Digest as _, Sha256};

const TEMPLATE: &str = "open-models";
const DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const NOW_MS: u64 = 1_800_000_000_000;
const WAIT: Duration = Duration::from_secs(10);
/// The template's checkpoint directory under `out/`.
const CHECKPOINTS: &str = "ckpt";
/// Past the node's default `jobs.checkpoints.scan_secs` (60).
const PAST_SCAN_MS: u64 = 61_000;

/// One checkpoint's files: a path under the label directory and its text.
type Files<'a> = &'a [(&'a str, &'a str)];

const STEP_100: Files<'static> = &[
    ("a.bin", "weights of step 100"),
    ("sub/b.bin", "optimiser of step 100"),
];

struct Fixture {
    dir: tempfile::TempDir,
    node: ScriptedNode,
    issuer: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temp dir");
    let node = ScriptedNode::new(dir.path(), EntityId::now(), TEMPLATE, DIGEST, NOW_MS);
    Fixture {
        dir,
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
        entry: "tools/units/train.sh".to_owned(),
        args: Vec::new(),
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

    /// Reserves and submits `key`, waits until its unit runs, and then makes
    /// the template resumable, so no scan ran before the test's first tick.
    fn run_resumable(&self, jobs: &NodeJobs, key: &str) -> std::path::PathBuf {
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
        self.node
            .admission
            .set_template_checkpoints(TEMPLATE, true, Some(CHECKPOINTS));
        let out = JobKeyId::for_key(key)
            .payload_dir(&self.node.paths.work_dir)
            .join("out");
        std::fs::create_dir_all(out.join(CHECKPOINTS)).expect("out dir");
        out
    }

    /// Moves the scan interval on and ticks until the key's checkpoint has
    /// the label `label`.
    fn scan_until_label(&self, jobs: &NodeJobs, key: &str, label: &str) -> CheckpointRecord {
        self.node.clock.advance_ms(PAST_SCAN_MS);
        tick_until(jobs, key, |entry| {
            entry
                .checkpoint
                .as_ref()
                .is_some_and(|checkpoint| checkpoint.label == label)
        })
        .checkpoint
        .expect("a checkpoint")
    }

    /// Writes the verdict, ends the unit cleanly, and ticks until the
    /// outputs are sealed.
    fn end_cleanly(&self, jobs: &NodeJobs, key: &str, out: &Path) -> NodeKey {
        std::fs::write(out.join("verdict.json"), br#"{"verdict":"pass"}"#).expect("verdict");
        self.node.clock.advance_ms(30_000);
        self.node.units.exit(key, 0);
        tick_until(jobs, key, |entry| entry.outputs != OutputsState::Pending)
    }
}

/// Writes `files` under `out/ckpt/<label>/`.
fn write_checkpoint(out: &Path, label: &str, files: Files<'_>) {
    for (path, text) in files {
        let file = out.join(CHECKPOINTS).join(label).join(path);
        std::fs::create_dir_all(file.parent().expect("a parent")).expect("checkpoint dir");
        std::fs::write(&file, text).expect("checkpoint file");
    }
}

/// Names `label` in `LATEST` by rename, as the workload does once the
/// checkpoint is complete.
fn publish(out: &Path, label: &str) {
    let dir = out.join(CHECKPOINTS);
    let next = dir.join("LATEST.next");
    std::fs::write(&next, format!("{label}\n")).expect("marker");
    std::fs::rename(&next, dir.join("LATEST")).expect("marker rename");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The checkpoint digest from the manifest format: one line
/// `<sha256> <bytes> <path>\n` per file, sorted by the path's bytes, then
/// the sha256 of the whole text.
fn expected_digest(files: Files<'_>) -> String {
    let mut lines: Vec<(&str, String)> = files
        .iter()
        .map(|(path, text)| {
            let line = format!("{} {} {path}\n", hex(&Sha256::digest(text)), text.len());
            (*path, line)
        })
        .collect();
    lines.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let manifest: String = lines.into_iter().map(|(_, line)| line).collect();
    hex(&Sha256::digest(manifest.as_bytes()))
}

fn total_bytes(files: Files<'_>) -> u64 {
    files.iter().map(|(_, text)| text.len() as u64).sum()
}

/// Whether `name` occurs in the encoded `bytes`.
fn contains(bytes: &[u8], name: &[u8]) -> bool {
    bytes.windows(name.len()).any(|at| at == name)
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

/// Ticks until `done` holds for the key. A checkpoint worker runs beside
/// the tick, and a tick while it runs starts no other work for the key, so
/// one tick alone may find the key busy.
fn tick_until(jobs: &NodeJobs, key: &str, done: impl Fn(&NodeKey) -> bool) -> NodeKey {
    // testkit-lint: allow(wall-clock) bounds a wait on the node's own worker threads
    let deadline = Instant::now() + WAIT;
    loop {
        jobs.tick();
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
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Opens the node again once the closed one's last worker has returned: a
/// worker holds the journal's writer lock while it lives.
fn reopen(fixture: &Fixture) -> NodeJobs {
    // testkit-lint: allow(wall-clock) bounds a wait on the node's own worker threads
    let deadline = Instant::now() + WAIT;
    loop {
        let error = match fixture.node.try_open() {
            Ok(jobs) => return jobs,
            Err(error) => error,
        };
        assert!(
            error.kind() == std::io::ErrorKind::WouldBlock
                // testkit-lint: allow(wall-clock) the same bound
                && Instant::now() < deadline,
            "the node does not open again: {error}"
        );
        // testkit-lint: allow(sleep) the poll interval; the worker threads signal nothing
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A node file holding the template `probe`, with `extra` lines appended to
/// that template's table.
fn node_text(extra: &str) -> String {
    format!(
        r#"[execution_node]
enabled = true
issuers = ["5d1e3c8a9b7f4e21a0c6d2b8f3e9a714"]
state_dir = "/var/lib/oneiron/jobs"
work_dir = "/data/oneiron-jobs"

[execution_node.templates.probe]
repo = "/srv/git/probe.git"
entries = ["tools/units/*.sh"]
interpreter = ["/usr/bin/bash"]
returnable = ["verdict.json"]
max_secs = 1800
memory_gib = 8
disk_gib = 4
{extra}
"#
    )
}

#[test]
fn a_resumable_templates_latest_complete_checkpoint_is_in_the_receipt() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let key = "job-c1-1/chunk-0";
    let out = fixture.run_resumable(&jobs, key);

    write_checkpoint(&out, "step-100", STEP_100);
    publish(&out, "step-100");
    let recorded = fixture.scan_until_label(&jobs, key, "step-100");

    let running = known(jobs.find(fixture.issuer, key));
    assert_eq!(running.state, JobState::Running);
    let checkpoint = running
        .checkpoint
        .expect("the receipt carries the checkpoint");
    assert_eq!(checkpoint, recorded);
    assert_eq!(checkpoint.label, "step-100");
    assert_eq!(checkpoint.files, 2);
    assert_eq!(checkpoint.bytes, total_bytes(STEP_100));
    assert_eq!(checkpoint.sha256, expected_digest(STEP_100));
    assert!(
        checkpoint.saved_at_ms >= NOW_MS + PAST_SCAN_MS,
        "stamped on the node's wall clock when it was recorded: {}",
        checkpoint.saved_at_ms
    );
}

#[test]
fn a_checkpoint_that_latest_does_not_name_is_never_in_the_receipt() {
    // No LATEST at all: the end's scan reports nothing.
    let unnamed = fixture();
    let jobs = unnamed.node.open();
    let key = "job-c1-2a/chunk-0";
    let out = unnamed.run_resumable(&jobs, key);
    write_checkpoint(&out, "step-200", STEP_100);
    let sealed = unnamed.end_cleanly(&jobs, key, &out);
    assert!(matches!(sealed.outputs, OutputsState::Hashed(_)));
    assert_eq!(sealed.checkpoint, None);
    assert_eq!(known(jobs.find(unnamed.issuer, key)).checkpoint, None);

    // LATEST names step-100 while step-200 is still being written: only
    // step-100 is reported, while the key runs and at its end.
    let named = fixture();
    let jobs = named.node.open();
    let key = "job-c1-2b/chunk-0";
    let out = named.run_resumable(&jobs, key);
    let step_200: Files<'_> = &[("a.bin", "half of step 200")];
    write_checkpoint(&out, "step-100", STEP_100);
    write_checkpoint(&out, "step-200", step_200);
    publish(&out, "step-100");
    let running = named.scan_until_label(&jobs, key, "step-100");
    assert_eq!(running.sha256, expected_digest(STEP_100));
    let sealed = named.end_cleanly(&jobs, key, &out);
    let last = known(jobs.find(named.issuer, key))
        .checkpoint
        .expect("the end keeps the named checkpoint");
    assert_eq!(last.label, "step-100");
    assert_eq!(last.sha256, expected_digest(STEP_100));
    assert_eq!(sealed.checkpoint.as_ref(), Some(&last));
}

#[test]
fn a_checkpoint_digest_changes_when_any_file_of_it_changes() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let key = "job-c1-3/chunk-0";
    let out = fixture.run_resumable(&jobs, key);
    let step_1: Files<'_> = &[("a.bin", "weights 0001"), ("b.bin", "optimiser 0001")];
    let step_2: Files<'_> = &[("a.bin", "weights 0002"), ("b.bin", "optimiser 0001")];

    write_checkpoint(&out, "step-1", step_1);
    publish(&out, "step-1");
    let first = fixture.scan_until_label(&jobs, key, "step-1");
    assert_eq!(first.sha256, expected_digest(step_1));

    write_checkpoint(&out, "step-2", step_2);
    publish(&out, "step-2");
    let second = fixture.scan_until_label(&jobs, key, "step-2");
    assert_eq!(second.sha256, expected_digest(step_2));
    assert_ne!(
        second.sha256, first.sha256,
        "one changed byte changes the digest"
    );

    // The same files under another label: the label is not hashed.
    write_checkpoint(&out, "step-3", step_2);
    publish(&out, "step-3");
    let third = fixture.scan_until_label(&jobs, key, "step-3");
    assert_eq!(third.sha256, second.sha256);
    assert_eq!(
        known(jobs.find(fixture.issuer, key))
            .checkpoint
            .map(|checkpoint| checkpoint.label),
        Some("step-3".to_owned())
    );
}

#[test]
fn a_checkpoint_holding_a_symlink_is_never_in_the_receipt() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let key = "job-c1-4/chunk-0";
    let out = fixture.run_resumable(&jobs, key);
    let step_0: Files<'_> = &[("a.bin", "weights 0000")];
    write_checkpoint(&out, "step-0", step_0);
    publish(&out, "step-0");
    let good = fixture.scan_until_label(&jobs, key, "step-0");

    // step-1 holds a link to a file outside out/: the scan fails, and the
    // last good checkpoint stays.
    let outside = fixture.dir.path().join("outside.bin");
    std::fs::write(&outside, b"not the workload's").expect("outside file");
    write_checkpoint(&out, "step-1", &[("a.bin", "weights 0001")]);
    std::os::unix::fs::symlink(
        &outside,
        out.join(CHECKPOINTS).join("step-1").join("link.bin"),
    )
    .expect("symlink");
    publish(&out, "step-1");
    let sealed = fixture.end_cleanly(&jobs, key, &out);
    assert!(
        matches!(sealed.outputs, OutputsState::Hashed(_)),
        "a failed scan does not hold the outputs: {:?}",
        sealed.outputs
    );
    assert_eq!(sealed.checkpoint.as_ref(), Some(&good));
    assert_eq!(
        known(jobs.find(fixture.issuer, key)).checkpoint,
        Some(good),
        "step-1 is never reported"
    );
}

#[test]
fn the_final_checkpoint_rides_in_the_receipt_with_the_hashed_outputs() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let key = "job-c1-5/chunk-0";
    let out = fixture.run_resumable(&jobs, key);
    // No tick runs between the checkpoint and the unit's end: the end's
    // scan finds it.
    write_checkpoint(&out, "step-900", STEP_100);
    publish(&out, "step-900");
    let sealed = fixture.end_cleanly(&jobs, key, &out);

    let ended = known(jobs.find(fixture.issuer, key));
    assert_eq!(ended.state, JobState::Ended);
    let OutputsState::Hashed(outputs) = &ended.outputs else {
        panic!("the outputs are hashed: {:?}", ended.outputs);
    };
    assert!(outputs.iter().any(|output| output.name == "verdict.json"));
    let checkpoint = ended
        .checkpoint
        .expect("the receipt with the hashed outputs carries the checkpoint");
    assert_eq!(checkpoint.label, "step-900");
    assert_eq!(checkpoint.sha256, expected_digest(STEP_100));
    assert_eq!(sealed.checkpoint, Some(checkpoint));
}

#[test]
fn a_template_without_the_checkpoint_fields_keeps_its_digest() {
    let parse = |extra: &str| {
        ExecutionNodeSettings::parse(&node_text(extra))
            .expect("the node's file validates")
            .template_digest("probe")
            .expect("the template has a digest")
    };
    let plain = parse("");
    assert_eq!(parse("resumable = false"), plain);
    assert_ne!(
        parse("resumable = true\ncheckpoint_output = \"ckpt\""),
        plain,
        "a resumable template is another template"
    );
}

#[test]
fn a_resumable_template_without_a_checkpoint_output_is_refused_at_load() {
    let refused = ExecutionNodeSettings::parse(&node_text("resumable = true"));
    assert!(
        refused
            .as_ref()
            .is_err_and(|why| why.contains("requires checkpoint_output")),
        "{refused:?}"
    );
    let returnable = ExecutionNodeSettings::parse(&node_text(
        "resumable = true\ncheckpoint_output = \"verdict.json\"",
    ));
    assert!(
        returnable
            .as_ref()
            .is_err_and(|why| why.contains("must not be returnable")),
        "{returnable:?}"
    );
    for name in ["a/b", "..", ""] {
        let nested = ExecutionNodeSettings::parse(&node_text(&format!(
            "resumable = true\ncheckpoint_output = \"{name}\""
        )));
        assert!(nested.is_err(), "{name:?} is not one path component");
    }
}

#[test]
fn a_receipt_without_a_checkpoint_signs_the_same_bytes_as_before() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let key = "job-c1-8/chunk-0";
    fixture.run_resumable(&jobs, key);
    let running = known(jobs.find(fixture.issuer, key));
    assert_eq!(running.checkpoint, None);

    // The codec writes each field's name: a receipt without a checkpoint has
    // no such field at all, so it encodes, and signs, as before the field.
    let plain = oneiron_organ_protocol::to_vec(&running).expect("the receipt encodes");
    assert!(contains(&plain, b"seq"), "the codec writes field names");
    assert!(!contains(&plain, b"checkpoint"));
    let decoded: JobReceipt = oneiron_organ_protocol::from_slice(&plain).expect("decodes");
    assert_eq!(decoded, running);

    let mut with = running.clone();
    with.checkpoint = Some(CheckpointRecord {
        label: "step-1".to_owned(),
        sha256: expected_digest(STEP_100),
        bytes: total_bytes(STEP_100),
        files: 2,
        saved_at_ms: NOW_MS,
    });
    let carried = oneiron_organ_protocol::to_vec(&with).expect("the receipt encodes");
    assert!(contains(&carried, b"checkpoint"));
    let decoded: JobReceipt = oneiron_organ_protocol::from_slice(&carried).expect("decodes");
    assert_eq!(decoded, with);
}

#[test]
fn a_restart_rebuilds_the_keys_checkpoint_from_the_journal() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let key = "job-c1-9/chunk-0";
    let out = fixture.run_resumable(&jobs, key);
    write_checkpoint(&out, "step-100", STEP_100);
    publish(&out, "step-100");
    let recorded = fixture.scan_until_label(&jobs, key, "step-100");

    // An engine restart: the same journal, the same checkpoint.
    drop(jobs);
    let jobs = reopen(&fixture);
    let again = known(jobs.find(fixture.issuer, key));
    assert_eq!(again.state, JobState::Running);
    assert_eq!(again.checkpoint.as_ref(), Some(&recorded));
    assert_eq!(
        entry(&jobs, key).and_then(|entry| entry.checkpoint),
        Some(recorded)
    );
}
