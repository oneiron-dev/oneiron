//! Pass 33 row R3b, the engine's half (`33-exec-node/DESIGN.md` 7.9 and
//! T23d; FIX EXEC-NODE-DISK-CHECK-UNBUILT): the disk check measures each
//! launched key's payload and ends one over its disk request as
//! `DiskLimit`; the measure counts what each file holds on disk, once, and
//! never through a link, and a payload it cannot measure within its bounds
//! passes every request; and an end step that saw a process of the unit
//! left quarantines the device (T23d: a kill that cannot be confirmed is
//! never an empty device). Against R3a's scripted unit manager, device
//! table and clock; the scripted units keep the trait's default measure,
//! the engine's own walk of the payload directory. No privilege and no
//! network.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --test node_job_unit_limits`.
#![cfg(all(oneiron_test_support, unix))]

use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::job_workload::{DeviceClaim, DeviceKind, Sharing};
use oneiron_server::gpu_execution_node::jobs::payload_usage::{
    PAYLOAD_DEPTH_MAX_DEFAULT, measure_payload, measure_payload_within,
};
use oneiron_server::gpu_execution_node::jobs::{
    EndingCause, JobKeyId, NodeGate, NodeJobs, NodeKey, PayloadUsage, PayloadWalkBounds,
};
use oneiron_server::gpu_execution_node::wire::{
    DeviceRelease, HoldRef, JobAnswer, JobEnd, JobReceipt, JobReserve, JobState, JobSubmit,
    NetworkMode, OutputDecl, ResourceRequest, ScopeKind, SignedJobSubmit, SlotSelector, Starter,
    WorkloadPin,
};
use oneiron_server::test_doors::node_jobs::{ScriptedNode, ScriptedSigner};

const TEMPLATE: &str = "open-models";
const DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const DEVICE: &str = "GPU-scripted-0";
const NOW_MS: u64 = 1_800_000_000_000;
const WAIT: Duration = Duration::from_secs(10);
const MIB: u64 = 1024 * 1024;
/// The pin's disk request, in MiB.
const DISK_MIB: u64 = 4;

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
            disk_mib: DISK_MIB,
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
    fn out_dir(&self, key: &str) -> PathBuf {
        let out = JobKeyId::for_key(key)
            .payload_dir(&self.node.paths.work_dir)
            .join("out");
        std::fs::create_dir_all(&out).expect("out dir");
        out
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

/// Writes `bytes` bytes that no filesystem compresses to `path`, synced, so
/// they are on disk when the walk counts them.
fn write_bytes(path: &Path, bytes: u64) {
    let length = usize::try_from(bytes).expect("a test size");
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15 ^ bytes;
    let mut data = Vec::with_capacity(length);
    while data.len() < length {
        // xorshift64: no run a filesystem could compress.
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        data.extend_from_slice(&state.to_le_bytes());
    }
    data.truncate(length);
    let mut file = std::fs::File::create(path).expect("payload file");
    file.write_all(&data).expect("payload bytes");
    file.sync_all().expect("payload sync");
}

/// `levels` directories, each in the one before, beneath `dir`.
fn nest(dir: &Path, levels: usize) -> PathBuf {
    let mut path = dir.to_path_buf();
    for _ in 0..levels {
        path.push("d");
    }
    std::fs::create_dir_all(&path).expect("nested directories");
    path
}

/// FIX EXEC-NODE-DISK-CHECK-UNBUILT (design 7.9): a running key whose
/// payload stays within its disk request runs on; once the payload passes
/// it, the disk check moves the key to `Ending { DiskLimit }` and stops its
/// unit, and the key ends as `DiskLimit`. A key that has begun to end is
/// not measured again.
#[test]
fn a_payload_over_its_disk_request_ends_as_disk_limit() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let key = "job-disk/chunk-0";
    let within = "job-disk/chunk-within";
    fixture.run(&jobs, key);
    let out = fixture.out_dir(key);

    write_bytes(&out.join("part-1.bin"), MIB);
    assert_eq!(jobs.check_payload_disk(), Vec::<String>::new());
    assert_eq!(
        entry(&jobs, key).expect("the key").state,
        JobState::Running,
        "a payload within its request runs on"
    );

    write_bytes(&out.join("part-2.bin"), DISK_MIB * MIB);
    assert_eq!(jobs.check_payload_disk(), vec![key.to_owned()]);
    let ending = entry(&jobs, key).expect("the key");
    assert_eq!(ending.ending_cause, Some(EndingCause::DiskLimit));
    assert_ne!(ending.state, JobState::Running);
    assert_eq!(jobs.check_payload_disk(), Vec::<String>::new());

    // The stop ended the unit; the end handling names the end.
    jobs.tick();
    let ended = wait_for(&jobs, key, NodeKey::is_ended);
    assert_eq!(ended.end, Some(JobEnd::DiskLimit));

    // Another key on the same node, within its request, is not touched.
    jobs.tick();
    wait_for(&jobs, key, |entry| {
        matches!(entry.release, DeviceRelease::Confirmed { .. })
    });
    fixture.run(&jobs, within);
    write_bytes(&fixture.out_dir(within).join("part.bin"), MIB);
    assert_eq!(jobs.check_payload_disk(), Vec::<String>::new());
    assert_eq!(
        entry(&jobs, within).expect("the key").state,
        JobState::Running
    );
}

/// The measure counts the blocks each file holds on disk: a sparse file
/// what it holds and not its length, a file with two names once, and a
/// link never as what it points to. It stops once it has counted past the
/// bound it was given, and a payload directory that does not exist yet
/// holds nothing. Every number is the temp file system's own (review r13
/// R13-16): the checks hold on one that keeps no hole too, and the case
/// covers the walk rather than proving a change (the base counted this
/// fixture the same way).
#[test]
fn a_payload_is_counted_on_disk_once_and_never_through_a_link() {
    let dir = tempfile::tempdir().expect("temp dir");
    let payload = dir.path().join("payload");
    let out = payload.join("out");
    std::fs::create_dir_all(&out).expect("out dir");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&outside).expect("outside dir");
    write_bytes(&outside.join("big.bin"), 8 * MIB);

    write_bytes(&out.join("data.bin"), MIB);
    std::fs::hard_link(out.join("data.bin"), out.join("same-data.bin")).expect("hard link");
    std::os::unix::fs::symlink(&outside, out.join("to-outside")).expect("dir link");
    std::os::unix::fs::symlink(outside.join("big.bin"), out.join("to-big.bin")).expect("file link");
    let sparse = std::fs::File::create(out.join("sparse.bin")).expect("sparse file");
    sparse.set_len(64 * MIB).expect("sparse length");
    drop(sparse);

    // What the filesystem itself says each entry holds, each file once
    // (review r12 R12-12: no assumption about block sizes).
    let held = [
        payload.clone(),
        out.clone(),
        out.join("data.bin"),
        out.join("to-outside"),
        out.join("to-big.bin"),
        out.join("sparse.bin"),
    ]
    .iter()
    .map(|path| std::fs::symlink_metadata(path).expect("entry").blocks() * 512)
    .sum::<u64>();
    let blocks_of = |path: &Path| std::fs::metadata(path).expect("entry").blocks() * 512;
    let data_blocks = blocks_of(&out.join("data.bin"));
    let sparse_blocks = blocks_of(&out.join("sparse.bin"));
    let outside_blocks = blocks_of(&outside.join("big.bin"));
    assert!(data_blocks > 0, "the synced data holds blocks");
    match measure_payload(&payload, u64::MAX).expect("measured") {
        PayloadUsage::Measured { bytes } => {
            assert_eq!(
                bytes, held,
                "each entry's blocks once, the hard link's file once, no link followed"
            );
            assert!(bytes >= data_blocks, "the data's blocks: {bytes}");
            assert!(
                bytes < held + data_blocks.min(outside_blocks),
                "neither the data twice nor the link's target: {bytes}"
            );
            // A file system that keeps the hole: the sparse length is not
            // counted. One that keeps none has the equality above alone.
            if sparse_blocks < 64 * MIB {
                assert!(
                    bytes < held - sparse_blocks + 64 * MIB,
                    "not the sparse length: {bytes}"
                );
            }
        }
        other => panic!("expected a measure, got {other:?}"),
    }
    match measure_payload(&payload, data_blocks / 2).expect("measured") {
        PayloadUsage::Past { bytes } => assert!(bytes > data_blocks / 2, "{bytes}"),
        other => panic!("expected a walk stopped past its bound, got {other:?}"),
    }
    assert!(
        PayloadUsage::Past { bytes: MIB }.passes(MIB / 2),
        "a walk stopped past the request passes it"
    );
    assert_eq!(
        measure_payload(&dir.path().join("not-yet"), 0).expect("measured"),
        PayloadUsage::Measured { bytes: 0 }
    );
    // The payload directory itself is never taken through a link.
    std::os::unix::fs::symlink(&outside, dir.path().join("payload-link")).expect("link");
    assert!(measure_payload(&dir.path().join("payload-link"), u64::MAX).is_err());

    // The control socket's line form reads back as it was written.
    for usage in [
        PayloadUsage::Measured { bytes: 7 },
        PayloadUsage::Past { bytes: u64::MAX },
        PayloadUsage::Unmeasurable {
            why: "more than 10 entries".to_owned(),
        },
    ] {
        assert_eq!(PayloadUsage::parse(&usage.render()), Some(usage));
    }
    for bad in [
        "bytes",
        "bytes ",
        "bytes -1",
        "bytes 1 2",
        "past x",
        "unmeasurable",
        "ok 5",
    ] {
        assert_eq!(PayloadUsage::parse(bad), None, "{bad:?}");
    }
}

/// A payload deeper than the walk enters, or with more entries than it
/// counts, cannot be measured, and passes every request: the node cannot
/// show it is within. The disk check walks within the node file's bounds
/// (`payload_entries_max`, `payload_depth_max`), and ends a running key
/// whose payload is past them as `DiskLimit`, whatever its bytes.
#[test]
fn a_payload_too_deep_or_too_wide_to_measure_counts_as_over_its_request() {
    let depth = usize::try_from(PAYLOAD_DEPTH_MAX_DEFAULT).expect("a depth");
    let dir = tempfile::tempdir().expect("temp dir");
    let deep_enough = dir.path().join("deep-enough");
    nest(&deep_enough, depth);
    assert!(
        matches!(
            measure_payload(&deep_enough, u64::MAX).expect("measured"),
            PayloadUsage::Measured { .. }
        ),
        "{depth} levels are measured"
    );
    let too_deep = dir.path().join("too-deep");
    nest(&too_deep, depth + 1);
    let usage = measure_payload(&too_deep, u64::MAX).expect("measured");
    assert!(
        matches!(usage, PayloadUsage::Unmeasurable { .. }),
        "{usage:?}"
    );
    assert!(usage.passes(u64::MAX));

    let wide = dir.path().join("wide");
    std::fs::create_dir_all(&wide).expect("wide dir");
    for name in 0..10 {
        std::fs::File::create(wide.join(format!("empty-{name}"))).expect("empty file");
    }
    let bounds = PayloadWalkBounds {
        entries_max: 10,
        ..PayloadWalkBounds::default()
    };
    // The directory and its ten files are eleven entries.
    let usage = measure_payload_within(&wide, u64::MAX, &bounds).expect("measured");
    assert!(
        matches!(usage, PayloadUsage::Unmeasurable { .. }),
        "{usage:?}"
    );
    let bounds = PayloadWalkBounds {
        entries_max: 11,
        ..PayloadWalkBounds::default()
    };
    assert!(matches!(
        measure_payload_within(&wide, u64::MAX, &bounds).expect("measured"),
        PayloadUsage::Measured { .. }
    ));

    // The node's bounds: twenty empty files are within the default ones,
    // and past ten entries the key ends.
    let fixture = fixture();
    let jobs = fixture.node.open();
    let wide_key = "job-disk-wide/chunk-0";
    fixture.run(&jobs, wide_key);
    let out = fixture.out_dir(wide_key);
    for name in 0..20 {
        std::fs::File::create(out.join(format!("empty-{name}"))).expect("empty file");
    }
    assert_eq!(jobs.check_payload_disk(), Vec::<String>::new());
    fixture.node.admission.set_payload_walk(PayloadWalkBounds {
        entries_max: 10,
        ..PayloadWalkBounds::default()
    });
    assert_eq!(jobs.check_payload_disk(), vec![wide_key.to_owned()]);
    jobs.tick();
    let ended = wait_for(&jobs, wide_key, NodeKey::is_ended);
    assert_eq!(ended.end, Some(JobEnd::DiskLimit));
    fixture
        .node
        .admission
        .set_payload_walk(PayloadWalkBounds::default());
    jobs.tick();
    wait_for(&jobs, wide_key, |entry| {
        matches!(entry.release, DeviceRelease::Confirmed { .. })
    });

    // A payload deeper than the default bound ends the next key.
    let deep_key = "job-disk-deep/chunk-0";
    fixture.run(&jobs, deep_key);
    nest(&fixture.out_dir(deep_key), depth);
    assert_eq!(jobs.check_payload_disk(), vec![deep_key.to_owned()]);
    jobs.tick();
    let ended = wait_for(&jobs, deep_key, NodeKey::is_ended);
    assert_eq!(ended.end, Some(JobEnd::DiskLimit));
}

/// T23d, the engine's half (coverage of R3a's end handling, which this PR
/// does not change: it passes on the base too; review r12 R12-11): the end
/// step ran and a process of the unit was left. The kill is not confirmed: the key stays `Ending`, never ended,
/// and its device is quarantined, so no reserve takes it, also after an
/// engine restart. A host reset ends the key as `Lost`, and only then a
/// clean probe gives the device back.
#[test]
fn a_kill_that_cannot_be_confirmed_quarantines_the_device() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    let key = "job-t23d/chunk-0";
    fixture.run(&jobs, key);

    fixture.node.units.exit_with_leftover(key);
    jobs.tick();
    let held = wait_for(&jobs, key, |entry| {
        matches!(entry.release, DeviceRelease::Unconfirmed { .. })
    });
    assert_eq!(held.state, JobState::Ending, "a process was left: no end");
    assert_eq!(held.end, None);
    assert!(fixture.node.devices.quarantined(DEVICE).is_some());
    let refused = receipt(jobs.reserve(fixture.issuer, fixture.reserve("job-t23d/chunk-1")));
    assert!(
        matches!(&refused.end, Some(JobEnd::Refused { reason }) if reason == "device_unavailable: claim 0"),
        "{:?}",
        refused.end
    );

    // More ticks settle nothing while the process is left.
    jobs.tick();
    jobs.tick();
    let still = entry(&jobs, key).expect("the key");
    assert_eq!(still.state, JobState::Ending);
    assert!(matches!(still.release, DeviceRelease::Unconfirmed { .. }));
    assert!(fixture.node.devices.quarantined(DEVICE).is_some());

    // An engine restart on the same boot: the quarantine is back before
    // the gate opens, and the key is still not ended.
    drop(jobs);
    fixture.node.devices.forget_quarantines();
    let jobs = fixture.node.open();
    assert_eq!(jobs.gate(), NodeGate::Open);
    assert!(fixture.node.devices.quarantined(DEVICE).is_some());
    assert_eq!(entry(&jobs, key).expect("the key").state, JobState::Ending);

    // A host reset: every unit is gone, the key ends as lost, and a clean
    // probe releases the device.
    drop(jobs);
    fixture.node.clock.reboot("boot-2");
    fixture.node.units.clear();
    fixture.node.devices.forget_quarantines();
    let jobs = fixture.node.open();
    let lost = wait_for(&jobs, key, NodeKey::is_ended);
    assert!(
        matches!(&lost.end, Some(JobEnd::Lost { reason, .. }) if reason == "host_reset"),
        "{:?}",
        lost.end
    );
    jobs.tick();
    wait_for(&jobs, key, |entry| {
        matches!(entry.release, DeviceRelease::Confirmed { .. })
    });
    assert_eq!(fixture.node.devices.quarantined(DEVICE), None);
}
