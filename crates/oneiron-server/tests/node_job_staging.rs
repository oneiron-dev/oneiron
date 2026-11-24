//! Pass 33 row R3c (`33-exec-node/DESIGN.md` section 7.4, tests T24 and
//! T25): staging. A key's code comes only from its template's host-local
//! mirror at the pinned commit, and its contract file must hash to the
//! pinned digest, or the key ends as `LaunchRefused` with no unit started
//! and no device held.
//!
//! The node is R3a's scripted node (unit manager, devices, clock) with the
//! real [`MirrorStager`] in place of the scripted stager, over a real bare
//! mirror that `git clone --mirror` makes in a temporary directory. The
//! mirror's origin is a local path that holds one more commit than the
//! mirror, so a node that fetched would find it.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --test node_job_staging`.
#![cfg(all(oneiron_test_support, unix))]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron_server::gpu_execution_node::jobs::staging::CHECKOUT_DIR_NAME;
use oneiron_server::gpu_execution_node::jobs::{
    JobKeyId, MirrorStager, NodeJobs, NodeKey, StagingRefusal, TemplateMirrors,
};
use oneiron_server::gpu_execution_node::wire::{
    HoldRef, JobAnswer, JobEnd, JobReceipt, JobReserve, JobState, JobSubmit, NetworkMode,
    OutputDecl, ResourceRequest, ScopeKind, SignedJobSubmit, SlotSelector, Starter, WorkloadPin,
};
use oneiron_server::test_doors::node_jobs::{ScriptedNode, ScriptedSigner};
use sha2::{Digest, Sha256};

const TEMPLATE: &str = "open-models";
const DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const NOW_MS: u64 = 1_800_000_000_000;
const WAIT: Duration = Duration::from_secs(20);
const ENTRY: &str = "tools/units/run.sh";
const CONTRACT: &str = "contract.json";
const CONTRACT_V1: &[u8] =
    b"{\"arm\":\"comparator\",\"forecast\":0.61,\"inputs\":{\"weights\":\"sha256:aa\"}}\n";
const CONTRACT_V2: &[u8] =
    b"{\"arm\":\"comparator\",\"forecast\":0.75,\"inputs\":{\"weights\":\"sha256:aa\"}}\n";
const RUN_SH: &[u8] = b"#!/usr/bin/bash\nset -eu\necho staged\n";

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// git with no system or global configuration and a fixed author.
fn git(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args([
            "-c",
            "user.name=Oneiron Test",
            "-c",
            "user.email=test@oneiron.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .output()
        .expect("git runs")
}

fn git_ok(dir: &Path, args: &[&str]) -> String {
    let output = git(dir, args);
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git prints text")
        .trim()
        .to_owned()
}

/// Whether the repository at `git_dir` holds `commit`.
fn holds(git_dir: &Path, commit: &str) -> bool {
    let target = format!("{commit}^{{commit}}");
    let dir = git_dir.to_str().expect("a UTF-8 temp path");
    git(
        Path::new("/"),
        &["--git-dir", dir, "cat-file", "-e", &target],
    )
    .status
    .success()
}

/// The template's history, in one line of commits, and its mirror.
struct Mirror {
    origin: PathBuf,
    path: PathBuf,
    /// The contract (v1) and the entry script.
    good: String,
    /// The contract file changed to v2.
    changed: String,
    /// The contract is a symbolic link to `real.json`, which holds v1.
    linked: String,
    /// Adds a 3 MiB file.
    big: String,
    /// Made in the origin after the mirror was cloned.
    origin_only: String,
}

impl Mirror {
    fn new(root: &Path) -> Self {
        let origin = root.join("origin");
        std::fs::create_dir_all(origin.join("tools/units")).expect("origin dir");
        git_ok(&origin, &["init", "-q"]);
        let commit = |message: &str| {
            git_ok(&origin, &["add", "-A"]);
            git_ok(&origin, &["commit", "-q", "-m", message]);
            git_ok(&origin, &["rev-parse", "HEAD"])
        };

        std::fs::write(origin.join(CONTRACT), CONTRACT_V1).expect("contract");
        std::fs::write(origin.join(ENTRY), RUN_SH).expect("entry");
        std::fs::set_permissions(origin.join(ENTRY), std::fs::Permissions::from_mode(0o755))
            .expect("entry mode");
        let good = commit("the arm and its contract");

        std::fs::write(origin.join(CONTRACT), CONTRACT_V2).expect("contract v2");
        let changed = commit("the contract changed");

        std::fs::remove_file(origin.join(CONTRACT)).expect("contract removed");
        std::fs::write(origin.join("real.json"), CONTRACT_V1).expect("real.json");
        std::os::unix::fs::symlink("real.json", origin.join(CONTRACT)).expect("contract link");
        let linked = commit("the contract is a link");

        std::fs::write(origin.join("weights.bin"), vec![7_u8; 3 * 1024 * 1024]).expect("big");
        let big = commit("a large file");

        let path = root.join("mirror.git");
        git_ok(
            root,
            &[
                "clone",
                "-q",
                "--mirror",
                origin.to_str().expect("a UTF-8 temp path"),
                path.to_str().expect("a UTF-8 temp path"),
            ],
        );

        std::fs::write(origin.join("later.txt"), b"after the mirror\n").expect("later");
        let origin_only = commit("after the mirror was made");

        Self {
            origin,
            path,
            good,
            changed,
            linked,
            big,
            origin_only,
        }
    }
}

/// The node's configuration as the stager reads it: one template, one
/// mirror.
struct OneMirror {
    template: String,
    path: PathBuf,
}

impl TemplateMirrors for OneMirror {
    fn mirror(&self, template: &str) -> Result<PathBuf, StagingRefusal> {
        if template == self.template {
            Ok(self.path.clone())
        } else {
            Err(StagingRefusal::TemplateUnknown)
        }
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    node: ScriptedNode,
    mirror: Mirror,
    issuer: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temp dir");
    let mirror = Mirror::new(dir.path());
    let node = ScriptedNode::new(
        &dir.path().join("node"),
        EntityId::now(),
        TEMPLATE,
        DIGEST,
        NOW_MS,
    );
    Fixture {
        _dir: dir,
        node,
        mirror,
        issuer: EntityId::now(),
    }
}

fn pin(commit: &str, contract_sha256: &str) -> WorkloadPin {
    WorkloadPin {
        template: TEMPLATE.to_owned(),
        template_digest: DIGEST.to_owned(),
        commit: commit.to_owned(),
        contract_sha256: contract_sha256.to_owned(),
        contract_path: CONTRACT.to_owned(),
        entry: ENTRY.to_owned(),
        args: vec!["seed=7".to_owned()],
        request: ResourceRequest {
            gpus: 1,
            vram_mib: 22 * 1024,
            memory_mib: 22 * 1024,
            disk_mib: 2 * 1024,
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
    /// The node's job service with the mirror stager in place of the
    /// scripted one.
    fn open(&self) -> NodeJobs {
        let mut parts = self.node.parts();
        parts.stager = Arc::new(MirrorStager::new(Arc::new(OneMirror {
            template: TEMPLATE.to_owned(),
            path: self.mirror.path.clone(),
        })));
        NodeJobs::open(self.node.paths.clone(), parts).expect("the node's job service opens")
    }

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
        };
        SignedJobSubmit::sign(submit, ScriptedSigner::new(self.issuer).as_ref())
            .expect("the issuer signs")
    }

    /// Reserves and submits `key`, and waits until its staging is over: the
    /// key launched, or it ended.
    fn stage(&self, jobs: &NodeJobs, key: &str, pin: &WorkloadPin) -> NodeKey {
        assert_eq!(
            receipt(jobs.reserve(self.issuer, self.reserve(key, pin))).state,
            JobState::Held
        );
        assert_eq!(
            receipt(jobs.submit(self.issuer, self.submit(key, pin))).state,
            JobState::Accepted
        );
        wait_for(jobs, key, |entry| {
            matches!(
                entry.state,
                JobState::Launching | JobState::Running | JobState::Ended
            )
        })
    }

    fn checkout(&self, key: &str) -> PathBuf {
        JobKeyId::for_key(key)
            .payload_dir(&self.node.paths.work_dir)
            .join(CHECKOUT_DIR_NAME)
    }

    /// Stages `key` and checks that it ended as `LaunchRefused` for
    /// `refusal`, with no unit started and no checkout left.
    fn refused(&self, jobs: &NodeJobs, key: &str, pin: &WorkloadPin, refusal: StagingRefusal) {
        let ended = self.stage(jobs, key, pin);
        assert_eq!(ended.state, JobState::Ended, "key {key}");
        assert_eq!(
            ended.end,
            Some(JobEnd::LaunchRefused {
                reason: refusal.code().to_owned()
            }),
            "key {key}"
        );
        assert_eq!(self.node.units.starts(key), 0, "key {key} started a unit");
        assert!(
            !self.checkout(key).exists(),
            "key {key} left a checkout on the node"
        );
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
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(found) = entry(jobs, key)
            && done(&found)
        {
            return found;
        }
        assert!(
            Instant::now() < deadline,
            "key {key} did not reach the state: {:?}",
            entry(jobs, key)
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .expect("the path exists")
        .permissions()
        .mode()
        & 0o7777
}

#[test]
fn a_pinned_commit_and_its_contract_stage_the_checkout_and_launch() {
    let fixture = fixture();
    let jobs = fixture.open();
    let key = "job-staged/chunk-0";

    let launched = fixture.stage(
        &jobs,
        key,
        &pin(&fixture.mirror.good, &sha256_hex(CONTRACT_V1)),
    );
    assert!(
        matches!(launched.state, JobState::Launching | JobState::Running),
        "the key launched: {launched:?}"
    );
    assert_eq!(fixture.node.units.starts(key), 1);

    // The checkout is the commit: the contract and the entry, with their
    // modes, owned by the engine's account and not writable by others.
    let checkout = fixture.checkout(key);
    assert_eq!(
        std::fs::read(checkout.join(CONTRACT)).expect("contract"),
        CONTRACT_V1
    );
    assert_eq!(std::fs::read(checkout.join(ENTRY)).expect("entry"), RUN_SH);
    assert_eq!(mode(&checkout.join(ENTRY)), 0o755);
    assert_eq!(mode(&checkout.join(CONTRACT)), 0o644);
    assert_eq!(mode(&checkout), 0o755);
    assert_eq!(mode(&checkout.join("tools/units")), 0o755);
    assert!(!checkout.join("weights.bin").exists());

    // Staging copied nothing else: the payload directory holds the checkout
    // only, and host data stays where the template names it.
    let payload = checkout.parent().expect("payload dir");
    let names: Vec<String> = std::fs::read_dir(payload)
        .expect("payload dir reads")
        .map(|found| {
            found
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(names, vec![CHECKOUT_DIR_NAME.to_owned()]);
}

#[test]
fn a_commit_missing_from_the_mirror_refuses_the_launch() {
    let fixture = fixture();
    let jobs = fixture.open();
    let contract = sha256_hex(CONTRACT_V1);

    // A commit the mirror's origin holds and the mirror does not: the node
    // never fetches it.
    let origin_only = &fixture.mirror.origin_only;
    assert!(holds(&fixture.mirror.origin.join(".git"), origin_only));
    fixture.refused(
        &jobs,
        "job-24/origin-only",
        &pin(origin_only, &contract),
        StagingRefusal::CommitMissing,
    );
    assert!(
        !holds(&fixture.mirror.path, origin_only),
        "staging fetched into the mirror"
    );

    // A commit no repository holds.
    fixture.refused(
        &jobs,
        "job-24/never",
        &pin(&"0123456789abcdef".repeat(5)[..40], &contract),
        StagingRefusal::CommitMissing,
    );

    // A commit id git could read as something else is refused before git
    // runs.
    fixture.refused(
        &jobs,
        "job-24/expression",
        &pin(
            &format!("{}^{{tree}}", &fixture.mirror.good[..30]),
            &contract,
        ),
        StagingRefusal::CommitInvalid,
    );

    assert_eq!(fixture.node.units.total_starts(), 0);
    assert_eq!(fixture.node.devices.leases_given(), 0, "a card was held");
}

#[test]
fn a_changed_contract_file_refuses_the_launch() {
    let fixture = fixture();
    let jobs = fixture.open();
    let pinned = sha256_hex(CONTRACT_V1);

    // The pin froze v1; the commit's contract file is v2.
    fixture.refused(
        &jobs,
        "job-25/changed",
        &pin(&fixture.mirror.changed, &pinned),
        StagingRefusal::ContractChanged,
    );

    // A symbolic link to a file with the pinned bytes is not the contract.
    fixture.refused(
        &jobs,
        "job-25/linked",
        &pin(&fixture.mirror.linked, &pinned),
        StagingRefusal::ContractNotAFile,
    );
    assert_eq!(fixture.node.units.total_starts(), 0);
    assert_eq!(fixture.node.devices.leases_given(), 0, "a card was held");

    // The same commit pinned with its own contract's digest launches.
    let repinned = fixture.stage(
        &jobs,
        "job-25/repinned",
        &pin(&fixture.mirror.changed, &sha256_hex(CONTRACT_V2)),
    );
    assert!(
        matches!(repinned.state, JobState::Launching | JobState::Running),
        "the repinned key launched: {repinned:?}"
    );
    assert_eq!(fixture.node.units.total_starts(), 1);
}

#[test]
fn a_checkout_larger_than_the_disk_request_refuses_the_launch() {
    let fixture = fixture();
    let jobs = fixture.open();
    let mut small = pin(&fixture.mirror.big, &sha256_hex(CONTRACT_V1));
    small.request.disk_mib = 2;
    fixture.refused(
        &jobs,
        "job-disk/small",
        &small,
        StagingRefusal::CheckoutOverDiskRequest,
    );
    assert_eq!(fixture.node.units.total_starts(), 0);
}

#[test]
fn a_contract_path_outside_the_checkout_refuses_the_launch() {
    let fixture = fixture();
    let jobs = fixture.open();
    let mut escaping = pin(&fixture.mirror.good, &sha256_hex(CONTRACT_V1));
    escaping.contract_path = "../mirror.git/config".to_owned();
    fixture.refused(
        &jobs,
        "job-path/escaping",
        &escaping,
        StagingRefusal::ContractPathInvalid,
    );
    let mut absent = pin(&fixture.mirror.good, &sha256_hex(CONTRACT_V1));
    absent.contract_path = "contracts/absent.json".to_owned();
    fixture.refused(
        &jobs,
        "job-path/absent",
        &absent,
        StagingRefusal::ContractMissing,
    );
    assert_eq!(fixture.node.units.total_starts(), 0);
}
