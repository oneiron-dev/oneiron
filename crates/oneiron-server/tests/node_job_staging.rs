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
//! mirror, so a node that fetched would find it. Review round 1 adds: a
//! mirror that borrows objects from another repository is refused, the
//! mirror's own configuration and attributes change nothing in the export,
//! a work directory other accounts may write in is refused, and a staged
//! key that does not launch keeps no checkout. Review round 2 adds: a
//! mirror whose object directory is a link into another store is refused,
//! the commit's own `export-subst` and `export-ignore` change nothing in the
//! checkout, a work directory beneath a directory others may write in is
//! not made, a work directory reached through the engine's own link stages,
//! and the unstage test waits for a completed staging first.
//!
//! The read-only work directory rule tests cover foreign owners, open and
//! sticky ancestors, and missing components.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --test node_job_staging`.
#![cfg(all(oneiron_test_support, unix))]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::job_workload::{DeviceClaim, DeviceKind, Sharing};
use oneiron_server::gpu_execution_node::jobs::staging::{
    CHECKOUT_DIR_NAME, GIT_VIEW_DIR_NAME, WorkDirAccess, WorkDirFault, WorkDirUnsafe,
    WorkDirVerdict, work_dir_verdict, work_dir_verdict_for,
};
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
const NOTES: &[u8] = b"notes the mirror's filter would rewrite\n";
const SUBST: &[u8] = b"commit $Format:%H$\n";

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// git with an empty environment but `PATH` (no inherited `GIT_DIR` or
/// `GIT_WORK_TREE`), no system or global configuration, and a fixed author.
fn git(dir: &Path, args: &[&str]) -> std::process::Output {
    let mut command = Command::new("git");
    command.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    command
        .current_dir(dir)
        .env("LC_ALL", "C")
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
    /// The contract is a file again (v1), and `.gitattributes` gives
    /// `notes.txt` the filter driver `marker`, `subst.txt` `export-subst`
    /// and `ignored.txt` `export-ignore`.
    filtered: String,
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

        std::fs::remove_file(origin.join(CONTRACT)).expect("contract link removed");
        std::fs::write(origin.join(CONTRACT), CONTRACT_V1).expect("contract v1 again");
        std::fs::write(origin.join("notes.txt"), NOTES).expect("notes");
        std::fs::write(origin.join("subst.txt"), SUBST).expect("subst");
        std::fs::write(origin.join("ignored.txt"), NOTES).expect("ignored");
        std::fs::write(
            origin.join(".gitattributes"),
            b"notes.txt filter=marker\nsubst.txt export-subst\nignored.txt export-ignore\n",
        )
        .expect("attributes");
        let filtered = commit("a file the filter driver marker would convert");

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
            filtered,
            origin_only,
        }
    }
}

/// The node's configuration as the stager reads it: one template at
/// [`DIGEST`], one mirror.
struct OneMirror {
    template: String,
    path: PathBuf,
}

impl TemplateMirrors for OneMirror {
    fn mirror(&self, template: &str, template_digest: &str) -> Result<PathBuf, StagingRefusal> {
        if template != self.template {
            Err(StagingRefusal::TemplateUnknown)
        } else if template_digest != DIGEST {
            Err(StagingRefusal::TemplateChanged)
        } else {
            Ok(self.path.clone())
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
    let node_dir = dir.path().join("node");
    let node = ScriptedNode::new(&node_dir, EntityId::now(), TEMPLATE, DIGEST, NOW_MS);
    // The work directory's ancestors are no other account's to write in,
    // whatever the test's umask made them.
    std::fs::create_dir_all(&node_dir).expect("node dir");
    std::fs::set_permissions(&node_dir, std::fs::Permissions::from_mode(0o755))
        .expect("node dir mode");
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
            continues: None,
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

    fn payload(&self, key: &str) -> PathBuf {
        JobKeyId::for_key(key).payload_dir(&self.node.paths.work_dir)
    }

    fn checkout(&self, key: &str) -> PathBuf {
        self.payload(key).join(CHECKOUT_DIR_NAME)
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

#[test]
fn a_mirror_that_borrows_objects_from_another_repository_refuses_the_launch() {
    let fixture = fixture();
    // The mirror's object directory names the origin's: the commit made in
    // the origin after the mirror reads through the mirror, and its
    // contract file is the pinned v1.
    let info = fixture.mirror.path.join("objects/info");
    std::fs::create_dir_all(&info).expect("objects/info");
    std::fs::write(
        info.join("alternates"),
        format!("{}\n", fixture.mirror.origin.join(".git/objects").display()),
    )
    .expect("alternates");
    assert!(
        holds(&fixture.mirror.path, &fixture.mirror.origin_only),
        "the mirror borrows the origin's objects"
    );
    let jobs = fixture.open();
    fixture.refused(
        &jobs,
        "job-24/borrowed",
        &pin(&fixture.mirror.origin_only, &sha256_hex(CONTRACT_V1)),
        StagingRefusal::MirrorNotSelfContained,
    );
    assert_eq!(fixture.node.units.total_starts(), 0);
    assert_eq!(fixture.node.devices.leases_given(), 0, "a card was held");
}

#[test]
fn the_mirrors_own_configuration_and_attributes_change_nothing_in_the_checkout() {
    let fixture = fixture();
    let root = fixture.mirror.path.parent().expect("temp root");
    let marker = root.join("filter-ran");
    // The mirror's configuration defines the filter driver the commit's
    // `.gitattributes` names; the driver leaves a marker when git runs it.
    git_ok(
        &fixture.mirror.path,
        &[
            "config",
            "filter.marker.smudge",
            &format!("touch '{}'; cat", marker.display()),
        ],
    );
    git_ok(
        &fixture.mirror.path,
        &["config", "filter.marker.required", "true"],
    );
    // The mirror's own attributes would leave the contract out of an export.
    let info = fixture.mirror.path.join("info");
    std::fs::create_dir_all(&info).expect("info");
    std::fs::write(info.join("attributes"), b"contract.json export-ignore\n").expect("attributes");

    let jobs = fixture.open();
    let key = "job-config/filtered";
    let launched = fixture.stage(
        &jobs,
        key,
        &pin(&fixture.mirror.filtered, &sha256_hex(CONTRACT_V1)),
    );
    assert!(
        matches!(launched.state, JobState::Launching | JobState::Running),
        "the key launched: {launched:?}"
    );
    assert!(!marker.exists(), "staging ran the mirror's filter driver");
    let checkout = fixture.checkout(key);
    assert_eq!(
        std::fs::read(checkout.join("notes.txt")).expect("notes"),
        NOTES
    );
    assert_eq!(
        std::fs::read(checkout.join(CONTRACT)).expect("contract"),
        CONTRACT_V1
    );
    // The commit's own attributes neither fill in `$Format:` text nor leave
    // a path out: the checkout is the commit's tree as committed.
    assert_eq!(
        std::fs::read(checkout.join("subst.txt")).expect("subst"),
        SUBST,
        "the export filled in the commit's $Format: text"
    );
    assert!(
        checkout.join("ignored.txt").is_file(),
        "the export left out a path the commit marks export-ignore"
    );
}

#[test]
fn a_mirror_whose_object_directory_links_into_another_store_refuses_the_launch() {
    let fixture = fixture();
    // The mirror's object directory is a link to the origin's, which holds
    // the commit made after the mirror and has no alternates of its own.
    let objects = fixture.mirror.path.join("objects");
    std::fs::rename(&objects, fixture.mirror.path.join("objects-moved")).expect("objects moved");
    std::os::unix::fs::symlink(fixture.mirror.origin.join(".git/objects"), &objects)
        .expect("objects link");
    assert!(
        holds(&fixture.mirror.path, &fixture.mirror.origin_only),
        "the mirror reads the origin's objects"
    );
    let jobs = fixture.open();
    fixture.refused(
        &jobs,
        "job-24/linked-objects",
        &pin(&fixture.mirror.origin_only, &sha256_hex(CONTRACT_V1)),
        StagingRefusal::MirrorNotSelfContained,
    );
    assert_eq!(fixture.node.units.total_starts(), 0);
    assert_eq!(fixture.node.devices.leases_given(), 0, "a card was held");
}

#[test]
fn a_work_directory_other_accounts_may_write_in_refuses_the_launch() {
    let fixture = fixture();
    let work_dir = &fixture.node.paths.work_dir;
    std::fs::create_dir_all(work_dir).expect("work dir");
    std::fs::set_permissions(work_dir, std::fs::Permissions::from_mode(0o777))
        .expect("work dir mode");
    let jobs = fixture.open();
    let key = "job-workdir/open";
    fixture.refused(
        &jobs,
        key,
        &pin(&fixture.mirror.good, &sha256_hex(CONTRACT_V1)),
        StagingRefusal::WorkDirUnsafe,
    );
    assert!(
        !fixture.payload(key).exists(),
        "staging made a payload directory in a work directory others may write in"
    );
    assert_eq!(fixture.node.devices.leases_given(), 0, "a card was held");
}

#[test]
fn a_work_directory_beneath_a_directory_others_may_write_in_is_not_made() {
    let fixture = fixture();
    let work_dir = &fixture.node.paths.work_dir;
    let parent = work_dir.parent().expect("the work directory's parent");
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o777)).expect("parent mode");
    assert!(!work_dir.exists(), "no work directory before staging");
    let jobs = fixture.open();
    fixture.refused(
        &jobs,
        "job-workdir/open-parent",
        &pin(&fixture.mirror.good, &sha256_hex(CONTRACT_V1)),
        StagingRefusal::WorkDirUnsafe,
    );
    assert!(
        !work_dir.exists(),
        "staging made the work directory beneath a directory others may write in"
    );
}

#[test]
fn a_work_directory_reached_through_the_engines_own_link_stages() {
    let fixture = fixture();
    let work_dir = &fixture.node.paths.work_dir;
    let real = work_dir.with_file_name("work-real");
    std::fs::create_dir(&real).expect("real work dir");
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755))
        .expect("real work dir mode");
    std::os::unix::fs::symlink("work-real", work_dir).expect("work dir link");
    let jobs = fixture.open();
    let key = "job-workdir/linked";
    let launched = fixture.stage(
        &jobs,
        key,
        &pin(&fixture.mirror.good, &sha256_hex(CONTRACT_V1)),
    );
    assert!(
        matches!(launched.state, JobState::Launching | JobState::Running),
        "the key launched: {launched:?}"
    );
    let staged = real
        .join(
            fixture
                .payload(key)
                .file_name()
                .expect("the payload's name"),
        )
        .join(CHECKOUT_DIR_NAME)
        .join(CONTRACT);
    assert_eq!(std::fs::read(staged).expect("contract"), CONTRACT_V1);
}

#[test]
fn the_work_dir_rule_names_an_ancestor_another_account_owns() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("resolved temp dir");
    let a = root.join("a");
    let work = a.join("work");
    make_work_dir_test_directory(&a, 0o755);
    make_work_dir_test_directory(&work, 0o755);
    let euid = rustix::process::geteuid().as_raw();
    let engine = if euid == 0 {
        std::os::unix::fs::chown(&a, Some(65534), Some(65534)).expect("give a to another account");
        0
    } else {
        euid + 1
    };
    let verdict = work_dir_verdict(&work, engine);
    let WorkDirVerdict::Unsafe(u) = verdict else {
        panic!("expected a foreign owner on the path: {verdict:?}");
    };
    assert!(
        matches!(u.fault, WorkDirFault::ForeignOwner { uid } if uid != 0 && uid != engine),
        "expected a foreign owner: {u:?}"
    );
    assert!(work.starts_with(&u.path), "not on the work path: {u:?}");
    if euid == 0 {
        assert_eq!(
            u.path, a,
            "the temp root and its ancestors must pass for root"
        );
    }
}

#[test]
fn the_work_dir_rule_names_an_ancestor_others_may_rename_in() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("resolved temp dir");
    let open = root.join("open");
    let work = open.join("work");
    make_work_dir_test_directory(&open, 0o777);
    make_work_dir_test_directory(&work, 0o755);
    let euid = rustix::process::geteuid().as_raw();
    let verdict = work_dir_verdict(&work, euid);
    assert!(
        matches!(
            &verdict,
            WorkDirVerdict::Unsafe(WorkDirUnsafe {
                path,
                fault: WorkDirFault::OthersMayRename { mode },
            }) if path == &open && *mode & 0o022 != 0
        ),
        "expected the open ancestor to fail; the temp root and its ancestors must pass for uid {euid}: {verdict:?}"
    );
}

#[test]
fn a_sticky_ancestor_others_may_write_in_passes_the_work_dir_rule() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("resolved temp dir");
    let shared = root.join("shared");
    let work = shared.join("work");
    make_work_dir_test_directory(&shared, 0o1777);
    make_work_dir_test_directory(&work, 0o755);
    let euid = rustix::process::geteuid().as_raw();
    assert_eq!(
        work_dir_verdict(&work, euid),
        WorkDirVerdict::Passes(work),
        "expected the sticky ancestor to pass; the temp root and its ancestors must pass for uid {euid}"
    );
}

#[test]
fn a_missing_work_dir_reads_missing_and_the_rule_makes_nothing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("resolved temp dir");
    let a = root.join("a");
    let b = a.join("b");
    let work = b.join("work");
    make_work_dir_test_directory(&a, 0o755);
    let euid = rustix::process::geteuid().as_raw();
    assert_eq!(
        work_dir_verdict(&work, euid),
        WorkDirVerdict::Missing {
            first_missing: b.clone(),
            engine_may_make: true,
        },
        "expected the first missing component; the temp root and its ancestors must pass for uid {euid}"
    );
    assert!(
        !b.exists(),
        "the read-only rule made the first missing component"
    );
}

#[test]
fn the_work_dir_rule_judged_for_the_engine_takes_the_engines_file_access() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("resolved temp dir");
    let closed = root.join("closed");
    let work = closed.join("work");
    make_work_dir_test_directory(&closed, 0o700);
    make_work_dir_test_directory(&work, 0o755);
    let euid = rustix::process::geteuid().as_raw();
    let me = WorkDirAccess::this_process().expect("this process has an account");
    if euid != 0 {
        // Only root can take another account's file access.
        let other = WorkDirAccess {
            uid: euid + 1,
            gid: me.gid,
            groups: Vec::new(),
        };
        let why = work_dir_verdict_for(&work, &other)
            .expect_err("a process that is not root judges only for itself");
        assert!(why.contains("can take neither root's"), "{why}");
        assert_eq!(
            work_dir_verdict_for(&work, &me),
            Ok(work_dir_verdict(&work, euid)),
            "judged for its own account, the walk runs here"
        );
        return;
    }
    // As root: the temp root opens to every account, `closed` is root's
    // alone (0700), and the work directory inside it is the engine's.
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))
        .expect("open the temp root");
    std::os::unix::fs::chown(&work, Some(65534), Some(65534)).expect("give work to the engine");
    assert_eq!(
        work_dir_verdict(&work, 65534),
        WorkDirVerdict::Passes(work.clone()),
        "with root's own file access the chain passes; the temp root and its ancestors must pass for root"
    );
    let engine = WorkDirAccess {
        uid: 65534,
        gid: 65534,
        groups: Vec::new(),
    };
    let verdict =
        work_dir_verdict_for(&work, &engine).expect("root takes the engine's file access");
    let WorkDirVerdict::Unsafe(u) = verdict else {
        panic!(
            "the engine may not search {}: {verdict:?}",
            closed.display()
        );
    };
    assert!(
        matches!(&u.fault, WorkDirFault::Unreadable(why) if why.contains("ermission denied")),
        "expected the engine's lookup to be refused: {u:?}"
    );
    assert!(work.starts_with(&u.path), "not on the work path: {u:?}");
    assert_eq!(
        rustix::process::geteuid().as_raw(),
        0,
        "the judgement's thread took the engine's access, not the process"
    );
}

#[test]
fn an_engine_work_dir_the_engine_may_not_write_in_fails_the_rule() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("resolved temp dir");
    let ro = root.join("ro");
    let work = ro.join("work");
    make_work_dir_test_directory(&ro, 0o755);
    make_work_dir_test_directory(&work, 0o555);
    let me = WorkDirAccess::this_process().expect("this process's file access");
    let engine = if me.uid == 0 {
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))
            .expect("open the temp root");
        std::os::unix::fs::chown(&work, Some(65534), Some(65534)).expect("give work to the engine");
        assert_eq!(
            work_dir_verdict(&work, 65534),
            WorkDirVerdict::Passes(work.clone()),
            "with root's own file access the read-only work dir passes"
        );
        WorkDirAccess {
            uid: 65534,
            gid: 65534,
            groups: Vec::new(),
        }
    } else {
        me
    };
    assert_eq!(
        work_dir_verdict_for(&work, &engine),
        Ok(WorkDirVerdict::Unsafe(WorkDirUnsafe {
            path: work.clone(),
            fault: WorkDirFault::EngineMayNotWrite,
        })),
        "judged for the engine, its read-only work dir fails"
    );
    std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o755)).expect("restore work");
}

#[test]
fn a_missing_work_dir_the_engine_may_not_make_reads_missing_unmakeable() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("resolved temp dir");
    let shut = root.join("shut");
    let open = root.join("open");
    make_work_dir_test_directory(&shut, 0o555);
    make_work_dir_test_directory(&open, 0o755);
    let shut_work = shut.join("work");
    let open_work = open.join("work");
    let euid = rustix::process::geteuid().as_raw();
    let access = if euid != 0 {
        WorkDirAccess::this_process().expect("this process has an account")
    } else {
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))
            .expect("open the temp root");
        std::os::unix::fs::chown(&shut, Some(65534), Some(65534)).expect("give shut to the engine");
        std::os::unix::fs::chown(&open, Some(65534), Some(65534)).expect("give open to the engine");
        WorkDirAccess {
            uid: 65534,
            gid: 65534,
            groups: Vec::new(),
        }
    };
    assert_eq!(
        work_dir_verdict_for(&shut_work, &access),
        Ok(WorkDirVerdict::Missing {
            first_missing: shut_work.clone(),
            engine_may_make: false,
        }),
        "the engine may not make its work dir in a read-only parent"
    );
    assert_eq!(
        work_dir_verdict_for(&open_work, &access),
        Ok(WorkDirVerdict::Missing {
            first_missing: open_work.clone(),
            engine_may_make: true,
        }),
        "the engine may make its work dir in a writable parent"
    );
    assert!(
        !shut_work.exists() && !open_work.exists(),
        "the read-only rule made a missing work directory"
    );
    std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o755)).expect("restore shut");
}

#[test]
fn a_caller_with_the_engines_uid_but_other_groups_does_not_judge_for_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("resolved temp dir");
    let ok = root.join("ok");
    let work = ok.join("work");
    make_work_dir_test_directory(&ok, 0o755);
    make_work_dir_test_directory(&work, 0o755);
    let me = WorkDirAccess::this_process().expect("this process's file access");
    let other_gid = me.groups.iter().copied().fold(me.gid, u32::max) + 1;
    let mut extra_group = me.clone();
    extra_group.groups.push(other_gid);
    if me.uid == 0 {
        work_dir_verdict_for(&work, &extra_group)
            .expect("root judges for its own uid with other groups on a thread");
        assert_eq!(rustix::process::geteuid().as_raw(), 0);
        assert_eq!(
            WorkDirAccess::this_process().expect("this process's file access after judgement"),
            me,
            "the judgement's thread took the groups, not the process"
        );
        return;
    }
    let mut other_primary = me.clone();
    other_primary.gid = other_gid;
    let why = work_dir_verdict_for(&work, &other_primary)
        .expect_err("another primary gid is not this process's file access");
    assert!(why.contains("but not its file access"), "{why}");
    let why = work_dir_verdict_for(&work, &extra_group)
        .expect_err("an extra group is not this process's file access");
    assert!(why.contains("but not its file access"), "{why}");
    let mut same_set = me.clone();
    same_set.groups.reverse();
    same_set.groups.push(me.gid);
    assert_eq!(
        work_dir_verdict_for(&work, &same_set),
        Ok(work_dir_verdict(&work, me.uid)),
        "the same group set in another order judges here"
    );
}

fn make_work_dir_test_directory(path: &Path, mode: u32) {
    std::fs::create_dir(path).expect("make test directory");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .expect("test directory mode");
}

#[test]
fn a_staged_key_that_does_not_launch_keeps_no_checkout() {
    let fixture = fixture();
    // The node's fold never reaches the submit's heads, so a key that staged
    // waits for them until the staging limit, and the launch is refused.
    fixture.node.admission.set_staging_limit_secs(8);
    fixture.node.authority.set_stale(true);
    let jobs = fixture.open();
    let key = "job-unstaged/stale";
    let pin = pin(&fixture.mirror.good, &sha256_hex(CONTRACT_V1));
    assert_eq!(
        receipt(jobs.reserve(fixture.issuer, fixture.reserve(key, &pin))).state,
        JobState::Held
    );
    assert_eq!(
        receipt(jobs.submit(fixture.issuer, fixture.submit(key, &pin))).state,
        JobState::Accepted
    );
    // Staging completed: its git view is gone (a staging that fails removes
    // the checkout first) and the checkout holds the contract, while the key
    // still waits.
    let checkout = fixture.checkout(key);
    let view = fixture.payload(key).join(GIT_VIEW_DIR_NAME);
    let staged = wait_for(&jobs, key, |entry| {
        entry.state == JobState::Ended || (!view.exists() && checkout.join(CONTRACT).is_file())
    });
    assert_eq!(
        staged.state,
        JobState::Staging,
        "the key waits after a completed staging: {staged:?}"
    );
    let ended = wait_for(&jobs, key, |entry| entry.state == JobState::Ended);
    assert!(
        matches!(
            &ended.end,
            Some(JobEnd::LaunchRefused { reason })
                if reason == "authority_stale" || reason == "staging_limit"
        ),
        "the key ended before its launch: {ended:?}"
    );
    assert_eq!(fixture.node.units.starts(key), 0);
    assert!(
        !fixture.checkout(key).exists(),
        "a key that did not launch left its checkout"
    );
}
