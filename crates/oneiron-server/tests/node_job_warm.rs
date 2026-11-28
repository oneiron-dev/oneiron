//! Pass 34 row P2 (`34-compute-general/DESIGN.md` sections 4.1, 7.1 gap 6 and 10): warm keys
//! on the node. The cache budget never removes a key that an open order lists or that a live
//! key may read; a listed input that is not on the node refuses the launch at zero seconds and
//! fetches nothing, while an absent cache is a cold start; an exit-0 attempt is a use of each
//! key it listed; `Node` reports each key with its presence; a cache path is removed only
//! directly inside a cache directory that is the engine's alone, and none while what is busy is
//! not known; no warm path may overlap a cache; and a template or a submit without warm keys
//! reads, hashes and signs as before.
//!
//! The node is R3a's scripted node (unit manager, devices, clock). The launch tests put the
//! real [`MirrorStager`] in place of the scripted stager, over a one-commit bare mirror that
//! `git clone --mirror` makes in a temporary directory.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --test node_job_warm`.
#![cfg(all(oneiron_test_support, unix))]

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::job_workload::{DeviceClaim, DeviceKind, Sharing};
use oneiron_server::gpu_execution_node::jobs::warm::{CacheBudget, WarmPath};
use oneiron_server::gpu_execution_node::jobs::{
    MirrorStager, NodeJobs, NodeKey, StagingRefusal, TemplateMirrors,
};
use oneiron_server::gpu_execution_node::node_settings::{
    CACHE_KEYS_MAX_MOST, EVICTED_DIR_NAME, ExecutionNodeSettings, NODE_WARM_KEYS_MAX,
    TEMPLATE_WARM_KEYS_MAX,
};
use oneiron_server::gpu_execution_node::wire::{
    HoldRef, JobAnswer, JobEnd, JobReceipt, JobReserve, JobState, JobSubmit, NetworkMode,
    OutputDecl, ResourceRequest, ScopeKind, SignedJobSubmit, SlotSelector, Starter, WarmKeyFact,
    WarmWanted, WorkloadPin,
};
use oneiron_server::test_doors::node_jobs::{ScriptedNode, ScriptedSigner};
use sha2::{Digest, Sha256};

const TEMPLATE: &str = "open-models";
const DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const NOW_MS: u64 = 1_800_000_000_000;
const WAIT: Duration = Duration::from_secs(20);
const ENTRY: &str = "tools/units/run.sh";
const CONTRACT: &str = "contract.json";
const CONTRACT_V1: &[u8] = b"{\"arm\":\"comparator\",\"inputs\":{\"weights\":\"sha256:aa\"}}\n";
const MIB: u64 = 1024 * 1024;

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// git with an empty environment but `PATH` (no inherited `GIT_DIR` or `GIT_WORK_TREE`), no
/// system or global configuration, and a fixed author, as `node_job_staging` runs it.
fn git_ok(dir: &Path, args: &[&str]) -> String {
    let mut command = Command::new("git");
    command.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    let output = command
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
        .expect("git runs");
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

/// A bare mirror of one commit that holds the contract and the entry; its id.
fn mirror(root: &Path) -> (PathBuf, String) {
    let origin = root.join("origin");
    std::fs::create_dir_all(origin.join("tools/units")).expect("origin dir");
    git_ok(&origin, &["init", "-q"]);
    std::fs::write(origin.join(CONTRACT), CONTRACT_V1).expect("contract");
    std::fs::write(origin.join(ENTRY), b"#!/usr/bin/bash\necho warm\n").expect("entry");
    std::fs::set_permissions(origin.join(ENTRY), std::fs::Permissions::from_mode(0o755))
        .expect("entry mode");
    git_ok(&origin, &["add", "-A"]);
    git_ok(&origin, &["commit", "-q", "-m", "the arm"]);
    let commit = git_ok(&origin, &["rev-parse", "HEAD"]);
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
    (path, commit)
}

/// The node's configuration as the stager reads it: one template at [`DIGEST`], its mirror,
/// and the warm keys the node's templates map.
struct WarmMirror {
    path: PathBuf,
    warm: BTreeMap<String, WarmPath>,
}

impl TemplateMirrors for WarmMirror {
    fn mirror(&self, template: &str, template_digest: &str) -> Result<PathBuf, StagingRefusal> {
        if template != TEMPLATE {
            Err(StagingRefusal::TemplateUnknown)
        } else if template_digest != DIGEST {
            Err(StagingRefusal::TemplateChanged)
        } else {
            Ok(self.path.clone())
        }
    }

    fn node_warm_paths(
        &self,
        template: &str,
        template_digest: &str,
    ) -> Result<BTreeMap<String, WarmPath>, StagingRefusal> {
        self.mirror(template, template_digest)?;
        Ok(self.warm.clone())
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    node: ScriptedNode,
    issuer: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temp dir");
    let node_dir = dir.path().join("node");
    let node = ScriptedNode::new(&node_dir, EntityId::now(), TEMPLATE, DIGEST, NOW_MS);
    std::fs::create_dir_all(&node_dir).expect("node dir");
    std::fs::set_permissions(&node_dir, std::fs::Permissions::from_mode(0o755))
        .expect("node dir mode");
    Fixture {
        dir,
        node,
        issuer: EntityId::now(),
    }
}

fn pin(commit: &str) -> WorkloadPin {
    WorkloadPin {
        template: TEMPLATE.to_owned(),
        template_digest: DIGEST.to_owned(),
        commit: commit.to_owned(),
        contract_sha256: sha256_hex(CONTRACT_V1),
        contract_path: CONTRACT.to_owned(),
        entry: ENTRY.to_owned(),
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
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The node's file: `open-models` maps `weights:aa` (an input) and the cache `target:h`;
    /// `builds` maps the caches `target:a`, `target:b` and `target:c`.
    fn settings(&self, cache_dir: &Path) -> ExecutionNodeSettings {
        self.settings_with(cache_dir, "")
    }

    /// [`Self::settings`] with `extra` (`, "<key>" = "<path>"` pairs) added to `open-models`'s
    /// map.
    fn settings_with(&self, cache_dir: &Path, extra: &str) -> ExecutionNodeSettings {
        let at = |name: &str| self.path(name).display().to_string();
        let cache = |name: &str| cache_dir.join(name).display().to_string();
        let text = format!(
            r#"
[execution_node]
state_dir = "{state}"
work_dir = "{work}"
cache_dir = "{cache_dir}"

[execution_node.templates.open-models]
repo = "/srv/mirror.git"
entries = ["{ENTRY}"]
interpreter = ["/usr/bin/bash"]
max_secs = 3600
memory_gib = 32
disk_gib = 10
warm = {{ "weights:aa" = "{weights}", "target:h" = "{h}"{extra} }}
caches = ["target:h"]

[execution_node.templates.builds]
repo = "/srv/builds.git"
entries = ["{ENTRY}"]
interpreter = ["/usr/bin/bash"]
max_secs = 3600
memory_gib = 32
disk_gib = 10
warm = {{ "target:a" = "{a}", "target:b" = "{b}", "target:c" = "{c}" }}
caches = ["target:a", "target:b", "target:c"]
"#,
            state = at("node/state"),
            work = at("node/work"),
            cache_dir = cache_dir.display(),
            weights = at("data/weights-aa"),
            h = cache("h"),
            a = cache("a"),
            b = cache("b"),
            c = cache("c"),
        );
        ExecutionNodeSettings::parse(&text).expect("the node's file validates")
    }

    /// A cache directory the engine alone writes in, with an entry of `mib` MiB for each name.
    fn cache_dir(&self, names: &[&str], mib: u64) -> PathBuf {
        let cache_dir = self.path("caches");
        std::fs::create_dir_all(&cache_dir).expect("cache dir");
        std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o755))
            .expect("cache dir mode");
        for name in names {
            let entry = cache_dir.join(name);
            std::fs::create_dir_all(&entry).expect("cache entry");
            std::fs::write(entry.join("blob.bin"), noise(mib * MIB)).expect("cache blob");
        }
        cache_dir
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

    fn submit(&self, key: &str, pin: &WorkloadPin, warm: &[&str]) -> SignedJobSubmit {
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
            warm: warm.iter().map(|key| (*key).to_owned()).collect(),
        };
        SignedJobSubmit::sign(submit, ScriptedSigner::new(self.issuer).as_ref())
            .expect("the issuer signs")
    }

    /// A second scripted node in this fixture's directory, whose template `open-models` is at
    /// `digest`: the digest the node's file gives it, so a key's pin matches the file.
    fn node_at(&self, digest: &str) -> ScriptedNode {
        let root = self.path("pinned");
        std::fs::create_dir_all(&root).expect("node dir");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))
            .expect("node dir mode");
        ScriptedNode::new(&root, EntityId::now(), TEMPLATE, digest, NOW_MS)
    }

    /// The job service with the mirror stager over `mirror` and `warm`.
    fn open_staging(&self, mirror: &Path, warm: BTreeMap<String, WarmPath>) -> NodeJobs {
        let mut parts = self.node.parts();
        parts.stager = Arc::new(MirrorStager::new(Arc::new(WarmMirror {
            path: mirror.to_path_buf(),
            warm,
        })));
        NodeJobs::open(self.node.paths.clone(), parts).expect("the node's job service opens")
    }

    /// Reserves and submits `key` listing `warm`, and waits until it launched or ended.
    fn run(&self, jobs: &NodeJobs, key: &str, pin: &WorkloadPin, warm: &[&str]) -> NodeKey {
        assert_eq!(
            receipt(jobs.reserve(self.issuer, self.reserve(key, pin))).state,
            JobState::Held
        );
        assert_eq!(
            receipt(jobs.submit(self.issuer, self.submit(key, pin, warm))).state,
            JobState::Accepted
        );
        wait_for(jobs, key, |entry| {
            matches!(
                entry.state,
                JobState::Launching | JobState::Running | JobState::Ended
            )
        })
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

/// `len` bytes no file system compresses: a cache entry then takes the disk its size says.
fn noise(len: u64) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

fn fact<'a>(facts: &'a [WarmKeyFact], key: &str) -> &'a WarmKeyFact {
    facts
        .iter()
        .find(|fact| fact.key == key)
        .unwrap_or_else(|| panic!("no fact for {key}: {facts:?}"))
}

/// The disk `path` and what it holds take, as the cache pass measures it (allocated blocks).
fn allocated(path: &Path) -> u64 {
    let found = std::fs::symlink_metadata(path).expect("the path exists");
    let mut bytes = found.blocks() * 512;
    if found.is_dir() {
        for entry in std::fs::read_dir(path)
            .expect("the directory reads")
            .flatten()
        {
            bytes += allocated(&entry.path());
        }
    }
    bytes
}

fn wanted(keys: &[&str]) -> WarmWanted {
    WarmWanted {
        keys: keys.iter().map(|key| (*key).to_owned()).collect(),
        overflow: false,
    }
}

fn input(path: PathBuf) -> WarmPath {
    WarmPath { path, cache: false }
}

/// A node's file with no cache directory and one template, `builds`, with `extra` lines.
fn builds_file(extra: &str) -> String {
    format!(
        r#"
[execution_node]
state_dir = "/var/lib/oneiron/node"
work_dir = "/var/lib/oneiron/work"

[execution_node.templates.builds]
repo = "/srv/builds.git"
entries = ["{ENTRY}"]
interpreter = ["/usr/bin/bash"]
max_secs = 3600
memory_gib = 32
disk_gib = 10
{extra}
"#
    )
}

/// The node's file as the cache pass reads it: `settings` at every reading.
fn unchanged_file(
    settings: &ExecutionNodeSettings,
) -> impl Fn() -> Option<ExecutionNodeSettings> + '_ {
    move || Some(settings.clone())
}

fn budget(cap_bytes: u64) -> CacheBudget {
    CacheBudget {
        cap_bytes,
        idle_ms: 10 * 86_400_000,
        protect_ms: 0,
    }
}

// It moves caches: off Linux the pass moves nothing (no `openat2`).
#[cfg(target_os = "linux")]
#[test]
fn the_cache_budget_never_evicts_a_key_an_open_order_lists() {
    let fixture = fixture();
    let cache_dir = fixture.cache_dir(&["a", "b", "c", "h"], 1);
    let settings = fixture.settings(&cache_dir);
    // The held key pins `open-models` at the digest the file gives it, so its map is known.
    let digest = settings
        .template_digest(TEMPLATE)
        .expect("open-models has a digest");
    let node = fixture.node_at(&digest);
    let jobs = node.open();
    // An open order on a live issuer lists `target:a`; a held key of `open-models` may read
    // `target:h`.
    jobs.warm_wanted(fixture.issuer, &wanted(&["target:a"]));
    let held = WorkloadPin {
        template_digest: digest,
        ..pin(DIGEST)
    };
    assert_eq!(
        receipt(jobs.reserve(fixture.issuer, fixture.reserve("job-held", &held))).state,
        JobState::Held
    );

    // Four caches of about 1 MiB under a cap that holds `target:a` and `target:h` as the disk
    // measures them: the plan goes in last use, then key order.
    let cap = allocated(&cache_dir.join("a")) + allocated(&cache_dir.join("h"));
    let first = jobs.cache_pass_under(&unchanged_file(&settings), &settings.cache, &budget(cap));
    let removed: Vec<&str> = first.removed.iter().map(|gone| gone.key.as_str()).collect();
    assert_eq!(removed, ["target:b", "target:c"], "{first:?}");
    assert_eq!(first.deferred, None);
    assert!(cache_dir.join("a").exists(), "the listed key was removed");
    assert!(
        cache_dir.join("h").exists(),
        "the held key's input was removed"
    );
    assert!(!cache_dir.join("b").exists() && !cache_dir.join("c").exists());
    let leftovers: Vec<_> = std::fs::read_dir(&cache_dir)
        .expect("cache dir reads")
        .flatten()
        .map(|found| found.file_name())
        .filter(|name| name != EVICTED_DIR_NAME)
        .collect();
    assert_eq!(
        leftovers.len(),
        2,
        "a removed cache was left: {leftovers:?}"
    );
    let evicted = std::fs::read_dir(cache_dir.join(EVICTED_DIR_NAME))
        .expect("the removed caches' directory reads")
        .count();
    assert_eq!(evicted, 0, "a removed cache's files were left");

    // Once the issuer's list is older than the wanted hold and no ask listed the key again,
    // it is a cache like any other; the held key still protects its own.
    node.clock
        .advance_ms(settings.cache.wanted_hold_secs * 1000 + 1000);
    // A cap that holds `target:h` alone: `target:a` takes disk, so it goes.
    assert!(
        allocated(&cache_dir.join("a")) > 0,
        "target:a takes no disk"
    );
    let cap = allocated(&cache_dir.join("h"));
    let second = jobs.cache_pass_under(&unchanged_file(&settings), &settings.cache, &budget(cap));
    let removed: Vec<&str> = second
        .removed
        .iter()
        .map(|gone| gone.key.as_str())
        .collect();
    assert_eq!(removed, ["target:a"], "{second:?}");
    assert!(!cache_dir.join("a").exists());
    assert!(
        cache_dir.join("h").exists(),
        "the held key's input was removed"
    );
}

#[test]
fn a_listed_warm_input_that_is_missing_refuses_the_launch_at_zero_seconds() {
    let fixture = fixture();
    let (mirror, commit) = mirror(fixture.dir.path());
    let present = fixture.path("data/weights-bb");
    std::fs::create_dir_all(&present).expect("present input");
    // `weights:aa` is mapped by any template of the node's file: a key names one thing on one
    // machine.
    let warm = [
        (
            "weights:aa".to_owned(),
            input(fixture.path("data/weights-aa")),
        ),
        ("weights:bb".to_owned(), input(present)),
    ]
    .into();
    let jobs = fixture.open_staging(&mirror, warm);
    let key = "job-warm/missing";
    let ended = fixture.run(&jobs, key, &pin(&commit), &["weights:bb", "weights:aa"]);
    assert_eq!(ended.state, JobState::Ended);
    assert_eq!(
        ended.end,
        Some(JobEnd::LaunchRefused {
            reason: "warm_key_missing:weights:aa".to_owned()
        })
    );
    assert_eq!(fixture.node.units.starts(key), 0, "a unit started");
    assert!(
        !fixture.path("data/weights-aa").exists(),
        "the node fetched the missing input"
    );
}

#[test]
fn an_absent_cache_key_is_a_cold_start() {
    let fixture = fixture();
    let (mirror, commit) = mirror(fixture.dir.path());
    let warm = [(
        "target:t".to_owned(),
        WarmPath {
            path: fixture.path("caches/t"),
            cache: true,
        },
    )]
    .into();
    let jobs = fixture.open_staging(&mirror, warm);
    let key = "job-warm/cold";
    // An absent cache, and a key no template maps: neither stops the launch.
    let launched = fixture.run(&jobs, key, &pin(&commit), &["target:t", "repo:unmapped"]);
    assert!(
        matches!(launched.state, JobState::Launching | JobState::Running),
        "{launched:?}"
    );
    assert_eq!(fixture.node.units.starts(key), 1);
}

#[test]
fn an_exit_0_attempt_refreshes_the_last_use_of_each_key_it_listed() {
    let fixture = fixture();
    let cache_dir = fixture.cache_dir(&["h"], 1);
    std::fs::create_dir_all(fixture.path("data/weights-aa")).expect("input");
    let settings = fixture.settings(&cache_dir);
    let jobs = fixture.node.open();
    let before = jobs.warm_facts(&settings, &settings.cache);
    assert_eq!(fact(&before, "weights:aa").uses, 0);
    assert_eq!(fact(&before, "weights:aa").last_used_ms, Some(NOW_MS));

    let key = "job-warm/used";
    let launched = fixture.run(&jobs, key, &pin(DIGEST), &["weights:aa", "repo:unmapped"]);
    assert!(matches!(
        launched.state,
        JobState::Launching | JobState::Running
    ));
    fixture.node.clock.advance_ms(60_000);
    fixture.node.units.exit(key, 0);
    jobs.tick();
    let ended = wait_for(&jobs, key, |entry| entry.end.is_some());
    assert_eq!(ended.end, Some(JobEnd::Exited { code: 0 }));

    let after = jobs.warm_facts(&settings, &settings.cache);
    let used = fact(&after, "weights:aa");
    assert_eq!(used.uses, 1);
    assert!(used.last_used_ms >= Some(NOW_MS + 60_000), "{used:?}");
    let remembered = fact(&after, "repo:unmapped");
    assert!(!remembered.mapped && !remembered.present);
    assert_eq!(remembered.uses, 1);
    assert_eq!(
        fact(&after, "target:h").uses,
        0,
        "a key the attempt did not list"
    );
    // Each end is counted once, however often the node is asked.
    assert_eq!(
        fact(&jobs.warm_facts(&settings, &settings.cache), "weights:aa").uses,
        1
    );
}

#[test]
fn the_node_answer_reports_each_warm_key_with_its_presence() {
    let fixture = fixture();
    let cache_dir = fixture.cache_dir(&["a"], 1);
    std::fs::create_dir_all(fixture.path("data/weights-aa")).expect("input");
    let settings = fixture.settings(&cache_dir);
    let jobs = fixture.node.open();
    let facts = jobs.warm_facts(&settings, &settings.cache);
    let input = fact(&facts, "weights:aa");
    assert!(input.present && input.mapped && !input.cache, "{input:?}");
    assert_eq!(input.last_used_ms, Some(NOW_MS));
    let cache = fact(&facts, "target:a");
    assert!(cache.present && cache.mapped && cache.cache, "{cache:?}");
    let cold = fact(&facts, "target:b");
    assert!(!cold.present && cold.mapped && cold.cache, "{cold:?}");
    assert_eq!(cold.last_used_ms, None);
    assert_eq!(facts.len(), 5, "{facts:?}");
}

#[test]
fn a_cache_path_outside_the_cache_dir_is_refused_and_a_shared_cache_dir_removes_nothing() {
    let fixture = fixture();
    let cache_dir = fixture.cache_dir(&["a", "b", "c", "h"], 1);
    let settings = fixture.settings(&cache_dir);
    let outside = format!(
        r#"
[execution_node]
state_dir = "/var/lib/oneiron/node"
work_dir = "/var/lib/oneiron/work"
cache_dir = "{}"

[execution_node.templates.builds]
repo = "/srv/builds.git"
entries = ["{ENTRY}"]
interpreter = ["/usr/bin/bash"]
max_secs = 3600
memory_gib = 32
disk_gib = 10
warm = {{ "target:x" = "{}" }}
caches = ["target:x"]
"#,
        cache_dir.display(),
        cache_dir.join("deeper/x").display(),
    );
    let refused = ExecutionNodeSettings::parse(&outside).expect_err("a nested cache path");
    assert!(
        refused.contains("directly in execution_node.cache_dir"),
        "{refused}"
    );

    // Another account may write in the cache directory: nothing is removed there.
    std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o777))
        .expect("cache dir mode");
    let jobs = fixture.node.open();
    let report = jobs.cache_pass_under(&unchanged_file(&settings), &settings.cache, &budget(0));
    assert!(report.removed.is_empty(), "{report:?}");
    for name in ["a", "b", "c", "h"] {
        assert!(cache_dir.join(name).exists(), "{name} was removed");
    }
}

// It needs the removed caches' directory: off Linux that does not open (no `openat2`), and the
// pass ends before it decides anything.
#[cfg(target_os = "linux")]
#[test]
fn a_cache_pass_removes_nothing_while_what_is_busy_is_not_known() {
    let fixture = fixture();
    let cache_dir = fixture.cache_dir(&["a", "b"], 1);
    let settings = fixture.settings(&cache_dir);
    // The scripted node admits `open-models` at DIGEST, a digest the node's file no longer
    // gives it: the held key's map is not known.
    let jobs = fixture.node.open();
    assert_eq!(
        receipt(jobs.reserve(fixture.issuer, fixture.reserve("job-held", &pin(DIGEST)))).state,
        JobState::Held
    );
    let report = jobs.cache_pass_under(&unchanged_file(&settings), &settings.cache, &budget(0));
    assert!(
        report.removed.is_empty() && report.deferred.is_some(),
        "{report:?}"
    );

    // An issuer whose open orders list more keys than one ask carries: no cache goes while its
    // ask holds.
    let digest = settings
        .template_digest(TEMPLATE)
        .expect("open-models has a digest");
    let node = fixture.node_at(&digest);
    let jobs = node.open();
    jobs.warm_wanted(
        fixture.issuer,
        &WarmWanted {
            keys: Vec::new(),
            overflow: true,
        },
    );
    let report = jobs.cache_pass_under(&unchanged_file(&settings), &settings.cache, &budget(0));
    assert!(
        report.removed.is_empty() && report.deferred.is_some(),
        "{report:?}"
    );
    for name in ["a", "b"] {
        assert!(cache_dir.join(name).exists(), "{name} was removed");
    }
}

// It needs the removed caches' directory: off Linux that does not open (no `openat2`), and the
// pass ends before it reads the file again.
#[cfg(target_os = "linux")]
#[test]
fn a_cache_pass_removes_nothing_when_the_file_changed_while_it_measured() {
    let fixture = fixture();
    let cache_dir = fixture.cache_dir(&["a", "b", "c", "h"], 1);
    let first = fixture.settings(&cache_dir);
    // The second reading maps one key more.
    let input = fixture.path("data/weights-bb");
    let second = fixture.settings_with(
        &cache_dir,
        &format!(r#", "weights:bb" = "{}""#, input.display()),
    );
    let readings = std::cell::Cell::new(0_u32);
    let read = || {
        readings.set(readings.get() + 1);
        Some(if readings.get() == 1 {
            first.clone()
        } else {
            second.clone()
        })
    };
    let jobs = fixture.node.open();
    let report = jobs.cache_pass_under(&read, &first.cache, &budget(0));
    assert!(
        report.removed.is_empty()
            && report
                .deferred
                .as_deref()
                .is_some_and(|why| why.contains("changed while the pass measured")),
        "{report:?}"
    );
    assert!(readings.get() >= 2, "the file was read once");
    for name in ["a", "b", "c", "h"] {
        assert!(cache_dir.join(name).exists(), "{name} was removed");
    }
}

// It moves caches: off Linux the pass moves nothing (no `openat2`).
#[cfg(target_os = "linux")]
#[test]
fn a_cache_pass_never_moves_a_cache_another_keys_path_resolves_into() {
    let fixture = fixture();
    let cache_dir = fixture.cache_dir(&["a", "b", "c", "h"], 1);
    // `weights:al` names a file in cache `b` through another spelling of the cache directory:
    // the file's check compares spellings, the pass resolves them. `weights:lk` names a file
    // outside every cache, through a link in cache `a`: its lookup passes through `a`.
    let alias = fixture.path("caches-alias");
    std::os::unix::fs::symlink(&cache_dir, &alias).expect("alias");
    let outside = fixture.path("outside.bin");
    std::fs::write(&outside, b"outside").expect("outside file");
    std::os::unix::fs::symlink(&outside, cache_dir.join("a/link")).expect("link in a");
    let settings = fixture.settings_with(
        &cache_dir,
        &format!(
            r#", "weights:al" = "{}", "weights:lk" = "{}""#,
            alias.join("b/blob.bin").display(),
            alias.join("a/link").display()
        ),
    );
    let jobs = fixture.node.open();
    let report = jobs.cache_pass_under(&unchanged_file(&settings), &settings.cache, &budget(0));
    assert_eq!(report.deferred, None, "{report:?}");
    let removed: Vec<&str> = report
        .removed
        .iter()
        .map(|gone| gone.key.as_str())
        .collect();
    for kept in ["target:a", "target:b"] {
        assert!(!removed.contains(&kept), "{report:?}");
        assert!(
            report
                .left
                .iter()
                .any(|(key, why)| key == kept && why.contains("another warm key's path")),
            "{report:?}"
        );
    }
    assert!(
        cache_dir.join("b/blob.bin").exists(),
        "the input in b was removed"
    );
    assert!(
        cache_dir.join("a/link").exists(),
        "the link in a was removed"
    );
    for name in ["c", "h"] {
        assert!(!cache_dir.join(name).exists(), "{name} was kept");
    }
}

// It moves caches: off Linux the pass moves nothing (no `openat2`).
#[cfg(target_os = "linux")]
#[test]
fn a_cache_pass_never_moves_a_cache_another_path_reaches_by_another_name_or_the_state_dir_lies_in()
{
    let fixture = fixture();
    let cache_dir = fixture.cache_dir(&["a", "b", "c", "h"], 1);
    // `weights:hl` names, outside every cache, a second name of the file in cache `b`: what a
    // bind mount of a directory in a cache shows too (the same file system and inode under a
    // path that never enters the cache). The node's state directory lies in cache `h`.
    let second_name = fixture.path("data/second-name.bin");
    std::fs::create_dir_all(fixture.path("data")).expect("data dir");
    std::fs::hard_link(cache_dir.join("b/blob.bin"), &second_name).expect("second name");
    let mut settings = fixture.settings_with(
        &cache_dir,
        &format!(r#", "weights:hl" = "{}""#, second_name.display()),
    );
    settings.state_dir = cache_dir.join("h/node-state");
    std::fs::create_dir_all(&settings.state_dir).expect("state dir in h");
    let jobs = fixture.node.open();
    let report = jobs.cache_pass_under(&unchanged_file(&settings), &settings.cache, &budget(0));
    assert_eq!(report.deferred, None, "{report:?}");
    for kept in ["target:b", "target:h"] {
        assert!(
            report
                .left
                .iter()
                .any(|(key, why)| key == kept && why.contains("reaches into it by another name")),
            "{report:?}"
        );
    }
    assert!(second_name.exists() && cache_dir.join("b/blob.bin").exists());
    assert!(settings.state_dir.exists(), "the state directory was moved");
    for name in ["a", "c"] {
        assert!(!cache_dir.join(name).exists(), "{name} was kept");
    }
}

// It moves caches: off Linux the pass moves nothing (no `openat2`).
#[cfg(target_os = "linux")]
#[test]
fn a_file_with_two_names_in_a_cache_counts_once_against_the_cap() {
    let fixture = fixture();
    let cache_dir = fixture.cache_dir(&["a", "b", "c", "h"], 1);
    let on_disk: u64 = ["a", "b", "c", "h"]
        .iter()
        .map(|name| allocated(&cache_dir.join(name)))
        .sum();
    // A second name for the file in cache `a` takes no more disk; the cap is what the caches
    // take, so nothing goes.
    std::fs::hard_link(
        cache_dir.join("a/blob.bin"),
        cache_dir.join("a/blob-again.bin"),
    )
    .expect("second name");
    let settings = fixture.settings(&cache_dir);
    let jobs = fixture.node.open();
    let report = jobs.cache_pass_under(
        &unchanged_file(&settings),
        &settings.cache,
        &budget(on_disk),
    );
    assert_eq!(report.deferred, None, "{report:?}");
    assert!(report.removed.is_empty(), "{report:?}");
    assert_eq!(report.kept_bytes, on_disk, "{report:?}");
}

#[test]
fn templates_that_map_more_warm_keys_together_than_the_node_reports_are_refused() {
    // Each template within its own bound, together past the node's: a `Node` answer stays
    // within the mesh's message.
    let templates = NODE_WARM_KEYS_MAX / TEMPLATE_WARM_KEYS_MAX + 1;
    let mut text = builds_file("");
    for index in 0..templates {
        let warm: Vec<String> = (0..TEMPLATE_WARM_KEYS_MAX)
            .map(|key| format!(r#""env:t{index}-{key}" = "/srv/warm/t{index}/{key}""#))
            .collect();
        text.push_str(&format!(
            r#"
[execution_node.templates.many-{index}]
repo = "/srv/builds.git"
entries = ["{ENTRY}"]
interpreter = ["/usr/bin/bash"]
max_secs = 3600
memory_gib = 32
disk_gib = 10
warm = {{ {} }}
"#,
            warm.join(", ")
        ));
    }
    let refused = ExecutionNodeSettings::parse(&text).expect_err("past the node's bound");
    assert!(refused.contains("warm keys together"), "{refused}");
    // The keys the table remembers past the templates' are bound too.
    let keys_max = |most: u32| {
        ExecutionNodeSettings::parse(&format!(
            "{}\n[execution_node.cache]\nkeys_max = {most}\n",
            builds_file("")
        ))
    };
    keys_max(CACHE_KEYS_MAX_MOST).expect("keys_max at its most");
    let refused = keys_max(CACHE_KEYS_MAX_MOST + 1).expect_err("keys_max past its most");
    assert!(refused.contains("keys_max"), "{refused}");
}

#[test]
fn a_cache_pass_after_the_service_closed_removes_nothing() {
    let fixture = fixture();
    let cache_dir = fixture.cache_dir(&["a", "b", "c", "h"], 1);
    let settings = fixture.settings(&cache_dir);
    let jobs = fixture.node.open();
    jobs.close();
    let report = jobs.cache_pass_under(&unchanged_file(&settings), &settings.cache, &budget(0));
    assert!(report.removed.is_empty(), "{report:?}");
    for name in ["a", "b", "c", "h"] {
        assert!(cache_dir.join(name).exists(), "{name} was removed");
    }
}

// It moves caches: off Linux the pass moves nothing (no `openat2`).
#[cfg(target_os = "linux")]
#[test]
fn the_removed_caches_directory_deletes_only_what_a_pass_moved() {
    let fixture = fixture();
    let cache_dir = fixture.cache_dir(&["a"], 1);
    let settings = fixture.settings(&cache_dir);
    // An entry no pass moved, in a removed caches' directory the engine alone may enter.
    let trash = cache_dir.join(EVICTED_DIR_NAME);
    std::fs::create_dir_all(trash.join("stranger")).expect("stranger");
    std::fs::write(trash.join("stranger/kept.bin"), b"kept").expect("stranger file");
    std::fs::set_permissions(&trash, std::fs::Permissions::from_mode(0o700)).expect("trash mode");
    let jobs = fixture.node.open();
    let report = jobs.cache_pass_under(&unchanged_file(&settings), &settings.cache, &budget(0));
    let removed: Vec<&str> = report
        .removed
        .iter()
        .map(|gone| gone.key.as_str())
        .collect();
    assert_eq!(removed, ["target:a"], "{report:?}");
    assert!(report.not_deleted.is_empty(), "{report:?}");
    assert!(!cache_dir.join("a").exists());
    let left: Vec<String> = std::fs::read_dir(&trash)
        .expect("trash reads")
        .flatten()
        .map(|found| found.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        left,
        ["stranger"],
        "the moved cache was left or the stranger deleted"
    );
    assert!(trash.join("stranger/kept.bin").exists());

    // A removed caches' directory others may enter: the pass removes nothing, though `b`
    // holds bytes over the cap.
    std::fs::create_dir_all(cache_dir.join("b")).expect("cache b");
    std::fs::write(cache_dir.join("b/blob.bin"), noise(MIB)).expect("cache b blob");
    assert!(allocated(&cache_dir.join("b")) > 0, "b takes no disk");
    std::fs::set_permissions(&trash, std::fs::Permissions::from_mode(0o755)).expect("trash mode");
    let report = jobs.cache_pass_under(&unchanged_file(&settings), &settings.cache, &budget(0));
    assert!(report.removed.is_empty(), "{report:?}");
    assert!(cache_dir.join("b").exists());
}

#[test]
fn a_warm_path_that_overlaps_a_cache_or_lies_where_removed_caches_go_is_refused() {
    let file = |warm: &str, caches: &str| {
        builds_file(&format!("warm = {{ {warm} }}\ncaches = [{caches}]"))
    };
    let cache_a = r#""target:a" = "/var/lib/oneiron/work/caches/a""#;
    // With no cache_dir, a cache lies directly in <work_dir>/caches.
    ExecutionNodeSettings::parse(&file(cache_a, r#""target:a""#))
        .expect("a cache in the default cache directory");
    // Two keys on one cache path; an input inside a cache; an input where removed caches go.
    let overlap = "one path or one inside the other";
    for (warm, caches, why) in [
        (
            format!(r#"{cache_a}, "target:b" = "/var/lib/oneiron/work/caches/a""#),
            r#""target:a""#,
            overlap,
        ),
        (
            format!(r#"{cache_a}, "weights:w" = "/var/lib/oneiron/work/caches/a/w""#),
            r#""target:a""#,
            overlap,
        ),
        (
            format!(r#""weights:w" = "/var/lib/oneiron/work/caches/{EVICTED_DIR_NAME}/w""#),
            "",
            "where the cache pass moves what it removes",
        ),
    ] {
        let refused = ExecutionNodeSettings::parse(&file(&warm, caches)).expect_err(&warm);
        assert!(refused.contains(why), "{warm}: {refused}");
    }
}

#[test]
fn a_template_and_a_submit_without_warm_keys_hash_and_sign_as_before() {
    let plain = ExecutionNodeSettings::parse(&builds_file("")).expect("plain");
    let empty =
        ExecutionNodeSettings::parse(&builds_file("warm = {}\ncaches = []")).expect("empty");
    assert_eq!(
        plain.template_digest("builds"),
        empty.template_digest("builds")
    );
    let encoded = oneiron::llm::canonical_json_bytes(&plain.templates["builds"]).expect("encodes");
    let text = String::from_utf8(encoded).expect("JSON");
    assert!(!text.contains("warm") && !text.contains("caches"), "{text}");

    let fixture = fixture();
    let without = fixture.submit("job-a", &pin(DIGEST), &[]).submit;
    let value = serde_json::to_value(&without).expect("encodes");
    assert!(value.get("warm").is_none(), "{value}");
    let with = fixture
        .submit("job-a", &pin(DIGEST), &["weights:aa"])
        .submit;
    assert_eq!(
        serde_json::to_value(&with).expect("encodes")["warm"],
        serde_json::json!(["weights:aa"])
    );
}

#[test]
fn a_submit_listing_a_repeated_or_malformed_warm_key_is_refused() {
    let fixture = fixture();
    let jobs = fixture.node.open();
    for (key, warm) in [
        ("job-warm/repeated", ["weights:aa", "weights:aa"]),
        ("job-warm/malformed", ["weights:aa", "no colon"]),
    ] {
        assert_eq!(
            receipt(jobs.reserve(fixture.issuer, fixture.reserve(key, &pin(DIGEST)))).state,
            JobState::Held
        );
        let answer = receipt(jobs.submit(fixture.issuer, fixture.submit(key, &pin(DIGEST), &warm)));
        assert_eq!(answer.state, JobState::Ended, "{key}");
        assert_eq!(
            answer.end,
            Some(JobEnd::Refused {
                reason: "warm_key_invalid".to_owned()
            }),
            "{key}"
        );
        assert_eq!(fixture.node.units.starts(key), 0);
    }
}
