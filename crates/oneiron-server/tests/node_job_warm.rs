//! Pass 34 row P2 (`34-compute-general/DESIGN.md` sections 4.1, 7.1 gap 6 and 10): warm keys
//! on the node. The cache budget never removes a key that an open order lists or that a live
//! key may read; a listed input that is not on the node refuses the launch at zero seconds and
//! fetches nothing, while an absent cache is a cold start; an exit-0 attempt is a use of each
//! key it listed; `Node` reports each key with its presence; a cache path is removed only
//! directly inside a cache directory that is the engine's alone; and a template or a submit
//! without warm keys reads, hashes and signs as before.
//!
//! The node is R3a's scripted node (unit manager, devices, clock). The launch tests put the
//! real [`MirrorStager`] in place of the scripted stager, over a one-commit bare mirror that
//! `git clone --mirror` makes in a temporary directory.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --test node_job_warm`.
#![cfg(all(oneiron_test_support, unix))]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::job_workload::{DeviceClaim, DeviceKind, Sharing};
use oneiron_server::gpu_execution_node::jobs::warm::{CacheBudget, TemplateWarm};
use oneiron_server::gpu_execution_node::jobs::{
    MirrorStager, NodeJobs, NodeKey, StagingRefusal, TemplateMirrors,
};
use oneiron_server::gpu_execution_node::node_settings::ExecutionNodeSettings;
use oneiron_server::gpu_execution_node::wire::{
    HoldRef, JobAnswer, JobEnd, JobReceipt, JobReserve, JobState, JobSubmit, NetworkMode,
    OutputDecl, ResourceRequest, ScopeKind, SignedJobSubmit, SlotSelector, Starter, WarmKeyFact,
    WorkloadPin,
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

fn git_ok(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
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

/// The node's configuration as the stager reads it: one template at [`DIGEST`], its mirror
/// and its warm keys.
struct WarmMirror {
    path: PathBuf,
    warm: TemplateWarm,
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

    fn template_warm(
        &self,
        template: &str,
        template_digest: &str,
    ) -> Result<TemplateWarm, StagingRefusal> {
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
warm = {{ "weights:aa" = "{weights}", "target:h" = "{h}" }}
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
            let bytes = vec![7_u8; usize::try_from(mib * MIB).expect("a small size")];
            std::fs::write(entry.join("blob.bin"), bytes).expect("cache blob");
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
            warm: warm.iter().map(|key| (*key).to_owned()).collect(),
        };
        SignedJobSubmit::sign(submit, ScriptedSigner::new(self.issuer).as_ref())
            .expect("the issuer signs")
    }

    /// The job service with the mirror stager over `mirror` and `warm`.
    fn open_staging(&self, mirror: &Path, warm: TemplateWarm) -> NodeJobs {
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
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn fact<'a>(facts: &'a [WarmKeyFact], key: &str) -> &'a WarmKeyFact {
    facts
        .iter()
        .find(|fact| fact.key == key)
        .unwrap_or_else(|| panic!("no fact for {key}: {facts:?}"))
}

fn budget(cap_bytes: u64) -> CacheBudget {
    CacheBudget {
        cap_bytes,
        idle_ms: 10 * 86_400_000,
        protect_ms: 0,
    }
}

#[test]
fn the_cache_budget_never_evicts_a_key_an_open_order_lists() {
    let fixture = fixture();
    let cache_dir = fixture.cache_dir(&["a", "b", "c", "h"], 1);
    let settings = fixture.settings(&cache_dir);
    let jobs = fixture.node.open();
    // An open order on a live issuer lists `target:a`; a held key of `open-models` may read
    // `target:h`.
    jobs.warm_wanted(fixture.issuer, &["target:a".to_owned()]);
    assert_eq!(
        receipt(jobs.reserve(fixture.issuer, fixture.reserve("job-held", &pin(DIGEST)))).state,
        JobState::Held
    );

    // Four caches of 1 MiB under a cap of 2.5 MiB: the plan goes in last use, then key order.
    let first = jobs.cache_pass_under(&settings, &settings.cache, &budget(5 * MIB / 2));
    let removed: Vec<&str> = first.removed.iter().map(|gone| gone.key.as_str()).collect();
    assert_eq!(removed, ["target:b", "target:c"], "{first:?}");
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
        .collect();
    assert_eq!(
        leftovers.len(),
        2,
        "a removed cache was left: {leftovers:?}"
    );

    // Once the issuer's list is older than the wanted hold and no ask listed the key again,
    // it is a cache like any other; the held key still protects its own.
    fixture
        .node
        .clock
        .advance_ms(settings.cache.wanted_hold_secs * 1000 + 1000);
    let second = jobs.cache_pass_under(&settings, &settings.cache, &budget(MIB / 2));
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
    let warm = TemplateWarm {
        paths: [
            ("weights:aa".to_owned(), fixture.path("data/weights-aa")),
            ("weights:bb".to_owned(), present),
        ]
        .into(),
        caches: Default::default(),
    };
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
    let warm = TemplateWarm {
        paths: [("target:t".to_owned(), fixture.path("caches/t"))].into(),
        caches: ["target:t".to_owned()].into(),
    };
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
    let report = jobs.cache_pass_under(&settings, &settings.cache, &budget(0));
    assert!(report.removed.is_empty(), "{report:?}");
    for name in ["a", "b", "c", "h"] {
        assert!(cache_dir.join(name).exists(), "{name} was removed");
    }
}

#[test]
fn a_template_and_a_submit_without_warm_keys_hash_and_sign_as_before() {
    let template = |extra: &str| {
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
    };
    let plain = ExecutionNodeSettings::parse(&template("")).expect("plain");
    let empty = ExecutionNodeSettings::parse(&template("warm = {}\ncaches = []")).expect("empty");
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
