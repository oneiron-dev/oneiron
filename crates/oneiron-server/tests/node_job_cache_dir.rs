//! FLEET-TOOL-PARITY row 5 ([NODE-TEMPLATE-CACHE-DIR], on pass 34 row P2's warm keys): a
//! template's kept job cache. The switch `[execution_node.job_cache] writable` is off by
//! default; while it is off a template that names a job cache is refused and the job unit is as
//! before, byte for byte. On, one run at a time holds the kept cache, a run that starts meanwhile
//! runs cold and never waits, the holder's end frees it, a held key is reported held and counted
//! warm on no machine where it is held, and a cache run's exec file writes the mount and names it.
//!
//! The node is R3a's scripted node (unit manager, devices, clock, admission). Root's bind and
//! the sweep need root: they are proven in the field, not here.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --test node_job_cache_dir`.
#![cfg(all(oneiron_test_support, target_os = "linux"))]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron_server::gpu_execution_node::jobs::job_cache::LaunchCache;
use oneiron_server::gpu_execution_node::jobs::{NodeJobs, NodeKey};
use oneiron_server::gpu_execution_node::node_settings::{
    ExecutionNodeSettings, JOB_CACHE_MOUNT_DEFAULT,
};
use oneiron_server::gpu_execution_node::scope_systemd::job_cache::{
    JOB_CACHE_ENV, JOB_CACHE_STATE_ENV, JobCacheView, add_to_exec,
};
use oneiron_server::gpu_execution_node::scope_systemd::records::ExecFile;
use oneiron_server::gpu_execution_node::scope_systemd::unit_file::{
    UnitInputs, installed_binds_job_cache, render_job_unit,
};
use oneiron_server::gpu_execution_node::wire::{
    HoldRef, JobAnswer, JobEnd, JobReceipt, JobReserve, JobState, JobSubmit, NetworkMode,
    NodeAnswer, OutputDecl, ResourceRequest, ScopeKind, SignedJobSubmit, SlotSelector, Starter,
    WarmKeyFact, WorkloadPin,
};
use oneiron_server::test_doors::node_jobs::{ScriptedNode, ScriptedSigner};
use oneiron_server::work_order_host::facts_of_answer;

const TEMPLATE: &str = "open-models";
const DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const NOW_MS: u64 = 1_800_000_000_000;
const WAIT: Duration = Duration::from_secs(20);
const CACHE_KEY: &str = "target:h";
const SWITCH_ON: &str = "[execution_node.job_cache]\nwritable = true\n";

/// A node's file with no cache directory: `[execution_node]`, then `tables`, then the template
/// `builds` (an input `weights:w` and the cache `target:a`) with `extra` lines.
fn node_file(tables: &str, extra: &str) -> String {
    format!(
        r#"
[execution_node]
state_dir = "/var/lib/oneiron/node"
work_dir = "/var/lib/oneiron/work"
{tables}
[execution_node.templates.builds]
repo = "/srv/builds.git"
entries = ["run.sh"]
interpreter = ["/usr/bin/bash"]
max_secs = 3600
memory_gib = 32
disk_gib = 10
warm = {{ "target:a" = "/var/lib/oneiron/work/caches/a", "weights:w" = "/srv/weights" }}
caches = ["target:a"]
{extra}
"#
    )
}

#[test]
fn a_job_cache_is_refused_while_job_writable_is_off() {
    let names = "job_cache = \"target:a\"";
    let unstated = ExecutionNodeSettings::parse(&node_file("", names))
        .expect_err("a job cache needs the switch");
    assert!(
        unstated.contains("execution_node.job_cache.writable"),
        "{unstated}"
    );
    let stated_off = ExecutionNodeSettings::parse(&node_file(
        "[execution_node.job_cache]\nwritable = false\n",
        names,
    ))
    .expect_err("a job cache needs the switch on");
    assert!(
        stated_off.contains("execution_node.job_cache.writable"),
        "{stated_off}"
    );
    let plain = ExecutionNodeSettings::parse(&node_file("", ""))
        .expect("a file without a job cache validates");
    assert!(!plain.job_cache.writable);
    assert_eq!(plain.job_cache.mount, Path::new(JOB_CACHE_MOUNT_DEFAULT));
    assert_eq!(plain.job_cache_target("builds"), None);
    let on = ExecutionNodeSettings::parse(&node_file(SWITCH_ON, names))
        .expect("on, a template names one of its caches");
    let target = on
        .job_cache_target("builds")
        .expect("the template's job cache");
    assert_eq!(target.key, "target:a");
    assert_eq!(target.path, Path::new("/var/lib/oneiron/work/caches/a"));
}

#[test]
fn a_job_cache_must_be_one_of_its_templates_caches_and_job_mount_must_lie_outside_the_node_dirs() {
    for key in ["weights:w", "target:z"] {
        let refused =
            ExecutionNodeSettings::parse(&node_file(SWITCH_ON, &format!("job_cache = \"{key}\"")))
                .expect_err(key);
        assert!(
            refused.contains("must be one of this template's caches"),
            "{key}: {refused}"
        );
    }
    for mount in [
        "relative/cache",
        "/",
        "/var/cache/../tmp",
        "/var/lib/oneiron/work/caches/x",
        "/var/lib/oneiron/node/c",
        "/var/lib/oneiron",
        "/run/oneiron-caches",
        "/proc/c",
        "/tmp/c",
    ] {
        let tables = format!("{SWITCH_ON}mount = \"{mount}\"\n");
        let refused = ExecutionNodeSettings::parse(&node_file(&tables, "")).expect_err(mount);
        assert!(
            refused.contains("execution_node.job_cache.mount"),
            "{mount}: {refused}"
        );
    }
    // While the switch is off the mount is not read: a file that read before reads still.
    let off = ExecutionNodeSettings::parse(&node_file(
        "[execution_node.job_cache]\nmount = \"/var/lib/oneiron/work/x\"\n",
        "",
    ))
    .expect("an unused mount is not checked");
    assert!(!off.job_cache.writable);
    let moved = ExecutionNodeSettings::parse(&node_file(
        &format!("{SWITCH_ON}mount = \"/srv/job-cache\"\n"),
        "job_cache = \"target:a\"",
    ))
    .expect("a mount outside the node's directories");
    assert_eq!(moved.job_cache.mount, Path::new("/srv/job-cache"));
}

#[test]
fn a_template_without_a_job_cache_keeps_its_digest() {
    let off = ExecutionNodeSettings::parse(&node_file("", "")).expect("validates");
    let on = ExecutionNodeSettings::parse(&node_file(SWITCH_ON, "")).expect("validates");
    let encoded = serde_json::to_value(&off.templates["builds"]).expect("a template encodes");
    assert!(encoded.get("job_cache").is_none(), "{encoded}");
    assert!(off.template_digest("builds").is_some());
    assert_eq!(off.template_digest("builds"), on.template_digest("builds"));
    let named = ExecutionNodeSettings::parse(&node_file(SWITCH_ON, "job_cache = \"target:a\""))
        .expect("validates");
    assert_ne!(
        named.template_digest("builds"),
        on.template_digest("builds"),
        "a template that names a job cache is another template"
    );
}

fn unit_inputs(job_cache_mount: Option<PathBuf>) -> UnitInputs {
    UnitInputs {
        binary: "/usr/bin/oneiron".into(),
        node_file: "/etc/oneiron/execution-node.toml".into(),
        engine_account: "oneiron".to_owned(),
        job_account: "oneiron-job".to_owned(),
        state_dir: "/var/lib/oneiron/jobs".into(),
        work_dir: "/data/oneiron-jobs".into(),
        protected: vec!["/var/lib/oneiron".into()],
        runtime_max_secs: 172_800,
        stop_grace_secs: 10,
        start_timeout_secs: 60,
        job_cache_mount,
    }
}

/// The job unit `install` wrote for [`unit_inputs`] before job caches, byte for byte.
const UNIT_BEFORE_JOB_CACHES: &str = concat!(
    "# Written by `oneiron execution-node install` (pass 33, section 7.6); root-owned.\n",
    "# Do not edit: install writes it again, and the prepare step refuses a job whose\n",
    "# maximum is past this file's RuntimeMaxSec.\n",
    "[Unit]\n",
    "Description=Oneiron job %i\n",
    "\n",
    "[Service]\n",
    "ExecStartPre=+/usr/bin/oneiron job-prepare --node-file /etc/oneiron/execution-node.toml --engine-account oneiron %i\n",
    "ExecStart=/usr/bin/oneiron job-exec %i\n",
    "ExecStartPost=+/usr/bin/oneiron job-prepare --after-exec --node-file /etc/oneiron/execution-node.toml --engine-account oneiron %i\n",
    "ExecStopPost=+/usr/bin/oneiron job-ended --node-file /etc/oneiron/execution-node.toml --engine-account oneiron %i\n",
    "Type=exec\n",
    "User=oneiron-job\n",
    "Group=oneiron-job\n",
    "Restart=no\n",
    "KillMode=control-group\n",
    "OOMPolicy=stop\n",
    "TimeoutStartSec=60\n",
    "TimeoutStopSec=10\n",
    "RuntimeMaxSec=172800\n",
    "MemorySwapMax=0\n",
    "NoNewPrivileges=yes\n",
    "PrivateNetwork=yes\n",
    "PrivateIPC=yes\n",
    "PrivateTmp=yes\n",
    "DevicePolicy=closed\n",
    "ProtectProc=invisible\n",
    "ProtectSystem=strict\n",
    "ProtectKernelTunables=yes\n",
    "ProtectKernelModules=yes\n",
    "ProtectKernelLogs=yes\n",
    "ProtectControlGroups=yes\n",
    "ProtectClock=yes\n",
    "ProtectHostname=yes\n",
    "RestrictSUIDSGID=yes\n",
    "RestrictRealtime=yes\n",
    "LockPersonality=yes\n",
    "CapabilityBoundingSet=\n",
    "AmbientCapabilities=\n",
    "UMask=0022\n",
    "KeyringMode=private\n",
    "InaccessiblePaths=/var/lib/oneiron/jobs -/var/lib/oneiron\n",
    "TemporaryFileSystem=/data/oneiron-jobs:ro /run/oneiron-jobs:ro\n",
    "BindPaths=-/run/oneiron-payloads/%i:/data/oneiron-jobs/%i\n",
    "ReadWritePaths=-/data/oneiron-jobs/%i\n",
    "BindReadOnlyPaths=-/run/oneiron-jobs/%i\n",
);

#[test]
fn the_unit_is_unchanged_while_job_writable_is_off_and_binds_job_mount_when_on() {
    let off = render_job_unit(&unit_inputs(None));
    assert_eq!(off, UNIT_BEFORE_JOB_CACHES);
    let mount = Path::new(JOB_CACHE_MOUNT_DEFAULT);
    assert!(!installed_binds_job_cache(&off, mount));
    let on = render_job_unit(&unit_inputs(Some(mount.to_path_buf())));
    assert!(
        on.contains("BindPaths=-/run/oneiron-payloads/%i:/data/oneiron-jobs/%i -/run/oneiron-caches/%i:/var/cache/oneiron-job\n"),
        "{on}"
    );
    assert!(
        on.contains("ReadWritePaths=-/data/oneiron-jobs/%i -/var/cache/oneiron-job\n"),
        "{on}"
    );
    assert!(installed_binds_job_cache(&on, mount));
    assert!(
        !installed_binds_job_cache(&on, Path::new("/srv/job-cache")),
        "a moved mount needs install again"
    );
    let differing: Vec<(&str, &str)> = off
        .lines()
        .zip(on.lines())
        .filter(|(before, after)| before != after)
        .collect();
    assert_eq!(differing.len(), 2, "{differing:?}");
    assert_eq!(off.lines().count(), on.lines().count());
}

struct Rig {
    dir: tempfile::TempDir,
    node: ScriptedNode,
    issuer: EntityId,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().expect("temp dir");
    let node_dir = dir.path().join("node");
    let node = ScriptedNode::new(&node_dir, EntityId::now(), TEMPLATE, DIGEST, NOW_MS);
    std::fs::create_dir_all(&node_dir).expect("node dir");
    std::fs::set_permissions(&node_dir, std::fs::Permissions::from_mode(0o755))
        .expect("node dir mode");
    Rig {
        dir,
        node,
        issuer: EntityId::now(),
    }
}

/// A pin of `open-models` with no device claim and 1 GiB of memory, so two of its runs fit the
/// scripted node at once.
fn cpu_pin() -> WorkloadPin {
    WorkloadPin {
        template: TEMPLATE.to_owned(),
        template_digest: DIGEST.to_owned(),
        commit: DIGEST.to_owned(),
        contract_sha256: "2222222222222222222222222222222222222222222222222222222222222222"
            .to_owned(),
        contract_path: "contract.json".to_owned(),
        entry: "tools/units/run.sh".to_owned(),
        args: Vec::new(),
        request: ResourceRequest {
            cpu_threads: 0,
            memory_mib: 1024,
            disk_mib: 1024,
            devices: Vec::new(),
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

impl Rig {
    fn cache_dir(&self) -> PathBuf {
        self.dir.path().join("caches")
    }

    fn cache_entry(&self) -> PathBuf {
        self.cache_dir().join("h")
    }

    /// The node names [`CACHE_KEY`] at [`Self::cache_entry`] as `open-models`'s job cache.
    fn with_job_cache(&self) {
        let entry = self.cache_entry();
        self.node
            .admission
            .set_template_job_cache(TEMPLATE, Some((CACHE_KEY, entry.as_path())));
    }

    /// The node's file as `Node` reads it: `open-models` maps the cache [`CACHE_KEY`] and names
    /// it its job cache.
    fn settings(&self) -> ExecutionNodeSettings {
        let at = |name: &str| self.dir.path().join(name).display().to_string();
        let text = format!(
            r#"
[execution_node]
state_dir = "{state}"
work_dir = "{work}"
cache_dir = "{cache_dir}"
{SWITCH_ON}
[execution_node.templates.open-models]
repo = "/srv/mirror.git"
entries = ["tools/units/run.sh"]
interpreter = ["/usr/bin/bash"]
max_secs = 3600
memory_gib = 32
disk_gib = 10
warm = {{ "{CACHE_KEY}" = "{entry}" }}
caches = ["{CACHE_KEY}"]
job_cache = "{CACHE_KEY}"
"#,
            state = at("node/state"),
            work = at("node/work"),
            cache_dir = self.cache_dir().display(),
            entry = self.cache_entry().display(),
        );
        ExecutionNodeSettings::parse(&text).expect("the node's file validates")
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
            warm: Vec::new(),
        };
        SignedJobSubmit::sign(submit, ScriptedSigner::new(self.issuer).as_ref())
            .expect("the issuer signs")
    }

    /// Reserves and submits `key`, and waits until it launched or ended.
    fn run(&self, jobs: &NodeJobs, key: &str) -> NodeKey {
        let pin = cpu_pin();
        assert_eq!(
            receipt(jobs.reserve(self.issuer, self.reserve(key, &pin))).state,
            JobState::Held
        );
        assert_eq!(
            receipt(jobs.submit(self.issuer, self.submit(key, &pin))).state,
            JobState::Accepted
        );
        wait_for(jobs, key, |entry| {
            matches!(
                entry.state,
                JobState::Launching | JobState::Running | JobState::Ended
            )
        })
    }

    /// Ends `key` with exit 0 and waits for its end.
    fn end(&self, jobs: &NodeJobs, key: &str) {
        self.node.clock.advance_ms(60_000);
        self.node.units.exit(key, 0);
        jobs.tick();
        let ended = wait_for(jobs, key, |entry| entry.end.is_some());
        assert_eq!(ended.end, Some(JobEnd::Exited { code: 0 }));
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

fn cache_of(known: &NodeKey) -> Option<LaunchCache> {
    known.launch.as_ref()?.cache.clone()
}

fn kept(kept: bool) -> Option<LaunchCache> {
    Some(LaunchCache {
        key: CACHE_KEY.to_owned(),
        kept,
    })
}

fn launched(known: &NodeKey) -> bool {
    matches!(known.state, JobState::Launching | JobState::Running)
}

#[test]
fn one_run_holds_the_kept_cache_and_a_concurrent_run_of_its_template_runs_cold() {
    let rig = rig();
    rig.with_job_cache();
    let jobs = rig.node.open();
    let first = rig.run(&jobs, "job-cache/first");
    assert!(launched(&first), "{first:?}");
    assert_eq!(cache_of(&first), kept(true));
    assert!(
        rig.cache_entry().is_dir(),
        "the engine makes the kept cache's entry"
    );
    let second = rig.run(&jobs, "job-cache/second");
    assert!(
        launched(&second),
        "a held cache never stops a launch: {second:?}"
    );
    assert_eq!(cache_of(&second), kept(false));
    assert_eq!(rig.node.units.starts("job-cache/second"), 1);
    // A template that names no job cache launches with none.
    rig.node.admission.set_template_job_cache(TEMPLATE, None);
    let plain = rig.run(&jobs, "job-cache/plain");
    assert!(launched(&plain), "{plain:?}");
    assert_eq!(cache_of(&plain), None);
}

#[test]
fn a_released_run_frees_the_kept_cache_for_the_next_launch() {
    let rig = rig();
    rig.with_job_cache();
    let jobs = rig.node.open();
    let first = rig.run(&jobs, "job-cache/first");
    assert_eq!(cache_of(&first), kept(true));
    rig.end(&jobs, "job-cache/first");
    let next = rig.run(&jobs, "job-cache/next");
    assert!(launched(&next), "{next:?}");
    assert_eq!(
        cache_of(&next),
        kept(true),
        "the holder's end frees the kept cache"
    );
}

/// An idle node's answer carrying `warm`.
fn answer(warm: Vec<WarmKeyFact>) -> NodeAnswer {
    NodeAnswer {
        enabled: true,
        paused: None,
        drained: None,
        templates: Vec::new(),
        scopes: Vec::new(),
        disk_free_bytes: 200 << 30,
        disk_reserved_bytes: 0,
        disk_reserve_bytes: 50 << 30,
        epoch: None,
        swept: true,
        boot_id: "boot-1".to_owned(),
        engine_version: "0.0.0-test".to_owned(),
        warm,
        readiness: None,
    }
}

fn fact(facts: &[WarmKeyFact], key: &str) -> WarmKeyFact {
    facts
        .iter()
        .find(|fact| fact.key == key)
        .cloned()
        .unwrap_or_else(|| panic!("no fact for {key}: {facts:?}"))
}

#[test]
fn a_held_cache_is_reported_held_and_left_out_of_machine_facts_warm() {
    let rig = rig();
    rig.with_job_cache();
    let settings = rig.settings();
    let jobs = rig.node.open();
    let machine = EntityId::now();
    assert!(!fact(&jobs.warm_facts(&settings, &settings.cache), CACHE_KEY).held);

    let first = rig.run(&jobs, "job-cache/first");
    assert_eq!(cache_of(&first), kept(true));
    let facts = jobs.warm_facts(&settings, &settings.cache);
    let held = fact(&facts, CACHE_KEY);
    assert!(held.held && held.present && held.cache, "{held:?}");
    let placed = facts_of_answer(machine, Some(&JobAnswer::Node(answer(facts))), NOW_MS);
    assert!(
        !placed.warm.iter().any(|key| key == CACHE_KEY),
        "a held cache is warm for no next run here: {:?}",
        placed.warm
    );

    rig.end(&jobs, "job-cache/first");
    let facts = jobs.warm_facts(&settings, &settings.cache);
    let freed = fact(&facts, CACHE_KEY);
    assert!(!freed.held && freed.present, "{freed:?}");
    let placed = facts_of_answer(machine, Some(&JobAnswer::Node(answer(facts))), NOW_MS);
    assert!(
        placed.warm.iter().any(|key| key == CACHE_KEY),
        "{:?}",
        placed.warm
    );
}

#[test]
fn the_exec_file_of_a_cache_run_writes_job_mount_and_names_it_in_its_env() {
    let before: ExecFile = serde_json::from_value(serde_json::json!({
        "key": "job-cache/first",
        "instance": "job-cache-first",
        "probe": false,
        "argv": ["/usr/bin/bash", "/data/oneiron-jobs/x/checkout/run.sh"],
        "env": { "ONEIRON_JOB_KEY": "job-cache/first" },
        "cwd": "/data/oneiron-jobs/x",
        "read": ["/usr", "/data/oneiron-jobs/x"],
        "write": ["/data/oneiron-jobs/x/out"],
        "protected": [],
        "devices_allowed": [],
        "devices_denied": [],
        "hidden_pids": [1],
        "host_network_namespace": "net:[4026531840]",
        "require": []
    }))
    .expect("an exec file");
    let mount = PathBuf::from(JOB_CACHE_MOUNT_DEFAULT);
    let mut exec = before.clone();
    add_to_exec(
        &mut exec,
        &JobCacheView {
            mount: mount.clone(),
            kept: true,
        },
    );
    assert_eq!(
        exec.write,
        [PathBuf::from("/data/oneiron-jobs/x/out"), mount.clone()]
    );
    assert_eq!(
        exec.env.get(JOB_CACHE_ENV).map(String::as_str),
        Some(JOB_CACHE_MOUNT_DEFAULT)
    );
    assert_eq!(
        exec.env.get(JOB_CACHE_STATE_ENV).map(String::as_str),
        Some("kept")
    );
    assert_eq!(exec.read, before.read, "a cache adds no read path");
    let mut cold = before.clone();
    add_to_exec(&mut cold, &JobCacheView { mount, kept: false });
    assert_eq!(
        cold.env.get(JOB_CACHE_STATE_ENV).map(String::as_str),
        Some("cold")
    );
}
