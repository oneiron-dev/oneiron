//! `oneiron job-prepare <id>` (root, the unit's `ExecStartPre=+`) and its
//! gate, `oneiron job-prepare --after-exec <id>` (root, `ExecStartPost=+`).
//!
//! The prepare step reads `launch.json` as untrusted input (pass 33, 7.6):
//! the key must hash to the unit's instance, the pin must pass the node
//! file's own admission check again, and every limit must fit the root-owned
//! ceilings. It then sets this job's limits on the unit, arms the cutoff, and
//! writes `exec.json` where only the job account can read it. Any no fails
//! the unit before a workload process exists.
//!
//! The gate runs once `job-exec` has started: it reads `job-exec`'s report
//! from a pipe, records it with its verdict, and only then lets the workload
//! start. The record is root's, so whether the workload started is never the
//! workload's word.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::super::jobs::{JobKeyId, LaunchFile};
use super::super::wire::NetworkMode;
use super::capabilities::kernel_facts;
use super::device_files;
use super::records::{
    BoundProof, CutoffPlan, ExecFile, PreparedRecord, ScopeRecord, ScopeReport, bound,
};
use super::safe_fs::{
    self, borrow, boot_id, boot_ns, make_dir_beneath, make_fifo_beneath, open_dir_beneath,
    open_dir_path, read_beneath, remove_beneath, write_beneath,
};
use super::step::{RECORD_MAX_BYTES, StepArgs, StepContext};
use super::systemd_unit::{SYSTEMCTL_TIMEOUT, run_tool, show};
use super::unit_file::installed_runtime_max_secs;
use super::{
    AWAKE_UNIT_PREFIX, CUTOFF_UNIT_PREFIX, EXCHANGE_ROOT, EXEC_FILE_NAME, GATE_GO, GO_PIPE_NAME,
    PREPARED_FILE_NAME, REPORT_PIPE_NAME, SCOPE_FILE_NAME, UNIT_TEMPLATE_PATH,
};

const NANOS_PER_SEC: u64 = 1_000_000_000;

/// The system paths every workload may read and run: its interpreter's
/// libraries, the system's configuration, and the kernel's views.
const SYSTEM_READ_PATHS: [&str; 9] = [
    "/usr", "/lib", "/lib64", "/lib32", "/bin", "/sbin", "/etc", "/proc", "/sys",
];

/// The pseudo devices every workload may read and write.
const PSEUDO_DEVICES: [&str; 5] = [
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
];

/// At most this many of the engine's processes are named for the proof that
/// the job cannot see them.
const HIDDEN_PIDS_MAX: usize = 64;

/// The prepare step. Returns the process exit status.
#[must_use]
pub fn run(args: StepArgs) -> i32 {
    if args.after_exec {
        return gate(args);
    }
    let context = match StepContext::open(args) {
        Ok(context) => context,
        Err(why) => {
            eprintln!("job-prepare: {why}");
            return 1;
        }
    };
    // A key starts once. A second start of a unit whose prepare step ran
    // keeps the first record and starts nothing.
    match context.read_record::<PreparedRecord>(PREPARED_FILE_NAME) {
        Ok(None) => {}
        Ok(Some(_)) => {
            eprintln!("job-prepare: {} was prepared before; a key starts once", context.unit());
            return 1;
        }
        Err(why) => {
            eprintln!("job-prepare: {why}");
            return 1;
        }
    }
    let mut record = PreparedRecord {
        key: String::new(),
        instance: context.args.instance.clone(),
        refusal: None,
        boot_id: boot_id(),
        at_boot_ns: boot_ns(),
        account: context.settings.job_account.clone(),
        properties: Vec::new(),
        devices: Vec::new(),
        cutoff: None,
        awake_unit: None,
        configured: BTreeMap::new(),
    };
    let outcome = prepare(&context, &mut record);
    if let Err(why) = &outcome {
        record.refusal = Some(why.clone());
        eprintln!("job-prepare: refused {}: {why}", context.unit());
    }
    if let Err(why) = context.write_record(PREPARED_FILE_NAME, &record) {
        eprintln!("job-prepare: {why}");
        return 1;
    }
    i32::from(outcome.is_err())
}

fn prepare(context: &StepContext, record: &mut PreparedRecord) -> Result<(), String> {
    let settings = &context.settings;
    let instance = &context.args.instance;
    let bytes = read_beneath(borrow(&context.control), "launch.json", RECORD_MAX_BYTES, None)
        .map_err(|error| format!("launch_file_unreadable: {error}"))?
        .ok_or("launch_file_missing")?;
    let launch: LaunchFile = serde_json::from_slice(&bytes)
        .map_err(|error| format!("launch_file_invalid: {error}"))?;
    record.key.clone_from(&launch.key);
    if JobKeyId::for_key(&launch.key).as_str() != instance {
        return Err("key_not_instance: launch.json names another key than this unit's".to_owned());
    }
    if launch.boot_id != record.boot_id {
        return Err("launch_from_another_boot".to_owned());
    }
    settings.admit_pin(&launch.pin)?;
    let template = settings
        .templates
        .get(&launch.pin.template)
        .ok_or("template_unknown")?;
    if launch.pin.network != NetworkMode::None {
        return Err(
            "network_host_unit_not_built: this machine's job unit has only a private network"
                .to_owned(),
        );
    }
    let maximum = launch.maximum_secs;
    if maximum == 0 || maximum > launch.pin.request.maximum_secs {
        return Err("maximum_above_pin".to_owned());
    }
    if maximum <= settings.stop_grace_secs {
        return Err("maximum_within_stop_grace".to_owned());
    }
    let unit_text = std::fs::read_to_string(UNIT_TEMPLATE_PATH)
        .map_err(|error| format!("unit_template_unreadable: {error}"))?;
    if installed_runtime_max_secs(&unit_text).is_none_or(|ceiling| maximum > ceiling) {
        return Err(
            "unit_runtime_max_below_maximum: run `oneiron execution-node install` again".to_owned(),
        );
    }
    let protected = installed_protected_paths(&unit_text, &settings.state_dir);

    let allowed = if launch.device_id.is_empty() {
        Vec::new()
    } else {
        device_files::files_of(&launch.device_id, &settings.device_files)?
    };
    let denied = device_files::files_denied(&allowed, &settings.device_files);
    record.devices = allowed.iter().map(|path| path.display().to_string()).collect();

    let stop_at_boot_ns = launch.launch_boot_ns.saturating_add(
        (maximum - settings.stop_grace_secs).saturating_mul(NANOS_PER_SEC),
    );
    let now = boot_ns();
    if stop_at_boot_ns <= now {
        return Err("cutoff_passed: the launch is older than its maximum".to_owned());
    }

    let payload_path = settings.work_dir.join(instance);
    prepare_payload(context, &payload_path)?;
    let exec = exec_file(context, &launch, template, &payload_path, &allowed, &denied, protected)?;
    write_exchange(context, &exec)?;

    let unit = context.unit();
    let memory_bytes = launch.pin.request.memory_mib.saturating_mul(1 << 20);
    let mut properties = vec![
        format!("MemoryMax={memory_bytes}"),
        format!("TasksMax={}", template.tasks_max),
    ];
    properties.extend(
        allowed
            .iter()
            .map(|path| format!("DeviceAllow={} rw", path.display())),
    );
    set_properties(&unit, &properties)
        .map_err(|why| format!("unit_limits_not_set: {why}"))?;
    let write_rate = format!(
        "IOWriteBandwidthMax={} {}",
        settings.work_dir.display(),
        template.write_mib_per_sec.saturating_mul(1 << 20)
    );
    let write_rate_applied = match set_properties(&unit, std::slice::from_ref(&write_rate)) {
        Ok(()) => {
            properties.push(write_rate);
            None
        }
        Err(why) => Some(why),
    };
    record.properties = properties;

    let binary = std::env::current_exe().map_err(|error| format!("binary_unknown: {error}"))?;
    let cutoff_unit = format!("{CUTOFF_UNIT_PREFIX}{instance}");
    let delay_ms = (stop_at_boot_ns - now) / 1_000_000;
    arm_cutoff(context, &binary, &cutoff_unit, delay_ms)
        .map_err(|why| format!("cutoff_not_armed: {why}"))?;
    record.cutoff = Some(CutoffPlan {
        unit: format!("{cutoff_unit}.timer"),
        stop_at_boot_ns,
        stop_grace_secs: settings.stop_grace_secs,
    });
    record.awake_unit = hold_awake(&unit, instance);
    record.configured = configured_bounds(&unit, write_rate_applied, !exec.devices_denied.is_empty());
    Ok(())
}

/// The protected paths the installed unit makes inaccessible (its
/// `InaccessiblePaths=`), so the proof checks exactly those.
pub(super) fn installed_protected_paths(unit_text: &str, state_dir: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = unit_text
        .lines()
        .filter_map(|line| line.strip_prefix("InaccessiblePaths="))
        .flat_map(str::split_whitespace)
        .map(|word| PathBuf::from(word.trim_start_matches('-')))
        .collect();
    if !paths.iter().any(|path| path == state_dir) {
        paths.push(state_dir.to_path_buf());
    }
    paths
}

/// The payload directory is the engine's, not a link, and traversable by
/// others; its checkout is there; `out`, `tmp` and `log` are made fresh for
/// the job account.
fn prepare_payload(context: &StepContext, payload_path: &Path) -> Result<(), String> {
    let work = open_dir_path(&context.settings.work_dir)
        .map_err(|error| format!("work_dir_unreadable: {error}"))?;
    let payload = open_dir_beneath(borrow(&work), OsStr::new(&context.args.instance))
        .map_err(|error| format!("payload_missing: {}: {error}", payload_path.display()))?;
    let found = safe_fs::facts(borrow(&payload)).map_err(|error| error.to_string())?;
    if found.uid != context.engine_uid {
        return Err("payload_not_engines".to_owned());
    }
    if found.mode & 0o001 == 0 {
        return Err("payload_not_traversable: the job account needs o+x on it".to_owned());
    }
    let checkout = open_dir_beneath(borrow(&payload), OsStr::new("checkout"))
        .map_err(|error| format!("checkout_missing: {error}"))?;
    let checkout_mode = safe_fs::facts(borrow(&checkout))
        .map_err(|error| error.to_string())?
        .mode;
    if checkout_mode & 0o005 != 0o005 {
        return Err("checkout_not_readable: the job account needs o+rx on it".to_owned());
    }
    for name in ["out", "tmp", "log"] {
        make_dir_beneath(
            borrow(&payload),
            name,
            0o755,
            (context.job_uid, context.job_gid),
        )
        .map_err(|error| format!("payload_not_fresh: {name}: {error}"))?;
    }
    Ok(())
}

fn exec_file(
    context: &StepContext,
    launch: &LaunchFile,
    template: &super::super::node_settings::NodeTemplate,
    payload: &Path,
    allowed: &[PathBuf],
    denied: &[PathBuf],
    protected: Vec<PathBuf>,
) -> Result<ExecFile, String> {
    let checkout = payload.join("checkout");
    let mut argv = template.interpreter.clone();
    argv.push(checkout.join(&launch.pin.entry).display().to_string());
    argv.extend(launch.pin.args.iter().cloned());
    let mut env = BTreeMap::new();
    env.insert("PATH".to_owned(), "/usr/local/bin:/usr/bin:/bin".to_owned());
    env.insert("LANG".to_owned(), "C.UTF-8".to_owned());
    env.insert("HOME".to_owned(), payload.join("tmp").display().to_string());
    env.insert("TMPDIR".to_owned(), payload.join("tmp").display().to_string());
    for (name, value) in &template.env {
        env.insert(name.clone(), value.clone());
    }
    env.insert("ONEIRON_JOB_KEY".to_owned(), launch.key.clone());
    env.insert("ONEIRON_JOB_OUT".to_owned(), payload.join("out").display().to_string());
    env.insert("ONEIRON_JOB_LOG".to_owned(), payload.join("log").display().to_string());
    env.insert("ONEIRON_JOB_CHECKOUT".to_owned(), checkout.display().to_string());
    if launch.device_id.starts_with("GPU-") {
        env.insert("CUDA_VISIBLE_DEVICES".to_owned(), launch.device_id.clone());
    }
    let mut read: Vec<PathBuf> = SYSTEM_READ_PATHS.iter().map(PathBuf::from).collect();
    read.push(payload.to_path_buf());
    read.push(checkout);
    read.extend(template.read.iter().cloned());
    let mut write: Vec<PathBuf> = ["out", "tmp", "log"]
        .iter()
        .map(|name| payload.join(name))
        .collect();
    write.extend(template.write.iter().cloned());
    write.extend(PSEUDO_DEVICES.iter().map(PathBuf::from));
    write.extend(allowed.iter().cloned());
    let mut hidden_pids = vec![1];
    hidden_pids.extend(processes_of(context.engine_uid));
    let mut protected = protected;
    protected.push(context.engine_home.clone());
    protected.sort();
    protected.dedup();
    Ok(ExecFile {
        key: launch.key.clone(),
        instance: context.args.instance.clone(),
        probe: false,
        argv,
        env,
        cwd: payload.to_path_buf(),
        read,
        write,
        protected,
        devices_allowed: allowed.to_vec(),
        devices_denied: denied.to_vec(),
        hidden_pids,
        require: template.require.clone(),
    })
}

/// Process ids owned by `uid`, at most [`HIDDEN_PIDS_MAX`].
fn processes_of(uid: u32) -> Vec<u32> {
    use std::os::unix::fs::MetadataExt as _;
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            (entry.metadata().ok()?.uid() == uid).then_some(pid)
        })
        .take(HIDDEN_PIDS_MAX)
        .collect()
}

/// Makes the job's exchange directory fresh (root, mode 0750, the job
/// account's group): `exec.json` and the two gate pipes.
///
/// # Errors
///
/// A step that failed.
pub fn write_exchange(context: &StepContext, exec: &ExecFile) -> Result<(), String> {
    let root = exchange_root().map_err(|why| format!("exchange_root: {why}"))?;
    let name = exec.instance.as_str();
    if let Ok(stale) = open_dir_beneath(borrow(&root), OsStr::new(name)) {
        for file in [EXEC_FILE_NAME, REPORT_PIPE_NAME, GO_PIPE_NAME] {
            remove_beneath(borrow(&stale), file).map_err(|error| error.to_string())?;
        }
        drop(stale);
        let c = std::ffi::CString::new(name).map_err(|error| error.to_string())?;
        // SAFETY: c is NUL terminated; AT_REMOVEDIR removes an empty dir.
        if unsafe { libc::unlinkat(root.as_raw_fd(), c.as_ptr(), libc::AT_REMOVEDIR) } < 0 {
            return Err(format!("exchange_not_fresh: {}", std::io::Error::last_os_error()));
        }
    }
    let exchange = make_dir_beneath(borrow(&root), name, 0o750, (0, context.job_gid))
        .map_err(|error| format!("exchange_dir: {error}"))?;
    let bytes = serde_json::to_vec_pretty(exec).map_err(|error| error.to_string())?;
    write_beneath(borrow(&exchange), EXEC_FILE_NAME, &bytes, 0o640, Some((0, context.job_gid)))
        .map_err(|error| format!("exec_file: {error}"))?;
    make_fifo_beneath(borrow(&exchange), REPORT_PIPE_NAME, 0o620, context.job_gid)
        .map_err(|error| format!("report_pipe: {error}"))?;
    make_fifo_beneath(borrow(&exchange), GO_PIPE_NAME, 0o640, context.job_gid)
        .map_err(|error| format!("go_pipe: {error}"))?;
    Ok(())
}

/// `/run/oneiron-jobs`, made root's (mode 0755) when absent.
fn exchange_root() -> Result<OwnedFd, String> {
    let path = Path::new(EXCHANGE_ROOT);
    if !path.exists() {
        std::fs::create_dir(path).map_err(|error| error.to_string())?;
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .map_err(|error| error.to_string())?;
    }
    safe_fs::require_root_owned(path)?;
    open_dir_path(path).map_err(|error| error.to_string())
}

fn set_properties(unit: &str, properties: &[String]) -> Result<(), String> {
    let mut args = vec!["set-property", "--runtime", unit];
    args.extend(properties.iter().map(String::as_str));
    run_tool("systemctl", &args, SYSTEMCTL_TIMEOUT).map(drop)
}

/// The cutoff: a transient timer of the service manager that runs
/// `job-cutoff` at the stop time. The engine's account may not stop it.
fn arm_cutoff(
    context: &StepContext,
    binary: &Path,
    cutoff_unit: &str,
    delay_ms: u64,
) -> Result<(), String> {
    let on_active = format!("--on-active={delay_ms}ms");
    let unit_flag = format!("--unit={cutoff_unit}");
    let binary = binary.display().to_string();
    let node_file = context.args.node_file.display().to_string();
    run_tool(
        "systemd-run",
        &[
            "--no-block",
            "--collect",
            "--quiet",
            &unit_flag,
            &on_active,
            "--timer-property=AccuracySec=100ms",
            "--timer-property=RemainAfterElapse=no",
            &binary,
            "job-cutoff",
            "--node-file",
            &node_file,
            "--engine-account",
            &context.args.engine_account,
            &context.args.instance,
        ],
        SYSTEMCTL_TIMEOUT,
    )
    .map(drop)
}

/// The sleep inhibitor, held by a root unit bound to the job unit: it holds
/// with the engine down, and ends with the job unit. `None` when the
/// machine has no `systemd-inhibit` or the unit did not start.
fn hold_awake(unit: &str, instance: &str) -> Option<String> {
    let inhibit = super::systemd_unit::tool_path("systemd-inhibit")?;
    let sleep = super::systemd_unit::tool_path("sleep")?;
    let awake = format!("{AWAKE_UNIT_PREFIX}{instance}");
    let unit_flag = format!("--unit={awake}");
    let binds = format!("--property=BindsTo={unit}");
    let after = format!("--property=After={unit}");
    let why = format!("--why=job unit {unit} runs");
    run_tool(
        "systemd-run",
        &[
            "--no-block",
            "--collect",
            "--quiet",
            &unit_flag,
            &binds,
            &after,
            &inhibit.display().to_string(),
            "--what=sleep:idle",
            "--who=oneiron job",
            &why,
            "--mode=block",
            &sleep.display().to_string(),
            "infinity",
        ],
        SYSTEMCTL_TIMEOUT,
    )
    .ok()
    .map(|()| format!("{awake}.service"))
}

/// Each bound as the unit's effective properties and this kernel give it.
fn configured_bounds(
    unit: &str,
    write_rate_failure: Option<String>,
    has_denied_device: bool,
) -> BTreeMap<String, BoundProof> {
    let facts = kernel_facts();
    let found = show(
        unit,
        &[
            "KillMode",
            "PrivateNetwork",
            "ProtectProc",
            "ProtectSystem",
            "DevicePolicy",
            "MemoryMax",
            "ControlGroup",
        ],
    )
    .unwrap_or_default();
    let is = |name: &str, value: &str| found.get(name).is_some_and(|got| got == value);
    let on = |holds: bool, evidence: String| {
        if holds {
            BoundProof::kernel(evidence)
        } else {
            BoundProof::none(evidence)
        }
    };
    let unified = !facts.cgroup_controllers.is_empty();
    let mut out = BTreeMap::new();
    out.insert(
        bound::TREE_KILL.to_owned(),
        on(
            unified && is("KillMode", "control-group"),
            format!("KillMode={}", found.get("KillMode").map_or("?", String::as_str)),
        ),
    );
    out.insert(
        bound::CUTOFF_WITHOUT_ENGINE.to_owned(),
        BoundProof::kernel("the service manager's cutoff timer, armed before the workload"),
    );
    out.insert(
        bound::EMPTINESS.to_owned(),
        on(unified, "cgroup v2 cgroup.events".to_owned()),
    );
    out.insert(
        bound::MEMORY_CAP.to_owned(),
        on(
            facts.cgroup_controllers.contains("memory")
                && found.get("MemoryMax").is_some_and(|value| value != "infinity"),
            format!("MemoryMax={}", found.get("MemoryMax").map_or("?", String::as_str)),
        ),
    );
    out.insert(
        bound::CPU_CAP.to_owned(),
        BoundProof::none("this scope sets no CPU cap yet"),
    );
    out.insert(
        bound::FILE_WALL.to_owned(),
        on(
            is("ProtectSystem", "strict") && facts.landlock_abi >= 3,
            format!(
                "ProtectSystem={}, Landlock ABI {}",
                found.get("ProtectSystem").map_or("?", String::as_str),
                facts.landlock_abi
            ),
        ),
    );
    out.insert(
        bound::NETWORK_CLOSED.to_owned(),
        on(
            is("PrivateNetwork", "yes"),
            format!(
                "PrivateNetwork={}",
                found.get("PrivateNetwork").map_or("?", String::as_str)
            ),
        ),
    );
    out.insert(
        bound::DEVICE_CLOSURE.to_owned(),
        on(
            is("DevicePolicy", "closed"),
            format!(
                "DevicePolicy={}{}",
                found.get("DevicePolicy").map_or("?", String::as_str),
                if has_denied_device { "" } else { "; no other device to try" }
            ),
        ),
    );
    out.insert(
        bound::PROCESSES_HIDDEN.to_owned(),
        on(
            is("ProtectProc", "invisible"),
            format!("ProtectProc={}", found.get("ProtectProc").map_or("?", String::as_str)),
        ),
    );
    out.insert(
        bound::WRITE_RATE_CAP.to_owned(),
        match write_rate_failure {
            None => BoundProof::kernel("IOWriteBandwidthMax= on the payload device"),
            Some(why) => BoundProof::none(format!("IOWriteBandwidthMax= not applied: {why}")),
        },
    );
    out
}

/// The gate: reads `job-exec`'s report, records it with its verdict in
/// `scope.json`, and only then writes the go. Returns the exit status: 0
/// when the workload may start, 1 when the unit must fail.
#[must_use]
pub fn gate(args: StepArgs) -> i32 {
    let context = match StepContext::open(args) {
        Ok(context) => context,
        Err(why) => {
            eprintln!("job-prepare --after-exec: {why}");
            return 1;
        }
    };
    let deadline = Duration::from_secs(context.settings.unit_start_timeout_secs.saturating_sub(5).max(5));
    let verdict = read_and_judge(&context, deadline);
    let (report, refusal) = match verdict {
        Ok(report) => {
            let refusal = report.refusal.clone();
            (Some(report), refusal)
        }
        Err(why) => (None, Some(why)),
    };
    let go = if refusal.is_none() {
        match open_go(&context) {
            Ok(go) => Some(go),
            Err(why) => {
                return finish_gate(&context, report, Some(why), None);
            }
        }
    } else {
        None
    };
    finish_gate(&context, report, refusal, go)
}

fn finish_gate(
    context: &StepContext,
    report: Option<ScopeReport>,
    refusal: Option<String>,
    go: Option<OwnedFd>,
) -> i32 {
    let released = refusal.is_none() && go.is_some();
    let record = ScopeRecord {
        instance: context.args.instance.clone(),
        report,
        released,
        refusal: refusal.clone(),
        at_boot_ns: boot_ns(),
    };
    // Recorded and synced before the go: a workload that started always has
    // `released` on disk.
    if let Err(why) = context.write_record(SCOPE_FILE_NAME, &record) {
        eprintln!("job-prepare --after-exec: {why}");
        return 1;
    }
    let Some(go) = go else {
        eprintln!(
            "job-prepare --after-exec: {} refused: {}",
            context.unit(),
            refusal.as_deref().unwrap_or("no go")
        );
        return 1;
    };
    let mut file = std::fs::File::from(go);
    use std::io::Write as _;
    if let Err(error) = file.write_all(GATE_GO) {
        eprintln!("job-prepare --after-exec: the go did not reach job-exec: {error}");
        return 1;
    }
    0
}

/// Reads the report from the pipe and judges it against the template's
/// required bounds, from root's own copy of `exec.json`.
fn read_and_judge(context: &StepContext, deadline: Duration) -> Result<ScopeReport, String> {
    let exchange = open_dir_path(&context.exchange_path())
        .map_err(|error| format!("exchange_dir: {error}"))?;
    let exec: ExecFile = serde_json::from_slice(
        &read_beneath(borrow(&exchange), EXEC_FILE_NAME, RECORD_MAX_BYTES, Some(0))
            .map_err(|error| format!("exec_file: {error}"))?
            .ok_or("exec_file_missing")?,
    )
    .map_err(|error| format!("exec_file: {error}"))?;
    let bytes = read_pipe(&exchange, REPORT_PIPE_NAME, deadline)?;
    let mut report: ScopeReport =
        serde_json::from_slice(&bytes).map_err(|error| format!("report_invalid: {error}"))?;
    if report.instance != context.args.instance {
        return Err("report_for_another_instance".to_owned());
    }
    if report.refusal.is_none()
        && let Some(missing) = exec.require.iter().find(|name| {
            !report
                .proofs
                .get(name.as_str())
                .is_some_and(BoundProof::holds)
        })
    {
        report.refusal = Some(format!("required_bound_not_proved: {missing}"));
    }
    Ok(report)
}

/// Reads a pipe beneath `dir` to its end, waiting at most `deadline` for the
/// writer.
pub(super) fn read_pipe(dir: &OwnedFd, name: &str, deadline: Duration) -> Result<Vec<u8>, String> {
    let c = std::ffi::CString::new(name).map_err(|error| error.to_string())?;
    // SAFETY: c is NUL terminated; a non-blocking read end opens at once.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!("{name}: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: openat returned a new descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    if !safe_fs::facts(borrow(&fd)).is_ok_and(|found| found.is_fifo && found.uid == 0) {
        return Err(format!("{name}: not root's pipe"));
    }
    let started = Instant::now();
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let left = deadline.saturating_sub(started.elapsed());
        if left.is_zero() {
            return Err("report_late: job-exec sent no report in time".to_owned());
        }
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = libc::c_int::try_from(left.as_millis()).unwrap_or(libc::c_int::MAX);
        // SAFETY: one valid pollfd.
        let ready = unsafe { libc::poll(&raw mut poll, 1, millis) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("{name}: {error}"));
        }
        if ready == 0 {
            continue;
        }
        // SAFETY: buffer is writable for its length.
        let read = unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
        match read {
            0 => return Ok(bytes),
            n if n > 0 => {
                bytes.extend_from_slice(&buffer[..usize::try_from(n).unwrap_or(0)]);
                if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > RECORD_MAX_BYTES {
                    return Err("report_too_large".to_owned());
                }
            }
            _ => {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::WouldBlock
                    && error.kind() != std::io::ErrorKind::Interrupted
                {
                    return Err(format!("{name}: {error}"));
                }
                if poll.revents & libc::POLLHUP != 0 {
                    return Ok(bytes);
                }
            }
        }
    }
}

/// Opens the go pipe for writing: it succeeds only while `job-exec` holds
/// its read end, so a go is never written to nobody.
fn open_go(context: &StepContext) -> Result<OwnedFd, String> {
    let path = context.exchange_path().join(GO_PIPE_NAME);
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|error| error.to_string())?;
    // SAFETY: c is NUL terminated; a non-blocking write end fails with ENXIO
    // when no reader holds the pipe.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_WRONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "go_unread: job-exec holds no go pipe: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: open returned a new descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
