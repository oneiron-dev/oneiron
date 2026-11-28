//! `oneiron job-prepare <id>` (root, the unit's `ExecStartPre=+`) and its
//! gate, `oneiron job-prepare --after-exec <id>` (root, `ExecStartPost=+`).
//!
//! The prepare step reads `launch.json` as untrusted input (pass 33, 7.6):
//! the key must hash to the unit's instance, the pin must pass the node
//! file's own admission check again, and every limit must fit the root-owned
//! ceilings. It then publishes the payload it checked as the unit's bind
//! source, sets this job's limits on the unit, arms the cutoff, and writes
//! `exec.json` where only the job account can read it. Any no fails the unit
//! before a workload process exists. The gate is [`super::gate`].

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use super::super::jobs::{JobKeyId, LaunchFile};
use super::super::wire::NetworkMode;
use super::capabilities::kernel_facts;
use super::control::CONTROL_SERVICE_UNIT_PATH;
use super::device_files;
use super::exchange::{publish_payload, write_exchange};
use super::records::{
    BoundReport, BoundRequirement, CutoffPlan, ExecFile, PROVED_INSIDE, PreparedRecord, ScopeBound,
    enforced_by_kernel, first_unmet, not_enforced,
};
use super::safe_fs::{
    self, boot_id, boot_ns, borrow, make_dir_beneath, open_dir_beneath, open_dir_path, read_beneath,
};
use super::step::{RECORD_MAX_BYTES, StepArgs, StepContext};
use super::systemd_unit::{SYSTEMCTL_TIMEOUT, run_tool, show};
use super::unit_file::{control_service_renews, installed_runtime_max_secs};
use super::{
    AWAKE_UNIT_PREFIX, CUTOFF_UNIT_PREFIX, PREPARED_FILE_NAME, UNIT_MEMORY_FLOOR_MIB,
    UNIT_TEMPLATE_PATH,
};

const NANOS_PER_SEC: u64 = 1_000_000_000;

/// The cutoff timer fires this much before the stop time: its accuracy
/// (`AccuracySec=100ms`) plus the cutoff step's start and its stop request,
/// so the TERM is sent by the stop time, not after it.
pub(super) const CUTOFF_MARGIN_MS: u64 = 500;

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
        return super::gate::run(args);
    }
    let context = match StepContext::open(args) {
        Ok(context) => context,
        Err(why) => {
            journal_line!("job-prepare: {why}");
            return 1;
        }
    };
    // A key starts once. A second start of a unit whose prepare step ran
    // keeps the first record and starts nothing.
    match context.read_record::<PreparedRecord>(PREPARED_FILE_NAME) {
        Ok(None) => {}
        Ok(Some(_)) => {
            journal_line!(
                "job-prepare: {} was prepared before; a key starts once",
                context.unit()
            );
            return 1;
        }
        Err(why) => {
            journal_line!("job-prepare: {why}");
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
        required: Vec::new(),
        fence: Vec::new(),
        session_until_boot_ns: None,
    };
    let outcome = prepare(&context, &mut record);
    if let Err(why) = &outcome {
        record.refusal = Some(why.clone());
        journal_line!("job-prepare: refused {}: {why}", context.unit());
    }
    if let Err(why) = context.write_record(PREPARED_FILE_NAME, &record) {
        journal_line!("job-prepare: {why}");
        return 1;
    }
    i32::from(outcome.is_err())
}

fn prepare(context: &StepContext, record: &mut PreparedRecord) -> Result<(), String> {
    if let Some(why) = &context.args.host_namespace_error {
        return Err(format!("host_mount_namespace_not_entered: {why}"));
    }
    let settings = &context.settings;
    let instance = &context.args.instance;
    let bytes = read_beneath(
        borrow(&context.control),
        "launch.json",
        RECORD_MAX_BYTES,
        None,
    )
    .map_err(|error| format!("launch_file_unreadable: {error}"))?
    .ok_or("launch_file_missing")?;
    let launch: LaunchFile =
        serde_json::from_slice(&bytes).map_err(|error| format!("launch_file_invalid: {error}"))?;
    if JobKeyId::for_key(&launch.key).as_str() != instance {
        return Err("key_not_instance: launch.json names another key than this unit's".to_owned());
    }
    // Only a key that names this unit's instance goes into the record.
    record.key.clone_from(&launch.key);
    if launch.boot_id != record.boot_id {
        return Err("launch_from_another_boot".to_owned());
    }
    let sampled = boot_ns();
    if launch.launch_boot_ns > sampled {
        return Err(
            "launch_in_the_future: launch.json's launch time is after this boot's clock".to_owned(),
        );
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
    // A session's renewals need the control handler `install` writes since
    // sessions: an older one would refuse the first renewal, at the end of
    // the first paid chunk, so the launch is refused now (row W1).
    if template.session_max_secs().is_some()
        && !std::fs::read_to_string(CONTROL_SERVICE_UNIT_PATH)
            .is_ok_and(|service| control_service_renews(&service))
    {
        return Err(
            "template_outdated: the job control service predates sessions: run `oneiron execution-node install` again"
                .to_owned(),
        );
    }
    let unit = context.unit();
    effective_stop_grace_matches(&unit, settings.stop_grace_secs)?;
    let protected = installed_protected_paths(&unit_text, &settings.state_dir);

    let mut allowed = Vec::new();
    for device_id in leased_device_ids(&launch)? {
        allowed.extend(device_files::files_of(&device_id, &settings.device_files)?);
    }
    allowed.sort();
    allowed.dedup();
    let denied = device_files::files_denied(&allowed, &settings.device_files);
    record.devices = allowed
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    let memory_mib = launch.host_memory_mib;
    if memory_mib == 0 || memory_mib < launch.pin.request.memory_mib {
        return Err(
            "memory_limit_below_request: launch.json's host memory is below the pin's memory"
                .to_owned(),
        );
    }
    if memory_mib > template.memory_gib.saturating_mul(1024) {
        return Err("request_above_ceiling: host_memory_mib".to_owned());
    }
    let cpu_threads = match launch.pin.request.cpu_threads {
        0 => template.cpu_threads,
        threads => threads,
    };

    let stop_at_boot_ns = launch
        .launch_boot_ns
        .saturating_add((maximum - settings.stop_grace_secs).saturating_mul(NANOS_PER_SEC));
    if stop_at_boot_ns <= sampled {
        return Err("cutoff_passed: the launch is older than its maximum".to_owned());
    }

    let payload_path = settings.work_dir.join(instance);
    let payload = prepare_payload(context, &payload_path)?;
    publish_payload(instance, &payload)?;
    let cache = super::job_cache::prepare(context, &launch, template, &unit_text, &payload)?;
    drop(payload);
    let mut exec = exec_file(
        context,
        &launch,
        template,
        &payload_path,
        &allowed,
        &denied,
        protected,
    )?;
    if let Some(cache) = &cache {
        super::job_cache::add_to_exec(&mut exec, cache);
    }
    write_exchange(context, &exec)?;
    record.required.clone_from(&template.require);
    record.fence = exec
        .read
        .iter()
        .map(|path| format!("read {}", path.display()))
        .chain(
            exec.write
                .iter()
                .map(|path| format!("write {}", path.display())),
        )
        .collect();

    // The unit's own steps count against the cap: never below the floor.
    let memory_bytes = memory_mib
        .max(UNIT_MEMORY_FLOOR_MIB)
        .saturating_mul(1 << 20);
    let mut properties = vec![
        format!("MemoryMax={memory_bytes}"),
        format!("TasksMax={}", template.tasks_max),
        format!("CPUQuota={}%", u64::from(cpu_threads).saturating_mul(100)),
    ];
    properties.extend(
        allowed
            .iter()
            .map(|path| format!("DeviceAllow={} rw", path.display())),
    );
    set_properties(&unit, &properties).map_err(|why| format!("unit_limits_not_set: {why}"))?;
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
    let group = unit_cgroup(&unit);
    let tasks = cgroup_file(group.as_deref(), "pids.max");
    if tasks.as_deref() != Some(template.tasks_max.to_string().as_str()) {
        // The cgroup's own controller list says whether the pids controller
        // was given to this unit at all (qualification q2: a container whose
        // root cgroup holds a process enables none).
        let controllers = cgroup_file(group.as_deref(), "cgroup.controllers");
        return Err(format!(
            "tasks_cap_not_applied: pids.max is {} where TasksMax={} (cgroup {}, controllers [{}])",
            tasks.as_deref().unwrap_or("unreadable"),
            template.tasks_max,
            group
                .as_deref()
                .map_or_else(|| "unknown".to_owned(), |path| path.display().to_string()),
            controllers.as_deref().unwrap_or("unreadable")
        ));
    }
    record.configured = configured_bounds(
        &unit,
        group.as_deref(),
        write_rate_applied,
        !exec.devices_denied.is_empty(),
    );
    // job-exec proves its bounds from inside; every other required bound is
    // judged here, from the unit's effective properties and its cgroup.
    let outside: Vec<BoundRequirement> = template
        .require
        .iter()
        .copied()
        .filter(|requirement| !PROVED_INSIDE.contains(&requirement.bound))
        .collect();
    if let Some(unmet) = first_unmet(&outside, &record.configured) {
        return Err(format!("required_bound_not_given: {unmet}"));
    }

    // A session's run may have its cutoff moved by renewals, up to the
    // launch plus the template's longest run (row W1).
    record.session_until_boot_ns = template.session_max_secs().map(|secs| {
        launch
            .launch_boot_ns
            .saturating_add(secs.saturating_mul(NANOS_PER_SEC))
    });
    // The cutoff stops the unit at a fixed boot-clock time: its delay is taken
    // from the clock just before the timer is made.
    let cutoff_unit = format!("{CUTOFF_UNIT_PREFIX}{instance}");
    let renewable = record.session_until_boot_ns.is_some();
    arm_cutoff(context, &cutoff_unit, stop_at_boot_ns, renewable)?;
    record.cutoff = Some(CutoffPlan {
        unit: format!("{cutoff_unit}.timer"),
        stop_at_boot_ns,
        stop_grace_secs: settings.stop_grace_secs,
    });
    record.awake_unit = hold_awake(&unit, instance);
    Ok(())
}

/// The device ids `launch` leases, checked against the pin's claims: each
/// lease names a claim of the request, each claim has exactly its count of
/// leases, and no device is leased twice. A request with no device claim
/// leases none, and its unit opens no device.
fn leased_device_ids(launch: &LaunchFile) -> Result<Vec<String>, String> {
    let claims = &launch.pin.request.devices;
    let mut leased = vec![0_u32; claims.len()];
    let mut ids = BTreeSet::new();
    for lease in &launch.devices {
        let count = leased
            .get_mut(lease.claim)
            .ok_or_else(|| format!("device_lease_without_claim: claim {}", lease.claim))?;
        *count = count.saturating_add(1);
        if !ids.insert(lease.device_id.clone()) {
            return Err(format!("device_leased_twice: {}", lease.device_id));
        }
    }
    for (index, (count, claim)) in leased.iter().zip(claims).enumerate() {
        if *count != claim.count {
            return Err(format!(
                "device_leases_not_claims: claim {index} asks {} and has {count}",
                claim.count
            ));
        }
    }
    Ok(ids.into_iter().collect())
}

/// The unit's effective stop timeout (its file and every drop-in) is the
/// node file's stop grace, so the cutoff's TERM comes a whole grace before
/// the maximum and the KILL by it.
fn effective_stop_grace_matches(unit: &str, stop_grace_secs: u64) -> Result<(), String> {
    let found =
        show(unit, &["TimeoutStopUSec"]).map_err(|why| format!("stop_grace_unknown: {why}"))?;
    let text = found.get("TimeoutStopUSec").map_or("", String::as_str);
    match timespan_usec(text) {
        Some(usec) if usec == stop_grace_secs.saturating_mul(1_000_000) => Ok(()),
        _ => Err(format!(
            "stop_grace_not_unit_timeout: the unit's TimeoutStopSec is {text:?} and the node file's stop grace {stop_grace_secs} s: run `oneiron execution-node install` again"
        )),
    }
}

/// A systemd time span as `systemctl show` prints it (`10s`, `1min 30s`,
/// `500ms`), in microseconds; `None` for `infinity` or a word it does not
/// know.
#[must_use]
pub(super) fn timespan_usec(text: &str) -> Option<u64> {
    let mut total: u64 = 0;
    let mut any = false;
    for word in text.split_whitespace() {
        let digits = word.find(|c: char| !c.is_ascii_digit())?;
        let (number, unit) = word.split_at(digits);
        let number: u64 = number.parse().ok()?;
        let scale: u64 = match unit {
            "us" => 1,
            "ms" => 1_000,
            "s" => 1_000_000,
            "min" => 60_000_000,
            "h" => 3_600_000_000,
            "d" => 86_400_000_000,
            _ => return None,
        };
        total = total.checked_add(number.checked_mul(scale)?)?;
        any = true;
    }
    any.then_some(total)
}

/// The unit's cgroup directory under `/sys/fs/cgroup`, from the service
/// manager.
fn unit_cgroup(unit: &str) -> Option<PathBuf> {
    let found = show(unit, &["ControlGroup"]).ok()?;
    let group = found
        .get("ControlGroup")
        .filter(|group| !group.is_empty())?;
    Some(Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/')))
}

/// One file of the unit's cgroup, trimmed: what the kernel holds now, not
/// only what the service manager accepted.
fn cgroup_file(group: Option<&Path>, name: &str) -> Option<String> {
    let text = std::fs::read_to_string(group?.join(name)).ok()?;
    Some(text.trim().to_owned())
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
/// the job account. Returns the payload directory, open: the unit's bind
/// source is made from this descriptor, never from the path again.
fn prepare_payload(context: &StepContext, payload_path: &Path) -> Result<OwnedFd, String> {
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
    Ok(payload)
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
    env.insert(
        "TMPDIR".to_owned(),
        payload.join("tmp").display().to_string(),
    );
    for (name, value) in &template.env {
        env.insert(name.clone(), value.clone());
    }
    env.insert("ONEIRON_JOB_KEY".to_owned(), launch.key.clone());
    env.insert(
        "ONEIRON_JOB_OUT".to_owned(),
        payload.join("out").display().to_string(),
    );
    env.insert(
        "ONEIRON_JOB_LOG".to_owned(),
        payload.join("log").display().to_string(),
    );
    env.insert(
        "ONEIRON_JOB_CHECKOUT".to_owned(),
        checkout.display().to_string(),
    );
    let cards: Vec<&str> = launch
        .devices
        .iter()
        .map(|lease| lease.device_id.as_str())
        .filter(|id| id.starts_with("GPU-"))
        .collect();
    if !cards.is_empty() {
        env.insert("CUDA_VISIBLE_DEVICES".to_owned(), cards.join(","));
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
        host_network_namespace: safe_fs::host_network_namespace(),
        require: template.require.clone(),
        log_max_bytes: template.log_max_bytes(),
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

fn set_properties(unit: &str, properties: &[String]) -> Result<(), String> {
    let mut args = vec!["set-property", "--runtime", unit];
    args.extend(properties.iter().map(String::as_str));
    run_tool("systemctl", &args, SYSTEMCTL_TIMEOUT).map(drop)
}

/// The cutoff: a transient timer `cutoff_unit` of the service manager that
/// runs `job-cutoff` at `stop_at_boot_ns` on the boot clock, less its
/// margin. The engine's account may not stop it. A session's timer
/// (`renewable`) names its stop time, so once a renewal armed a later one it
/// stops nothing (row W1); a job's names none, and its cutoff stops the unit
/// before it reads anything. A session's timer is armed only once the
/// service manager runs it and it waits (`systemd-run` waits for its start,
/// then [`cutoff_timer_armed`]), since a renewal stops the timer it replaces.
///
/// # Errors
///
/// Too little time is left to arm it (`cutoff_passed`), or the service
/// manager did not take it (`cutoff_not_armed`).
pub(super) fn arm_cutoff(
    context: &StepContext,
    cutoff_unit: &str,
    stop_at_boot_ns: u64,
    renewable: bool,
) -> Result<(), String> {
    let binary = std::env::current_exe().map_err(|error| format!("binary_unknown: {error}"))?;
    let delay_ms = (stop_at_boot_ns.saturating_sub(boot_ns()) / 1_000_000)
        .checked_sub(CUTOFF_MARGIN_MS)
        .filter(|delay| *delay > 0)
        .ok_or("cutoff_passed: too little of the maximum is left to arm the cutoff")?;
    let on_active = format!("--on-active={delay_ms}ms");
    let unit_flag = format!("--unit={cutoff_unit}");
    let binary = binary.display().to_string();
    let node_file = context.args.node_file.display().to_string();
    let stop_at = stop_at_boot_ns.to_string();
    let mut args: Vec<&str> = Vec::new();
    if !renewable {
        args.push("--no-block");
    }
    args.extend([
        "--collect",
        "--quiet",
        unit_flag.as_str(),
        on_active.as_str(),
        "--timer-property=AccuracySec=100ms",
        "--timer-property=RemainAfterElapse=no",
        binary.as_str(),
        "job-cutoff",
        "--node-file",
        node_file.as_str(),
        "--engine-account",
        context.args.engine_account.as_str(),
    ]);
    if renewable {
        args.extend(["--stop-at", stop_at.as_str()]);
    }
    args.push(context.args.instance.as_str());
    run_tool("systemd-run", &args, SYSTEMCTL_TIMEOUT)
        .map_err(|why| format!("cutoff_not_armed: {why}"))?;
    // A start job that finished does not prove the timer waits (a condition
    // can leave it inactive): a session's timer is checked before anything
    // relies on it.
    if renewable {
        cutoff_timer_armed(&format!("{cutoff_unit}.timer"))?;
    }
    Ok(())
}

/// `Ok` while the cutoff timer `timer` (a `.timer` unit) is armed: the
/// service manager runs it and it waits for its elapse.
///
/// # Errors
///
/// `cutoff_not_armed`, with the timer's state, or the service manager's
/// error.
pub(super) fn cutoff_timer_armed(timer: &str) -> Result<(), String> {
    let found = show(timer, &["ActiveState", "SubState"])
        .map_err(|why| format!("cutoff_not_armed: {timer}: {why}"))?;
    let active = found.get("ActiveState").map_or("", String::as_str);
    let sub_state = found.get("SubState").map_or("", String::as_str);
    if active == "active" && sub_state == "waiting" {
        Ok(())
    } else {
        Err(format!(
            "cutoff_not_armed: the timer {timer} is {active:?} ({sub_state:?})"
        ))
    }
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
    .map(|_| format!("{awake}.service"))
}

/// Each bound as the unit's effective properties and this kernel give it.
fn configured_bounds(
    unit: &str,
    group: Option<&Path>,
    write_rate_failure: Option<String>,
    has_denied_device: bool,
) -> BTreeMap<ScopeBound, BoundReport> {
    let facts = kernel_facts();
    let found = show(
        unit,
        &[
            "KillMode",
            "PrivateNetwork",
            "ProtectProc",
            "ProtectSystem",
            "DevicePolicy",
        ],
    )
    .unwrap_or_default();
    let is = |name: &str, value: &str| found.get(name).is_some_and(|got| got == value);
    let cgroup_file = |name: &str| cgroup_file(group, name);
    let memory_max = cgroup_file("memory.max");
    let io_max = cgroup_file("io.max");
    let on = |holds: bool, evidence: String| {
        if holds {
            enforced_by_kernel(evidence)
        } else {
            not_enforced(evidence)
        }
    };
    let unified = !facts.cgroup_controllers.is_empty();
    let mut out = BTreeMap::new();
    out.insert(
        ScopeBound::TreeKill,
        on(
            unified && is("KillMode", "control-group"),
            format!(
                "KillMode={}",
                found.get("KillMode").map_or("?", String::as_str)
            ),
        ),
    );
    out.insert(
        ScopeBound::CutoffWithoutEngine,
        enforced_by_kernel("the service manager's cutoff timer, armed before the workload"),
    );
    out.insert(
        ScopeBound::Emptiness,
        on(unified, "cgroup v2 cgroup.events".to_owned()),
    );
    out.insert(
        ScopeBound::MemoryCap,
        on(
            memory_max
                .as_deref()
                .is_some_and(|value| value.parse::<u64>().is_ok()),
            format!(
                "memory.max {}",
                memory_max.as_deref().unwrap_or("unreadable")
            ),
        ),
    );
    let cpu_max = cgroup_file("cpu.max");
    out.insert(
        ScopeBound::CpuCap,
        on(
            cpu_max
                .as_deref()
                .and_then(|text| text.split_whitespace().next())
                .is_some_and(|quota| quota.parse::<u64>().is_ok()),
            format!("cpu.max {}", cpu_max.as_deref().unwrap_or("unreadable")),
        ),
    );
    out.insert(
        ScopeBound::FileWall,
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
        ScopeBound::NetworkClosed,
        on(
            is("PrivateNetwork", "yes"),
            format!(
                "PrivateNetwork={}",
                found.get("PrivateNetwork").map_or("?", String::as_str)
            ),
        ),
    );
    out.insert(
        ScopeBound::DeviceClosure,
        on(
            is("DevicePolicy", "closed"),
            format!(
                "DevicePolicy={}{}",
                found.get("DevicePolicy").map_or("?", String::as_str),
                if has_denied_device {
                    ""
                } else {
                    "; no other device to try"
                }
            ),
        ),
    );
    out.insert(
        ScopeBound::ProcessesHidden,
        on(
            is("ProtectProc", "invisible"),
            format!(
                "ProtectProc={}",
                found.get("ProtectProc").map_or("?", String::as_str)
            ),
        ),
    );
    out.insert(
        ScopeBound::WriteRateCap,
        match (write_rate_failure, io_max.as_deref()) {
            (None, Some(text)) if text.contains("wbps=") && !text.contains("wbps=max") => {
                enforced_by_kernel(format!("io.max {text}"))
            }
            (None, text) => not_enforced(format!(
                "IOWriteBandwidthMax= accepted, but io.max holds no write rate ({}): no block device under the payload directory?",
                text.unwrap_or("unreadable")
            )),
            (Some(why), _) => not_enforced(format!("IOWriteBandwidthMax= not applied: {why}")),
        },
    );
    out
}
