//! The scope half of `oneiron execution-node check` (pass 33, 7.6:
//! "`execution-node check` runs the same checks in a probe unit"). As root
//! it starts a transient unit with exactly the installed template's
//! properties, runs `job-exec` in it in probe mode, reads its report as the
//! gate would, and writes the report beside the node file, where the
//! engine's capability report reads it. Without root it prints the
//! capability report from what it can read.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::os::fd::AsFd as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use super::super::jobs::JobKeyId;
use super::super::node_settings::ExecutionNodeSettings;
use super::capabilities::{CheckReport, capabilities_of, check_report_path, kernel_facts};
use super::control::{CONTROL_SOCKET_PATH, CONTROL_SOCKET_UNIT};
use super::device_files;
use super::gate::{GateSocket, MainProcess, MainProcessWatch, read_report};
use super::records::{ExecFile, ScopeBound, ScopeReport};
use super::safe_fs::{self, account, boot_id, borrow, make_dir_beneath, open_dir_path};
use super::systemd_unit::{SYSTEMCTL_TIMEOUT, run_tool, show_within, tool_path};
use super::{EXCHANGE_ROOT, PROBE_UNIT_PREFIX, UNIT_TEMPLATE_PATH};

/// How long the probe unit may run.
const PROBE_TIMEOUT: Duration = Duration::from_secs(60);

/// How long the probe unit has to end once root closed its connection,
/// past [`PROBE_TIMEOUT`] when the report came late.
const PROBE_END_GRACE: Duration = Duration::from_secs(10);

/// How often the probe looks at its starter while it waits for it to end.
const STARTER_POLL: Duration = Duration::from_millis(50);

/// Whether the control socket is there: its socket unit removes the file
/// when it stops (`RemoveOnStop=yes`).
fn control_socket_listens() -> bool {
    use std::os::unix::fs::FileTypeExt as _;
    std::fs::symlink_metadata(CONTROL_SOCKET_PATH).is_ok_and(|found| found.file_type().is_socket())
}

/// Prints each bound's strength and returns what would refuse a job: a
/// machine without the minimum contract, or a template that requires a
/// bound this machine lacks.
#[must_use]
pub fn check_scope(node_file: &Path, settings: &ExecutionNodeSettings) -> Vec<String> {
    let facts = kernel_facts();
    let mut refusals = Vec::new();
    // SAFETY: geteuid has no preconditions.
    let probed = if unsafe { libc::geteuid() } == 0 && facts.unit_installed {
        match run_probe(node_file, settings) {
            Ok(report) => Some(report),
            Err(why) => {
                stdout_line!("scope probe: did not run: {why}");
                None
            }
        }
    } else {
        stdout_line!(
            "scope probe: not run ({}); the report below is from the configuration{}",
            if facts.unit_installed {
                "run `execution-node check` as root to prove each bound in a probe unit"
            } else {
                "the job unit is not installed: run `oneiron execution-node install`"
            },
            if check_report_path(node_file).exists() {
                " and the last probe of this boot"
            } else {
                ""
            }
        );
        std::fs::read(check_report_path(node_file))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<CheckReport>(&bytes).ok())
            .filter(|report| report.boot_id == boot_id())
    };
    let capabilities = capabilities_of(&facts, probed.as_ref());
    for bound in ScopeBound::ALL {
        let proof = capabilities.report(bound);
        stdout_line!(
            "scope {}: {:?}: {}",
            bound.name(),
            proof.strength,
            proof.evidence
        );
    }
    if facts.unit_installed && !control_socket_listens() {
        refusals.push(format!(
            "the job control socket {CONTROL_SOCKET_PATH} is not there ({CONTROL_SOCKET_UNIT} not started): the engine could not start a job (run `oneiron execution-node install`)"
        ));
    }
    if !capabilities.meets_minimum_contract() {
        refusals.push(
            "the scope lacks the minimum contract (tree kill, a cutoff with the engine stopped, emptiness): this machine offers no jobs"
                .to_owned(),
        );
    }
    for (template_name, template) in &settings.templates {
        for required in capabilities.missing(&template.require) {
            refusals.push(format!(
                "template {template_name} requires {required}, which this machine's scope lacks"
            ));
        }
    }
    refusals
}

/// Runs the probe unit and writes its report beside the node file.
fn run_probe(node_file: &Path, settings: &ExecutionNodeSettings) -> Result<CheckReport, String> {
    let unit_text = std::fs::read_to_string(UNIT_TEMPLATE_PATH)
        .map_err(|error| format!("{UNIT_TEMPLATE_PATH}: {error}"))?;
    let (job_uid, job_gid, _) = account(&settings.job_account)
        .map_err(|error| format!("job account {}: {error}", settings.job_account))?;
    let binary = std::env::current_exe().map_err(|error| error.to_string())?;
    let at_ms = wall_ms();
    let id = JobKeyId::for_key(&format!("execution-node-check-probe-{}-{at_ms}", boot_id()));
    let instance = id.as_str().to_owned();

    let payload = settings.work_dir.join(&instance);
    let work = open_dir_path(&settings.work_dir).map_err(|error| error.to_string())?;
    let payload_fd = make_dir_beneath(borrow(&work), &instance, 0o755, (0, 0))
        .map_err(|error| format!("probe payload: {error}"))?;
    make_dir_beneath(borrow(&payload_fd), "checkout", 0o755, (0, 0))
        .map_err(|error| format!("probe checkout: {error}"))?;
    for name in ["out", "tmp", "log"] {
        make_dir_beneath(borrow(&payload_fd), name, 0o755, (job_uid, job_gid))
            .map_err(|error| format!("probe {name}: {error}"))?;
    }
    if let Err(why) = super::exchange::publish_payload(&instance, &payload_fd) {
        let _ = std::fs::remove_dir_all(&payload);
        return Err(format!("probe {why}"));
    }
    drop(payload_fd);
    let protected = super::prepare::installed_protected_paths(&unit_text, &settings.state_dir);
    let exec = ExecFile {
        key: format!("probe-{instance}"),
        instance: instance.clone(),
        probe: true,
        argv: Vec::new(),
        env: BTreeMap::new(),
        cwd: payload.clone(),
        read: ["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/sys"]
            .iter()
            .map(PathBuf::from)
            .chain([payload.clone()])
            .collect(),
        write: ["out", "tmp", "log"]
            .iter()
            .map(|name| payload.join(name))
            .chain([PathBuf::from("/dev/null")])
            .collect(),
        protected,
        devices_allowed: Vec::new(),
        devices_denied: device_files::files_denied(&[], &settings.device_files),
        hidden_pids: vec![1],
        host_network_namespace: safe_fs::host_network_namespace(),
        require: Vec::new(),
        log_max_bytes: u64::from(super::super::node_settings::LOG_MAX_MIB_DEFAULT) << 20,
    };
    let exchange = Path::new(EXCHANGE_ROOT).join(&instance);
    let outcome = probe_in_unit(
        settings, &unit_text, &binary, &exec, &exchange, job_uid, job_gid,
    );
    super::exchange::withdraw(&instance);
    let _ = std::fs::remove_dir_all(&payload);
    let _ = std::fs::remove_dir_all(&exchange);
    // A refusal in the probe's report (its job-exec's disk allocation
    // check: a probe requires no bound) fails the check, as it would refuse
    // every launch here (review r14 R14-14 of #10512).
    let (proofs, probe_failure) = match outcome {
        Ok(report) => (
            report.proofs,
            report
                .refusal
                .map(|why| format!("the probe's job-exec refused: {why}")),
        ),
        Err(why) => (BTreeMap::new(), Some(why)),
    };
    let report = CheckReport {
        boot_id: boot_id(),
        at_ms,
        facts: kernel_facts(),
        proofs,
        probe_failure: probe_failure.clone(),
    };
    let path = check_report_path(node_file);
    let bytes = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
    let dir = open_dir_path(path.parent().unwrap_or(Path::new("/")))
        .map_err(|error| error.to_string())?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or("the node file has no name")?;
    safe_fs::write_beneath(borrow(&dir), name, &bytes, 0o644, Some((0, 0)))
        .map_err(|error| format!("{}: {error}", path.display()))?;
    stdout_line!("scope probe: report written to {}", path.display());
    match probe_failure {
        Some(why) => Err(why),
        None => Ok(report),
    }
}

/// Starts the probe unit with the installed template's properties and reads
/// `job-exec`'s report on the gate's socket, from the probe unit's main
/// process alone, as the gate takes it (FIX EXEC-UNIT-ONE-JOB-ACCOUNT).
fn probe_in_unit(
    settings: &ExecutionNodeSettings,
    unit_text: &str,
    binary: &Path,
    exec: &ExecFile,
    exchange: &Path,
    job_uid: u32,
    job_gid: u32,
) -> Result<ScopeReport, String> {
    let root = open_dir_path(Path::new(EXCHANGE_ROOT))
        .or_else(|_| {
            std::fs::create_dir_all(EXCHANGE_ROOT)?;
            open_dir_path(Path::new(EXCHANGE_ROOT))
        })
        .map_err(|error| error.to_string())?;
    let dir = make_dir_beneath(borrow(&root), &exec.instance, 0o750, (0, job_gid))
        .map_err(|error| format!("probe exchange: {error}"))?;
    let bytes = serde_json::to_vec_pretty(exec).map_err(|error| error.to_string())?;
    safe_fs::write_beneath(
        borrow(&dir),
        super::EXEC_FILE_NAME,
        &bytes,
        0o640,
        Some((0, job_gid)),
    )
    .map_err(|error| error.to_string())?;
    let socket = GateSocket::bind(exchange, job_gid)?;
    let unit = format!("{PROBE_UNIT_PREFIX}{}", exec.instance);
    let systemd_run = tool_path("systemd-run").ok_or("systemd-run: not found")?;
    let mut command = Command::new(systemd_run);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .args(["--wait", "--collect", "--quiet"])
        .arg(format!("--unit={unit}"))
        .arg("--property=MemoryMax=268435456")
        .arg("--property=TasksMax=64")
        .arg(format!(
            "--property=IOWriteBandwidthMax={} 1048576",
            settings.work_dir.display()
        ));
    for property in template_properties(unit_text, &exec.instance) {
        command.arg(format!("--property={property}"));
    }
    command
        .arg(binary)
        .arg("job-exec")
        .arg(&exec.instance)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let mut child = command
        .spawn()
        .map_err(|error| format!("systemd-run: {error}"))?;
    let until = Instant::now() + PROBE_TIMEOUT;
    // `job-exec` waits on its connection until root closes it, after the
    // report, so the service manager still names it while root checks it.
    let mut start = ProbeStart {
        unit: &unit,
        starter: &mut child,
        main: None,
    };
    let read = socket
        .accept_main_process(&mut start, job_uid, until, &unit)
        .and_then(|connection| {
            read_report(
                connection.as_fd(),
                until.saturating_duration_since(Instant::now()),
            )
        });
    drop(socket);
    drop(start);
    let ended = end_starter(
        &mut child,
        &unit,
        until.max(Instant::now() + PROBE_END_GRACE),
    );
    let bytes = read?;
    let status = ended?;
    // A report from a unit that then failed is no proof (review r7 R7-04).
    if !status.success() {
        return Err(format!(
            "probe_unit_failed: systemd-run {status} after the report"
        ));
    }
    serde_json::from_slice(&bytes).map_err(|error| format!("probe report: {error}"))
}

/// The probe unit's start as the gate's socket waits on it: its main process
/// once the service manager names it, held from then on, and its starter
/// `systemd-run`, whose end before the connection ends the wait (review r7
/// R7-03, R7-04).
struct ProbeStart<'a> {
    unit: &'a str,
    starter: &'a mut Child,
    main: Option<MainProcess>,
}

impl MainProcessWatch for ProbeStart<'_> {
    fn main_process(&mut self, left: Duration) -> Result<Option<&MainProcess>, String> {
        if self.main.is_none()
            && let Some(pid) = unit_main_process(self.unit, left)?
        {
            self.main = Some(MainProcess::hold(pid)?);
        }
        Ok(self.main.as_ref())
    }

    fn still_starting(&mut self) -> Result<(), String> {
        match self.starter.try_wait() {
            Ok(None) => Ok(()),
            Ok(Some(status)) => Err(format!(
                "probe_start_failed: systemd-run {status} before job-exec connected"
            )),
            Err(error) => Err(format!("systemd-run: {error}")),
        }
    }
}

/// The main process of the unit `unit`, as the service manager names it,
/// asking for at most `left`; `None` while it names none (the unit not
/// there yet, or `MainPID=0`).
fn unit_main_process(unit: &str, left: Duration) -> Result<Option<libc::pid_t>, String> {
    let pid = show_within(unit, &["MainPID"], left.min(SYSTEMCTL_TIMEOUT))?
        .get("MainPID")
        .and_then(|text| text.trim().parse::<libc::pid_t>().ok())
        .unwrap_or(0);
    Ok((pid > 0).then_some(pid))
}

/// Waits for the starter until `until`. A probe unit still running then is
/// stopped and its starter killed and reaped, so `execution-node check`
/// never outlives its deadline by more than the stop (review r7 R7-04).
fn end_starter(starter: &mut Child, unit: &str, until: Instant) -> Result<ExitStatus, String> {
    loop {
        match starter.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() >= until => break,
            Ok(None) => std::thread::sleep(STARTER_POLL),
            Err(error) => return Err(format!("systemd-run: {error}")),
        }
    }
    let stopped = run_tool("systemctl", &["stop", unit], SYSTEMCTL_TIMEOUT);
    let _ = starter.kill();
    let _ = starter.wait();
    Err(format!(
        "probe_unit_did_not_end: {unit} still ran at the probe's deadline; stopped: {}",
        stopped.map_or_else(|why| why, |_| "yes".to_owned())
    ))
}

/// The installed template's `[Service]` properties other than its `Exec*`
/// lines, with `%i` set to `instance`: the probe unit gets exactly the job's
/// bounds.
fn template_properties(unit_text: &str, instance: &str) -> Vec<String> {
    let mut in_service = false;
    let mut out = Vec::new();
    for line in unit_text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_service = line == "[Service]";
            continue;
        }
        if !in_service || line.is_empty() || line.starts_with('#') || line.starts_with("Exec") {
            continue;
        }
        out.push(line.replace("%i", instance));
    }
    out
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}
