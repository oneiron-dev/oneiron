//! The scope half of `oneiron execution-node check` (pass 33, 7.6:
//! "`execution-node check` runs the same checks in a probe unit"). As root
//! it starts a transient unit with exactly the installed template's
//! properties, runs `job-exec` in it in probe mode, reads its report as the
//! gate would, and writes the report beside the node file, where the
//! engine's capability report reads it. Without root it prints the
//! capability report from what it can read.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use super::super::jobs::JobKeyId;
use super::super::node_settings::ExecutionNodeSettings;
use super::capabilities::{CheckReport, capabilities_of, check_report_path, kernel_facts};
use super::device_files;
use super::records::{ExecFile, ScopeBound, ScopeReport};
use super::safe_fs::{self, account, boot_id, borrow, make_dir_beneath, open_dir_path};
use super::systemd_unit::tool_path;
use super::{EXCHANGE_ROOT, PROBE_UNIT_PREFIX, REPORT_PIPE_NAME, UNIT_TEMPLATE_PATH};

/// How long the probe unit may run.
const PROBE_TIMEOUT: Duration = Duration::from_secs(60);

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
                println!("scope probe: did not run: {why}");
                None
            }
        }
    } else {
        println!(
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
        println!(
            "scope {}: {:?}: {}",
            bound.name(),
            proof.strength,
            proof.evidence
        );
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
        require: Vec::new(),
    };
    let exchange = Path::new(EXCHANGE_ROOT).join(&instance);
    let outcome = probe_in_unit(settings, &unit_text, &binary, &exec, &exchange, job_gid);
    let _ = std::fs::remove_dir_all(&payload);
    let _ = std::fs::remove_dir_all(&exchange);
    let (proofs, probe_failure) = match outcome {
        Ok(report) => (report.proofs, None),
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
    println!("scope probe: report written to {}", path.display());
    match probe_failure {
        Some(why) => Err(why),
        None => Ok(report),
    }
}

/// Starts the probe unit with the installed template's properties and reads
/// `job-exec`'s report from its pipe.
fn probe_in_unit(
    settings: &ExecutionNodeSettings,
    unit_text: &str,
    binary: &Path,
    exec: &ExecFile,
    exchange: &Path,
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
    safe_fs::make_fifo_beneath(borrow(&dir), REPORT_PIPE_NAME, 0o620, job_gid)
        .map_err(|error| error.to_string())?;
    safe_fs::make_fifo_beneath(borrow(&dir), super::GO_PIPE_NAME, 0o640, job_gid)
        .map_err(|error| error.to_string())?;
    let systemd_run = tool_path("systemd-run").ok_or("systemd-run: not found")?;
    let mut command = Command::new(systemd_run);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .args(["--wait", "--collect", "--quiet"])
        .arg(format!("--unit={PROBE_UNIT_PREFIX}{}", exec.instance))
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
    let read = super::prepare::read_pipe(&dir, REPORT_PIPE_NAME, PROBE_TIMEOUT);
    let waited = child.wait();
    let _ = exchange;
    let bytes = read?;
    waited.map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|error| format!("probe report: {error}"))
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
