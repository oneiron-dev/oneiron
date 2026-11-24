//! R3a's [`JobUnit`] over the system's service manager: the engine's account
//! starts and stops instances of `oneiron-job@.service` (the polkit rule
//! `install` wrote allows exactly that) and reads their state. A tool that
//! does not answer is an error, never "inactive".

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::super::jobs::{
    JobKeyId, JobUnit, JobUnitError, JobUnitPhase, JobUnitStatus, ScopeCapabilities,
};
use super::capabilities;
use super::records::BoundReport;

/// How long one `systemctl` call may take before it counts as no answer.
pub const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(15);

/// Where the service manager's tools are looked for, in order. Fixed paths:
/// no `PATH` of the engine's or a caller's is ever searched.
const TOOL_DIRS: [&str; 4] = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

/// The path of a system tool, from [`TOOL_DIRS`].
#[must_use]
pub fn tool_path(name: &str) -> Option<PathBuf> {
    TOOL_DIRS
        .iter()
        .map(|dir| Path::new(dir).join(name))
        .find(|path| path.is_file())
}

/// Runs a system tool with a clean environment and no input, and returns
/// its standard output.
///
/// # Errors
///
/// The tool is missing, did not start, ran past `timeout`, or exited with a
/// failure (its standard error, trimmed, is the reason).
pub fn run_tool(name: &str, args: &[&str], timeout: Duration) -> Result<String, String> {
    let Some(path) = tool_path(name) else {
        return Err(format!("{name}: not found in {}", TOOL_DIRS.join(", ")));
    };
    let mut child = Command::new(&path)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "C")
        .env("SYSTEMD_PAGER", "")
        .env("SYSTEMD_COLORS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("{name}: {error}"))?;
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{name} {}: no answer in {timeout:?}", args.join(" ")));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => return Err(format!("{name}: {error}")),
        }
    };
    let mut out = String::new();
    let mut err = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut out);
    }
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut err);
    }
    if status.success() {
        Ok(out)
    } else {
        Err(format!(
            "{name} {} exited {status}: {}",
            args.join(" "),
            err.trim()
        ))
    }
}

/// Reads `systemctl show` output (`Name=value` lines) into a map.
#[must_use]
pub fn parse_show(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

/// The unit properties `names` of `unit`, now.
///
/// # Errors
///
/// `systemctl` did not answer.
pub fn show(unit: &str, names: &[&str]) -> Result<BTreeMap<String, String>, String> {
    let mut args = vec!["show", unit];
    let flags: Vec<String> = names.iter().map(|name| format!("--property={name}")).collect();
    args.extend(flags.iter().map(String::as_str));
    run_tool("systemctl", &args, SYSTEMCTL_TIMEOUT).map(|text| parse_show(&text))
}

/// The phase a unit's `ActiveState` means.
#[must_use]
pub fn phase_of(active_state: &str) -> JobUnitPhase {
    match active_state {
        "activating" => JobUnitPhase::Starting,
        "active" | "reloading" | "refreshing" => JobUnitPhase::Active,
        "deactivating" | "maintenance" => JobUnitPhase::Stopping,
        _ => JobUnitPhase::Inactive,
    }
}

/// Whether the control group `cgroup` (a path below the cgroup v2 root, as
/// `ControlGroup=` names it) holds no process. An empty name, or a group
/// that no longer exists, holds none.
///
/// # Errors
///
/// The group exists and its `cgroup.events` cannot be read.
pub fn cgroup_empty(cgroup: &str) -> Result<bool, String> {
    if cgroup.is_empty() {
        return Ok(true);
    }
    let events = Path::new("/sys/fs/cgroup")
        .join(cgroup.trim_start_matches('/'))
        .join("cgroup.events");
    match std::fs::read_to_string(&events) {
        Ok(text) => Ok(text
            .lines()
            .any(|line| line.trim() == "populated 0")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(format!("{}: {error}", events.display())),
    }
}

/// The job unit on Linux with systemd (pass 33, 7.6; pass 34, 2.2: the
/// first launch-scope plug-in).
#[derive(Debug, Clone)]
pub struct SystemdJobUnit {
    /// The node's `[execution_node]` file: `probe` reads the scope report
    /// `execution-node check` wrote beside it.
    node_file: PathBuf,
}

impl SystemdJobUnit {
    #[must_use]
    pub fn new(node_file: PathBuf) -> Self {
        Self { node_file }
    }

    /// What this machine can enforce now, by bound name, each with one line
    /// of evidence; [`JobUnit::probe`] gives the same as R3a's
    /// `ScopeCapabilities`.
    #[must_use]
    pub fn bound_reports(&self) -> BTreeMap<String, BoundReport> {
        capabilities::report(&self.node_file)
    }

    fn error(unit: &JobKeyId, reason: String) -> JobUnitError {
        JobUnitError {
            unit: unit.unit_name(),
            reason,
        }
    }
}

impl JobUnit for SystemdJobUnit {
    fn probe(&self) -> ScopeCapabilities {
        capabilities::scope_capabilities(&self.bound_reports())
    }

    fn start(&self, unit: &JobKeyId) -> Result<(), JobUnitError> {
        run_tool(
            "systemctl",
            &["start", "--no-block", &unit.unit_name()],
            SYSTEMCTL_TIMEOUT,
        )
        .map(drop)
        .map_err(|reason| Self::error(unit, reason))
    }

    fn stop(&self, unit: &JobKeyId) -> Result<(), JobUnitError> {
        run_tool(
            "systemctl",
            &["stop", "--no-block", &unit.unit_name()],
            SYSTEMCTL_TIMEOUT,
        )
        .map(drop)
        .map_err(|reason| Self::error(unit, reason))
    }

    fn status(&self, unit: &JobKeyId) -> Result<JobUnitStatus, JobUnitError> {
        let found = show(&unit.unit_name(), &["ActiveState", "ControlGroup"])
            .map_err(|reason| Self::error(unit, reason))?;
        let Some(active_state) = found.get("ActiveState") else {
            return Err(Self::error(
                unit,
                "systemctl show named no ActiveState".to_owned(),
            ));
        };
        let empty = cgroup_empty(found.get("ControlGroup").map_or("", String::as_str))
            .map_err(|reason| Self::error(unit, reason))?;
        Ok(JobUnitStatus {
            phase: phase_of(active_state),
            cgroup_empty: empty,
        })
    }

    fn live_units(&self) -> Result<Vec<(JobKeyId, JobUnitStatus)>, JobUnitError> {
        let listing = run_tool(
            "systemctl",
            &[
                "list-units",
                "--all",
                "--plain",
                "--no-legend",
                "--full",
                "oneiron-job@*.service",
            ],
            SYSTEMCTL_TIMEOUT,
        )
        .map_err(|reason| JobUnitError {
            unit: "oneiron-job@*.service".to_owned(),
            reason,
        })?;
        let mut live = Vec::new();
        for line in listing.lines() {
            let Some(name) = line.split_whitespace().next() else {
                continue;
            };
            let Some(id) = name
                .strip_prefix(super::super::jobs::job_unit::JOB_UNIT_TEMPLATE_PREFIX)
                .and_then(|rest| rest.strip_suffix(super::super::jobs::job_unit::JOB_UNIT_SUFFIX))
                .and_then(JobKeyId::parse)
            else {
                continue;
            };
            let status = self.status(&id)?;
            if !status.is_gone() {
                live.push((id, status));
            }
        }
        Ok(live)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemctl_show_lines_read_as_a_map() {
        let found = parse_show("ActiveState=active\nControlGroup=/system.slice/x.service\n");
        assert_eq!(found.get("ActiveState").map(String::as_str), Some("active"));
        assert_eq!(phase_of("activating"), JobUnitPhase::Starting);
        assert_eq!(phase_of("failed"), JobUnitPhase::Inactive);
    }
}
