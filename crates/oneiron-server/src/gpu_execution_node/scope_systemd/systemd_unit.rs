//! R3a's [`JobUnit`] over the system's service manager: the engine's account
//! starts and stops instances of `oneiron-job@.service` through the job
//! control socket `install` wrote ([`super::control`]; it holds no polkit
//! grant) and reads their state with `systemctl show`. A tool that does not
//! answer is an error, never "inactive".

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::super::jobs::{
    JobKeyId, JobUnit, JobUnitError, JobUnitPhase, JobUnitStatus, PayloadUsage, PayloadWalkBounds,
    RenewRefusal,
};
use super::super::wire::ScopeFacts;
use super::capabilities;
use super::control::{self, ControlVerb};
use super::records::{PreparedRecord, ScopeCapabilities, ScopeRecord, scope_facts};
use super::step::RECORD_MAX_BYTES;
use super::{PREPARED_FILE_NAME, SCOPE_FILE_NAME};

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
    // Both pipes are read while the tool runs, so a long answer never blocks
    // it on a full pipe.
    let out = drain(child.stdout.take());
    let err = drain(child.stderr.take());
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "{name} {}: no answer in {timeout:?}",
                    args.join(" ")
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => return Err(format!("{name}: {error}")),
        }
    };
    // A process the tool left behind may hold a pipe open: its reader is
    // given a moment, not the rest of the timeout.
    let out = out.recv_timeout(PIPE_DRAIN_WAIT).unwrap_or_default();
    let err = err.recv_timeout(PIPE_DRAIN_WAIT).unwrap_or_default();
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

/// How long a tool's output is waited for once the tool has exited.
const PIPE_DRAIN_WAIT: Duration = Duration::from_secs(1);

/// Reads `pipe` to its end on a thread of its own; the text comes on the
/// returned channel (empty when there is no pipe).
fn drain<R: std::io::Read + Send + 'static>(pipe: Option<R>) -> std::sync::mpsc::Receiver<String> {
    let (sender, receiver) = std::sync::mpsc::channel();
    match pipe {
        Some(mut pipe) => {
            std::thread::spawn(move || {
                let mut text = String::new();
                let _ = pipe.read_to_string(&mut text);
                let _ = sender.send(text);
            });
        }
        None => {
            let _ = sender.send(String::new());
        }
    }
    receiver
}

/// Reads `systemctl show` output (`Name=value` lines) into a map.
#[must_use]
pub fn parse_show(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

/// The answer of one `systemctl show` naming several units: one map per
/// unit, as the blank lines between them part them.
#[must_use]
pub fn parse_show_units(text: &str) -> Vec<BTreeMap<String, String>> {
    text.split("\n\n")
        .map(parse_show)
        .filter(|found| !found.is_empty())
        .collect()
}

/// The unit properties `names` of `unit`, now.
///
/// # Errors
///
/// `systemctl` did not answer.
pub fn show(unit: &str, names: &[&str]) -> Result<BTreeMap<String, String>, String> {
    show_within(unit, names, SYSTEMCTL_TIMEOUT)
}

/// [`show`], waiting at most `timeout` for the service manager.
///
/// # Errors
///
/// As [`show`].
pub fn show_within(
    unit: &str,
    names: &[&str],
    timeout: Duration,
) -> Result<BTreeMap<String, String>, String> {
    let mut args = vec!["show", unit];
    let flags: Vec<String> = names
        .iter()
        .map(|name| format!("--property={name}"))
        .collect();
    args.extend(flags.iter().map(String::as_str));
    run_tool("systemctl", &args, timeout).map(|text| parse_show(&text))
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
        Ok(text) => Ok(text.lines().any(|line| line.trim() == "populated 0")),
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
    /// The node's state directory: each key's control directory, where the
    /// unit's root steps keep their records.
    state_dir: PathBuf,
}

impl SystemdJobUnit {
    #[must_use]
    pub fn new(node_file: PathBuf, state_dir: PathBuf) -> Self {
        Self {
            node_file,
            state_dir,
        }
    }

    /// A root step's record in the key's control directory: root-owned, and
    /// naming this key's instance, else none.
    fn root_record<T: serde::de::DeserializeOwned>(
        &self,
        unit: &JobKeyId,
        name: &str,
        instance_of: impl Fn(&T) -> &str,
    ) -> Option<T> {
        let control = super::safe_fs::open_dir_path(&unit.control_dir(&self.state_dir)).ok()?;
        let bytes = super::safe_fs::read_beneath(
            super::safe_fs::borrow(&control),
            name,
            RECORD_MAX_BYTES,
            Some(0),
        )
        .ok()??;
        let record: T = serde_json::from_slice(&bytes).ok()?;
        (instance_of(&record) == unit.as_str()).then_some(record)
    }

    fn error(unit: &JobKeyId, reason: String) -> JobUnitError {
        JobUnitError {
            unit: unit.unit_name(),
            reason,
        }
    }

    /// The unit's status from its `ActiveState` and `ControlGroup`, as
    /// `systemctl show` gave them.
    fn status_from(
        unit: &JobKeyId,
        found: &BTreeMap<String, String>,
    ) -> Result<JobUnitStatus, JobUnitError> {
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
}

impl JobUnit for SystemdJobUnit {
    fn probe(&self) -> ScopeCapabilities {
        capabilities::report(&self.node_file)
    }

    fn scope_facts(&self, unit: &JobKeyId) -> Option<ScopeFacts> {
        let prepared: PreparedRecord =
            self.root_record(unit, PREPARED_FILE_NAME, |record: &PreparedRecord| {
                record.instance.as_str()
            })?;
        let scope: Option<ScopeRecord> =
            self.root_record(unit, SCOPE_FILE_NAME, |record: &ScopeRecord| {
                record.instance.as_str()
            });
        Some(scope_facts(&prepared, scope.as_ref()))
    }

    fn start(&self, unit: &JobKeyId) -> Result<(), JobUnitError> {
        control::request(ControlVerb::Start, unit).map_err(|reason| Self::error(unit, reason))
    }

    fn stop(&self, unit: &JobKeyId) -> Result<(), JobUnitError> {
        control::request(ControlVerb::Stop, unit).map_err(|reason| Self::error(unit, reason))
    }

    /// A session's renewal (pass 34, 2.5; row W1), through the control
    /// socket's `renew` verb: root hands the unit's cutoff over to a later
    /// timer, forward only and within the session's longest run.
    fn renew(&self, unit: &JobKeyId, cutoff_boot_ns: u64) -> Result<(), RenewRefusal> {
        control::request(ControlVerb::Renew { cutoff_boot_ns }, unit)
            .map_err(|reason| RenewRefusal::Unit(Self::error(unit, reason)))
    }

    /// The checkpoint notice, through the control socket's `signal` verb:
    /// root sends it to the unit's main process alone.
    /// The disk check's measure, through the control socket's `usage`
    /// verb: root walks the unit's own bind source of the payload, so a
    /// directory the job made private to its uid counts too (FIX
    /// EXEC-NODE-DISK-CHECK-UNBUILT). `payload_dir` is the engine's path of
    /// it, which root does not use.
    fn payload_usage(
        &self,
        unit: &JobKeyId,
        _payload_dir: &Path,
        stop_past: u64,
        bounds: &PayloadWalkBounds,
    ) -> Result<PayloadUsage, JobUnitError> {
        control::request_usage(unit, stop_past, bounds).map_err(|reason| Self::error(unit, reason))
    }

    fn signal(&self, unit: &JobKeyId, signal: &str) -> Result<(), JobUnitError> {
        let verb = ControlVerb::from_words("signal", Some(signal))
            .map_err(|reason| Self::error(unit, format!("signal {signal}: {reason}")))?;
        control::request(verb, unit).map_err(|reason| Self::error(unit, reason))
    }

    fn status(&self, unit: &JobKeyId) -> Result<JobUnitStatus, JobUnitError> {
        let found = show(&unit.unit_name(), &["ActiveState", "ControlGroup"])
            .map_err(|reason| Self::error(unit, reason))?;
        Self::status_from(unit, &found)
    }

    /// Every job unit the service manager lists, with one `systemctl show`
    /// for all of them (FIX EXEC-UNIT-LIVE-UNITS-ONE-SHOW-PER-UNIT: one per
    /// unit held the admission lock that much longer).
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
        let ids: Vec<JobKeyId> = listing
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .filter_map(|name| {
                name.strip_prefix(super::super::jobs::job_unit::JOB_UNIT_TEMPLATE_PREFIX)
                    .and_then(|rest| {
                        rest.strip_suffix(super::super::jobs::job_unit::JOB_UNIT_SUFFIX)
                    })
                    .and_then(JobKeyId::parse)
            })
            .collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let names: Vec<String> = ids.iter().map(JobKeyId::unit_name).collect();
        let mut args = vec![
            "show",
            "--property=Id",
            "--property=ActiveState",
            "--property=ControlGroup",
        ];
        args.extend(names.iter().map(String::as_str));
        let answer =
            run_tool("systemctl", &args, SYSTEMCTL_TIMEOUT).map_err(|reason| JobUnitError {
                unit: "oneiron-job@*.service".to_owned(),
                reason,
            })?;
        let units = parse_show_units(&answer);
        let mut live = Vec::new();
        for (id, name) in ids.into_iter().zip(&names) {
            let Some(found) = units
                .iter()
                .find(|found| found.get("Id").is_some_and(|unit| unit == name))
            else {
                return Err(Self::error(
                    &id,
                    "systemctl show gave no properties for it".to_owned(),
                ));
            };
            let status = Self::status_from(&id, found)?;
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

    #[test]
    fn one_show_for_several_units_reads_as_one_map_per_unit() {
        let units = parse_show_units(
            "Id=oneiron-job@a.service\nActiveState=active\nControlGroup=/system.slice/a\n\n\
             Id=oneiron-job@b.service\nActiveState=inactive\nControlGroup=\n",
        );
        assert_eq!(units.len(), 2);
        assert_eq!(
            units[1].get("Id").map(String::as_str),
            Some("oneiron-job@b.service")
        );
        assert_eq!(
            units[1].get("ActiveState").map(String::as_str),
            Some("inactive")
        );
        assert_eq!(
            units[0].get("ControlGroup").map(String::as_str),
            Some("/system.slice/a")
        );
    }
}
