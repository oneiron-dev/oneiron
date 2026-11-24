//! `oneiron job-ended <id>` (root, the unit's `ExecStopPost=+`): runs after
//! every process of the unit is gone, whether or not the engine is up, and
//! writes the end record (pass 33, 7.6, "The end record"; R3a's
//! [`EndRecord`]): the service manager's result, the boot and the boot-clock
//! time, whether the cutoff fired, whether the workload ever started (the
//! gate's own record), and whether the unit's cgroup holds any process but
//! this step. The workload cannot write any of it.

use std::path::Path;
use std::time::{Duration, Instant};

use super::super::jobs::{EndRecord, JobKeyId, LaunchFile};
use super::records::{CutoffMark, PreparedRecord, ScopeRecord};
use super::safe_fs::{self, boot_id, boot_ns, borrow, open_dir_path, read_beneath};
use super::step::{RECORD_MAX_BYTES, StepArgs, StepContext};
use super::systemd_unit::{SYSTEMCTL_TIMEOUT, run_tool, show};
use super::{
    CUTOFF_FILE_NAME, CUTOFF_UNIT_PREFIX, EXCHANGE_ROOT, EXEC_FILE_NAME, GO_PIPE_NAME,
    PREPARED_FILE_NAME, REPORT_PIPE_NAME, SCOPE_FILE_NAME, refusal_of_exit_status,
};

/// How long the step waits for processes that were killed to be reaped
/// before it records the cgroup as not empty.
const REAP_WAIT: Duration = Duration::from_secs(2);

/// The end record's file, R3a's `END_RECORD_FILE_NAME`.
const END_RECORD: &str = super::super::jobs::job_unit::END_RECORD_FILE_NAME;

/// The step. Returns its exit status.
#[must_use]
pub fn run(args: StepArgs) -> i32 {
    let context = match StepContext::open(args) {
        Ok(context) => context,
        Err(why) => {
            eprintln!("job-ended: no end record: {why}");
            return 1;
        }
    };
    // One end record per key: a second run of the unit keeps the first.
    if read_beneath(borrow(&context.control), END_RECORD, RECORD_MAX_BYTES, Some(0))
        .is_ok_and(|found| found.is_some())
    {
        eprintln!("job-ended: {} has its end record already", context.unit());
        disarm(&context);
        return 0;
    }
    let record = end_record(&context);
    let written = serde_json::to_vec_pretty(&record)
        .map_err(|error| error.to_string())
        .and_then(|bytes| {
            safe_fs::write_beneath(borrow(&context.control), END_RECORD, &bytes, 0o644, None)
                .map_err(|error| error.to_string())
        });
    disarm(&context);
    match written {
        Ok(()) => 0,
        Err(why) => {
            eprintln!("job-ended: the end record was not written: {why}");
            1
        }
    }
}

fn end_record(context: &StepContext) -> EndRecord {
    let prepared = context
        .read_record::<PreparedRecord>(PREPARED_FILE_NAME)
        .ok()
        .flatten();
    let scope = context.read_record::<ScopeRecord>(SCOPE_FILE_NAME).ok().flatten();
    let cutoff = context.read_record::<CutoffMark>(CUTOFF_FILE_NAME).ok().flatten();
    let key = prepared
        .as_ref()
        .map(|record| record.key.clone())
        .filter(|key| !key.is_empty())
        .or_else(|| launch_key(context))
        .unwrap_or_default();
    let service_result = std::env::var("SERVICE_RESULT").unwrap_or_default();
    let exit_code = std::env::var("EXIT_CODE").ok();
    let exit_status = std::env::var("EXIT_STATUS").ok();
    let workload_started = scope.as_ref().is_some_and(|record| record.released);
    let refusal = (!workload_started).then(|| {
        prepared
            .as_ref()
            .and_then(|record| record.refusal.clone())
            .or_else(|| scope.as_ref().and_then(|record| record.refusal.clone()))
            .or_else(|| {
                (exit_code.as_deref() == Some("exited"))
                    .then(|| exit_status.as_deref()?.parse::<i32>().ok())
                    .flatten()
                    .and_then(refusal_of_exit_status)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| format!("unit: {service_result}"))
    });
    EndRecord {
        key,
        service_result,
        exit_code,
        exit_status,
        boot_id: boot_id(),
        end_boot_ns: boot_ns(),
        cutoff_fired: cutoff.is_some(),
        workload_started,
        cgroup_empty: cgroup_empty_but_self(&context.unit()),
        refusal,
    }
}

/// The key `launch.json` names, when it hashes to this unit's instance.
fn launch_key(context: &StepContext) -> Option<String> {
    let bytes = read_beneath(borrow(&context.control), "launch.json", RECORD_MAX_BYTES, None)
        .ok()??;
    let launch: LaunchFile = serde_json::from_slice(&bytes).ok()?;
    (JobKeyId::for_key(&launch.key).as_str() == context.args.instance).then_some(launch.key)
}

/// Whether the unit's cgroup, and every group below it, holds no process
/// but this step and its own threads. Killed processes get a moment to be
/// reaped; a group that cannot be read counts as not empty.
fn cgroup_empty_but_self(unit: &str) -> bool {
    let Ok(found) = show(unit, &["ControlGroup"]) else {
        return false;
    };
    let group = found.get("ControlGroup").cloned().unwrap_or_default();
    if group.is_empty() {
        return true;
    }
    let root = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    let me = std::process::id();
    let started = Instant::now();
    loop {
        match others_in(&root, me) {
            Some(0) => return true,
            Some(_) if started.elapsed() < REAP_WAIT => {
                std::thread::sleep(Duration::from_millis(50));
            }
            _ => return false,
        }
    }
}

/// How many processes other than `me` the group at `dir` and its children
/// hold; `None` when one cannot be read.
fn others_in(dir: &Path, me: u32) -> Option<usize> {
    let procs = match std::fs::read_to_string(dir.join("cgroup.procs")) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Some(0),
        Err(_) => return None,
    };
    let mut count = procs
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .filter(|pid| *pid != me)
        .count();
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        if entry.file_type().ok()?.is_dir() {
            count += others_in(&entry.path(), me)?;
        }
    }
    Some(count)
}

/// Stops the cutoff timer of a unit that ended before it, and removes the
/// job's exchange directory.
fn disarm(context: &StepContext) {
    let timer = format!("{CUTOFF_UNIT_PREFIX}{}.timer", context.args.instance);
    let _ = run_tool("systemctl", &["stop", "--no-block", &timer], SYSTEMCTL_TIMEOUT);
    let exchange = Path::new(EXCHANGE_ROOT).join(&context.args.instance);
    if let Ok(dir) = open_dir_path(&exchange) {
        for name in [EXEC_FILE_NAME, REPORT_PIPE_NAME, GO_PIPE_NAME] {
            let _ = safe_fs::remove_beneath(borrow(&dir), name);
        }
        drop(dir);
        let _ = std::fs::remove_dir(&exchange);
    }
}
