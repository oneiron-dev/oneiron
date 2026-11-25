//! `oneiron job-ended <id>` (root, the unit's `ExecStopPost=+`): runs after
//! every process of the unit is gone, whether or not the engine is up, and
//! writes the end record (pass 33, 7.6, "The end record"; R3a's
//! [`EndRecord`]): the service manager's result, the boot and the boot-clock
//! time, whether the cutoff fired, whether the workload ever started (the
//! gate's own record), and whether the unit's cgroup holds any process but
//! this step once the stop grace is over. The workload cannot write any of
//! it.

use std::path::Path;
use std::time::{Duration, Instant};

use super::super::jobs::{EndRecord, JobKeyId, LaunchFile};
use super::exchange;
use super::prepare::CUTOFF_MARGIN_MS;
use super::records::{CutoffMark, PreparedRecord, ScopeRecord};
use super::safe_fs::{self, boot_id, boot_ns, borrow, read_beneath};
use super::step::{RECORD_MAX_BYTES, StepArgs, StepContext};
use super::systemd_unit::{SYSTEMCTL_TIMEOUT, run_tool, show};
use super::{
    CUTOFF_FILE_NAME, CUTOFF_UNIT_PREFIX, PREPARED_FILE_NAME, SCOPE_FILE_NAME,
    refusal_of_exit_status,
};

/// The least the step waits for processes that were killed to be reaped
/// before it records the cgroup as not empty.
const REAP_WAIT: Duration = Duration::from_secs(2);

/// The step leaves this much of its own timeout (the stop grace, which the
/// service manager gives `ExecStopPost=` too) unused, so it always ends in
/// time to write the record.
const STOP_POST_MARGIN: Duration = Duration::from_secs(3);

/// The end record's file, R3a's `END_RECORD_FILE_NAME`.
const END_RECORD: &str = super::super::jobs::job_unit::END_RECORD_FILE_NAME;

/// The step. Returns its exit status.
#[must_use]
pub fn run(args: StepArgs) -> i32 {
    if let Some(why) = &args.host_namespace_error {
        // The record goes on from inside the unit's view: the control
        // directory is not one of its binds.
        eprintln!("job-ended: process 1's mount namespace not entered: {why}");
    }
    let context = match StepContext::open(args) {
        Ok(context) => context,
        Err(why) => {
            eprintln!("job-ended: no end record: {why}");
            return 1;
        }
    };
    // One end record per key: a second run of the unit keeps the first.
    if read_beneath(
        borrow(&context.control),
        END_RECORD,
        RECORD_MAX_BYTES,
        Some(0),
    )
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
    // Root's records only count for this unit's own instance: a record moved
    // in from another key's control directory is no record.
    let instance = context.args.instance.as_str();
    let prepared = context
        .read_record::<PreparedRecord>(PREPARED_FILE_NAME)
        .ok()
        .flatten()
        .filter(|record| record.instance == instance);
    let scope = context
        .read_record::<ScopeRecord>(SCOPE_FILE_NAME)
        .ok()
        .flatten()
        .filter(|record| record.instance == instance);
    let cutoff = context
        .read_record::<CutoffMark>(CUTOFF_FILE_NAME)
        .ok()
        .flatten()
        .filter(|record| record.instance == instance);
    let key = prepared
        .as_ref()
        .map(|record| record.key.clone())
        .filter(|key| !key.is_empty())
        .or_else(|| launch_key(context))
        .unwrap_or_default();
    let service_result = std::env::var("SERVICE_RESULT").unwrap_or_default();
    let exit_code = std::env::var("EXIT_CODE").ok();
    let exit_status = std::env::var("EXIT_STATUS").ok();
    let workload_started = scope
        .as_ref()
        .is_some_and(|record| record.released && record.exec_failed.is_none());
    let refusal = (!workload_started).then(|| {
        prepared
            .as_ref()
            .and_then(|record| record.refusal.clone())
            .or_else(|| scope.as_ref().and_then(|record| record.refusal.clone()))
            .or_else(|| {
                scope
                    .as_ref()
                    .and_then(|record| record.exec_failed.as_ref())
                    .map(|why| format!("workload_exec_failed: {why}"))
            })
            .or_else(|| {
                (exit_code.as_deref() == Some("exited"))
                    .then(|| exit_status.as_deref()?.parse::<i32>().ok())
                    .flatten()
                    .and_then(refusal_of_exit_status)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| format!("unit: {service_result}"))
    });
    // The cutoff ended the run when its mark is there, or when the unit ended
    // at or past the time the cutoff timer fires (the mark is written after
    // the stop, so it may come later than this step). The service manager's
    // `timeout` alone says nothing: it is also a stop grace that ran out.
    let end_boot_ns = boot_ns();
    let cutoff_time_reached = prepared
        .as_ref()
        .and_then(|record| record.cutoff.as_ref())
        .is_some_and(|plan| {
            end_boot_ns.saturating_add(CUTOFF_MARGIN_MS.saturating_mul(1_000_000))
                >= plan.stop_at_boot_ns
        });
    EndRecord {
        key,
        service_result,
        exit_code,
        exit_status,
        boot_id: boot_id(),
        end_boot_ns,
        cutoff_fired: cutoff.is_some() || (workload_started && cutoff_time_reached),
        workload_started,
        cgroup_empty: cgroup_empty_but_self(&context.unit(), context.settings.stop_grace_secs),
        refusal,
    }
}

/// The key `launch.json` names, when it hashes to this unit's instance.
fn launch_key(context: &StepContext) -> Option<String> {
    let bytes = read_beneath(
        borrow(&context.control),
        "launch.json",
        RECORD_MAX_BYTES,
        None,
    )
    .ok()??;
    let launch: LaunchFile = serde_json::from_slice(&bytes).ok()?;
    (JobKeyId::for_key(&launch.key).as_str() == context.args.instance).then_some(launch.key)
}

/// Whether the unit's cgroup, and every group below it, holds no process
/// but this step and its own threads, once the stop grace is over
/// ([`emptiness_wait`]). A group that cannot be read counts as not empty.
fn cgroup_empty_but_self(unit: &str, stop_grace_secs: u64) -> bool {
    let Ok(found) = show(
        unit,
        &[
            "ControlGroup",
            "ActiveState",
            "ActiveExitTimestampMonotonic",
        ],
    ) else {
        return false;
    };
    let group = found.get("ControlGroup").cloned().unwrap_or_default();
    if group.is_empty() {
        return true;
    }
    let wait = emptiness_wait(&found, stop_grace_secs);
    let root = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    let me = std::process::id();
    let started = Instant::now();
    loop {
        match others_in(&root, me) {
            Some(0) => return true,
            Some(_) if started.elapsed() < wait => {
                std::thread::sleep(Duration::from_millis(50));
            }
            _ => return false,
        }
    }
}

/// How long the unit's other processes may take to be gone (review r2
/// R2-08). The service manager runs this step as soon as the main process
/// exits, even while the others still run their TERM handlers inside the
/// stop grace. So a unit that is stopping gets the rest of its stop grace,
/// counted from when it left `active`, at most the grace less
/// [`STOP_POST_MARGIN`] and at least [`REAP_WAIT`]. A unit that is not
/// stopping (this step run by hand) gets [`REAP_WAIT`].
fn emptiness_wait(
    found: &std::collections::BTreeMap<String, String>,
    stop_grace_secs: u64,
) -> Duration {
    let stopping_since_us = found
        .get("ActiveExitTimestampMonotonic")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|since| *since > 0);
    let (Some("deactivating"), Some(since_us)) = (
        found.get("ActiveState").map(String::as_str),
        stopping_since_us,
    ) else {
        return REAP_WAIT;
    };
    let grace = Duration::from_secs(stop_grace_secs);
    let ceiling = grace.saturating_sub(STOP_POST_MARGIN).max(REAP_WAIT);
    let grace_end_us =
        since_us.saturating_add(u64::try_from(grace.as_micros()).unwrap_or(u64::MAX));
    Duration::from_micros(grace_end_us.saturating_sub(monotonic_us())).clamp(REAP_WAIT, ceiling)
}

/// `CLOCK_MONOTONIC` in microseconds: the clock of the service manager's
/// `*TimestampMonotonic` properties.
fn monotonic_us() -> u64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: now is a valid timespec for the call.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut now) };
    u64::try_from(now.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000)
        .saturating_add(u64::try_from(now.tv_nsec).unwrap_or(0) / 1_000)
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

/// Stops the cutoff timer of a unit that ended before it, and takes away
/// the job's payload bind source and exchange directory.
fn disarm(context: &StepContext) {
    let timer = format!("{CUTOFF_UNIT_PREFIX}{}.timer", context.args.instance);
    let _ = run_tool(
        "systemctl",
        &["stop", "--no-block", &timer],
        SYSTEMCTL_TIMEOUT,
    );
    exchange::withdraw(&context.args.instance);
}
