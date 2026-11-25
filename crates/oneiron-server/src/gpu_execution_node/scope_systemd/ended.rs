//! `oneiron job-ended <id>` (root, the unit's `ExecStopPost=+`): runs after
//! every process of the unit is gone, whether or not the engine is up, and
//! writes the end record (pass 33, 7.6, "The end record"; R3a's
//! [`EndRecord`]): the service manager's result, the boot and the boot-clock
//! time, whether the cutoff fired, whether the workload ever started (the
//! gate's own record), and whether the unit's cgroup holds any process but
//! this step once the stop grace is over. The workload cannot write any of
//! it.
//!
//! Once the group is empty, and before the record is written, the step hands
//! every entry of the payload that the job's uid owns to the engine's account
//! ([`handover`]) and gives the uid back to the node's table ([`job_ids`]; FIX
//! EXEC-UNIT-CROSS-JOB-SAME-UID). A group that did not empty, or a hand-over
//! that did not complete, keeps the uid taken: the table takes it back only
//! once no process holds it.

use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::path::Path;
use std::time::{Duration, Instant};

use super::super::jobs::{EndRecord, JobKeyId, LaunchFile};
use super::exchange;
use super::handover::{self, hand_over};
use super::job_ids::{self, JobIdentity};
use super::prepare::CUTOFF_MARGIN_MS;
use super::records::{CutoffMark, ExecFile, PreparedRecord, ScopeRecord};
use super::safe_fs::{
    self, boot_id, boot_ns, borrow, open_dir_beneath, open_dir_path, read_beneath,
};
use super::step::{RECORD_MAX_BYTES, StepArgs, StepContext};
use super::systemd_unit::{run_tool, show, show_within};
use super::{
    CUTOFF_FILE_NAME, CUTOFF_UNIT_PREFIX, EXEC_FILE_NAME, PREPARED_FILE_NAME, SCOPE_FILE_NAME,
    is_job_instance, refusal_of_exit_status,
};

/// How long the step, run by hand, looks for the unit's group to empty.
const REAP_WAIT: Duration = Duration::from_secs(2);

/// The longest the step waits for one answer of the service manager: its
/// whole run fits in its own timeout, the stop grace (review r3 R3-06).
const QUERY_WAIT: Duration = Duration::from_secs(1);

/// The least wait for the id table's lock when the job's id goes back.
const RELEASE_WAIT_MIN: Duration = Duration::from_millis(200);

/// The end record's file, R3a's `END_RECORD_FILE_NAME`.
const END_RECORD: &str = super::super::jobs::job_unit::END_RECORD_FILE_NAME;

/// The step. Returns its exit status.
#[must_use]
pub fn run(args: StepArgs) -> i32 {
    let began = Instant::now();
    if let Some(why) = &args.host_namespace_error {
        // The record goes on from inside the unit's view: the control
        // directory is not one of its binds.
        journal_line!("job-ended: process 1's mount namespace not entered: {why}");
    }
    let instance = args.instance.clone();
    let context = match StepContext::open(args) {
        Ok(context) => context,
        Err(why) => {
            journal_line!("job-ended: no end record: {why}");
            // The runtime paths go even so (review r3 R3-05): they are named
            // by the instance alone, once it is a job's.
            if is_job_instance(&instance) {
                disarm_instance(&instance);
            }
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
        journal_line!("job-ended: {} has its end record already", context.unit());
        // A later run's id and files still go back.
        if let Some(identity) = job_identity(&context) {
            let (cgroup_empty, _) =
                settle_cgroup(&context.unit(), context.settings.stop_grace_secs);
            give_back(&context, identity, cgroup_empty, began);
        }
        disarm(&context);
        return 0;
    }
    // Read from root's exchange before `disarm` removes it.
    let identity = job_identity(&context);
    let record = end_record(&context);
    if let Some(identity) = identity {
        give_back(&context, identity, record.cgroup_empty, began);
    }
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
            journal_line!("job-ended: the end record was not written: {why}");
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
    // That time is this step's start: the step may wait for the unit's other
    // processes after it.
    let step_boot_ns = boot_ns();
    let cutoff_time_reached = prepared
        .as_ref()
        .and_then(|record| record.cutoff.as_ref())
        .is_some_and(|plan| {
            step_boot_ns.saturating_add(CUTOFF_MARGIN_MS.saturating_mul(1_000_000))
                >= plan.stop_at_boot_ns
        });
    // The end time is when the group was seen empty, or when the step gave up
    // on it (review r3 R3-03).
    let (cgroup_empty, end_boot_ns) =
        settle_cgroup(&context.unit(), context.settings.stop_grace_secs);
    EndRecord {
        key,
        service_result,
        exit_code,
        exit_status,
        boot_id: boot_id(),
        end_boot_ns,
        cutoff_fired: cutoff.is_some() || (workload_started && cutoff_time_reached),
        workload_started,
        cgroup_empty,
        refusal,
    }
}

/// The ids the prepare step gave this unit's job: the id table's entry for
/// the unit (the reservation of this run, review r9 R9-13), else root's
/// `exec.json`. The table also answers when the prepare step refused before
/// it wrote that file (review r8 R8-04): the job's directories are handed
/// over even then.
fn job_identity(context: &StepContext) -> Option<JobIdentity> {
    job_ids::identity_of(&context.unit()).or_else(|| exchange_identity(context))
}

/// The ids root's `exec.json` names for this unit's instance.
fn exchange_identity(context: &StepContext) -> Option<JobIdentity> {
    let exchange = open_dir_path(&context.exchange_path()).ok()?;
    let bytes =
        read_beneath(borrow(&exchange), EXEC_FILE_NAME, RECORD_MAX_BYTES, Some(0)).ok()??;
    let exec: ExecFile = serde_json::from_slice(&bytes).ok()?;
    (exec.instance == context.args.instance).then_some(exec.identity)
}

/// Hands the job's files to the engine's account and gives its uid back,
/// once no process of the unit is left. The settling of the group takes at
/// most two thirds of the stop grace from the step's start; the hand-over
/// ends by four fifths and the wait for the id table's lock by five sixths
/// (review r8 R8-03), so the record is still written within the step's
/// timeout. An id not given back in time stays taken until it is taken back.
fn give_back(context: &StepContext, identity: JobIdentity, cgroup_empty: bool, began: Instant) {
    let unit = context.unit();
    if !cgroup_empty {
        journal_line!(
            "job-ended: uid {} kept: the unit's group did not empty",
            identity.uid
        );
        return;
    }
    let grace = Duration::from_secs(context.settings.stop_grace_secs);
    let wait = share_of(grace, 4, 5).saturating_sub(began.elapsed());
    let payload = open_dir_path(&context.settings.work_dir).and_then(|work| {
        open_dir_beneath(borrow(&work), std::ffi::OsStr::new(&context.args.instance))
    });
    let outcome = match payload {
        Ok(payload) => hand_over(
            borrow(&payload),
            identity,
            (context.engine_uid, context.engine_gid),
            wait,
        ),
        // No payload: nothing of the job's is left to hand over.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => handover::HandOver {
            changed: 0,
            seen: 0,
            incomplete: None,
        },
        Err(error) => handover::HandOver {
            changed: 0,
            seen: 0,
            incomplete: Some(format!("payload: {error}")),
        },
    };
    if let Some(why) = &outcome.incomplete {
        journal_line!(
            "job-ended: uid {} kept: the hand-over to the engine did not complete ({} of {} entries changed): {why}",
            identity.uid,
            outcome.changed,
            outcome.seen
        );
        return;
    }
    let lock_wait = share_of(grace, 5, 6)
        .saturating_sub(began.elapsed())
        .max(RELEASE_WAIT_MIN);
    match job_ids::release(identity, &unit, lock_wait) {
        Ok(_) => {}
        Err(why) => journal_line!("job-ended: uid {} not given back: {why}", identity.uid),
    }
}

/// `parts` of `whole` shares of `grace`.
fn share_of(grace: Duration, parts: u32, whole: u32) -> Duration {
    grace
        .saturating_mul(parts)
        .checked_div(whole)
        .unwrap_or_default()
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
/// but this step, and the boot-clock time it was first seen so (or the time
/// the step gave up on it). A group that cannot be read counts as not empty.
///
/// Run as the unit's `ExecStopPost=` (the step is in the unit's own group),
/// the unit is stopping, and the service manager may have started this step
/// as soon as the main process exited, while others still run their TERM
/// handlers, and sends its final TERM and KILL only after this step (review
/// r2 R2-08, r3 R3-01). So the step waits until the stop grace, counted from
/// when the unit left `active`, is over, then kills what is left itself and
/// watches the group empty: a kill that the group does not confirm is the
/// unconfirmed kill the end record names. Everything fits in two thirds of
/// the stop grace, the step's own timeout (r3 R3-06). Run by hand, the step
/// kills nothing and looks for [`REAP_WAIT`].
fn settle_cgroup(unit: &str, stop_grace_secs: u64) -> (bool, u64) {
    let began = Instant::now();
    let me = std::process::id();
    let own = own_cgroup();
    let in_unit = own
        .as_deref()
        .is_some_and(|group| group.rsplit('/').next() == Some(unit));
    let group = if in_unit {
        own.unwrap_or_default()
    } else {
        match show(unit, &["ControlGroup"]) {
            Ok(found) => found.get("ControlGroup").cloned().unwrap_or_default(),
            Err(_) => return (false, boot_ns()),
        }
    };
    if group.is_empty() {
        return (true, boot_ns());
    }
    let root = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    if !in_unit {
        return watch_empty(&root, me, began + REAP_WAIT);
    }
    let budget = Duration::from_secs(stop_grace_secs).saturating_mul(2) / 3;
    let reap = budget / 3;
    let grace_left = show_within(unit, &["ActiveExitTimestampMonotonic"], QUERY_WAIT)
        .ok()
        .and_then(|found| {
            found
                .get("ActiveExitTimestampMonotonic")?
                .parse::<u64>()
                .ok()
        })
        .filter(|since| *since > 0)
        .map(|since_us| {
            let grace_end_us = since_us.saturating_add(stop_grace_secs.saturating_mul(1_000_000));
            Duration::from_micros(grace_end_us.saturating_sub(monotonic_us()))
        });
    // When the stop's start is unknown, the leftover processes get half of
    // what is left before the kill.
    let kill_after = grace_left
        .unwrap_or(budget / 2)
        .min(budget.saturating_sub(reap));
    let watched = watch_empty(&root, me, began + kill_after);
    if watched.0 {
        return watched;
    }
    kill_others(&root, &group, me);
    watch_empty(&root, me, began + budget)
}

/// Watches the group at `root` until it holds no process but `me`, or
/// `until`: whether it emptied, and the boot-clock time it was seen empty or
/// the watch ended.
fn watch_empty(root: &Path, me: u32, until: Instant) -> (bool, u64) {
    loop {
        match pids_in(root) {
            Some(pids) if pids.iter().all(|pid| *pid == me) => return (true, boot_ns()),
            Some(_) if Instant::now() < until => std::thread::sleep(Duration::from_millis(50)),
            _ => return (false, boot_ns()),
        }
    }
}

/// The processes of the group at `dir` and of every group below it; `None`
/// when one cannot be read.
fn pids_in(dir: &Path) -> Option<Vec<u32>> {
    let procs = match std::fs::read_to_string(dir.join("cgroup.procs")) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Some(Vec::new()),
        Err(_) => return None,
    };
    let mut pids: Vec<u32> = procs
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .collect();
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        if entry.file_type().ok()?.is_dir() {
            pids.extend(pids_in(&entry.path())?);
        }
    }
    Some(pids)
}

/// Sends KILL to every process of the group at `root` (named `group` below
/// the cgroup root) but `me`. Each process is held by a pidfd first and then
/// checked to be in the group, so a process id that was reused in between
/// is never signalled.
fn kill_others(root: &Path, group: &str, me: u32) {
    let Some(pids) = pids_in(root) else {
        return;
    };
    let below = format!("{group}/");
    for pid in pids.into_iter().filter(|pid| *pid != me) {
        let Ok(raw_pid) = libc::pid_t::try_from(pid) else {
            continue;
        };
        // SAFETY: pidfd_open takes a process id and no flags, and returns a
        // new descriptor or -1.
        let opened = unsafe { libc::syscall(libc::SYS_pidfd_open, raw_pid, 0_u32) };
        let Ok(fd) = libc::c_int::try_from(opened) else {
            continue;
        };
        if fd < 0 {
            continue;
        }
        // SAFETY: fd is the descriptor pidfd_open just returned.
        let pidfd = unsafe { OwnedFd::from_raw_fd(fd) };
        let in_group = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).is_ok_and(|text| {
            text.lines()
                .filter_map(|line| line.strip_prefix("0::"))
                .any(|path| path.trim() == group || path.trim().starts_with(&below))
        });
        if in_group {
            // SAFETY: pidfd is open; a null info and no flags send a plain
            // KILL to the very process it holds, or fail if that one is gone.
            let _ = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0_u32,
                )
            };
        }
    }
}

/// This process's cgroup v2 group, as `/proc/self/cgroup` names it.
fn own_cgroup() -> Option<String> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(|path| path.trim().to_owned())
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

/// Stops the cutoff timer of a unit that ended before it, and takes away
/// the job's payload bind source and exchange directory.
fn disarm(context: &StepContext) {
    disarm_instance(&context.args.instance);
}

/// [`disarm`] by a checked job instance alone.
fn disarm_instance(instance: &str) {
    let timer = format!("{CUTOFF_UNIT_PREFIX}{instance}.timer");
    let _ = run_tool("systemctl", &["stop", "--no-block", &timer], QUERY_WAIT);
    exchange::withdraw(instance);
}
