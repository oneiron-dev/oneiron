//! The gate, `oneiron job-prepare --after-exec <id>` (root, the unit's
//! `ExecStartPost=+`). It runs once `job-exec` has started: it binds the
//! gate's socket ([`super::GATE_SOCKET_NAME`]; [`socket`]) in the job's exchange directory,
//! takes the connection of the unit's main process and no other, reads
//! `job-exec`'s report on it, records the report with its verdict in
//! `scope.json`, and only then writes the go. The record is root's, so
//! whether the workload was let start is never the workload's word.
//!
//! Another process with the job's own ids could reach this job's exchange
//! directory. The gate therefore asks the kernel who connected
//! (`SO_PEERCRED`) and takes only the process the service manager names as
//! the unit's main process (`MAINPID`, `job-exec`) under the job's own uid,
//! which `exec.json` names (FIX EXEC-UNIT-CROSS-JOB-SAME-UID). It closes every other connection, says so in the
//! journal and waits on (FIX EXEC-UNIT-ONE-JOB-ACCOUNT). The gate holds the
//! main process by a pidfd from before its socket exists, and takes a
//! connection only while that process has not been reaped: a process id is
//! not reused before then, so the id the kernel recorded at the `connect`
//! was `job-exec`'s and no later process's (review r7 R7-02). Once it holds
//! `job-exec`'s connection it closes the socket and removes its name, before
//! the go, so nothing can connect again (review r3 R3-04).
//!
//! The report is one line, and `job-exec` keeps the connection open after it
//! (close-on-exec) until it becomes the workload (review r2 R2-02). Just
//! before its `execve` it writes [`EXEC_MARK`]; a successful `execve` then
//! closes the connection with nothing more said, and a failed one writes why
//! before `job-exec` exits. A go that did not reach `job-exec`, a close with
//! no mark (`job-exec` ended before its exec), words after the mark (a failed
//! exec), or no mark in time is recorded as the record's `exec_failed` (r3
//! R3-02), so the end record says the workload never started. The judgment
//! reads only the connection, never the process after the close, so a
//! workload that ends at once still counts as started (FIX
//! EXEC-UNIT-GATE-EXEC-RACE).

mod socket;

use std::io::Write as _;
use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use super::records::{
    BoundRequirement, ExecFile, PROVED_INSIDE, ScopeRecord, ScopeReport, first_unmet,
};
use super::safe_fs::{boot_ns, borrow, open_dir_path, read_beneath};
use super::step::{RECORD_MAX_BYTES, StepArgs, StepContext};
use super::{EXEC_FILE_NAME, EXEC_MARK, GATE_GO, SCOPE_FILE_NAME};
pub(super) use socket::{GateSocket, MainProcess, MainProcessWatch, read_report};
use socket::{Received, deadline_in, main_process_id, read_some};

/// How long the gate waits after its go for `job-exec` to become the
/// workload or to say why it could not.
const EXEC_WAIT: Duration = Duration::from_secs(10);

/// At most this much of an exec failure's words goes into the record.
const EXEC_FAILURE_MAX_BYTES: usize = 1024;

/// The gate. Returns the exit status: 0 when the workload started, 1 when
/// the unit must fail.
#[must_use]
pub fn run(args: StepArgs) -> i32 {
    let context = match StepContext::open(args) {
        Ok(context) => context,
        Err(why) => {
            journal_line!("job-prepare --after-exec: {why}");
            return 1;
        }
    };
    let deadline = Duration::from_secs(
        context
            .settings
            .unit_start_timeout_secs
            .saturating_sub(5)
            .max(5),
    );
    let verdict = match &context.args.host_namespace_error {
        Some(why) => Err(format!("host_mount_namespace_not_entered: {why}")),
        None => read_and_judge(&context, deadline),
    };
    let (report, refusal, connection) = match verdict {
        Ok((report, connection)) => {
            let refusal = report.refusal.clone();
            (Some(report), refusal, Some(connection))
        }
        Err(why) => (None, Some(why), None),
    };
    // A refused job's connection closes with no go: `job-exec` then ends
    // before any workload exists.
    let go = connection.filter(|_| refusal.is_none());
    finish(&context, report, refusal, go)
}

fn finish(
    context: &StepContext,
    report: Option<ScopeReport>,
    refusal: Option<String>,
    go: Option<UnixStream>,
) -> i32 {
    let released = refusal.is_none() && go.is_some();
    let mut record = ScopeRecord {
        instance: context.args.instance.clone(),
        report,
        released,
        refusal: refusal.clone(),
        exec_failed: None,
        at_boot_ns: boot_ns(),
    };
    // Recorded and synced before the go: a workload that started always has
    // `released` on disk.
    if let Err(why) = context.write_record(SCOPE_FILE_NAME, &record) {
        journal_line!("job-prepare --after-exec: {why}");
        return 1;
    }
    let Some(mut connection) = go else {
        journal_line!(
            "job-prepare --after-exec: {} refused: {}",
            context.unit(),
            refusal.as_deref().unwrap_or("no go")
        );
        return 1;
    };
    let outcome = match connection.write_all(GATE_GO) {
        Err(error) => AfterGo::Failed(format!("go_not_delivered: {error}")),
        Ok(()) => after_go(connection.as_fd(), EXEC_WAIT),
    };
    drop(connection);
    match outcome {
        AfterGo::Became => 0,
        AfterGo::Failed(why) => {
            journal_line!(
                "job-prepare --after-exec: {}: the workload's exec failed: {why}",
                context.unit()
            );
            record.exec_failed = Some(why);
            if let Err(error) = context.write_record(SCOPE_FILE_NAME, &record) {
                journal_line!("job-prepare --after-exec: {error}");
            }
            1
        }
    }
}

/// What came on the gate connection after the go.
#[derive(Debug, PartialEq, Eq)]
enum AfterGo {
    /// The exec mark and then nothing more: `job-exec` became the workload.
    Became,
    /// Why the workload never started: `job-exec`'s words on its exec, its
    /// end before the exec, or no exec in time.
    Failed(String),
}

/// Waits for `job-exec`'s exec: reads what it says after the go until the
/// connection closes or the wait runs out, then judges it
/// ([`judge_after_go`]). When the wait runs out, the gate looks at the
/// connection once more without waiting, so a mark that came as the wait
/// ended still counts as the exec (review r5 R5-03). The window left is the
/// gate's own exit after that look, and only after `job-exec` stalled the
/// whole wait.
fn after_go(connection: BorrowedFd<'_>, wait: Duration) -> AfterGo {
    let started = Instant::now();
    let mut said = Vec::new();
    let mut buffer = [0_u8; 512];
    loop {
        let left = wait.saturating_sub(started.elapsed());
        if left.is_zero() {
            let closed = drain_now(connection, &mut said, &mut buffer);
            return judge_after_go(&said, closed, wait);
        }
        match read_some(connection, &mut buffer, left) {
            Ok(Received::Bytes(count)) => keep_said(&mut said, &buffer[..count]),
            Ok(Received::End) => return judge_after_go(&said, true, wait),
            Ok(Received::Nothing) => {}
            Err(why) => {
                return match judge_after_go(&said, false, wait) {
                    AfterGo::Failed(_) if said.is_empty() => {
                        AfterGo::Failed(format!("gate connection: {why}"))
                    }
                    judged => judged,
                };
            }
        }
    }
}

/// Keeps what `job-exec` said, up to [`EXEC_FAILURE_MAX_BYTES`].
fn keep_said(said: &mut Vec<u8>, bytes: &[u8]) {
    let room = EXEC_FAILURE_MAX_BYTES.saturating_sub(said.len());
    said.extend_from_slice(&bytes[..bytes.len().min(room)]);
}

/// Reads what the connection holds now, without waiting. Returns whether it
/// closed.
fn drain_now(connection: BorrowedFd<'_>, said: &mut Vec<u8>, buffer: &mut [u8]) -> bool {
    // job-exec says at most the mark and one line, so a few reads empty it.
    for _ in 0..16 {
        match read_some(connection, buffer, Duration::ZERO) {
            Ok(Received::Bytes(count)) => keep_said(said, &buffer[..count]),
            Ok(Received::End) => return true,
            Ok(Received::Nothing) | Err(_) => return false,
        }
    }
    false
}

/// Judges what `job-exec` wrote after the go. `closed`: the connection
/// closed; otherwise the wait ran out. Words without the mark are a failure
/// before the exec, words after it a failed exec. The mark alone is the
/// exec, also when the wait ran out before the close: the exec was under
/// way, and the workload may run, so the record must not say it never
/// started.
fn judge_after_go(said: &[u8], closed: bool, wait: Duration) -> AfterGo {
    let words = |bytes: &[u8]| String::from_utf8_lossy(bytes).trim().to_owned();
    match said.strip_prefix(EXEC_MARK) {
        Some([]) => AfterGo::Became,
        Some(after) => AfterGo::Failed(words(after)),
        None if !said.is_empty() => AfterGo::Failed(words(said)),
        None if closed => AfterGo::Failed("job-exec ended before the workload's exec".to_owned()),
        None => AfterGo::Failed(format!("no_exec_in_time: {} s", wait.as_secs())),
    }
}

/// Takes `job-exec`'s connection on the gate's socket, reads its report and
/// judges it against the template's required bounds, from root's own copy
/// of `exec.json`. Returns the report and the connection, still open; the
/// socket is closed and its name gone.
fn read_and_judge(
    context: &StepContext,
    deadline: Duration,
) -> Result<(ScopeReport, UnixStream), String> {
    let until = deadline_in(deadline);
    let exchange = open_dir_path(&context.exchange_path())
        .map_err(|error| format!("exchange_dir: {error}"))?;
    let exec: ExecFile = serde_json::from_slice(
        &read_beneath(borrow(&exchange), EXEC_FILE_NAME, RECORD_MAX_BYTES, Some(0))
            .map_err(|error| format!("exec_file: {error}"))?
            .ok_or("exec_file_missing")?,
    )
    .map_err(|error| format!("exec_file: {error}"))?;
    // Held before the socket exists, so every connection comes after it.
    let mut main = MainProcess::hold(main_process_id()?)?;
    // The socket is dropped at the end of this statement: closed, its name
    // removed, before the report is even read.
    let connection = GateSocket::bind(&context.exchange_path(), exec.identity.gid)?
        .accept_main_process(&mut main, exec.identity.uid, until, &context.unit())?;
    let bytes = read_report(
        connection.as_fd(),
        until.saturating_duration_since(Instant::now()),
    )?;
    let mut report: ScopeReport =
        serde_json::from_slice(&bytes).map_err(|error| format!("report_invalid: {error}"))?;
    if report.instance != context.args.instance {
        return Err("report_for_another_instance".to_owned());
    }
    let inside: Vec<BoundRequirement> = exec
        .require
        .iter()
        .copied()
        .filter(|requirement| PROVED_INSIDE.contains(&requirement.bound))
        .collect();
    if report.refusal.is_none()
        && let Some(missing) = first_unmet(&inside, &report.proofs)
    {
        report.refusal = Some(format!("required_bound_not_proved: {missing}"));
    }
    Ok((report, connection))
}

#[cfg(test)]
mod tests {
    use super::{AfterGo, EXEC_MARK, after_go, judge_after_go};
    use std::io::Write as _;
    use std::os::fd::{AsFd as _, FromRawFd as _, OwnedFd};
    use std::time::Duration;

    const WAIT: Duration = Duration::from_secs(10);

    fn failed(why: &str) -> AfterGo {
        AfterGo::Failed(why.to_owned())
    }

    #[test]
    fn a_close_after_the_mark_alone_is_the_exec() {
        assert_eq!(judge_after_go(EXEC_MARK, true, WAIT), AfterGo::Became);
    }

    #[test]
    fn a_close_with_no_mark_is_an_end_before_the_exec() {
        assert_eq!(
            judge_after_go(b"", true, WAIT),
            failed("job-exec ended before the workload's exec")
        );
    }

    #[test]
    fn words_after_the_mark_are_a_failed_exec() {
        let said = [EXEC_MARK, b"/usr/bin/bash: No such file or directory\n"].concat();
        assert_eq!(
            judge_after_go(&said, true, WAIT),
            failed("/usr/bin/bash: No such file or directory")
        );
    }

    #[test]
    fn words_without_the_mark_are_a_failure_before_the_exec() {
        assert_eq!(
            judge_after_go(b"exec.json names no program\n", true, WAIT),
            failed("exec.json names no program")
        );
    }

    #[test]
    fn a_wait_that_ran_out_without_the_mark_is_no_exec_in_time() {
        assert_eq!(
            judge_after_go(b"", false, WAIT),
            failed("no_exec_in_time: 10 s")
        );
    }

    #[test]
    fn a_wait_that_ran_out_after_the_mark_counts_as_started() {
        assert_eq!(judge_after_go(EXEC_MARK, false, WAIT), AfterGo::Became);
    }

    /// Review r5 R5-03: the mark is on the connection when the wait has run
    /// out.
    #[test]
    fn a_mark_that_came_as_the_wait_ran_out_counts_as_started() {
        let mut ends = [0; 2];
        // SAFETY: ends has room for the two descriptors.
        let made = unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
        assert_eq!(made, 0);
        // SAFETY: pipe2 returned two new descriptors.
        let (read_end, write_end) =
            unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) };
        let mut writer = std::fs::File::from(write_end);
        writer.write_all(EXEC_MARK).expect("the mark fits the pipe");
        assert_eq!(after_go(read_end.as_fd(), Duration::ZERO), AfterGo::Became);
        drop(writer);
        assert_eq!(
            after_go(read_end.as_fd(), Duration::ZERO),
            failed("job-exec ended before the workload's exec")
        );
    }
}
