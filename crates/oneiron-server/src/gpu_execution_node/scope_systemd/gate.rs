//! The gate, `oneiron job-prepare --after-exec <id>` (root, the unit's
//! `ExecStartPost=+`). It runs once `job-exec` has started: it reads
//! `job-exec`'s report from the report pipe, records it with its verdict in
//! `scope.json`, and only then writes the go. The record is root's, so
//! whether the workload was let start is never the workload's word.
//!
//! The report is one line, and `job-exec` keeps the pipe open after it
//! (close-on-exec) until it becomes the workload (review r2 R2-02). Just
//! before its `execve` it writes [`EXEC_MARK`]; a successful `execve` then
//! closes the pipe with nothing more said, and a failed one writes why
//! before `job-exec` exits. The gate unlinks both pipes' names before its
//! go, so the workload cannot open them again (review r3 R3-04), and then
//! reads until the pipe closes. A go that did not reach `job-exec`, a close
//! with no mark (`job-exec` ended before its exec), words after the mark (a
//! failed exec), or no mark in time is recorded as the record's
//! `exec_failed` (r3 R3-02), so the end record says the workload never
//! started. The judgment reads only the pipe, never the process after the
//! close, so a workload that ends at once still counts as started (FIX
//! EXEC-UNIT-GATE-EXEC-RACE).

use std::io::{self, Write as _};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use super::records::{
    BoundRequirement, ExecFile, PROVED_INSIDE, ScopeRecord, ScopeReport, first_unmet,
};
use super::safe_fs::{self, boot_ns, borrow, open_dir_path, read_beneath, remove_beneath};
use super::step::{RECORD_MAX_BYTES, StepArgs, StepContext};
use super::{
    EXEC_FILE_NAME, EXEC_MARK, GATE_GO, GO_PIPE_NAME, REPORT_FRAME_END, REPORT_PIPE_NAME,
    SCOPE_FILE_NAME,
};

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
    let (report, refusal, pipe) = match verdict {
        Ok((report, pipe)) => {
            let refusal = report.refusal.clone();
            (Some(report), refusal, Some(pipe))
        }
        Err(why) => (None, Some(why), None),
    };
    let go = if refusal.is_none() {
        match open_go(&context).and_then(|go| unlink_pipes(&context).map(|()| go)) {
            Ok(go) => Some(go),
            Err(why) => return finish(&context, report, Some(why), None, None),
        }
    } else {
        None
    };
    finish(&context, report, refusal, go, pipe)
}

/// Unlinks the two pipes' names once the gate holds both pipes: after the go,
/// nothing may open them again.
fn unlink_pipes(context: &StepContext) -> Result<(), String> {
    let exchange = open_dir_path(&context.exchange_path())
        .map_err(|error| format!("exchange_dir: {error}"))?;
    for name in [REPORT_PIPE_NAME, GO_PIPE_NAME] {
        remove_beneath(borrow(&exchange), name)
            .map_err(|error| format!("pipes_not_unlinked: {name}: {error}"))?;
    }
    Ok(())
}

fn finish(
    context: &StepContext,
    report: Option<ScopeReport>,
    refusal: Option<String>,
    go: Option<OwnedFd>,
    pipe: Option<OwnedFd>,
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
    let Some(go) = go else {
        journal_line!(
            "job-prepare --after-exec: {} refused: {}",
            context.unit(),
            refusal.as_deref().unwrap_or("no go")
        );
        return 1;
    };
    let mut file = std::fs::File::from(go);
    let outcome = match file.write_all(GATE_GO) {
        Err(error) => AfterGo::Failed(format!("go_not_delivered: {error}")),
        Ok(()) => match &pipe {
            Some(pipe) => after_go(pipe, EXEC_WAIT),
            None => AfterGo::Became,
        },
    };
    drop(file);
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

/// What came on the report pipe after the go.
#[derive(Debug, PartialEq, Eq)]
enum AfterGo {
    /// The exec mark and then nothing more: `job-exec` became the workload.
    Became,
    /// Why the workload never started: `job-exec`'s words on its exec, its
    /// end before the exec, or no exec in time.
    Failed(String),
}

/// Waits for `job-exec`'s exec: reads what it says after the go until the
/// pipe closes or the wait runs out, then judges it ([`judge_after_go`]).
fn after_go(pipe: &OwnedFd, wait: Duration) -> AfterGo {
    let started = Instant::now();
    let mut said = Vec::new();
    let mut buffer = [0_u8; 512];
    loop {
        let left = wait.saturating_sub(started.elapsed());
        if left.is_zero() {
            return judge_after_go(&said, false, wait);
        }
        match read_some(pipe, &mut buffer, left) {
            Ok(PipeRead::Bytes(count)) => {
                let room = EXEC_FAILURE_MAX_BYTES.saturating_sub(said.len());
                said.extend_from_slice(&buffer[..count.min(room)]);
            }
            Ok(PipeRead::End) => return judge_after_go(&said, true, wait),
            Ok(PipeRead::Nothing) => {}
            Err(why) => {
                return match judge_after_go(&said, false, wait) {
                    AfterGo::Failed(_) if said.is_empty() => {
                        AfterGo::Failed(format!("report pipe: {why}"))
                    }
                    judged => judged,
                };
            }
        }
    }
}

/// Judges what `job-exec` wrote after the go. `closed`: the pipe closed;
/// otherwise the wait ran out. Words without the mark are a failure before
/// the exec, words after it a failed exec. The mark alone is the exec, also
/// when the wait ran out before the close: the exec was under way, and the
/// workload may run, so the record must not say it never started.
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

/// Reads the report from the pipe and judges it against the template's
/// required bounds, from root's own copy of `exec.json`. Returns the report
/// and the pipe's read end, still open.
fn read_and_judge(
    context: &StepContext,
    deadline: Duration,
) -> Result<(ScopeReport, OwnedFd), String> {
    let exchange = open_dir_path(&context.exchange_path())
        .map_err(|error| format!("exchange_dir: {error}"))?;
    let exec: ExecFile = serde_json::from_slice(
        &read_beneath(borrow(&exchange), EXEC_FILE_NAME, RECORD_MAX_BYTES, Some(0))
            .map_err(|error| format!("exec_file: {error}"))?
            .ok_or("exec_file_missing")?,
    )
    .map_err(|error| format!("exec_file: {error}"))?;
    let (bytes, pipe) = read_report(&exchange, REPORT_PIPE_NAME, deadline)?;
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
    Ok((report, pipe))
}

/// Opens root's pipe `name` beneath `dir` and reads one report: the bytes
/// before [`REPORT_FRAME_END`], or all of them when the writer closes first,
/// waiting at most `deadline`. Returns the report and the read end, still
/// open. A byte after the report's end is refused: `job-exec` says nothing
/// more before the go.
///
/// # Errors
///
/// The pipe is not root's, the report is late, too large or followed by
/// more, or a read failed.
pub(super) fn read_report(
    dir: &OwnedFd,
    name: &str,
    deadline: Duration,
) -> Result<(Vec<u8>, OwnedFd), String> {
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
        return Err(format!("{name}: {}", io::Error::last_os_error()));
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
        match read_some(&fd, &mut buffer, left).map_err(|why| format!("{name}: {why}"))? {
            PipeRead::Bytes(count) => {
                bytes.extend_from_slice(&buffer[..count]);
                if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > RECORD_MAX_BYTES {
                    return Err("report_too_large".to_owned());
                }
                if let Some(end) = bytes.iter().position(|byte| *byte == REPORT_FRAME_END) {
                    if end + 1 != bytes.len() {
                        return Err("report_invalid: bytes after the report".to_owned());
                    }
                    bytes.truncate(end);
                    return Ok((bytes, fd));
                }
            }
            PipeRead::End => return Ok((bytes, fd)),
            PipeRead::Nothing => {}
        }
    }
}

/// One poll and read of a non-blocking pipe.
enum PipeRead {
    Bytes(usize),
    /// Every writer closed.
    End,
    /// Nothing within the wait, or an interrupted call.
    Nothing,
}

fn read_some(fd: &OwnedFd, buffer: &mut [u8], left: Duration) -> Result<PipeRead, String> {
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let millis = libc::c_int::try_from(left.as_millis()).unwrap_or(libc::c_int::MAX);
    // SAFETY: one valid pollfd.
    let ready = unsafe { libc::poll(&raw mut poll, 1, millis) };
    if ready < 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::Interrupted {
            Ok(PipeRead::Nothing)
        } else {
            Err(error.to_string())
        };
    }
    if ready == 0 {
        return Ok(PipeRead::Nothing);
    }
    // SAFETY: buffer is writable for its length.
    let read = unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
    match read {
        0 => Ok(PipeRead::End),
        count if count > 0 => Ok(PipeRead::Bytes(usize::try_from(count).unwrap_or(0))),
        _ => {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::WouldBlock
                && error.kind() != io::ErrorKind::Interrupted
            {
                return Err(error.to_string());
            }
            Ok(if poll.revents & libc::POLLHUP != 0 {
                PipeRead::End
            } else {
                PipeRead::Nothing
            })
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
            io::Error::last_os_error()
        ));
    }
    // SAFETY: open returned a new descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::{AfterGo, EXEC_MARK, judge_after_go};
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
}
