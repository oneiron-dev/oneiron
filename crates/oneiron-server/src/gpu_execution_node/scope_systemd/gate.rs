//! The gate, `oneiron job-prepare --after-exec <id>` (root, the unit's
//! `ExecStartPost=+`). It runs once `job-exec` has started: it binds the
//! gate's socket ([`GATE_SOCKET_NAME`]) in the job's exchange directory,
//! takes the connection of the unit's main process and no other, reads
//! `job-exec`'s report on it, records the report with its verdict in
//! `scope.json`, and only then writes the go. The record is root's, so
//! whether the workload was let start is never the workload's word.
//!
//! Every job unit runs as the one job account, so another job's workload may
//! reach this job's exchange directory (through `/proc` of a process of the
//! same account, where Landlock is missing). The gate therefore asks the
//! kernel who connected (`SO_PEERCRED`) and takes only the process the
//! service manager names as the unit's main process (`MAINPID`, `job-exec`)
//! under the job account. It closes every other connection, says so in the
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

use std::io::{self, Write as _};
use std::os::fd::{AsFd as _, AsRawFd, BorrowedFd, FromRawFd as _, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use super::records::{
    BoundRequirement, ExecFile, PROVED_INSIDE, ScopeRecord, ScopeReport, first_unmet,
};
use super::safe_fs::{self, boot_ns, borrow, open_dir_path, read_beneath, remove_beneath};
use super::step::{RECORD_MAX_BYTES, StepArgs, StepContext};
use super::{
    EXEC_FILE_NAME, EXEC_MARK, GATE_GO, GATE_SOCKET_NAME, REPORT_FRAME_END, SCOPE_FILE_NAME,
};

/// How long the gate waits after its go for `job-exec` to become the
/// workload or to say why it could not.
const EXEC_WAIT: Duration = Duration::from_secs(10);

/// At most this much of an exec failure's words goes into the record.
const EXEC_FAILURE_MAX_BYTES: usize = 1024;

/// At most this many refused connections are said in the journal, one line
/// each; the error at the deadline counts them all.
const REFUSALS_SAID_MAX: u32 = 8;

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
    let until = Instant::now() + deadline;
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
    let connection = GateSocket::bind(&context.exchange_path(), context.job_gid)?
        .accept_main_process(&mut main, context.job_uid, until, &context.unit())?;
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

/// The unit's main process, `job-exec`, as the service manager names it to
/// an `ExecStartPost=` step.
fn main_process_id() -> Result<libc::pid_t, String> {
    std::env::var("MAINPID")
        .ok()
        .and_then(|text| text.trim().parse::<libc::pid_t>().ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| "main_pid_unknown: the service manager named no MAINPID".to_owned())
}

/// A unit's main process, held by a pidfd. While the process has not been
/// reaped its id names it and no other process (review r7 R7-02).
pub(super) struct MainProcess {
    pid: libc::pid_t,
    pidfd: OwnedFd,
}

impl MainProcess {
    /// Holds the process `pid`.
    ///
    /// # Errors
    ///
    /// The process is gone, or the kernel has no pidfds.
    pub(super) fn hold(pid: libc::pid_t) -> Result<Self, String> {
        // SAFETY: pidfd_open takes a process id and no flags, and returns a
        // new descriptor or -1.
        let opened = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
        let error = io::Error::last_os_error();
        let fd = libc::c_int::try_from(opened)
            .ok()
            .filter(|fd| *fd >= 0)
            .ok_or_else(|| format!("main_process_gone: process {pid}: {error}"))?;
        // SAFETY: fd is the descriptor pidfd_open just returned.
        let pidfd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self { pid, pidfd })
    }

    /// Whether the held process has not been reaped (a zombie still counts).
    fn alive(&self) -> bool {
        // SAFETY: the pidfd is open; signal 0 with a null info and no flags
        // only asks whether the very process it holds is still there.
        let sent = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                0,
                std::ptr::null::<libc::siginfo_t>(),
                0_u32,
            )
        };
        sent == 0
    }
}

/// What the gate's socket asks while it waits for a unit's main process.
pub(super) trait MainProcessWatch {
    /// The unit's main process as known now, asking for at most `left`. An
    /// error, or `None` while the service manager names none yet, refuses
    /// the connection at hand and the wait goes on (review r7 R7-03).
    ///
    /// # Errors
    ///
    /// Why the main process is not known.
    fn main_process(&mut self, left: Duration) -> Result<Option<&MainProcess>, String>;

    /// Asked before each wait for a connection: an error ends the wait at
    /// once, as when the unit's start failed (review r7 R7-04).
    ///
    /// # Errors
    ///
    /// Why no connection of the main process can come.
    fn still_starting(&mut self) -> Result<(), String> {
        Ok(())
    }
}

/// The gate's case: the main process is held from the start.
impl MainProcessWatch for MainProcess {
    fn main_process(&mut self, _left: Duration) -> Result<Option<&MainProcess>, String> {
        Ok(Some(self))
    }
}

/// How long one wait for a connection lasts before the watch is asked again.
const WATCH_SLICE: Duration = Duration::from_millis(200);

/// What the gate does with one connection.
enum Admission {
    Take,
    Refuse(String),
}

/// The gate's listening socket in a job's exchange directory. Dropping it
/// removes its name and closes it.
pub(super) struct GateSocket {
    listener: UnixListener,
    exchange: OwnedFd,
}

impl GateSocket {
    /// Binds [`GATE_SOCKET_NAME`] in the exchange directory `exchange` and
    /// gives it the job account's group `job_gid` and mode 0660: the job
    /// account may connect, and no one else but root. Only root writes in
    /// that directory, so the name is root's to make.
    ///
    /// # Errors
    ///
    /// The directory does not open, or a step failed.
    pub(super) fn bind(exchange: &Path, job_gid: u32) -> Result<Self, String> {
        let dir = open_dir_path(exchange).map_err(|error| format!("exchange_dir: {error}"))?;
        let listener = UnixListener::bind(exchange.join(GATE_SOCKET_NAME))
            .map_err(|error| format!("gate_socket: {error}"))?;
        let socket = Self {
            listener,
            exchange: dir,
        };
        safe_fs::set_group_and_mode_beneath(
            borrow(&socket.exchange),
            GATE_SOCKET_NAME,
            job_gid,
            0o660,
        )
        .map_err(|error| format!("gate_socket: {error}"))?;
        socket
            .listener
            .set_nonblocking(true)
            .map_err(|error| format!("gate_socket: {error}"))?;
        Ok(socket)
    }

    /// Takes connections until one comes from the unit's main process under
    /// the job account `job_uid`, and returns it. `watch` names that process;
    /// it is asked at each connection, while the peer still waits on it, and
    /// the connection is taken only while the held process has not been
    /// reaped. Every other connection is closed and said in the journal for
    /// `unit`, and the wait goes on until `until` or until `watch` ends it.
    ///
    /// # Errors
    ///
    /// No connection of the main process by `until`, the main process was
    /// reaped, `watch` ended the wait, or the socket failed.
    pub(super) fn accept_main_process(
        &self,
        watch: &mut dyn MainProcessWatch,
        job_uid: u32,
        until: Instant,
        unit: &str,
    ) -> Result<UnixStream, String> {
        let mut refused = 0_u32;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(format!(
                    "report_late: job-exec did not connect in time ({refused} other connection(s) refused)"
                ));
            }
            watch.still_starting()?;
            if poll_in(self.listener.as_fd(), left.min(WATCH_SLICE))?.is_none() {
                continue;
            }
            let connection = match self.listener.accept() {
                Ok((connection, _)) => connection,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(format!("gate_socket: {error}")),
            };
            let left = until.saturating_duration_since(Instant::now());
            let admission = match peer_of(&connection) {
                Err(why) => Admission::Refuse(why),
                Ok(peer) => match watch.main_process(left) {
                    Err(why) => Admission::Refuse(format!("process {}: {why}", peer.pid)),
                    Ok(None) => Admission::Refuse(format!(
                        "process {} connected before the service manager named the unit's main process",
                        peer.pid
                    )),
                    Ok(Some(main)) => match peer_refusal(peer, main.pid, job_uid) {
                        Some(why) => Admission::Refuse(why),
                        None if main.alive() => Admission::Take,
                        None => {
                            return Err(format!(
                                "main_process_gone: process {} was reaped while its connection waited",
                                main.pid
                            ));
                        }
                    },
                },
            };
            let why = match admission {
                Admission::Take => {
                    connection
                        .set_nonblocking(true)
                        .map_err(|error| format!("gate connection: {error}"))?;
                    return Ok(connection);
                }
                Admission::Refuse(why) => why,
            };
            refused = refused.saturating_add(1);
            if refused <= REFUSALS_SAID_MAX {
                journal_line!("{unit}: the gate refused a peer: {why}");
            }
        }
    }
}

impl Drop for GateSocket {
    fn drop(&mut self) {
        if let Err(error) = remove_beneath(borrow(&self.exchange), GATE_SOCKET_NAME) {
            journal_line!("{GATE_SOCKET_NAME}: not removed: {error}");
        }
    }
}

/// The process at the other end of a gate connection, as the kernel
/// recorded it at its `connect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Peer {
    pid: libc::pid_t,
    uid: u32,
}

/// The kernel's record of the process that connected (`SO_PEERCRED`).
fn peer_of(connection: &UnixStream) -> Result<Peer, String> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let size = std::mem::size_of::<libc::ucred>();
    let mut length = libc::socklen_t::try_from(size).map_err(|error| error.to_string())?;
    // SAFETY: credentials is writable for `length` bytes, and getsockopt
    // writes at most that many.
    let got = unsafe {
        libc::getsockopt(
            connection.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &raw mut length,
        )
    };
    if got != 0 {
        return Err(format!("peer credentials: {}", io::Error::last_os_error()));
    }
    if usize::try_from(length).ok() != Some(size) {
        return Err("peer credentials: a short answer".to_owned());
    }
    Ok(Peer {
        pid: credentials.pid,
        uid: credentials.uid,
    })
}

/// Why `peer` may not answer the gate, or `None` when it is the unit's main
/// process `main_pid` under the job account `job_uid` (FIX
/// EXEC-UNIT-ONE-JOB-ACCOUNT).
fn peer_refusal(peer: Peer, main_pid: libc::pid_t, job_uid: u32) -> Option<String> {
    if peer.pid != main_pid {
        return Some(format!(
            "process {} is not the unit's main process {main_pid}",
            peer.pid
        ));
    }
    if peer.uid != job_uid {
        return Some(format!(
            "process {} runs as uid {}, not the job account's {job_uid}",
            peer.pid, peer.uid
        ));
    }
    None
}

/// Reads one report from `connection`: the bytes before
/// [`REPORT_FRAME_END`], or all of them when the peer closes first, waiting
/// at most `deadline`. A byte after the report's end is refused: `job-exec`
/// says nothing more before the go.
///
/// # Errors
///
/// The report is late, too large or followed by more, or a read failed.
pub(super) fn read_report(
    connection: BorrowedFd<'_>,
    deadline: Duration,
) -> Result<Vec<u8>, String> {
    let started = Instant::now();
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let left = deadline.saturating_sub(started.elapsed());
        if left.is_zero() {
            return Err("report_late: job-exec sent no report in time".to_owned());
        }
        match read_some(connection, &mut buffer, left)
            .map_err(|why| format!("gate connection: {why}"))?
        {
            Received::Bytes(count) => {
                bytes.extend_from_slice(&buffer[..count]);
                if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > RECORD_MAX_BYTES {
                    return Err("report_too_large".to_owned());
                }
                if let Some(end) = bytes.iter().position(|byte| *byte == REPORT_FRAME_END) {
                    if end + 1 != bytes.len() {
                        return Err("report_invalid: bytes after the report".to_owned());
                    }
                    bytes.truncate(end);
                    return Ok(bytes);
                }
            }
            Received::End => return Ok(bytes),
            Received::Nothing => {}
        }
    }
}

/// One poll and read of a non-blocking descriptor.
enum Received {
    Bytes(usize),
    /// The peer closed.
    End,
    /// Nothing within the wait, or an interrupted call.
    Nothing,
}

/// Waits at most `left` for `fd` to be readable: its poll events, or `None`
/// when nothing came within the wait or the call was interrupted.
fn poll_in(fd: BorrowedFd<'_>, left: Duration) -> Result<Option<libc::c_short>, String> {
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
            Ok(None)
        } else {
            Err(error.to_string())
        };
    }
    Ok((ready > 0).then_some(poll.revents))
}

fn read_some(fd: BorrowedFd<'_>, buffer: &mut [u8], left: Duration) -> Result<Received, String> {
    let Some(revents) = poll_in(fd, left)? else {
        return Ok(Received::Nothing);
    };
    // SAFETY: buffer is writable for its length.
    let read = unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
    match read {
        0 => Ok(Received::End),
        count if count > 0 => Ok(Received::Bytes(usize::try_from(count).unwrap_or(0))),
        _ => {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::WouldBlock
                && error.kind() != io::ErrorKind::Interrupted
            {
                return Err(error.to_string());
            }
            Ok(if revents & libc::POLLHUP != 0 {
                Received::End
            } else {
                Received::Nothing
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AfterGo, EXEC_MARK, GATE_SOCKET_NAME, GateSocket, MainProcess, MainProcessWatch, Peer,
        after_go, judge_after_go, peer_of, peer_refusal,
    };
    use std::io::Write as _;
    use std::os::fd::{AsFd as _, FromRawFd as _, OwnedFd};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    const WAIT: Duration = Duration::from_secs(10);

    fn failed(why: &str) -> AfterGo {
        AfterGo::Failed(why.to_owned())
    }

    fn this_process() -> libc::pid_t {
        libc::pid_t::try_from(std::process::id()).expect("a pid fits pid_t")
    }

    fn parent_process() -> libc::pid_t {
        // SAFETY: getppid has no preconditions.
        unsafe { libc::getppid() }
    }

    /// A watch that names `main` only once `named` is set.
    struct NamedLater {
        main: MainProcess,
        named: bool,
    }

    impl MainProcessWatch for NamedLater {
        fn main_process(&mut self, _left: Duration) -> Result<Option<&MainProcess>, String> {
            Ok(self.named.then_some(&self.main))
        }
    }

    /// A watch whose unit's start failed.
    struct StartFailed;

    impl MainProcessWatch for StartFailed {
        fn main_process(&mut self, _left: Duration) -> Result<Option<&MainProcess>, String> {
            Ok(None)
        }

        fn still_starting(&mut self) -> Result<(), String> {
            Err("probe_start_failed: systemd-run ended".to_owned())
        }
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

    /// FIX EXEC-UNIT-ONE-JOB-ACCOUNT: another process of the job account
    /// (another job's workload) is refused, and so is the main process's id
    /// under another account.
    #[test]
    fn only_the_units_main_process_under_the_job_account_may_answer_the_gate() {
        let job_uid = 990;
        assert_eq!(
            peer_refusal(
                Peer {
                    pid: 4242,
                    uid: 990
                },
                4242,
                job_uid
            ),
            None
        );
        assert_eq!(
            peer_refusal(
                Peer {
                    pid: 4243,
                    uid: 990
                },
                4242,
                job_uid
            ),
            Some("process 4243 is not the unit's main process 4242".to_owned())
        );
        assert_eq!(
            peer_refusal(Peer { pid: 4242, uid: 0 }, 4242, job_uid),
            Some("process 4242 runs as uid 0, not the job account's 990".to_owned())
        );
    }

    #[test]
    fn a_connection_names_the_process_that_made_it() {
        let (ours, _theirs) = UnixStream::pair().expect("a socket pair");
        let peer = peer_of(&ours).expect("peer credentials");
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        assert_eq!(
            peer,
            Peer {
                pid: this_process(),
                uid
            }
        );
    }

    /// The socket itself, in this process: a connection whose peer is not
    /// the named main process is closed and the wait goes on to its end; the
    /// main process's connection is taken; the name goes with the socket.
    #[test]
    fn the_gate_socket_takes_only_the_main_process_and_leaves_no_name() {
        let dir = tempfile::tempdir().expect("temp dir");
        // SAFETY: getegid and geteuid have no preconditions.
        let (gid, uid) = unsafe { (libc::getegid(), libc::geteuid()) };
        let path = dir.path().join(GATE_SOCKET_NAME);
        {
            let socket = GateSocket::bind(dir.path(), gid).expect("the socket binds");
            let metadata = std::fs::symlink_metadata(&path).expect("the socket's name");
            assert_eq!(metadata.permissions().mode() & 0o7777, 0o660);
            assert_eq!(metadata.gid(), gid);
            let _other = UnixStream::connect(&path).expect("a connection");
            let until = Instant::now() + Duration::from_millis(300);
            let mut other = MainProcess::hold(parent_process()).expect("the parent process");
            let refused = socket
                .accept_main_process(&mut other, uid, until, "test")
                .expect_err("another process's connection is not taken");
            assert!(
                refused.contains("1 other connection(s) refused"),
                "{refused}"
            );
            let _main = UnixStream::connect(&path).expect("a connection");
            let until = Instant::now() + Duration::from_secs(5);
            let mut main = MainProcess::hold(this_process()).expect("this process");
            socket
                .accept_main_process(&mut main, uid, until, "test")
                .expect("the main process's connection is taken");
        }
        assert!(
            std::fs::symlink_metadata(&path).is_err(),
            "the name is gone"
        );
    }

    /// Review r7 R7-03: a connection that comes before the service manager
    /// names the main process is refused, and the wait goes on to take the
    /// main process's connection once it is named.
    #[test]
    fn a_connection_before_the_main_process_is_named_is_refused_and_the_wait_goes_on() {
        let dir = tempfile::tempdir().expect("temp dir");
        // SAFETY: getegid and geteuid have no preconditions.
        let (gid, uid) = unsafe { (libc::getegid(), libc::geteuid()) };
        let path = dir.path().join(GATE_SOCKET_NAME);
        let socket = GateSocket::bind(dir.path(), gid).expect("the socket binds");
        let mut watch = NamedLater {
            main: MainProcess::hold(this_process()).expect("this process"),
            named: false,
        };
        let _early = UnixStream::connect(&path).expect("a connection");
        let until = Instant::now() + Duration::from_millis(300);
        let refused = socket
            .accept_main_process(&mut watch, uid, until, "test")
            .expect_err("a connection before the main process is named is not taken");
        assert!(
            refused.contains("1 other connection(s) refused"),
            "{refused}"
        );
        watch.named = true;
        let _main = UnixStream::connect(&path).expect("a connection");
        let until = Instant::now() + Duration::from_secs(5);
        socket
            .accept_main_process(&mut watch, uid, until, "test")
            .expect("the named main process's connection is taken");
    }

    /// Review r7 R7-04: a watch whose unit's start failed ends the wait at
    /// once, with its own words.
    #[test]
    fn a_failed_start_ends_the_wait_at_once() {
        let dir = tempfile::tempdir().expect("temp dir");
        // SAFETY: getegid and geteuid have no preconditions.
        let (gid, uid) = unsafe { (libc::getegid(), libc::geteuid()) };
        let socket = GateSocket::bind(dir.path(), gid).expect("the socket binds");
        let started = Instant::now();
        let why = socket
            .accept_main_process(
                &mut StartFailed,
                uid,
                started + Duration::from_secs(30),
                "test",
            )
            .expect_err("no connection can come");
        assert_eq!(why, "probe_start_failed: systemd-run ended");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// Review r7 R7-02: a held process counts as there until it is reaped,
    /// and not after, whatever process later gets its id.
    #[test]
    fn a_held_main_process_is_alive_until_it_is_reaped() {
        assert!(
            MainProcess::hold(this_process())
                .expect("this process")
                .alive()
        );
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("true starts");
        let pid = libc::pid_t::try_from(child.id()).expect("a pid fits pid_t");
        let held = MainProcess::hold(pid).expect("held before it is reaped");
        child.wait().expect("the child is reaped");
        assert!(!held.alive());
    }
}
