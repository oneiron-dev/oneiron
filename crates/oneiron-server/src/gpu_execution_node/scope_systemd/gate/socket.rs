//! The gate's socket and the reads on its connection ([`super`]): the
//! listening socket in a job's exchange directory, which takes the connection
//! of the unit's main process alone (FIX EXEC-UNIT-ONE-JOB-ACCOUNT), the hold
//! on that process, and the bounded reads of `job-exec`'s report.

use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use super::super::safe_fs::{self, borrow, open_dir_path, remove_beneath};
use super::super::step::RECORD_MAX_BYTES;
use super::super::{GATE_SOCKET_NAME, REPORT_FRAME_END};

/// At most this many refused connections are said in the journal, one line
/// each; the error at the deadline counts them all.
const REFUSALS_SAID_MAX: u32 = 8;

/// The time `wait` from now: the deadline of the gate's wait on its socket.
#[must_use]
pub(in super::super) fn deadline_in(wait: Duration) -> Instant {
    Instant::now() + wait
}

/// The unit's main process, `job-exec`, as the service manager names it to
/// an `ExecStartPost=` step.
pub(super) fn main_process_id() -> Result<libc::pid_t, String> {
    std::env::var("MAINPID")
        .ok()
        .and_then(|text| text.trim().parse::<libc::pid_t>().ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| "main_pid_unknown: the service manager named no MAINPID".to_owned())
}

/// A unit's main process, held by a pidfd. While the process has not been
/// reaped its id names it and no other process (review r7 R7-02).
pub(in super::super) struct MainProcess {
    pid: libc::pid_t,
    pidfd: OwnedFd,
}

impl MainProcess {
    /// Holds the process `pid`.
    ///
    /// # Errors
    ///
    /// The process is gone, or the kernel has no pidfds.
    pub(in super::super) fn hold(pid: libc::pid_t) -> Result<Self, String> {
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
pub(in super::super) trait MainProcessWatch {
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
pub(in super::super) struct GateSocket {
    listener: UnixListener,
    exchange: OwnedFd,
}

impl GateSocket {
    /// Binds [`GATE_SOCKET_NAME`] in the exchange directory `exchange` and
    /// gives it the job's own group `job_gid` and mode 0660: the job's ids
    /// may connect, and no one else but root. Only root writes in
    /// that directory, so the name is root's to make.
    ///
    /// # Errors
    ///
    /// The directory does not open, or a step failed.
    pub(in super::super) fn bind(exchange: &Path, job_gid: u32) -> Result<Self, String> {
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
    /// the job's own uid `job_uid`, and returns it. `watch` names that process;
    /// it is asked at each connection, while the peer still waits on it, and
    /// the connection is taken only while the held process has not been
    /// reaped. Every other connection is closed and said in the journal for
    /// `unit`, and the wait goes on until `until` or until `watch` ends it.
    ///
    /// # Errors
    ///
    /// No connection of the main process by `until`, the main process was
    /// reaped, `watch` ended the wait, or the socket failed.
    pub(in super::super) fn accept_main_process(
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
/// process `main_pid` under the job's own uid `job_uid` (FIX
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
            "process {} runs as uid {}, not the job's {job_uid}",
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
pub(in super::super) fn read_report(
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
pub(super) enum Received {
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

pub(super) fn read_some(
    fd: BorrowedFd<'_>,
    buffer: &mut [u8],
    left: Duration,
) -> Result<Received, String> {
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
        GATE_SOCKET_NAME, GateSocket, MainProcess, MainProcessWatch, Peer, deadline_in, peer_of,
        peer_refusal,
    };
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

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

    /// FIX EXEC-UNIT-ONE-JOB-ACCOUNT: another process with the job's ids is
    /// refused, and so is the main process's id under another uid.
    #[test]
    fn only_the_units_main_process_under_the_jobs_uid_may_answer_the_gate() {
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
            Some("process 4242 runs as uid 0, not the job's 990".to_owned())
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
            let until = deadline_in(Duration::from_millis(300));
            let mut other = MainProcess::hold(parent_process()).expect("the parent process");
            let refused = socket
                .accept_main_process(&mut other, uid, until, "test")
                .expect_err("another process's connection is not taken");
            assert!(
                refused.contains("1 other connection(s) refused"),
                "{refused}"
            );
            let _main = UnixStream::connect(&path).expect("a connection");
            let until = deadline_in(Duration::from_secs(5));
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
        let until = deadline_in(Duration::from_millis(300));
        let refused = socket
            .accept_main_process(&mut watch, uid, until, "test")
            .expect_err("a connection before the main process is named is not taken");
        assert!(
            refused.contains("1 other connection(s) refused"),
            "{refused}"
        );
        watch.named = true;
        let _main = UnixStream::connect(&path).expect("a connection");
        let until = deadline_in(Duration::from_secs(5));
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
        // The watch's own words, not the deadline's, end the wait.
        let why = socket
            .accept_main_process(
                &mut StartFailed,
                uid,
                deadline_in(Duration::from_secs(30)),
                "test",
            )
            .expect_err("no connection can come");
        assert_eq!(why, "probe_start_failed: systemd-run ended");
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
