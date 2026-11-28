//! The job control socket's device query (FIX
//! EXEC-NODE-PROBE-AFTER-HANDOVER): the engine reads its GPUs through root,
//! which runs the query as the job account.
//!
//! After the device hand-over (runbook 1.9 step 3; T40,
//! `scripts/execution-node/field/check_device_handoff.sh`) only the job
//! account's group opens the card's files, and the engine's account, by
//! design, does not. The engine's GPU probe ([`NvidiaSmiProbe`]) still reads
//! the cards at each ask, and its readiness check drains the node when it
//! cannot (R6's first job, mel, 26 Nov 15:28). So where the job control
//! socket listens, the probe sends `device-query <word>` there
//! ([`NvidiaSmiRoute::JobControl`]).
//!
//! The handler serves one query per connection, and one query runs on the
//! machine at a time: each handler takes the machine's query lock
//! ([`DeviceQueryLock`]) without waiting, and the query's process keeps the
//! lock's descriptor. So a query its kill cannot end (a driver call wedged
//! in the kernel) holds the lock until it does end, past the handler that
//! started it, and every later handler meanwhile refuses with `query_stuck`
//! and starts no process into the same wedge (review r2 of #10540; FIX
//! EXEC-NODE-PROBE-STUCK-QUERY-PER-HANDLER). Every handler locks the one
//! same file: it lives in a directory only root writes
//! ([`DEVICE_QUERY_LOCK_DIR`]), install makes it before the socket starts
//! ([`provision_lock`]), and a handler only opens it, never makes, removes
//! or replaces it (the Engine's extra review of #10540: in the engine's
//! state directory the engine could swap the name, and a hard link there
//! made root open a file from elsewhere). A query of the version before
//! this one locked another file, in the state directory, so install
//! refuses any entry there and leaves it as it is
//! ([`require_no_old_state_dir_lock`]; the Engine's review of #10541). The engine
//! itself holds no process and waits no longer than its deadline: it
//! connects without blocking and waits out a full listen queue only until
//! then.
//!
//! Where the socket file is there and no handler listens (`ECONNREFUSED`, a
//! file the socket unit left behind), the file went away (`ENOENT`), or this
//! account may not connect to it (`EACCES`, `EPERM`: the file's mode, or a
//! security module's denial of the connection), found at the connection
//! before any request is sent, the probe runs the tool itself, as on a
//! machine with no socket ([`DeviceQueryError::Unusable`]). A handler's
//! refusal stays a refusal (reviews r1 and r2 of #10540).
//!
//! The root handler takes only a word of [`NvidiaSmiQuery`], a closed list,
//! so the engine names no program and no argument. It reads the job account
//! from the root-owned node file ([`query_settings`]) and runs that query
//! of [`NVIDIA_SMI`], from the
//! fixed tool directories, as the job account ([`run_device_tool_as`]): in
//! its own process group, within [`GPU_QUERY_TIMEOUT`], the group killed
//! past it. The engine's account gains no power it lacked, since every job
//! it starts through this socket already runs as the job account, and the
//! card's files stay closed to it.
//!
//! The reply is `ok <n>\n` and the tool's `n` bytes of output, at most
//! [`DEVICE_QUERY_OUTPUT_MAX_BYTES`], or `refused <why>\n`.
//!
//! [`NvidiaSmiProbe`]: super::super::device::NvidiaSmiProbe
//! [`NvidiaSmiRoute::JobControl`]: super::super::device::NvidiaSmiRoute::JobControl

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::super::device::{
    DeviceToolAccount, GPU_QUERY_TIMEOUT, GpuProbeError, NVIDIA_SMI, NvidiaSmiQuery,
    run_device_tool_as,
};
use super::super::node_settings::ExecutionNodeSettings;
use super::control::{REQUEST_WAIT, read_line};
use super::exec::connect_by_deadline;
use super::safe_fs::{
    account, borrow, facts, facts_beneath, make_dir_beneath, make_lock_beneath, open_dir_beneath,
    open_dir_path, open_lock_beneath, require_owned_by_root_or, require_root_owned,
};
use super::systemd_unit::tool_path;

/// The request's verb.
pub const DEVICE_QUERY_VERB: &str = "device-query";

/// The directory of the machine's query lock: root's, mode 0700, below
/// directories that are root's too, made by `oneiron execution-node install`
/// with the lock file in it ([`provision_lock`]), so no other account can
/// make, replace or link a name there.
pub const DEVICE_QUERY_LOCK_DIR: &str = "/var/lib/oneiron-job-control";

/// The machine's query lock's file, in [`DEVICE_QUERY_LOCK_DIR`].
pub const DEVICE_QUERY_LOCK_FILE: &str = "device-query.lock";

/// The query lock's file of the version before this one (#10540), in the
/// engine's state directory: install refuses any entry there
/// ([`require_no_old_state_dir_lock`]).
pub const STATE_DIR_LOCK_FILE: &str = "device-query.lock";

/// The lock directory's mode: its owner's alone.
const DEVICE_QUERY_LOCK_DIR_MODE: u32 = 0o700;

/// The most output one query answers: a few lines a card in practice.
pub const DEVICE_QUERY_OUTPUT_MAX_BYTES: usize = 1 << 20;

/// How long the engine waits for the handler past the query's own deadline:
/// the handler's start and its reply.
const ANSWER_MARGIN: Duration = Duration::from_secs(5);

/// The longest first line of a reply the engine reads.
const REPLY_HEAD_MAX_BYTES: usize = 1024;

/// Why the engine's device query did not answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceQueryError {
    /// The socket takes no request from this process, found at the
    /// connection, before any request was sent: the file went away
    /// (`ENOENT`), no listener holds it (`ECONNREFUSED`), or this account may
    /// not connect to it (`EACCES`, `EPERM`). The probe then runs the tool
    /// itself ([`super::super::device::NvidiaSmiRoute::JobControl`]).
    Unusable { reason: String },
    /// No connection or no answer in time, the handler refused (its reason:
    /// the tool's failure, or a refusal of the request), or the reply is not
    /// one this side reads.
    Unavailable(GpuProbeError),
}

/// The request line for `query`: `device-query <word>\n`.
#[must_use]
pub fn render_request(query: NvidiaSmiQuery) -> String {
    format!("{DEVICE_QUERY_VERB} {}\n", query.word())
}

/// The device query `line` asks for: `None` when `line` is another verb's
/// request, else the query or the refusal's reason (`device_query_unknown`
/// for any word but one of [`NvidiaSmiQuery`]'s, or more words than one).
#[must_use]
pub fn parse_request(line: &[u8]) -> Option<Result<NvidiaSmiQuery, String>> {
    let rest = line
        .strip_prefix(DEVICE_QUERY_VERB.as_bytes())?
        .strip_prefix(b" ")?;
    Some(
        std::str::from_utf8(rest)
            .ok()
            .and_then(|text| text.strip_suffix('\n'))
            .and_then(NvidiaSmiQuery::from_word)
            .ok_or_else(|| "device_query_unknown".to_owned()),
    )
}

/// What the handler reads from the root-owned node file for a device query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceQuerySettings {
    /// The account the query runs as: neither root nor the engine's.
    pub account: DeviceToolAccount,
    /// The directory of the machine's query lock ([`DEVICE_QUERY_LOCK_DIR`]
    /// on an installed machine).
    pub lock_dir: PathBuf,
}

/// The device query's settings: the job account, from the root-owned node
/// file, neither root nor the engine's account (`engine_uid`), and the
/// lock's directory, [`DEVICE_QUERY_LOCK_DIR`].
///
/// # Errors
///
/// The node file is not root's alone or not there, the account does not
/// exist, or it is root or the engine's.
pub fn query_settings(node_file: &Path, engine_uid: u32) -> Result<DeviceQuerySettings, String> {
    require_root_owned(node_file)?;
    let settings = ExecutionNodeSettings::read(node_file)?
        .ok_or_else(|| format!("{}: no node file", node_file.display()))?;
    let (uid, gid, _) = account(&settings.job_account)
        .map_err(|error| format!("job account {}: {error}", settings.job_account))?;
    if uid == 0 || uid == engine_uid {
        return Err("the job account must be neither root nor the engine's".to_owned());
    }
    Ok(DeviceQuerySettings {
        account: DeviceToolAccount {
            name: settings.job_account,
            uid,
            gid,
        },
        lock_dir: PathBuf::from(DEVICE_QUERY_LOCK_DIR),
    })
}

/// The machine's device query lock: an exclusive `flock` on
/// [`DEVICE_QUERY_LOCK_FILE`], taken without waiting. The query's process
/// gets the lock's descriptor ([`run_device_tool_as`]), and the lock lasts
/// while any descriptor of it is open, so it lasts as long as the query,
/// past the handler that took it (review r2 of #10540).
///
/// Every handler must lock the one same file, so it lives in a directory
/// only root writes, below directories that are root's too
/// ([`DEVICE_QUERY_LOCK_DIR`]): no other account can put another file, a
/// link or a hard link at its name, or move the directory. Install makes
/// it ([`provision_lock`]); a handler only opens it. An entry there that is
/// not root's own empty regular file with one name and mode 0600 is refused
/// as it is: never opened, removed or made again (the Engine's extra review
/// of #10540; review r1 of #10541).
#[derive(Debug)]
pub struct DeviceQueryLock {
    file: File,
}

impl DeviceQueryLock {
    /// Takes the lock in `lock_dir`, never waiting: the directory and every
    /// one above it this process's account's (root's, on an installed
    /// machine) or root's and writable by no one else, and the file this
    /// account's own empty regular file with one name and mode 0600
    /// ([`open_lock_beneath`]).
    ///
    /// # Errors
    ///
    /// `query_stuck` while an earlier query holds the lock; else why the
    /// directory or the file is refused, or the lock's failure.
    pub fn take(lock_dir: &Path) -> Result<Self, String> {
        let failed = |why: &dyn std::fmt::Display| {
            format!(
                "device_query_lock: {}/{DEVICE_QUERY_LOCK_FILE}: {why}",
                lock_dir.display()
            )
        };
        let owner = rustix::process::geteuid().as_raw();
        let dir = open_lock_dir(lock_dir, owner).map_err(|why| failed(&why))?;
        let file = match open_lock_beneath(borrow(&dir), DEVICE_QUERY_LOCK_FILE, owner) {
            Ok(fd) => File::from(fd),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(failed(&"absent; `oneiron execution-node install` makes it"));
            }
            Err(error) => {
                return Err(failed(&format_args!("{error}; refused and left as it is")));
            }
        };
        match file.try_lock() {
            Ok(()) => Ok(Self { file }),
            Err(std::fs::TryLockError::WouldBlock) => {
                Err("query_stuck: an earlier device query has not ended".to_owned())
            }
            Err(std::fs::TryLockError::Error(error)) => Err(failed(&error)),
        }
    }
}

/// The lock directory `lock_dir`, open: it and every directory above it
/// `owner`'s or root's and writable by no one else (a sticky directory
/// above it excepted), and the directory opened `owner`'s with no group or
/// other write bit.
fn open_lock_dir(lock_dir: &Path, owner: u32) -> Result<OwnedFd, String> {
    require_owned_by_root_or(lock_dir, owner)?;
    let dir = open_dir_path(lock_dir).map_err(|error| error.to_string())?;
    let found = facts(borrow(&dir)).map_err(|error| error.to_string())?;
    if found.uid != owner {
        return Err(format!(
            "its directory is uid {}'s, not uid {owner}'s",
            found.uid
        ));
    }
    // Sticky or not: another account could still put a name there.
    if found.mode & 0o022 != 0 {
        return Err(format!(
            "its directory is writable by group or others (mode {:o})",
            found.mode
        ));
    }
    Ok(dir)
}

/// Makes the machine's query lock for [`DeviceQueryLock`], as `oneiron
/// execution-node install` does before it starts the socket, so the lock is
/// there before any request: the directory `lock_dir`, this process's
/// account's with mode 0700, beneath a parent that must be there and be
/// root's like every directory above it (one there already must be this
/// account's, and is given mode 0700), and the empty lock file in it, mode
/// 0600 whatever the umask. With whether this call made or changed
/// anything. Anything at the lock file's name but this account's own empty
/// regular file with one name and mode 0600 is refused, as it is, for its
/// maker to remove.
///
/// A directory that was there with another mode is refused and left as it
/// is: something in it may be another account's to reach, as an oneiron
/// binary the job account runs (review r2 of #10541).
///
/// # Errors
///
/// The step that failed or the entry refused, in words.
pub fn provision_lock(lock_dir: &Path) -> Result<bool, String> {
    let failed = |why: &dyn std::fmt::Display| {
        format!("the device query lock in {}: {why}", lock_dir.display())
    };
    let (Some(parent), Some(name)) = (lock_dir.parent(), lock_dir.file_name()) else {
        return Err(failed(&"not a directory below /"));
    };
    let owner = rustix::process::geteuid().as_raw();
    let group = rustix::process::getegid().as_raw();
    require_owned_by_root_or(parent, owner).map_err(|why| failed(&why))?;
    let above = open_dir_path(parent).map_err(|error| failed(&error))?;
    let mut changed = false;
    let dir = match open_dir_beneath(borrow(&above), name) {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            changed = true;
            let text = name
                .to_str()
                .ok_or_else(|| failed(&"a name that is not UTF-8"))?;
            make_dir_beneath(
                borrow(&above),
                text,
                DEVICE_QUERY_LOCK_DIR_MODE,
                (owner, group),
            )
            .map_err(|error| failed(&error))?
        }
        Err(error) => return Err(failed(&error)),
    };
    let found = facts(borrow(&dir)).map_err(|error| failed(&error))?;
    if found.uid != owner {
        return Err(failed(&format_args!(
            "owned by uid {}, not uid {owner}",
            found.uid
        )));
    }
    if found.mode != DEVICE_QUERY_LOCK_DIR_MODE {
        return Err(failed(&format_args!(
            "mode {:o}, not {DEVICE_QUERY_LOCK_DIR_MODE:o}; install changes the mode of no directory that was there: move it aside, then install again",
            found.mode
        )));
    }
    let made = make_lock_beneath(borrow(&dir), DEVICE_QUERY_LOCK_FILE, owner)
        .map_err(|error| failed(&format_args!("{error}; remove it, then install again")))?;
    Ok(changed || made)
}

/// Refuses an engine's directory `dir` (`what`: its state or payload
/// directory) that is the query lock's directory `lock_dir`, lies beneath
/// it, or holds it, as install does before it changes anything (review r1
/// of #10541): install makes `lock_dir` root's alone, mode 0700, which
/// would cut the engine off from a directory beneath it, and a lock
/// directory beneath one of the engine's is one the engine could move.
/// The paths are compared one component at a time; install opens each
/// directory on them never through a link.
///
/// # Errors
///
/// Which directory, and the lock's.
pub fn require_apart_from_lock_dir(what: &str, dir: &Path, lock_dir: &Path) -> Result<(), String> {
    if dir.starts_with(lock_dir) || lock_dir.starts_with(dir) {
        return Err(format!(
            "the {what} {} must not be, lie beneath or hold the device query lock's directory {}",
            dir.display(),
            lock_dir.display()
        ));
    }
    Ok(())
}

/// Refuses, as install does before it changes anything, the engine's state
/// and payload directories `state_dir` and `work_dir` when either overlaps
/// the query lock's directory `lock_dir` ([`require_apart_from_lock_dir`]),
/// and an oneiron `binary` beneath it: the job unit runs that binary as the
/// job account, which a directory of root's alone, mode 0700, cuts off
/// (review r2 of #10541).
///
/// # Errors
///
/// As [`require_apart_from_lock_dir`], for the first path that overlaps.
pub fn require_install_paths_apart(
    state_dir: &Path,
    work_dir: &Path,
    binary: &Path,
    lock_dir: &Path,
) -> Result<(), String> {
    require_apart_from_lock_dir("state directory", state_dir, lock_dir)?;
    require_apart_from_lock_dir("payload directory", work_dir, lock_dir)?;
    require_apart_from_lock_dir("oneiron binary", binary, lock_dir)
}

/// Refuses any entry at [`STATE_DIR_LOCK_FILE`] in the engine's state
/// directory `state_dir`, where the handlers of the version before this one
/// (#10540) kept their query lock, as install does before it changes
/// anything (the Engine's review of #10541 at 8f39ebb9). No machine ran
/// that version, so nothing is expected there; an entry means one may have,
/// and a query of it that its kill could not end may still hold that lock
/// while a handler of this version locks another file. Install never
/// opens, locks or removes the entry, which the engine's account could
/// swap under it: the refusal names the steps by hand.
///
/// # Errors
///
/// An entry is there, or the state directory could not be read.
pub fn require_no_old_state_dir_lock(state_dir: &Path) -> Result<(), String> {
    let old = state_dir.join(STATE_DIR_LOCK_FILE);
    let dir = match open_dir_path(state_dir) {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("{}: {error}", old.display())),
    };
    match facts_beneath(borrow(&dir), STATE_DIR_LOCK_FILE) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("{}: {error}", old.display())),
        Ok(_) => Err(format!(
            "{}: an entry is where the version before this one kept its query lock, so a query of that version may still hold it; install changes nothing while it is there. As root: stop oneiron.service and oneiron-job-control.socket, wait {} s (the handlers' RuntimeMaxSec), check that `systemctl list-units --all 'oneiron-job-control@*'` lists nothing (reboot if one stays), remove the entry, then install again",
            old.display(),
            super::unit_file::CONTROL_HANDLER_RUNTIME_MAX_SECS
        )),
    }
}

/// The handler's side on an installed machine: [`answer`] with
/// [`NVIDIA_SMI`] from the fixed tool directories, never from a `PATH`.
///
/// # Errors
///
/// As [`answer`], and the tool is in none of those directories.
pub fn answer_installed(
    query: NvidiaSmiQuery,
    settings: &DeviceQuerySettings,
) -> Result<Vec<u8>, String> {
    let program = tool_path(NVIDIA_SMI).ok_or_else(|| format!("{NVIDIA_SMI}: not found"))?;
    answer(query, &program, settings)
}

/// Runs `query` of `program` as the settings' account, under the machine's
/// query lock ([`DeviceQueryLock`]), and answers its output.
///
/// # Errors
///
/// An earlier query still holds the lock (`query_stuck`), the query failed
/// or did not answer in time (the probe's own reason), or its output passed
/// [`DEVICE_QUERY_OUTPUT_MAX_BYTES`].
pub fn answer(
    query: NvidiaSmiQuery,
    program: &Path,
    settings: &DeviceQuerySettings,
) -> Result<Vec<u8>, String> {
    let lock = DeviceQueryLock::take(&settings.lock_dir)?;
    // The query's process keeps its own copy of the lock's descriptor, so
    // this copy's close at the end of the call frees the lock only once the
    // query has ended too.
    let output = run_device_tool_as(
        program,
        &query.args(),
        Some(&settings.account),
        Some(&lock.file),
        DEVICE_QUERY_OUTPUT_MAX_BYTES,
    )
    .map_err(|error| match error {
        // The engine's probe names the class itself.
        GpuProbeError::Unavailable { reason } => reason,
        other => other.to_string(),
    })?;
    if output.len() > DEVICE_QUERY_OUTPUT_MAX_BYTES {
        return Err(format!(
            "device_query_output_too_long: {} bytes, at most {DEVICE_QUERY_OUTPUT_MAX_BYTES}",
            output.len()
        ));
    }
    Ok(output.into_bytes())
}

/// The engine's side of [`super::super::device::NvidiaSmiRoute::JobControl`]:
/// asks the handler at `socket` for `query` and answers the tool's output,
/// all within [`GPU_QUERY_TIMEOUT`] and a margin ([`request_within`]).
///
/// # Errors
///
/// As [`request_within`].
pub fn request(socket: &Path, query: NvidiaSmiQuery) -> Result<String, DeviceQueryError> {
    request_within(socket, query, GPU_QUERY_TIMEOUT + ANSWER_MARGIN)
}

/// [`request`] with the whole exchange, the connection, the request line and
/// the reply, within `wait` of the call. The availability answer holds the
/// slot table while the probe runs, so a listener that takes no connection
/// holds it no longer than `wait` either ([`connect_by`]; review r1 of
/// #10540).
///
/// # Errors
///
/// [`DeviceQueryError::Unusable`] when `socket` takes no request from this
/// process; else [`DeviceQueryError::Unavailable`].
pub fn request_within(
    socket: &Path,
    query: NvidiaSmiQuery,
    wait: Duration,
) -> Result<String, DeviceQueryError> {
    let unavailable =
        |reason: String| DeviceQueryError::Unavailable(GpuProbeError::Unavailable { reason });
    let fail = |error: std::io::Error| unavailable(format!("{}: {error}", socket.display()));
    let deadline = Instant::now() + wait;
    let mut stream = connect_by(socket, deadline)?;
    let write_wait = time_left(deadline).map_err(fail)?.min(REQUEST_WAIT);
    stream.set_write_timeout(Some(write_wait)).map_err(fail)?;
    stream
        .write_all(render_request(query).as_bytes())
        .map_err(fail)?;
    let head = read_line(
        &mut stream,
        REPLY_HEAD_MAX_BYTES,
        deadline.saturating_duration_since(Instant::now()),
    )
    .map_err(fail)?;
    let head = String::from_utf8_lossy(&head);
    let head = head.trim_end();
    if let Some(why) = head.strip_prefix("refused ") {
        return Err(unavailable(format!(
            "job control refused the {} query: {why}",
            query.word()
        )));
    }
    let length = head
        .strip_prefix("ok ")
        .and_then(|length| length.parse::<usize>().ok())
        .filter(|length| *length <= DEVICE_QUERY_OUTPUT_MAX_BYTES)
        .ok_or_else(|| {
            unavailable(format!(
                "job control answered the {} query with {head:?}",
                query.word()
            ))
        })?;
    let output = read_exactly(&mut stream, length, deadline).map_err(fail)?;
    String::from_utf8(output)
        .map_err(|error| unavailable(format!("the {} query's output: {error}", query.word())))
}

/// The connection to the handler at `socket`, made by `deadline`. Each try
/// connects without blocking ([`connect_by_deadline`]), and a full listen
/// queue (`EAGAIN`) is tried again until the deadline: a blocking connect
/// would wait in the kernel with no bound while the listener takes no connection.
///
/// # Errors
///
/// [`DeviceQueryError::Unusable`] for `ENOENT`, `ECONNREFUSED`, `EACCES`
/// and `EPERM`; [`DeviceQueryError::Unavailable`] for a queue still full at
/// the deadline or any other failure.
fn connect_by(socket: &Path, deadline: Instant) -> Result<UnixStream, DeviceQueryError> {
    let unavailable =
        |reason: String| DeviceQueryError::Unavailable(GpuProbeError::Unavailable { reason });
    let address = rustix::net::SocketAddrUnix::new(socket)
        .map_err(|error| unavailable(format!("{}: {error}", socket.display())))?;
    connect_by_deadline(&address, deadline).map_err(|error| match error.raw_os_error() {
        Some(libc::ENOENT | libc::ECONNREFUSED) => DeviceQueryError::Unusable {
            reason: format!(
                "no job control handler listens at {}: {error}",
                socket.display()
            ),
        },
        // The file's mode, or a security module that lets this account
        // write the socket's file but not connect to it (review r2 of
        // #10540): no request was sent, so the tool runs here.
        Some(libc::EACCES | libc::EPERM) => DeviceQueryError::Unusable {
            reason: format!(
                "this account may not connect to the job control socket at {}: {error}",
                socket.display()
            ),
        },
        _ => unavailable(format!("{}: {error}", socket.display())),
    })
}

/// The time from now to `deadline`; an error once it has passed.
fn time_left(deadline: Instant) -> std::io::Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "the query's deadline passed",
        ));
    }
    Ok(left)
}

/// Exactly `length` bytes from `stream`, all by `deadline`.
pub(super) fn read_exactly(
    stream: &mut UnixStream,
    length: usize,
    deadline: Instant,
) -> std::io::Result<Vec<u8>> {
    let mut output = vec![0_u8; length];
    let mut filled = 0;
    while filled < length {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the query's output did not arrive in time",
            ));
        }
        stream.set_read_timeout(Some(left))?;
        match stream.read(&mut output[filled..])? {
            0 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("the query's output ended after {filled} of {length} bytes"),
                ));
            }
            read => filled += read,
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_query_names_one_word_of_the_closed_list_and_nothing_else() {
        for query in NvidiaSmiQuery::ALL {
            let line = render_request(query);
            assert!(line.len() <= 64, "{line:?} fits the handler's request line");
            assert_eq!(parse_request(line.as_bytes()), Some(Ok(query)));
        }
        for bad in [
            "device-query nvidia-devices",
            "device-query nvidia-devices --query-gpu=serial\n",
            "device-query nvidia-devices\n\n",
            "device-query /usr/bin/id\n",
            "device-query NVIDIA-DEVICES\n",
            "device-query \n",
        ] {
            assert_eq!(
                parse_request(bad.as_bytes()),
                Some(Err("device_query_unknown".to_owned())),
                "{bad:?}"
            );
        }
        // Another verb's request is not a device query.
        for other in [
            "start 0123\n",
            "device-query\n",
            "device-queryx nvidia-devices\n",
        ] {
            assert_eq!(parse_request(other.as_bytes()), None, "{other:?}");
        }
    }
}
