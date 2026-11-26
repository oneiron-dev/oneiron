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
//! The handler serves one query per connection and refuses while a query of
//! its own that it killed is unreaped; a later connection's handler is a new
//! process and does not see an earlier handler's killed query (FIX
//! EXEC-NODE-PROBE-STUCK-QUERY-PER-HANDLER). The engine itself holds no
//! process and waits no longer than its deadline: it connects without
//! blocking and waits out a full listen queue only until then.
//!
//! Where the socket file is there and no handler listens (`ECONNREFUSED`, a
//! file the socket unit left behind) or the file went away (`ENOENT`), found
//! at the connection before any request is sent, the probe runs the tool
//! itself, as on a machine with no socket ([`DeviceQueryError::NoListener`]).
//! A handler's refusal stays a refusal (review r1 of #10540).
//!
//! The root handler takes only a word of [`NvidiaSmiQuery`], a closed list,
//! so the engine names no program and no argument. It reads the job account
//! from the root-owned node file and runs that query of [`NVIDIA_SMI`], from
//! the fixed tool directories, as the job account
//! ([`run_device_tool_as`]): in its own process group, within
//! [`GPU_QUERY_TIMEOUT`], the group killed past it. The engine's account
//! gains no power it lacked, since every job it starts through this socket
//! already runs as the job account, and the card's files stay closed to it.
//!
//! The reply is `ok <n>\n` and the tool's `n` bytes of output, at most
//! [`DEVICE_QUERY_OUTPUT_MAX_BYTES`], or `refused <why>\n`.
//!
//! [`NvidiaSmiProbe`]: super::super::device::NvidiaSmiProbe
//! [`NvidiaSmiRoute::JobControl`]: super::super::device::NvidiaSmiRoute::JobControl

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use super::super::device::{
    DeviceToolAccount, GPU_QUERY_TIMEOUT, GpuProbeError, NVIDIA_SMI, NvidiaSmiQuery,
    run_device_tool_as,
};
use super::super::node_settings::ExecutionNodeSettings;
use super::control::{REQUEST_WAIT, read_line};
use super::exec::connect_once;
use super::safe_fs::{account, require_root_owned};
use super::systemd_unit::tool_path;

/// The request's verb.
pub const DEVICE_QUERY_VERB: &str = "device-query";

/// The most output one query answers: a few lines a card in practice.
pub const DEVICE_QUERY_OUTPUT_MAX_BYTES: usize = 1 << 20;

/// How long the engine waits for the handler past the query's own deadline:
/// the handler's start and its reply.
const ANSWER_MARGIN: Duration = Duration::from_secs(5);

/// The longest first line of a reply the engine reads.
const REPLY_HEAD_MAX_BYTES: usize = 1024;

/// How long the engine waits before it tries again to connect while the
/// listener's queue is full.
const CONNECT_RETRY: Duration = Duration::from_millis(20);

/// Why the engine's device query did not answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceQueryError {
    /// No handler listens at the socket: the file went away (`ENOENT`) or no
    /// listener holds it (`ECONNREFUSED`), found at the connection, before
    /// any request was sent. The probe then runs the tool itself
    /// ([`super::super::device::NvidiaSmiRoute::JobControl`]).
    NoListener { reason: String },
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

/// The job account a device query runs as, from the root-owned node file:
/// neither root nor the engine's account (`engine_uid`).
///
/// # Errors
///
/// The node file is not root's alone or not there, the account does not
/// exist, or it is root or the engine's.
pub fn job_account(node_file: &Path, engine_uid: u32) -> Result<DeviceToolAccount, String> {
    require_root_owned(node_file)?;
    let settings = ExecutionNodeSettings::read(node_file)?
        .ok_or_else(|| format!("{}: no node file", node_file.display()))?;
    let (uid, gid, _) = account(&settings.job_account)
        .map_err(|error| format!("job account {}: {error}", settings.job_account))?;
    if uid == 0 || uid == engine_uid {
        return Err("the job account must be neither root nor the engine's".to_owned());
    }
    Ok(DeviceToolAccount {
        name: settings.job_account,
        uid,
        gid,
    })
}

/// The handler's side on an installed machine: [`answer`] with
/// [`NVIDIA_SMI`] from the fixed tool directories, never from a `PATH`.
///
/// # Errors
///
/// As [`answer`], and the tool is in none of those directories.
pub fn answer_installed(
    query: NvidiaSmiQuery,
    account: &DeviceToolAccount,
) -> Result<Vec<u8>, String> {
    let program = tool_path(NVIDIA_SMI).ok_or_else(|| format!("{NVIDIA_SMI}: not found"))?;
    answer(query, &program, account)
}

/// Runs `query` of `program` as `account` and answers its output.
///
/// # Errors
///
/// The query failed or did not answer in time (the probe's own reason), or
/// its output passed [`DEVICE_QUERY_OUTPUT_MAX_BYTES`].
pub fn answer(
    query: NvidiaSmiQuery,
    program: &Path,
    account: &DeviceToolAccount,
) -> Result<Vec<u8>, String> {
    let output =
        run_device_tool_as(program, &query.args(), Some(account)).map_err(|error| match error {
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
/// [`DeviceQueryError::NoListener`] when no handler listens at `socket`;
/// else [`DeviceQueryError::Unavailable`].
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
/// connects without blocking ([`connect_once`]), and a full listen queue
/// (`EAGAIN`) is tried again until the deadline: a blocking connect would
/// wait in the kernel with no bound while the listener takes no connection.
///
/// # Errors
///
/// [`DeviceQueryError::NoListener`] for `ENOENT` and `ECONNREFUSED`;
/// [`DeviceQueryError::Unavailable`] for a queue still full at the deadline
/// or any other failure.
fn connect_by(socket: &Path, deadline: Instant) -> Result<UnixStream, DeviceQueryError> {
    let unavailable =
        |reason: String| DeviceQueryError::Unavailable(GpuProbeError::Unavailable { reason });
    let address = rustix::net::SocketAddrUnix::new(socket)
        .map_err(|error| unavailable(format!("{}: {error}", socket.display())))?;
    loop {
        let error = match connect_once(&address) {
            Ok(stream) => return Ok(stream),
            Err(error) => error,
        };
        match error.raw_os_error() {
            Some(libc::ENOENT | libc::ECONNREFUSED) => {
                return Err(DeviceQueryError::NoListener {
                    reason: format!(
                        "no job control handler listens at {}: {error}",
                        socket.display()
                    ),
                });
            }
            Some(libc::EAGAIN | libc::EINTR) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(unavailable(format!(
                        "{}: the handler took no connection in time: {error}",
                        socket.display()
                    )));
                }
                std::thread::sleep(CONNECT_RETRY.min(left));
            }
            _ => return Err(unavailable(format!("{}: {error}", socket.display()))),
        }
    }
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
fn read_exactly(
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
