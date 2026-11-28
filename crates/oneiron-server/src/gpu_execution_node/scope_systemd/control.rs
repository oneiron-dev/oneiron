//! The job control socket: the engine's account starts and stops job units
//! through a root handler, and holds no polkit grant (review r1 of #10439,
//! P1; FIX row EXEC-UNIT-POLKIT-TRANSACTION-MODE).
//!
//! systemd hands polkit only a unit name and a verb. `StartTransientUnit`
//! asks for the same verb, `start`, so a rule that lets an account start
//! `oneiron-job@<id>.service` also lets it create a transient unit of that
//! name with any command, run as root and outside the template. The job mode
//! is not passed to polkit either. So `install` writes no rule. It writes a
//! socket unit instead: [`CONTROL_SOCKET_PATH`], owned by root, mode 0660,
//! group the engine account's. For each connection the socket starts one
//! `oneiron job-control` as root. That handler reads one request line
//! ([`parse_request`]), checks the caller's uid and the instance name, and
//! asks the service manager itself for that one job unit, always in the job
//! mode `replace`.
//!
//! The third verb, `signal <id> <name>`, is the checkpoint notice (design
//! 7.1 `Signal`; R4's `JobUnit::signal`): the handler sends one of
//! [`CHECKPOINT_SIGNALS`] to that unit's main process alone, the workload,
//! and never stops the unit. It sends it only while the unit is `active`:
//! the unit is `Type=exec` with the root gate as `ExecStartPost=`, and the
//! gate ends only after the workload's exec, so an active unit's main
//! process is the workload and never `job-exec` in its start, which a
//! checkpoint signal could end (review r6 R6-06). Before that the notice is
//! refused and lost, as a notice may be.
//!
//! The fourth verb, `renew <id> <cutoff boot ns>`, is a session's renewal
//! (pass 34, 2.5; row W1): the handler, given the node file, moves that
//! unit's cutoff forward by root's timer handoff ([`super::renew`]).
//!
//! A key runs in one of two job units (row NODE-NETWORK-HOST-UNIT,
//! [`super::network_unit`]): `start` starts the host network unit only for a
//! pin that asks `host`, `stop` stops the key's unit under each installed
//! template, and `signal` goes to the one that is active.
//!
//! The fifth, `device-query <word>`, is the engine's GPU probe after the
//! device hand-over: the handler, given the node file, runs that one query of
//! a closed list as the job account and answers its output, one query on the
//! machine at a time ([`super::device_query`]; FIX
//! EXEC-NODE-PROBE-AFTER-HANDOVER).

use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use super::super::jobs::{JobKeyId, JobUnitPhase};
use super::super::node_settings::CHECKPOINT_SIGNALS;
use super::device_query;
use super::exec::connect_by_deadline;
use super::network_unit::{self, UnitNetwork};
use super::safe_fs::account;
use super::step::{StepArgs, StepContext};
use super::systemd_unit::{SYSTEMCTL_TIMEOUT, phase_of, run_tool, show};
use super::unit_file::plain_account;

/// The socket the engine's account connects to.
pub const CONTROL_SOCKET_PATH: &str = "/run/oneiron-job-control.sock";

/// The socket unit `install` enables.
pub const CONTROL_SOCKET_UNIT: &str = "oneiron-job-control.socket";

/// The socket unit's file, as `install` writes it.
pub const CONTROL_SOCKET_UNIT_PATH: &str = "/etc/systemd/system/oneiron-job-control.socket";

/// The handler's unit template: one instance per connection (`Accept=yes`).
pub const CONTROL_SERVICE_UNIT_PATH: &str = "/etc/systemd/system/oneiron-job-control@.service";

/// The one job mode the handler asks for.
pub const CONTROL_JOB_MODE: &str = "replace";

/// The unit's `ActiveState` in which a checkpoint notice is sent: past its
/// start, so its main process is the workload (module doc).
const SIGNAL_ACTIVE_STATE: &str = "active";

/// The longest request line: `signal `, 32 hex digits, a space, the
/// longest checkpoint signal's name and the newline fit with room, and so
/// does `renew `, 32 hex digits, a space, a `u64`'s 20 digits and the
/// newline (60 bytes).
const REQUEST_MAX_BYTES: usize = 64;

/// The most digits a renewal's cutoff has: a `u64`.
const CUTOFF_DIGITS_MAX: usize = 20;

/// The longest reply line the engine reads.
const REPLY_MAX_BYTES: usize = 1024;

/// How long the handler waits for the whole request line, from its start.
/// The engine's job control connect and the socket writes wait as long.
pub(super) const REQUEST_WAIT: Duration = Duration::from_secs(5);

/// How long the engine waits for the handler's answer: the handler's own
/// `systemctl` wait ([`SYSTEMCTL_TIMEOUT`]) and its start, with room, so a
/// slow but successful start is not reported as no answer (review r4 R4-05).
pub const CONTROL_ANSWER_WAIT: Duration = Duration::from_secs(25);

/// Whether a job control socket file is at `path` and this process may
/// connect to it: it may write to the socket file (the engine's group, or
/// root). The socket unit removes the file when it stops (`RemoveOnStop=yes`);
/// a file left behind with no listener, or a connection a security module
/// denies, is found at the connection, and the GPU probe then runs its tool
/// itself ([`super::device_query::DeviceQueryError::Unusable`]).
#[must_use]
pub fn control_socket_usable(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt as _;
    std::fs::symlink_metadata(path).is_ok_and(|found| found.file_type().is_socket())
        && rustix::fs::access(path, rustix::fs::Access::WRITE_OK).is_ok()
}

/// What the engine may ask for one job unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlVerb {
    Start,
    Stop,
    /// A checkpoint notice: one of [`CHECKPOINT_SIGNALS`], by name.
    Signal(&'static str),
    /// A session's renewal (row W1): move the unit's cutoff forward to this
    /// boot-clock time.
    Renew {
        cutoff_boot_ns: u64,
    },
}

impl ControlVerb {
    /// The request's word.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Signal(_) => "signal",
            Self::Renew { .. } => "renew",
        }
    }

    /// The verb a request word names, with the signal's name for `signal`.
    ///
    /// # Errors
    ///
    /// The refusal's reason: an unknown word, a signal that is not a
    /// checkpoint signal, or a name given where none belongs.
    pub fn from_words(word: &str, signal: Option<&str>) -> Result<Self, String> {
        match (word, signal) {
            ("start", None) => Ok(Self::Start),
            ("stop", None) => Ok(Self::Stop),
            ("signal", Some(name)) => CHECKPOINT_SIGNALS
                .iter()
                .copied()
                .find(|known| *known == name)
                .map(Self::Signal)
                .ok_or_else(|| "signal_not_a_checkpoint_signal".to_owned()),
            ("signal", None) => Err("signal_name_missing".to_owned()),
            ("start" | "stop", Some(_)) => Err("request_malformed".to_owned()),
            _ => Err("verb_unknown".to_owned()),
        }
    }

    /// The `systemctl` arguments that carry the verb out on `unit`; `None`
    /// for a renewal, which root carries out itself ([`super::renew`]).
    fn systemctl_args(self, unit: &str) -> Option<Vec<String>> {
        Some(match self {
            Self::Renew { .. } => return None,
            Self::Start | Self::Stop => vec![
                self.word().to_owned(),
                "--no-block".to_owned(),
                format!("--job-mode={CONTROL_JOB_MODE}"),
                unit.to_owned(),
            ],
            Self::Signal(name) => vec![
                "kill".to_owned(),
                "--kill-whom=main".to_owned(),
                format!("--signal=SIG{name}"),
                unit.to_owned(),
            ],
        })
    }
}

/// A renewal's cutoff as the request line carries it: 1 to 20 decimal
/// digits, not zero.
fn parse_cutoff(text: &str) -> Result<u64, String> {
    let malformed = || "renew_cutoff_malformed".to_owned();
    if text.is_empty()
        || text.len() > CUTOFF_DIGITS_MAX
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(malformed());
    }
    text.parse::<u64>()
        .ok()
        .filter(|cutoff| *cutoff > 0)
        .ok_or_else(malformed)
}

/// The request line for `verb` on the job unit `id`: `<verb> <32 hex>\n`,
/// `signal <32 hex> <name>\n` or `renew <32 hex> <cutoff>\n`.
#[must_use]
pub fn render_request(verb: ControlVerb, id: &JobKeyId) -> String {
    match verb {
        ControlVerb::Signal(name) => format!("signal {id} {name}\n"),
        ControlVerb::Renew { cutoff_boot_ns } => format!("renew {id} {cutoff_boot_ns}\n"),
        ControlVerb::Start | ControlVerb::Stop => format!("{} {id}\n", verb.word()),
    }
}

/// One request line, as the handler reads it: exactly a known verb, one
/// space, a job instance id (32 lower-hex digits), for `signal` one space
/// and a checkpoint signal's name, for `renew` one space and the cutoff's
/// boot-clock time in decimal, and a newline.
///
/// # Errors
///
/// The refusal's reason.
pub fn parse_request(line: &[u8]) -> Result<(ControlVerb, JobKeyId), String> {
    let text = std::str::from_utf8(line).map_err(|_| "request_not_text".to_owned())?;
    let text = text
        .strip_suffix('\n')
        .ok_or_else(|| "request_not_one_line".to_owned())?;
    let (word, rest) = text
        .split_once(' ')
        .ok_or_else(|| "request_malformed".to_owned())?;
    let (id, extra) = match word {
        "signal" => rest
            .split_once(' ')
            .map(|(id, name)| (id, Some(name)))
            .ok_or_else(|| "signal_name_missing".to_owned())?,
        "renew" => rest
            .split_once(' ')
            .map(|(id, cutoff)| (id, Some(cutoff)))
            .ok_or_else(|| "renew_cutoff_missing".to_owned())?,
        _ => (rest, None),
    };
    let verb = match (word, extra) {
        ("renew", Some(cutoff)) => ControlVerb::Renew {
            cutoff_boot_ns: parse_cutoff(cutoff)?,
        },
        _ => ControlVerb::from_words(word, extra)?,
    };
    let id = JobKeyId::parse(id).ok_or_else(|| "instance_not_a_job".to_owned())?;
    Ok((verb, id))
}

/// The engine's side: makes the connection within `REQUEST_WAIT`, asks the
/// handler for `verb` on the job unit `id`, then waits at most
/// [`CONTROL_ANSWER_WAIT`] for its answer.
///
/// # Errors
///
/// As [`request_at`].
pub fn request(verb: ControlVerb, id: &JobKeyId) -> Result<(), String> {
    request_at(Path::new(CONTROL_SOCKET_PATH), verb, id, REQUEST_WAIT)
}

/// Asks the handler at `socket` for `verb` on the job unit `id`, allowing
/// `connect_wait` for the connection.
///
/// # Errors
///
/// The socket could not be reached or did not answer, or the handler refused
/// (its reason).
pub fn request_at(
    socket: &Path,
    verb: ControlVerb,
    id: &JobKeyId,
    connect_wait: Duration,
) -> Result<(), String> {
    let fail = |error: std::io::Error| format!("{}: {error}", socket.display());
    let deadline = Instant::now() + connect_wait;
    let address = rustix::net::SocketAddrUnix::new(socket).map_err(|error| fail(error.into()))?;
    let mut stream = connect_by_deadline(&address, deadline).map_err(fail)?;
    stream.set_write_timeout(Some(REQUEST_WAIT)).map_err(fail)?;
    stream
        .write_all(render_request(verb, id).as_bytes())
        .map_err(fail)?;
    let reply = read_line(&mut stream, REPLY_MAX_BYTES, CONTROL_ANSWER_WAIT).map_err(fail)?;
    let reply = String::from_utf8_lossy(&reply);
    let reply = reply.trim_end();
    if reply == "ok" {
        return Ok(());
    }
    Err(reply
        .strip_prefix("refused ")
        .map_or_else(|| format!("job-control answered {reply:?}"), str::to_owned))
}

/// `oneiron job-control --engine-account <name> [--node-file <path>]` (root,
/// one instance of the socket's handler per connection; the connection is
/// its standard input and output). Answers `ok` or `refused <reason>` on one
/// line. Only `renew` reads the node file; a handler installed without it
/// refuses a renewal.
#[must_use]
pub fn run(args: &[String]) -> i32 {
    let answer = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|error| format!("connection: {error}"))
        .map(UnixStream::from)
        .and_then(|mut stream| {
            let answer = serve(args, &mut stream);
            let _ = write_reply(&mut stream, &render_reply(&answer), REQUEST_WAIT);
            answer
        });
    match answer {
        Ok(_) => 0,
        Err(why) => {
            journal_line!("job-control: refused: {why}");
            1
        }
    }
}

/// Writes the handler's reply. A device query can return up to
/// [`device_query::DEVICE_QUERY_OUTPUT_MAX_BYTES`] bytes of output. The whole
/// reply gets `wait`, measured from the first byte (review r1 of #10579),
/// not each write: if the peer does not drain the reply, the root handler
/// gives up after `wait`, rather than waiting for the unit's `RuntimeMaxSec`.
/// No write starts once `wait` has passed (review r2 of #10579), so a reply
/// is never finished late.
///
/// # Errors
///
/// The stream's blocking mode could not be changed, the peer closed the
/// reply, the peer did not take the whole reply within `wait`, or a write
/// failed.
pub fn write_reply(stream: &mut UnixStream, reply: &[u8], wait: Duration) -> std::io::Result<()> {
    let deadline = Instant::now() + wait;
    stream.set_nonblocking(true)?;
    let mut written = 0;
    let mut result: std::io::Result<()> = Ok(());
    while written < reply.len() {
        // The deadline holds before every write, also after a poll that
        // ended at it: a peer that drains the reply late takes no more of it
        // (review r2 of #10579, P1).
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            result = Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the peer did not take the reply within its wait",
            ));
            break;
        }
        match stream.write(&reply[written..]) {
            Ok(0) => {
                result = Err(std::io::ErrorKind::WriteZero.into());
                break;
            }
            Ok(count) => written += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                let mut poll = libc::pollfd {
                    fd: stream.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                let sub_ms = u64::from(left.subsec_nanos() % 1_000_000 != 0);
                let millis = left.as_millis().saturating_add(u128::from(sub_ms));
                let millis = libc::c_int::try_from(millis).unwrap_or(libc::c_int::MAX);
                // SAFETY: one valid pollfd.
                let ready = unsafe { libc::poll(&raw mut poll, 1, millis) };
                if ready < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() != std::io::ErrorKind::Interrupted {
                        result = Err(error);
                        break;
                    }
                }
            }
            Err(error) => {
                result = Err(error);
                break;
            }
        }
    }
    let _ = stream.set_nonblocking(false);
    result
}

/// The handler's reply to one request: `ok\n`; for a device query, `ok <n>\n`
/// and the query's `n` bytes of output; or `refused <why>\n`, on one line,
/// since the engine reads up to the first newline (review r4 R4-06).
#[must_use]
pub fn render_reply(answer: &Result<Option<Vec<u8>>, String>) -> Vec<u8> {
    match answer {
        Ok(None) => b"ok\n".to_vec(),
        Ok(Some(output)) => {
            let mut reply = format!("ok {}\n", output.len()).into_bytes();
            reply.extend_from_slice(output);
            reply
        }
        Err(why) => format!("refused {}\n", why.replace(['\n', '\r'], " ")).into_bytes(),
    }
}

/// Serves one connection: the device query's output, `None` for the other
/// verbs, or the refusal's reason.
fn serve(args: &[String], stream: &mut UnixStream) -> Result<Option<Vec<u8>>, String> {
    let (engine, node_file) = match args {
        [flag, name] if flag == "--engine-account" && plain_account(name) => (name, None),
        [flag, name, file_flag, file]
            if flag == "--engine-account" && plain_account(name) && file_flag == "--node-file" =>
        {
            (name, Some(std::path::Path::new(file)))
        }
        _ => {
            return Err(
                "usage: job-control --engine-account <name> [--node-file <path>]".to_owned(),
            );
        }
    };
    let (engine_uid, _, _) =
        account(engine).map_err(|error| format!("engine account {engine}: {error}"))?;
    let caller = peer_uid(stream)?;
    if caller != engine_uid && caller != 0 {
        return Err(format!("caller_not_the_engine: uid {caller}"));
    }
    let line = read_line(stream, REQUEST_MAX_BYTES, REQUEST_WAIT)
        .map_err(|error| format!("request: {error}"))?;
    if let Some(query) = device_query::parse_request(&line) {
        let query = query?;
        let node_file = node_file
            .ok_or("device_query_needs_node_file: run `oneiron execution-node install` again")?;
        let settings = device_query::query_settings(node_file, engine_uid)?;
        return device_query::answer_installed(query, &settings).map(Some);
    }
    let (verb, id) = parse_request(&line)?;
    if let ControlVerb::Renew { cutoff_boot_ns } = verb {
        let node_file = node_file.ok_or(
            "renew_needs_node_file: run `oneiron execution-node install` again for sessions",
        )?;
        return super::renew::renew_cutoff(node_file, engine, &id, cutoff_boot_ns).map(|()| None);
    }
    let host_installed = network_unit::host_network_unit_installed();
    let units = match verb {
        ControlVerb::Start => vec![start_unit(engine, node_file, &id, host_installed)?],
        ControlVerb::Signal(_) => vec![active_unit(&id, host_installed)?],
        ControlVerb::Stop | ControlVerb::Renew { .. } => {
            network_unit::installed_unit_names(id.as_str(), host_installed)
        }
    };
    // A stop asks for the key's unit under each template, each asked even
    // when another refused; the first refusal answers.
    let mut answer = Ok(None);
    for unit in &units {
        let args = verb
            .systemctl_args(unit)
            .ok_or("verb_not_a_systemctl_request")?;
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        if let Err(why) = run_tool("systemctl", &args, SYSTEMCTL_TIMEOUT)
            && answer.is_ok()
        {
            answer = Err(why);
        }
    }
    answer
}

/// The unit a `start` of `id` starts: the host network unit for a pin of
/// `launch.json` that asks `host`, where that template is installed, and
/// otherwise the private one. A `launch.json` that does not read, or a
/// handler with no node file, starts the private unit, whose prepare step
/// then refuses the key with its reason, as before this row.
///
/// # Errors
///
/// `unit_of_other_network_live` while the key's unit under the other
/// template is not inactive: one key never runs in both. A service manager
/// that does not answer.
fn start_unit(
    engine: &str,
    node_file: Option<&Path>,
    id: &JobKeyId,
    host_installed: bool,
) -> Result<String, String> {
    let pin_network = node_file.and_then(|node_file| {
        let context = StepContext::open(StepArgs {
            node_file: node_file.to_owned(),
            engine_account: engine.to_owned(),
            instance: id.as_str().to_owned(),
            after_exec: false,
            host_network: false,
            host_namespace_error: None,
            stop_at_boot_ns: None,
        })
        .ok()?;
        let launch = context.read_launch().ok()?;
        (JobKeyId::for_key(&launch.key) == *id).then_some(launch.pin.network)
    });
    let network = pin_network.map_or(UnitNetwork::Private, |pin| {
        network_unit::start_unit_network(pin, host_installed)
    });
    for other in network_unit::installed_networks(host_installed) {
        if other == network {
            continue;
        }
        let other_unit = other.unit_name(id.as_str());
        let found = show(&other_unit, &["ActiveState"])?;
        let state = found.get("ActiveState").map_or("", String::as_str);
        if phase_of(state) != JobUnitPhase::Inactive {
            return Err(format!(
                "unit_of_other_network_live: {other_unit} is {state:?}"
            ));
        }
    }
    Ok(network.unit_name(id.as_str()))
}

/// The key's unit that is active, under either installed template: the one
/// a checkpoint notice goes to.
///
/// # Errors
///
/// `workload_not_running` with the private unit's state when none is
/// active, or the service manager's error.
fn active_unit(id: &JobKeyId, host_installed: bool) -> Result<String, String> {
    let mut first_state = None;
    for unit in network_unit::installed_unit_names(id.as_str(), host_installed) {
        let found = show(&unit, &["ActiveState"])?;
        let state = found.get("ActiveState").cloned().unwrap_or_default();
        if state == SIGNAL_ACTIVE_STATE {
            return Ok(unit);
        }
        first_state.get_or_insert(state);
    }
    Err(format!(
        "workload_not_running: the unit is {:?}",
        first_state.unwrap_or_default()
    ))
}

/// The uid of the process at the other end of `stream`, from the kernel
/// (`SO_PEERCRED`), not from anything it sent.
fn peer_uid(stream: &UnixStream) -> Result<u32, String> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
        .map_err(|_| "ucred size".to_owned())?;
    // SAFETY: the descriptor is open for the call, and `credentials` and
    // `length` are valid for writes of the size `length` names.
    let answer = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &raw mut length,
        )
    };
    if answer != 0 {
        return Err(format!(
            "caller_unknown: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(credentials.uid)
}

/// Bytes up to and including the first newline, at most `limit` of them,
/// all within `wait` of the call: the deadline is for the whole line, not
/// for each read, so a peer that sends a byte at a time cannot hold the
/// reader past it (review r4 R4-04).
pub(super) fn read_line(
    stream: &mut UnixStream,
    limit: usize,
    wait: Duration,
) -> std::io::Result<Vec<u8>> {
    let deadline = Instant::now() + wait;
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    while line.len() < limit {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "no whole line in time",
            ));
        }
        stream.set_read_timeout(Some(left))?;
        if stream.read(&mut byte)? == 0 {
            break;
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reply_to_a_peer_that_never_reads_gives_up_within_its_wait() {
        let (mut writer, _reader) = UnixStream::pair().expect("a connected pair");
        let wait = Duration::from_millis(200);
        let limit = wait + Duration::from_secs(3);
        let (answered, answer) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let reply = vec![0_u8; 8 << 20];
            // testkit-lint: allow(wall-clock) measures the real socket write timeout
            let started = Instant::now();
            let result = write_reply(&mut writer, &reply, wait);
            let _ = answered.send((result, started.elapsed()));
        });
        let (result, elapsed) = answer.recv_timeout(limit).expect("the write timed out");
        let error = result.expect_err("the peer never drained the reply");
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "{error}"
        );
        assert!(elapsed < limit, "the write took {elapsed:?}");
    }

    #[test]
    fn a_reply_to_a_peer_that_reads_slowly_gives_up_at_its_deadline() {
        use std::io::Read as _;
        let (mut writer, mut reader) = UnixStream::pair().expect("a connected pair");
        let wait = Duration::from_millis(200);
        let limit = wait + Duration::from_secs(3);
        std::thread::spawn(move || {
            let mut drained = [0_u8; 4096];
            loop {
                match reader.read(&mut drained) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        // testkit-lint: allow(sleep) a slow peer drains a little at a time
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            }
        });
        let (answered, answer) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let reply = vec![0_u8; 8 << 20];
            // testkit-lint: allow(wall-clock) measures the real socket write deadline
            let started = Instant::now();
            let result = write_reply(&mut writer, &reply, wait);
            let _ = answered.send((result, started.elapsed()));
        });
        let (result, elapsed) = answer.recv_timeout(limit).expect("the write answered");
        let error = result.expect_err("the slow peer never took the whole reply");
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "{error}"
        );
        assert!(
            elapsed < wait + Duration::from_secs(2),
            "the write took {elapsed:?}"
        );
    }

    /// No write starts once the wait has passed (review r2 of #10579): a
    /// reply with no wait left sends nothing, even to a peer that would take
    /// it at once, so a peer that drains late never receives a finished reply.
    #[test]
    fn no_write_starts_once_the_reply_wait_has_passed() {
        use std::io::Read as _;
        let (mut writer, mut reader) = UnixStream::pair().expect("a connected pair");
        let error = write_reply(&mut writer, b"ok\n", Duration::ZERO)
            .expect_err("a reply with no wait left is not written");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut, "{error}");
        drop(writer);
        let mut taken = Vec::new();
        reader
            .read_to_end(&mut taken)
            .expect("the peer reads the closed stream");
        assert!(taken.is_empty(), "the peer took {taken:?}");
    }

    #[test]
    fn a_request_names_a_known_verb_and_a_job_instance_and_nothing_else() {
        let id = JobKeyId::for_key("k");
        let line = render_request(ControlVerb::Start, &id);
        assert_eq!(
            parse_request(line.as_bytes()),
            Ok((ControlVerb::Start, id.clone()))
        );
        let stop = render_request(ControlVerb::Stop, &id);
        assert_eq!(
            parse_request(stop.as_bytes()),
            Ok((ControlVerb::Stop, id.clone()))
        );
        for name in CHECKPOINT_SIGNALS.iter().copied() {
            let verb = ControlVerb::from_words("signal", Some(name)).expect("a checkpoint signal");
            let line = render_request(verb, &id);
            assert_eq!(line, format!("signal {id} {name}\n"));
            assert!(line.len() <= REQUEST_MAX_BYTES);
            assert_eq!(parse_request(line.as_bytes()), Ok((verb, id.clone())));
            let signal = format!("--signal=SIG{name}");
            assert_eq!(
                verb.systemctl_args("u").expect("a systemctl request"),
                ["kill", "--kill-whom=main", signal.as_str(), "u"]
            );
            // A renewal is root's own handoff, never a systemctl request.
            assert_eq!(
                ControlVerb::Renew { cutoff_boot_ns: 5 }.systemctl_args("u"),
                None
            );
        }
        for (bad, why) in [
            (format!("start {id}"), "request_not_one_line"),
            (format!("restart {id}\n"), "verb_unknown"),
            (format!("start  {id}\n"), "instance_not_a_job"),
            (format!("start {id}.service\n"), "instance_not_a_job"),
            (
                "start oneiron-job@x.service\n".to_owned(),
                "instance_not_a_job",
            ),
            (
                format!("start {id} --job-mode=flush\n"),
                "instance_not_a_job",
            ),
            (
                format!("start {}\n", id.as_str().to_uppercase()),
                "instance_not_a_job",
            ),
            ("start\n".to_owned(), "request_malformed"),
            (format!("signal {id}\n"), "signal_name_missing"),
            (
                format!("signal {id} KILL\n"),
                "signal_not_a_checkpoint_signal",
            ),
            (
                format!("signal {id} TERM\n"),
                "signal_not_a_checkpoint_signal",
            ),
            (
                format!("signal {id} SIGUSR1\n"),
                "signal_not_a_checkpoint_signal",
            ),
            (
                format!("signal {id} USR1 USR2\n"),
                "signal_not_a_checkpoint_signal",
            ),
            (format!("signal {id}.service USR1\n"), "instance_not_a_job"),
            (format!("stop {id} USR1\n"), "instance_not_a_job"),
        ] {
            assert_eq!(
                parse_request(bad.as_bytes()),
                Err(why.to_owned()),
                "{bad:?}"
            );
        }
    }
}
