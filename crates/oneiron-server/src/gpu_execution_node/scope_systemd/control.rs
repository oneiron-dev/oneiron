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
//! The fourth verb, `usage <id> <bytes> <entries> <depth>`, is the disk
//! check's measure (design 7.9; FIX EXEC-NODE-DISK-CHECK-UNBUILT): a job
//! runs as its own uid and may make a directory the engine's account cannot
//! list, so root walks the payload. It walks the unit's own bind source,
//! `<PAYLOAD_ROOT>/<id>`, under a root-only directory, never the engine's
//! path; it stops once it has counted more than `<bytes>`, and a payload
//! with more than `<entries>` entries or directories deeper than `<depth>`
//! (the node file's walk bounds, which the engine reads) is unmeasurable.
//! The walk's depth never passes [`PAYLOAD_DEPTH_MAX_CEILING`] and its time
//! never passes the engine's bound. The answer is `ok ` and
//! [`PayloadUsage::render`]'s line.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use super::super::jobs::payload_usage::{
    PAYLOAD_DEPTH_MAX_CEILING, PayloadWalkBounds, measure_payload_fd_counting,
};
use super::super::jobs::{JobKeyId, PayloadUsage};
use super::super::node_settings::CHECKPOINT_SIGNALS;
use super::PAYLOAD_ROOT;
use super::held_files::{HeldScan, add_unlinked_held};
use super::job_ids;
use super::safe_fs::{account, borrow, facts, open_dir_beneath, open_dir_path};
use super::systemd_unit::{SYSTEMCTL_TIMEOUT, run_tool, show};
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
/// does the longest `usage` line: `usage `, 32 hex digits, two numbers of
/// up to 20 digits and one of up to 10, each after a space, and the newline
/// (92 bytes).
const REQUEST_MAX_BYTES: usize = 128;

/// The most digits a `usage` number has: `u64::MAX`'s.
const USAGE_NUMBER_MAX_DIGITS: usize = 20;

/// The longest reply line the engine reads.
const REPLY_MAX_BYTES: usize = 1024;

/// How long the handler waits for the whole request line, from its start.
const REQUEST_WAIT: Duration = Duration::from_secs(5);

/// How long the engine waits for the handler's answer: the handler's own
/// `systemctl` wait ([`SYSTEMCTL_TIMEOUT`]) and its start, with room, so a
/// slow but successful start is not reported as no answer (review r4 R4-05).
pub const CONTROL_ANSWER_WAIT: Duration = Duration::from_secs(25);

/// What the engine may ask for one job unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlVerb {
    Start,
    Stop,
    /// A checkpoint notice: one of [`CHECKPOINT_SIGNALS`], by name.
    Signal(&'static str),
    /// The disk check's measure of the job's payload: it stops once it has
    /// counted more than `stop_past` bytes; a payload past `entries_max`
    /// entries or `depth_max` directory levels is unmeasurable.
    Usage {
        stop_past: u64,
        entries_max: u64,
        depth_max: u32,
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
            Self::Usage { .. } => "usage",
        }
    }

    /// The verb a request word names, with its argument: the signal's name
    /// for `signal`; for `usage` the byte bound, the entry bound and the
    /// depth bound, in decimal digits, each after one space.
    ///
    /// # Errors
    ///
    /// The refusal's reason: an unknown word, a signal that is not a
    /// checkpoint signal, a bound that is not a decimal number, or an
    /// argument missing or given where none belongs.
    pub fn from_words(word: &str, argument: Option<&str>) -> Result<Self, String> {
        match (word, argument) {
            ("start", None) => Ok(Self::Start),
            ("stop", None) => Ok(Self::Stop),
            ("signal", Some(name)) => CHECKPOINT_SIGNALS
                .iter()
                .copied()
                .find(|known| *known == name)
                .map(Self::Signal)
                .ok_or_else(|| "signal_not_a_checkpoint_signal".to_owned()),
            ("signal", None) => Err("signal_name_missing".to_owned()),
            ("usage", Some(bounds)) => {
                usage_bounds(bounds).ok_or_else(|| "usage_bound_malformed".to_owned())
            }
            ("usage", None) => Err("usage_bound_missing".to_owned()),
            ("start" | "stop", Some(_)) => Err("request_malformed".to_owned()),
            _ => Err("verb_unknown".to_owned()),
        }
    }

    /// The `systemctl` arguments that carry the verb out on `unit`; `None`
    /// for `usage`, which root answers itself.
    fn systemctl_args(self, unit: &str) -> Option<Vec<String>> {
        Some(match self {
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
            Self::Usage { .. } => return None,
        })
    }
}

/// A `usage` verb's three numbers, `<bytes> <entries> <depth>`: each 1 to
/// 20 decimal digits, one space between them, the depth within a `u32`.
fn usage_bounds(text: &str) -> Option<ControlVerb> {
    let number = |word: &str| -> Option<u64> {
        (!word.is_empty()
            && word.len() <= USAGE_NUMBER_MAX_DIGITS
            && word.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| word.parse().ok())
        .flatten()
    };
    let mut words = text.split(' ');
    let stop_past = number(words.next()?)?;
    let entries_max = number(words.next()?)?;
    let depth_max = u32::try_from(number(words.next()?)?).ok()?;
    if words.next().is_some() {
        return None;
    }
    Some(ControlVerb::Usage {
        stop_past,
        entries_max,
        depth_max,
    })
}

/// The request line for `verb` on the job unit `id`: `<verb> <32 hex>\n`,
/// `signal <32 hex> <name>\n` or `usage <32 hex> <bytes> <entries>
/// <depth>\n`.
#[must_use]
pub fn render_request(verb: ControlVerb, id: &JobKeyId) -> String {
    match verb {
        ControlVerb::Signal(name) => format!("signal {id} {name}\n"),
        ControlVerb::Usage {
            stop_past,
            entries_max,
            depth_max,
        } => format!("usage {id} {stop_past} {entries_max} {depth_max}\n"),
        ControlVerb::Start | ControlVerb::Stop => format!("{} {id}\n", verb.word()),
    }
}

/// One request line, as the handler reads it: exactly a known verb, one
/// space, a job instance id (32 lower-hex digits), for `signal` one space
/// and a checkpoint signal's name, for `usage` its three numbers, each
/// after one space, and a newline.
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
    let (id, argument) = match word {
        "signal" => rest
            .split_once(' ')
            .map(|(id, name)| (id, Some(name)))
            .ok_or_else(|| "signal_name_missing".to_owned())?,
        "usage" => rest
            .split_once(' ')
            .map(|(id, bounds)| (id, Some(bounds)))
            .ok_or_else(|| "usage_bound_missing".to_owned())?,
        _ => (rest, None),
    };
    let verb = ControlVerb::from_words(word, argument)?;
    let id = JobKeyId::parse(id).ok_or_else(|| "instance_not_a_job".to_owned())?;
    Ok((verb, id))
}

/// The engine's side: asks the handler for `verb` on the job unit `id` and
/// waits at most [`CONTROL_ANSWER_WAIT`] for its answer.
///
/// # Errors
///
/// The socket is missing or did not answer, or the handler refused (its
/// reason).
pub fn request(verb: ControlVerb, id: &JobKeyId) -> Result<(), String> {
    exchange(verb, id).map(drop)
}

/// The disk check's measure of the job `id`'s payload, as root walked it
/// within `bounds` (their depth and entries; the time bound is root's own),
/// stopping once it has counted more than `stop_past` bytes.
///
/// # Errors
///
/// As [`request`], and an answer that is not a measure.
pub fn request_usage(
    id: &JobKeyId,
    stop_past: u64,
    bounds: &PayloadWalkBounds,
) -> Result<PayloadUsage, String> {
    let verb = ControlVerb::Usage {
        stop_past,
        entries_max: bounds.entries_max,
        depth_max: bounds.depth_max,
    };
    let answer = exchange(verb, id)?;
    PayloadUsage::parse(&answer).ok_or_else(|| format!("job-control answered usage {answer:?}"))
}

/// Sends the request and reads the answer: what follows `ok` on its line
/// (empty for `start`, `stop` and `signal`).
fn exchange(verb: ControlVerb, id: &JobKeyId) -> Result<String, String> {
    let fail = |error: std::io::Error| format!("{CONTROL_SOCKET_PATH}: {error}");
    let mut stream = connect_within(Path::new(CONTROL_SOCKET_PATH), CONNECT_WAIT).map_err(fail)?;
    stream.set_write_timeout(Some(REQUEST_WAIT)).map_err(fail)?;
    stream
        .write_all(render_request(verb, id).as_bytes())
        .map_err(fail)?;
    let reply = read_line(&mut stream, REPLY_MAX_BYTES, CONTROL_ANSWER_WAIT).map_err(fail)?;
    let reply = String::from_utf8_lossy(&reply);
    let reply = reply.trim_end();
    if reply == "ok" {
        return Ok(String::new());
    }
    if let Some(answer) = reply.strip_prefix("ok ") {
        return Ok(answer.to_owned());
    }
    Err(reply
        .strip_prefix("refused ")
        .map_or_else(|| format!("job-control answered {reply:?}"), str::to_owned))
}

/// The longest the engine waits for the socket to take its connection: a
/// full accept queue (the service manager not accepting for a while) holds
/// a blocking connect for as long as it lasts (review r13 R13-15).
const CONNECT_WAIT: Duration = Duration::from_secs(5);

/// The pause between two connection tries while the accept queue is full.
const CONNECT_RETRY_PAUSE: Duration = Duration::from_millis(50);

/// A connection to the stream socket at `path`, made within `wait`: each
/// try does not block, and a full accept queue is tried again until the
/// wait ends. The connection is then made blocking.
fn connect_within(path: &Path, wait: Duration) -> std::io::Result<UnixStream> {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
    let address = SocketAddrUnix::new(path)?;
    let deadline = Instant::now() + wait;
    loop {
        let socket = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )?;
        match rustix::net::connect(&socket, &address) {
            Ok(()) => {
                rustix::io::ioctl_fionbio(&socket, false)?;
                return Ok(UnixStream::from(socket));
            }
            Err(rustix::io::Errno::AGAIN) if Instant::now() < deadline => {
                std::thread::sleep(CONNECT_RETRY_PAUSE);
            }
            Err(rustix::io::Errno::AGAIN) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("not accepted within {} s", wait.as_secs()),
                ));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// `oneiron job-control --engine-account <name>` (root, one instance of the
/// socket's handler per connection; the connection is its standard input
/// and output). Answers `ok`, `ok <measure>` for `usage`, or
/// `refused <reason>` on one line.
#[must_use]
pub fn run(args: &[String]) -> i32 {
    let answer = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|error| format!("connection: {error}"))
        .map(UnixStream::from)
        .and_then(|mut stream| {
            let answer = serve(args, &mut stream);
            let line = match &answer {
                Ok(measure) if measure.is_empty() => "ok\n".to_owned(),
                Ok(measure) => format!("ok {measure}\n"),
                // One line: the engine reads up to the first newline
                // (review r4 R4-06).
                Err(why) => format!("refused {}\n", why.replace(['\n', '\r'], " ")),
            };
            let _ = stream.write_all(line.as_bytes());
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

/// Carries out one request: `Ok` with the measure for `usage`, else empty.
fn serve(args: &[String], stream: &mut UnixStream) -> Result<String, String> {
    let engine = match args {
        [flag, name] if flag == "--engine-account" && plain_account(name) => name,
        _ => return Err("usage: job-control --engine-account <name>".to_owned()),
    };
    let (engine_uid, _, _) =
        account(engine).map_err(|error| format!("engine account {engine}: {error}"))?;
    let caller = peer_uid(stream)?;
    if caller != engine_uid && caller != 0 {
        return Err(format!("caller_not_the_engine: uid {caller}"));
    }
    let line = read_line(stream, REQUEST_MAX_BYTES, REQUEST_WAIT)
        .map_err(|error| format!("request: {error}"))?;
    let (verb, id) = parse_request(&line)?;
    if let ControlVerb::Usage {
        stop_past,
        entries_max,
        depth_max,
    } = verb
    {
        let bounds = PayloadWalkBounds {
            depth_max: depth_max.min(PAYLOAD_DEPTH_MAX_CEILING),
            entries_max,
            ..PayloadWalkBounds::default()
        };
        return payload_usage(&id, stop_past, &bounds).map(|usage| usage.render());
    }
    let unit = id.unit_name();
    if matches!(verb, ControlVerb::Signal(_)) {
        let found = show(&unit, &["ActiveState"])?;
        let state = found.get("ActiveState").map_or("", String::as_str);
        if state != SIGNAL_ACTIVE_STATE {
            return Err(format!("workload_not_running: the unit is {state:?}"));
        }
    }
    let args = verb
        .systemctl_args(&unit)
        .ok_or_else(|| "verb_unknown".to_owned())?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    run_tool("systemctl", &args, SYSTEMCTL_TIMEOUT).map(|_| String::new())
}

/// Root's measure of the job `id`'s payload: the unit's bind source
/// `<PAYLOAD_ROOT>/<id>`, opened beneath the root-only payload root and
/// never through a link, so the walk counts the directory the unit binds
/// and no path the engine's account could replace (the bind carries no
/// submount), and then the inodes on a device the walk met that the unit's
/// tasks hold with no name left and the job's uid owns (review r12 R12-01,
/// r13 R13-01..R13-04, r14 R14-08). Both within the walk's time bound, from
/// the request's start; the held files' links have a bound of their own,
/// the size of the walk's entry bound (r14 R14-10).
fn payload_usage(
    id: &JobKeyId,
    stop_past: u64,
    bounds: &PayloadWalkBounds,
) -> Result<PayloadUsage, String> {
    let deadline = Instant::now() + bounds.time_max;
    let unit = id.unit_name();
    let found = show(&unit, &["ControlGroup"])?;
    let control_group = found.get("ControlGroup").map_or("", String::as_str);
    // The job's uid, from root's id table: a running job unit holds one
    // entry (FIX EXEC-UNIT-CROSS-JOB-SAME-UID).
    let job_uid = job_ids::identity_of(&unit)
        .ok_or_else(|| format!("payload_not_measured: {unit} holds no id in the id table"))?
        .uid;
    let root = open_dir_path(Path::new(PAYLOAD_ROOT))
        .map_err(|error| format!("payload_not_published: {error}"))?;
    let root_facts = facts(borrow(&root)).map_err(|error| format!("payload_root: {error}"))?;
    if root_facts.uid != 0 || root_facts.mode & 0o077 != 0 {
        return Err(format!(
            "payload_root_not_root_only: {PAYLOAD_ROOT} is uid {} mode {:o}",
            root_facts.uid, root_facts.mode
        ));
    }
    let payload = open_dir_beneath(borrow(&root), OsStr::new(id.as_str()))
        .map_err(|error| format!("payload_not_published: {error}"))?;
    let walk_bounds = PayloadWalkBounds {
        time_max: deadline.saturating_duration_since(Instant::now()),
        ..bounds.clone()
    };
    let mut counted = HashSet::new();
    let walked = measure_payload_fd_counting(payload, stop_past, &walk_bounds, &mut counted)
        .map_err(|error| format!("payload_not_measured: {error}"))?;
    let PayloadUsage::Measured { bytes } = walked else {
        return Ok(walked);
    };
    // The payload directory's own device is among them: the walk counts it.
    let payload_devices: HashSet<u64> = counted.iter().map(|&(device, _)| device).collect();
    let scan = HeldScan {
        control_group,
        payload_devices: &payload_devices,
        job_uid,
        deadline,
        links_max: bounds.entries_max,
    };
    add_unlinked_held(&scan, &mut counted, bytes, stop_past)
        .map_err(|why| format!("payload_not_measured: {why}"))
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
fn read_line(stream: &mut UnixStream, limit: usize, wait: Duration) -> std::io::Result<Vec<u8>> {
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
                verb.systemctl_args("u"),
                Some(vec![
                    "kill".to_owned(),
                    "--kill-whom=main".to_owned(),
                    signal,
                    "u".to_owned()
                ])
            );
        }
        for (stop_past, entries_max, depth_max) in [
            (0, 1, 1),
            (1_048_576, 1_000_000, 64),
            (u64::MAX, u64::MAX, u32::MAX),
        ] {
            let verb = ControlVerb::Usage {
                stop_past,
                entries_max,
                depth_max,
            };
            let line = render_request(verb, &id);
            assert_eq!(
                line,
                format!("usage {id} {stop_past} {entries_max} {depth_max}\n")
            );
            assert!(line.len() <= REQUEST_MAX_BYTES);
            assert_eq!(parse_request(line.as_bytes()), Ok((verb, id.clone())));
            assert_eq!(verb.systemctl_args("u"), None);
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
            (format!("usage {id}\n"), "usage_bound_missing"),
            (format!("usage {id} \n"), "usage_bound_malformed"),
            (format!("usage {id} 5\n"), "usage_bound_malformed"),
            (format!("usage {id} 5 6\n"), "usage_bound_malformed"),
            (format!("usage {id} -1 6 7\n"), "usage_bound_malformed"),
            (format!("usage {id} +5 6 7\n"), "usage_bound_malformed"),
            (format!("usage {id} 5  6 7\n"), "usage_bound_malformed"),
            (format!("usage {id} 5 6 7 8\n"), "usage_bound_malformed"),
            (
                format!("usage {id} 18446744073709551616 6 7\n"),
                "usage_bound_malformed",
            ),
            (
                format!("usage {id} 5 6 4294967296\n"),
                "usage_bound_malformed",
            ),
            (format!("usage {id}.service 5 6 7\n"), "instance_not_a_job"),
        ] {
            assert_eq!(
                parse_request(bad.as_bytes()),
                Err(why.to_owned()),
                "{bad:?}"
            );
        }
    }
}
