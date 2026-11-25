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

use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use super::super::jobs::JobKeyId;
use super::safe_fs::account;
use super::systemd_unit::{SYSTEMCTL_TIMEOUT, run_tool};
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

/// The longest request line: `start ` and 32 hex digits and the newline fit
/// with room.
const REQUEST_MAX_BYTES: usize = 64;

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
}

impl ControlVerb {
    /// The request's word, which is also `systemctl`'s verb.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
        }
    }

    /// The verb a request word names.
    #[must_use]
    pub fn from_word(word: &str) -> Option<Self> {
        match word {
            "start" => Some(Self::Start),
            "stop" => Some(Self::Stop),
            _ => None,
        }
    }
}

/// The request line for `verb` on the job unit `id`: `<verb> <32 hex>\n`.
#[must_use]
pub fn render_request(verb: ControlVerb, id: &JobKeyId) -> String {
    format!("{} {id}\n", verb.word())
}

/// One request line, as the handler reads it: exactly a known verb, one
/// space, a job instance id (32 lower-hex digits) and a newline.
///
/// # Errors
///
/// The refusal's reason.
pub fn parse_request(line: &[u8]) -> Result<(ControlVerb, JobKeyId), String> {
    let text = std::str::from_utf8(line).map_err(|_| "request_not_text".to_owned())?;
    let text = text
        .strip_suffix('\n')
        .ok_or_else(|| "request_not_one_line".to_owned())?;
    let (word, id) = text
        .split_once(' ')
        .ok_or_else(|| "request_malformed".to_owned())?;
    let verb = ControlVerb::from_word(word).ok_or_else(|| "verb_unknown".to_owned())?;
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
    let fail = |error: std::io::Error| format!("{CONTROL_SOCKET_PATH}: {error}");
    let mut stream = UnixStream::connect(CONTROL_SOCKET_PATH).map_err(fail)?;
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

/// `oneiron job-control --engine-account <name>` (root, one instance of the
/// socket's handler per connection; the connection is its standard input
/// and output). Answers `ok` or `refused <reason>` on one line.
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
                Ok(()) => "ok\n".to_owned(),
                // One line: the engine reads up to the first newline
                // (review r4 R4-06).
                Err(why) => format!("refused {}\n", why.replace(['\n', '\r'], " ")),
            };
            let _ = stream.write_all(line.as_bytes());
            answer
        });
    match answer {
        Ok(()) => 0,
        Err(why) => {
            journal_line!("job-control: refused: {why}");
            1
        }
    }
}

fn serve(args: &[String], stream: &mut UnixStream) -> Result<(), String> {
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
    let job_mode = format!("--job-mode={CONTROL_JOB_MODE}");
    let unit = id.unit_name();
    run_tool(
        "systemctl",
        &[verb.word(), "--no-block", &job_mode, &unit],
        SYSTEMCTL_TIMEOUT,
    )
    .map(drop)
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
        ] {
            assert_eq!(
                parse_request(bad.as_bytes()),
                Err(why.to_owned()),
                "{bad:?}"
            );
        }
    }
}
