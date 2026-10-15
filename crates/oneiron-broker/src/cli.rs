//! `oneiron-broker serve --socket <path> --client-uid <uid> [--extra-roots <pem>]…
//! [--timeout-secs <n>]`: the separate-user broker (OSH-2). The host runs it as
//! its own OS user; the daemon's `[broker]` config names the socket and that
//! user's uid. It reads no environment and takes no key on its command line.
//!
//! `oneiron-broker child [--extra-roots <pem>]… [--timeout-secs <n>]`: the
//! same-user child (`#broker-same-user-open`). Only the daemon starts it
//! ([`crate::ChildBroker`]), with its channel on descriptor 3. It takes calls
//! over that channel alone, and exits when its stdin or the channel closes.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use crate::SendPolicy;

/// The default limit on one call, the server's provider default.
const DEFAULT_TIMEOUT_SECS: u64 = 120;

const USAGE: &str = "usage: oneiron-broker serve --socket <path> --client-uid <uid> \
                     [--extra-roots <pem file>]... [--timeout-secs <n>]\n       \
                     oneiron-broker child [--extra-roots <pem file>]... [--timeout-secs <n>]";

/// What the command line asks for.
#[cfg(unix)]
enum Mode {
    Serve(crate::ServeConfig),
    Child(SendPolicy),
}

/// The binary's entry point.
#[must_use]
pub fn main() -> ExitCode {
    match run(std::env::args_os().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("oneiron-broker: {message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(unix)]
fn run(args: Vec<OsString>) -> Result<(), String> {
    let child = args.first().map(OsString::as_os_str) == Some(std::ffi::OsStr::new("child"));
    if child {
        // First, before anything is read.
        crate::peer::confine_child()
            .map_err(|error| format!("cannot confine the child: {error}"))?;
        let channel = crate::peer::inherited_channel()
            .map_err(|error| format!("the child broker has no channel on fd 3: {error}"))?;
        let Mode::Child(policy) = parse(args)? else {
            return Err(USAGE.to_owned());
        };
        return run_child(channel, &policy);
    }
    let Mode::Serve(config) = parse(args)? else {
        return Err(USAGE.to_owned());
    };
    if config.client_uid == crate::peer::own_uid() {
        return Err(
            "--client-uid is this process's own uid; a separate-user broker \
                    runs as its own user"
                .to_owned(),
        );
    }
    crate::peer::harden().map_err(|error| format!("cannot close process memory: {error}"))?;
    runtime()?
        .block_on(crate::serve(config))
        .map_err(|error| format!("serve: {error}"))
}

/// The child serves the process that started it, over `channel`, until its
/// stdin or the channel closes.
#[cfg(unix)]
fn run_child(channel: std::os::unix::net::UnixStream, policy: &SendPolicy) -> Result<(), String> {
    use std::io::Read as _;
    std::thread::Builder::new()
        .name("lifeline".to_owned())
        .spawn(|| {
            let mut stdin = std::io::stdin();
            let mut byte = [0; 1];
            loop {
                match stdin.read(&mut byte) {
                    Ok(0) => break,
                    Err(error) if error.kind() != std::io::ErrorKind::Interrupted => break,
                    _ => {}
                }
            }
            std::process::exit(0);
        })
        .map_err(|error| format!("lifeline: {error}"))?;
    runtime()?
        .block_on(crate::serve::serve_channel(channel, policy))
        .map_err(|error| format!("serve: {error}"))
}

#[cfg(unix)]
fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("runtime: {error}"))
}

#[cfg(not(unix))]
fn run(_: Vec<OsString>) -> Result<(), String> {
    Err("the broker needs Unix sockets".to_owned())
}

#[cfg(unix)]
fn parse(args: Vec<OsString>) -> Result<Mode, String> {
    let mut args = args.into_iter();
    let child = match args.next().as_deref().and_then(std::ffi::OsStr::to_str) {
        Some("serve") => false,
        Some("child") => true,
        _ => return Err(USAGE.to_owned()),
    };
    let mut socket = None;
    let mut client_uid = None;
    let mut extra_roots = Vec::new();
    let mut timeout = Duration::from_secs(DEFAULT_TIMEOUT_SECS);
    while let Some(flag) = args.next() {
        let value = args.next().ok_or_else(|| USAGE.to_owned())?;
        match flag.to_str() {
            Some("--socket") if !child => socket = Some(PathBuf::from(value)),
            Some("--client-uid") if !child => {
                client_uid = Some(
                    value
                        .to_str()
                        .and_then(|uid| uid.parse::<u32>().ok())
                        .ok_or_else(|| USAGE.to_owned())?,
                );
            }
            Some("--extra-roots") => {
                let pem = std::fs::read(&value).map_err(|error| {
                    format!("--extra-roots {}: {error}", PathBuf::from(&value).display())
                })?;
                extra_roots.push(pem);
            }
            Some("--timeout-secs") => {
                let secs = value
                    .to_str()
                    .and_then(|secs| secs.parse::<u64>().ok())
                    .filter(|secs| *secs > 0)
                    .ok_or_else(|| USAGE.to_owned())?;
                timeout = Duration::from_secs(secs);
            }
            _ => return Err(USAGE.to_owned()),
        }
    }
    let policy = SendPolicy {
        timeout,
        extra_roots,
    };
    if child {
        return Ok(Mode::Child(policy));
    }
    Ok(Mode::Serve(crate::ServeConfig {
        socket: socket.ok_or_else(|| USAGE.to_owned())?,
        client_uid: client_uid.ok_or_else(|| USAGE.to_owned())?,
        policy,
    }))
}
