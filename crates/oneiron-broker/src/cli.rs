//! `oneiron-broker serve --socket <path> --client-uid <uid> [--extra-roots <pem>]…
//! [--timeout-secs <n>]`: the separate-user broker (OSH-2). The host runs it as
//! its own OS user; the daemon's `[broker]` config names the socket and that
//! user's uid. It reads no environment and takes no key on its command line.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use crate::SendPolicy;

/// The default limit on one call, the server's provider default.
const DEFAULT_TIMEOUT_SECS: u64 = 120;

const USAGE: &str = "usage: oneiron-broker serve --socket <path> --client-uid <uid> \
                     [--extra-roots <pem file>]... [--timeout-secs <n>]";

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
    let config = parse(args)?;
    if config.client_uid == crate::peer::own_uid() {
        return Err(
            "--client-uid is this process's own uid; a separate-user broker \
                    runs as its own user"
                .to_owned(),
        );
    }
    crate::peer::harden().map_err(|error| format!("cannot close process memory: {error}"))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("runtime: {error}"))?;
    runtime
        .block_on(crate::serve(config))
        .map_err(|error| format!("serve: {error}"))
}

#[cfg(not(unix))]
fn run(_: Vec<OsString>) -> Result<(), String> {
    Err("the broker needs Unix sockets".to_owned())
}

#[cfg(unix)]
fn parse(args: Vec<OsString>) -> Result<crate::ServeConfig, String> {
    let mut args = args.into_iter();
    if args.next().as_deref() != Some(std::ffi::OsStr::new("serve")) {
        return Err(USAGE.to_owned());
    }
    let mut socket = None;
    let mut client_uid = None;
    let mut extra_roots = Vec::new();
    let mut timeout = Duration::from_secs(DEFAULT_TIMEOUT_SECS);
    while let Some(flag) = args.next() {
        let value = args.next().ok_or_else(|| USAGE.to_owned())?;
        match flag.to_str() {
            Some("--socket") => socket = Some(PathBuf::from(value)),
            Some("--client-uid") => {
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
    Ok(crate::ServeConfig {
        socket: socket.ok_or_else(|| USAGE.to_owned())?,
        client_uid: client_uid.ok_or_else(|| USAGE.to_owned())?,
        policy: SendPolicy {
            timeout,
            extra_roots,
        },
    })
}
