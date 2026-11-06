//! The crate's single git child-process constructor plus its bounded IO and thread-pump helpers.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use crate::git_wire::config::GIT_WIRE_CONFIG_POLICY;
use crate::git_wire::config::GIT_WIRE_FIXED_ENV;
use crate::git_wire::config::GIT_WIRE_POLL_INTERVAL;
use crate::git_wire::config::GIT_WIRE_READ_CHUNK_BYTES;
use oneiron_base::error::Result;

type ReaderHandle = std::thread::JoinHandle<(Vec<u8>, bool)>;

pub fn spawn_stdin_writer(child: &mut Child, payload: &[u8]) -> std::thread::JoinHandle<()> {
    let mut sink = child.stdin.take();
    let owned = payload.to_vec();
    std::thread::spawn(move || {
        if let Some(pipe) = sink.as_mut() {
            let _ = pipe.write_all(&owned);
            let _ = pipe.flush();
        }
        drop(sink);
    })
}

pub fn spawn_reader<R>(pipe: R, cap: usize) -> ReaderHandle
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || read_capped(pipe, cap))
}

pub fn join_reader(handle: Option<ReaderHandle>) -> (Vec<u8>, bool) {
    match handle {
        Some(handle) => handle.join().unwrap_or_else(|_| (Vec::new(), true)),
        None => (Vec::new(), false),
    }
}

/// Reads a pipe to completion under a byte cap. Once the cap is exceeded the
/// remainder is drained and discarded, so a runaway child is bounded without
/// being blocked into a deadlock.
fn read_capped<R: Read>(mut pipe: R, cap: usize) -> (Vec<u8>, bool) {
    let mut collected = Vec::new();
    let mut chunk = [0_u8; GIT_WIRE_READ_CHUNK_BYTES];
    let mut overflowed = false;
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                if overflowed || collected.len() + read > cap {
                    overflowed = true;
                } else {
                    collected.extend_from_slice(&chunk[..read]);
                }
            }
        }
    }
    (collected, overflowed)
}

/// Waits for the child under a wall-clock bound, killing and reaping it on
/// expiry; `None` waits for the child itself. An answer of `None` means the
/// bound was exceeded.
pub fn wait_bounded(
    child: &mut Child,
    timeout: Option<Duration>,
    hub_root: Option<&Path>,
    isolated: bool,
) -> Result<Option<ExitStatus>> {
    let deadline = timeout.map(|timeout| Instant::now() + timeout);
    loop {
        if let (Some(root), Some(deadline)) = (hub_root, deadline) {
            crate::git_wire::hub_read::check_budget(root, deadline)?;
        }
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            stop_child(child, isolated);
            return Ok(None);
        }
        std::thread::sleep(GIT_WIRE_POLL_INTERVAL);
    }
}

/// The only ambient-environment read GitWire performs.
pub fn ambient_env(key: &str) -> Option<OsString> {
    std::env::var_os(key)
}

/// The closed config policy rendered as git's command-line-precedence
/// environment block.
pub fn config_policy_env() -> Vec<(String, OsString)> {
    let mut pairs = Vec::with_capacity(GIT_WIRE_CONFIG_POLICY.len() * 2 + 1);
    pairs.push((
        "GIT_CONFIG_COUNT".to_owned(),
        OsString::from(GIT_WIRE_CONFIG_POLICY.len().to_string()),
    ));
    for (index, (key, value)) in GIT_WIRE_CONFIG_POLICY.into_iter().enumerate() {
        pairs.push((format!("GIT_CONFIG_KEY_{index}"), OsString::from(key)));
        pairs.push((format!("GIT_CONFIG_VALUE_{index}"), OsString::from(value)));
    }
    pairs
}

pub fn stop_child(child: &mut Child, isolated: bool) {
    #[cfg(unix)]
    if isolated {
        // SAFETY: the hub and mirror profiles start this child as leader of
        // its own process group.
        unsafe {
            libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    let _ = isolated;
    let _ = child.kill();
    let _ = child.wait();
}
