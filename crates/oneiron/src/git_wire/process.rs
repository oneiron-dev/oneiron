//! The crate's single git child-process constructor plus its bounded IO and thread-pump helpers.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use super::config::{GIT_WIRE_POLL_INTERVAL, GIT_WIRE_READ_CHUNK_BYTES};
use super::{GIT_WIRE_CONFIG_POLICY, GIT_WIRE_FIXED_ENV, GitWireProcessEnv};
use crate::error::Result;

/// Captured result of one git child process.
#[derive(Debug, Clone)]
pub(crate) struct GitWireProcessOutput {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) exit_code: Option<i32>,
    pub(crate) success: bool,
    pub(crate) timed_out: bool,
    pub(crate) truncated: bool,
}

/// The single production git subprocess constructor in this crate.
///
/// Shape: `<pinned git> -C <repo_root> <frozen argv>`. The environment is
/// cleared and rebuilt from [`GIT_WIRE_INHERITED_ENV_KEYS`], the forced
/// [`GIT_WIRE_FIXED_ENV`] pairs, and the [`GIT_WIRE_CONFIG_POLICY`] override
/// block. Runtime and captured output are bounded, stdin is written on its own
/// thread so a large payload cannot deadlock against a full output pipe, and no
/// shell is ever spawned.
pub(super) fn spawn_git(
    process_env: &GitWireProcessEnv,
    repo_root: &Path,
    args: &[OsString],
    stdin_payload: Option<&[u8]>,
) -> Result<GitWireProcessOutput> {
    let mut command = Command::new(process_env.git_binary.as_os_str());
    command.arg("-C").arg(repo_root).args(args);
    command.env_clear();
    for (key, value) in child_env(process_env) {
        command.env(key, value);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    command.stdin(if stdin_payload.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = command.spawn()?;
    let writer = stdin_payload.map(|payload| spawn_stdin_writer(&mut child, payload));
    let cap = process_env.max_output_bytes;
    let out_reader = child.stdout.take().map(|pipe| spawn_reader(pipe, cap));
    let err_reader = child.stderr.take().map(|pipe| spawn_reader(pipe, cap));
    let status = wait_bounded(&mut child, process_env.timeout)?;
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    let (stdout, stdout_over) = join_reader(out_reader);
    let (stderr, stderr_over) = join_reader(err_reader);
    let truncated = stdout_over || stderr_over;
    let (exit_code, exited_zero) = match status {
        Some(status) => (status.code(), status.success()),
        None => (None, false),
    };
    Ok(GitWireProcessOutput {
        stdout,
        stderr,
        exit_code,
        success: exited_zero && !truncated,
        timed_out: status.is_none(),
        truncated,
    })
}

type ReaderHandle = std::thread::JoinHandle<(Vec<u8>, bool)>;

fn spawn_stdin_writer(child: &mut Child, payload: &[u8]) -> std::thread::JoinHandle<()> {
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

fn spawn_reader<R>(pipe: R, cap: usize) -> ReaderHandle
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || read_capped(pipe, cap))
}

fn join_reader(handle: Option<ReaderHandle>) -> (Vec<u8>, bool) {
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
/// expiry. `None` means the bound was exceeded.
fn wait_bounded(child: &mut Child, timeout: Duration) -> Result<Option<ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        std::thread::sleep(GIT_WIRE_POLL_INTERVAL);
    }
}

/// The complete environment of a GitWire child after `env_clear`.
pub(super) fn child_env(process_env: &GitWireProcessEnv) -> Vec<(String, OsString)> {
    child_env_from(process_env, ambient_env)
}

/// The only ambient-environment read GitWire performs.
fn ambient_env(key: &str) -> Option<OsString> {
    std::env::var_os(key)
}

/// The environment builder with the ambient lookup injected.
///
/// Only [`GIT_WIRE_INHERITED_ENV_KEYS`] is ever asked of `ambient`. The fixed
/// pairs and the config-policy block are appended afterwards, so an ambient
/// `GIT_CONFIG_NOSYSTEM=0` cannot reach a child: those keys are never read from
/// the parent at all.
pub(super) fn child_env_from<F>(
    process_env: &GitWireProcessEnv,
    ambient: F,
) -> Vec<(String, OsString)>
where
    F: Fn(&str) -> Option<OsString>,
{
    let mut pairs = Vec::new();
    pairs.push(("PATH".to_owned(), process_env.path.clone()));
    pairs.push((
        "TMPDIR".to_owned(),
        process_env.tmpdir.clone().into_os_string(),
    ));
    for key in ["LANG", "LC_ALL"] {
        if let Some(value) = ambient(key) {
            pairs.push((key.to_owned(), value));
        }
    }
    for (key, value) in GIT_WIRE_FIXED_ENV {
        pairs.push((key.to_owned(), OsString::from(value)));
    }
    pairs.extend(config_policy_env());
    pairs
}

/// The closed config policy rendered as git's command-line-precedence
/// environment block.
fn config_policy_env() -> Vec<(String, OsString)> {
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
