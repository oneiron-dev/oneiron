//! The crate's single git child-process constructor plus its bounded IO and thread-pump helpers.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use super::config::{GIT_WIRE_POLL_INTERVAL, GIT_WIRE_READ_CHUNK_BYTES};
use super::retained_object::{GitSpool, RetainedGitIo, spawn_spool_reader, spawn_spool_writer};
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
    /// A retained call's whole stdout (FIX 7608 slice 2b-i): `stdout` is
    /// then empty. `None` for every captured call.
    pub(crate) spooled: Option<GitSpool>,
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
    command: &super::execution_context::GitCommandSpec<'_>,
) -> Result<GitWireProcessOutput> {
    let repo_root = command.context().root().canonicalize()?;
    if !command.effect().needs_profile() {
        return spawn_git_child(
            process_env,
            &repo_root,
            command.args(),
            command.stdin(),
            None,
            command.hold(),
            command.retained(),
        );
    }
    let profile = super::repository_profile::AdmittedRepoProfile::admit(
        process_env,
        &repo_root,
        command.prefix(),
        command.effect().creates_worktree(),
    )?;
    let scope = super::execution_scope::PreparedGitExecution::prepare(
        process_env,
        profile,
        command.effect().creates_worktree(),
    )?;
    if scope.source_changed()? {
        return Err(super::failure::invalid(
            "repository profile changed before git effect",
        ));
    }
    #[cfg(test)]
    if let Some((path, bytes)) = &process_env.after_attribute_snapshot {
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .append(true)
            .open(path)?
            .write_all(bytes)?;
    }
    let output = spawn_git_child(
        process_env,
        &repo_root,
        command.args(),
        command.stdin(),
        Some(scope.common_dir()),
        command.hold(),
        command.retained(),
    )?;
    if let Some(target) = command.worktree_target() {
        scope.rebind_created_worktree(target, output.success)?;
        if output.success
            && let Some(expected) = command.expected_commit()
        {
            let verify = [
                OsString::from("rev-parse"),
                OsString::from("--verify"),
                OsString::from("HEAD"),
            ];
            let observed = spawn_git_inner(process_env, target, &verify, None, None)?;
            if !observed.success || observed.stdout != format!("{}\n", expected.as_str()).as_bytes()
            {
                return Err(super::failure::invalid(
                    "worktree HEAD does not match the requested commit",
                ));
            }
        }
    }
    if scope.source_changed()? {
        return Err(super::failure::invalid(
            "repository profile changed during git effect",
        ));
    }
    Ok(output)
}

pub(super) fn spawn_git_inner(
    process_env: &GitWireProcessEnv,
    repo_root: &Path,
    args: &[OsString],
    stdin_payload: Option<&[u8]>,
    attribute_common_dir: Option<&Path>,
) -> Result<GitWireProcessOutput> {
    spawn_git_child(
        process_env,
        repo_root,
        args,
        stdin_payload,
        attribute_common_dir,
        None,
        None,
    )
}

/// [`spawn_git_inner`] for an effect child. With `hold`, the child inherits
/// this thread's coordinator descriptor on that common directory, so the
/// repository stays held while the child lives, past its parent's hold or
/// death. With `retained` (FIX 7608 slice 2b-i), stdin is fed from its
/// spool and stdout is spooled whole, and the child runs with no wall-clock
/// bound (Rule 5); a pump or feed that fails fails the call.
fn spawn_git_child(
    process_env: &GitWireProcessEnv,
    repo_root: &Path,
    args: &[OsString],
    stdin_payload: Option<&[u8]>,
    attribute_common_dir: Option<&Path>,
    hold: Option<&Path>,
    retained: Option<&RetainedGitIo>,
) -> Result<GitWireProcessOutput> {
    let retained = retained.filter(|io| io.is_retained());
    let retained_stdin = retained.and_then(RetainedGitIo::stdin).cloned();
    // A removed repository must not fall back to an unrelated ancestor. Git
    // excludes the ceiling itself; the working directory is still inspected.
    let ceiling = std::env::join_paths([repo_root.parent().unwrap_or(repo_root)])
        .map_err(|_| super::failure::invalid("git repository ceiling is not representable"))?;
    let git = process_env.git_binary.as_os_str();
    #[cfg(unix)]
    let mut command = match hold.and_then(super::repo::held_lock_fd) {
        Some(fd) => oneiron_spawn::command_with_fds(git, &[(fd, fd)]),
        None => oneiron_spawn::command(git),
    };
    #[cfg(not(unix))]
    let mut command = {
        let _ = hold;
        oneiron_spawn::command(git)
    };
    command.arg("-C").arg(repo_root).args(args);
    command.env_clear();
    for (key, value) in child_env(process_env) {
        command.env(key, value);
    }
    command.env("GIT_CEILING_DIRECTORIES", ceiling);
    if let Some(common) = attribute_common_dir {
        command.env("GIT_COMMON_DIR", common);
    }
    if let Some(root) = &process_env.hub_root {
        super::hub_read::configure(&mut command, root)?;
    }
    if let Some(egress) = &process_env.mirror_egress {
        super::mirror_push::configure(&mut command, egress);
    }
    if let Some(profile) = &process_env.import_profile {
        profile.configure(&mut command, repo_root)?;
    }
    let isolated = process_env.hub_root.is_some()
        || process_env.mirror_egress.is_some()
        || process_env.import_profile.is_some();
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    command.stdin(if stdin_payload.is_some() || retained_stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = command.spawn()?;
    let (writer, spool_writer) = match retained_stdin {
        Some(spool) => (None, Some(spawn_spool_writer(&mut child, spool))),
        None => (
            stdin_payload.map(|payload| spawn_stdin_writer(&mut child, payload)),
            None,
        ),
    };
    let cap = process_env.max_output_bytes;
    let spool_reader = if retained.is_some_and(RetainedGitIo::spools_stdout) {
        child
            .stdout
            .take()
            .map(|pipe| spawn_spool_reader(pipe, process_env.tmpdir.clone()))
    } else {
        None
    };
    let out_reader = child.stdout.take().map(|pipe| spawn_reader(pipe, cap));
    let err_reader = child.stderr.take().map(|pipe| spawn_reader(pipe, cap));
    // An import leg's profile and a retained call lift the wall-clock
    // bound (Rule 5); every other child keeps it.
    let timeout = match &process_env.import_profile {
        _ if retained.is_some() => None,
        Some(profile) if profile.lifts_child_bound() => None,
        _ => Some(process_env.timeout),
    };
    let status = wait_bounded(
        &mut child,
        timeout,
        process_env.hub_root.as_deref(),
        isolated,
    );
    if status.is_err() {
        stop_child(&mut child, isolated);
    }
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    let fed = spool_writer.is_none_or(|writer| writer.join().unwrap_or(false));
    let spooled = spool_reader.map(|reader| reader.join().ok().flatten());
    let (stdout, stdout_over) = join_reader(out_reader);
    let (stderr, stderr_over) = join_reader(err_reader);
    let truncated = stdout_over || stderr_over;
    let status = status?;
    let spooled = match spooled {
        Some(Some(spool)) => Some(spool),
        Some(None) => {
            return Err(super::failure::invalid(
                "a retained git output did not spool",
            ));
        }
        None => None,
    };
    let (exit_code, exited_zero) = match status {
        Some(status) => (status.code(), status.success()),
        None => (None, false),
    };
    Ok(GitWireProcessOutput {
        stdout,
        stderr,
        exit_code,
        success: exited_zero && !truncated && fed,
        timed_out: status.is_none(),
        truncated,
        spooled,
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
/// expiry; `None` waits for the child itself. An answer of `None` means the
/// bound was exceeded.
fn wait_bounded(
    child: &mut Child,
    timeout: Option<Duration>,
    hub_root: Option<&Path>,
    isolated: bool,
) -> Result<Option<ExitStatus>> {
    let deadline = timeout.map(|timeout| Instant::now() + timeout);
    loop {
        if let (Some(root), Some(deadline)) = (hub_root, deadline) {
            super::hub_read::check_budget(root, deadline)?;
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

/// The fixed environment baseline; `spawn_git` adds the repository search ceiling.
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

fn stop_child(child: &mut Child, isolated: bool) {
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
