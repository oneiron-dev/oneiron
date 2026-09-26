//! The crate's single git child-process constructor plus its bounded IO and thread-pump helpers.

use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

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
    let repo_root = repo_root.canonicalize()?;
    // `git init` has no repository configuration to inspect. The empty argv is
    // used only by the test-only bounded-process probes; no production caller
    // passes it. Every other git child must refuse executable filter drivers
    // before the operation can read .gitattributes and run one.
    if args.is_empty()
        || args
            .first()
            .is_some_and(|arg| arg.as_os_str() == std::ffi::OsStr::new("init"))
    {
        return spawn_git_inner(process_env, &repo_root, args, stdin_payload, None);
    }
    reject_repository_filter_commands(process_env, &repo_root)?;
    if !requires_attribute_scope(args) {
        return spawn_git_inner(process_env, &repo_root, args, stdin_payload, None);
    }
    // Include conditions are evaluated again in Git's child worktree, so a
    // source-root probe cannot approve them. Refuse them before any effect.
    reject_conditional_config(process_env, &repo_root)?;
    let scope = TrustedAttributeScope::new(process_env, &repo_root, args)?;
    // Close the source-probe-to-snapshot window too: a changed repository
    // config is never certified even though the child only sees the sealed
    // common dir. Changes after this point are checked again on return.
    reject_repository_filter_commands(process_env, &repo_root)?;
    reject_conditional_config(process_env, &repo_root)?;
    if scope.source_config_changed()? {
        return Err(super::failure::invalid(
            "repository configuration changed before git effect",
        ));
    }
    #[cfg(test)]
    if let Some((path, bytes)) = &process_env.after_attribute_snapshot {
        use std::io::Write as _;
        fs::OpenOptions::new()
            .append(true)
            .open(path)?
            .write_all(bytes)?;
    }
    let output = spawn_git_inner(
        process_env,
        &repo_root,
        args,
        stdin_payload,
        Some(scope.shadow.path()),
    )?;
    // Git may write the temporary common-dir spelling into the linked
    // worktree's .git file. Replace it with the real registered directory
    // before the short-lived shadow is dropped, including on partial effects.
    scope.rebind_created_worktree(args, output.success)?;
    // A local config edit during the effect cannot reach the child, but the
    // caller must not receive a success receipt for a changed repository.
    if scope.source_config_changed()? {
        return Err(super::failure::invalid(
            "repository configuration changed during git effect",
        ));
    }
    Ok(output)
}

fn reject_repository_filter_commands(
    process_env: &GitWireProcessEnv,
    repo_root: &Path,
) -> Result<()> {
    // `--includes` considers local and per-worktree includeIf entries;
    // system/global config is already disabled by the pinned child baseline.
    // Git has no wildcard override for filter.<driver>.process/clean/smudge,
    // so an arbitrary driver must fail closed, not be enumerated from a
    // possibly changing .gitattributes file.
    let args = [
        "config",
        "--includes",
        "--null",
        "--name-only",
        "--get-regexp",
        r"^filter\..*\.(clean|smudge|process)$",
    ]
    .map(OsString::from);
    let probe = spawn_git_inner(process_env, repo_root, &args, None, None)?;
    if probe.exit_code == Some(1) && !probe.timed_out && !probe.truncated && probe.stdout.is_empty()
    {
        return Ok(());
    }
    if probe.success && !probe.stdout.is_empty() {
        return Err(super::failure::invalid(
            "repository-configured git filter commands are forbidden",
        ));
    }
    Err(super::failure::invalid(
        "unable to verify repository git filter configuration",
    ))
}

/// Only these verbs never consult working-tree attributes while executing.
/// Unknown verbs go through the isolated common-dir boundary, not the other way
/// around. `worktree add` is the one worktree subcommand that materializes files.
fn requires_attribute_scope(args: &[OsString]) -> bool {
    let mut index = 0;
    while args
        .get(index)
        .is_some_and(|arg| arg.as_os_str() == std::ffi::OsStr::new("-c"))
    {
        index += 2;
    }
    let Some(verb) = args.get(index).and_then(|arg| arg.to_str()) else {
        return true;
    };
    let tail = &args[index + 1..];
    match verb {
        "rev-parse" | "for-each-ref" | "show-ref" | "update-ref" | "config" | "remote"
        | "branch" | "mktree" | "commit-tree" | "notes" | "rev-list" | "merge-base" | "ls-tree"
        | "ls-files" | "check-ref-format" | "symbolic-ref" | "fsck" | "count-objects"
        | "pack-refs" | "prune" | "gc" | "version" => false,
        "cat-file" => tail.iter().any(|arg| {
            matches!(
                arg.to_str(),
                Some("--filters" | "--textconv" | "--batch-command")
            )
        }),
        "hash-object" => tail
            .iter()
            .any(|arg| arg.to_string_lossy().starts_with("--path")),
        "worktree" => !tail
            .first()
            .is_some_and(|arg| matches!(arg.to_str(), Some("list" | "prune" | "remove"))),
        _ => true,
    }
}

fn reject_conditional_config(process_env: &GitWireProcessEnv, repo_root: &Path) -> Result<()> {
    let args = [
        "config",
        "--null",
        "--name-only",
        "--get-regexp",
        r"^(include\.path|includeif\..*\.path)$",
    ]
    .map(OsString::from);
    let probe = spawn_git_inner(process_env, repo_root, &args, None, None)?;
    if probe.exit_code == Some(1) && !probe.timed_out && !probe.truncated && probe.stdout.is_empty()
    {
        return Ok(());
    }
    if probe.success && !probe.stdout.is_empty() {
        return Err(super::failure::invalid(
            "conditional repository configuration is forbidden for git attribute effects",
        ));
    }
    Err(super::failure::invalid(
        "unable to verify repository include configuration",
    ))
}

/// A per-child trusted Git common directory. The data-bearing refs and objects
/// still point at the proven repository, but executable configuration and
/// attribute policy come only from this private, short-lived directory.
struct TrustedAttributeScope {
    shadow: TempDir,
    common: PathBuf,
    original_config: PathBuf,
    config_before: Option<Vec<u8>>,
}

impl TrustedAttributeScope {
    fn new(process_env: &GitWireProcessEnv, repo_root: &Path, args: &[OsString]) -> Result<Self> {
        let command = [
            OsString::from("rev-parse"),
            OsString::from("--git-common-dir"),
        ];
        let observed = spawn_git_inner(process_env, repo_root, &command, None, None)?;
        if !observed.success {
            return Err(super::failure::invalid(
                "git common directory cannot be verified",
            ));
        }
        let text = std::str::from_utf8(&observed.stdout)
            .map_err(|_| super::failure::invalid("git common directory must be UTF-8"))?;
        let dir = Path::new(text.trim());
        if dir.as_os_str().is_empty() {
            return Err(super::failure::invalid("git common directory is empty"));
        }
        let common = if dir.is_absolute() {
            dir.to_path_buf()
        } else {
            repo_root.join(dir)
        }
        .canonicalize()?;
        let original_config = common.join("config");
        let config_before = read_optional_config(&original_config)?;
        let shadow = tempfile::Builder::new()
            .prefix("oneiron-git-attributes-")
            .tempdir_in(&process_env.tmpdir)?;
        fs::create_dir(shadow.path().join("info"))?;
        fs::write(shadow.path().join("info/attributes"), b"")?;
        fs::write(
            shadow.path().join("config"),
            b"[core]\n repositoryformatversion = 0\n bare = false\n filemode = true\n logallrefupdates = true\n",
        )?;
        if let Ok(exclude) = fs::read(common.join("info/exclude")) {
            fs::write(shadow.path().join("info/exclude"), exclude)?;
        }
        let worktree_add = args.windows(2).any(|pair| {
            pair[0].as_os_str() == std::ffi::OsStr::new("worktree")
                && pair[1].as_os_str() == std::ffi::OsStr::new("add")
        });
        if worktree_add {
            fs::create_dir_all(common.join("worktrees"))?;
        }
        for entry in ["objects", "refs", "logs", "worktrees", "packed-refs"] {
            let source = common.join(entry);
            if source.exists() {
                link_common_entry(&source, &shadow.path().join(entry))?;
            }
        }
        if !shadow.path().join("objects").exists() || !shadow.path().join("refs").exists() {
            return Err(super::failure::invalid(
                "git object and ref stores are unavailable",
            ));
        }
        Ok(Self {
            shadow,
            common,
            original_config,
            config_before,
        })
    }

    fn rebind_created_worktree(&self, args: &[OsString], succeeded: bool) -> Result<()> {
        let worktree_add = args.windows(2).any(|pair| {
            pair[0].as_os_str() == std::ffi::OsStr::new("worktree")
                && pair[1].as_os_str() == std::ffi::OsStr::new("add")
        });
        if !worktree_add {
            return Ok(());
        }
        let target = args
            .iter()
            .position(|arg| arg.as_os_str() == std::ffi::OsStr::new("--"))
            .and_then(|index| args.get(index + 1))
            .ok_or_else(|| super::failure::invalid("worktree add path is missing"))?;
        let git_file = Path::new(target).join(".git");
        let meta = match fs::symlink_metadata(&git_file) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !succeeded => {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        if !meta.file_type().is_file() {
            return Err(super::failure::invalid(
                "worktree gitdir is not a regular file",
            ));
        }
        let current = fs::read_to_string(&git_file)?;
        let prefix = format!("gitdir: {}/worktrees/", self.shadow.path().display());
        let Some(name) = current
            .strip_prefix(&prefix)
            .map(|text| text.trim_end_matches('\n'))
        else {
            // Some Git versions resolve the symlink themselves and write the
            // real common-dir path. Never overwrite an unrelated .git file.
            let real_prefix = format!("gitdir: {}/worktrees/", self.common.display());
            if current.starts_with(&real_prefix) {
                return Ok(());
            }
            return Err(super::failure::invalid(
                "worktree gitdir has an unexpected owner",
            ));
        };
        if name.is_empty() || name.contains('/') || name.contains('\\') {
            return Err(super::failure::invalid(
                "worktree registration name is malformed",
            ));
        }
        let registered = self.common.join("worktrees").join(name);
        if !registered.is_dir() {
            return Err(super::failure::invalid("worktree registration is missing"));
        }
        let mut replacement = tempfile::NamedTempFile::new_in(Path::new(target))?;
        writeln!(replacement, "gitdir: {}", registered.display())?;
        replacement
            .persist(&git_file)
            .map_err(|error| error.error)?;
        Ok(())
    }

    fn source_config_changed(&self) -> Result<bool> {
        Ok(read_optional_config(&self.original_config)? != self.config_before)
    }
}

fn read_optional_config(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn link_common_entry(source: &Path, target: &Path) -> Result<()> {
    std::os::unix::fs::symlink(source, target)?;
    Ok(())
}

#[cfg(not(unix))]
fn link_common_entry(_source: &Path, _target: &Path) -> Result<()> {
    Err(super::failure::invalid(
        "isolated git attributes require a supported host",
    ))
}

fn spawn_git_inner(
    process_env: &GitWireProcessEnv,
    repo_root: &Path,
    args: &[OsString],
    stdin_payload: Option<&[u8]>,
    attribute_common_dir: Option<&Path>,
) -> Result<GitWireProcessOutput> {
    // A removed repository must not fall back to an unrelated ancestor. Git
    // excludes the ceiling itself; the working directory is still inspected.
    let ceiling = std::env::join_paths([repo_root.parent().unwrap_or(repo_root)])
        .map_err(|_| super::failure::invalid("git repository ceiling is not representable"))?;
    let mut command = Command::new(process_env.git_binary.as_os_str());
    command.arg("-C").arg(repo_root).args(args);
    command.env_clear();
    for (key, value) in child_env(process_env) {
        command.env(key, value);
    }
    command.env("GIT_CEILING_DIRECTORIES", ceiling);
    if let Some(common) = attribute_common_dir {
        command.env("GIT_COMMON_DIR", common);
        command.env(
            "GIT_ATTR_SOURCE",
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
        );
    }
    if let Some(root) = &process_env.hub_root {
        super::hub_read::configure(&mut command, root)?;
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
    let status = wait_bounded(
        &mut child,
        process_env.timeout,
        process_env.hub_root.as_deref(),
    );
    if status.is_err() {
        stop_child(&mut child, process_env.hub_root.is_some());
    }
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    let (stdout, stdout_over) = join_reader(out_reader);
    let (stderr, stderr_over) = join_reader(err_reader);
    let truncated = stdout_over || stderr_over;
    let status = status?;
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
fn wait_bounded(
    child: &mut Child,
    timeout: Duration,
    hub_root: Option<&Path>,
) -> Result<Option<ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(root) = hub_root {
            super::hub_read::check_budget(root, deadline)?;
        }
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            stop_child(child, hub_root.is_some());
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
        // SAFETY: the hub profile starts this child as leader of its own process group.
        unsafe {
            libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    let _ = isolated;
    let _ = child.kill();
    let _ = child.wait();
}
