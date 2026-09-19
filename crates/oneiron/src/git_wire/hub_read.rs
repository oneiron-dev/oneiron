//! Fixed network-read profile for a private disposable hub object store.
//! No caller-controlled config pairs, checkout, hooks or inherited credentials.
use super::failure::invalid;
use super::{GitWireProcessEnv, process::spawn_git};
use crate::error::Result;
use std::{
    path::Path,
    process::Command,
    time::{Duration, Instant},
};
const DISK_LIMIT: u64 = 128 * 1024 * 1024;
#[cfg(unix)]
const FILE_LIMIT: u64 = 64 * 1024 * 1024;

pub(crate) fn read_hub_git(root: &Path, args: &[&str], limit: usize) -> Result<Vec<u8>> {
    // This internal door only touches the caller-owned scratch repository.
    // It cannot become a general mutation bridge or accept arbitrary -c pairs.
    let valid = args == ["init", "--bare", "--quiet", "repo"]
        || (args.first() == Some(&"--git-dir=repo")
            && match args.get(1).copied() {
                Some("config") => {
                    args.len() == 4
                        && matches!(
                            args[2],
                            "remote.origin.url"
                                | "remote.origin.promisor"
                                | "remote.origin.partialclonefilter"
                        )
                }
                Some("fetch") => {
                    args.len() == 10
                        && args[2..9]
                            == [
                                "--quiet",
                                "--no-tags",
                                "--no-recurse-submodules",
                                "--depth=1",
                                "--filter=blob:none",
                                "--",
                                "origin",
                            ]
                }
                Some("rev-parse") => args[2..] == ["--verify", "FETCH_HEAD^{commit}"],
                Some("ls-tree") => args.len() == 6 && args[2..5] == ["-r", "-z", "--full-tree"],
                Some("cat-file") => args.len() == 4 && matches!(args[2], "-s" | "blob"),
                _ => false,
            });
    if !valid {
        return Err(invalid("unsupported hub Git operation"));
    }
    let mut argv = Vec::with_capacity(args.len());
    for arg in args {
        super::argv::validate_argv_token(arg)?;
        argv.push(std::ffi::OsString::from(arg));
    }
    let mut env =
        GitWireProcessEnv::capture()?.with_limits(Duration::from_secs(30), limit.max(4096))?;
    env.hub_root = Some(root.to_path_buf());
    let output = spawn_git(&env, root, &argv, None)?;
    if !output.success || output.timed_out || output.truncated || output.stdout.len() > limit {
        return Err(invalid("hub Git read refused or exceeded its budget"));
    }
    Ok(output.stdout)
}

pub(super) fn configure(command: &mut Command, root: &Path) -> Result<()> {
    command
        .env("HOME", root)
        .env("XDG_CONFIG_HOME", root)
        .env("GIT_LFS_SKIP_SMUDGE", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_PROTOCOL_FROM_USER", "0")
        .env("GIT_ALLOW_PROTOCOL", "https:http:file")
        .env("GIT_NO_LAZY_FETCH", "0");
    // Append to the normal closed GitWire policy, never replace its hook/credential rules.
    const POLICY: &[(&str, &str)] = &[
        ("protocol.https.allow", "always"),
        ("protocol.http.allow", "always"),
        ("protocol.file.allow", "always"),
        ("http.followRedirects", "false"),
        ("http.proxy", ""),
        ("http.extraHeader", ""),
        ("http.lowSpeedLimit", "1024"),
        ("http.lowSpeedTime", "10"),
        ("submodule.recurse", "false"),
        ("fetch.writeCommitGraph", "false"),
        ("uploadpack.allowFilter", "true"),
        ("pack.threads", "1"),
        ("pack.windowMemory", "16m"),
        ("pack.deltaCacheSize", "16m"),
        ("core.deltaBaseCacheLimit", "16m"),
        ("fetch.unpackLimit", "1"),
    ];
    let offset = super::GIT_WIRE_CONFIG_POLICY.len();
    command.env("GIT_CONFIG_COUNT", (offset + POLICY.len()).to_string());
    for (i, (key, value)) in POLICY.iter().enumerate() {
        command
            .env(format!("GIT_CONFIG_KEY_{}", offset + i), key)
            .env(format!("GIT_CONFIG_VALUE_{}", offset + i), value);
    }
    limit_process(command)
}
pub(super) fn check_budget(root: &Path, deadline: Instant) -> Result<()> {
    if tree_size(root, deadline)? > DISK_LIMIT {
        return Err(invalid("hub Git disk budget exceeded"));
    }
    Ok(())
}
fn tree_size(root: &Path, deadline: Instant) -> Result<u64> {
    let mut size = 0u64;
    for entry in std::fs::read_dir(root)? {
        if Instant::now() >= deadline {
            return Err(invalid("hub Git time budget exceeded"));
        }
        let entry = entry?;
        let metadata = match std::fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if metadata.is_symlink() {
            return Err(invalid("symlink in hub Git scratch"));
        }
        size = size.saturating_add(if metadata.is_dir() {
            tree_size(&entry.path(), deadline)?
        } else {
            metadata.len()
        });
        if size > DISK_LIMIT {
            break;
        }
    }
    Ok(size)
}
#[cfg(unix)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the unsupported-platform implementation fails closed through this same signature"
)]
fn limit_process(command: &mut Command) -> Result<()> {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
    // SAFETY: pre_exec performs only async-signal-safe setrlimit calls. No allocation,
    // locks, callbacks, or inherited descriptors are touched in the fork child.
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: FILE_LIMIT as libc::rlim_t,
                rlim_max: FILE_LIMIT as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}
#[cfg(not(unix))]
fn limit_process(_: &mut Command) -> Result<()> {
    Err(invalid(
        "Git transport needs a host with process resource limits",
    ))
}
