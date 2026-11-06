//! Fixed network-read profile for a private disposable hub object store.
//! No caller-controlled config pairs, checkout, hooks or inherited credentials.
use crate::git_wire::failure::invalid;
use crate::git_wire::failure::uncertain;
use oneiron_base::error::Result;
use std::{
    path::Path,
    process::Command,
    time::{Duration, Instant},
};
const DISK_LIMIT: u64 = 128 * 1024 * 1024;
#[cfg(unix)]
const FILE_LIMIT: u64 = 64 * 1024 * 1024;

/// Names the op and the cause. The scratch repository holds no credentials by
/// construction, so its stderr head is safe to carry.
pub fn refused(
    op: &str,
    cause: &str,
    started: Instant,
    detail: &str,
) -> oneiron_base::error::Error {
    let elapsed = started.elapsed().as_millis();
    uncertain(format!(
        "hub Git read refused or exceeded its budget: op={op} cause={cause} elapsed_ms={elapsed}{detail}"
    ))
}

/// First 200 bytes of stderr on one line.
pub fn stderr_head(stderr: &[u8]) -> String {
    let head = &stderr[..stderr.len().min(200)];
    String::from_utf8_lossy(head)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn configure(command: &mut Command, root: &Path) -> Result<()> {
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
    command
        .env("HOME", root)
        .env("XDG_CONFIG_HOME", root)
        .env("GIT_LFS_SKIP_SMUDGE", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_PROTOCOL_FROM_USER", "0")
        .env("GIT_ALLOW_PROTOCOL", "https:http:file")
        .env("GIT_NO_LAZY_FETCH", "0");
    let offset = crate::git_wire::config::GIT_WIRE_CONFIG_POLICY.len();
    command.env("GIT_CONFIG_COUNT", (offset + POLICY.len()).to_string());
    for (i, (key, value)) in POLICY.iter().enumerate() {
        command
            .env(format!("GIT_CONFIG_KEY_{}", offset + i), key)
            .env(format!("GIT_CONFIG_VALUE_{}", offset + i), value);
    }
    limit_process(command)
}
pub fn check_budget(root: &Path, deadline: Instant) -> Result<()> {
    if tree_size(root, &root.join("repo"), deadline)? > DISK_LIMIT {
        return Err(invalid("hub Git disk budget exceeded"));
    }
    Ok(())
}
fn tree_size(root: &Path, git_dir: &Path, deadline: Instant) -> Result<u64> {
    let mut size = 0u64;
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        // Git removed this directory after the parent listing named it; the
        // walk runs while git works, exactly like a vanished file below.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
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
            if is_init_symlink_probe(&entry.path(), git_dir) {
                continue;
            }
            return Err(invalid("symlink in hub Git scratch"));
        }
        size = size.saturating_add(if metadata.is_dir() {
            tree_size(&entry.path(), git_dir, deadline)?
        } else {
            metadata.len()
        });
        if size > DISK_LIMIT {
            break;
        }
    }
    Ok(size)
}
/// `git init` tests symlink support by linking `<git dir>/tXXXXXX` to
/// `testing` and unlinking it at once. That transient probe is git's own, not
/// a scratch escape; any other symlink still refuses.
fn is_init_symlink_probe(path: &Path, git_dir: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    path.parent() == Some(git_dir)
        && name.len() == 7
        && name.starts_with('t')
        && name
            .bytes()
            .skip(1)
            .all(|byte| byte.is_ascii_alphanumeric())
        && match std::fs::read_link(path) {
            Ok(target) => target == Path::new("testing"),
            Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        }
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
