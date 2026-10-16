//! The local servers running for this user, one runtime file each, so a
//! client such as `oneiron hook` finds any running vault without knowing
//! where it lives (ARCH-0028 `#plugin-first-run`, step 2).
//!
//! The folder is `oneiron/` in the platform's runtime folder where there is
//! one (`dirs::runtime_dir()`: `$XDG_RUNTIME_DIR` on Linux), else `run/` in
//! the per-user oneiron folder the default config sits in. It is created
//! 0700 and each file 0600. `serve` writes its file, named for its pid, once
//! its listener is bound and it is ready, and removes it on a clean stop. A
//! file whose pid is gone is stale; a reader removes it.

use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{EnvConfig, ServeArgs, default_config_path};

/// A runtime file is a few hundred bytes; a larger one is not read.
const MAX_FILE_BYTES: u64 = 64 * 1024;

/// One running server, as its runtime file names it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LocalServer {
    /// The authority vault id its slips carry, in hex; `null` until the
    /// vault is rooted.
    pub(crate) vault_id: Option<String>,
    /// The origin a client on this host reaches it at.
    pub(crate) url: String,
    pub(crate) pid: u32,
    /// The vault's folder.
    pub(crate) state_dir: PathBuf,
    /// The config file `serve` read, if it read one.
    pub(crate) config: Option<PathBuf>,
    pub(crate) started_at_ms: u64,
}

/// The per-user oneiron folder: the default config, the hook's pin and,
/// where there is no runtime folder, `run/`.
pub(crate) fn user_dir() -> Option<PathBuf> {
    default_config_path().and_then(|path| path.parent().map(Path::to_path_buf))
}

pub(crate) fn run_dir() -> Option<PathBuf> {
    match dirs::runtime_dir() {
        Some(dir) => Some(dir.join("oneiron")),
        None => user_dir().map(|dir| dir.join("run")),
    }
}

/// The config file `serve` reads for `args`, when one exists: the same
/// choice the config layers make (`--config`, `ONEIRON_CONFIG`, the default).
pub(crate) fn config_file(args: &ServeArgs) -> Option<PathBuf> {
    args.config
        .clone()
        .or_else(|| EnvConfig::from_process().ok()?.config_path)
        .or_else(default_config_path)
        .filter(|path| path.is_file())
}

/// This server's runtime file. Dropping it removes the file.
pub(crate) struct Registration {
    path: PathBuf,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// The authority vault id a runtime file names, in hex; `None` until the
/// vault is rooted.
pub(crate) fn vault_id(vault: &oneiron::Vault) -> Option<String> {
    vault
        .authority_fold()
        .ok()
        .and_then(|fold| fold.vault_id)
        .map(|id| id.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Registers a ready `serve` whose API listener is bound at `bound`. A
/// server that cannot write its file still serves; a client just does not
/// find it.
pub(crate) fn register(
    vault_id: Option<String>,
    bound: SocketAddr,
    state_dir: &Path,
    config: Option<&Path>,
) -> Option<Registration> {
    // A wildcard bind is reached on loopback.
    let ip = match bound.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    let absolute = |path: &Path| std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let server = LocalServer {
        vault_id,
        url: format!("http://{}", SocketAddr::new(ip, bound.port())),
        pid: std::process::id(),
        state_dir: absolute(state_dir),
        config: config.map(absolute),
        started_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
            }),
    };
    match write(&server) {
        Ok(registration) => Some(registration),
        Err(error) => {
            tracing::warn!(%error, "no runtime file: `oneiron hook` will not find this server");
            None
        }
    }
}

/// The run folder, created 0700 if it is missing; refused unless it is
/// this user's alone to write.
pub(crate) fn ensure_run_dir() -> anyhow::Result<PathBuf> {
    let dir = run_dir().ok_or_else(|| anyhow::anyhow!("no HOME and no runtime folder"))?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|error| anyhow::anyhow!("create {}: {error}", dir.display()))?;
    ours(&dir)?;
    Ok(dir)
}

/// Writes `server`'s file whole, under its final name in one rename.
fn write(server: &LocalServer) -> anyhow::Result<Registration> {
    let dir = ensure_run_dir()?;
    let path = dir.join(format!("{}.json", server.pid));
    let staged = dir.join(format!(".{}.json.tmp", server.pid));
    let _ = fs::remove_file(&staged);
    let body = serde_json::to_vec(server)?;
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged)
        .and_then(|mut file| file.write_all(&body))
        .and_then(|()| fs::rename(&staged, &path));
    if let Err(error) = written {
        let _ = fs::remove_file(&staged);
        anyhow::bail!("write {}: {error}", path.display());
    }
    Ok(Registration { path })
}

/// Every runtime file in the run folder, with its path. A folder another
/// user owns or can write is not read, nor is a file that is a link or
/// another user's.
pub(crate) fn listed() -> Vec<(PathBuf, LocalServer)> {
    let Some(dir) = run_dir() else {
        return Vec::new();
    };
    let Ok(entries) = ours(&dir).and_then(|()| Ok(fs::read_dir(&dir)?)) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .filter_map(|path| read(&path).map(|server| (path, server)))
        .collect()
}

fn read(path: &Path) -> Option<LocalServer> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.uid() != rustix::process::geteuid().as_raw() {
        return None;
    }
    let mut body = Vec::new();
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut body).ok()?;
    if body.len() as u64 > MAX_FILE_BYTES {
        return None;
    }
    serde_json::from_slice(&body).ok()
}

/// Whether a process with this pid exists (another user's counts).
pub(crate) fn alive(pid: u32) -> bool {
    let Some(pid) = i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    else {
        return false;
    };
    match rustix::process::test_kill_process(pid) {
        Ok(()) => true,
        Err(error) => error == rustix::io::Errno::PERM,
    }
}

/// The run folder is this user's: owned by them, not a link, and nobody
/// else can write it.
fn ours(dir: &Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(dir)?;
    anyhow::ensure!(
        metadata.is_dir()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o022 == 0,
        "{} is not a folder only this user can write",
        dir.display()
    );
    Ok(())
}
