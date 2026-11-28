//! The origin each `oneiron mcp` sends its paired credential file to, as the
//! bridge records it after the vault first admits it. A hook that holds the
//! same file sends it to that origin alone, and nowhere when no bridge
//! recorded one (REVIEW-10587 round 2 P1 1): the plugin's MCP entry may name
//! its vault by `--url` or its own environment, which the hook's command
//! never sees.
//!
//! One record per bridge process in the run folder's `mcp-origins` folder:
//! file `<digest>.<pid>`, the digest of the credential file's canonical path
//! and this bridge's pid, holding the bridge's normalized origin. The record
//! is written on the first answer the client gets that has no `error` key,
//! and removed when the bridge ends. A hook uses an origin only while a
//! bridge that wrote it runs, and nothing when live bridges disagree.

use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::DirBuilderExt as _;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron_contracts::fingerprint::ContentHash;

use crate::commands::{credential_file, local_servers};

const FOLDER: &str = "mcp-origins";
/// The longest record read; a normalized origin is far shorter.
const MAX_RECORD_BYTES: u64 = 4 * 1024;

/// Records that this bridge sends the credential file `credential` to
/// `origin`: written under a staging name of this writer's alone, then
/// renamed into place.
pub(crate) fn record(credential: &Path, origin: &str) -> anyhow::Result<()> {
    let digest = record_name(credential)
        .ok_or_else(|| anyhow::anyhow!("resolve {}", credential.display()))?;
    let name = format!("{digest}.{}", std::process::id());
    let folder = local_servers::ensure_run_dir()?.join(FOLDER);
    match fs::DirBuilder::new().mode(0o700).create(&folder) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => anyhow::bail!("create {}: {error}", folder.display()),
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let staged = folder.join(format!(".{name}.{}.{nanos}.tmp", std::process::id()));
    let written = credential_file::create(&staged)
        .and_then(|mut file| Ok(file.write_all(origin.as_bytes())?))
        .and_then(|()| Ok(fs::rename(&staged, folder.join(&name))?));
    if let Err(error) = written {
        let _ = fs::remove_file(&staged);
        anyhow::bail!("record the origin of {}: {error}", credential.display());
    }
    Ok(())
}

/// Forgets this bridge's record for the credential file `credential`, best
/// effort: a record left behind is a dead bridge's, which [`recorded`]
/// skips.
pub(crate) fn forget(credential: &Path) {
    let Some(digest) = record_name(credential) else {
        return;
    };
    let Some(folder) = local_servers::run_dir().map(|dir| dir.join(FOLDER)) else {
        return;
    };
    let _ = fs::remove_file(folder.join(format!("{digest}.{}", std::process::id())));
}

/// The origin the running bridges recorded for the credential file
/// `credential`: `Some` only when at least one live bridge's record names
/// it and every live record names the same one. A bridge that ended leaves
/// a record no hook uses, and live bridges that disagree leave none.
pub(crate) fn recorded(credential: &Path) -> Option<String> {
    let digest = record_name(credential)?;
    let folder = local_servers::run_dir()?.join(FOLDER);
    let entries = fs::read_dir(&folder).ok()?;
    let mut origin: Option<String> = None;
    let mut live = false;
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            continue;
        }
        let Some(pid) = name
            .strip_prefix(digest.as_str())
            .and_then(|rest| rest.strip_prefix('.'))
            .filter(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|suffix| suffix.parse::<u32>().ok())
        else {
            continue;
        };
        if !local_servers::alive(pid) {
            continue;
        }
        live = true;
        let file = local_servers::open_own(&folder.join(entry.file_name()))?;
        let mut text = String::new();
        file.take(MAX_RECORD_BYTES + 1)
            .read_to_string(&mut text)
            .ok()?;
        if text.is_empty() || text.len() as u64 > MAX_RECORD_BYTES {
            return None;
        }
        match &origin {
            Some(held) if *held == text => {}
            Some(_) => return None,
            None => origin = Some(text),
        }
    }
    live.then_some(origin).flatten()
}

/// The record's file digest: of the credential file's canonical path, so
/// every spelling of one path names one record.
fn record_name(credential: &Path) -> Option<String> {
    let canonical = fs::canonicalize(credential).ok()?;
    Some(ContentHash::of(canonical.as_os_str().as_encoded_bytes()).to_hex())
}
