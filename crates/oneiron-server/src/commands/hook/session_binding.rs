//! The hosted vault a session bound, recorded by its `session-start` for its
//! hand-over (REVIEW-9834). A hand-over sends a session's log to a hosted
//! vault only when that session itself bound that vault and it is still the
//! one selected; it never finds a destination of its own. One file per
//! session, `<run folder>/hook-sessions/<session id>.json`, names the hosted
//! vault's origin and vault id, never its credential. A session that bound a
//! pin, a local vault or nothing has no file, so its hand-over queues
//! locally.
//!
//! A file is written as a runtime file is, owner-only in the owner-only run
//! folder, and one that anyone else could write is never read. A record
//! that cannot be written leaves none, and the hand-over then queues
//! locally. A session that starts again (a resume, a compaction) records
//! again; a record older than [`KEEP_FOR`] is removed when another session
//! records its own.

use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use super::hosted_selection::HostedVault;
use crate::commands::{credential_file, local_servers};

/// The folder in the run folder the records are in.
const FOLDER: &str = "hook-sessions";
/// The longest record read; one is a few hundred bytes.
const MAX_RECORD_BYTES: u64 = 4 * 1024;
/// The longest session id a record is named by.
const MAX_SESSION_ID_BYTES: usize = 128;
/// How long a record is kept after it was written.
const KEEP_FOR: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// The hosted vault a session bound: its origin and vault id.
#[derive(Serialize, Deserialize)]
pub(super) struct HostedBinding {
    origin: String,
    vault_id: String,
}

impl HostedBinding {
    /// Whether `vault` is the hosted vault the session bound.
    pub(super) fn names(&self, vault: &HostedVault) -> bool {
        self.origin == vault.origin && self.vault_id == vault.vault_id
    }
}

/// Records what the session `session` bound: the hosted vault `hosted`, or,
/// with `None`, no hosted vault, which removes any record an earlier start
/// of the session wrote.
pub(super) fn record(session: &str, hosted: Option<&HostedVault>) {
    let Some(path) = record_path(session) else {
        return;
    };
    let Some(vault) = hosted else {
        let _ = fs::remove_file(&path);
        return;
    };
    let binding = HostedBinding {
        origin: vault.origin.clone(),
        vault_id: vault.vault_id.clone(),
    };
    // A record that could not be replaced must not name the vault an
    // earlier start bound.
    if write(&path, &binding).is_err() {
        let _ = fs::remove_file(&path);
    }
    if let Some(folder) = path.parent() {
        remove_old(folder);
    }
}

/// The hosted vault the session `session` bound, when its start recorded
/// one in a file no one else could write.
pub(super) fn hosted(session: &str) -> Option<HostedBinding> {
    let file = local_servers::open_own(&record_path(session)?)?;
    let mut body = Vec::new();
    file.take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut body)
        .ok()?;
    if body.len() as u64 > MAX_RECORD_BYTES {
        return None;
    }
    serde_json::from_slice(&body).ok()
}

/// The record of `session`, when its id is a plain name: ASCII letters,
/// digits, dashes and underscores, as hosts name sessions, so it names no
/// file outside the folder.
fn record_path(session: &str) -> Option<PathBuf> {
    let plain = !session.is_empty()
        && session.len() <= MAX_SESSION_ID_BYTES
        && session
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    if !plain {
        return None;
    }
    Some(
        local_servers::run_dir()?
            .join(FOLDER)
            .join(format!("{session}.json")),
    )
}

/// Writes `binding` at `path` whole, under its final name in one rename,
/// 0600 in an 0700 folder in the run folder.
fn write(path: &Path, binding: &HostedBinding) -> anyhow::Result<()> {
    let run = local_servers::ensure_run_dir()?;
    let folder = run.join(FOLDER);
    match fs::DirBuilder::new().mode(0o700).create(&folder) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => anyhow::bail!("create {}: {error}", folder.display()),
    }
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} names no file", path.display()))?;
    let staged = folder.join(format!(".{}.tmp", name.to_string_lossy()));
    let _ = fs::remove_file(&staged);
    let body = serde_json::to_vec(binding)?;
    let written = credential_file::create(&staged)
        .and_then(|mut file| Ok(file.write_all(&body)?))
        .and_then(|()| Ok(fs::rename(&staged, path)?));
    if let Err(error) = written {
        let _ = fs::remove_file(&staged);
        anyhow::bail!("write {}: {error}", path.display());
    }
    Ok(())
}

/// Removes the records in `folder` written more than [`KEEP_FOR`] ago.
fn remove_old(folder: &Path) {
    let Ok(entries) = fs::read_dir(folder) else {
        return;
    };
    let Some(cutoff) = SystemTime::now().checked_sub(KEEP_FOR) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let old = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .is_ok_and(|modified| modified < cutoff);
        if old && entry.path().extension().is_some_and(|ext| ext == "json") {
            let _ = fs::remove_file(entry.path());
        }
    }
}
