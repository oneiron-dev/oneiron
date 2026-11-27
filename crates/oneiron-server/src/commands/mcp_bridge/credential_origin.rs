//! The origin each `oneiron mcp` sends its paired credential file to, as the
//! bridge records it when it starts. A hook that holds the same file sends
//! it to that origin alone, and nowhere when no bridge recorded one
//! (REVIEW-10587 round 2 P1 1): the plugin's MCP entry may name its vault by
//! `--url` or its own environment, which the hook's command never sees.
//!
//! One file per credential file in the run folder's `mcp-origins` folder,
//! 0600 in 0700 folders, named by a digest of the credential file's
//! canonical path and holding the bridge's normalized origin. The bridge
//! that started last on a file wrote its record last.

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
    let name = record_name(credential)
        .ok_or_else(|| anyhow::anyhow!("resolve {}", credential.display()))?;
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

/// The origin a bridge recorded for the credential file `credential`; `None`
/// when none did, or the record is not this user's own file.
pub(crate) fn recorded(credential: &Path) -> Option<String> {
    let name = record_name(credential)?;
    let file = local_servers::open_own(&local_servers::run_dir()?.join(FOLDER).join(name))?;
    let mut origin = String::new();
    file.take(MAX_RECORD_BYTES + 1)
        .read_to_string(&mut origin)
        .ok()?;
    (!origin.is_empty() && origin.len() as u64 <= MAX_RECORD_BYTES).then_some(origin)
}

/// The record's file name: the digest of the credential file's canonical
/// path, so every spelling of one path names one record.
fn record_name(credential: &Path) -> Option<String> {
    let canonical = fs::canonicalize(credential).ok()?;
    Some(ContentHash::of(canonical.as_os_str().as_encoded_bytes()).to_hex())
}
