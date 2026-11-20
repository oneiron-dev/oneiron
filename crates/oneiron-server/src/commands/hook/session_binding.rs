//! What a session's starts bound, recorded by each `session-start` of a
//! Claude Code session for its hand-over (REVIEW-9834). A hand-over sends a
//! session's log to a hosted vault only when every start of that session
//! bound that one vault and it is still the one selected; it never finds a
//! destination of its own.
//!
//! Each session has a folder, `<run folder>/hook-sessions/<session id>/`,
//! with one file per distinct binding its starts made:
//! - `local`: a pin, a local vault or no vault, whose log the local queue
//!   takes, as before;
//! - `hosted-<16 hex digits>`: a hosted vault, the file naming its origin
//!   and vault id, never its credential;
//! - `unknown`: a resumed or compacted session's start that found no record
//!   of the session, so the vault its earlier turns came from is not known.
//!
//! A log holds every turn of its session, so a session whose folder holds
//! more than one file has a log that mixes vaults: no hand-over sends it
//! anywhere, and selecting a vault again never undoes that. The person moves
//! it (`oneiron continue --cloud --transcript <log>`). A session with no
//! folder (its start ran before this record, or could write none) queues
//! locally, as every hand-over did before.
//!
//! Files are only added. Each is written under a staging name no other
//! writer uses and renamed into place, so starts of one session running at
//! once never replace or remove each other's file, and a writer that fails
//! removes only its own staging file. A file anyone else could write is
//! never read. The folders of sessions whose files are all older than
//! [`KEEP_FOR`] are removed when another session records.

use std::ffi::OsStr;
use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::hosted_selection::HostedVault;
use crate::commands::{credential_file, local_servers};

/// The folder in the run folder the sessions' folders are in.
const FOLDER: &str = "hook-sessions";
/// The file of a session that bound a pin, a local vault or no vault.
const LOCAL: &str = "local";
/// The file of a session whose earlier turns' vault is not known.
const UNKNOWN: &str = "unknown";
/// The start of a hosted vault's file name.
const HOSTED_PREFIX: &str = "hosted-";
/// The longest hosted vault file read; one is a few hundred bytes.
const MAX_RECORD_BYTES: u64 = 4 * 1024;
/// The longest session id a folder is named by.
const MAX_SESSION_ID_BYTES: usize = 128;
/// How long a session's files are kept after the newest was written.
const KEEP_FOR: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// A hosted vault a session bound: its origin and vault id.
#[derive(Serialize, Deserialize)]
pub(super) struct HostedBinding {
    origin: String,
    vault_id: String,
}

impl HostedBinding {
    fn of(vault: &HostedVault) -> Self {
        Self {
            origin: vault.origin.clone(),
            vault_id: vault.vault_id.clone(),
        }
    }

    /// Whether `vault` is the hosted vault the session bound.
    pub(super) fn names(&self, vault: &HostedVault) -> bool {
        self.origin == vault.origin && self.vault_id == vault.vault_id
    }

    /// The file it is recorded in: `hosted-` and the first 16 hex digits of
    /// the SHA-256 of its origin, a NUL and its vault id.
    fn file_name(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(self.origin.as_bytes());
        hash.update([0_u8]);
        hash.update(self.vault_id.as_bytes());
        let digest = hash.finalize();
        let hex: String = digest[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!("{HOSTED_PREFIX}{hex}")
    }
}

/// What the starts of a session bound, as its hand-over reads it.
pub(super) enum SessionBinding {
    /// A pin, a local vault or no vault, at every start: the local queue's.
    Local,
    /// One hosted vault, at every start.
    Hosted(HostedBinding),
    /// More than one, or turns whose vault is not known: no vault takes the
    /// log.
    Mixed,
}

/// Records that a start of the session `session` bound the hosted vault
/// `hosted`, or, with `None`, a pin, a local vault or no vault. `resumed`
/// says the start goes on from turns that ran before it (a resume or a
/// compaction); when no earlier start of the session recorded anything,
/// that their vault is not known is recorded first, and a start that cannot
/// record that records nothing.
pub(super) fn record(session: &str, hosted: Option<&HostedVault>, resumed: bool) {
    let Some(folder) = session_folder(session) else {
        return;
    };
    if resumed && !recorded(&folder) && add(&folder, UNKNOWN, b"").is_err() {
        return;
    }
    let _ = match hosted {
        Some(vault) => {
            let binding = HostedBinding::of(vault);
            serde_json::to_vec(&binding)
                .map_err(anyhow::Error::from)
                .and_then(|body| add(&folder, &binding.file_name(), &body))
        }
        None => add(&folder, LOCAL, b""),
    };
    remove_old(&folder);
}

/// What the starts of the session `session` bound; `None` when none
/// recorded anything. A file that anyone else could write, or that this
/// version does not read, reads as a mixed log, which no vault takes.
pub(super) fn bound(session: &str) -> Option<SessionBinding> {
    let folder = session_folder(session)?;
    let mut files = fs::read_dir(&folder)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .filter(|name| !staging(name));
    let first = files.next()?;
    if files.next().is_some() {
        return Some(SessionBinding::Mixed);
    }
    let Some(file) = local_servers::open_own(&folder.join(&first)) else {
        return Some(SessionBinding::Mixed);
    };
    let binding = match first.to_str() {
        Some(LOCAL) => SessionBinding::Local,
        Some(name) if name.starts_with(HOSTED_PREFIX) => {
            let mut body = Vec::new();
            let read = file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut body);
            match serde_json::from_slice::<HostedBinding>(&body) {
                Ok(hosted)
                    if read.is_ok()
                        && body.len() as u64 <= MAX_RECORD_BYTES
                        && hosted.file_name() == name =>
                {
                    SessionBinding::Hosted(hosted)
                }
                _ => SessionBinding::Mixed,
            }
        }
        _ => SessionBinding::Mixed,
    };
    Some(binding)
}

/// The folder of `session`, when its id is a plain name: ASCII letters,
/// digits, dashes and underscores, as hosts name sessions, so it names no
/// folder outside the run folder's.
fn session_folder(session: &str) -> Option<PathBuf> {
    let plain = !session.is_empty()
        && session.len() <= MAX_SESSION_ID_BYTES
        && session
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    if !plain {
        return None;
    }
    Some(local_servers::run_dir()?.join(FOLDER).join(session))
}

/// Whether a start of the session whose folder is `folder` recorded
/// anything.
fn recorded(folder: &Path) -> bool {
    fs::read_dir(folder).is_ok_and(|mut entries| {
        entries.any(|entry| entry.is_ok_and(|entry| !staging(&entry.file_name())))
    })
}

/// Whether `name` is a writer's staging file, not yet a record.
fn staging(name: &OsStr) -> bool {
    name.as_encoded_bytes().starts_with(b".")
}

/// Adds the file `name` holding `body` to the session folder `folder`, 0600
/// in 0700 folders in the run folder: written under a staging name of this
/// writer's alone, then renamed into place, where a file of that name is
/// replaced by the same bytes. A writer that fails removes its staging file
/// alone.
fn add(folder: &Path, name: &str, body: &[u8]) -> anyhow::Result<()> {
    let sessions = local_servers::ensure_run_dir()?.join(FOLDER);
    for dir in [sessions.as_path(), folder] {
        match fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => anyhow::bail!("create {}: {error}", dir.display()),
        }
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let staged = folder.join(format!(".{name}.{}.{nanos}.tmp", std::process::id()));
    let written = credential_file::create(&staged)
        .and_then(|mut file| Ok(file.write_all(body)?))
        .and_then(|()| Ok(fs::rename(&staged, folder.join(name))?));
    if let Err(error) = written {
        let _ = fs::remove_file(&staged);
        anyhow::bail!("write {}: {error}", folder.join(name).display());
    }
    Ok(())
}

/// Removes the folders of sessions other than the one at `own` whose files
/// were all written more than [`KEEP_FOR`] ago.
fn remove_old(own: &Path) {
    let Some(sessions) = own.parent() else {
        return;
    };
    let Some(cutoff) = SystemTime::now().checked_sub(KEEP_FOR) else {
        return;
    };
    let Ok(entries) = fs::read_dir(sessions) else {
        return;
    };
    let old = |path: &Path| {
        fs::symlink_metadata(path)
            .and_then(|metadata| metadata.modified())
            .is_ok_and(|modified| modified < cutoff)
    };
    for entry in entries.filter_map(Result::ok) {
        let folder = entry.path();
        if folder == own || !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let Ok(files) = fs::read_dir(&folder) else {
            continue;
        };
        let files: Vec<PathBuf> = files
            .filter_map(Result::ok)
            .map(|file| file.path())
            .collect();
        if files.iter().all(|file| old(file)) {
            for file in &files {
                let _ = fs::remove_file(file);
            }
            let _ = fs::remove_dir(&folder);
        }
    }
}
