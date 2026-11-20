//! The hand-over queue of an OAuth selection (row
//! HOOK-HOSTED-HAND-OVER-OAUTH-READ-TIER; lead ruling B, Sat 21 Nov 07:0x).
//!
//! On an OAuth selection the hooks' hand-over lands a session's log on the
//! hand-over sign-in alone ([`super::hosted_sign_in::StepUp::HandOver`]): `full` at the vault's
//! `/mcp`, never its `/git`, which `oneiron hosted login --hand-over` makes.
//! The recall sign-in stays `read`, and the import is a Write row, so a
//! hand-over on it never landed. When no hand-over sign-in stands, the log
//! waits here: one small owner-only file per session in an owner-only folder
//! per vault ([`hosted_selection::hand_over_queue_dir`]), naming the host,
//! the session and the log's path, never a copy of the log.
//!
//! At the next hand-over on a standing sign-in, the logs waiting land after
//! the session's own, each read again through the hand-over's own checks
//! ([`super::continue_command::hand_over_hosted`]). One that lands, or whose
//! log is gone or refused, leaves the queue; one whose send fails waits on.
//! A logout of the vault empties its queue ([`clear`]).

use std::io::Read as _;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::hosted_selection;
use crate::cli::HookHost;
use crate::commands::{credential_file, local_servers, oauth_sign_in};

/// The most logs that wait for one vault. A further session's log takes
/// the oldest one's place.
const MAX_QUEUED: usize = 256;
/// A queued log's file is a few hundred bytes; a larger one is not one.
const MAX_ENTRY_BYTES: u64 = 16 * 1024;

/// One queued log's file body.
#[derive(Serialize, Deserialize)]
struct Entry {
    /// The host whose session it is, as `--host` names it.
    host: String,
    /// The session, as its host's event named it.
    session: String,
    /// The log's path, as its host's event named it.
    log: PathBuf,
    /// When it was queued, in ms since the Unix epoch.
    queued_at_ms: u64,
}

/// A log waiting in a vault's queue.
pub(super) struct Queued {
    /// Its file in the queue.
    file: PathBuf,
    pub(super) host: HookHost,
    pub(super) session: String,
    pub(super) log: PathBuf,
    queued_at_ms: u64,
}

impl Queued {
    /// Takes it out of the queue.
    pub(super) fn leave(&self) {
        let _ = std::fs::remove_file(&self.file);
    }
}

/// The file `host`'s session `session` waits in, in `dir`: one per session,
/// so each later hand-over of the session finds the same one.
fn entry_file(dir: &Path, host: HookHost, session: &str) -> PathBuf {
    let digest = oneiron_contracts::fingerprint::ContentHash::of(session.as_bytes()).to_hex();
    dir.join(format!("{}-{}.json", host.as_str(), &digest[..16]))
}

/// Queues the log at `log` of `host`'s session `session` for the vault at
/// `origin`, in place of any earlier entry of the session; past
/// [`MAX_QUEUED`], the oldest log leaves. Answers whether the queue held no
/// log before.
pub(super) fn enqueue(
    origin: &str,
    host: HookHost,
    session: &str,
    log: &Path,
) -> anyhow::Result<bool> {
    let dir = hosted_selection::hand_over_queue_dir(origin)
        .ok_or_else(|| anyhow::anyhow!("there is no per-user oneiron folder (HOME is not set)"))?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|error| anyhow::anyhow!("create {}: {error}", dir.display()))?;
    let file = entry_file(&dir, host, session);
    let waiting = read_dir(&dir);
    let first = waiting.is_empty();
    if !waiting.iter().any(|queued| queued.file == file) && waiting.len() >= MAX_QUEUED {
        let oldest = waiting.len() + 1 - MAX_QUEUED;
        waiting.iter().take(oldest).for_each(Queued::leave);
    }
    let entry = Entry {
        host: host.as_str().to_owned(),
        session: session.to_owned(),
        log: log.to_owned(),
        queued_at_ms: oauth_sign_in::now_ms(),
    };
    credential_file::replace(&file, &serde_json::to_vec(&entry)?)?;
    Ok(first)
}

/// The logs waiting for the vault at `origin`, oldest first. A file that is
/// not one only this user can write, or not a queued log, is passed over.
pub(super) fn queued(origin: &str) -> Vec<Queued> {
    hosted_selection::hand_over_queue_dir(origin).map_or_else(Vec::new, |dir| read_dir(&dir))
}

/// Takes the log of `host`'s session `session` out of the queue of the
/// vault at `origin`, if it waits there.
pub(super) fn leave(origin: &str, host: HookHost, session: &str) {
    if let Some(dir) = hosted_selection::hand_over_queue_dir(origin) {
        let _ = std::fs::remove_file(entry_file(&dir, host, session));
    }
}

/// Empties the queue of the vault at `origin`, and removes its folder.
pub(super) fn clear(origin: &str) -> anyhow::Result<()> {
    let Some(dir) = hosted_selection::hand_over_queue_dir(origin) else {
        return Ok(());
    };
    match std::fs::remove_dir_all(&dir) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(anyhow::anyhow!("remove {}: {error}", dir.display()))
        }
        _ => Ok(()),
    }
}

/// What the hand-over says on stderr when a session's log is the first to
/// wait for the vault at `origin`: which command lets it land.
pub(super) fn waiting_note(origin: &str) -> String {
    format!(
        "This session's log waits on this machine: {origin} is signed in here for recall \
         alone, and landing a log writes. `oneiron hosted login --origin {origin} --hand-over` \
         lets session logs land there as each session ends; the logs waiting land at the next \
         one."
    )
}

/// The logs queued in `dir`, oldest first.
fn read_dir(dir: &Path) -> Vec<Queued> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut queued: Vec<Queued> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .filter_map(|path| read_entry(&path))
        .collect();
    queued.sort_by_key(|queued| queued.queued_at_ms);
    queued
}

/// The queued log `path` holds, when it is a file only this user can write
/// and reads as one, under the name its host and session give it.
fn read_entry(path: &Path) -> Option<Queued> {
    let file = local_servers::open_own(path)?;
    let mut body = Vec::new();
    file.take(MAX_ENTRY_BYTES + 1).read_to_end(&mut body).ok()?;
    if body.len() as u64 > MAX_ENTRY_BYTES {
        return None;
    }
    let entry: Entry = serde_json::from_slice(&body).ok()?;
    let host = <HookHost as clap::ValueEnum>::from_str(&entry.host, false).ok()?;
    let named_for = entry_file(path.parent()?, host, &entry.session);
    (named_for == path).then(|| Queued {
        file: path.to_owned(),
        host,
        session: entry.session,
        log: entry.log,
        queued_at_ms: entry.queued_at_ms,
    })
}
