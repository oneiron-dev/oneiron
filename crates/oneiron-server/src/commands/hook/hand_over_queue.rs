//! The hand-over queue of an OAuth selection (row
//! HOOK-HOSTED-HAND-OVER-OAUTH-READ-TIER; lead ruling B, Sat 21 Nov 07:0x).
//!
//! On an OAuth selection the hooks' hand-over lands a session's log on the
//! hand-over sign-in alone ([`super::hosted_sign_in::StepUp::HandOver`]):
//! `full` at the vault's `/mcp`, never its `/git`, which `oneiron hosted
//! login --hand-over` makes. The recall sign-in stays `read`, and the import
//! is a Write row, so a hand-over on it never landed. A log waits here when
//! no hand-over sign-in stands, or when its send did not land it whole (a
//! sign-in the vault no longer takes, a vault that does not answer, turns
//! waiting behind another import): one small owner-only file per session in
//! an owner-only folder per origin and vault id
//! ([`hosted_selection::hand_over_queue_dir`]), naming the host, the session
//! and the log's path, never a copy of the log.
//!
//! Each entry has a generation, drawn when it is written; a hand-over takes
//! out only the generation it saw ([`leave`]), so an older send never takes
//! out a newer entry of the same session. Every change runs under the
//! queue's lock, a file beside its folder ([`Locked`]), which a logout's
//! [`clear`] takes too, and an entry is written only while the vault is
//! still recorded here.
//!
//! The next hand-over that lands a log whole lands the waiting logs of the
//! same host after it ([`super::continue_command::hand_over_hosted`]). A log
//! that lands whole, whose log is gone, refused here, or refused by the
//! vault, or whose session no hosted vault may take, leaves the queue; one
//! bound to another vault, one with turns still pending, and one whose send
//! got no answer wait on.

use std::io::Read as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::hosted_selection::{self, HostedVault};
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
    /// Which write of the file this is ([`Generation`]).
    #[serde(default)]
    generation: String,
}

/// Which write of a queued log's file a hand-over saw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Generation(String);

impl Generation {
    /// A fresh one: the time in ms and this process's id, which no other
    /// write of the same file shares.
    fn fresh() -> Self {
        Self(format!(
            "{}-{}",
            oauth_sign_in::now_ms(),
            std::process::id()
        ))
    }
}

/// A log waiting in a vault's queue.
pub(super) struct Queued {
    /// Its file in the queue.
    file: PathBuf,
    pub(super) host: HookHost,
    pub(super) session: String,
    pub(super) log: PathBuf,
    queued_at_ms: u64,
    generation: Generation,
}

impl Queued {
    /// The generation it waits as.
    pub(super) fn generation(&self) -> &Generation {
        &self.generation
    }
}

/// `vault`'s queue, locked until it drops: an exclusive `flock` on a file
/// beside its folder, so a [`clear`] that removes the folder still excludes
/// a writer.
struct Locked {
    dir: PathBuf,
    _lock: std::fs::File,
}

impl Locked {
    fn take(vault: &HostedVault) -> anyhow::Result<Self> {
        let dir = hosted_selection::hand_over_queue_dir(vault).ok_or_else(|| {
            anyhow::anyhow!("there is no per-user oneiron folder (HOME is not set)")
        })?;
        hosted_selection::create_user_dir_for(&dir)?;
        let path = dir.with_extension("lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| anyhow::anyhow!("open {}: {error}", path.display()))?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)
            .map_err(|error| anyhow::anyhow!("lock {}: {error}", path.display()))?;
        Ok(Self { dir, _lock: file })
    }
}

/// The file `host`'s session `session` waits in, in `dir`: one per session,
/// so each later hand-over of the session finds the same one.
fn entry_file(dir: &Path, host: HookHost, session: &str) -> PathBuf {
    let digest = oneiron_contracts::fingerprint::ContentHash::of(session.as_bytes()).to_hex();
    dir.join(format!("{}-{}.json", host.as_str(), &digest[..16]))
}

/// Queues the log at `log` of `host`'s session `session` for `vault`, in
/// place of any earlier entry of the session, as a new generation; past
/// [`MAX_QUEUED`], the oldest log leaves. Under the queue's lock, and only
/// while `vault` is still recorded here (a logout since the hook read the
/// selection queues nothing), so session ends that queue at once keep the
/// bound. Answers whether the queue held no log before.
pub(super) fn enqueue(
    vault: &HostedVault,
    host: HookHost,
    session: &str,
    log: &Path,
) -> anyhow::Result<bool> {
    let locked = Locked::take(vault)?;
    anyhow::ensure!(
        still_recorded(vault),
        "{} is no longer signed in here; nothing was queued",
        vault.origin
    );
    let dir = &locked.dir;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|error| anyhow::anyhow!("create {}: {error}", dir.display()))?;
    let file = entry_file(dir, host, session);
    let waiting = read_dir(dir);
    let first = waiting.is_empty();
    if !waiting.iter().any(|queued| queued.file == file) && waiting.len() >= MAX_QUEUED {
        let oldest = waiting.len() + 1 - MAX_QUEUED;
        for queued in waiting.iter().take(oldest) {
            let _ = std::fs::remove_file(&queued.file);
        }
    }
    let entry = Entry {
        host: host.as_str().to_owned(),
        session: session.to_owned(),
        log: log.to_owned(),
        queued_at_ms: oauth_sign_in::now_ms(),
        generation: Generation::fresh().0,
    };
    credential_file::replace(&file, &serde_json::to_vec(&entry)?)?;
    Ok(first)
}

/// Whether `vault` is still recorded here as it was read: the same origin,
/// vault id, mode and credential file.
fn still_recorded(vault: &HostedVault) -> bool {
    hosted_selection::read().is_ok_and(|selection| {
        selection.vaults.iter().any(|recorded| {
            recorded.origin == vault.origin
                && recorded.vault_id == vault.vault_id
                && recorded.auth_mode == vault.auth_mode
                && recorded.credential_file == vault.credential_file
        })
    })
}

/// The logs waiting for `vault`, oldest first. A file that is not one only
/// this user can write, or not a queued log, is passed over.
pub(super) fn queued(vault: &HostedVault) -> Vec<Queued> {
    hosted_selection::hand_over_queue_dir(vault).map_or_else(Vec::new, |dir| read_dir(&dir))
}

/// The generation the log of `host`'s session `session` waits as in
/// `vault`'s queue, if it waits there.
pub(super) fn generation_of(
    vault: &HostedVault,
    host: HookHost,
    session: &str,
) -> Option<Generation> {
    let dir = hosted_selection::hand_over_queue_dir(vault)?;
    read_entry(&entry_file(&dir, host, session)).map(|queued| queued.generation)
}

/// Takes the log of `host`'s session `session` out of `vault`'s queue, when
/// it still waits as the generation `seen`: a later hand-over of the
/// session that queued it again keeps its entry.
pub(super) fn leave(vault: &HostedVault, host: HookHost, session: &str, seen: &Generation) {
    let Ok(locked) = Locked::take(vault) else {
        return;
    };
    let file = entry_file(&locked.dir, host, session);
    if read_entry(&file).is_some_and(|queued| &queued.generation == seen) {
        let _ = std::fs::remove_file(&file);
    }
}

/// Empties `vault`'s queue and removes its folder, under its lock.
pub(super) fn clear(vault: &HostedVault) -> anyhow::Result<()> {
    let locked = Locked::take(vault)?;
    match std::fs::remove_dir_all(&locked.dir) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(anyhow::anyhow!("remove {}: {error}", locked.dir.display()))
        }
        _ => Ok(()),
    }
}

/// What the hand-over says on stderr when a session's log is the first to
/// wait for the vault at `origin` with no hand-over sign-in, or when it
/// `asked` the owner for the hand-over sign-in: how the log comes to land.
pub(super) fn waiting_note(origin: &str, asked: bool) -> String {
    let how = if asked {
        format!(
            "Your Oneiron inbox now asks to let this machine's session logs land there as each \
             session ends (or run `oneiron hosted login --origin {origin} --hand-over`)"
        )
    } else {
        format!(
            "`oneiron hosted login --origin {origin} --hand-over` lets session logs land there \
             as each session ends"
        )
    };
    format!(
        "This session's log waits on this machine: {origin} is signed in here for recall \
         alone, and landing a log writes. {how}; the logs waiting land at the next one."
    )
}

/// What the hand-over says on stderr when a session's log, the first to
/// wait for the vault at `origin`, did not land whole on its hand-over
/// sign-in, and `why`.
pub(super) fn unlanded_note(origin: &str, why: &str) -> String {
    format!(
        "This session's log waits on this machine: its hand-over to {origin} did not land it \
         whole ({why}). It lands at a later session end; when the vault no longer takes the \
         hand-over sign-in, `oneiron hosted login --origin {origin} --hand-over` signs in again."
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
        generation: Generation(entry.generation),
    })
}
