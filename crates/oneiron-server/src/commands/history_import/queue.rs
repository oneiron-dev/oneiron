//! The import queue. `oneiron import <source> <log> --queue` leaves one small
//! file naming a session log; a running `serve` with `[import] queue = true`
//! imports that log within seconds, as `oneiron import` does on a stopped
//! vault. A client hook hands a live session over this way with no
//! credential and no wait. Only the owner can write the queue folder, and
//! `serve` reads only logs under the source's configured root.
//!
//! The folder is opened once per pass without following a link, checked on
//! that descriptor, and every entry is listed, claimed, read and removed
//! relative to it. An entry is claimed by renaming it, so a log queued again
//! while it is being imported waits as a new entry. A pass lands what it
//! claimed earliest first across entries, so a session lands before a
//! resumed copy of it, as in a folder import. An entry is removed once it
//! landed or was refused: queueing the log again tries again, and the import
//! ledger lands only what is new. A claim stays while landing fails, and
//! for a few passes while its log ends mid-line; the next pass takes it up.
//! A claim that waits past the decoded budget keeps where it sorts and what
//! it decodes to, so it is read again only to land.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use oneiron::ingest::history::{HistoryConversation, HistorySource};
use rustix::fs::{AtFlags, CWD, Dir, Mode, OFlags, fstat, openat, renameat, statat, unlinkat};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};

use super::confined::open_file;
use super::{
    Decoded, ImportWarning, QueuedSession, Totals, below, earliest_first, order_key, read_queued,
};
use crate::config::{ImportConfig, ServeConfig};
use crate::server::SyncServer;

#[cfg(test)]
mod tests;

/// How often a running server looks for queued logs.
const TICK: Duration = Duration::from_secs(5);

/// The largest queue entry read: a source id and one path.
const MAX_ENTRY_BYTES: u64 = 64 * 1024;

/// Passes that read a log again because it ended mid-line.
const MID_LINE_PASSES: u8 = 3;

/// One queued log.
#[derive(Serialize, Deserialize)]
struct Entry {
    source: String,
    path: PathBuf,
    /// How many passes already read this log and found its last line cut.
    #[serde(default)]
    passes: u8,
    /// Where the log sorts and what it decodes to, kept in the claim once a
    /// pass has read it. A hand-over queued since replaces the claim, and so
    /// this, since the log has grown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    place: Option<Place>,
}

/// What a pass that read a log keeps of it while it waits: enough to choose
/// what lands without reading it again.
#[derive(Serialize, Deserialize, Clone, Copy)]
struct Place {
    /// When its earliest conversation started, then ended.
    first: (u64, u64),
    size: Decoded,
}

/// `oneiron import <source> <log> --queue`: checks what `serve` will check,
/// then writes the entry whole under its final name in one rename.
pub(super) fn enqueue(
    source: HistorySource,
    path: &Path,
    config: &ServeConfig,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        config.import.queue,
        "the import queue is off; set `queue = true` under `[import]` in the serve config and \
         restart `serve`"
    );
    let root = config.import.root_for(source).ok_or_else(|| {
        anyhow::anyhow!(
            "a {} export is not a session log; import it with `serve` stopped",
            source.source_id()
        )
    })?;
    let path = std::path::absolute(path)?;
    below(&root, &path)?;
    let dir = config.import.queue_dir_for(&config.vault_path);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|error| anyhow::anyhow!("create {}: {error}", dir.display()))?;
    let name = entry_name(source, &path);
    let staged = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let body = serde_json::to_vec(&Entry {
        source: source.source_id().to_owned(),
        path: path.clone(),
        passes: 0,
        place: None,
    })?;
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged)
        .and_then(|mut file| file.write_all(&body))
        .and_then(|()| fs::rename(&staged, dir.join(format!("{name}.json"))));
    if let Err(error) = written {
        let _ = fs::remove_file(&staged);
        anyhow::bail!("queue {}: {error}", path.display());
    }
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(
        &mut stdout,
        &serde_json::json!({ "source": source.source_id(), "queued": path }),
    )?;
    writeln!(stdout)?;
    Ok(())
}

/// One entry per log: queueing the same log again replaces its entry.
fn entry_name(source: HistorySource, path: &Path) -> String {
    let digest = blake3::hash(path.as_os_str().as_encoded_bytes()).to_hex();
    format!("{}-{}", source.source_id(), &digest[..16])
}

/// What a running server drains: its queue folder and each source's root.
pub(in crate::commands) struct ImportQueue {
    dir: PathBuf,
    vault_path: PathBuf,
    config: ImportConfig,
    /// What one pass may hold decoded.
    budget: Decoded,
}

/// One claimed entry.
struct Claimed {
    name: String,
    entry: Entry,
    /// Its log, while this pass holds it decoded.
    read: Option<Log>,
    /// Its place was found this pass and is not in its claim yet.
    placed: bool,
}

/// A claimed log as read.
struct Log {
    source: HistorySource,
    session: QueuedSession,
}

/// What a pass lands, each with its log read, and what waits.
struct Chosen {
    landing: Vec<(Claimed, Log)>,
    waits: Vec<Claimed>,
}

/// What a pass landed, and the logs it left out.
#[derive(Default)]
struct Landed {
    totals: Totals,
    left_out: Vec<ImportWarning>,
}

#[cfg(test)]
thread_local! {
    /// Each log a pass read, in order, for the tests to count.
    static READS: std::cell::RefCell<Vec<PathBuf>> = const { std::cell::RefCell::new(Vec::new()) };
}

impl Claimed {
    /// Where it lands among the others; its name breaks a tie.
    fn order(&self) -> ((u64, u64), &str) {
        let first = self
            .entry
            .place
            .map_or((u64::MAX, u64::MAX), |place| place.first);
        (first, &self.name)
    }

    fn size(&self) -> Decoded {
        self.entry
            .place
            .map_or_else(Decoded::default, |place| place.size)
    }
}

impl ImportQueue {
    /// The queue when the owner turned it on. A hosted or relay node imports
    /// through its host, not from files beside the vault.
    pub(in crate::commands) fn from_config(config: &ServeConfig) -> Option<Self> {
        (config.import.queue
            && config.privacy_posture == oneiron::HostingPrivacyPosture::SelfHostLocal)
            .then(|| Self {
                dir: config.import.queue_dir_for(&config.vault_path),
                vault_path: config.vault_path.clone(),
                config: config.import.clone(),
                budget: Decoded::LIMIT,
            })
    }

    /// Drains the queue every few seconds, one pass at a time, off the async
    /// runtime. After a failed pass it waits longer each time, up to about
    /// five minutes, since its claims are read again.
    pub(in crate::commands) fn spawn(self, server: Arc<SyncServer>) -> tokio::task::JoinHandle<()> {
        let queue = Arc::new(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(TICK);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut failed = 0_u32;
            loop {
                interval.tick().await;
                let (queue, server) = (Arc::clone(&queue), Arc::clone(&server));
                let pass = tokio::task::spawn_blocking(move || queue.pass(server.vault())).await;
                let error = match pass {
                    Ok(Ok(_)) => {
                        failed = 0;
                        continue;
                    }
                    Ok(Err(error)) => format!("{error:#}"),
                    Err(error) => error.to_string(),
                };
                failed = failed.saturating_add(1);
                tracing::warn!(error = %error, "import queue pass failed");
                tokio::time::sleep(TICK * (1 << failed.min(6))).await;
            }
        })
    }

    /// One pass: claims every entry waiting, then lands the earliest that fit
    /// the decoded budget together, earliest first, and removes them. Entries
    /// land whole, in the order of their earliest conversation: a resumed or
    /// forked session starts with its original's first line, time and all,
    /// so its entry never sorts before the original's.
    ///
    /// A log is read once to land. One no pass has read yet is read to place
    /// it, and what it decodes is held while it can still land this pass;
    /// one that must wait keeps its place in its claim, so a later pass reads
    /// it only to land it.
    fn pass(&self, vault: &oneiron::Vault) -> anyhow::Result<Landed> {
        let Some(dir) = self.open_checked()? else {
            return Ok(Landed::default());
        };
        let Chosen { landing, waits } = self.choose(&dir)?;
        let unwritten = |error: std::io::Error| {
            anyhow::anyhow!("a claim kept for the next pass is unwritten: {error}")
        };
        let mut kept = Ok(());
        for held in waits.iter().filter(|held| held.placed) {
            kept = kept.and(rewrite(&dir, &held.name, &held.entry));
        }
        if landing.is_empty() {
            return kept.map(|()| Landed::default()).map_err(unwritten);
        }

        let mut sources: Vec<(HistorySource, Vec<HistoryConversation>)> = Vec::new();
        let mut landed = Landed::default();
        let mut done = Vec::new();
        for (held, Log { source, session }) in landing {
            match sources.iter_mut().find(|(known, _)| *known == source) {
                Some((_, conversations)) => conversations.extend(session.conversations),
                None => sources.push((source, session.conversations)),
            }
            landed.left_out.extend(session.left_out);
            done.push((held, session.mid_line));
        }
        landed.totals = land(vault, sources)
            .map_err(|error| error.context("its claimed logs are read again next pass"))?;
        let totals = &landed.totals;
        tracing::info!(
            conversations = totals.conversations,
            new = totals.new,
            skipped = totals.skipped,
            changed = totals.changed,
            refused = totals.refused,
            too_large = landed.left_out.len(),
            "queued import landed"
        );
        for left_out in &landed.left_out {
            let ImportWarning::LogTooLarge { path, bytes, limit } = left_out;
            tracing::warn!(
                warning = "log_too_large",
                path = %path,
                bytes,
                limit,
                "queued import left out a session log over the per-log limit; the rest landed"
            );
        }
        for (mut held, mid_line) in done {
            if mid_line && held.entry.passes < MID_LINE_PASSES {
                held.entry.passes += 1;
                kept = kept.and(rewrite(&dir, &held.name, &held.entry));
            } else {
                remove(&dir, &held.name);
            }
        }
        kept.map(|()| landed).map_err(unwritten)
    }

    /// Claims every entry waiting and chooses what lands: the earliest that
    /// fit the decoded budget, each read once. The rest wait.
    fn choose(&self, dir: &OwnedFd) -> anyhow::Result<Chosen> {
        let mut claimed: Vec<Claimed> = Vec::new();
        let mut unplaced = Vec::new();
        for name in waiting(dir)? {
            let Some(entry) = take(dir, &name) else {
                continue;
            };
            let held = Claimed {
                name,
                entry,
                read: None,
                placed: false,
            };
            if held.entry.place.is_some() {
                claimed.push(held);
            } else {
                unplaced.push(held);
            }
        }
        claimed.sort_by(|one, other| one.order().cmp(&other.order()));
        for mut held in unplaced {
            let Some(read) = self.read(dir, &mut held) else {
                continue;
            };
            held.read = Some(read);
            let at = claimed.partition_point(|known| known.order() < held.order());
            claimed.insert(at, held);
            // What sorts after the budget is spent cannot land this pass.
            let mut ahead = Decoded::default();
            for held in &mut claimed {
                ahead = ahead.and(held.size());
                if !ahead.within(self.budget) {
                    held.read = None;
                }
            }
        }

        let mut ahead = Decoded::default();
        let mut landing = Vec::new();
        let mut waits = Vec::new();
        for mut held in claimed {
            if waits.is_empty() && ahead.and(held.size()).within(self.budget) {
                let read = match held.read.take() {
                    Some(read) => read,
                    None => match self.read(dir, &mut held) {
                        Some(read) => read,
                        None => continue,
                    },
                };
                // A log that grew since it was placed may no longer fit.
                ahead = ahead.and(held.size());
                if ahead.within(self.budget) {
                    landing.push((held, read));
                    continue;
                }
            }
            held.read = None;
            waits.push(held);
        }
        Ok(Chosen { landing, waits })
    }

    /// The queue folder, opened without following a link and checked on that
    /// descriptor: the vault's owner owns it and no one else may write it.
    fn open_checked(&self) -> anyhow::Result<Option<OwnedFd>> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let dir = match openat(CWD, &self.dir, flags, Mode::empty()) {
            Ok(dir) => dir,
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => anyhow::bail!("open {}: {error}", self.dir.display()),
        };
        let folder = fstat(&dir)?;
        let vault_owner = fs::metadata(&self.vault_path)?.uid();
        anyhow::ensure!(
            folder.st_uid == vault_owner
                && !Mode::from_raw_mode(folder.st_mode).intersects(Mode::WGRP | Mode::WOTH),
            "{} must be a folder only the vault's owner can write (`chmod 700` it)",
            self.dir.display()
        );
        Ok(Some(dir))
    }

    /// Reads a claimed entry's log and places it. One that cannot be read is
    /// refused and removed.
    fn read(&self, dir: &OwnedFd, held: &mut Claimed) -> Option<Log> {
        #[cfg(test)]
        READS.with_borrow_mut(|reads| reads.push(held.entry.path.clone()));
        let entry = &held.entry;
        let read = HistorySource::parse(&entry.source)
            .ok_or_else(|| anyhow::anyhow!("unknown source {:?}", entry.source))
            .and_then(|source| {
                let root = self.config.root_for(source).ok_or_else(|| {
                    anyhow::anyhow!("{} logs are not imported from the queue", entry.source)
                })?;
                let session = read_queued(source, &root, &entry.path)?;
                Ok(Log { source, session })
            });
        match read {
            Ok(read) => {
                let conversations = &read.session.conversations;
                let mut size = Decoded::default();
                size.add(conversations);
                let first = conversations
                    .iter()
                    .map(order_key)
                    .min()
                    .map_or((u64::MAX, u64::MAX), |(started, ended, _)| (started, ended));
                held.entry.place = Some(Place { first, size });
                held.placed = true;
                Some(read)
            }
            Err(error) => {
                tracing::warn!(
                    entry = %held.name,
                    error = %format!("{error:#}"),
                    "queued import refused; queue the log again to retry"
                );
                remove(dir, &held.name);
                None
            }
        }
    }
}

/// Claims one entry; one that cannot be read is dropped.
fn take(dir: &OwnedFd, name: &str) -> Option<Entry> {
    claim(dir, name).unwrap_or_else(|error| {
        tracing::warn!(
            entry = %name,
            error = %format!("{error:#}"),
            "queue entry dropped"
        );
        None
    })
}

/// The entries waiting, by name, claimed ones included.
fn waiting(dir: &OwnedFd) -> anyhow::Result<Vec<String>> {
    let mut names = BTreeSet::new();
    for entry in Dir::read_from(dir)? {
        let entry = entry?;
        let Some(entry) = entry
            .file_name()
            .to_str()
            .ok()
            .filter(|entry| !entry.starts_with('.'))
        else {
            continue;
        };
        if let Some(name) = entry
            .strip_suffix(".json")
            .or_else(|| entry.strip_suffix(".taking"))
        {
            names.insert(name.to_owned());
        }
    }
    Ok(names.into_iter().collect())
}

/// Claims one entry by renaming it, and reads it. A claim a pass kept, or
/// left when it did not finish, is read again; a hand-over queued since
/// replaces it.
fn claim(dir: &OwnedFd, name: &str) -> anyhow::Result<Option<Entry>> {
    let taking = format!("{name}.taking");
    match renameat(dir, format!("{name}.json"), dir, &taking) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(error) => anyhow::bail!("claim {name}: {error}"),
    }
    if statat(dir, &taking, AtFlags::SYMLINK_NOFOLLOW).is_err() {
        return Ok(None);
    }
    let read = open_file(dir, OsStr::new(&taking), Path::new(&taking)).and_then(|file| {
        let mut text = String::new();
        file.take(MAX_ENTRY_BYTES).read_to_string(&mut text)?;
        Ok(serde_json::from_str::<Entry>(&text)?)
    });
    match read {
        Ok(entry) => Ok(Some(entry)),
        Err(error) => {
            remove(dir, name);
            anyhow::bail!("queue entry {name} is unreadable: {error:#}")
        }
    }
}

fn remove(dir: &OwnedFd, name: &str) {
    let _ = unlinkat(dir, format!("{name}.taking"), AtFlags::empty());
}

/// Rewrites a claim the next pass takes up: a log that ended mid-line,
/// counting this pass, or one that waits, with its place. A hand-over queued
/// meanwhile replaces it when that pass claims it. Unwritten, the claim stays
/// as it was.
fn rewrite(dir: &OwnedFd, name: &str, entry: &Entry) -> std::io::Result<()> {
    let staged = format!(".{name}.again.tmp");
    let flags =
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let written = serde_json::to_vec(entry)
        .map_err(std::io::Error::from)
        .and_then(|body| {
            let file = openat(dir, &staged, flags, Mode::RUSR | Mode::WUSR)?;
            fs::File::from(file).write_all(&body)
        })
        .and_then(|()| {
            renameat(dir, &staged, dir, format!("{name}.taking")).map_err(std::io::Error::from)
        });
    if written.is_err() {
        let _ = unlinkat(dir, &staged, AtFlags::empty());
    }
    written
}

/// Lands every claimed conversation, earliest first within each source.
fn land(
    vault: &oneiron::Vault,
    sources: Vec<(HistorySource, Vec<HistoryConversation>)>,
) -> anyhow::Result<Totals> {
    let owner = crate::owner::local_owner(vault)?;
    let imported_at = vault.now_recorded_at();
    let mut totals = Totals::default();
    for (source, mut conversations) in sources {
        earliest_first(&mut conversations);
        for conversation in &conversations {
            let report = vault
                .import_history(&owner, source, conversation, imported_at)
                .map_err(|error| anyhow::anyhow!("import stopped: {error}"))?;
            totals.add(&report);
        }
    }
    Ok(totals)
}
