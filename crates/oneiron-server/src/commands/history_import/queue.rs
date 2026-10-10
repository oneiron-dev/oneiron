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
use super::{Decoded, Totals, below, earliest_first, order_key, read_queued};
use crate::config::{ImportConfig, ServeConfig};
use crate::server::SyncServer;

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
}

/// One claimed entry, read and waiting to land.
struct Claimed {
    name: String,
    entry: Entry,
    source: HistorySource,
    conversations: Vec<HistoryConversation>,
    /// Where its earliest conversation sorts.
    first: (u64, u64, String),
    mid_line: bool,
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
                    Ok(Ok(())) => {
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

    /// One pass: claims and reads every entry waiting, then lands them
    /// together, earliest first, and removes them. Entries land whole, in the
    /// order of their earliest conversation: a resumed or forked session
    /// starts with its original's first line, time and all, so its entry
    /// never sorts before the original's. Past the decoded budget, only the
    /// earliest entries that fit are read again to land; the rest wait.
    fn pass(&self, vault: &oneiron::Vault) -> anyhow::Result<()> {
        let Some(dir) = self.open_checked()? else {
            return Ok(());
        };
        let mut claimed: Vec<Claimed> = Vec::new();
        let mut decoded = Decoded::default();
        let mut over = false;
        for name in waiting(&dir)? {
            let Some(mut read) = self.take(&dir, name) else {
                continue;
            };
            decoded.add(&read.conversations);
            if !over && !decoded.fits() {
                over = true;
                for held in &mut claimed {
                    held.conversations = Vec::new();
                }
            }
            if over {
                read.conversations = Vec::new();
            }
            claimed.push(read);
        }
        claimed.sort_by(|one, other| one.first.cmp(&other.first));
        if over {
            let mut decoded = Decoded::default();
            let mut ready = Vec::new();
            for held in claimed {
                let Some(read) = self.read(&dir, held.name, held.entry) else {
                    continue;
                };
                decoded.add(&read.conversations);
                if !decoded.fits() {
                    // This claim and every later one wait for the next pass.
                    break;
                }
                ready.push(read);
            }
            claimed = ready;
        }
        if claimed.is_empty() {
            return Ok(());
        }
        let mut sources: Vec<(HistorySource, Vec<HistoryConversation>)> = Vec::new();
        for read in &mut claimed {
            let conversations = std::mem::take(&mut read.conversations);
            match sources.iter_mut().find(|(known, _)| *known == read.source) {
                Some((_, landing)) => landing.extend(conversations),
                None => sources.push((read.source, conversations)),
            }
        }
        let totals = land(vault, sources)
            .map_err(|error| error.context("its claimed logs are read again next pass"))?;
        tracing::info!(
            conversations = totals.conversations,
            new = totals.new,
            skipped = totals.skipped,
            changed = totals.changed,
            refused = totals.refused,
            "queued import landed"
        );
        let mut kept = Ok(());
        for done in claimed {
            if done.mid_line && done.entry.passes < MID_LINE_PASSES {
                kept = kept.and(again(&dir, &done.name, done.entry));
            } else {
                remove(&dir, &done.name);
            }
        }
        kept.map_err(|error| anyhow::anyhow!("a log that ended mid-line is read again: {error}"))
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

    /// Claims one entry and reads its log.
    fn take(&self, dir: &OwnedFd, name: String) -> Option<Claimed> {
        match claim(dir, &name) {
            Ok(Some(entry)) => self.read(dir, name, entry),
            Ok(None) => None,
            Err(error) => {
                tracing::warn!(
                    entry = %name,
                    error = %format!("{error:#}"),
                    "queue entry dropped"
                );
                None
            }
        }
    }

    /// Reads a claimed entry's log. One that cannot be read is refused and
    /// removed.
    fn read(&self, dir: &OwnedFd, name: String, entry: Entry) -> Option<Claimed> {
        let read = HistorySource::parse(&entry.source)
            .ok_or_else(|| anyhow::anyhow!("unknown source {:?}", entry.source))
            .and_then(|source| {
                let root = self.config.root_for(source).ok_or_else(|| {
                    anyhow::anyhow!("{} logs are not imported from the queue", entry.source)
                })?;
                Ok((source, read_queued(source, &root, &entry.path)?))
            });
        match read {
            Ok((source, (conversations, mid_line))) => Some(Claimed {
                first: conversations.iter().map(order_key).min().unwrap_or((
                    u64::MAX,
                    u64::MAX,
                    String::new(),
                )),
                name,
                entry,
                source,
                conversations,
                mid_line,
            }),
            Err(error) => {
                tracing::warn!(
                    entry = %name,
                    error = %format!("{error:#}"),
                    "queued import refused; queue the log again to retry"
                );
                remove(dir, &name);
                None
            }
        }
    }
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

/// Keeps the claim on a log that ended mid-line for the next pass, counting
/// this one. A hand-over queued meanwhile replaces it when that pass claims
/// it. Unwritten, the claim stays as it was.
fn again(dir: &OwnedFd, name: &str, mut entry: Entry) -> std::io::Result<()> {
    entry.passes += 1;
    let staged = format!(".{name}.again.tmp");
    let flags =
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let written = serde_json::to_vec(&entry)
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
