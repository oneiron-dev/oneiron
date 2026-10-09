//! The import queue. `oneiron import <source> <log> --queue` leaves one small
//! file naming a session log; a running `serve` with `[import] queue = true`
//! imports that log within seconds, as `oneiron import` does on a stopped
//! vault. A client hook hands a live session over this way with no
//! credential and no wait. Only the owner can write the queue folder, and
//! `serve` reads only logs under the source's configured root.
//!
//! An entry is claimed by renaming it, so a log queued again while it is
//! being imported waits as a new entry. Every entry is removed once tried,
//! landed or refused; queueing the log again tries again, and the import
//! ledger lands only what is new.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use oneiron::ingest::history::HistorySource;
use serde::{Deserialize, Serialize};

use super::{Totals, below, open_in, read_queued};
use crate::config::{ImportConfig, ServeConfig};
use crate::server::SyncServer;

/// How often a running server looks for queued logs.
const TICK: Duration = Duration::from_secs(5);

/// The largest queue entry read: a source id and one path.
const MAX_ENTRY_BYTES: u64 = 64 * 1024;

/// One queued log.
#[derive(Serialize, Deserialize)]
struct Entry {
    source: String,
    path: PathBuf,
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

    /// Drains the queue every few seconds, one entry at a time, off the
    /// async runtime.
    pub(in crate::commands) fn spawn(self, server: Arc<SyncServer>) -> tokio::task::JoinHandle<()> {
        let queue = Arc::new(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(TICK);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let (queue, server) = (Arc::clone(&queue), Arc::clone(&server));
                if let Err(error) =
                    tokio::task::spawn_blocking(move || queue.drain(server.vault())).await
                {
                    tracing::warn!(error = %error, "import queue task failed");
                }
            }
        })
    }

    fn drain(&self, vault: &oneiron::Vault) {
        let names = match self.waiting() {
            Ok(names) => names,
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "import queue not read");
                return;
            }
        };
        for name in names {
            match self.take(vault, &name) {
                Ok(Some(totals)) => tracing::info!(
                    entry = %name,
                    conversations = totals.conversations,
                    new = totals.new,
                    skipped = totals.skipped,
                    changed = totals.changed,
                    refused = totals.refused,
                    "queued import landed"
                ),
                Ok(None) => {}
                Err(error) => tracing::warn!(
                    entry = %name,
                    error = %format!("{error:#}"),
                    "queued import refused; queue the log again to retry"
                ),
            }
        }
    }

    /// The entries waiting, by name. A missing folder holds none; a folder
    /// another user owns or may write is not read at all.
    fn waiting(&self) -> anyhow::Result<Vec<String>> {
        let folder = match fs::symlink_metadata(&self.dir) {
            Ok(folder) => folder,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => anyhow::bail!("read {}: {error}", self.dir.display()),
        };
        let vault_owner = fs::metadata(&self.vault_path)?.uid();
        anyhow::ensure!(
            folder.is_dir() && folder.uid() == vault_owner && folder.mode() & 0o022 == 0,
            "{} must be a folder only the vault's owner can write (`chmod 700` it)",
            self.dir.display()
        );
        let mut names = BTreeSet::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?.file_name();
            let Some(entry) = entry.to_str().filter(|entry| !entry.starts_with('.')) else {
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

    /// Claims one entry, lands its log, and removes it whatever happened.
    /// An entry claimed before a restart is taken up again.
    fn take(&self, vault: &oneiron::Vault, name: &str) -> anyhow::Result<Option<Totals>> {
        let taking = format!("{name}.taking");
        match fs::rename(
            self.dir.join(format!("{name}.json")),
            self.dir.join(&taking),
        ) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => anyhow::bail!("claim {name}: {error}"),
        }
        let Some(entry) = open_in(&self.dir, &taking)? else {
            return Ok(None);
        };
        let landed = self.land(vault, entry);
        let _ = fs::remove_file(self.dir.join(&taking));
        landed.map(Some)
    }

    fn land(&self, vault: &oneiron::Vault, entry: File) -> anyhow::Result<Totals> {
        let mut text = String::new();
        entry.take(MAX_ENTRY_BYTES).read_to_string(&mut text)?;
        let entry: Entry = serde_json::from_str(&text)?;
        let source = HistorySource::parse(&entry.source)
            .ok_or_else(|| anyhow::anyhow!("unknown source {:?}", entry.source))?;
        let root = self.config.root_for(source).ok_or_else(|| {
            anyhow::anyhow!("{} logs are not imported from the queue", entry.source)
        })?;
        let conversations = read_queued(source, &root, &entry.path)?;
        let owner = crate::owner::local_owner(vault)?;
        let imported_at = vault.now_recorded_at();
        let mut totals = Totals::default();
        for conversation in &conversations {
            let report = vault
                .import_history(&owner, source, conversation, imported_at)
                .map_err(|error| anyhow::anyhow!("import stopped: {error}"))?;
            totals.add(&report);
        }
        Ok(totals)
    }
}
