//! The hosted import's job (ARCH-0027 #hosted-import, CROSS-ARCH-0024
//! #onboarding-import): an export staged inside the vault's own data
//! directory, in `imports/<id>/`, landed by the vault's own process as a
//! durable job.
//!
//! The stager ([`stage`]; `oneiron import <chatgpt|claude> <file> --hosted`,
//! the operator's seam) copies the export into `<id>/export.part`, counting
//! and hashing the bytes it writes. It syncs the copy and renames it to
//! `export.zip` or `export.json` by its first bytes, then writes
//! `request.json` (the source, the count and the hash) last, in one rename:
//! a folder holding `request.json` is whole. Only the vault's owner may
//! write `imports/`, as for the session-log queue's folder.
//!
//! Each pass of the worker ([`HostedImports::pass`]) first makes the job row
//! ([`oneiron::Vault::hosted_import_create`]) of each whole folder that has
//! none, at a second of its own, so the import has a review of its own. It
//! then takes up every unended job, oldest first. It decodes the export as
//! `oneiron import` does, sorts it earliest first, and lands each
//! conversation from the job's place on, keeping the place after each one.
//! A restart's first pass takes each job up at its place. When every
//! conversation has landed, the import's one inbox row is written, the
//! Dreamer is queued, the job ends Landed and its folder is removed. An
//! export that is gone, changed or does not decode ends its job Failed with
//! the reason, and the folder is removed: it would fail the same way on
//! every later pass. A failure of the vault leaves the job where it is for
//! the next pass.
//!
//! Each conversation lands under the host's admission, as a served write
//! does: a managed vault frozen for reap lands nothing, and the pass stops
//! between conversations.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use oneiron::ingest::history::{
    HistorySource, HostedImportId, HostedImportJob, HostedImportStaged, HostedImportState,
};
use rustix::fs::{CWD, Mode, OFlags, openat};
use serde::{Deserialize, Serialize};

use super::{decode, earliest_first, own_second, queue_dreamer};
use crate::config::ServeConfig;
use crate::server::{HousekeepingAdmission, SyncServer};

/// How often a running server looks for staged imports.
const TICK: Duration = Duration::from_secs(5);

/// The staging folder's name inside the vault's data directory.
const IMPORTS_DIR: &str = "imports";
/// A folder's files: the export while it is copied, the export once whole
/// (by its first bytes), and the request that marks the folder whole.
const PART_FILE: &str = "export.part";
const ZIP_FILE: &str = "export.zip";
const JSON_FILE: &str = "export.json";
const REQUEST_FILE: &str = "request.json";
const REQUEST_PART_FILE: &str = "request.part";

/// A zip's first bytes (a local file header).
const ZIP_MAGIC: [u8; 4] = *b"PK\x03\x04";
/// The largest `request.json` read: a source id, a count and a hash.
const MAX_REQUEST_BYTES: u64 = 4 * 1024;
/// The stager's copy buffer.
const COPY_BUFFER_BYTES: usize = 1 << 20;

/// What a whole folder asks for, as the stager wrote it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    source: String,
    bytes: u64,
    /// The BLAKE3 of the bytes, hex.
    blake3: String,
}

/// The vault's staging folder for the vault at `vault_path`.
fn imports_root(vault_path: &Path) -> PathBuf {
    vault_path.join(IMPORTS_DIR)
}

/// Stages `file` as a hosted import of `source` in the vault at
/// `vault_path`: the folder is whole once this returns, and the running
/// server lands it on its next pass. Only `file` is read, never through a
/// symbolic link.
///
/// # Errors
///
/// A source that is not an export, a `file` that is not a regular file, a
/// staging folder that someone other than the vault's owner may write, or a
/// failed copy; a folder left half-copied is removed.
pub(crate) fn stage(
    vault_path: &Path,
    source: HistorySource,
    file: &Path,
) -> anyhow::Result<(HostedImportId, HostedImportStaged)> {
    anyhow::ensure!(
        matches!(source, HistorySource::Chatgpt | HistorySource::Claude),
        "a hosted import takes a ChatGPT or Claude export; {} is not one",
        source.source_id()
    );
    anyhow::ensure!(
        vault_path.join("data.mdb").is_file(),
        "vault {} does not exist; `oneiron init` creates one",
        vault_path.display()
    );
    let root = imports_root(vault_path);
    match fs::DirBuilder::new().mode(0o700).create(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => anyhow::bail!("create {}: {error}", root.display()),
    }
    check_root(vault_path, &root)?;
    let id = HostedImportId::generate();
    let folder = root.join(id.to_hex());
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&folder)
        .map_err(|error| anyhow::anyhow!("create {}: {error}", folder.display()))?;
    match stage_into(&folder, source, file) {
        Ok(staged) => Ok((id, staged)),
        Err(error) => {
            let _ = fs::remove_dir_all(&folder);
            Err(error)
        }
    }
}

/// Copies `file` into `folder` and writes its request last.
fn stage_into(
    folder: &Path,
    source: HistorySource,
    file: &Path,
) -> anyhow::Result<HostedImportStaged> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut input = File::from(
        openat(CWD, file, flags, Mode::empty())
            .map_err(|error| anyhow::anyhow!("open {}: {error}", file.display()))?,
    );
    anyhow::ensure!(
        input.metadata()?.is_file(),
        "{} is not a regular file",
        file.display()
    );
    let part = folder.join(PART_FILE);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&part)
        .map_err(|error| anyhow::anyhow!("create {}: {error}", part.display()))?;
    let mut hasher = blake3::Hasher::new();
    let mut head = Vec::with_capacity(ZIP_MAGIC.len());
    let mut bytes = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|error| anyhow::anyhow!("read {}: {error}", file.display()))?;
        if read == 0 {
            break;
        }
        let chunk = &buffer[..read];
        let wanted = ZIP_MAGIC.len().saturating_sub(head.len());
        head.extend_from_slice(&chunk[..wanted.min(read)]);
        hasher.update(chunk);
        output.write_all(chunk)?;
        bytes += u64::try_from(read)?;
    }
    output.sync_all()?;
    drop(output);
    let name = if head == ZIP_MAGIC {
        ZIP_FILE
    } else {
        JSON_FILE
    };
    fs::rename(&part, folder.join(name))?;
    let blake3 = *hasher.finalize().as_bytes();
    let request = serde_json::to_vec(&Request {
        source: source.source_id().to_owned(),
        bytes,
        blake3: blake3::Hash::from_bytes(blake3).to_hex().to_string(),
    })?;
    let request_part = folder.join(REQUEST_PART_FILE);
    let mut written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&request_part)?;
    written.write_all(&request)?;
    written.sync_all()?;
    drop(written);
    fs::rename(&request_part, folder.join(REQUEST_FILE))?;
    File::open(folder)?.sync_all()?;
    Ok(HostedImportStaged { bytes, blake3 })
}

/// `imports/` must be a folder, not a link, that only the vault's owner can
/// write.
fn check_root(vault_path: &Path, root: &Path) -> anyhow::Result<()> {
    let folder = fs::symlink_metadata(root)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", root.display()))?;
    let vault_owner = fs::metadata(vault_path)?.uid();
    anyhow::ensure!(
        folder.is_dir() && folder.uid() == vault_owner && (folder.mode() & 0o022) == 0,
        "{} must be a folder only the vault's owner can write (`chmod 700` it)",
        root.display()
    );
    Ok(())
}

/// `oneiron import <chatgpt|claude> <file> --hosted`: stages the export for
/// the running `serve` and prints its id.
pub(super) fn stage_command(
    source: HistorySource,
    file: &Path,
    config: &ServeConfig,
) -> anyhow::Result<()> {
    let (id, staged) = stage(&config.vault_path, source, file)?;
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(
        &mut stdout,
        &serde_json::json!({
            "import_id": id.to_hex(),
            "source": source.source_id(),
            "staged_bytes": staged.bytes,
        }),
    )?;
    writeln!(stdout)?;
    Ok(())
}

/// What a running server drains: the staged imports of its vault.
pub(crate) struct HostedImports {
    vault_path: PathBuf,
    /// Asked before each conversation lands; `None` lands nothing more this
    /// pass.
    admission: HousekeepingAdmission,
}

impl HostedImports {
    pub(crate) fn new(vault_path: PathBuf, admission: HousekeepingAdmission) -> Self {
        Self {
            vault_path,
            admission,
        }
    }

    /// Runs a pass every few seconds, one at a time, off the async runtime.
    /// After a failed pass it waits longer each time, up to about five
    /// minutes.
    pub(crate) fn spawn(self, server: Arc<SyncServer>) -> tokio::task::JoinHandle<()> {
        let worker = Arc::new(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(TICK);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut failed = 0_u32;
            loop {
                interval.tick().await;
                let worker = Arc::clone(&worker);
                let vault = Arc::clone(server.vault());
                let pass = tokio::task::spawn_blocking(move || worker.pass(&vault, None)).await;
                let error = match pass {
                    Ok(Ok(())) => {
                        failed = 0;
                        continue;
                    }
                    Ok(Err(error)) => format!("{error:#}"),
                    Err(error) => error.to_string(),
                };
                failed = failed.saturating_add(1);
                tracing::warn!(error = %error, "hosted import pass failed");
                tokio::time::sleep(TICK * (1 << failed.min(6))).await;
            }
        })
    }

    /// One pass: makes the row of each whole folder that has none, then
    /// lands every unended job, oldest first. `budget` lands at most that
    /// many conversations in this pass, as a process that stops part way
    /// does; `None` lands them all.
    ///
    /// # Errors
    ///
    /// A staging folder someone other than the vault's owner may write, or a
    /// failure of the vault; each job keeps its place.
    pub(crate) fn pass(&self, vault: &oneiron::Vault, budget: Option<u64>) -> anyhow::Result<()> {
        let root = imports_root(&self.vault_path);
        let root_exists = match fs::symlink_metadata(&root) {
            Ok(_) => {
                check_root(&self.vault_path, &root)?;
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => anyhow::bail!("read {}: {error}", root.display()),
        };
        if root_exists {
            adopt(vault, &root)?;
        }
        let mut budget = budget;
        for (id, job) in vault.hosted_imports()? {
            if job.ended() {
                continue;
            }
            if !self.run(vault, &root, id, &job, &mut budget)? {
                break;
            }
        }
        Ok(())
    }

    /// Lands one job from its place on. `false` when the pass must stop:
    /// its budget is spent or the host admits no more.
    fn run(
        &self,
        vault: &oneiron::Vault,
        root: &Path,
        id: HostedImportId,
        job: &HostedImportJob,
        budget: &mut Option<u64>,
    ) -> anyhow::Result<bool> {
        let folder = root.join(id.to_hex());
        let Some(source) = job.history_source() else {
            fail(
                vault,
                &folder,
                id,
                "the import's source is not one this build reads",
            )?;
            return Ok(true);
        };
        let Some(export) = staged_export(&folder, job.staged_bytes)? else {
            fail(vault, &folder, id, "the staged export is gone or changed")?;
            return Ok(true);
        };
        let mut conversations = match decode(source, &export) {
            Ok((_, conversations)) => conversations,
            Err(error) => {
                fail(vault, &folder, id, &format!("{error:#}"))?;
                return Ok(true);
            }
        };
        earliest_first(&mut conversations);
        let messages: u64 = conversations
            .iter()
            .map(|conversation| u64::try_from(conversation.messages.len()).unwrap_or(u64::MAX))
            .sum();
        vault.hosted_import_decoded(id, u64::try_from(conversations.len())?, messages)?;
        let owner = crate::owner::local_owner(vault)?;
        let mut cursor = job.cursor;
        for conversation in conversations
            .iter()
            .skip(usize::try_from(cursor).unwrap_or(usize::MAX))
        {
            if *budget == Some(0) {
                return Ok(false);
            }
            let Some(_admitted) = (self.admission)() else {
                return Ok(false);
            };
            let report = vault
                .import_history(&owner, source, conversation, job.imported_at)
                .map_err(|error| anyhow::anyhow!("import stopped: {error}"))?;
            cursor += 1;
            vault.hosted_import_landed(id, cursor, &report)?;
            if let Some(left) = budget.as_mut() {
                *left -= 1;
            }
        }
        let landed = vault.hosted_import(id)?;
        if landed
            .as_ref()
            .is_some_and(|landed| landed.new + landed.changed > 0)
        {
            // One inbox row for the import, never one per conversation.
            vault.record_history_import_finished(source, job.imported_at)?;
        }
        queue_dreamer(vault, job.imported_at)?;
        vault.hosted_import_end(id, HostedImportState::Landed)?;
        remove_folder(&folder);
        tracing::info!(
            import = %id.to_hex(),
            review = %oneiron::ingest::history::history_import_review_id(source, job.imported_at),
            "hosted import landed; its claims wait for the owner in this review"
        );
        Ok(true)
    }
}

/// Makes the row of each whole folder under `root` that has none, each at a
/// second of its own.
fn adopt(vault: &oneiron::Vault, root: &Path) -> anyhow::Result<()> {
    let mut whole = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let Some(id) = entry.file_name().to_str().and_then(HostedImportId::parse) else {
            continue;
        };
        if !entry.file_type()?.is_dir() || vault.hosted_import(id)?.is_some() {
            continue;
        }
        let Some(request) = read_request(&entry.path())? else {
            continue;
        };
        let (Some(source), Ok(hash)) = (
            HistorySource::parse(&request.source),
            blake3::Hash::from_hex(&request.blake3),
        ) else {
            tracing::warn!(import = %id.to_hex(), "a staged import's request does not read; left");
            continue;
        };
        let staged = HostedImportStaged {
            bytes: request.bytes,
            blake3: *hash.as_bytes(),
        };
        whole.push((id, source, staged));
    }
    if whole.is_empty() {
        return Ok(());
    }
    let owner = crate::owner::local_owner(vault)?;
    for (id, source, staged) in whole {
        vault.hosted_import_create(&owner, id, source, staged, own_second(vault)?)?;
        tracing::info!(import = %id.to_hex(), source = source.source_id(), "hosted import staged");
    }
    Ok(())
}

/// The request of a whole folder; `None` while the folder is not whole.
fn read_request(folder: &Path) -> anyhow::Result<Option<Request>> {
    let path = folder.join(REQUEST_FILE);
    let file = match openat(
        CWD,
        &path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => File::from(file),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => anyhow::bail!("open {}: {error}", path.display()),
    };
    let mut bytes = Vec::new();
    file.take(MAX_REQUEST_BYTES + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len())? > MAX_REQUEST_BYTES {
        return Ok(None);
    }
    Ok(serde_json::from_slice(&bytes).ok())
}

/// The folder's export, when it is a regular file of the staged length.
fn staged_export(folder: &Path, bytes: u64) -> anyhow::Result<Option<PathBuf>> {
    for name in [ZIP_FILE, JSON_FILE] {
        let path = folder.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                return Ok((metadata.is_file() && metadata.len() == bytes).then_some(path));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => anyhow::bail!("read {}: {error}", path.display()),
        }
    }
    Ok(None)
}

/// Ends a job Failed with `reason` and removes its folder.
fn fail(
    vault: &oneiron::Vault,
    folder: &Path,
    id: HostedImportId,
    reason: &str,
) -> anyhow::Result<()> {
    vault.hosted_import_end(id, HostedImportState::Failed(reason.to_owned()))?;
    remove_folder(folder);
    tracing::warn!(import = %id.to_hex(), reason, "hosted import failed");
    Ok(())
}

/// Removes an ended job's folder; a failure is said, and the job stays
/// ended.
fn remove_folder(folder: &Path) {
    match fs::remove_dir_all(folder) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(folder = %folder.display(), error = %error, "hosted import folder not removed");
        }
    }
}
