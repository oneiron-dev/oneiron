//! The hosted import's job (ARCH-0027 #hosted-import, CROSS-ARCH-0024
//! #onboarding-import): an export staged inside the vault's own data
//! directory, in `imports/<id>/`, landed by the vault's own process as a
//! durable job.
//!
//! One writer stages every export, in three steps: it makes the folder with
//! an empty `export.part`, appends the export's bytes to the part, syncing
//! each append, and finishes the folder. Finishing names the part
//! `export.zip` or `export.json` by its first bytes, then writes
//! `request.json` (the source, the count and the hash) last, in one rename:
//! a folder holding `request.json` is whole. Only the vault's owner may
//! write `imports/`, as for the session-log queue's folder. Two callers use
//! the writer:
//! - the stager ([`stage`]; `oneiron import <chatgpt|claude> <file>
//!   --hosted`, the operator's seam) copies the export in one append;
//! - an upload to the vault's own hostname (`/v1/owner/imports/hosted`)
//!   first declares the export's source and size ([`declare_upload`]), kept
//!   in `declared.json` beside the part, then sends the export in parts,
//!   each at the offset the part has reached ([`upload_part`]). The upload's
//!   state between two parts is the folder alone, so a restart resumes it
//!   there. The part that reaches the declared size finishes the folder.
//!   An upload the owner gives up before its export is staged is deleted
//!   with its folder ([`delete_upload`]).
//!
//! Each pass of the worker ([`HostedImports::pass`]) first makes the job row
//! ([`oneiron::Vault::hosted_import_create`]) of each whole folder that has
//! none, at a second of its own, so the import has a review of its own. It
//! then takes up every unended job, oldest first. It decodes the export as
//! `oneiron import` does, through the archive pre-check, and keeps in the
//! row what the export holds and the entries the pre-check skipped. It sorts
//! the conversations earliest first and lands each one from the job's place
//! on, keeping the place after each one. A restart's first pass takes each
//! job up at its place. When every conversation has landed, the import's
//! one inbox row is written, the Dreamer is queued, the job ends Landed and
//! its folder is removed. An export that is gone, changed, refused by the
//! pre-check or does not decode ends its job Failed with the reason, and the
//! folder is removed: it would fail the same way on every later pass. A
//! failure of the vault leaves the job where it is for the next pass.
//!
//! A job asked to cancel (`vault.imports.cancel`) is Cancelling. Its worker
//! reads the row again before each conversation, so a cancel that comes
//! during a pass stops the job at the next conversation. What landed is
//! surfaced in the import's review as a finished job's is, the job ends
//! Cancelled and its folder is removed. A pass also removes the folder of an
//! ended job that outlived its end, and what is left of a deleted upload's.
//!
//! Every write of a pass is made under the host's admission, as a served
//! write is: the rows it makes and the folders it removes, each conversation,
//! and a job's end with its inbox row, its Dreamer queue and the removal of
//! its folder, which run under the guard of the job's last conversation. A
//! managed vault frozen for reap writes nothing, and the pass gives the guard
//! back between two conversations and stops there.
//!
//! A process that stops after a conversation's landing commits and before the
//! job's place is kept leaves messages the import landed that the landing of
//! the same conversation again counts skipped. The pass reads them first
//! ([`oneiron::Vault::hosted_import_resumed`]) and counts them as they landed,
//! so the job's counts, and whether its import is surfaced, stay true. A job
//! asked to cancel before that conversation landed again keeps them the same
//! way before it ends, and lands nothing more.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use oneiron::ingest::history::{
    HistoryConversation, HistorySource, HostedImportId, HostedImportJob, HostedImportStaged,
    HostedImportState,
};
use rustix::fs::{CWD, Mode, OFlags, openat};
use serde::{Deserialize, Serialize};

use super::{ExportBounds, decode, earliest_first, own_second, queue_dreamer};
use crate::config::{ImportConfig, ServeConfig};
use crate::server::{HousekeepingAdmission, SyncServer};

/// How often a running server looks for staged imports.
const TICK: Duration = Duration::from_secs(5);

/// The staging folder's name inside the vault's data directory.
const IMPORTS_DIR: &str = "imports";
/// A folder's files: the export while it is written, the export once whole
/// (by its first bytes), the request that marks the folder whole, and an
/// upload's declared source and size.
const PART_FILE: &str = "export.part";
const ZIP_FILE: &str = "export.zip";
const JSON_FILE: &str = "export.json";
const REQUEST_FILE: &str = "request.json";
const REQUEST_PART_FILE: &str = "request.part";
const DECLARED_FILE: &str = "declared.json";
const DECLARED_PART_FILE: &str = "declared.part";
/// The suffix a deleted upload's folder is renamed to before it is removed:
/// a folder so named is no upload, and a pass removes what a stopped process
/// left of it.
const DELETED_SUFFIX: &str = ".deleted";

/// A zip's first bytes (a local file header).
const ZIP_MAGIC: [u8; 4] = *b"PK\x03\x04";
/// The largest `request.json` or `declared.json` read: a source id, a count
/// and a hash.
const MAX_REQUEST_BYTES: u64 = 4 * 1024;
/// The stager's copy buffer, and the finish's hash buffer.
const COPY_BUFFER_BYTES: usize = 1 << 20;

/// What a whole folder asks for, as the writer wrote it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    source: String,
    bytes: u64,
    /// The BLAKE3 of the bytes, hex.
    blake3: String,
}

/// What an upload declared before its first byte: the export's source and
/// its size. A folder holding it is an upload.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Declared {
    source: String,
    bytes: u64,
}

/// The vault's staging folder for the vault at `vault_path`.
fn imports_root(vault_path: &Path) -> PathBuf {
    vault_path.join(IMPORTS_DIR)
}

/// Whether `source` is an export a hosted import takes: ChatGPT's or
/// Claude.ai's (HI-SCOPE = A, 13 Nov 07:14).
pub(crate) fn takes_source(source: HistorySource) -> bool {
    matches!(source, HistorySource::Chatgpt | HistorySource::Claude)
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
        takes_source(source),
        "a hosted import takes a ChatGPT or Claude export; {} is not one",
        source.source_id()
    );
    let (id, folder) = create_folder(vault_path)?;
    match stage_into(&folder, source, file) {
        Ok(staged) => Ok((id, staged)),
        Err(error) => {
            let _ = fs::remove_dir_all(&folder);
            Err(error)
        }
    }
}

/// Copies `file` into `folder`'s part in one append and finishes the
/// folder.
fn stage_into(
    folder: &Path,
    source: HistorySource,
    file: &Path,
) -> anyhow::Result<HostedImportStaged> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let input = File::from(
        openat(CWD, file, flags, Mode::empty())
            .map_err(|error| anyhow::anyhow!("open {}: {error}", file.display()))?,
    );
    anyhow::ensure!(
        input.metadata()?.is_file(),
        "{} is not a regular file",
        file.display()
    );
    let mut part = open_part(folder)?;
    let mut input = BufReader::with_capacity(COPY_BUFFER_BYTES, input);
    match append_part(&mut part, 0, &mut input, u64::MAX) {
        Ok(_) => {}
        Err(AppendFailed::Read(error)) => anyhow::bail!("read {}: {error}", file.display()),
        Err(AppendFailed::Write(error)) => return Err(error.into()),
        Err(AppendFailed::PastLimit) => anyhow::bail!("{} has no end", file.display()),
    }
    drop(part);
    finish_folder(folder, source)
}

/// Makes a new import's folder in the vault at `vault_path`, holding an
/// empty `export.part`: the writer's first step.
fn create_folder(vault_path: &Path) -> anyhow::Result<(HostedImportId, PathBuf)> {
    anyhow::ensure!(
        vault_path.join("data.mdb").is_file(),
        "vault {} does not exist; `oneiron init` creates one",
        vault_path.display()
    );
    let root = imports_root(vault_path);
    match fs::DirBuilder::new().mode(0o700).create(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => anyhow::bail!("create {}: {error}", root.display()),
    }
    check_root(vault_path, &root)?;
    let id = HostedImportId::generate();
    let folder = root.join(id.to_hex());
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&folder)
        .map_err(|error| anyhow::anyhow!("create {}: {error}", folder.display()))?;
    let part = folder.join(PART_FILE);
    if let Err(error) = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&part)
    {
        let _ = fs::remove_dir_all(&folder);
        anyhow::bail!("create {}: {error}", part.display());
    }
    Ok((id, folder))
}

/// The folder's `export.part`, open to write, never through a link.
fn open_part(folder: &Path) -> anyhow::Result<File> {
    let part = folder.join(PART_FILE);
    let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    Ok(File::from(
        openat(CWD, &part, flags, Mode::empty())
            .map_err(|error| anyhow::anyhow!("open {}: {error}", part.display()))?,
    ))
}

/// Why a part was not appended. The part keeps the length it had.
enum AppendFailed {
    /// The input holds more bytes than the append may take.
    PastLimit,
    /// The input could not be read.
    Read(io::Error),
    /// The part could not be written or synced.
    Write(io::Error),
}

/// Appends what `input` holds to `part`, which is `start` bytes long, and
/// syncs it: the writer's second step. An input of more than `limit` bytes
/// appends nothing, nor does one whose copy fails: the part is cut back to
/// `start`. Answers the bytes appended.
fn append_part(
    part: &mut File,
    start: u64,
    input: &mut dyn BufRead,
    limit: u64,
) -> Result<u64, AppendFailed> {
    let copied = copy_at(part, start, input, limit);
    if copied.is_err() {
        // What was written past `start` is not the export: the part keeps
        // only whole appends.
        let _ = part.set_len(start).and_then(|()| part.sync_all());
    }
    copied
}

/// The copy of [`append_part`], then the sync.
fn copy_at(
    part: &mut File,
    start: u64,
    input: &mut dyn BufRead,
    limit: u64,
) -> Result<u64, AppendFailed> {
    part.seek(SeekFrom::Start(start))
        .map_err(AppendFailed::Write)?;
    let mut appended = 0_u64;
    loop {
        let chunk = match input.fill_buf() {
            Ok(chunk) => chunk,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(AppendFailed::Read(error)),
        };
        if chunk.is_empty() {
            break;
        }
        let read = chunk.len();
        appended = appended.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if appended > limit {
            return Err(AppendFailed::PastLimit);
        }
        part.write_all(chunk).map_err(AppendFailed::Write)?;
        input.consume(read);
    }
    part.sync_all().map_err(AppendFailed::Write)?;
    Ok(appended)
}

/// Finishes `folder`: names its part by its first bytes, then writes
/// `request.json` (the source, the count and the hash of the export as it
/// is on the disk) last, in one rename: the writer's third step. A folder
/// whose part was named but whose request was not written, as a process
/// that stopped between the two leaves it, is finished from there.
fn finish_folder(folder: &Path, source: HistorySource) -> anyhow::Result<HostedImportStaged> {
    let part = folder.join(PART_FILE);
    let export = match fs::symlink_metadata(&part) {
        Ok(_) => {
            let mut head = Vec::with_capacity(ZIP_MAGIC.len());
            open_regular(&part)?
                .take(u64::try_from(ZIP_MAGIC.len())?)
                .read_to_end(&mut head)?;
            let name = if head == ZIP_MAGIC {
                ZIP_FILE
            } else {
                JSON_FILE
            };
            let export = folder.join(name);
            fs::rename(&part, &export)?;
            export
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => named_export(folder)?
            .ok_or_else(|| anyhow::anyhow!("{} holds no export", folder.display()))?,
        Err(error) => anyhow::bail!("read {}: {error}", part.display()),
    };
    let mut hasher = blake3::Hasher::new();
    let mut read = BufReader::with_capacity(COPY_BUFFER_BYTES, open_regular(&export)?);
    let bytes = io::copy(&mut read, &mut hasher)?;
    let blake3 = *hasher.finalize().as_bytes();
    let request = serde_json::to_vec(&Request {
        source: source.source_id().to_owned(),
        bytes,
        blake3: blake3::Hash::from_bytes(blake3).to_hex().to_string(),
    })?;
    write_last(folder, REQUEST_PART_FILE, REQUEST_FILE, &request)?;
    Ok(HostedImportStaged { bytes, blake3 })
}

/// Writes `bytes` to `part_name` in `folder`, syncs it, renames it to
/// `name` and syncs the folder: `name` appears whole or not at all. A
/// `part_name` a stopped process left is written over.
fn write_last(folder: &Path, part_name: &str, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
    let part = folder.join(part_name);
    let mut written = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&part)?;
    written.write_all(bytes)?;
    written.sync_all()?;
    drop(written);
    fs::rename(&part, folder.join(name))?;
    File::open(folder)?.sync_all()?;
    Ok(())
}

/// `path` open to read, when it is a regular file, never through a link.
fn open_regular(path: &Path) -> anyhow::Result<File> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let file = File::from(
        openat(CWD, path, flags, Mode::empty())
            .map_err(|error| anyhow::anyhow!("open {}: {error}", path.display()))?,
    );
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "{} is not a regular file",
        path.display()
    );
    Ok(file)
}

/// The folder's named export, `export.zip` or `export.json`, when one is
/// there.
fn named_export(folder: &Path) -> anyhow::Result<Option<PathBuf>> {
    for name in [ZIP_FILE, JSON_FILE] {
        let path = folder.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => return Ok(Some(path)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => anyhow::bail!("read {}: {error}", path.display()),
        }
    }
    Ok(None)
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

/// An upload's state, as the upload routes answer it.
#[derive(Debug, Serialize)]
pub(crate) struct HostedUpload {
    /// The import's id: its job's, once the export is staged
    /// (`vault.imports.get`).
    pub(crate) import_id: String,
    /// The export's source: `chatgpt` or `claude`.
    pub(crate) source: String,
    /// The export's size, as declared.
    pub(crate) declared_bytes: u64,
    /// The bytes written so far: where the next part starts.
    pub(crate) offset: u64,
    /// Whether the export is whole and staged: the vault's worker lands it
    /// from here, and the upload takes no more bytes.
    pub(crate) staged: bool,
}

/// Why an upload's state was not read or its part not appended. Nothing was
/// written.
#[derive(Debug)]
pub(crate) enum UploadRefusal {
    /// No upload of that id is in this vault: it was never declared, or its
    /// job has ended and its folder is gone.
    NotFound,
    /// The export is staged: the upload takes no more bytes.
    Staged,
    /// The part does not start where the upload stands: the bytes written so
    /// far.
    Offset(u64),
    /// Another part of this upload is being written.
    Busy,
    /// The part runs past the declared size: the bytes still to come.
    PastDeclared(u64),
    /// The vault's disk had no room for the part.
    NoRoom,
    /// The folder's files failed.
    Failed(anyhow::Error),
}

impl From<anyhow::Error> for UploadRefusal {
    fn from(error: anyhow::Error) -> Self {
        Self::Failed(error)
    }
}

impl From<io::Error> for UploadRefusal {
    fn from(error: io::Error) -> Self {
        Self::Failed(error.into())
    }
}

/// Declares an upload of a `source` export of `bytes` bytes in the vault at
/// `vault_path`: its folder, with its empty part, and `declared.json` last.
/// The upload's parts come after.
///
/// # Errors
///
/// A source that is not an export, a size of nothing, a staging folder that
/// someone other than the vault's owner may write, or a failed write; a
/// folder left half-made is removed.
pub(crate) fn declare_upload(
    vault_path: &Path,
    source: HistorySource,
    bytes: u64,
) -> anyhow::Result<HostedUpload> {
    anyhow::ensure!(
        takes_source(source),
        "a hosted import takes a ChatGPT or Claude export; {} is not one",
        source.source_id()
    );
    anyhow::ensure!(bytes > 0, "an export of no bytes is not an export");
    let (id, folder) = create_folder(vault_path)?;
    let declared = serde_json::to_vec(&Declared {
        source: source.source_id().to_owned(),
        bytes,
    })?;
    if let Err(error) = write_last(&folder, DECLARED_PART_FILE, DECLARED_FILE, &declared) {
        let _ = fs::remove_dir_all(&folder);
        return Err(error);
    }
    Ok(HostedUpload {
        import_id: id.to_hex(),
        source: source.source_id().to_owned(),
        declared_bytes: bytes,
        offset: 0,
        staged: false,
    })
}

/// Upload `id`'s state in the vault at `vault_path`.
///
/// # Errors
///
/// [`UploadRefusal::NotFound`] for an id that is no upload in this vault;
/// a failure of its folder's files.
pub(crate) fn upload_state(
    vault_path: &Path,
    id: HostedImportId,
) -> Result<HostedUpload, UploadRefusal> {
    let upload = Upload::open(vault_path, id)?;
    let (offset, staged) = upload.written()?;
    Ok(upload.state(offset, staged))
}

/// Appends `part` to upload `id` in the vault at `vault_path` at `offset`,
/// the bytes it has written so far, and syncs it. The part that brings the
/// export to its declared size finishes the folder: the export is staged.
/// Once staged, the upload answers a part of no bytes at its declared size
/// with its state, as a client whose last reply was lost sends it again, and
/// refuses any other. One part is written at a time.
///
/// # Errors
///
/// An [`UploadRefusal`]: the part appended nothing.
pub(crate) fn upload_part(
    vault_path: &Path,
    id: HostedImportId,
    offset: u64,
    part: &mut dyn BufRead,
) -> Result<HostedUpload, UploadRefusal> {
    let upload = Upload::open(vault_path, id)?;
    upload.lock()?;
    let (written, staged) = upload.written()?;
    let declared = upload.declared;
    if staged {
        return if offset == declared && is_empty(part)? {
            Ok(upload.state(declared, true))
        } else {
            Err(UploadRefusal::Staged)
        };
    }
    if offset != written {
        return Err(UploadRefusal::Offset(written));
    }
    let room = declared
        .checked_sub(written)
        .ok_or_else(|| anyhow::anyhow!("the upload holds more than it declared"))?;
    let appended = if fs::symlink_metadata(upload.folder.join(PART_FILE)).is_ok() {
        let mut file = open_part(&upload.folder)?;
        match append_part(&mut file, written, part, room) {
            Ok(appended) => appended,
            Err(AppendFailed::PastLimit) => return Err(UploadRefusal::PastDeclared(room)),
            Err(AppendFailed::Read(error)) => return Err(error.into()),
            Err(AppendFailed::Write(error)) if error.kind() == io::ErrorKind::StorageFull => {
                return Err(UploadRefusal::NoRoom);
            }
            Err(AppendFailed::Write(error)) => return Err(error.into()),
        }
    } else if is_empty(part)? {
        // The part was named, the request not written: the finish below
        // goes on from there.
        0
    } else {
        return Err(UploadRefusal::PastDeclared(room));
    };
    let reached = written + appended;
    if reached < declared {
        return Ok(upload.state(reached, false));
    }
    finish_folder(&upload.folder, upload.source)?;
    Ok(upload.state(reached, true))
}

/// What a deleted upload answers.
#[derive(Debug, Serialize)]
pub(crate) struct DeletedUpload {
    /// The deleted upload's id: no upload route answers it any more.
    pub(crate) import_id: String,
    /// The bytes the upload had written, removed with its folder.
    pub(crate) removed_bytes: u64,
}

/// Deletes upload `id` in the vault at `vault_path`, whose export is not
/// staged, with its folder: no upload route answers it after, and the bytes
/// it had written leave the vault's disk. The delete takes the upload's
/// lock, so it never meets a part being written. The folder is renamed away
/// in one step, then removed; the worker's next pass removes what a process
/// that stopped between the two left.
///
/// # Errors
///
/// [`UploadRefusal::NotFound`] for an id that is no upload in this vault,
/// [`UploadRefusal::Busy`] while a part is written,
/// [`UploadRefusal::Staged`] once the export is staged (its import is
/// cancelled instead, with `vault.imports.cancel`), or a failed rename:
/// nothing was deleted.
pub(crate) fn delete_upload(
    vault_path: &Path,
    id: HostedImportId,
) -> Result<DeletedUpload, UploadRefusal> {
    let upload = Upload::open(vault_path, id)?;
    upload.lock()?;
    // A staged export is the worker's from here: it makes the import's job
    // from the request, and only the job's cancel stops it.
    match fs::symlink_metadata(upload.folder.join(REQUEST_FILE)) {
        Ok(_) => return Err(UploadRefusal::Staged),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    // A folder whose export is gone is deleted all the same.
    let removed_bytes = upload.written().map_or(0, |(written, _)| written);
    let root = imports_root(vault_path);
    let deleted = root.join(format!("{}{DELETED_SUFFIX}", id.to_hex()));
    fs::rename(&upload.folder, &deleted)?;
    if let Err(error) = File::open(&root).and_then(|imports| imports.sync_all()) {
        tracing::warn!(import = %id.to_hex(), error = %error, "hosted import folder rename not synced");
    }
    remove_folder(&deleted);
    Ok(DeletedUpload {
        import_id: id.to_hex(),
        removed_bytes,
    })
}

/// Whether `part` holds no byte.
fn is_empty(part: &mut dyn BufRead) -> io::Result<bool> {
    loop {
        match part.fill_buf() {
            Ok(chunk) => return Ok(chunk.is_empty()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// One declared upload's folder, as read.
struct Upload {
    id: HostedImportId,
    folder: PathBuf,
    source: HistorySource,
    /// The declared size.
    declared: u64,
    /// `declared.json`, open: the lock each part takes.
    declared_file: File,
}

impl Upload {
    /// Upload `id` in the vault at `vault_path`: a folder of `imports/`
    /// holding `declared.json`. A folder the stager writes holds none.
    fn open(vault_path: &Path, id: HostedImportId) -> Result<Self, UploadRefusal> {
        let root = imports_root(vault_path);
        match fs::symlink_metadata(&root) {
            Ok(_) => check_root(vault_path, &root)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(UploadRefusal::NotFound);
            }
            Err(error) => return Err(error.into()),
        }
        let folder = root.join(id.to_hex());
        match fs::symlink_metadata(&folder) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Err(UploadRefusal::NotFound),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(UploadRefusal::NotFound);
            }
            Err(error) => return Err(error.into()),
        }
        let path = folder.join(DECLARED_FILE);
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let declared_file = match openat(CWD, &path, flags, Mode::empty()) {
            Ok(file) => File::from(file),
            Err(rustix::io::Errno::NOENT) => return Err(UploadRefusal::NotFound),
            Err(error) => {
                return Err(anyhow::anyhow!("open {}: {error}", path.display()).into());
            }
        };
        let mut bytes = Vec::new();
        (&declared_file)
            .take(MAX_REQUEST_BYTES + 1)
            .read_to_end(&mut bytes)?;
        let declared: Declared = serde_json::from_slice(&bytes)
            .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
        let source = HistorySource::parse(&declared.source)
            .filter(|source| takes_source(*source))
            .ok_or_else(|| anyhow::anyhow!("{} names no export source", path.display()))?;
        Ok(Self {
            id,
            folder,
            source,
            declared: declared.bytes,
            declared_file,
        })
    }

    /// Takes the upload's lock, on `declared.json`, which stays in the
    /// folder through the finish: a second part or a delete sent meanwhile
    /// is refused at once, never left waiting. An upload deleted between its
    /// open and its lock is no upload: the delete moved its folder away.
    fn lock(&self) -> Result<(), UploadRefusal> {
        match self.declared_file.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => return Err(UploadRefusal::Busy),
            Err(fs::TryLockError::Error(error)) => return Err(error.into()),
        }
        match fs::symlink_metadata(self.folder.join(DECLARED_FILE)) {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(UploadRefusal::NotFound),
            Err(error) => Err(error.into()),
        }
    }

    /// The bytes written so far, and whether the export is staged: the
    /// request's count once it is, else the part's length, or the named
    /// export's when the finish stopped between its two steps.
    fn written(&self) -> anyhow::Result<(u64, bool)> {
        if fs::symlink_metadata(self.folder.join(REQUEST_FILE)).is_ok() {
            return Ok((self.declared, true));
        }
        let part = self.folder.join(PART_FILE);
        let path = if fs::symlink_metadata(&part).is_ok() {
            part
        } else {
            named_export(&self.folder)?
                .ok_or_else(|| anyhow::anyhow!("{} holds no export", self.folder.display()))?
        };
        Ok((open_regular(&path)?.metadata()?.len(), false))
    }

    fn state(&self, offset: u64, staged: bool) -> HostedUpload {
        HostedUpload {
            import_id: self.id.to_hex(),
            source: self.source.source_id().to_owned(),
            declared_bytes: self.declared,
            offset,
            staged,
        }
    }
}

/// What a running server drains: the staged imports of its vault.
pub(crate) struct HostedImports {
    vault_path: PathBuf,
    /// Asked before each unit of writes (a job's first conversation with
    /// its decode, each later conversation, the rows and removals of the
    /// staging folder); `None` writes nothing more this pass.
    admission: HousekeepingAdmission,
    /// The most entries a staged export's archive may declare: the host's
    /// `[import] archive_max_entries` (ARCH-0027 #archive-precheck).
    archive_entry_cap: u64,
}

impl HostedImports {
    pub(crate) fn new(vault_path: PathBuf, admission: HousekeepingAdmission) -> Self {
        Self {
            vault_path,
            admission,
            archive_entry_cap: ImportConfig::default().archive_entry_cap(),
        }
    }

    /// Reads staged exports under the host's `[import]` entry cap, so the
    /// owner lifts it for a hosted import as for `oneiron import`.
    pub(crate) fn with_archive_entry_cap(mut self, archive_entry_cap: u64) -> Self {
        self.archive_entry_cap = archive_entry_cap;
        self
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
        if root_exists && !self.adopt(vault, &root)? {
            return Ok(());
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
    /// its budget is spent or the host admits no more. A job asked to cancel
    /// lands nothing more: the row is read again before each conversation,
    /// so a cancel that comes during a pass stops it at the next one.
    fn run(
        &self,
        vault: &oneiron::Vault,
        root: &Path,
        id: HostedImportId,
        job: &HostedImportJob,
        budget: &mut Option<u64>,
    ) -> anyhow::Result<bool> {
        let folder = root.join(id.to_hex());
        // Held through every write of the job's first conversation, and of
        // its end when that comes in this pass; given back and asked again
        // between two conversations.
        let mut admitted = (self.admission)();
        if admitted.is_none() {
            return Ok(false);
        }
        let Some(source) = job.history_source() else {
            fail(
                vault,
                &folder,
                id,
                "the import's source is not one this build reads",
            )?;
            return Ok(true);
        };
        if job.state == HostedImportState::Cancelling {
            if let Some(conversation) =
                conversation_at_place(&folder, source, job, self.archive_entry_cap)
            {
                keep_resumed(vault, id, source, job, job.cursor, &conversation)?;
            }
            finish(
                vault,
                &folder,
                id,
                source,
                job,
                HostedImportState::Cancelled,
            )?;
            return Ok(true);
        }
        let Some(export) = staged_export(&folder, job.staged_bytes)? else {
            fail(vault, &folder, id, "the staged export is gone or changed")?;
            return Ok(true);
        };
        let (archive_skips, mut conversations) = match decode(
            source,
            &export,
            &ExportBounds::staged(self.archive_entry_cap),
        ) {
            Ok((files, conversations)) => (files.archive_skips, conversations),
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
        vault.hosted_import_decoded(
            id,
            u64::try_from(conversations.len())?,
            messages,
            &archive_skips[..0],
        )?;
        let owner = crate::owner::local_owner(vault)?;
        let mut cursor = job.cursor;
        for (landed_here, conversation) in conversations
            .iter()
            .skip(usize::try_from(cursor).unwrap_or(usize::MAX))
            .enumerate()
        {
            if *budget == Some(0) {
                return Ok(false);
            }
            if landed_here > 0 {
                drop(admitted.take());
                admitted = (self.admission)();
                if admitted.is_none() {
                    return Ok(false);
                }
            }
            if vault
                .hosted_import(id)?
                .is_some_and(|row| row.state == HostedImportState::Cancelling)
            {
                if landed_here == 0 {
                    keep_resumed(vault, id, source, job, cursor, conversation)?;
                }
                finish(
                    vault,
                    &folder,
                    id,
                    source,
                    job,
                    HostedImportState::Cancelled,
                )?;
                return Ok(true);
            }
            // The conversation at the job's place may hold what a process
            // that stopped part way landed of it.
            let resumed = if landed_here == 0 {
                Some(vault.hosted_import_resumed(source, conversation, job.imported_at)?)
            } else {
                None
            };
            let mut report = vault
                .import_history(&owner, source, conversation, job.imported_at)
                .map_err(|error| anyhow::anyhow!("import stopped: {error}"))?;
            if let Some(resumed) = resumed {
                resumed.fold_into(&mut report);
            }
            cursor += 1;
            vault.hosted_import_landed(id, cursor, &report)?;
            if let Some(left) = budget.as_mut() {
                *left -= 1;
            }
        }
        // A cancel asked while the last conversation landed finds nothing
        // left to stop: the job ends Landed, under the last guard.
        finish(vault, &folder, id, source, job, HostedImportState::Landed)?;
        drop(admitted);
        Ok(true)
    }

    /// Makes the row of each whole folder under `root` that has none, each
    /// at a second of its own, and removes what is left of a deleted
    /// upload's folder and the folder of an ended job. `false` when there
    /// is such work and the host admits none.
    fn adopt(&self, vault: &oneiron::Vault, root: &Path) -> anyhow::Result<bool> {
        let mut whole = Vec::new();
        let mut removals = Vec::new();
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name
                .strip_suffix(DELETED_SUFFIX)
                .and_then(HostedImportId::parse)
                .is_some()
            {
                // A deleted upload's folder, renamed away, that a process
                // which stopped before removing it left.
                removals.push(entry.path());
                continue;
            }
            let Some(id) = HostedImportId::parse(name) else {
                continue;
            };
            if !entry.file_type()?.is_dir() {
                continue;
            }
            if let Some(job) = vault.hosted_import(id)? {
                // An ended job's folder that outlived its end, as a process
                // that stopped between the two, or a removal that failed,
                // leaves it.
                if job.ended() {
                    removals.push(entry.path());
                }
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
        if whole.is_empty() && removals.is_empty() {
            return Ok(true);
        }
        let Some(_admitted) = (self.admission)() else {
            return Ok(false);
        };
        for folder in &removals {
            remove_folder(folder);
        }
        if whole.is_empty() {
            return Ok(true);
        }
        let owner = crate::owner::local_owner(vault)?;
        for (id, source, staged) in whole {
            vault.hosted_import_create(&owner, id, source, staged, own_second(vault)?)?;
            tracing::info!(import = %id.to_hex(), source = source.source_id(), "hosted import staged");
        }
        Ok(true)
    }
}

/// Ends a job that lands nothing more as `state`, Landed or Cancelled. What
/// landed is surfaced in the import's one review: one inbox row for the
/// import, never one per conversation, when anything landed new or changed,
/// and the Dreamer queued. Then the job ends and its folder is removed.
/// The caller holds the host's admission through all of it.
fn finish(
    vault: &oneiron::Vault,
    folder: &Path,
    id: HostedImportId,
    source: HistorySource,
    job: &HostedImportJob,
    state: HostedImportState,
) -> anyhow::Result<()> {
    let landed = vault.hosted_import(id)?;
    if landed
        .as_ref()
        .is_some_and(|landed| landed.new + landed.changed > 0)
    {
        vault.record_history_import_finished(source, job.imported_at)?;
    }
    let queued = queue_dreamer(vault, job.imported_at)?;
    let cancelled = state == HostedImportState::Cancelled;
    vault.hosted_import_end(id, state, u64::try_from(queued)?)?;
    remove_folder(folder);
    let review = oneiron::ingest::history::history_import_review_id(source, job.imported_at);
    if cancelled {
        tracing::info!(
            import = %id.to_hex(),
            review = %review,
            "hosted import cancelled; what landed waits for the owner in this review"
        );
    } else {
        tracing::info!(
            import = %id.to_hex(),
            review = %review,
            "hosted import landed; its claims wait for the owner in this review"
        );
    }
    Ok(())
}

/// The conversation at a job's place, earliest first, read from its staged
/// export. `None` when the job is past its last conversation, or its export
/// is gone, changed, unreadable or does not decode: what a stopped landing
/// left of it is then not read.
fn conversation_at_place(
    folder: &Path,
    source: HistorySource,
    job: &HostedImportJob,
    archive_entry_cap: u64,
) -> Option<HistoryConversation> {
    let export = staged_export(folder, job.staged_bytes).ok().flatten()?;
    let (_, mut conversations) =
        decode(source, &export, &ExportBounds::staged(archive_entry_cap)).ok()?;
    earliest_first(&mut conversations);
    conversations
        .into_iter()
        .nth(usize::try_from(job.cursor).ok()?)
}

/// Keeps on a job asked to cancel what a process that stopped after the
/// landing of `conversation`, at the job's place `cursor`, committed, and
/// before that place was kept, landed of it: its messages count as they
/// landed, its TURNs are the job's, and the place moves past it, as the
/// record of that landing would have done. Lands nothing. The caller holds
/// the host's admission.
fn keep_resumed(
    vault: &oneiron::Vault,
    id: HostedImportId,
    source: HistorySource,
    job: &HostedImportJob,
    cursor: u64,
    conversation: &HistoryConversation,
) -> anyhow::Result<()> {
    let resumed = vault.hosted_import_resumed(source, conversation, job.imported_at)?;
    if resumed.new + resumed.changed > 0 {
        vault.hosted_import_landed(id, cursor + 1, &resumed.report(conversation))?;
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
    let Some(path) = named_export(folder)? else {
        return Ok(None);
    };
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    Ok((metadata.is_file() && metadata.len() == bytes).then_some(path))
}

/// Door for `tests/hosted_import_job.rs`: lands conversation `index`
/// (earliest first) of hosted import `id` into its review and keeps no
/// place, as a process that stops after that landing commits and before the
/// job's place is kept leaves it. Compiled only under
/// `--cfg oneiron_test_support`; never API.
#[cfg(oneiron_test_support)]
pub(crate) fn land_unplaced(
    vault: &oneiron::Vault,
    vault_path: &Path,
    id: HostedImportId,
    index: usize,
) -> anyhow::Result<()> {
    let job = vault
        .hosted_import(id)?
        .ok_or_else(|| anyhow::anyhow!("no hosted import {}", id.to_hex()))?;
    let source = job
        .history_source()
        .ok_or_else(|| anyhow::anyhow!("the import's source is not one this build reads"))?;
    let folder = imports_root(vault_path).join(id.to_hex());
    let export = staged_export(&folder, job.staged_bytes)?
        .ok_or_else(|| anyhow::anyhow!("the staged export is gone or changed"))?;
    let bounds = ExportBounds::staged(ImportConfig::default().archive_entry_cap());
    let (_, mut conversations) = decode(source, &export, &bounds)?;
    earliest_first(&mut conversations);
    let conversation = conversations
        .get(index)
        .ok_or_else(|| anyhow::anyhow!("the export has no conversation {index}"))?;
    let owner = crate::owner::local_owner(vault)?;
    vault
        .import_history(&owner, source, conversation, job.imported_at)
        .map_err(|error| anyhow::anyhow!("import stopped: {error}"))?;
    Ok(())
}

/// Ends a job Failed with `reason` and removes its folder, under the
/// caller's admission.
fn fail(
    vault: &oneiron::Vault,
    folder: &Path,
    id: HostedImportId,
    reason: &str,
) -> anyhow::Result<()> {
    vault.hosted_import_end(id, HostedImportState::Failed(reason.to_owned()), 0)?;
    remove_folder(folder);
    tracing::warn!(import = %id.to_hex(), reason, "hosted import failed");
    Ok(())
}

/// Removes an ended job's folder, or a deleted upload's; a failure is said,
/// the job stays ended, and a later pass removes the folder.
fn remove_folder(folder: &Path) {
    match fs::remove_dir_all(folder) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(folder = %folder.display(), error = %error, "hosted import folder not removed");
        }
    }
}
