//! Placing a manifest's files on this machine, verifying an operator's
//! directory, and reading what is on disk.
//!
//! Blocking throughout, like the embedder's model manager: a caller on an
//! async runtime runs these on a blocking thread.
//!
//! The layout under the artifacts root ([`artifacts_root`], the embedder's
//! models root plus `artifacts/`):
//!
//! - `<id>/<revision>/`: an installed model, every pinned file plus
//!   [`RECORD_FILE`], renamed into place whole;
//! - `<id>/.staging-<revision>/`: an install in progress, each file fetched
//!   to `<path>.partial` and renamed to `<path>` once it checks;
//! - `<id>/.staging-<revision>.lock`: held by the install in progress.
//!
//! A crash at any point leaves no `<revision>/` directory, or a complete one
//! whose every file was verified and synced before the rename.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

use reqwest::header::HeaderValue;
use serde::{Deserialize, Serialize};

use super::ArtifactError;
use super::licence::admit_download;
use super::manifest::{ArtifactFile, ArtifactManifest, PARTIAL_SUFFIX, RECORD_FILE};
use crate::embedder::model_manager::{self, PinnedArtifact, ResumableFetch};

/// The directory under the models root the artifacts live in, beside the
/// embedder's `<org>/<name>/<revision>/` trees.
const ARTIFACTS_DIR: &str = "artifacts";

/// Names this fetch in a transfer failure.
const FETCH_TOOL: &str = "model-artifact-download";

/// An installed directory's mode: the shared models root admits no group-
/// or other-writable path, and a worker's user must enter it.
#[cfg(unix)]
const DIR_MODE: u32 = 0o755;

/// An installed file's mode: read by every worker's user, written by none.
#[cfg(unix)]
const FILE_MODE: u32 = 0o644;

/// `<models root>/artifacts`, the models root resolved as the embedder's is:
/// `models_dir` when set, else `$XDG_DATA_HOME/oneiron/models`, else
/// `$HOME/.local/share/oneiron/models`. No new setting: a host that moved
/// the embedder's root moves this one by passing the same override.
pub(crate) fn artifacts_root(models_dir: Option<&Path>) -> oneiron::Result<PathBuf> {
    let root = model_manager::resolve_models_root(
        models_dir,
        model_manager::absolute_env_dir("XDG_DATA_HOME"),
        model_manager::absolute_env_dir("HOME"),
    )?;
    Ok(root.join(ARTIFACTS_DIR))
}

/// A Hugging Face read token, held as the `Authorization` value it is sent
/// as, to the hub's origin alone. Its `Debug` shows nothing of it, and no
/// error or log here carries it.
pub(crate) struct HubToken(HeaderValue);

impl std::fmt::Debug for HubToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HubToken(<redacted>)")
    }
}

impl HubToken {
    /// A bearer token, surrounding whitespace dropped. `None` when nothing
    /// is left or it holds characters a header cannot carry.
    pub(crate) fn bearer(token: &str) -> Option<Self> {
        let token = token.trim();
        if token.is_empty() {
            return None;
        }
        let mut value = HeaderValue::from_str(&format!("Bearer {token}")).ok()?;
        value.set_sensitive(true);
        Some(Self(value))
    }
}

/// A model whose every pinned file is present and verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Installed {
    pub(crate) dir: PathBuf,
    /// The manifest's digest ([`ArtifactManifest::digest`]).
    pub(crate) manifest_digest: String,
    pub(crate) total_bytes: u64,
    /// Bytes this call moved over the network; 0 when every file was there.
    pub(crate) fetched_bytes: u64,
}

/// What is on disk for a manifest, read without the network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ArtifactState {
    /// Nothing installed or staged.
    Absent,
    /// An install stopped part-way; `bytes_present` of the pinned files'
    /// bytes are staged or in partials, for the next install to keep.
    Partial { bytes_present: u64 },
    /// Installed: the record is this manifest's and every file is there at
    /// its pinned size.
    Installed {
        dir: PathBuf,
        manifest_digest: String,
        total_bytes: u64,
    },
    /// Installed, but this file is missing or not its pinned size, or the
    /// record is not this manifest's ([`RECORD_FILE`]).
    Corrupt { file: String },
}

/// The installed directory's record, written last.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledRecord {
    manifest_sha256: String,
    manifest: ArtifactManifest,
}

/// What a file looked like when it was verified: size and modification
/// time, enough to notice it being replaced and cheap to read on every
/// start, which hashing 15 GB is not. The embedder's `FileStamp`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Stamp {
    bytes: u64,
    modified: Option<SystemTime>,
}

impl Stamp {
    fn read(path: &Path) -> std::io::Result<Self> {
        let metadata = std::fs::metadata(path)?;
        Ok(Self {
            bytes: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }
}

/// A file this process verified: its stamp then, and the digest it matched.
struct Verified {
    stamp: Stamp,
    sha256: String,
}

/// The artifacts under one root, and what this process has verified there.
///
/// The verified files live on the store, never in a process static: the
/// supervisor that owns the store owns the answers. A file whose stamp has
/// not changed since it matched the same digest is not hashed again; any
/// change hashes it again.
pub(crate) struct ArtifactStore {
    root: PathBuf,
    verified: Mutex<HashMap<PathBuf, Verified>>,
}

impl ArtifactStore {
    /// A store over `root`, the artifacts root ([`artifacts_root`] by
    /// default). Nothing is read or created until an install.
    pub(crate) fn new(root: PathBuf) -> Self {
        Self {
            root,
            verified: Mutex::new(HashMap::new()),
        }
    }

    /// `<root>/<id>/<revision>/`, where the manifest installs.
    pub(crate) fn install_dir(
        &self,
        manifest: &ArtifactManifest,
    ) -> Result<PathBuf, ArtifactError> {
        manifest.validate()?;
        Ok(self.final_dir(manifest))
    }

    /// Makes every pinned file present and verified under
    /// `<root>/<id>/<revision>/`, fetching from the Hugging Face hub what is
    /// not there.
    ///
    /// The manifest is checked and its licence admitted before any byte is
    /// fetched. An installed directory is reused once its record and files
    /// check, and is never removed or repaired here. Otherwise each file is
    /// fetched to its partial in the staging directory, resuming what an
    /// earlier run left; checked for exact size, then SHA-256; synced; and
    /// renamed to its own name. The record goes in last, the staging
    /// directory is synced and renamed into place whole, and its parent is
    /// synced. A second install of the same manifest waits on the lock, then
    /// finds it installed.
    ///
    /// No deadline bounds a transfer: a request the client's own timeout
    /// ends only paces, and the next request resumes from the partial. A
    /// request that adds no byte stops the install, the partial kept.
    pub(crate) fn install(
        &self,
        manifest: &ArtifactManifest,
        token: Option<&HubToken>,
    ) -> Result<Installed, ArtifactError> {
        manifest.validate()?;
        admit_download(manifest)?;
        let dir = self.final_dir(manifest);
        if dir.symlink_metadata().is_ok() {
            return self.reuse(manifest, &dir);
        }
        let parent = self.root.join(&*manifest.id);
        if let Some(models_root) = self.root.parent() {
            let created = std::fs::create_dir_all(models_root);
            created.map_err(io_error(manifest, "creating", models_root))?;
        }
        ensure_dir(manifest, &self.root)?;
        ensure_dir(manifest, &parent)?;
        let revision: &str = &manifest.revision;
        let _lock = lock(manifest, &parent.join(format!(".staging-{revision}.lock")))?;
        // An install that held the lock first may have placed it meanwhile.
        if dir.symlink_metadata().is_ok() {
            return self.reuse(manifest, &dir);
        }
        let staging = self.staging_dir(manifest);
        ensure_dir(manifest, &staging)?;
        prune(manifest, &staging, Path::new(""))?;
        let mut fetched_bytes = 0_u64;
        let mut stamps = Vec::with_capacity(manifest.files.len());
        for file in &*manifest.files {
            let (fetched, stamp) = stage(manifest, &staging, file, token)?;
            fetched_bytes += fetched;
            stamps.push((file, stamp));
        }
        let manifest_digest = commit(manifest, &staging, &dir)?;
        for (file, stamp) in stamps {
            self.remember(dir.join(&*file.path), file, stamp);
        }
        tracing::info!(
            model = %manifest.id,
            dir = %dir.display(),
            fetched_bytes,
            "model artifact installed"
        );
        Ok(Installed {
            dir,
            manifest_digest,
            total_bytes: manifest.total_bytes(),
            fetched_bytes,
        })
    }

    /// Verifies an operator's directory against the manifest: every pinned
    /// file present at its exact size and SHA-256. No network, no copy and
    /// no record; nothing in `dir` is written. The licence policy gates
    /// downloads and is not applied here.
    pub(crate) fn verify_dir(
        &self,
        manifest: &ArtifactManifest,
        dir: &Path,
    ) -> Result<Installed, ArtifactError> {
        manifest.validate()?;
        for file in &*manifest.files {
            let path = dir.join(&*file.path);
            if !path.is_file() {
                return Err(ArtifactError::Missing {
                    model: manifest.id.to_string(),
                    file: file.path.to_string(),
                    dir: dir.display().to_string(),
                });
            }
            self.verify_unless_unchanged(manifest, &path, file)?;
        }
        Ok(Installed {
            dir: dir.to_path_buf(),
            manifest_digest: manifest.digest()?,
            total_bytes: manifest.total_bytes(),
            fetched_bytes: 0,
        })
    }

    /// What is on disk for the manifest, without the network and without
    /// hashing: a status row must not read 15 GB. An installed directory is
    /// [`ArtifactState::Installed`] when its record is this manifest's and
    /// every file is its pinned size; a same-size change shows at the next
    /// install, which hashes any file whose stamp moved.
    pub(crate) fn inspect(
        &self,
        manifest: &ArtifactManifest,
    ) -> Result<ArtifactState, ArtifactError> {
        manifest.validate()?;
        let dir = self.final_dir(manifest);
        if dir.symlink_metadata().is_ok() {
            if record_mismatch(manifest, &dir).is_some() {
                return Ok(ArtifactState::Corrupt {
                    file: RECORD_FILE.to_owned(),
                });
            }
            for file in &*manifest.files {
                let held = std::fs::metadata(dir.join(&*file.path));
                if !held.is_ok_and(|metadata| metadata.is_file() && metadata.len() == file.bytes) {
                    return Ok(ArtifactState::Corrupt {
                        file: file.path.to_string(),
                    });
                }
            }
            return Ok(ArtifactState::Installed {
                dir,
                manifest_digest: manifest.digest()?,
                total_bytes: manifest.total_bytes(),
            });
        }
        let staging = self.staging_dir(manifest);
        let bytes_present: u64 = manifest
            .files
            .iter()
            .map(|file| {
                let staged = staging.join(&*file.path);
                let len =
                    |path: &Path| std::fs::metadata(path).map_or(0, |metadata| metadata.len());
                len(&staged)
                    .max(len(&partial_path(&staged)))
                    .min(file.bytes)
            })
            .sum();
        Ok(if bytes_present == 0 {
            ArtifactState::Absent
        } else {
            ArtifactState::Partial { bytes_present }
        })
    }

    fn final_dir(&self, manifest: &ArtifactManifest) -> PathBuf {
        self.root.join(&*manifest.id).join(&*manifest.revision)
    }

    fn staging_dir(&self, manifest: &ArtifactManifest) -> PathBuf {
        let revision: &str = &manifest.revision;
        self.root
            .join(&*manifest.id)
            .join(format!(".staging-{revision}"))
    }

    /// An installed directory: its record must be this manifest's, and
    /// each file must check.
    fn reuse(&self, manifest: &ArtifactManifest, dir: &Path) -> Result<Installed, ArtifactError> {
        let installed_mismatch = |reason: String| ArtifactError::InstalledMismatch {
            model: manifest.id.to_string(),
            dir: dir.display().to_string(),
            reason,
        };
        if let Some(reason) = record_mismatch(manifest, dir) {
            return Err(installed_mismatch(reason));
        }
        for file in &*manifest.files {
            let path = dir.join(&*file.path);
            if !path.is_file() {
                return Err(installed_mismatch(format!("{} is missing", file.path)));
            }
            if let Err(error) = self.verify_unless_unchanged(manifest, &path, file) {
                return Err(installed_mismatch(error.to_string()));
            }
        }
        Ok(Installed {
            dir: dir.to_path_buf(),
            manifest_digest: manifest.digest()?,
            total_bytes: manifest.total_bytes(),
            fetched_bytes: 0,
        })
    }

    /// Verifies a file, unless this process verified it against the same
    /// digest and its stamp has not changed since.
    fn verify_unless_unchanged(
        &self,
        manifest: &ArtifactManifest,
        path: &Path,
        file: &ArtifactFile,
    ) -> Result<(), ArtifactError> {
        let stamp = Stamp::read(path).map_err(io_error(manifest, "reading", path))?;
        let unchanged = self
            .verified
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(path)
            .is_some_and(|seen| seen.stamp == stamp && seen.sha256 == file.sha256);
        if unchanged {
            return Ok(());
        }
        check(manifest, path, file)?;
        self.remember(path.to_path_buf(), file, stamp);
        Ok(())
    }

    fn remember(&self, path: PathBuf, file: &ArtifactFile, stamp: Stamp) {
        let verified = Verified {
            stamp,
            sha256: file.sha256.to_string(),
        };
        self.verified
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(path, verified);
    }
}

/// Why the installed record is not this manifest's, or `None` when it is.
fn record_mismatch(manifest: &ArtifactManifest, dir: &Path) -> Option<String> {
    let Ok(raw) = std::fs::read(dir.join(RECORD_FILE)) else {
        return Some(format!("{RECORD_FILE} is unreadable"));
    };
    let Ok(record) = serde_json::from_slice::<InstalledRecord>(&raw) else {
        return Some(format!("{RECORD_FILE} is not a record"));
    };
    let Ok(digest) = manifest.digest() else {
        return Some("the manifest does not serialize".to_owned());
    };
    if record.manifest_sha256 != digest || record.manifest != *manifest {
        return Some(format!(
            "{RECORD_FILE} records manifest {}, not {digest}",
            record.manifest_sha256
        ));
    }
    None
}

/// Removes what the staging directory holds beyond the pinned files and
/// their partials, walking down from `relative`. An earlier install of
/// another manifest at this id and revision may have left some, and a
/// loader that globs its directory (exllamav3 reads every `*.safetensors`)
/// must find only the pinned files once it is placed.
fn prune(
    manifest: &ArtifactManifest,
    staging: &Path,
    relative: &Path,
) -> Result<(), ArtifactError> {
    let pinned: Vec<&Path> = manifest
        .files
        .iter()
        .map(|file| Path::new(&*file.path))
        .collect();
    let here = staging.join(relative);
    let entries = std::fs::read_dir(&here).map_err(io_error(manifest, "listing", &here))?;
    for entry in entries {
        let entry = entry.map_err(io_error(manifest, "listing", &here))?;
        let name = relative.join(entry.file_name());
        let path = entry.path();
        let is_dir = entry.file_type().is_ok_and(|kind| kind.is_dir());
        if is_dir
            && pinned
                .iter()
                .any(|file| *file != name && file.starts_with(&name))
        {
            prune(manifest, staging, &name)?;
            continue;
        }
        let kept = !is_dir
            && pinned
                .iter()
                .any(|file| *file == name || partial_path(file) == name);
        if kept {
            continue;
        }
        let removed = if is_dir {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        removed.map_err(io_error(manifest, "removing", &path))?;
    }
    Ok(())
}

/// Makes `<staging>/<path>` the pinned file: kept when an earlier run staged
/// it and it still checks, else fetched to its partial, checked there,
/// synced and renamed. Returns the bytes fetched, and the file's stamp.
fn stage(
    manifest: &ArtifactManifest,
    staging: &Path,
    file: &ArtifactFile,
    token: Option<&HubToken>,
) -> Result<(u64, Stamp), ArtifactError> {
    let staged = staging.join(&*file.path);
    if staged.is_file() {
        if check(manifest, &staged, file).is_ok() {
            let stamp = Stamp::read(&staged).map_err(io_error(manifest, "reading", &staged))?;
            return Ok((0, stamp));
        }
        // Only a checked file is ever renamed to this name; one that no
        // longer checks is this staging's own to drop.
        std::fs::remove_file(&staged).map_err(io_error(manifest, "removing", &staged))?;
    }
    ensure_parents(manifest, staging, file)?;
    let partial = partial_path(&staged);
    let fetched = fetch(manifest, &partial, file, token)?;
    if let Err(error) = check(manifest, &partial, file) {
        // Resuming bytes that are not the pinned file would only fail again.
        let _ = std::fs::remove_file(&partial);
        return Err(error);
    }
    sync_file(manifest, &partial)?;
    let stamp = Stamp::read(&partial).map_err(io_error(manifest, "reading", &partial))?;
    std::fs::rename(&partial, &staged).map_err(io_error(manifest, "staging", &partial))?;
    Ok((fetched, stamp))
}

/// Fetches one file into `partial` until it holds the pinned size, through
/// the embedder's resumable fetch. Each request that adds bytes is followed
/// by another from where it stopped, however it ended; one that adds none
/// stops the fetch with the partial kept. Returns the bytes fetched.
fn fetch(
    manifest: &ArtifactManifest,
    partial: &Path,
    file: &ArtifactFile,
    token: Option<&HubToken>,
) -> Result<u64, ArtifactError> {
    let url = model_manager::hub_url(&manifest.repo, &manifest.revision, &file.path);
    // The resumable fetch reads the path and the size; the digest is checked
    // here, on the whole file.
    let pin = PinnedArtifact {
        file: file.path.clone(),
        sha256: model_manager::UNPINNED,
        bytes: file.bytes,
    };
    let authorization = token.map(|token| &token.0);
    let held = |path: &Path| std::fs::metadata(path).map_or(0, |metadata| metadata.len());
    let refused = |reason: String| ArtifactError::Transfer {
        model: manifest.id.to_string(),
        file: file.path.to_string(),
        reason,
    };
    let mut fetched_total = 0_u64;
    loop {
        let before = held(partial);
        let answer = model_manager::fetch_resumable(&url, partial, &pin, authorization, FETCH_TOOL);
        let after = held(partial);
        match answer {
            Ok(ResumableFetch::Written { fetched, .. }) => {
                fetched_total += fetched;
                if after >= file.bytes {
                    return Ok(fetched_total);
                }
                // A source that answers short again and again, or restarts
                // the file each time, never grows the partial.
                if after <= before {
                    return Err(refused(format!(
                        "the source stopped at {after} of {} bytes",
                        file.bytes
                    )));
                }
            }
            Ok(ResumableFetch::NotFound) => {
                return Err(ArtifactError::NotFound {
                    model: manifest.id.to_string(),
                    file: file.path.to_string(),
                });
            }
            Ok(ResumableFetch::Unauthorized) => {
                return Err(ArtifactError::Unauthorized {
                    model: manifest.id.to_string(),
                    file: file.path.to_string(),
                });
            }
            Ok(ResumableFetch::WrongSize { offered }) => {
                let _ = std::fs::remove_file(partial);
                let offered = offered.map_or_else(
                    || "nothing past the partial".to_owned(),
                    |offered| format!("{offered} bytes"),
                );
                return Err(ArtifactError::Mismatch {
                    model: manifest.id.to_string(),
                    file: file.path.to_string(),
                    reason: format!(
                        "the source offers {offered}, pinned {}; partial removed",
                        file.bytes
                    ),
                });
            }
            Err(error) if after > before => {
                fetched_total += after - before;
                tracing::info!(
                    model = %manifest.id,
                    file = %file.path,
                    held = after,
                    pinned = file.bytes,
                    %error,
                    "model artifact transfer interrupted; resuming from the partial"
                );
            }
            Err(error) => return Err(refused(error.to_string())),
        }
    }
}

/// Writes the record, sets the modes, syncs every staged directory, then
/// renames the staging directory into place whole and syncs its parent.
/// Returns the manifest's digest.
fn commit(
    manifest: &ArtifactManifest,
    staging: &Path,
    dir: &Path,
) -> Result<String, ArtifactError> {
    let manifest_digest = manifest.digest()?;
    let record = InstalledRecord {
        manifest_sha256: manifest_digest.clone(),
        manifest: manifest.clone(),
    };
    let bytes = serde_json::to_vec_pretty(&record).map_err(|error| ArtifactError::Invalid {
        model: manifest.id.to_string(),
        reason: format!("its record does not serialize: {error}"),
    })?;
    let record_path = staging.join(RECORD_FILE);
    let mut written = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&record_path)
        .map_err(io_error(manifest, "creating", &record_path))?;
    written
        .write_all(&bytes)
        .and_then(|()| written.sync_all())
        .map_err(io_error(manifest, "writing", &record_path))?;
    drop(written);
    #[cfg(unix)]
    {
        for file in &*manifest.files {
            set_mode(manifest, &staging.join(&*file.path), FILE_MODE)?;
        }
        set_mode(manifest, &record_path, FILE_MODE)?;
        set_mode(manifest, staging, DIR_MODE)?;
    }
    // Each nested directory once, deepest first, so a directory's entries are
    // durable before the directory that names it.
    let mut dirs: Vec<PathBuf> = Vec::new();
    for file in &*manifest.files {
        for ancestor in Path::new(&*file.path).ancestors().skip(1) {
            if !ancestor.as_os_str().is_empty() {
                dirs.push(staging.join(ancestor));
            }
        }
    }
    dirs.sort();
    dirs.dedup();
    dirs.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for staged_dir in &dirs {
        sync_dir(manifest, staged_dir)?;
    }
    sync_dir(manifest, staging)?;
    std::fs::rename(staging, dir).map_err(io_error(manifest, "placing", staging))?;
    if let Some(parent) = dir.parent() {
        sync_dir(manifest, parent)?;
    }
    Ok(manifest_digest)
}

/// `<path>.partial`: where a file's fetch writes until it checks.
fn partial_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(PARTIAL_SUFFIX);
    PathBuf::from(name)
}

/// Size first, then SHA-256, against the pin.
fn check(
    manifest: &ArtifactManifest,
    path: &Path,
    file: &ArtifactFile,
) -> Result<(), ArtifactError> {
    let mismatch = |reason: String| ArtifactError::Mismatch {
        model: manifest.id.to_string(),
        file: file.path.to_string(),
        reason,
    };
    let held = std::fs::metadata(path)
        .map_err(io_error(manifest, "reading", path))?
        .len();
    if held != file.bytes {
        return Err(mismatch(format!("{held} bytes, pinned {}", file.bytes)));
    }
    let digest = model_manager::sha256_file(path).map_err(io_error(manifest, "hashing", path))?;
    if digest != file.sha256 {
        return Err(mismatch(format!("sha256 {digest}, pinned {}", file.sha256)));
    }
    Ok(())
}

/// Creates the staging directories a nested file sits in.
fn ensure_parents(
    manifest: &ArtifactManifest,
    staging: &Path,
    file: &ArtifactFile,
) -> Result<(), ArtifactError> {
    let Some((parents, _)) = file.path.rsplit_once('/') else {
        return Ok(());
    };
    let mut dir = staging.to_path_buf();
    for segment in parents.split('/') {
        dir.push(segment);
        ensure_dir(manifest, &dir)?;
    }
    Ok(())
}

/// Creates one directory, `0755` on Unix, or takes the one already there.
fn ensure_dir(manifest: &ArtifactManifest, path: &Path) -> Result<(), ArtifactError> {
    if path.is_dir() {
        return Ok(());
    }
    if let Err(error) = std::fs::create_dir(path) {
        // Another install may have made it meanwhile.
        return if path.is_dir() {
            Ok(())
        } else {
            Err(io_error(manifest, "creating", path)(error))
        };
    }
    #[cfg(unix)]
    set_mode(manifest, path, DIR_MODE)?;
    Ok(())
}

/// Sets a mode whatever the umask made it.
#[cfg(unix)]
fn set_mode(manifest: &ArtifactManifest, path: &Path, mode: u32) -> Result<(), ArtifactError> {
    use std::os::unix::fs::PermissionsExt as _;
    let permissions = std::fs::Permissions::from_mode(mode);
    let set = std::fs::set_permissions(path, permissions);
    set.map_err(io_error(manifest, "setting the mode of", path))
}

fn sync_file(manifest: &ArtifactManifest, path: &Path) -> Result<(), ArtifactError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(io_error(manifest, "syncing", path))
}

/// Makes a directory's entries durable. Unix only: elsewhere a directory
/// does not open as a file, and the rename is what the platform offers.
fn sync_dir(manifest: &ArtifactManifest, path: &Path) -> Result<(), ArtifactError> {
    if cfg!(unix) {
        sync_file(manifest, path)
    } else {
        Ok(())
    }
}

/// Opens the staging lock and holds it until the returned file drops.
fn lock(manifest: &ArtifactManifest, path: &Path) -> Result<File, ArtifactError> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(io_error(manifest, "opening", path))?;
    file.lock().map_err(io_error(manifest, "locking", path))?;
    Ok(file)
}

fn io_error<E: std::fmt::Display>(
    manifest: &ArtifactManifest,
    action: &'static str,
    path: &Path,
) -> impl FnOnce(E) -> ArtifactError {
    let model = manifest.id.to_string();
    let path = path.display().to_string();
    move |error| ArtifactError::Io {
        model,
        action,
        path,
        reason: error.to_string(),
    }
}
