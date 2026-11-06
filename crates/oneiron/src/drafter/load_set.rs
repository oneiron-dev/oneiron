//! A drafter version's load set on disk (FIX 14976): its sealed files, and
//! the plaintext a serving host materialises from them.
//!
//! The sealed files of artifact `<id>` sit under the vault's
//! `drafter-artifacts/<id as 32 hex>/`, one per load-set file, under the
//! file's own name:
//!
//! ```text
//! sealed file   frame*                    every chunk of the file, in order
//! frame         u32be length ‖ envelope   one chunk, as DrafterSealing::seal_chunk seals it
//! ```
//!
//! Every chunk but the last holds [`SEALED_CHUNK_BYTES`] of the file; the
//! last holds the rest, 0 to [`SEALED_CHUNK_BYTES`]. A chunk's envelope binds
//! the version, the artifact, the file's name, the chunk's index and whether
//! it is the last, so a frame dropped, moved, reordered or appended does not
//! open. A reader checks the sealed length the record names before it opens
//! a frame, authenticates each chunk before it writes a byte of it, and
//! checks the file's length and BLAKE3 once every chunk is open.
//!
//! A serving host materialises a load set into a fresh directory under the
//! vault's `drafter-serving/`, named `<load set BLAKE3 as 64 hex>-<32 random
//! hex>`, readable by this user alone. The plaintext goes nowhere else: never
//! to the shared model-artifact install or its cache.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use super::{DrafterArtifactFile, DrafterSealing, hash_json, invalid};
use crate::Vault;
use crate::error::{Error, Result};

/// The plaintext each sealed chunk of a load-set file holds, all but the
/// last.
pub const SEALED_CHUNK_BYTES: usize = 64 * 1024;
/// The longest frame a reader takes: one chunk's envelope is the chunk and a
/// header far shorter than another chunk.
const MAX_FRAME_BYTES: usize = 2 * SEALED_CHUNK_BYTES;
/// The longest file name a load set holds: a file system's own name limit,
/// not a policy.
const MAX_FILE_NAME_BYTES: usize = 255;
/// The random part of a plaintext directory's name, in bytes.
const INCARNATION_BYTES: usize = 16;

fn corrupt() -> Error {
    Error::CorruptedIndex("drafter artifact file")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Whether `name` is one plain file name a load set may hold: ASCII letters,
/// digits, '.', '_' and '-', opening with a letter or a digit, at most
/// [`MAX_FILE_NAME_BYTES`] long. No path, no hidden file.
#[must_use]
pub fn drafter_file_name_is_plain(name: &str) -> bool {
    name.len() <= MAX_FILE_NAME_BYTES
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// The digest a load set's record names: BLAKE3 of the canonical JSON of
/// its files, as [`Vault::publish_drafter_artifact`] takes it.
///
/// # Errors
/// The files do not encode.
pub fn drafter_load_set_blake3(files: &[DrafterArtifactFile]) -> Result<[u8; 32]> {
    hash_json(&files)
}

/// Fills `buf` from `reader` until it is full or the reader ends; how many
/// bytes it holds.
fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

/// The next frame of a sealed file, `None` at its end.
fn read_frame(input: &mut impl Read) -> Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match read_full(input, &mut len)? {
        0 => return Ok(None),
        4 => {}
        _ => return Err(corrupt()),
    }
    let len = usize::try_from(u32::from_be_bytes(len)).map_err(|_| corrupt())?;
    if len > MAX_FRAME_BYTES {
        return Err(corrupt());
    }
    let mut frame = vec![0u8; len];
    if read_full(input, &mut frame)? != len {
        return Err(corrupt());
    }
    Ok(Some(frame))
}

/// A new directory, readable by this user alone.
fn private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// A new file, readable by this user alone; an existing one is refused.
fn private_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

/// `root`, made where it is missing and kept this user's alone.
fn private_root(root: &Path) -> std::io::Result<()> {
    fs::create_dir_all(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

impl DrafterSealing {
    /// Seals `plain`, the whole of load-set file `name`, chunk by chunk into a
    /// new file at `sealed`, synced before this returns, and returns the
    /// file's record: its length and BLAKE3, and its sealed length. An
    /// existing file at `sealed` is refused.
    ///
    /// # Errors
    /// A name that is not plain, the envelope refusing a chunk, and I/O
    /// faults.
    pub fn seal_file(
        &self,
        name: &str,
        plain: &mut impl Read,
        sealed: &Path,
    ) -> Result<DrafterArtifactFile> {
        if !drafter_file_name_is_plain(name) {
            return Err(invalid(
                "a drafter load-set file name is one plain name: letters, digits, '.', '_' and '-'",
            ));
        }
        let mut out = BufWriter::new(private_file(sealed)?);
        let mut hasher = blake3::Hasher::new();
        let mut chunk = vec![0u8; SEALED_CHUNK_BYTES];
        let (mut bytes, mut sealed_bytes, mut index) = (0u64, 0u64, 0u64);
        loop {
            let filled = read_full(plain, &mut chunk)?;
            let last = filled < SEALED_CHUNK_BYTES;
            let piece = &chunk[..filled];
            hasher.update(piece);
            bytes += filled as u64;
            let envelope = self.seal_chunk(name, index, last, piece)?;
            let len = u32::try_from(envelope.len())
                .map_err(|_| invalid("a sealed drafter chunk does not fit its frame"))?;
            out.write_all(&len.to_be_bytes())?;
            out.write_all(&envelope)?;
            sealed_bytes += 4 + envelope.len() as u64;
            if last {
                break;
            }
            index += 1;
        }
        let file = out
            .into_inner()
            .map_err(|error| Error::from(error.into_error()))?;
        file.sync_all()?;
        Ok(DrafterArtifactFile {
            name: name.to_owned(),
            bytes,
            blake3: *hasher.finalize().as_bytes(),
            sealed_bytes,
        })
    }

    /// Opens sealed load-set file `file` from `sealed_dir` and writes its
    /// plaintext into `out_dir`, readable by this user alone: its sealed
    /// length checked first, each chunk authenticated before a byte of it is
    /// written, its length and BLAKE3 checked last.
    fn open_file(
        &self,
        sealed_dir: &Path,
        file: &DrafterArtifactFile,
        out_dir: &Path,
    ) -> Result<()> {
        if !drafter_file_name_is_plain(&file.name) {
            return Err(corrupt());
        }
        let sealed = File::open(sealed_dir.join(&file.name))?;
        if sealed.metadata()?.len() != file.sealed_bytes {
            return Err(corrupt());
        }
        let mut input = BufReader::new(sealed);
        let mut out = BufWriter::new(private_file(&out_dir.join(&file.name))?);
        let mut hasher = blake3::Hasher::new();
        let mut bytes = 0u64;
        let mut frame = read_frame(&mut input)?.ok_or_else(corrupt)?;
        let mut index = 0u64;
        loop {
            let next = read_frame(&mut input)?;
            let plain = self.open_chunk(&file.name, index, next.is_none(), &frame)?;
            hasher.update(&plain);
            bytes += plain.len() as u64;
            out.write_all(&plain)?;
            let Some(following) = next else {
                break;
            };
            frame = following;
            index += 1;
        }
        let out = out
            .into_inner()
            .map_err(|error| Error::from(error.into_error()))?;
        out.sync_all()?;
        if bytes != file.bytes || hasher.finalize().as_bytes() != &file.blake3 {
            return Err(corrupt());
        }
        Ok(())
    }
}

impl Vault {
    /// Where the sealed files of artifact `artifact` sit, for the host that
    /// seals a trained load set ([`DrafterSealing::seal_file`]) and the
    /// serving host that opens it.
    #[must_use]
    pub fn drafter_artifact_files_dir(&self, artifact: &[u8; 16]) -> PathBuf {
        self.store.drafter_artifact_dir().join(hex(artifact))
    }

    /// A fresh plaintext directory's path for load set `load_set`, under
    /// `drafter-serving/`, which is made this user's alone; the directory
    /// itself is not made.
    ///
    /// # Errors
    /// The random source or the parent directory failed.
    pub fn new_drafter_serving_dir(&self, load_set: &[u8; 32]) -> Result<PathBuf> {
        let root = self.store.drafter_serving_dir();
        private_root(&root)?;
        let mut incarnation = [0u8; INCARNATION_BYTES];
        crate::key_material::os_fill(&mut incarnation)?;
        Ok(root.join(format!("{}-{}", hex(load_set), hex(&incarnation))))
    }

    /// A fresh plaintext directory's path under `drafter-evaluation/`, which
    /// is made this user's alone; the directory itself is not made. An
    /// evaluator's workers load from it (FIX 14975); a serving pass never
    /// removes it.
    ///
    /// # Errors
    /// The random source or the parent directory failed.
    pub fn new_drafter_evaluation_dir(&self) -> Result<PathBuf> {
        let root = self.store.drafter_evaluation_dir();
        private_root(&root)?;
        let mut incarnation = [0u8; INCARNATION_BYTES];
        crate::key_material::os_fill(&mut incarnation)?;
        Ok(root.join(hex(&incarnation)))
    }

    /// Removes every directory and file under `drafter-evaluation/`; returns
    /// how many went. An evaluation runs it when it starts and when it ends,
    /// and a vault lock before the key drops. One that does not go is left
    /// for the next, with a warning.
    pub fn remove_drafter_evaluation_plaintext(&self) -> usize {
        let Ok(entries) = fs::read_dir(self.store.drafter_evaluation_dir()) else {
            return 0;
        };
        let mut removed = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            let gone = if path.is_dir() {
                fs::remove_dir_all(&path)
            } else {
                fs::remove_file(&path)
            };
            match gone {
                Ok(()) => removed += 1,
                Err(error) => tracing::warn!(
                    %error,
                    "a drafter evaluation directory did not go; the next evaluation retries"
                ),
            }
        }
        removed
    }

    /// Opens the sealed files `files` of `sealing`'s artifact and writes their
    /// plaintext into the new directory `dir`, made this user's alone, each
    /// file checked as it is opened. On any failure `dir` is removed.
    pub(super) fn open_drafter_load_set(
        &self,
        sealing: &DrafterSealing,
        files: &[DrafterArtifactFile],
        dir: &Path,
    ) -> Result<()> {
        let sealed_dir = self.drafter_artifact_files_dir(&sealing.artifact());
        let mut names = BTreeSet::new();
        let opened = private_dir(dir).map_err(Error::from).and_then(|()| {
            for file in files {
                if !names.insert(file.name.as_str()) {
                    return Err(corrupt());
                }
                sealing.open_file(&sealed_dir, file, dir)?;
            }
            Ok(())
        });
        if opened.is_err() {
            let _ = fs::remove_dir_all(dir);
        }
        opened
    }

    /// Removes every directory and file under `drafter-serving/` but the
    /// directories `keep` names; returns how many went. One that does not go
    /// is left for the next pass, with a warning.
    pub fn remove_drafter_plaintext(&self, keep: &BTreeSet<PathBuf>) -> usize {
        let root = self.store.drafter_serving_dir();
        let Ok(entries) = fs::read_dir(&root) else {
            return 0;
        };
        let mut removed = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if keep.contains(&path) {
                continue;
            }
            let gone = if path.is_dir() {
                fs::remove_dir_all(&path)
            } else {
                fs::remove_file(&path)
            };
            match gone {
                Ok(()) => removed += 1,
                Err(error) => tracing::warn!(
                    %error,
                    "a drafter plaintext directory did not go; the next serving pass retries"
                ),
            }
        }
        removed
    }
}
