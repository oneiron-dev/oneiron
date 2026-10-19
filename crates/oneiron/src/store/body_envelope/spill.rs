//! Writing body files (FIX 5348, KS-2A): a body spilled as it streams as
//! one minted instance, sealed chunk by chunk under its key in a sealed
//! directory, and the copies a promotion or a restore makes of one.

use std::fs::File;
use std::io::{self, Read, Write};
use std::sync::Arc;

use heed::RwTxn;

use super::custody::BodyInstance;
use super::frames::{Domain, FileKey, FrameWriter, LineCounter, SealedStream, write_line_index};
use super::reader::BodyFile;
use super::rows::{BODY_KEYS, BodyKeyRow, body_key_row_in_txn};
use super::{DirSeal, KeyScope, sealed_body_file_name};
use crate::error::{Error, Result};
use crate::store::{BodyDir, LINE_INDEX_BLOCK_BYTES, LINE_INDEX_SUFFIX, Store, body_file_name};

/// A body file a writer staged, and the instance row the row or descriptor
/// naming its body commits with ([`super::bind_body_key_in_txn`]): a vault
/// instance's on either tier, or an off-record session's wrapped key.
pub(crate) struct StagedBodyKey {
    pub(super) digest: [u8; 32],
    pub(super) row: BodyKeyRow,
    scope: KeyScope,
    /// The opened key of a sealed file; `None` for a plain one.
    key: Option<Arc<FileKey>>,
}

impl StagedBodyKey {
    pub(crate) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(crate) const fn row(&self) -> &BodyKeyRow {
        &self.row
    }

    /// Whether `held`, the instance row a route already holds for this
    /// digest, is a committed pair in `dir`, where this file is: of this
    /// scope, its file there. Then it stays, and its file serves the body.
    ///
    /// # Errors
    ///
    /// A row that does not parse, and filesystem errors.
    pub(crate) fn keeps(&self, held: &BodyKeyRow, dir: &BodyDir) -> Result<bool> {
        let scoped = match &dir.sealed {
            Some(sealed) => sealed.scope == self.scope,
            None => self.scope == KeyScope::Vault,
        };
        Ok(scoped && dir.holds_pair(&self.digest, Some(held))?)
    }

    /// Writes `index`, the body's line index, beside its file in `dir`:
    /// sealed under the file's key, or plain beside a plain file. Derived: a
    /// failure leaves none, to be rebuilt.
    pub(crate) fn write_line_index(&self, dir: &BodyDir, index: &[u64]) {
        match &self.key {
            Some(key) => write_sealed_lines(dir, &self.digest, key, index),
            None => dir.write_line_index(&body_file_name(&self.digest), index),
        }
    }
}

fn write_sealed_lines(dir: &BodyDir, digest: &[u8; 32], key: &Arc<FileKey>, index: &[u64]) {
    let Ok((file, temp)) = dir.create_temp() else {
        return;
    };
    let name = format!(
        "{}{LINE_INDEX_SUFFIX}",
        sealed_body_file_name(digest, key.instance())
    );
    match write_line_index(file, Arc::clone(key), index) {
        Ok(file) => {
            let _ = dir.publish(file, &temp, &name);
        }
        Err(_) => dir.discard(&temp),
    }
}

/// One body spilling to a temp file in its directory: its bytes as they
/// come, or, in a sealed directory, sealed as they come under its
/// instance's key. The caller removes the temp file if it is dropped
/// unfinished.
pub(crate) struct BodySpill {
    temp: String,
    out: Out,
    /// The vault instance it is, `None` for an off-record session's file
    /// and for a temp that is never published.
    instance: Option<[u8; 16]>,
}

enum Out {
    Plain(File),
    Sealed {
        writer: Box<FrameWriter>,
        dir: DirSeal,
    },
}

impl BodySpill {
    /// A spill into `dir` that may be published: a vault directory's is
    /// `instance`, minted before the writer that names it opened; an
    /// off-record session's takes a fresh key of its own, `instance` unused.
    ///
    /// # Errors
    ///
    /// Filesystem errors, an off-record directory whose seal is not
    /// admitted, and a vault directory given no instance.
    pub(crate) fn create(dir: &BodyDir, instance: Option<BodyInstance>) -> Result<Self> {
        match (dir.session, instance) {
            (false, Some(instance)) => {
                let key = dir.sealed.as_ref().map(|_| Arc::clone(instance.key()));
                Self::open(dir, key, Some(*instance.instance()))
            }
            (true, None) => {
                let key = match &dir.sealed {
                    Some(sealed) => Some(Arc::new(FileKey::generate(sealed.seal()?.vault_id)?)),
                    None => None,
                };
                Self::open(dir, key, None)
            }
            _ => Err(Error::InvariantViolation(
                "a vault body file is one minted instance, a session's none",
            )),
        }
    }

    /// A spill into `dir` that is never published: a temp a stager reads
    /// back whole. A sealed directory's is sealed under a key held in
    /// memory only, which no row and no custody ever holds.
    ///
    /// # Errors
    ///
    /// Filesystem and sealing errors.
    pub(crate) fn ephemeral(dir: &BodyDir) -> Result<Self> {
        let key = match &dir.sealed {
            Some(_) => {
                let mut vault = [0u8; 32];
                crate::world_keys::os_fill(&mut vault)?;
                Some(Arc::new(FileKey::generate(vault)?))
            }
            None => None,
        };
        Self::open(dir, key, None)
    }

    fn open(dir: &BodyDir, key: Option<Arc<FileKey>>, instance: Option<[u8; 16]>) -> Result<Self> {
        let (file, temp) = dir.create_temp()?;
        let out = match (key, &dir.sealed) {
            (Some(key), Some(sealed)) => Out::Sealed {
                writer: Box::new(FrameWriter::new(file, key, Domain::Body)),
                dir: sealed.clone(),
            },
            _ => Out::Plain(file),
        };
        Ok(Self {
            temp,
            out,
            instance,
        })
    }

    /// The temp file's name in its directory.
    pub(crate) fn temp(&self) -> &str {
        &self.temp
    }

    pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match &mut self.out {
            Out::Plain(file) => Ok(file.write_all(bytes)?),
            Out::Sealed { writer, .. } => writer.write(bytes),
        }
    }

    /// Finishes the body `digest`, `len` bytes long: a sealed spill's last
    /// chunk and terminal record are sealed. Its instance row is staged: a
    /// vault instance's, or an off-record key wrapped for its session.
    /// Nothing is published yet.
    ///
    /// # Errors
    ///
    /// Filesystem and sealing errors, and a sealed spill that holds other
    /// bytes than `digest`.
    pub(crate) fn finish(self, digest: &[u8; 32], len: u64) -> Result<SpilledBody> {
        let (file, key) = match self.out {
            Out::Plain(file) => (file, None),
            Out::Sealed { writer, dir } => {
                let key = Arc::clone(writer.key());
                let (file, written, sealed) = writer.finish()?;
                if written != len || sealed != *digest {
                    return Err(Error::InvariantViolation(
                        "a sealed body file holds other bytes than its body",
                    ));
                }
                (file, Some((key, dir)))
            }
        };
        let staged = match (key, self.instance) {
            (Some((key, dir)), None) if dir.scope == KeyScope::OffRecord => Some(StagedBodyKey {
                digest: *digest,
                row: BodyKeyRow::off_record(dir.seal()?, &key, digest, len)?,
                scope: KeyScope::OffRecord,
                key: Some(key),
            }),
            (key, Some(instance)) => Some(StagedBodyKey {
                digest: *digest,
                row: BodyKeyRow::vault(instance, len, false),
                scope: KeyScope::Vault,
                key: key.map(|(key, _)| key),
            }),
            _ => None,
        };
        let sealed_key = staged.as_ref().and_then(|staged| staged.key.clone());
        Ok(SpilledBody {
            file,
            temp: self.temp,
            digest: *digest,
            len,
            sealed_key,
            key: staged,
        })
    }
}

/// A finished spill, not yet published.
pub(crate) struct SpilledBody {
    file: File,
    temp: String,
    digest: [u8; 32],
    len: u64,
    /// The key a sealed spill was sealed under, a temp's included.
    sealed_key: Option<Arc<FileKey>>,
    key: Option<StagedBodyKey>,
}

impl SpilledBody {
    /// The temp file's name in its directory, until it is published.
    pub(crate) fn temp(&self) -> &str {
        &self.temp
    }

    /// A reader over the finished body, from the temp file's descriptor: it
    /// reads on once the temp file is gone.
    ///
    /// # Errors
    ///
    /// Filesystem errors, and an envelope that does not check.
    pub(crate) fn reader(&self) -> Result<BodyFile> {
        let file = self.file.try_clone()?;
        match &self.sealed_key {
            None => Ok(BodyFile::plain(file, self.len)),
            Some(key) => BodyFile::sealed(file, Arc::clone(key), &self.digest, self.len),
        }
    }

    /// Publishes the body under its name in `dir`, the directory it spilled
    /// into: synced, renamed into place, the directory synced. A plain
    /// body's name is its digest, an envelope's `<digest>-<instance>`. Its
    /// staged instance row, `None` for an off-record session's plain body.
    ///
    /// # Errors
    ///
    /// Filesystem errors, and a temp spill, which is never published; the
    /// temp file is removed.
    pub(crate) fn publish(self, dir: &BodyDir) -> Result<Option<StagedBodyKey>> {
        let name = match (&self.key, &self.sealed_key) {
            (_, None) => body_file_name(&self.digest),
            (Some(staged), Some(_)) => sealed_body_file_name(&self.digest, &staged.row.instance),
            (None, Some(_)) => {
                dir.discard(&self.temp);
                return Err(Error::InvariantViolation(
                    "a temp body spill is never published",
                ));
            }
        };
        dir.publish(self.file, &self.temp, &name)?;
        Ok(self.key)
    }
}

/// Reads until `buffer` is full or `source` ends; returns how much it holds.
fn read_full(source: &mut impl Read, buffer: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match source.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(filled)
}

impl BodyDir {
    /// Copies in the sealed body `digest`, `len` bytes long, that `source`
    /// holds as an envelope under `key`, ciphertext as it is, under its own
    /// name: every envelope is authenticated as it passes, and the whole is
    /// checked against the body before it is published. With `lines`, its
    /// sealed line index is written beside it. A file of this instance this
    /// directory holds already stays as it is.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] for an envelope that does not check;
    /// filesystem errors. Nothing is left behind.
    pub(crate) fn import_sealed(
        &self,
        digest: &[u8; 32],
        len: u64,
        source: impl Read,
        key: Arc<FileKey>,
        lines: bool,
    ) -> Result<()> {
        let name = sealed_body_file_name(digest, key.instance());
        if self.open_named(&name)?.is_some() {
            return Ok(());
        }
        let (mut file, temp) = self.create_temp()?;
        let mut stream = SealedStream::ciphertext(source, Arc::clone(&key), *digest, len);
        if let Err(error) = io::copy(&mut stream, &mut file) {
            self.discard(&temp);
            return Err(error.into());
        }
        self.publish(file, &temp, &name)?;
        if lines {
            write_sealed_lines(self, digest, &key, stream.line_index());
        }
        Ok(())
    }

    /// Seals the plain body `digest`, `len` bytes long, that `source` holds
    /// into a new envelope of `instance` in this sealed vault directory,
    /// with its sealed line index when `lines`, and its staged instance row.
    ///
    /// # Errors
    ///
    /// Filesystem and sealing errors, and a source that holds other bytes.
    /// Nothing is left behind.
    pub(crate) fn import_sealing(
        &self,
        digest: &[u8; 32],
        len: u64,
        source: &mut impl Read,
        lines: bool,
        instance: BodyInstance,
    ) -> Result<StagedBodyKey> {
        let mut spill = BodySpill::create(self, Some(instance))?;
        let temp = spill.temp().to_owned();
        let mut counter = LineCounter::default();
        let mut frame = vec![0u8; LINE_INDEX_BLOCK_BYTES as usize];
        let spilled = loop {
            let filled = match read_full(source, &mut frame) {
                Ok(filled) => filled,
                Err(error) => break Err(error),
            };
            counter.chunk(&frame[..filled]);
            if let Err(error) = spill.write(&frame[..filled]) {
                break Err(error);
            }
            if filled < frame.len() {
                break spill.finish(digest, len);
            }
        };
        let staged = match spilled.and_then(|spilled| spilled.publish(self)) {
            Ok(Some(staged)) => staged,
            Ok(None) => {
                return Err(Error::InvariantViolation(
                    "a vault body file is one minted instance",
                ));
            }
            Err(error) => {
                self.discard(&temp);
                return Err(error);
            }
        };
        if lines {
            staged.write_line_index(self, counter.index());
        }
        Ok(staged)
    }

    /// Brings the result body `digest`, `len` bytes long, that `file` holds
    /// in an off-record session's directory into this vault directory as
    /// the vault instance `instance`: sealed again under its key in a sealed
    /// vault, plain in a plain one, checked against the body as it streams,
    /// its line index beside it. The session's key is never copied or
    /// wrapped again (KS-2A).
    ///
    /// # Errors
    ///
    /// As [`BodyDir::import`] and [`Self::import_sealing`].
    pub(crate) fn import_promoted(
        &self,
        digest: &[u8; 32],
        len: u64,
        mut file: BodyFile,
        instance: BodyInstance,
    ) -> Result<()> {
        if self.sealed.is_some() {
            self.import_sealing(digest, len, &mut file, true, instance)?;
        } else {
            self.import(digest, len, &mut file)?;
        }
        Ok(())
    }
}

/// FIX 5348, KS-2A: the instance row of a result body a save brings from an
/// off-record room into the vault, in the save's transaction, before the
/// row naming it commits: the vault's own committed pair when it holds one,
/// else the row of `promoted`, the vault instance its promotion imported
/// the body as before this transaction opened, with the custody binding
/// pinned. Whether the vault's `bodies/` then holds the body.
///
/// # Errors
///
/// Storage and filesystem errors, and a key custody does not hold.
pub(crate) fn keep_promoted_body_key_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    digest: &[u8; 32],
    len: u64,
    promoted: Option<[u8; 16]>,
) -> Result<bool> {
    let dir = store.body_dir()?;
    let mut row = body_key_row_in_txn(store, txn, digest)?;
    if !dir.holds_pair(digest, row.as_ref())?
        && let Some(instance) = promoted
    {
        let promoted = BodyKeyRow::vault(instance, len, false);
        super::custody::pin_body_custody_in_txn(store, txn)?;
        BODY_KEYS.put(store, txn, digest, &promoted)?;
        row = Some(promoted);
    }
    Ok(dir.open_reader(digest, len, row.as_ref())?.is_some())
}
