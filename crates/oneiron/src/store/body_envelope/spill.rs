//! Writing body files (FIX 5348): a body spilled as it streams, sealed
//! chunk by chunk in a sealed directory, and the copies a promotion or a
//! restore makes of one.

use std::fs::File;
use std::io::{self, Read, Write};
use std::sync::Arc;

use heed::RwTxn;

use super::frames::{Domain, FileKey, FrameWriter, LineCounter, SealedStream, write_line_index};
use super::reader::BodyFile;
use super::rows::{BODY_KEYS, BodyKeyRow, body_key_row_in_txn};
use super::{DirSeal, KeyScope, sealed_body_file_name};
use crate::error::{Error, Result};
use crate::side_table::SideTableDbs;
use crate::store::{BodyDir, LINE_INDEX_BLOCK_BYTES, LINE_INDEX_SUFFIX, Store, body_file_name};

/// A sealed body file a writer staged, and the key row the row or
/// descriptor naming its body commits with ([`super::bind_body_key_in_txn`]).
pub(crate) struct StagedBodyKey {
    pub(super) digest: [u8; 32],
    pub(super) row: BodyKeyRow,
    scope: KeyScope,
    key: Arc<FileKey>,
}

impl StagedBodyKey {
    pub(crate) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(crate) const fn row(&self) -> &BodyKeyRow {
        &self.row
    }

    /// Whether `held`, the key row a route already holds for this digest,
    /// is a committed pair in `dir`, where this key's file is: wrapped for
    /// this key's scope, its file there. Then it stays, and its file serves
    /// the body.
    ///
    /// # Errors
    ///
    /// A row that does not parse, and filesystem errors.
    pub(crate) fn keeps(&self, held: &BodyKeyRow, dir: &BodyDir) -> Result<bool> {
        Ok(dir
            .sealed
            .as_ref()
            .is_some_and(|sealed| sealed.scope == self.scope)
            && dir.holds_pair(&self.digest, Some(held))?)
    }

    /// Writes `index`, the body's line index, sealed beside its file in
    /// `dir`. Derived: a failure leaves none, to be rebuilt.
    pub(crate) fn write_line_index(&self, dir: &BodyDir, index: &[u64]) {
        write_sealed_lines(dir, &self.digest, &self.key, index);
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
/// come, or, in a sealed directory, sealed under a fresh key of its own as
/// they come. The caller removes the temp file if it is dropped unfinished.
pub(crate) struct BodySpill {
    temp: String,
    out: Out,
}

enum Out {
    Plain(File),
    Sealed {
        writer: Box<FrameWriter>,
        dir: DirSeal,
    },
}

impl BodySpill {
    /// A spill into `dir`.
    ///
    /// # Errors
    ///
    /// Filesystem errors, and a sealed directory whose key is not admitted.
    pub(crate) fn create(dir: &BodyDir) -> Result<Self> {
        let sealed = match &dir.sealed {
            Some(sealed) => Some((
                sealed.clone(),
                Arc::new(FileKey::generate(sealed.seal()?.vault_id)?),
            )),
            None => None,
        };
        let (file, temp) = dir.create_temp()?;
        let out = match sealed {
            None => Out::Plain(file),
            Some((dir, key)) => Out::Sealed {
                writer: Box::new(FrameWriter::new(file, key, Domain::Body)),
                dir,
            },
        };
        Ok(Self { temp, out })
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
    /// chunk and terminal record are sealed and its key wrapped for its
    /// directory's scope. Nothing is published yet.
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
                let row = BodyKeyRow::wrap(dir.seal()?, dir.scope, &key, digest, len)?;
                (
                    file,
                    Some(StagedBodyKey {
                        digest: *digest,
                        row,
                        scope: dir.scope,
                        key,
                    }),
                )
            }
        };
        Ok(SpilledBody {
            file,
            temp: self.temp,
            digest: *digest,
            len,
            key,
        })
    }
}

/// A finished spill, not yet published.
pub(crate) struct SpilledBody {
    file: File,
    temp: String,
    digest: [u8; 32],
    len: u64,
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
        match &self.key {
            None => Ok(BodyFile::plain(file, self.len)),
            Some(staged) => BodyFile::sealed(file, Arc::clone(&staged.key), &self.digest, self.len),
        }
    }

    /// Publishes the body under its name in `dir`, the directory it spilled
    /// into: synced, renamed into place, the directory synced. A plain
    /// body's name is its digest, an envelope's `<digest>-<instance>`. Its
    /// staged key, `None` for a plain body.
    ///
    /// # Errors
    ///
    /// Filesystem errors; the temp file is removed.
    pub(crate) fn publish(self, dir: &BodyDir) -> Result<Option<StagedBodyKey>> {
        let name = match &self.key {
            None => body_file_name(&self.digest),
            Some(staged) => sealed_body_file_name(&self.digest, &staged.row.instance),
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
    /// Publishes `body`, the body `digest`, as a new envelope in this sealed
    /// directory, and its staged key.
    ///
    /// # Errors
    ///
    /// Filesystem and sealing errors; nothing is left behind.
    pub(crate) fn publish_sealed_body(
        &self,
        digest: &[u8; 32],
        body: &[u8],
    ) -> Result<StagedBodyKey> {
        let mut spill = BodySpill::create(self)?;
        let temp = spill.temp().to_owned();
        let spilled = spill
            .write(body)
            .and_then(|()| spill.finish(digest, body.len() as u64));
        let spilled = match spilled {
            Ok(spilled) => spilled,
            Err(error) => {
                self.discard(&temp);
                return Err(error);
            }
        };
        spilled.publish(self)?.ok_or(Error::InvariantViolation(
            "a sealed body directory published a plain body",
        ))
    }

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
    /// into a new envelope in this sealed directory, with its sealed line
    /// index when `lines`, and its staged key.
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
    ) -> Result<StagedBodyKey> {
        let mut spill = BodySpill::create(self)?;
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
                    "a sealed body directory published a plain body",
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

    /// Brings in the result body `digest`, `len` bytes long, that `file`
    /// holds in another directory of `store`'s (an off-record session's):
    /// a plain file through [`BodyDir::import`], an envelope's ciphertext as
    /// it is, with its line index, unless the vault holds a committed pair
    /// for the digest already.
    ///
    /// # Errors
    ///
    /// As [`BodyDir::import`] and [`Self::import_sealed`].
    pub(crate) fn import_body(
        &self,
        store: &Store,
        digest: &[u8; 32],
        len: u64,
        file: BodyFile,
    ) -> Result<()> {
        match file.into_sealed() {
            Err(mut plain) => self.import(digest, len, &mut plain),
            Ok((file, key, _)) => {
                let row = {
                    let rtxn = store.env.read_txn()?;
                    body_key_row_in_txn(store, &rtxn, digest)?
                };
                if self.holds_pair(digest, row.as_ref())? {
                    return Ok(());
                }
                self.import_sealed(digest, len, file, key, true)
            }
        }
    }
}

/// FIX 5348: the key row of a result body a save brings from an off-record
/// room into the vault, in the save's transaction, before the row naming it
/// commits: the vault's own committed pair when it holds one, else the
/// room's row wrapped again for the vault (promotion copied its file in
/// first). Whether the vault's `bodies/` then holds the body.
///
/// # Errors
///
/// Storage and filesystem errors, and a key that does not open.
pub(crate) fn keep_promoted_body_key_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    room: &impl SideTableDbs,
    digest: &[u8; 32],
    len: u64,
) -> Result<bool> {
    let dir = store.body_dir()?;
    let mut row = body_key_row_in_txn(store, txn, digest)?;
    if !dir.holds_pair(digest, row.as_ref())?
        && let Some(sealed) = &dir.sealed
        && let Some(held) = body_key_row_in_txn(room, txn, digest)?
    {
        let from = DirSeal {
            scope: KeyScope::OffRecord,
            seal: sealed.seal.clone(),
        };
        if let Some(rewrapped) = held.rewrap(digest, &from, sealed)? {
            BODY_KEYS.put(store, txn, digest, &rewrapped)?;
            row = Some(rewrapped);
        }
    }
    Ok(dir.open_reader(digest, len, row.as_ref())?.is_some())
}
