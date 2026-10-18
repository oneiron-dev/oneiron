//! FIX 2766 (rule 5): the whole-vault archive is built through spool files and
//! read member by member, so no archive, member, row group or file map is ever
//! held whole. Each spool is an anonymous owner-only file under the vault's own
//! pinned staging directory, never a path a caller names.
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};

use serde_json::Value;

use super::{ArchiveFile, ArchiveRecordFile, ArchiveRecordKind};
use crate::Vault;
use crate::error::{Error, Result};

impl Vault {
    /// An anonymous owner-only spool file under this vault's staging
    /// directory (created 0700, opened no-follow and held while the file is
    /// made), for an archive a door writes before it sends it on (FIX 2766).
    /// It is never a path the caller names, and it is gone once dropped. A
    /// host with no descriptor-bound vault root (not unix) spools to an
    /// anonymous temporary file the system deletes on close, so its export
    /// still works.
    pub fn archive_spool_file(&self) -> Result<File> {
        #[cfg(unix)]
        {
            self.store.lfs_staging_file()
        }
        #[cfg(not(unix))]
        {
            Ok(tempfile::tempfile()?)
        }
    }
}

/// One JSONL member as it is spooled: each row written as it comes, counted
/// and hashed, so the manifest names the member before it is copied.
pub(crate) struct RecordSpool {
    pub(crate) kind: ArchiveRecordKind,
    file: BufWriter<File>,
    rows: u64,
    bytes: u64,
    hasher: blake3::Hasher,
}

impl RecordSpool {
    pub(crate) fn new(vault: &Vault, kind: ArchiveRecordKind) -> Result<Self> {
        Ok(Self {
            kind,
            file: BufWriter::new(vault.archive_spool_file()?),
            rows: 0,
            bytes: 0,
            hasher: blake3::Hasher::new(),
        })
    }

    /// Writes one row, then its line end.
    pub(crate) fn push(&mut self, row: &Value) -> Result<()> {
        let mut line = serde_json::to_vec(row).map_err(|_| spool_failed())?;
        line.push(b'\n');
        self.push_line(&line)
    }

    /// Writes one row already encoded, its line end included.
    pub(crate) fn push_line(&mut self, line: &[u8]) -> Result<()> {
        self.file.write_all(line)?;
        self.hasher.update(line);
        self.bytes += line.len() as u64;
        self.rows += 1;
        Ok(())
    }

    /// The manifest's entry for this member at `path`.
    pub(crate) fn record(&self, path: &str) -> ArchiveRecordFile {
        ArchiveRecordFile {
            path: path.to_owned(),
            kind: self.kind,
            rows: self.rows,
            bytes: self.bytes,
            blake3: crate::entity_id::bytes_to_hex_lower(self.hasher.finalize().as_bytes()),
        }
    }

    /// The spooled rows, read from the start.
    pub(crate) fn reader(&mut self) -> Result<BufReader<File>> {
        self.file.flush()?;
        let mut file = self.file.get_ref().try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        Ok(BufReader::new(file))
    }

    /// Each spooled row in order, with where its line starts in the spool.
    pub(crate) fn rows(&mut self) -> Result<SpooledRows> {
        Ok(SpooledRows {
            reader: self.reader()?,
            at: 0,
        })
    }

    /// The same member without the rows `drop` names: a fresh spool, counted
    /// and hashed again.
    pub(crate) fn filtered(
        mut self,
        vault: &Vault,
        mut drop: impl FnMut(&Value) -> bool,
    ) -> Result<Self> {
        let mut kept = Self::new(vault, self.kind)?;
        let mut rows = self.rows()?;
        while let Some((_, line)) = rows.next_line()? {
            let row: Value = serde_json::from_slice(&line).map_err(|_| spool_failed())?;
            if !drop(&row) {
                kept.push_line(&line)?;
            }
        }
        Ok(kept)
    }

    /// The spooled line at `at`, its line end included.
    pub(crate) fn line_at(&mut self, at: u64) -> Result<Vec<u8>> {
        let mut reader = self.reader()?;
        reader.seek(SeekFrom::Start(at))?;
        let mut line = Vec::new();
        reader.read_until(b'\n', &mut line)?;
        Ok(line)
    }
}

/// A spool's rows read back in order.
pub(crate) struct SpooledRows {
    reader: BufReader<File>,
    at: u64,
}

impl SpooledRows {
    /// The next line and where it starts, its line end included.
    pub(crate) fn next_line(&mut self) -> Result<Option<(u64, Vec<u8>)>> {
        let mut line = Vec::new();
        let read = self.reader.read_until(b'\n', &mut line)?;
        if read == 0 {
            return Ok(None);
        }
        let start = self.at;
        self.at += read as u64;
        Ok(Some((start, line)))
    }

    /// The next row and where it starts.
    pub(crate) fn next_row(&mut self) -> Result<Option<(u64, Value)>> {
        let Some((at, line)) = self.next_line()? else {
            return Ok(None);
        };
        let row = serde_json::from_slice(&line).map_err(|_| spool_failed())?;
        Ok(Some((at, row)))
    }
}

/// The archive's attached files as they are spooled: each once by its
/// BLAKE3, whatever cites it, and copied into the archive one at a time.
pub(crate) struct FileSpool {
    file: BufWriter<File>,
    index: BTreeMap<String, (u64, u64)>,
    end: u64,
}

impl FileSpool {
    pub(crate) fn new(vault: &Vault) -> Result<Self> {
        Ok(Self {
            file: BufWriter::new(vault.archive_spool_file()?),
            index: BTreeMap::new(),
            end: 0,
        })
    }

    /// Spools `bytes` under its BLAKE3 unless the same bytes already are;
    /// returns the digest.
    pub(crate) fn attach(&mut self, bytes: &[u8]) -> Result<String> {
        let digest = super::blake3_hex(bytes);
        self.attach_as(digest.clone(), bytes)?;
        Ok(digest)
    }

    /// [`Self::attach`] for bytes whose BLAKE3 the caller has checked.
    pub(crate) fn attach_as(&mut self, digest: String, bytes: &[u8]) -> Result<()> {
        if self.index.contains_key(&digest) {
            return Ok(());
        }
        self.file.write_all(bytes)?;
        self.index.insert(digest, (self.end, bytes.len() as u64));
        self.end += bytes.len() as u64;
        Ok(())
    }

    /// The manifest's file list, in digest order.
    pub(crate) fn manifest(&self) -> Vec<ArchiveFile> {
        self.index
            .iter()
            .map(|(blake3, (_, bytes))| ArchiveFile {
                blake3: blake3.clone(),
                bytes: *bytes,
            })
            .collect()
    }

    /// Hands each spooled file, in digest order, to `copy` as a reader over
    /// exactly its bytes.
    pub(crate) fn each(
        &mut self,
        mut copy: impl FnMut(&str, &mut dyn Read) -> Result<()>,
    ) -> Result<()> {
        self.file.flush()?;
        let mut file = self.file.get_ref().try_clone()?;
        for (blake3, (at, bytes)) in &self.index {
            file.seek(SeekFrom::Start(*at))?;
            copy(blake3, &mut (&mut file).take(*bytes))?;
        }
        Ok(())
    }
}

pub(crate) fn spool_failed() -> Error {
    Error::InvariantViolation("whole-vault archive spool failed")
}
