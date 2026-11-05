//! Core half of `batch::export::archive_spool`: its store-layer items live in `oneiron_store::batch::export::archive_spool` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::batch::export::archive_spool::*;

use super::{ArchiveFile, ArchiveRecordFile, ArchiveRecordKind};
use crate::Vault;
use crate::error::{Error, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};

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

    /// [`Self::attach`] for a body read from `body` as it streams (FIX 3677),
    /// `bytes` long with BLAKE3 `digest`, as its source names it: it is
    /// staged a chunk at a time, each byte hashed as it is copied, and read
    /// to its end, so the source's own check runs too. It is indexed only
    /// once both agree with those facts; one that fails is cut off again and
    /// nothing names it. One already spooled is still read and checked, then
    /// cut off. Returns the digest.
    pub(crate) fn attach_reader(
        &mut self,
        bytes: u64,
        digest: [u8; 32],
        body: &mut dyn Read,
    ) -> Result<String> {
        let mut hasher = blake3::Hasher::new();
        let staged = self.stage(bytes, |out| {
            let mut chunk = vec![0; 64 * 1024];
            loop {
                let read = match body.read(&mut chunk) {
                    Ok(0) => return Ok(()),
                    Ok(read) => read,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                };
                hasher.update(&chunk[..read]);
                out.write_all(&chunk[..read])?;
            }
        })?;
        if *hasher.finalize().as_bytes() != digest {
            self.discard_staged(staged)?;
            return Err(Error::CorruptedIndex("attached file digest"));
        }
        let named = crate::entity_id::bytes_to_hex_lower(&digest);
        self.commit_staged(named.clone(), staged)?;
        Ok(named)
    }

    /// Copies a body through `copy` onto the spool's end without indexing it
    /// (FIX 7213), so a scan reads it there before it is kept: the one copy
    /// of it on disk. A copy that fails, or is not the `bytes` long the
    /// caller has checked, is cut off again and fails. Nothing else is
    /// spooled while a body is staged.
    pub(crate) fn stage(
        &mut self,
        bytes: u64,
        copy: impl FnOnce(&mut BufWriter<File>) -> Result<()>,
    ) -> Result<StagedFile> {
        let at = self.end;
        self.file.seek(SeekFrom::Start(at))?;
        let copied = match copy(&mut self.file) {
            Ok(()) => self.file.stream_position().map_err(Error::from),
            Err(error) => Err(error),
        };
        let staged = StagedFile { at, bytes };
        match copied {
            Ok(end) if end == at + bytes => Ok(staged),
            failed => {
                self.discard_staged(staged)?;
                Err(failed.err().unwrap_or_else(spool_failed))
            }
        }
    }

    /// Hands a staged body to `scan` as a reader over exactly its bytes, read
    /// where they are spooled (FIX 7213); the spool writes on after it.
    pub(crate) fn scan_staged<T>(
        &mut self,
        staged: &StagedFile,
        scan: impl FnOnce(&mut StagedReader<'_>) -> Result<T>,
    ) -> Result<T> {
        self.file.flush()?;
        let at = staged.at;
        let file = self.file.get_mut();
        file.seek(SeekFrom::Start(at))?;
        let mut reader = StagedReader {
            file,
            at,
            bytes: staged.bytes,
            pos: 0,
        };
        let scanned = scan(&mut reader);
        reader.file.seek(SeekFrom::Start(at + staged.bytes))?;
        scanned
    }

    /// Indexes a staged body under `digest`, whose BLAKE3 and length the
    /// caller has checked (FIX 7213). A body already spooled under it is cut
    /// off instead, so no digest is spooled twice.
    pub(crate) fn commit_staged(&mut self, digest: String, staged: StagedFile) -> Result<()> {
        if self.index.contains_key(&digest) {
            return self.discard_staged(staged);
        }
        self.end = staged.at + staged.bytes;
        self.index.insert(digest, (staged.at, staged.bytes));
        Ok(())
    }

    /// Cuts a staged body off the spool's end (FIX 7213): its bytes are
    /// freed, and the next file is written where it started.
    pub(crate) fn discard_staged(&mut self, staged: StagedFile) -> Result<()> {
        self.file.seek(SeekFrom::Start(staged.at))?;
        self.file.get_ref().set_len(staged.at)?;
        self.end = staged.at;
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
