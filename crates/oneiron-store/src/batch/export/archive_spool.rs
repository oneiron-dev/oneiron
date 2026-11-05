//! FIX 2766 (rule 5): the whole-vault archive is built through spool files and
//! read member by member, so no archive, member, row group or file map is ever
//! held whole. Each spool is an anonymous owner-only file under the vault's own
//! pinned staging directory, never a path a caller names.
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};

use serde_json::Value;

use crate::batch::export::archive_types::ArchiveFile;
use crate::batch::export::archive_types::ArchiveRecordFile;
use crate::batch::export::archive_types::ArchiveRecordKind;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

/// A spool's rows read back in order.
pub struct SpooledRows {
    pub reader: BufReader<File>,
    pub at: u64,
}

impl SpooledRows {
    /// The next line and where it starts, its line end included.
    pub fn next_line(&mut self) -> Result<Option<(u64, Vec<u8>)>> {
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
    pub fn next_row(&mut self) -> Result<Option<(u64, Value)>> {
        let Some((at, line)) = self.next_line()? else {
            return Ok(None);
        };
        let row = serde_json::from_slice(&line).map_err(|_| spool_failed())?;
        Ok(Some((at, row)))
    }
}

/// A body staged at the end of a [`FileSpool`] and not yet indexed
/// (FIX 7213), until [`FileSpool::commit_staged`] keeps it or
/// [`FileSpool::discard_staged`] cuts it off.
#[must_use]
pub struct StagedFile {
    pub at: u64,
    pub bytes: u64,
}

/// A staged body read where it is spooled ([`FileSpool::scan_staged`]):
/// exactly its bytes, through the file under the spool's writer.
pub struct StagedReader<'f> {
    pub file: &'f mut File,
    pub at: u64,
    pub bytes: u64,
    pub pos: u64,
}

impl Read for StagedReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.bytes.saturating_sub(self.pos);
        let take = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        let read = self.file.read(&mut buf[..take])?;
        self.pos += read as u64;
        Ok(read)
    }
}

impl Seek for StagedReader<'_> {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        let pos = match to {
            SeekFrom::Start(pos) => Some(pos),
            SeekFrom::End(by) => self.bytes.checked_add_signed(by),
            SeekFrom::Current(by) => self.pos.checked_add_signed(by),
        };
        let Some(pos) = pos else {
            return Err(std::io::ErrorKind::InvalidInput.into());
        };
        let from = self.at.saturating_add(pos);
        self.file.seek(SeekFrom::Start(from))?;
        self.pos = pos;
        Ok(pos)
    }
}

pub fn spool_failed() -> Error {
    Error::InvariantViolation("whole-vault archive spool failed")
}
