//! The Google Takeout `.zip` arm of the mbox import: each mbox file of an
//! archive the archive pre-check passed, read in turn up to the room the
//! vault's storage cap leaves.

use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

use super::{Intake, MboxImportProgress, READ_BUFFER_BYTES, read_stream, unreadable};
use crate::EntityId;
use crate::ingest::archive_precheck::{
    ArchiveBounds, ArchiveRefusal, EntryReader, check_archive, storage_room,
};
use crate::mail_pack::mbox::MboxReader;
use crate::memory::{MEMORY_CODE_INTERNAL, MemoryError, MemoryResult};

/// The read error of a zipped mbox past the room the vault's storage cap
/// leaves ([`RoomBounded`]): the call stops there.
#[derive(Debug)]
struct PastStorageCap;

impl fmt::Display for PastStorageCap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the archive unpacks past the room the vault's storage cap leaves")
    }
}

impl std::error::Error for PastStorageCap {}

pub(super) fn past_storage_cap(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<PastStorageCap>())
}

/// A zipped mbox read under the room the vault's storage cap leaves: it
/// hands its reader at most `room` more bytes, and fails with
/// [`PastStorageCap`] where the mbox holds more. It counts the bytes its
/// reader takes, never those its buffer holds ahead.
struct RoomBounded<R> {
    inner: R,
    room: u64,
}

impl<R: BufRead> Read for RoomBounded<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let taken = available.len().min(out.len());
        out[..taken].copy_from_slice(&available[..taken]);
        self.consume(taken);
        Ok(taken)
    }
}

impl<R: BufRead> BufRead for RoomBounded<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let available = self.inner.fill_buf()?;
        if available.is_empty() {
            return Ok(available);
        }
        if self.room == 0 {
            return Err(io::Error::other(PastStorageCap));
        }
        let shown =
            usize::try_from(self.room).map_or(available.len(), |room| room.min(available.len()));
        Ok(&available[..shown])
    }

    fn consume(&mut self, taken: usize) {
        self.room = self
            .room
            .saturating_sub(u64::try_from(taken).unwrap_or(u64::MAX));
        self.inner.consume(taken);
    }
}

/// The call's error for a `.zip` the archive pre-check refused; past the
/// entry cap, it names the request field that raises the cap.
fn archive_refused(refusal: &ArchiveRefusal) -> MemoryError {
    match refusal {
        ArchiveRefusal::TooManyEntries { declared, cap } => MemoryError::bad_request_with(
            format!(
                "the archive declares {declared} entries, past the entry cap of {cap} \
                 (`archive_max_entries`); this call read none of it"
            ),
            &["Raise archive_max_entries in the request to import a larger archive."],
        ),
        other => MemoryError::bad_request(format!(
            "the archive pre-check refused the archive: {other}"
        )),
    }
}

/// Reads the next `budget` messages of the `.zip` at `path`: each mbox file
/// of it the archive pre-check passed, under `bounds`, in turn, up to the
/// room the vault's storage cap leaves.
pub(super) fn read_archive(
    path: &Path,
    key: &(EntityId, [u8; 32]),
    progress: &mut MboxImportProgress,
    mut budget: u32,
    bounds: ArchiveBounds,
    intake: &mut Intake<'_>,
) -> MemoryResult<()> {
    let file = File::open(path).map_err(|error| unreadable(&error))?;
    let mut archive = check_archive(file, bounds).map_err(|refusal| archive_refused(&refusal))?;
    intake.report.skipped_entries = archive.skipped().to_vec();
    // The mbox files among the entries the pass kept, by their place there.
    let entries: Vec<usize> = archive
        .entries()
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            !entry.directory
                && entry
                    .path
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .ends_with(".mbox")
        })
        .map(|(at, _)| at)
        .collect();
    if entries.is_empty() {
        return Err(MemoryError::bad_request_with(
            "the archive holds no .mbox file",
            &["Export Mail from Google Takeout as mbox, then import its .zip or its .mbox file."],
        ));
    }
    // The room the vault's storage cap leaves, measured once per call: what
    // this call reads past an earlier call's place counts against it, across
    // the archive's mbox files. A later call measures it again.
    let vault = intake.vault;
    let mut room = storage_room(vault.config.storage_cap_bytes, vault.path())
        .map_err(|error| {
            MemoryError::new(
                MEMORY_CODE_INTERNAL,
                format!("the vault's folder cannot be measured against its storage cap: {error}"),
                &[],
            )
        })?
        .unwrap_or(u64::MAX);
    while let Some(&at) = entries.get(progress.entry as usize) {
        // An mbox streams message by message, so no byte bound holds it
        // whole; its first bytes are checked before any message is read. The
        // room under the storage cap bounds what this call reads of it
        // below, never the entry's declared size: one Takeout mbox holds
        // the whole mailbox, and a call lands what fits.
        let entry = archive
            .open_entry(at, EntryReader::Mbox, u64::MAX)
            .map_err(|refusal| archive_refused(&refusal))?;
        let mut reader = BufReader::with_capacity(READ_BUFFER_BYTES, entry);
        // A zipped mbox reads from its start: what an earlier call read is
        // passed over.
        std::io::copy(
            &mut (&mut reader).take(progress.offset),
            &mut std::io::sink(),
        )
        .map_err(|error| unreadable(&error))?;
        let mut bounded = RoomBounded {
            inner: reader,
            room,
        };
        let ended = read_stream(
            MboxReader::new(&mut bounded, progress.offset),
            key,
            progress,
            &mut budget,
            intake,
        )?;
        room = bounded.room;
        if !ended {
            return Ok(());
        }
        progress.entry += 1;
        progress.offset = 0;
    }
    progress.done = true;
    Ok(())
}
