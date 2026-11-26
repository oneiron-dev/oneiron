//! The node's half of `Tail` (pass 34 row Q3, section 7.2): the bytes of a
//! key's stdout or stderr from a logical offset, while the key runs and after
//! it ended, until its payload is cleaned. Only the issuer the journal
//! recorded for the key is answered; nothing is written.
//!
//! The unit's log writer (row R3b) writes `<payload>/log/<stream>`: the
//! stream's first bytes, then its newest. When the template's cap drops the
//! bytes between them, the writer records that in `log/<stream>.dropped`,
//! JSON `{"at": <bytes kept before the gap>, "dropped": <bytes dropped so
//! far>}`, rewritten through a temp file and a rename, and with
//! `"rotating": true` from before it changes the file until it has. With no
//! record nothing was dropped. The file's byte `f` is the stream's byte `f`
//! below `at` and its byte `f + dropped` from `at` on.
//!
//! `log/` belongs to the workload, so both files are its untrusted bytes:
//! each is opened beneath the payload without following a link, must be a
//! regular file, and is read within bounds. A drop record that does not
//! parse or does not fit its file is refused, never guessed. A rotation
//! under the read is seen by reading the record and the file's length again
//! after it: the read is tried again, and answered `Busy` if it keeps
//! moving. A record still `rotating` once the key ended names a rotation no
//! writer is left to finish (a writer killed inside it: the key ends only
//! when the unit's control group was empty), so that read is refused, never
//! answered `Busy` for good.

use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::FileExt as _;
use std::path::Path;

use oneiron::EntityId;
use rustix::fs::{FileType, Mode, OFlags};
use rustix::io::Errno;
use serde::Deserialize;

use super::NodeJobs;
use super::admission::{answering, status_busy};
use super::status::own_key;
use crate::gpu_execution_node::wire::{
    JobRefusal, JobState, JobStatusAnswer, LogStream, LogTail, LogTailRequest, LogTruncation,
    TAIL_MAX_BYTES,
};

/// The most bytes a drop record takes: two numbers and a flag.
const DROP_RECORD_MAX_BYTES: u64 = 256;

/// The reads of one `Tail` before a rotation that keeps moving answers
/// `Busy`.
const READ_ATTEMPTS: usize = 3;

fn not_readable(why: impl Into<String>) -> JobStatusAnswer {
    JobStatusAnswer::Refused(JobRefusal::LogNotReadable { why: why.into() })
}

impl NodeJobs {
    /// `Tail { key, stream, offset, max }`: at most `max` (and at most
    /// [`TAIL_MAX_BYTES`]) bytes of the key's `stream` from the logical
    /// `offset`. An offset inside a gap the cap dropped answers the bytes
    /// after the gap with `truncated`; an offset past the stream's end
    /// answers nothing from the end. A key that has not launched has an
    /// empty stream. `ended` holds once the key ended and the answer reaches
    /// the stream's end.
    #[must_use]
    pub fn tail(&self, peer: EntityId, request: &LogTailRequest) -> JobStatusAnswer {
        let key = request.key.as_str();
        let known = {
            let mut book = self.lock();
            let journal = match answering(&mut book) {
                Ok(journal) => journal,
                Err(answer) => return answer,
            };
            let epoch = journal.epoch().to_hex();
            match own_key(journal.table().holder(key), peer, epoch) {
                Ok(known) => known,
                Err(answer) => return answer,
            }
        };
        if known.cleaned {
            return not_readable("payload_cleaned");
        }
        // Read before the file: a key that ends meanwhile answers `ended`
        // only at its next `Tail`, once the writer is gone.
        let ended = known.state == JobState::Ended;
        let payload_dir = known.id.payload_dir(&self.paths().work_dir);
        let max = request.max.min(TAIL_MAX_BYTES);
        for _ in 0..READ_ATTEMPTS {
            match read_page(&payload_dir, request.stream, request.offset, max) {
                Ok(Attempt::Page(page)) => {
                    return JobStatusAnswer::Tail(LogTail {
                        ended: ended && page.at_end,
                        next_offset: page.next_offset,
                        truncated: (page.skipped > 0).then_some(LogTruncation {
                            dropped: page.skipped,
                        }),
                        bytes: page.bytes,
                    });
                }
                // No writer is left to finish the rotation once the key ended.
                Ok(Attempt::Rotating) if ended => {
                    return not_readable(format!(
                        "log_writer_ended_inside_rotation: log/{}.dropped still says rotating",
                        request.stream.file_name()
                    ));
                }
                Ok(Attempt::Rotating | Attempt::Moved) => {}
                Err(why) => return not_readable(why),
            }
        }
        status_busy()
    }
}

/// What one read of a stream found.
#[derive(Debug, PartialEq, Eq)]
enum Attempt {
    Page(Page),
    /// The record or the file moved under the read.
    Moved,
    /// The drop record says the writer is inside a rotation.
    Rotating,
}

/// One answered range of a stream.
#[derive(Debug, PartialEq, Eq)]
struct Page {
    bytes: Vec<u8>,
    /// The logical offset after the bytes.
    next_offset: u64,
    /// The bytes of the gap between the asked offset and the first byte.
    skipped: u64,
    /// Nothing follows `next_offset` in the file read.
    at_end: bool,
}

/// The writer's `log/<stream>.dropped`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
struct DropRecord {
    at: u64,
    dropped: u64,
    #[serde(default)]
    rotating: bool,
}

/// Where a logical range lies in the file: `at` bytes of head, a gap of
/// `dropped`, then the rest of the file's `len` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LogMap {
    at: u64,
    dropped: u64,
    len: u64,
}

/// The part of the file one read takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Range {
    /// The asked offset, held at the stream's end.
    offset: u64,
    skipped: u64,
    file_offset: u64,
    take: u64,
}

impl LogMap {
    /// The map of a file of `len` bytes under `record`; refused when the
    /// record's head is past the file's end or its sums overflow.
    fn new(record: Option<DropRecord>, len: u64) -> Result<Self, String> {
        let Some(record) = record else {
            return Ok(Self {
                at: len,
                dropped: 0,
                len,
            });
        };
        if record.at > len {
            return Err(format!(
                "log_drop_record_past_file: at {} after the file's {len} bytes",
                record.at
            ));
        }
        if len.checked_add(record.dropped).is_none() {
            return Err(format!(
                "log_drop_record_overflows: dropped {}",
                record.dropped
            ));
        }
        Ok(Self {
            at: record.at,
            dropped: record.dropped,
            len,
        })
    }

    /// The stream's logical length.
    fn end(self) -> u64 {
        self.len.saturating_add(self.dropped)
    }

    /// The file range that answers `offset` with at most `max` bytes: within
    /// the head up to the gap, the bytes after the gap for an offset inside
    /// it, or the tail from the offset's place.
    fn locate(self, offset: u64, max: u64) -> Range {
        let offset = offset.min(self.end());
        let gap_end = self.at.saturating_add(self.dropped);
        let (skipped, file_offset, room) = if offset < self.at {
            (0, offset, self.at - offset)
        } else if offset < gap_end {
            (gap_end - offset, self.at, self.len - self.at)
        } else {
            let file_offset = offset - self.dropped;
            (0, file_offset, self.len.saturating_sub(file_offset))
        };
        Range {
            offset,
            skipped,
            file_offset,
            take: room.min(max),
        }
    }
}

/// One read of the stream.
fn read_page(
    payload_dir: &Path,
    stream: LogStream,
    offset: u64,
    max: u32,
) -> Result<Attempt, String> {
    let empty = Page {
        bytes: Vec::new(),
        next_offset: 0,
        skipped: 0,
        at_end: true,
    };
    let Some(log) = open_log_dir(payload_dir)? else {
        return Ok(Attempt::Page(empty));
    };
    let record_name = format!("{}.dropped", stream.file_name());
    let before = read_drop_record(&log, &record_name)?;
    if before.is_some_and(|record| record.rotating) {
        return Ok(Attempt::Rotating);
    }
    let Some(file) = open_regular(&log, stream.file_name())? else {
        if before.is_some() {
            return Err(format!("{record_name} without its log file"));
        }
        return Ok(Attempt::Page(empty));
    };
    let len_before = file_len(&file)?;
    let map = LogMap::new(before, len_before)?;
    let range = map.locate(offset, u64::from(max));
    let bytes = read_at(&file, range.file_offset, range.take)?;
    let len_after = file_len(&file)?;
    let after = read_drop_record(&log, &record_name)?;
    if after != before || len_after < len_before {
        return Ok(Attempt::Moved);
    }
    let read = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let next_offset = range
        .offset
        .saturating_add(range.skipped)
        .saturating_add(read);
    Ok(Attempt::Page(Page {
        at_end: next_offset >= map.end(),
        next_offset,
        skipped: range.skipped,
        bytes,
    }))
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// `<payload_dir>/log`, or `None` before the unit made it.
fn open_log_dir(payload_dir: &Path) -> Result<Option<rustix::fd::OwnedFd>, String> {
    let base = match rustix::fs::open(payload_dir, directory_flags(), Mode::empty()) {
        Ok(base) => base,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(format!("payload_dir: {error}")),
    };
    match rustix::fs::openat(&base, "log", directory_flags(), Mode::empty()) {
        Ok(log) => Ok(Some(log)),
        Err(Errno::NOENT) => Ok(None),
        Err(error) => Err(format!("log: {error}")),
    }
}

/// `name` beneath `dir` as a regular file, without following a link and
/// without blocking on a pipe; `None` when it does not exist.
fn open_regular(dir: &rustix::fd::OwnedFd, name: &str) -> Result<Option<File>, String> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let descriptor = match rustix::fs::openat(dir, name, flags, Mode::empty()) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(format!("log/{name}: {error}")),
    };
    let regular = rustix::fs::fstat(&descriptor)
        .is_ok_and(|stat| FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile);
    if !regular {
        return Err(format!("log/{name}: not a regular file"));
    }
    Ok(Some(File::from(descriptor)))
}

fn file_len(file: &File) -> Result<u64, String> {
    file.metadata()
        .map(|metadata| metadata.len())
        .map_err(|error| format!("log: {error}"))
}

/// The record `name` under `log/`, or `None` when the writer dropped
/// nothing.
fn read_drop_record(log: &rustix::fd::OwnedFd, name: &str) -> Result<Option<DropRecord>, String> {
    let Some(file) = open_regular(log, name)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(DROP_RECORD_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{name}: {error}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > DROP_RECORD_MAX_BYTES {
        return Err(format!("{name}: over {DROP_RECORD_MAX_BYTES} bytes"));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| format!("{name}: {error}"))
}

/// Up to `take` bytes of `file` from `file_offset`; fewer when the file
/// ends first.
fn read_at(file: &File, file_offset: u64, take: u64) -> Result<Vec<u8>, String> {
    let take = usize::try_from(take).map_err(|_| format!("log: a read of {take} bytes"))?;
    let mut bytes = vec![0u8; take];
    let mut filled = 0usize;
    while filled < take {
        let at = file_offset.saturating_add(u64::try_from(filled).unwrap_or(u64::MAX));
        match file.read_at(&mut bytes[filled..], at) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("log: {error}")),
        }
    }
    bytes.truncate(filled);
    Ok(bytes)
}
