//! The job journal's file: an append-only sequence of framed records in
//! `<state_dir>/journal`, beside the journal's epoch in `<state_dir>/epoch`
//! (design pass 33, 5.2).
//!
//! - The file starts with a header: [`JOURNAL_MAGIC`], the format version,
//!   and the epoch it was made with. A header whose epoch differs from the
//!   epoch file is a journal from another history.
//! - Each record is one frame: its payload length (u32, little endian), a
//!   check of that length (the first 4 bytes of its blake3 hash), the
//!   payload, and the first 16 bytes of the blake3 hash of length and
//!   payload. The length's own check tells a torn write from a damaged
//!   length: a length that fails its check is damage, never a torn tail.
//! - [`JournalFile::append`] returns only after the frame is synced to disk.
//!   A write or a sync that fails is rolled back to the length before the
//!   append, so no reply can go out for a record that is not on disk and the
//!   record does not appear after a restart. When the rollback fails too,
//!   the file is poisoned: every later append is refused until the journal
//!   is opened again.
//! - At open, a torn last frame was never answered: it is cut off. A frame
//!   is torn when its checked length runs past the end of the file, when
//!   fewer bytes than a length and its check remain, or when its bytes from
//!   its start to the end are all zero. Any other bad frame, last or not, is
//!   a damaged history.
//! - One writer per `state_dir`: [`JournalWriterLock`] holds an exclusive
//!   lock on `<state_dir>/journal.lock` for as long as the job service
//!   lives, so a second service on the same directory is refused before it
//!   reads the journal.
//!
//! The file knows bytes only; [`super::journal`] gives the records their
//! meaning.

use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oneiron_contracts::fingerprint::{ContentHash, ContentHasher};
use rand_core::{OsRng, RngCore as _};

/// The first eight bytes of every job journal.
pub const JOURNAL_MAGIC: [u8; 8] = *b"ONJOBJNL";

/// The journal format this build writes and reads. Another version is read
/// as a damaged history: there is no reader for other formats.
pub const JOURNAL_FORMAT_VERSION: u32 = 1;

/// The journal's file name inside `state_dir`.
pub const JOURNAL_FILE_NAME: &str = "journal";

/// The epoch's file name inside `state_dir`.
pub const EPOCH_FILE_NAME: &str = "epoch";

/// The writer lock's file name inside `state_dir`.
pub const WRITER_LOCK_FILE_NAME: &str = "journal.lock";

/// The largest payload one frame may carry. A record is a key's event; the
/// largest (`accepted`, with its signed submit) is a few KiB.
pub const MAX_FRAME_PAYLOAD_BYTES: u32 = 1 << 20;

const EPOCH_BYTES: usize = 16;
const HEADER_BYTES: u64 = 8 + 4 + EPOCH_BYTES as u64;
const LENGTH_BYTES: u64 = 4;
const LENGTH_CHECK_BYTES: u64 = 4;
const FRAME_HEAD_BYTES: u64 = LENGTH_BYTES + LENGTH_CHECK_BYTES;
const CHECKSUM_BYTES: u64 = 16;

/// A hook a test sets to fail an append between its write and its sync.
pub type JournalAppendFault = Arc<dyn Fn() -> io::Result<()> + Send + Sync>;

/// The random id a journal is made with. Every receipt carries it, so a
/// reader can tell one history of this node from another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JournalEpoch([u8; EPOCH_BYTES]);

impl JournalEpoch {
    fn random() -> Self {
        let mut bytes = [0u8; EPOCH_BYTES];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// The epoch as 32 lower-case hex digits.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn from_hex(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.len() != EPOCH_BYTES * 2 || !text.is_ascii() {
            return None;
        }
        let mut bytes = [0u8; EPOCH_BYTES];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
        }
        Some(Self(bytes))
    }
}

impl std::fmt::Display for JournalEpoch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

/// The exclusive lock of the one journal writer of a `state_dir`, held until
/// it drops.
#[derive(Debug)]
pub struct JournalWriterLock {
    _file: File,
}

impl JournalWriterLock {
    /// Takes the lock, never waiting.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::WouldBlock`] when another writer holds it, or the
    /// I/O error that stopped it.
    pub fn take(state_dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(state_dir)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(state_dir.join(WRITER_LOCK_FILE_NAME))?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!(
                    "job_journal.locked: another job service holds {}",
                    state_dir.display()
                ),
            )),
            Err(std::fs::TryLockError::Error(error)) => Err(error),
        }
    }
}

/// Why the journal's history cannot be read. Every case is answered as
/// history lost: the node never reads a damaged journal as "no such key".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JournalDamage {
    #[error("job_journal.journal_missing: the epoch file exists and the journal does not")]
    JournalMissing,
    #[error("job_journal.epoch_missing: the journal exists and the epoch file does not")]
    EpochMissing,
    #[error("job_journal.unreadable: {0}")]
    Unreadable(String),
    #[error("job_journal.bad_epoch_file: the epoch file does not hold one epoch")]
    BadEpochFile,
    #[error("job_journal.bad_header: the journal does not start with a job journal header")]
    BadHeader,
    #[error(
        "job_journal.unknown_format: the journal is format {found}; this build reads {JOURNAL_FORMAT_VERSION}"
    )]
    UnknownFormat { found: u32 },
    #[error(
        "job_journal.epoch_mismatch: the journal was made with epoch {journal}, the epoch file says {file}"
    )]
    EpochMismatch { journal: String, file: String },
    #[error("job_journal.bad_frame: the record at byte {offset} is damaged")]
    BadFrame { offset: u64 },
}

/// Why an append did not land.
#[derive(Debug, thiserror::Error)]
pub enum JournalAppendError {
    #[error(
        "job_journal.append_failed: {0}; the journal was rolled back to its length before the append"
    )]
    RolledBack(#[source] io::Error),
    #[error(
        "job_journal.poisoned: an append could not be rolled back; the journal takes no record until it is opened again"
    )]
    Poisoned,
    #[error(
        "job_journal.record_too_large: a record of {bytes} bytes is over the {MAX_FRAME_PAYLOAD_BYTES}-byte frame limit"
    )]
    TooLarge { bytes: usize },
}

/// What [`JournalFile::open`] found in `state_dir`.
#[derive(Debug)]
pub enum JournalOpening {
    /// Neither the journal nor the epoch exists: a node that never held a
    /// key, or one whose history is gone. The caller decides which, from
    /// the control and payload directories, before it calls
    /// [`JournalFile::create`].
    Absent,
    /// The history cannot be read.
    Damaged(JournalDamage),
    /// The journal, its epoch, and every whole record in order.
    Opened {
        file: JournalFile,
        records: Vec<Vec<u8>>,
        /// Whether a torn last frame was cut off.
        cut_torn_tail: bool,
    },
}

/// The open journal: the one writer appends here.
pub struct JournalFile {
    path: PathBuf,
    file: File,
    epoch: JournalEpoch,
    length: u64,
    poisoned: bool,
    append_fault: Option<JournalAppendFault>,
}

impl std::fmt::Debug for JournalFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JournalFile")
            .field("path", &self.path)
            .field("epoch", &self.epoch)
            .field("length", &self.length)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl JournalFile {
    /// Opens the journal in `state_dir`, reading every whole record.
    #[must_use]
    pub fn open(state_dir: &Path) -> JournalOpening {
        let journal_path = state_dir.join(JOURNAL_FILE_NAME);
        let epoch_path = state_dir.join(EPOCH_FILE_NAME);
        let exists = |path: &Path| {
            path.try_exists().map_err(|error| {
                JournalOpening::Damaged(JournalDamage::Unreadable(format!(
                    "{}: {error}",
                    path.display()
                )))
            })
        };
        let journal_exists = match exists(&journal_path) {
            Ok(exists) => exists,
            Err(opening) => return opening,
        };
        let epoch_exists = match exists(&epoch_path) {
            Ok(exists) => exists,
            Err(opening) => return opening,
        };
        match (journal_exists, epoch_exists) {
            (false, false) => return JournalOpening::Absent,
            (false, true) => return JournalOpening::Damaged(JournalDamage::JournalMissing),
            (true, false) => return JournalOpening::Damaged(JournalDamage::EpochMissing),
            (true, true) => {}
        }
        let epoch = match std::fs::read_to_string(&epoch_path) {
            Ok(text) => match JournalEpoch::from_hex(&text) {
                Some(epoch) => epoch,
                None => return JournalOpening::Damaged(JournalDamage::BadEpochFile),
            },
            Err(error) => {
                return JournalOpening::Damaged(JournalDamage::Unreadable(format!(
                    "{}: {error}",
                    epoch_path.display()
                )));
            }
        };
        let mut file = match OpenOptions::new()
            .read(true)
            .write(true)
            .open(&journal_path)
        {
            Ok(file) => file,
            Err(error) => {
                return JournalOpening::Damaged(JournalDamage::Unreadable(format!(
                    "{}: {error}",
                    journal_path.display()
                )));
            }
        };
        let mut bytes = Vec::new();
        if let Err(error) = file.read_to_end(&mut bytes) {
            return JournalOpening::Damaged(JournalDamage::Unreadable(format!(
                "{}: {error}",
                journal_path.display()
            )));
        }
        let parsed = match parse_journal(&bytes, epoch) {
            Ok(parsed) => parsed,
            Err(damage) => return JournalOpening::Damaged(damage),
        };
        let cut_torn_tail = parsed.whole_length < bytes.len() as u64;
        if cut_torn_tail
            && let Err(error) = file
                .set_len(parsed.whole_length)
                .and_then(|()| file.sync_data())
        {
            return JournalOpening::Damaged(JournalDamage::Unreadable(format!(
                "{}: cutting the torn last record: {error}",
                journal_path.display()
            )));
        }
        JournalOpening::Opened {
            file: Self {
                path: journal_path,
                file,
                epoch,
                length: parsed.whole_length,
                poisoned: false,
                append_fault: None,
            },
            records: parsed.records,
            cut_torn_tail,
        }
    }

    /// Makes a new, empty journal with a new epoch in `state_dir`. Any
    /// journal and epoch already there are replaced: this is the node's
    /// `reset-history` and its first start.
    ///
    /// # Errors
    ///
    /// The I/O error that stopped it. The epoch file is written last, so a
    /// failure leaves no epoch that names a journal without its header.
    pub fn create(state_dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(state_dir)?;
        let journal_path = state_dir.join(JOURNAL_FILE_NAME);
        let epoch_path = state_dir.join(EPOCH_FILE_NAME);
        let epoch = JournalEpoch::random();
        match std::fs::remove_file(&epoch_path) {
            Ok(()) => sync_dir(state_dir)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut header = Vec::with_capacity(HEADER_BYTES as usize);
        header.extend_from_slice(&JOURNAL_MAGIC);
        header.extend_from_slice(&JOURNAL_FORMAT_VERSION.to_le_bytes());
        header.extend_from_slice(&epoch.0);
        let staging_path = state_dir.join(format!("{JOURNAL_FILE_NAME}.new"));
        {
            let mut staging = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&staging_path)?;
            staging.write_all(&header)?;
            staging.sync_all()?;
        }
        std::fs::rename(&staging_path, &journal_path)?;
        sync_dir(state_dir)?;
        let epoch_staging = state_dir.join(format!("{EPOCH_FILE_NAME}.new"));
        {
            let mut staging = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&epoch_staging)?;
            staging.write_all(format!("{}\n", epoch.to_hex()).as_bytes())?;
            staging.sync_all()?;
        }
        std::fs::rename(&epoch_staging, &epoch_path)?;
        sync_dir(state_dir)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&journal_path)?;
        Ok(Self {
            path: journal_path,
            file,
            epoch,
            length: HEADER_BYTES,
            poisoned: false,
            append_fault: None,
        })
    }

    /// The epoch this journal was made with.
    #[must_use]
    pub fn epoch(&self) -> JournalEpoch {
        self.epoch
    }

    /// Whether an append could not be rolled back.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// The file's length: the header and every whole record.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.length
    }

    /// Whether the journal holds no record.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.length == HEADER_BYTES
    }

    /// Sets the hook that runs between an append's write and its sync.
    pub fn set_append_fault(&mut self, fault: Option<JournalAppendFault>) {
        self.append_fault = fault;
    }

    /// Appends one record and syncs it to disk before it returns.
    ///
    /// # Errors
    ///
    /// [`JournalAppendError`]: the record is not in the journal.
    pub fn append(&mut self, payload: &[u8]) -> Result<(), JournalAppendError> {
        if self.poisoned {
            return Err(JournalAppendError::Poisoned);
        }
        let Ok(payload_length) = u32::try_from(payload.len()) else {
            return Err(JournalAppendError::TooLarge {
                bytes: payload.len(),
            });
        };
        if payload_length > MAX_FRAME_PAYLOAD_BYTES {
            return Err(JournalAppendError::TooLarge {
                bytes: payload.len(),
            });
        }
        let frame = frame(payload_length, payload);
        let start = self.length;
        let written = self
            .file
            .seek(SeekFrom::Start(start))
            .and_then(|_| self.file.write_all(&frame))
            .and_then(|()| match &self.append_fault {
                Some(fault) => fault(),
                None => Ok(()),
            })
            .and_then(|()| self.file.sync_data());
        match written {
            Ok(()) => {
                self.length = start + frame.len() as u64;
                Ok(())
            }
            Err(error) => match self
                .file
                .set_len(start)
                .and_then(|()| self.file.sync_data())
            {
                Ok(()) => Err(JournalAppendError::RolledBack(error)),
                Err(_) => {
                    self.poisoned = true;
                    Err(JournalAppendError::Poisoned)
                }
            },
        }
    }
}

fn frame(payload_length: u32, payload: &[u8]) -> Vec<u8> {
    let length = payload_length.to_le_bytes();
    let mut frame =
        Vec::with_capacity(payload.len() + (FRAME_HEAD_BYTES + CHECKSUM_BYTES) as usize);
    frame.extend_from_slice(&length);
    frame.extend_from_slice(&length_check(&length));
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&frame_checksum(&length, payload));
    frame
}

fn length_check(length: &[u8; 4]) -> [u8; LENGTH_CHECK_BYTES as usize] {
    let hash = ContentHash::of(length);
    let mut check = [0u8; LENGTH_CHECK_BYTES as usize];
    check.copy_from_slice(&hash.as_bytes()[..LENGTH_CHECK_BYTES as usize]);
    check
}

fn frame_checksum(length: &[u8; 4], payload: &[u8]) -> [u8; CHECKSUM_BYTES as usize] {
    let hash = ContentHasher::new().update(length).update(payload).finish();
    let mut checksum = [0u8; CHECKSUM_BYTES as usize];
    checksum.copy_from_slice(&hash.as_bytes()[..CHECKSUM_BYTES as usize]);
    checksum
}

struct ParsedJournal {
    records: Vec<Vec<u8>>,
    /// The length of the header and every whole record.
    whole_length: u64,
}

fn parse_journal(bytes: &[u8], file_epoch: JournalEpoch) -> Result<ParsedJournal, JournalDamage> {
    if (bytes.len() as u64) < HEADER_BYTES || bytes[..8] != JOURNAL_MAGIC {
        return Err(JournalDamage::BadHeader);
    }
    let mut version = [0u8; 4];
    version.copy_from_slice(&bytes[8..12]);
    let version = u32::from_le_bytes(version);
    if version != JOURNAL_FORMAT_VERSION {
        return Err(JournalDamage::UnknownFormat { found: version });
    }
    let mut journal_epoch = [0u8; EPOCH_BYTES];
    journal_epoch.copy_from_slice(&bytes[12..HEADER_BYTES as usize]);
    let journal_epoch = JournalEpoch(journal_epoch);
    if journal_epoch != file_epoch {
        return Err(JournalDamage::EpochMismatch {
            journal: journal_epoch.to_hex(),
            file: file_epoch.to_hex(),
        });
    }
    let mut records = Vec::new();
    let mut offset = HEADER_BYTES as usize;
    while offset < bytes.len() {
        let rest = &bytes[offset..];
        if rest.iter().all(|byte| *byte == 0) {
            break;
        }
        if (rest.len() as u64) < FRAME_HEAD_BYTES {
            break;
        }
        let mut length = [0u8; 4];
        length.copy_from_slice(&rest[..4]);
        if rest[LENGTH_BYTES as usize..FRAME_HEAD_BYTES as usize] != length_check(&length) {
            // A length whose check was never written (the rest is zero) is a
            // torn write; any other mismatch is a damaged length.
            if rest[LENGTH_BYTES as usize..].iter().all(|byte| *byte == 0) {
                break;
            }
            return Err(JournalDamage::BadFrame {
                offset: offset as u64,
            });
        }
        let payload_length = u64::from(u32::from_le_bytes(length));
        let frame_length = FRAME_HEAD_BYTES + payload_length + CHECKSUM_BYTES;
        // No frame this build wrote is longer than the limit, so such a length
        // is damage, not a torn write.
        if payload_length > u64::from(MAX_FRAME_PAYLOAD_BYTES) {
            return Err(JournalDamage::BadFrame {
                offset: offset as u64,
            });
        }
        // The length passed its check, so a frame that runs past the end is
        // one whose append never completed.
        if (rest.len() as u64) < frame_length {
            break;
        }
        let payload_end = (FRAME_HEAD_BYTES + payload_length) as usize;
        let payload = &rest[FRAME_HEAD_BYTES as usize..payload_end];
        let checksum = &rest[payload_end..frame_length as usize];
        if frame_checksum(&length, payload)[..] != *checksum {
            return Err(JournalDamage::BadFrame {
                offset: offset as u64,
            });
        }
        records.push(payload.to_vec());
        offset += frame_length as usize;
    }
    Ok(ParsedJournal {
        records,
        whole_length: offset as u64,
    })
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}
