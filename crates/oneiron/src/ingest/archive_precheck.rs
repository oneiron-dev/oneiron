//! The pass an import makes over an archive's own entry list before it reads
//! or writes anything of it (ARCH-0027 #archive-precheck; CROSS-ARCH-0024
//! #onboarding-import 01-05). One deterministic pass over the central
//! directory, in its own order:
//!
//! - the archive starts as a zip, and the entry count its end records
//!   declare is refused past the caller's cap before the `zip` reader sizes
//!   its tables by it;
//! - an entry whose path would leave the import folder, a symbolic link, and
//!   a device file, FIFO or socket are skipped and listed; every other entry
//!   is kept, its mode stripped of the set-uid, set-gid and sticky bits;
//! - a name held twice is refused: the reader keeps one entry per name;
//! - entries whose bytes overlap, or run into the central directory, are
//!   refused: the "better zip bomb" shape Info-ZIP fixed for CVE-2019-13232.
//!
//! Each kept entry is then read under a bound: a declared size past it is
//! refused before anything is inflated, the first bytes are checked against
//! the reader that will parse them, and the real bytes are counted against
//! the bound whatever the header said.
//!
//! The pass writes nothing and hands out only enclosed paths
//! (`enclosed_name`), so an unpacker built on it never writes outside its
//! folder and never follows a link. The same bytes always give the same
//! entries, skips and refusal.

use std::collections::HashSet;
use std::fmt;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::PathBuf;

use oneiron_store::batch::secret_scan::container::archive::declared_zip_entries;
use serde::{Deserialize, Serialize};
use zip::ZipArchive;
use zip::read::ZipFile;

/// The first bytes of a zip: a local entry, or the end record of an empty
/// archive.
const ZIP_LOCAL_ENTRY: &[u8; 4] = b"PK\x03\x04";
const ZIP_EMPTY_ARCHIVE: &[u8; 4] = b"PK\x05\x06";
/// A central directory entry's least length: no archive holds more entries
/// than its bytes hold at this length.
const CENTRAL_ENTRY_LEN: u64 = 46;
/// How much of an entry the magic check reads before the rest streams.
const MAGIC_PREFIX_LEN: u64 = 512;
/// The most of an entry's name a skip or a refusal repeats.
const NAME_LABEL_MAX: usize = 512;
/// The UTF-8 byte-order mark a JSON file may start with.
const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

/// A unix mode's file-type bits, and the types the pass tells apart.
const FILE_TYPE_BITS: u32 = 0o170_000;
const SYMBOLIC_LINK: u32 = 0o120_000;
const CHARACTER_DEVICE: u32 = 0o020_000;
const BLOCK_DEVICE: u32 = 0o060_000;
const FIFO: u32 = 0o010_000;
const SOCKET: u32 = 0o140_000;
/// The bits a kept entry's mode keeps: permissions, never set-uid, set-gid
/// or sticky.
const PERMISSION_BITS: u32 = 0o777;

/// What the pass bounds before it reads the entry list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveBounds {
    /// The most entries the archive may declare.
    pub max_entries: u64,
}

/// An entry the pass kept.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckedEntry {
    /// The entry's place in the central directory.
    pub index: usize,
    /// Its path, enclosed: never absolute, never above the archive's root.
    pub path: PathBuf,
    /// The size its central directory entry declares; the read counts the
    /// real bytes all the same.
    pub declared_size: u64,
    /// Its unix permission bits, when the archive records a mode.
    pub mode: Option<u32>,
    /// Whether it is a directory entry, which holds no bytes to read.
    pub directory: bool,
}

/// An entry the pass skipped, and why. Nothing of it is read.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkippedEntry {
    /// Its name as the archive gives it, at most 512 bytes.
    pub name: String,
    pub reason: SkipReason,
}

/// Why the pass skipped an entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// Its path is absolute, or climbs above the archive's root.
    EscapingPath,
    /// A symbolic link: never followed.
    SymbolicLink,
    /// A character or block device, a FIFO or a socket.
    SpecialFile,
}

impl SkipReason {
    /// The reason's name in a report.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EscapingPath => "escaping_path",
            Self::SymbolicLink => "symbolic_link",
            Self::SpecialFile => "special_file",
        }
    }
}

/// The reader that will parse an entry, whose first bytes the read checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryReader {
    /// A JSON document: an optional UTF-8 byte-order mark and whitespace,
    /// then `{` or `[`.
    Json,
    /// An mbox: empty, or a `From ` separator first.
    Mbox,
}

impl EntryReader {
    fn name(self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Mbox => "mbox",
        }
    }

    /// Whether `prefix`, an entry's first bytes (all of it when `whole`),
    /// starts as this reader's input.
    fn admits(self, prefix: &[u8], whole: bool) -> bool {
        match self {
            Self::Json => {
                let text = prefix.strip_prefix(UTF8_BOM).unwrap_or(prefix);
                text.iter()
                    .find(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
                    .is_some_and(|first| matches!(first, b'{' | b'['))
            }
            Self::Mbox => (whole && prefix.is_empty()) || prefix.starts_with(b"From "),
        }
    }
}

/// Why the pass refused an archive or an entry's read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArchiveRefusal {
    /// The file does not start as a zip, or no end record reads.
    NotAZip,
    /// The end records declare more entries than the cap.
    TooManyEntries { declared: u64, cap: u64 },
    /// Two entries hold one name.
    DuplicateName { name: String },
    /// Two entries' bytes overlap.
    OverlappingEntries { first: String, second: String },
    /// An entry's bytes run into the central directory.
    EntryRunsIntoDirectory { name: String },
    /// An entry does not start as the reader that would parse it expects.
    WrongMagic { name: String, reader: EntryReader },
    /// An entry declares or holds more than its read's bound.
    PastBound { name: String, bound: u64 },
    /// The archive or an entry does not read.
    Unreadable { detail: String },
}

impl fmt::Display for ArchiveRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAZip => write!(f, "not a zip archive: no zip signature or end record"),
            Self::TooManyEntries { declared, cap } => {
                write!(
                    f,
                    "declares {declared} entries, past the entry cap of {cap}"
                )
            }
            Self::DuplicateName { name } => write!(f, "holds two entries named {name:?}"),
            Self::OverlappingEntries { first, second } => write!(
                f,
                "overlapping entries: {first:?} and {second:?} share bytes"
            ),
            Self::EntryRunsIntoDirectory { name } => write!(
                f,
                "overlapping entries: {name:?} runs into the central directory"
            ),
            Self::WrongMagic { name, reader } => write!(
                f,
                "magic bytes: {name:?} does not start as {} input, so the {} reader \
                 does not read it",
                reader.name(),
                reader.name()
            ),
            Self::PastBound { name, bound } => {
                write!(f, "{name:?} holds more than {bound} bytes")
            }
            Self::Unreadable { detail } => write!(f, "unreadable: {detail}"),
        }
    }
}

impl std::error::Error for ArchiveRefusal {}

/// An archive the pass checked: its kept entries, read only through
/// [`CheckedArchive::open_entry`], and its skipped ones.
pub struct CheckedArchive<R> {
    archive: ZipArchive<R>,
    entries: Vec<CheckedEntry>,
    skipped: Vec<SkippedEntry>,
}

/// Runs the pass over `source`. Nothing of any entry is inflated.
pub fn check_archive<R: Read + Seek>(
    mut source: R,
    bounds: ArchiveBounds,
) -> Result<CheckedArchive<R>, ArchiveRefusal> {
    starts_as_zip(&mut source)?;
    let declared = declared_zip_entries(&mut source).ok_or(ArchiveRefusal::NotAZip)?;
    if declared > bounds.max_entries {
        return Err(ArchiveRefusal::TooManyEntries {
            declared,
            cap: bounds.max_entries,
        });
    }
    let length = source.seek(SeekFrom::End(0)).map_err(unreadable)?;
    if declared > length / CENTRAL_ENTRY_LEN {
        return Err(ArchiveRefusal::Unreadable {
            detail: format!("declares {declared} entries, more than its {length} bytes hold"),
        });
    }
    let mut archive = ZipArchive::new(source).map_err(unreadable)?;
    let walked = walk(&mut archive)?;
    walked.refuse_overlaps()?;
    Ok(CheckedArchive {
        archive,
        entries: walked.entries,
        skipped: walked.skipped,
    })
}

impl<R: Read + Seek> CheckedArchive<R> {
    /// The kept entries, in central-directory order.
    pub fn entries(&self) -> &[CheckedEntry] {
        &self.entries
    }

    /// The skipped entries, in central-directory order.
    pub fn skipped(&self) -> &[SkippedEntry] {
        &self.skipped
    }

    /// The skipped entries, for a report.
    pub fn into_skipped(self) -> Vec<SkippedEntry> {
        self.skipped
    }

    /// Opens kept entry `at` (its place in [`Self::entries`]) for `reader`,
    /// to at most `bound` bytes. A declared size past the bound is refused
    /// before anything is inflated, the first bytes are checked against
    /// `reader` before the rest streams, and a read past `bound` real bytes
    /// fails with [`ArchiveRefusal::PastBound`] (inside the `io::Error`;
    /// [`refusal_of`] takes it out).
    pub fn open_entry(
        &mut self,
        at: usize,
        reader: EntryReader,
        bound: u64,
    ) -> Result<CheckedRead<'_>, ArchiveRefusal> {
        let entry = self
            .entries
            .get(at)
            .ok_or_else(|| ArchiveRefusal::Unreadable {
                detail: format!("no kept entry {at}"),
            })?;
        let name = label(&entry.path.to_string_lossy());
        if entry.declared_size > bound {
            return Err(ArchiveRefusal::PastBound { name, bound });
        }
        let mut file = self.archive.by_index(entry.index).map_err(unreadable)?;
        let wanted = MAGIC_PREFIX_LEN.min(bound.saturating_add(1));
        let mut prefix = Vec::new();
        file.by_ref()
            .take(wanted)
            .read_to_end(&mut prefix)
            .map_err(unreadable)?;
        let held = u64::try_from(prefix.len()).unwrap_or(u64::MAX);
        if held > bound {
            return Err(ArchiveRefusal::PastBound { name, bound });
        }
        if !reader.admits(&prefix, held < wanted) {
            return Err(ArchiveRefusal::WrongMagic { name, reader });
        }
        Ok(CheckedRead {
            prefix: Cursor::new(prefix),
            rest: file,
            counted: 0,
            bound,
            name,
        })
    }

    /// Kept entry `at`, read whole as [`Self::open_entry`] reads it.
    pub fn read_entry(
        &mut self,
        at: usize,
        reader: EntryReader,
        bound: u64,
    ) -> Result<Vec<u8>, ArchiveRefusal> {
        let mut read = self.open_entry(at, reader, bound)?;
        let mut bytes = Vec::new();
        read.read_to_end(&mut bytes).map_err(refusal_of)?;
        Ok(bytes)
    }
}

/// A kept entry's bytes: the checked first bytes, then the rest, every byte
/// counted against the bound.
pub struct CheckedRead<'a> {
    prefix: Cursor<Vec<u8>>,
    rest: ZipFile<'a>,
    counted: u64,
    bound: u64,
    name: String,
}

impl Read for CheckedRead<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut got = self.prefix.read(buf)?;
        if got == 0 {
            got = self.rest.read(buf)?;
        }
        self.counted = self
            .counted
            .saturating_add(u64::try_from(got).unwrap_or(u64::MAX));
        if self.counted > self.bound {
            return Err(io::Error::other(ArchiveRefusal::PastBound {
                name: self.name.clone(),
                bound: self.bound,
            }));
        }
        Ok(got)
    }
}

/// The refusal a [`CheckedRead`] failed with, or the read's own error as
/// [`ArchiveRefusal::Unreadable`].
pub fn refusal_of(error: io::Error) -> ArchiveRefusal {
    let detail = error.to_string();
    error
        .into_inner()
        .and_then(|inner| inner.downcast::<ArchiveRefusal>().ok())
        .map_or(ArchiveRefusal::Unreadable { detail }, |refusal| *refusal)
}

/// The archive starts as a zip: a local entry, or an empty archive's end
/// record. Read before the end records, so no other file is searched.
fn starts_as_zip<R: Read + Seek>(source: &mut R) -> Result<(), ArchiveRefusal> {
    let mut head = [0_u8; 4];
    source.seek(SeekFrom::Start(0)).map_err(unreadable)?;
    source
        .read_exact(&mut head)
        .map_err(|_| ArchiveRefusal::NotAZip)?;
    if &head == ZIP_LOCAL_ENTRY || &head == ZIP_EMPTY_ARCHIVE {
        Ok(())
    } else {
        Err(ArchiveRefusal::NotAZip)
    }
}

/// The central directory, walked once in its own order.
struct Walked {
    entries: Vec<CheckedEntry>,
    skipped: Vec<SkippedEntry>,
    /// Each entry's name, by its place in the central directory.
    names: Vec<String>,
    /// Each entry's bytes, local header to the end of its data, and its
    /// place in the central directory.
    ranges: Vec<(u64, u64, usize)>,
    /// Where the central directory starts: its first entry.
    directory_start: u64,
}

fn walk<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Result<Walked, ArchiveRefusal> {
    let mut walked = Walked {
        entries: Vec::new(),
        skipped: Vec::new(),
        names: Vec::with_capacity(archive.len()),
        ranges: Vec::with_capacity(archive.len()),
        directory_start: u64::MAX,
    };
    let mut seen = HashSet::with_capacity(archive.len());
    for index in 0..archive.len() {
        // The raw entry: its local header is read for where its data
        // starts, and nothing is inflated.
        let entry = archive.by_index_raw(index).map_err(unreadable)?;
        let name = entry.name().to_owned();
        if !seen.insert(name.clone()) {
            return Err(ArchiveRefusal::DuplicateName { name: label(&name) });
        }
        walked.ranges.push((
            entry.header_start(),
            entry.data_start().saturating_add(entry.compressed_size()),
            index,
        ));
        walked.directory_start = walked.directory_start.min(entry.central_header_start());
        match kept(&entry, index) {
            Ok(kept) => walked.entries.push(kept),
            Err(reason) => walked.skipped.push(SkippedEntry {
                name: label(&name),
                reason,
            }),
        }
        walked.names.push(name);
    }
    Ok(walked)
}

/// Entry `index` as kept, or why it is skipped. An escaping path is named
/// before a link or a special file.
fn kept(entry: &ZipFile<'_>, index: usize) -> Result<CheckedEntry, SkipReason> {
    let path = entry
        .enclosed_name()
        .ok_or(SkipReason::EscapingPath)?
        .to_path_buf();
    let mode = entry.unix_mode();
    match mode.map(|mode| mode & FILE_TYPE_BITS) {
        Some(SYMBOLIC_LINK) => return Err(SkipReason::SymbolicLink),
        Some(CHARACTER_DEVICE | BLOCK_DEVICE | FIFO | SOCKET) => {
            return Err(SkipReason::SpecialFile);
        }
        _ => {}
    }
    Ok(CheckedEntry {
        index,
        path,
        declared_size: entry.size(),
        mode: mode.map(|mode| mode & PERMISSION_BITS),
        directory: entry.is_dir(),
    })
}

impl Walked {
    /// Refuses entries whose bytes overlap, skipped ones too, and an entry
    /// that runs into the central directory. Ranges are taken in order of
    /// where they start, then of their place in the central directory.
    fn refuse_overlaps(&self) -> Result<(), ArchiveRefusal> {
        let mut ranges = self.ranges.clone();
        ranges.sort_unstable_by_key(|&(start, _, index)| (start, index));
        let mut reach: Option<(u64, usize)> = None;
        for &(start, end, index) in &ranges {
            if let Some((reached, by)) = reach
                && start < reached
            {
                return Err(ArchiveRefusal::OverlappingEntries {
                    first: self.label_of(by),
                    second: self.label_of(index),
                });
            }
            if end > self.directory_start {
                return Err(ArchiveRefusal::EntryRunsIntoDirectory {
                    name: self.label_of(index),
                });
            }
            if reach.is_none_or(|(reached, _)| end > reached) {
                reach = Some((end, index));
            }
        }
        Ok(())
    }

    fn label_of(&self, index: usize) -> String {
        self.names
            .get(index)
            .map(String::as_str)
            .map_or_else(String::new, label)
    }
}

/// At most [`NAME_LABEL_MAX`] bytes of `name`, cut on a character boundary.
fn label(name: &str) -> String {
    let mut end = name.len().min(NAME_LABEL_MAX);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    name[..end].to_owned()
}

fn unreadable(error: impl fmt::Display) -> ArchiveRefusal {
    ArchiveRefusal::Unreadable {
        detail: error.to_string(),
    }
}
