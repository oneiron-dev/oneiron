//! Containers the secret mask reads into (OF-067 C, owner ruling G04 binary
//! = C2): a ZIP archive (Office, OpenDocument and the other ZIP-family
//! files), a gzip file, a tar archive, an xz file (FIX 2471), a 7z archive
//! (FIX 11575) and a PDF's streams and text strings. The write door
//! reads each member as it reads a body, and a member's keys are placed at
//! their spans in the decoded member. A reader the owner has not granted gets
//! a copy rebuilt around the overwritten keys, each key in a text member
//! standing as its custody handle (FIX 7944); the stored bytes never change.
//!
//! One walk serves the write door, the release scan and the rebuild, its
//! frames on the heap ([`retained_iterative`]), under one floor of decoded
//! bytes for a file's whole tree. No count of members, objects or nesting
//! ends it (FIX 7943): a container met inside itself is a cycle, and a
//! central directory that declares more entries than its bytes can hold is
//! malformed. A container the walk cannot read whole (malformed, failing a
//! checksum, encrypted, in a method or filter no reader here decodes, or
//! past the byte floor) is sealed ([`is_sealed`]): the write door stores it
//! as it is and leaves it unmarked (owner ruling C2, "encrypted files are
//! stored as they are"), a serving door gives it to the owner and refuses it
//! to a masked reader, and every release door reads it as a hit.
//!
//! The bytes no reader shows (a PDF's superseded revisions, a ZIP's bytes
//! outside its central directory's entries) are read by the scans alone
//! (FIX 2470): a release door and a masked read of an unmarked file read
//! them, and the rebuilt copy leaves them out, so no mark is placed there.
//! An unmarked container whose only key sits in them at its root is served
//! its copy rebuilt at the root without them (FIX 11553, 12268).
//!
//! A container is known by its leading bytes, never by its name, and text
//! with a container's leading bytes is one only when it parses as one (FIX
//! 2474). A RAR file is read as plain bytes (FIX 2471, 11575); a ZIP that
//! starts past a file's first byte opens through the zip crate's own offset
//! handling.

pub mod archive;
pub mod gzip;
pub mod pdf;
pub mod projection_edit;
pub mod retained_iterative;
pub mod sevenz;
pub mod tar;
pub mod xz;

pub use crate::batch::secret_scan::container::projection_edit::RetainedProjectionEdit;

use crate::file_secret_marks::KeyPlaces;
use crate::file_secret_marks::MemberStep;
use crate::file_secret_marks::PlaceHandles;
use crate::file_secret_marks::masked_copy_withheld;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

/// The least bytes all of a file's members may decode to over its whole
/// tree: the fixed minimum of what one walk holds, on any machine. A
/// rebuilt copy is held to the walk's floor too. The floor a walk actually
/// holds is [`expanded_floor`]: this minimum, raised by the memory the
/// machine measures free (FIX 7943).
const MAX_EXPANDED_BYTES: usize = 512 * 1024 * 1024;

/// The free memory a walk leaves untouched: the larger of 256 MiB and a
/// sixteenth of the machine's memory, as the carrier join leaves it.
const EXPANDED_RESERVE_FLOOR_BYTES: u64 = 256 << 20;

/// The bytes all of a file's members may decode to over its whole tree on
/// this machine now (FIX 7943): the fixed minimum, or the memory measured
/// free past the reserve above when that is more. Raise-only, so a file a
/// walk serves on the fixed floor is served on every machine; where no
/// memory reads, the fixed minimum stands. Read at each walk's start, as
/// the probes are read live.
pub fn expanded_floor() -> usize {
    use oneiron_contracts::limit_ask::{available_memory_bytes, machine_memory_bytes};
    let reserve = machine_memory_bytes().map_or(EXPANDED_RESERVE_FLOOR_BYTES, |total| {
        (total / 16).max(EXPANDED_RESERVE_FLOOR_BYTES)
    });
    let fixed = MAX_EXPANDED_BYTES as u64;
    let floor =
        available_memory_bytes().map_or(fixed, |room| room.saturating_sub(reserve).max(fixed));
    usize::try_from(floor).unwrap_or(usize::MAX)
}

/// The keys one file may carry; the write door refuses a file with more.
pub const MAX_FILE_KEYS: usize = 10_000;

/// A container no reader here reads whole: malformed, truncated, failing a
/// checksum, encrypted, holding one name twice, or in a compression method
/// or PDF filter not decoded here.
pub const REASON_UNREADABLE: &str = "gate.secret_scan.container_unreadable";
/// A container whose members decode past the byte floor above.
pub const REASON_OVER_BUDGET: &str = "gate.secret_scan.container_over_budget";
/// A container a walk meets inside itself: its whole bytes are those of a
/// container the walk is already inside (FIX 8031). An integrity stop, not a
/// bound: the walk reads no further down it.
const REASON_ARCHIVE_CYCLE: &str = "gate.secret_scan.archive_cycle";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Zip,
    Gzip,
    // FIX 2471: a tar archive and an xz file.
    Tar,
    Xz,
    // FIX 11575: a 7z archive.
    SevenZip,
    Pdf,
}

/// The container `bytes` lead as: the head test alone.
pub fn kind(bytes: &[u8]) -> Option<Kind> {
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        Some(Kind::Zip)
    } else if bytes.starts_with(&[0x1f, 0x8b, 0x08]) {
        Some(Kind::Gzip)
    } else if bytes.starts_with(b"%PDF-") && bytes.get(5).is_some_and(u8::is_ascii_digit) {
        Some(Kind::Pdf)
    } else if bytes.len() >= 512
        && bytes
            .get(257..)
            .is_some_and(|magic| magic.starts_with(b"ustar"))
    {
        // FIX 2471: a ustar header.
        Some(Kind::Tar)
    } else if bytes.starts_with(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]) {
        // FIX 2471: an xz stream.
        Some(Kind::Xz)
    } else if bytes.starts_with(&sevenz::SIGNATURE) {
        // FIX 11575: a 7z signature header.
        Some(Kind::SevenZip)
    } else {
        None
    }
}

/// The container the walk reads `bytes` as (FIX 2474): the head's, save
/// that UTF-8 text is a container only when its frame parses (a ZIP's end
/// record and central directory, a tar's first header checksum, a PDF's
/// header, cross-reference and trailer). A credential line or a string that
/// only starts like one reads as text. Binary bytes keep the head's: a
/// malformed container stays sealed. A gzip file's second byte is no UTF-8.
pub fn classify(bytes: &[u8]) -> Option<Kind> {
    let Some(head) = kind(bytes) else {
        // FIX 2471: a ZIP that starts past byte 0 opens through the zip
        // crate's own offset handling; binary bytes only.
        if std::str::from_utf8(bytes).is_err() && archive::opens(bytes) {
            return Some(Kind::Zip);
        }
        return None;
    };
    if std::str::from_utf8(bytes).is_err() {
        return Some(head);
    }
    let parses = match head {
        Kind::Zip => archive::opens(bytes),
        Kind::Gzip => true,
        // FIX 11575: a 7z signature's third byte is no UTF-8.
        Kind::SevenZip => true,
        Kind::Tar => tar::opens(bytes),
        Kind::Xz => true,
        Kind::Pdf => pdf::opens(bytes),
    };
    parses.then_some(head)
}

/// Whether `bytes` lead as a container: the head pre-filter a reader that
/// holds only a body's first bytes takes. The walk reads `bytes` as the
/// classification above does.
pub fn is_container(bytes: &[u8]) -> bool {
    // FIX 2471: a prefixed ZIP opens through the zip crate's own offset handling.
    kind(bytes).is_some() || (std::str::from_utf8(bytes).is_err() && archive::opens(bytes))
}

/// Whether a key's span is placed in `bytes` as they are: plain bytes, and a
/// PDF, whose own bytes hold its uncompressed objects. A ZIP, gzip, tar, xz
/// or 7z file is rebuilt from its members, so a key in one is placed in the
/// member (FIX 2471, 11575).
pub fn holds_spans(bytes: &[u8]) -> bool {
    !matches!(
        classify(bytes),
        Some(Kind::Zip | Kind::Gzip | Kind::Tar | Kind::Xz | Kind::SevenZip)
    )
}

/// Whether a key at `path` in the member `bytes` stands as its handle text
/// in a masked copy (FIX 7944): the UTF-8 text of a ZIP entry, a gzip
/// payload, a tar entry, an xz payload, a 7z entry (FIX 2471, 11575), a PDF content stream
/// (FIX 11550) or a PDF object's strings, each encoded again around its new
/// length. The stored bytes' own spans, a binary member's, a PDF object
/// stream's (it names its objects by byte offset) and a PDF's own bytes
/// (its cross-reference does) keep the filler's width.
pub fn writes_handles(path: &[MemberStep], bytes: &[u8]) -> bool {
    matches!(
        path.last(),
        Some(
            MemberStep::Zip { .. }
                | MemberStep::Gzip
                | MemberStep::Tar { .. }
                | MemberStep::Xz
                | MemberStep::SevenZip { .. }
                | MemberStep::PdfStream { .. }
                | MemberStep::PdfStrings { .. }
        )
    ) && std::str::from_utf8(bytes).is_ok()
        && classify(bytes).is_none()
}

/// Why a walk stopped before the end of a file's tree.
pub enum Stop {
    /// The door refuses the file with this reason code: a hit, or a
    /// container read no further ([`REASON_UNREADABLE`],
    /// [`REASON_OVER_BUDGET`], [`REASON_ARCHIVE_CYCLE`]).
    Refuse(&'static str),
    /// The engine failed, or a reader's own scan refused.
    Fail(Error),
}

impl From<Error> for Stop {
    fn from(error: Error) -> Self {
        Self::Fail(error)
    }
}

pub type Walked<T> = std::result::Result<T, Stop>;

pub fn unreadable() -> Stop {
    Stop::Refuse(REASON_UNREADABLE)
}

pub fn over_budget() -> Stop {
    Stop::Refuse(REASON_OVER_BUDGET)
}

/// A copy the rebuild could not encode.
pub fn encode_failed() -> Stop {
    Stop::Fail(Error::InvariantViolation(
        "a masked container copy did not encode",
    ))
}

/// A serving door's error for a masked copy that stopped (FIX 2475): a
/// file this reader cannot be served masked is the typed refusal, and an
/// engine failure stays its own error.
pub fn withheld(stop: Stop) -> Error {
    match stop {
        Stop::Refuse(reason) => masked_copy_withheld(reason),
        Stop::Fail(error) => error,
    }
}

/// How a walk reads a file's tree.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ContainerReadMode {
    /// The write door's, release doors' and serving doors' read: the byte
    /// floor holds.
    Generic,
    /// A retained repository blob's read (FIX 7608, rule 5): no byte floor.
    /// The same decoders read it, with every integrity check theirs
    /// (declared lengths, CRCs, duplicate names, methods, filters,
    /// encryption, cross-references); what stops it is a container no
    /// reader here reads, or the machine.
    RetainedRepo,
}

/// What a walk over one file's tree has left. A member's own walk spends
/// from it; none starts a budget of its own. A retained repository read
/// spends none of it. Every walk keeps the containers it is inside.
pub struct Budget {
    pub mode: ContainerReadMode,
    /// The walk's own byte floor ([`expanded_floor`] at its start): what
    /// `expanded` counts down from, and what a rebuilt copy is held to.
    pub floor: usize,
    pub expanded: usize,
    /// Whether the walk also reads the bytes no reader shows (FIX 2470): a
    /// PDF's superseded revisions and a ZIP's bytes outside its central
    /// directory's entries. Only a scan reads them; a mark or a rebuild never
    /// does.
    pub hidden: bool,
    /// The BLAKE3 of each container the walk is inside, the file first: this
    /// walk's own, never kept or logged.
    pub ancestors: Vec<[u8; 32]>,
    /// The walk's root file's checked BLAKE3, taken for the root
    /// container's entry instead of hashing the file again (FIX 12270).
    /// `None` hashes as before.
    pub root_digest: Option<[u8; 32]>,
}

impl Budget {
    pub fn new() -> Self {
        Self::of(ContainerReadMode::Generic)
    }

    pub fn of(mode: ContainerReadMode) -> Self {
        let floor = expanded_floor();
        Self {
            mode,
            floor,
            expanded: floor,
            hidden: false,
            ancestors: Vec::new(),
            root_digest: None,
        }
    }

    /// This budget, its walk reading the bytes no reader shows too.
    pub fn reading_hidden(mut self) -> Self {
        self.hidden = true;
        self
    }

    /// This budget, its walk taking the root container's entry from
    /// `digest`, the BLAKE3 the caller checked the file against (FIX 12270).
    pub fn with_root_digest(mut self, digest: Option<&[u8; 32]>) -> Self {
        self.root_digest = digest.copied();
        self
    }

    /// Whether the byte floor holds for this walk.
    pub fn capped(&self) -> bool {
        self.mode == ContainerReadMode::Generic
    }

    /// The most bytes the next member may decode to: the machine's most
    /// when no floor holds.
    pub fn limit(&self) -> usize {
        if self.capped() {
            self.expanded
        } else {
            usize::MAX
        }
    }

    /// The most bytes a PDF's loader may decompress one stream to; `None`
    /// when no floor holds.
    pub fn decompressed_ceiling(&self) -> Option<usize> {
        self.capped().then_some(self.expanded)
    }

    /// Whether a rebuilt copy of `len` bytes is past the byte floor.
    pub fn copy_over(&self, len: usize) -> bool {
        self.capped() && len > self.floor
    }

    /// Charges `len` decoded bytes.
    pub fn spend(&mut self, len: usize) -> Walked<()> {
        if self.capped() {
            self.expanded = self.expanded.checked_sub(len).ok_or_else(over_budget)?;
        }
        Ok(())
    }

    /// Enters the container whose whole bytes are `bytes`, before its
    /// members are read (FIX 8031). A walk already inside a container of the
    /// same bytes has met a cycle, and reads no further down it. Each entry
    /// is left once its members are read, so a container met again beside
    /// itself is read again.
    pub fn enter_container(&mut self, bytes: &[u8]) -> Walked<()> {
        // The walk enters its root file first, so the first entry takes
        // the caller's checked digest instead of hashing the file again;
        // members hash as before (FIX 12270).
        let digest = match self.root_digest.take() {
            Some(digest) => {
                debug_assert!(
                    blake3::hash(bytes).as_bytes() == &digest,
                    "a caller's root digest names other bytes"
                );
                digest
            }
            None => *blake3::hash(bytes).as_bytes(),
        };
        if self.ancestors.contains(&digest) {
            return Err(Stop::Refuse(REASON_ARCHIVE_CYCLE));
        }
        self.ancestors.push(digest);
        Ok(())
    }

    /// Leaves the container entered last.
    pub fn leave_container(&mut self) {
        self.ancestors.pop();
    }
}
