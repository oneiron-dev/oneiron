//! Containers the secret mask reads into (OF-067 C, owner ruling G04 binary
//! = C2): a ZIP archive (Office, OpenDocument and the other ZIP-family
//! files), a gzip file, a tar archive, an xz file (FIX 2471) and a PDF's
//! streams and text strings. The write door
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
//!
//! A container is known by its leading bytes, never by its name, and text
//! with a container's leading bytes is one only when it parses as one (FIX
//! 2474). A 7z or RAR file is read as plain bytes (FIX 2471); a ZIP that
//! starts past a file's first byte opens through the zip crate's own offset
//! handling.

mod archive;
mod gzip;
mod pdf;
mod projection_edit;
mod retained_iterative;
mod tar;
mod xz;

pub(crate) use self::projection_edit::{
    RetainedProjectionEdit, apply_retained_repo_projection_diff,
};

use super::{release_hit, scan_payload, secret_scan_error, write_payload_hit};
use crate::error::{Error, Result};
use crate::secret_custody::{KeyPlaces, MemberStep, PlaceHandles, masked_copy_withheld};

/// The bytes all of a file's members may decode to over its whole tree: the
/// floor of what one walk holds. A rebuilt copy is held to it too.
const MAX_EXPANDED_BYTES: usize = 512 * 1024 * 1024;
/// The keys one file may carry; the write door refuses a file with more.
pub(super) const MAX_FILE_KEYS: usize = 10_000;

/// A container no reader here reads whole: malformed, truncated, failing a
/// checksum, encrypted, holding one name twice, or in a compression method
/// or PDF filter not decoded here.
pub(super) const REASON_UNREADABLE: &str = "gate.secret_scan.container_unreadable";
/// A container whose members decode past the byte floor above.
pub(super) const REASON_OVER_BUDGET: &str = "gate.secret_scan.container_over_budget";
/// A container a walk meets inside itself: its whole bytes are those of a
/// container the walk is already inside (FIX 8031). An integrity stop, not a
/// bound: the walk reads no further down it.
const REASON_ARCHIVE_CYCLE: &str = "gate.secret_scan.archive_cycle";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Zip,
    Gzip,
    // FIX 2471: a tar archive and an xz file.
    Tar,
    Xz,
    Pdf,
}

/// The container `bytes` lead as: the head test alone.
fn kind(bytes: &[u8]) -> Option<Kind> {
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        Some(Kind::Zip)
    } else if bytes.starts_with(&[0x1f, 0x8b, 0x08]) {
        Some(Kind::Gzip)
    } else if bytes.starts_with(b"%PDF-") && bytes.get(5).is_some_and(u8::is_ascii_digit) {
        Some(Kind::Pdf)
    } else if bytes.len() >= 512
        && bytes.get(257..).is_some_and(|magic| magic.starts_with(b"ustar"))
    {
        // FIX 2471: a ustar header.
        Some(Kind::Tar)
    } else if bytes.starts_with(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]) {
        // FIX 2471: an xz stream.
        Some(Kind::Xz)
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
fn classify(bytes: &[u8]) -> Option<Kind> {
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
        Kind::Tar => tar::opens(bytes),
        Kind::Xz => true,
        Kind::Pdf => pdf::opens(bytes),
    };
    parses.then_some(head)
}

/// Whether `bytes` lead as a container: the head pre-filter a reader that
/// holds only a body's first bytes takes. The walk reads `bytes` as the
/// classification above does.
pub(crate) fn is_container(bytes: &[u8]) -> bool {
    // FIX 2471: a prefixed ZIP opens through the zip crate's own offset handling.
    kind(bytes).is_some() || (std::str::from_utf8(bytes).is_err() && archive::opens(bytes))
}

/// Whether `bytes` is a container the walk cannot read whole: encrypted,
/// malformed, in a method or filter no reader here decodes, met inside
/// itself, or past the byte floor. Its members are not read, so no mark can
/// place a key in it.
pub(crate) fn is_sealed(bytes: &[u8]) -> bool {
    matches!(
        walk_members(bytes, &mut |_: &[MemberStep], _: &[u8]| -> Walked<()> {
            Ok(())
        }),
        Err(Stop::Refuse(_))
    )
}

/// Whether a key's span is placed in `bytes` as they are: plain bytes, and a
/// PDF, whose own bytes hold its uncompressed objects. A ZIP, gzip, tar or
/// xz file is rebuilt from its members, so a key in one is placed in the
/// member (FIX 2471).
pub(super) fn holds_spans(bytes: &[u8]) -> bool {
    !matches!(
        classify(bytes),
        Some(Kind::Zip | Kind::Gzip | Kind::Tar | Kind::Xz)
    )
}

/// Whether bytes no reader shows are handed to a scan's walk as a member
/// (FIX 2470): plain bytes, and a container the walk reads whole. One the
/// walk does not read is left to the scan of the file's own bytes: no reader
/// shows it either.
fn hidden_member(bytes: &[u8]) -> bool {
    classify(bytes).is_none() || !is_sealed(bytes)
}

/// Whether a key at `path` in the member `bytes` stands as its handle text
/// in a masked copy (FIX 7944): the UTF-8 text of a ZIP entry, a gzip
/// payload, a tar entry, an xz payload (FIX 2471) or a PDF object's
/// strings, each encoded again around its new length. The stored bytes' own
/// spans, a binary member's, a PDF stream's (an object stream names its
/// objects by offset) and a PDF's own bytes (its cross-reference does) keep
/// the filler's width.
fn writes_handles(path: &[MemberStep], bytes: &[u8]) -> bool {
    matches!(
        path.last(),
        Some(
            MemberStep::Zip { .. }
                | MemberStep::Gzip
                | MemberStep::Tar { .. }
                | MemberStep::Xz
                | MemberStep::PdfStrings { .. }
        )
    ) && std::str::from_utf8(bytes).is_ok()
        && classify(bytes).is_none()
}

/// Why a walk stopped before the end of a file's tree.
pub(super) enum Stop {
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

type Walked<T> = std::result::Result<T, Stop>;

fn unreadable() -> Stop {
    Stop::Refuse(REASON_UNREADABLE)
}

fn over_budget() -> Stop {
    Stop::Refuse(REASON_OVER_BUDGET)
}

/// A copy the rebuild could not encode.
fn encode_failed() -> Stop {
    Stop::Fail(Error::InvariantViolation(
        "a masked container copy did not encode",
    ))
}

/// The write door's error for a walk that stopped.
pub(super) fn refusal(stop: Stop) -> Error {
    match stop {
        Stop::Refuse(reason) => secret_scan_error(reason),
        Stop::Fail(error) => error,
    }
}

/// A serving door's error for a masked copy that stopped (FIX 2475): a
/// file this reader cannot be served masked is the typed refusal, and an
/// engine failure stays its own error.
fn withheld(stop: Stop) -> Error {
    match stop {
        Stop::Refuse(reason) => masked_copy_withheld(reason),
        Stop::Fail(error) => error,
    }
}

/// How a walk reads a file's tree.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ContainerReadMode {
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
struct Budget {
    mode: ContainerReadMode,
    expanded: usize,
    /// Whether the walk also reads the bytes no reader shows (FIX 2470): a
    /// PDF's superseded revisions and a ZIP's bytes outside its central
    /// directory's entries. Only a scan reads them; a mark or a rebuild never
    /// does.
    hidden: bool,
    /// The BLAKE3 of each container the walk is inside, the file first: this
    /// walk's own, never kept or logged.
    ancestors: Vec<[u8; 32]>,
}

impl Budget {
    fn new() -> Self {
        Self::of(ContainerReadMode::Generic)
    }

    fn of(mode: ContainerReadMode) -> Self {
        Self {
            mode,
            expanded: MAX_EXPANDED_BYTES,
            hidden: false,
            ancestors: Vec::new(),
        }
    }

    /// This budget, its walk reading the bytes no reader shows too.
    fn reading_hidden(mut self) -> Self {
        self.hidden = true;
        self
    }

    /// Whether the byte floor holds for this walk.
    fn capped(&self) -> bool {
        self.mode == ContainerReadMode::Generic
    }

    /// The most bytes the next member may decode to: the machine's most
    /// when no floor holds.
    fn limit(&self) -> usize {
        if self.capped() {
            self.expanded
        } else {
            usize::MAX
        }
    }

    /// The most bytes a PDF's loader may decompress one stream to; `None`
    /// when no floor holds.
    fn decompressed_ceiling(&self) -> Option<usize> {
        self.capped().then_some(self.expanded)
    }

    /// Whether a rebuilt copy of `len` bytes is past the byte floor.
    fn copy_over(&self, len: usize) -> bool {
        self.capped() && len > MAX_EXPANDED_BYTES
    }

    /// Charges `len` decoded bytes.
    fn spend(&mut self, len: usize) -> Walked<()> {
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
    fn enter_container(&mut self, bytes: &[u8]) -> Walked<()> {
        let digest = *blake3::hash(bytes).as_bytes();
        if self.ancestors.contains(&digest) {
            return Err(Stop::Refuse(REASON_ARCHIVE_CYCLE));
        }
        self.ancestors.push(digest);
        Ok(())
    }

    /// Leaves the container entered last.
    fn leave_container(&mut self) {
        self.ancestors.pop();
    }
}

/// Hands each member under `bytes` to `visit` with its path, depth first in
/// each container's order: a ZIP's entries, a gzip file's payload, a PDF's
/// streams and each object's text strings. A member that is itself a
/// container is handed whole, then walked. Plain bytes hold no members.
pub(super) fn walk_members(
    bytes: &[u8],
    visit: &mut dyn FnMut(&[MemberStep], &[u8]) -> Walked<()>,
) -> Walked<()> {
    retained_iterative::walk(bytes, &mut Budget::new(), visit)
}

/// [`walk_members`], and the bytes no reader shows beside each container's
/// members (FIX 2470), each handed as a member too: what a scan reads.
fn walk_members_with_hidden(
    bytes: &[u8],
    visit: &mut dyn FnMut(&[MemberStep], &[u8]) -> Walked<()>,
) -> Walked<()> {
    retained_iterative::walk(bytes, &mut Budget::new().reading_hidden(), visit)
}

/// [`walk_members`] over a retained repository blob (FIX 7608, rule 5):
/// every member, at any depth, read whole, with no byte floor. A stop is a
/// container no reader here reads, one met inside itself
/// ([`REASON_ARCHIVE_CYCLE`]), or a visitor's own.
pub(super) fn walk_retained_repo_members(
    bytes: &[u8],
    visit: &mut dyn FnMut(&[MemberStep], &[u8]) -> Walked<()>,
) -> Walked<()> {
    let mut budget = Budget::of(ContainerReadMode::RetainedRepo);
    retained_iterative::walk(bytes, &mut budget, visit)
}

/// The write door over each member under `bytes`, each read as the door
/// reads a body (FIX 2312, 2477). A container the walk reads no further is
/// read as far as it reads: the door stores it as it is (owner ruling C2).
pub(super) fn scan_readable_members(bytes: &[u8]) -> Result<()> {
    let mut scan = |_: &[MemberStep], member: &[u8]| -> Walked<()> {
        let _secrets_nulled = scan_payload(member)?;
        Ok(())
    };
    match walk_members(bytes, &mut scan) {
        Ok(()) | Err(Stop::Refuse(_)) => Ok(()),
        Err(Stop::Fail(error)) => Err(error),
    }
}

/// `rules` over each member under `bytes` and each run of bytes no reader
/// shows: the first hit's reason, or why the walk read no further.
fn members_hit(bytes: &[u8], rules: fn(&[u8]) -> Option<&'static str>) -> Option<&'static str> {
    let mut scan = |_: &[MemberStep], member: &[u8]| -> Walked<()> {
        rules(member).map_or(Ok(()), |reason| Err(Stop::Refuse(reason)))
    };
    match walk_members_with_hidden(bytes, &mut scan) {
        Ok(()) => None,
        Err(Stop::Refuse(reason)) => Some(reason),
        Err(Stop::Fail(_)) => Some(REASON_UNREADABLE),
    }
}

/// The release doors' rules over each member under `bytes` and the bytes no
/// reader shows.
pub(super) fn release_members_hit(bytes: &[u8]) -> Option<&'static str> {
    members_hit(bytes, release_hit)
}

/// The write door's rules over each member under `bytes` and the bytes no
/// reader shows: what a masked reader's copy, and an unmarked container, is
/// read by before it is served (FIX 2470, 2480).
pub(super) fn write_members_hit(bytes: &[u8]) -> Option<&'static str> {
    members_hit(bytes, write_payload_hit)
}

/// `bytes` with each key `places` names overwritten: the spans at a place
/// filled first, then each member under it rebuilt the same way and the
/// container encoded around its members again. Every place must be met.
pub(crate) fn masked_copy(bytes: &[u8], places: &KeyPlaces) -> Result<Vec<u8>> {
    masked_copy_in(bytes, places, None, Budget::new()).map_err(refusal)
}

/// [`masked_copy`] for a serving door's masked reader: each key in a text
/// member stands as the handle text `handles` gives it (FIX 7944), and a
/// copy the walk cannot build is [`SecretError::MaskedCopyWithheld`] (FIX
/// 2475).
///
/// [`SecretError::MaskedCopyWithheld`]: crate::error::SecretError::MaskedCopyWithheld
pub(crate) fn served_masked_copy(
    bytes: &[u8],
    places: &KeyPlaces,
    handles: &PlaceHandles,
) -> Result<Vec<u8>> {
    masked_copy_in(bytes, places, Some(handles), Budget::new()).map_err(withheld)
}

/// [`masked_copy`] of a retained repository blob, under its whole read
/// ([`walk_retained_repo_members`]). The stop is the caller's to read: a
/// container no reader here rebuilds is not an engine failure.
pub(super) fn masked_retained_repo_copy(bytes: &[u8], places: &KeyPlaces) -> Walked<Vec<u8>> {
    masked_copy_in(
        bytes,
        places,
        None,
        Budget::of(ContainerReadMode::RetainedRepo),
    )
}

fn masked_copy_in(
    bytes: &[u8],
    places: &KeyPlaces,
    handles: Option<&PlaceHandles>,
    mut budget: Budget,
) -> Walked<Vec<u8>> {
    let mut met = 0;
    let copy = retained_iterative::rebuild(bytes, places, handles, &mut budget, &mut met)?;
    if met != places.len() {
        return Err(Stop::Fail(Error::CorruptedIndex("masked file member path")));
    }
    Ok(copy)
}
