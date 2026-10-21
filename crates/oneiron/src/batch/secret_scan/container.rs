//! Containers the secret mask reads into (OF-067 C, owner ruling G04 binary
//! = C2): a ZIP archive (Office, OpenDocument and the other ZIP-family
//! files), a gzip file and a PDF's streams. The write door reads each member
//! as it reads a body, and a member's keys are placed at their spans in the
//! decoded member. A reader the owner has not granted gets a copy rebuilt
//! around the overwritten keys; the stored bytes never change.
//!
//! One walk serves the write door, the release scan and the rebuild, under
//! one budget for a file's whole tree. A container the walk cannot read
//! whole (past a bound, malformed, failing a checksum, encrypted, or in a
//! method or filter no reader here decodes) is sealed ([`is_sealed`]): the
//! write door stores it as it is and leaves it unmarked (owner ruling C2,
//! "encrypted files are stored as they are"), a serving door gives it to the
//! owner and refuses it to a masked reader, and every release door reads it
//! as a hit.
//!
//! A container is known by its leading bytes, never by its name. A tar, 7z,
//! RAR or xz file is read as plain bytes, and so is a container that starts
//! past a file's first byte.

mod archive;
mod gzip;
mod pdf;
mod projection_edit;
mod retained_iterative;

pub(crate) use self::projection_edit::{
    RetainedMemberDiff, RetainedProjectionEdit, apply_retained_repo_projection_diff,
};

use super::{release_hit, scan_payload, secret_scan_error};
use crate::error::{Error, Result};
use crate::secret_custody::{KeyPlaces, MemberStep, filled};

/// Containers nested in one file, the file itself counted.
const MAX_DEPTH: usize = 4;
/// Members one walk reads over a file's whole tree: ZIP entries, gzip
/// payloads and decoded PDF streams.
const MAX_MEMBERS: usize = 50_000;
/// The bytes one member may decode to.
const MAX_MEMBER_BYTES: usize = 64 * 1024 * 1024;
/// The bytes all of a file's members may decode to over its whole tree. A
/// rebuilt copy is held to it too.
const MAX_EXPANDED_BYTES: usize = 512 * 1024 * 1024;
/// The indirect objects one PDF may hold.
const MAX_PDF_OBJECTS: usize = 50_000;
/// The keys one file may carry; the write door refuses a file with more.
pub(super) const MAX_FILE_KEYS: usize = 10_000;

/// A container no reader here reads whole: malformed, truncated, failing a
/// checksum, encrypted, holding one name twice, or in a compression method
/// or PDF filter not decoded here.
pub(super) const REASON_UNREADABLE: &str = "gate.secret_scan.container_unreadable";
/// A container past one of the bounds above.
pub(super) const REASON_OVER_BUDGET: &str = "gate.secret_scan.container_over_budget";
/// A container a retained repository read meets inside itself: its whole
/// bytes are those of a container the walk is already inside (FIX 8031).
/// An integrity stop, not a bound: the walk reads no further down it.
const REASON_ARCHIVE_CYCLE: &str = "gate.secret_scan.archive_cycle";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Zip,
    Gzip,
    Pdf,
}

fn kind(bytes: &[u8]) -> Option<Kind> {
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        Some(Kind::Zip)
    } else if bytes.starts_with(&[0x1f, 0x8b, 0x08]) {
        Some(Kind::Gzip)
    } else if bytes.starts_with(b"%PDF-") && bytes.get(5).is_some_and(u8::is_ascii_digit) {
        Some(Kind::Pdf)
    } else {
        None
    }
}

/// Whether the walk reads into `bytes`.
pub(crate) fn is_container(bytes: &[u8]) -> bool {
    kind(bytes).is_some()
}

/// Whether `bytes` is a container the walk cannot read whole: encrypted,
/// malformed, in a method or filter no reader here decodes, or past one of
/// the bounds above. Its members are not read, so no mark can place a key in
/// it.
pub(crate) fn is_sealed(bytes: &[u8]) -> bool {
    is_container(bytes)
        && matches!(
            walk_members(bytes, &mut |_: &[MemberStep], _: &[u8]| -> Walked<()> {
                Ok(())
            }),
            Err(Stop::Refuse(_))
        )
}

/// Whether a key's span is placed in `bytes` as they are: plain bytes, and a
/// PDF, whose own bytes hold its uncompressed objects. A ZIP or gzip file is
/// rebuilt from its members, so a key in one is placed in the member.
pub(super) fn holds_spans(bytes: &[u8]) -> bool {
    !matches!(kind(bytes), Some(Kind::Zip | Kind::Gzip))
}

/// Why a walk stopped before the end of a file's tree.
pub(super) enum Stop {
    /// The door refuses the file with this reason code: a hit, or a
    /// container read no further ([`REASON_UNREADABLE`],
    /// [`REASON_OVER_BUDGET`], and a retained read's
    /// [`REASON_ARCHIVE_CYCLE`]).
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

/// How a walk reads a file's tree.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ContainerReadMode {
    /// The write door's, release doors' and serving doors' read: every bound
    /// above holds.
    Generic,
    /// A retained repository blob's read (FIX 7608, rule 5): no member,
    /// object, depth or expanded-byte bound. The same decoders read it, with
    /// every integrity check theirs (declared lengths, CRCs, duplicate
    /// names, methods, filters, encryption, cross-references); what stops it
    /// is a container no reader here reads, or the machine.
    RetainedRepo,
}

/// What a walk over one file's tree has left. A member's own walk spends
/// from it; none starts a budget of its own. A retained repository read
/// counts against none of it, and keeps the containers it is inside.
struct Budget {
    mode: ContainerReadMode,
    members: usize,
    expanded: usize,
    /// The BLAKE3 of each container a retained read is inside, the file
    /// first: this walk's own, never kept or logged.
    ancestors: Vec<[u8; 32]>,
}

impl Budget {
    fn new() -> Self {
        Self::of(ContainerReadMode::Generic)
    }

    fn of(mode: ContainerReadMode) -> Self {
        Self {
            mode,
            members: MAX_MEMBERS,
            expanded: MAX_EXPANDED_BYTES,
            ancestors: Vec::new(),
        }
    }

    /// Whether the bounds above hold for this walk.
    fn capped(&self) -> bool {
        self.mode == ContainerReadMode::Generic
    }

    /// Counts one more member.
    fn member(&mut self) -> Walked<()> {
        if self.capped() {
            self.members = self.members.checked_sub(1).ok_or_else(over_budget)?;
        }
        Ok(())
    }

    /// The members the walk may still read; `None` when no bound holds.
    fn members_left(&self) -> Option<usize> {
        self.capped().then_some(self.members)
    }

    /// The most bytes the next member may decode to: the machine's most
    /// when no bound holds.
    fn limit(&self) -> usize {
        if self.capped() {
            self.expanded.min(MAX_MEMBER_BYTES)
        } else {
            usize::MAX
        }
    }

    /// The most bytes a PDF's loader may decompress one stream to; `None`
    /// when no bound holds.
    fn decompressed_ceiling(&self) -> Option<usize> {
        self.capped().then_some(MAX_MEMBER_BYTES)
    }

    /// Whether `objects` indirect objects are past the PDF bound.
    fn objects_over(&self, objects: usize) -> bool {
        self.capped() && objects > MAX_PDF_OBJECTS
    }

    /// Whether a container `depth` steps down is past the depth bound.
    fn too_deep(&self, depth: usize) -> bool {
        self.capped() && depth >= MAX_DEPTH
    }

    /// Whether a rebuilt copy of `len` bytes is past the expanded bound.
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
    /// members are read (FIX 8031). A retained read already inside a
    /// container of the same bytes has met a cycle, and reads no further
    /// down it. Each entry is left once its members are read, so a
    /// container met again beside itself is read again. A bounded walk
    /// keeps no ancestry: its own bounds end it.
    fn enter_container(&mut self, bytes: &[u8]) -> Walked<()> {
        if self.capped() {
            return Ok(());
        }
        let digest = *blake3::hash(bytes).as_bytes();
        if self.ancestors.contains(&digest) {
            return Err(Stop::Refuse(REASON_ARCHIVE_CYCLE));
        }
        self.ancestors.push(digest);
        Ok(())
    }

    /// Leaves the container entered last.
    fn leave_container(&mut self) {
        if !self.capped() {
            self.ancestors.pop();
        }
    }
}

/// Hands each member under `bytes` to `visit` with its path, depth first in
/// each container's order: a ZIP's entries, a gzip file's payload, a PDF's
/// streams. A member that is itself a container is handed whole, then
/// walked. Plain bytes hold no members.
pub(super) fn walk_members(
    bytes: &[u8],
    visit: &mut dyn FnMut(&[MemberStep], &[u8]) -> Walked<()>,
) -> Walked<()> {
    walk(bytes, &mut Vec::new(), &mut Budget::new(), visit)
}

/// [`walk_members`] over a retained repository blob (FIX 7608, rule 5):
/// every member, at any depth, read whole, with no policy bound. A stop is
/// a container no reader here reads, one met inside itself
/// ([`REASON_ARCHIVE_CYCLE`]), or a visitor's own. Its frames are on the
/// heap ([`retained_iterative`]), so no depth of nesting runs the thread's
/// stack out.
pub(super) fn walk_retained_repo_members(
    bytes: &[u8],
    visit: &mut dyn FnMut(&[MemberStep], &[u8]) -> Walked<()>,
) -> Walked<()> {
    let mut budget = Budget::of(ContainerReadMode::RetainedRepo);
    retained_iterative::walk(bytes, &mut budget, visit)
}

fn walk(
    bytes: &[u8],
    path: &mut Vec<MemberStep>,
    budget: &mut Budget,
    visit: &mut dyn FnMut(&[MemberStep], &[u8]) -> Walked<()>,
) -> Walked<()> {
    let Some(kind) = kind(bytes) else {
        return Ok(());
    };
    if budget.too_deep(path.len()) {
        return Err(over_budget());
    }
    let mut each = |step: MemberStep, member: &[u8], budget: &mut Budget| -> Walked<()> {
        path.push(step);
        let read = visit(path.as_slice(), member)
            .and_then(|()| walk(member, &mut *path, budget, &mut *visit));
        path.pop();
        read
    };
    match kind {
        Kind::Zip => archive::members(bytes, budget, &mut each),
        Kind::Gzip => gzip::members(bytes, budget, &mut each),
        Kind::Pdf => pdf::members(bytes, budget, &mut each),
    }
}

/// The write door over each member under `bytes`, each read as the door
/// reads a body.
pub(crate) fn scan_members(bytes: &[u8]) -> Result<()> {
    let mut scan = |_: &[MemberStep], member: &[u8]| -> Walked<()> {
        let _secrets_nulled = scan_payload(member)?;
        Ok(())
    };
    walk_members(bytes, &mut scan).map_err(refusal)
}

/// The release doors' rules over each member under `bytes`: the first
/// hit's reason, or why the walk read no further.
pub(super) fn release_members_hit(bytes: &[u8]) -> Option<&'static str> {
    if !is_container(bytes) {
        return None;
    }
    let mut scan = |_: &[MemberStep], member: &[u8]| -> Walked<()> {
        release_hit(member).map_or(Ok(()), |reason| Err(Stop::Refuse(reason)))
    };
    match walk_members(bytes, &mut scan) {
        Ok(()) => None,
        Err(Stop::Refuse(reason)) => Some(reason),
        Err(Stop::Fail(_)) => Some(REASON_UNREADABLE),
    }
}

/// `bytes` with each key `places` names overwritten: the spans at a place
/// filled first, then each member under it rebuilt the same way and the
/// container encoded around its members again. Every place must be met.
pub(crate) fn masked_copy(bytes: &[u8], places: &KeyPlaces) -> Result<Vec<u8>> {
    masked_copy_in(bytes, places, Budget::new()).map_err(refusal)
}

/// [`masked_copy`] of a retained repository blob, under its whole read
/// ([`walk_retained_repo_members`]). The stop is the caller's to read: a
/// container no reader here rebuilds is not an engine failure.
pub(super) fn masked_retained_repo_copy(bytes: &[u8], places: &KeyPlaces) -> Walked<Vec<u8>> {
    masked_copy_in(bytes, places, Budget::of(ContainerReadMode::RetainedRepo))
}

fn masked_copy_in(bytes: &[u8], places: &KeyPlaces, mut budget: Budget) -> Walked<Vec<u8>> {
    let mut met = 0;
    let copy = if budget.capped() {
        rebuild(bytes, &mut Vec::new(), places, &mut budget, &mut met)?
    } else {
        retained_iterative::rebuild(bytes, places, &mut budget, &mut met)?
    };
    if met != places.len() {
        return Err(Stop::Fail(Error::CorruptedIndex("masked file member path")));
    }
    Ok(copy)
}

fn rebuild(
    bytes: &[u8],
    path: &mut Vec<MemberStep>,
    places: &KeyPlaces,
    budget: &mut Budget,
    met: &mut usize,
) -> Walked<Vec<u8>> {
    let mut copy = bytes.to_vec();
    for (_, spans) in places
        .iter()
        .filter(|(at, _)| at.as_slice() == path.as_slice())
    {
        copy = filled(&copy, spans.iter().copied())?;
        *met += 1;
    }
    if !places
        .iter()
        .any(|(at, _)| at.len() > path.len() && at.starts_with(path.as_slice()))
    {
        return Ok(copy);
    }
    let kind = kind(bytes).ok_or(Stop::Fail(Error::CorruptedIndex("masked file member path")))?;
    if budget.too_deep(path.len()) {
        return Err(over_budget());
    }
    let mut each =
        |step: MemberStep, member: &[u8], budget: &mut Budget| -> Walked<Option<Vec<u8>>> {
            path.push(step);
            let marked = places.iter().any(|(at, _)| at.starts_with(path.as_slice()));
            let copy = if marked {
                rebuild(member, &mut *path, places, budget, &mut *met).map(Some)
            } else {
                Ok(None)
            };
            path.pop();
            copy
        };
    let copy = match kind {
        Kind::Zip => archive::rebuilt(&copy, budget, &mut each),
        Kind::Gzip => gzip::rebuilt(&copy, budget, &mut each),
        Kind::Pdf => pdf::rebuilt(&copy, budget, &mut each),
    }?;
    if budget.copy_over(copy.len()) {
        return Err(over_budget());
    }
    Ok(copy)
}
