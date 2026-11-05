//! Core half of `batch::secret_scan::container`: its store-layer items live in `oneiron_store::batch::secret_scan::container` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::batch::secret_scan::container::*;

pub(crate) use self::projection_edit::{
    RetainedProjectionEdit, apply_retained_repo_projection_diff,
};
use super::{
    Door, detect, framed_payload, release_hit, scan_payload, secret_scan_error, write_payload_hit,
};
use crate::error::{Error, Result};
use crate::file_secret_marks::{KeyPlaces, MemberStep, PlaceHandles, masked_copy_withheld};

mod archive;
mod pdf;
mod projection_edit;
mod retained_iterative;

/// Whether `bytes` is a container the walk cannot read whole: encrypted,
/// malformed, in a method or filter no reader here decodes, met inside
/// itself, or past the byte floor. Its members are not read, so no mark can
/// place a key in it.
///
/// `digest` is the BLAKE3 of `bytes` when the caller holds one it checked
/// against these exact bytes: the root's entry takes it instead of hashing
/// the file again (FIX 12270). `None` hashes as before.
pub(crate) fn is_sealed(bytes: &[u8], digest: Option<&[u8; 32]>) -> bool {
    matches!(
        walk_members(
            bytes,
            &mut |_: &[MemberStep], _: &[u8]| -> Walked<()> { Ok(()) },
            digest,
        ),
        Err(Stop::Refuse(_))
    )
}

/// Whether bytes no reader shows are handed to a scan's walk as a member
/// (FIX 2470): plain bytes, and a container the walk reads whole. One the
/// walk does not read is left to the scan of the file's own bytes: no reader
/// shows it either.
fn hidden_member(bytes: &[u8]) -> bool {
    classify(bytes).is_none() || !is_sealed(bytes, None)
}

/// The write door's error for a walk that stopped.
pub(super) fn refusal(stop: Stop) -> Error {
    match stop {
        Stop::Refuse(reason) => secret_scan_error(reason),
        Stop::Fail(error) => error,
    }
}

/// Hands each member under `bytes` to `visit` with its path, depth first in
/// each container's order: a ZIP's entries, a gzip file's payload, a PDF's
/// streams and each object's text strings. A member that is itself a
/// container is handed whole, then walked. Plain bytes hold no members.
///
/// `digest` is the BLAKE3 of `bytes` when the caller holds one it checked
/// against these exact bytes: the root's entry takes it instead of hashing
/// the file again (FIX 12270). `None` hashes as before.
pub(super) fn walk_members(
    bytes: &[u8],
    visit: &mut dyn FnMut(&[MemberStep], &[u8]) -> Walked<()>,
    digest: Option<&[u8; 32]>,
) -> Walked<()> {
    retained_iterative::walk(bytes, &mut Budget::new().with_root_digest(digest), visit)
}

/// [`walk_members`], and the bytes no reader shows beside each container's
/// members (FIX 2470), each handed as a member too: what a scan reads.
/// `digest` is the root file's checked BLAKE3, taken for the root's entry
/// (FIX 12270); `None` hashes as before.
fn walk_members_with_hidden(
    bytes: &[u8],
    visit: &mut dyn FnMut(&[MemberStep], &[u8]) -> Walked<()>,
    digest: Option<&[u8; 32]>,
) -> Walked<()> {
    retained_iterative::walk(
        bytes,
        &mut Budget::new().reading_hidden().with_root_digest(digest),
        visit,
    )
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
    match walk_members(bytes, &mut scan, None) {
        Ok(()) | Err(Stop::Refuse(_)) => Ok(()),
        Err(Stop::Fail(error)) => Err(error),
    }
}

/// `rules` over each member under `bytes` and each run of bytes no reader
/// shows: the first hit's reason, or why the walk read no further.
/// `digest` is the root file's checked BLAKE3, taken for the root's entry
/// (FIX 12270); `None` hashes as before.
fn members_hit(
    bytes: &[u8],
    rules: fn(&[u8]) -> Option<&'static str>,
    digest: Option<&[u8; 32]>,
) -> Option<&'static str> {
    let mut scan = |_: &[MemberStep], member: &[u8]| -> Walked<()> {
        rules(member).map_or(Ok(()), |reason| Err(Stop::Refuse(reason)))
    };
    match walk_members_with_hidden(bytes, &mut scan, digest) {
        Ok(()) => None,
        Err(Stop::Refuse(reason)) => Some(reason),
        Err(Stop::Fail(_)) => Some(REASON_UNREADABLE),
    }
}

/// The release doors' rules over each member under `bytes` and the bytes no
/// reader shows.
pub(super) fn release_members_hit(bytes: &[u8]) -> Option<&'static str> {
    members_hit(bytes, release_hit, None)
}

/// [`super::scan_file_content`] over text, which is valid UTF-8. Text with
/// no container's leading bytes is no container to the walk ([`classify`]),
/// so it has no member to read, and text with no framed carrier's magic has
/// no body to decode: such text is read by the release text rules alone, as
/// the whole scan reads it, with no decode tried and no walk entered
/// (speed). Any other text takes the whole scan.
pub(crate) fn scan_text_content(text: &str) -> Option<&'static str> {
    let bytes = text.as_bytes();
    if kind(bytes).is_none() && framed_payload(bytes).is_none() {
        return detect(text, Door::Release);
    }
    super::scan_file_content("", bytes)
}

/// The write door's rules over each member under `bytes` and the bytes no
/// reader shows: what a masked reader's copy, and an unmarked container, is
/// read by before it is served (FIX 2470, 2480).
///
/// `digest` is the BLAKE3 of `bytes` when the caller holds one it checked
/// against these exact bytes: the root's entry takes it instead of hashing
/// the file again (FIX 12270). `None` hashes as before.
pub(super) fn write_members_hit(bytes: &[u8], digest: Option<&[u8; 32]>) -> Option<&'static str> {
    members_hit(bytes, write_payload_hit, digest)
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
///
/// `digest` is the BLAKE3 of `bytes` when the caller holds one it checked
/// against these exact bytes: the root's entry takes it instead of hashing
/// the file again (FIX 12270). `None` hashes as before.
pub(crate) fn served_masked_copy(
    bytes: &[u8],
    places: &KeyPlaces,
    handles: &PlaceHandles,
    digest: Option<&[u8; 32]>,
) -> Result<Vec<u8>> {
    masked_copy_in(
        bytes,
        places,
        Some(handles),
        Budget::new().with_root_digest(digest),
    )
    .map_err(withheld)
}

/// The copy a serving door's masked reader may be served of `bytes`, a
/// container no mark covers whose write-door scan hits (FIX 11553, 12268,
/// 12279): the whole tree encoded again by its readers, every container
/// member rebuilt the same way, so the bytes no reader shows are left out
/// at every level, each member's decoding against the one budget `digest`
/// seeds at the root's entry (FIX 12270). `None` when the walk reads
/// `bytes` as no container, or the rebuild stops anywhere in the tree:
/// the file stays refused as its scan read it, and no partial copy is
/// served. The copy is served only once the write door's scan reads it
/// clean.
pub(crate) fn tree_rebuilt_copy(bytes: &[u8], digest: Option<&[u8; 32]>) -> Option<Vec<u8>> {
    classify(bytes)?;
    retained_iterative::rebuild_tree(bytes, &mut Budget::new().with_root_digest(digest)).ok()
}

/// The first write-rule hit in what a reader shows of `bytes` (FIX 12280):
/// a serving pre-walk that refuses a live-content key before the tree
/// rebuild decodes, encodes and rescans to the same refusal. Only the
/// refusal's timing may change: a hit under a PDF object stream never
/// qualifies, as a rebuilt copy writes its objects whole and the rescan
/// never hands those bytes as a member; a walk that stops (a stop this
/// walk's caller has already read past once, at its seal read) records no
/// hit and falls through to the rebuild, which keeps the raw root-byte
/// hits this walk cannot see on their own path. A member that is itself a
/// container never qualifies either: the tree rebuild re-encodes its whole
/// bytes (its own comment and framing dropped), so only its members,
/// visited below it, can carry a qualifying hit; a leaf member's bytes are
/// re-handed byte for byte by the rebuild's readers, which is what makes
/// its hit the rescan's hit too.
pub(crate) fn live_content_hit(bytes: &[u8], digest: Option<&[u8; 32]>) -> Option<&'static str> {
    let mut hit = None;
    let mut scan = |path: &[MemberStep], member: &[u8]| -> Walked<()> {
        if classify(member).is_some()
            || path
                .iter()
                .any(|step| matches!(step, MemberStep::PdfObjectStream { .. }))
        {
            return Ok(());
        }
        match write_payload_hit(member) {
            Some(reason) => {
                hit = Some(reason);
                Err(Stop::Refuse(reason))
            }
            None => Ok(()),
        }
    };
    let _ = walk_members(bytes, &mut scan, digest);
    hit
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
