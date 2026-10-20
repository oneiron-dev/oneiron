//! A file's marks for the values custody came to know after it was stored
//! (FIX 2781). A file keeps its bytes, so a value custody learns later is
//! not in its mark: each value the index now knows, in the file's own bytes
//! and in each member, that its mark does not cover yet is marked beside the
//! marks it holds, with the custody record that holds it, reason
//! `gate.secret_scan.known_value`, and the file's band. Nothing is minted,
//! no byte changes, and a value the owner ruled no secret in the record
//! stays unmarked. The batch door does this for a file put again, and the
//! lift sweep's known-value pass for every file stored before
//! (`lift_history`).
//!
//! A known value's mark sits outside the file's key budget: it holds no new
//! custody record, and nothing is refused or skipped for how many there are.

use std::ops::Range;

use heed::RwTxn;

use super::super::container::{Stop, holds_spans, is_sealed, walk_members};
use super::{REASON_KNOWN_VALUE, offset};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::secret_custody::{
    KeptValues, KeyPlaces, KeySpan, KnownValues, MASKED_FILE_BAND, MaskedFile, MemberStep,
    masked_file_in_txn, put_masked_file_in_txn,
};
use crate::store::Store;

/// One known value a file's mark does not cover yet: the member that holds
/// it (none for the file's own bytes), its span there, and its record.
pub(super) struct KnownMark {
    pub(super) path: Vec<MemberStep>,
    pub(super) span: Range<usize>,
    pub(super) custody: EntityId,
}

/// Each known value in the file `bytes`, its own bytes and each member's,
/// that no span `prior` marks overlaps and `keep` does not keep (a value the
/// owner ruled no secret in the record). A sealed file is stored as it is
/// and left unmarked, as the batch door leaves it; a container the walk
/// reads no further is marked as far as it reads.
pub(super) fn unmarked_known(
    bytes: &[u8],
    known: &KnownValues,
    keep: impl Fn(&[u8]) -> bool,
    prior: &KeyPlaces,
) -> Result<Vec<KnownMark>> {
    if is_sealed(bytes) {
        return Ok(Vec::new());
    }
    let mut found = Vec::new();
    let mut read_leaf = |path: &[MemberStep], leaf: &[u8]| -> Result<()> {
        if !holds_spans(leaf) {
            return Ok(());
        }
        let held = prior
            .iter()
            .find(|(at, _)| at.as_slice() == path)
            .map_or(&[][..], |(_, spans)| spans.as_slice());
        for hit in known.spans(leaf) {
            let (start, end) = (offset(hit.span.start)?, offset(hit.span.end)?);
            if held.iter().any(|&(from, to)| from < end && start < to)
                || leaf.get(hit.span.clone()).is_none_or(&keep)
            {
                continue;
            }
            found.push(KnownMark {
                path: path.to_vec(),
                span: hit.span,
                custody: hit.custody,
            });
        }
        Ok(())
    };
    read_leaf(&[], bytes)?;
    let mut visit = |path: &[MemberStep], member: &[u8]| -> std::result::Result<(), Stop> {
        read_leaf(path, member).map_err(Stop::Fail)
    };
    match walk_members(bytes, &mut visit) {
        Ok(()) | Err(Stop::Refuse(_)) => Ok(found),
        Err(Stop::Fail(error)) => Err(error),
    }
}

/// `prior` (the file's mark, if it has one) with each of `found` marked
/// beside what it holds; `None` when none was added.
fn united(
    prior: Option<MaskedFile>,
    found: Vec<KnownMark>,
    at: u64,
) -> Result<Option<MaskedFile>> {
    let mut mark = prior.unwrap_or(MaskedFile {
        band: MASKED_FILE_BAND,
        keys: Vec::new(),
        masked_at: at,
        members: Vec::new(),
    });
    let mut added = false;
    for found in found {
        added |= mark.unite(
            &found.path,
            KeySpan {
                start: offset(found.span.start)?,
                end: offset(found.span.end)?,
                custody: found.custody,
                reason: REASON_KNOWN_VALUE.to_owned(),
            },
        );
    }
    Ok(added.then_some(mark))
}

/// Marks each value `known` knows in the file `bytes` that ASSET `record`
/// stores and its mark does not cover yet, past the owner's rulings in
/// `kept`, in `wtxn`; the record takes the file's band. `true` when a mark
/// was added.
pub(crate) fn remark_known_file_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    record: &EntityId,
    bytes: &[u8],
    known: &KnownValues,
    kept: &KeptValues,
) -> Result<bool> {
    let hash = *blake3::hash(bytes).as_bytes();
    let prior = masked_file_in_txn(store, wtxn, &hash)?;
    let places = prior.as_ref().map(MaskedFile::places).unwrap_or_default();
    let found = unmarked_known(bytes, known, |value| kept.holds(record, value), &places)?;
    if found.is_empty() {
        return Ok(false);
    }
    let at = crate::ports::recorded_at_in_txn(store, wtxn)?;
    let Some(mark) = united(prior, found, at)? else {
        return Ok(false);
    };
    put_masked_file_in_txn(store, wtxn, &hash, &mark)?;
    crate::federation::record_scope::restrict_stamp_in_txn(store, wtxn, *record, MASKED_FILE_BAND)?;
    Ok(true)
}

/// Whether the file `bytes` holds a known value its mark `prior` does not
/// cover yet, past `keep`: what a census reads before a writer marks it.
pub(crate) fn holds_unmarked_known(
    bytes: &[u8],
    known: &KnownValues,
    keep: impl Fn(&[u8]) -> bool,
    prior: Option<&MaskedFile>,
) -> Result<bool> {
    let places = prior.map(MaskedFile::places).unwrap_or_default();
    Ok(!unmarked_known(bytes, known, keep, &places)?.is_empty())
}
