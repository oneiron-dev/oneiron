//! The native slice a bound step's TURNs lie in, and the step's scope over it.
//!
//! A bound step cites TURNs of exactly one native slice. Preparation groups the cited
//! TURNs by the native slice key to prove that, and a reader of the step's record
//! rebuilds the step's attenuated scope over the same slice, so a candidate the step
//! kept is read under the scope its call asked under.

use std::collections::{BTreeMap, BTreeSet};

use super::super::TurnText;
use super::super::extraction_pack::bound_branch_error;
use super::super::resources::BoundBranchRead;
use super::super::support::invalid_consolidation;
use super::super::watermark::decode_turn_body;
use super::{ExtractionStepPiece, slice_group_key};
use crate::claim::ScopedRead;
use crate::entity_id::EntityId;
use crate::memory::MemoryResult;
use oneiron_model::llm::Scope;

/// Each cited TURN's speaker, and the piece positions grouped by native
/// slice key.
pub(super) type SliceGroups = (
    BTreeMap<EntityId, Option<String>>,
    BTreeMap<(u32, Vec<EntityId>), Vec<usize>>,
);

/// Reads each TURN `pieces` cite and groups the pieces by the native slice
/// each lies in.
///
/// # Errors
///
/// An unlisted TURN, an unreadable TURN body, or a wrong TURN type.
pub(super) fn slice_groups(
    txn: &heed::RoTxn<'_>,
    read: &ScopedRead<'_>,
    bound: &BoundBranchRead,
    pieces: &[ExtractionStepPiece],
) -> MemoryResult<SliceGroups> {
    let distinct: BTreeSet<EntityId> = pieces.iter().map(|piece| piece.turn).collect();
    let ordered: Vec<EntityId> = distinct.iter().copied().collect();
    let rows = read
        .get_entities_parts_in_txn(txn, &ordered)
        .map_err(bound_branch_error)?;
    let mut speakers: BTreeMap<EntityId, Option<String>> = BTreeMap::new();
    let mut bodies: BTreeMap<EntityId, Vec<u8>> = BTreeMap::new();
    for (turn, row) in ordered.iter().zip(rows) {
        bound
            .turn_conversation(*turn)
            .ok_or_else(|| bound_branch_error(invalid_consolidation("unlisted branch turn")))?;
        let Some((kind, _, body)) = row else {
            return Err(bound_branch_error(invalid_consolidation(
                "branch source is not readable",
            )));
        };
        if kind != crate::registry::ENTITY_TYPE_TURN {
            return Err(bound_branch_error(invalid_consolidation(
                "invalid branch source type",
            )));
        }
        speakers.insert(*turn, decode_turn_body(&body).speaker);
        bodies.insert(*turn, body);
    }
    let mut groups: BTreeMap<(u32, Vec<EntityId>), Vec<usize>> = BTreeMap::new();
    for (index, piece) in pieces.iter().enumerate() {
        let body = bodies
            .get(&piece.turn)
            .ok_or_else(|| bound_branch_error(invalid_consolidation("unlisted branch turn")))?;
        let frozen = bound.turn_text(piece.turn).and_then(TurnText::text);
        let line = bound.turn_line(piece.turn);
        let key = slice_group_key(bound.neighbourhood(), line, body, frozen);
        groups.entry(key).or_default().push(index);
    }
    Ok((speakers, groups))
}

/// The attenuated scope the bound step over `pieces` asked under, rebuilt
/// as `prepare_bound_step` builds it over the slice's kept listing: `None`
/// when the cited TURNs no longer lie in one native slice.
///
/// # Errors
///
/// An unlisted TURN, an unreadable TURN body, a wrong TURN type, or the
/// attenuated scope projection's own failures.
pub(crate) fn bound_step_scope(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    read: &ScopedRead<'_>,
    bound: &BoundBranchRead,
    pieces: &[ExtractionStepPiece],
) -> MemoryResult<Option<Scope>> {
    let cited: Vec<EntityId> = pieces.iter().map(|piece| piece.turn).collect();
    let (_, groups) = slice_groups(txn, read, bound, pieces)?;
    let mut slices = groups.into_keys();
    let (Some((_, entities)), None) = (slices.next(), slices.next()) else {
        return Ok(None);
    };
    let known = bound.neighbourhood().slice(&entities);
    let scoped = bound
        .extraction_scope(vault, txn, &cited, &known)
        .map_err(bound_branch_error)?;
    Ok(Some(scoped.scope))
}
