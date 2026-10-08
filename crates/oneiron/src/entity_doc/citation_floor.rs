//! Citation floors: a derived record that quotes an entity document keeps the
//! history it quoted. The citing write records the frontier it read (or the
//! birth state, when the entity had no document yet) in its own transaction.
//! An owner purge never drops history past the floor of a live citer; a
//! value-only recovery that rebuilds the document under a fresh incarnation
//! stales those citers instead of leaving them naming lost history. Unlike a
//! `CitationPin`, a floor is not a quote the recovery artifact must carry, so
//! canonical capture stays available.

use super::document::decode_frontier;
use super::side_keys::HexPair;
use super::{invalid, storage};
use crate::EntityId;
use crate::error::Result;
use crate::side_table::{self, HexId, Named, SideTable};
use crate::store::Store;
use crate::vault::live_entity_row_in_txn;
use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

/// What one citer quoted of one entity document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CitationFloor {
    /// Every incarnation-qualified frontier the citer named.
    pub(super) frontiers: Vec<Vec<u8>>,
    /// The citer quoted the entity before it had a document: its birth state.
    pub(super) birth: bool,
}

/// Keyed by cited entity then citer.
pub(super) const ENTITY_DOC_CITATION_FLOOR: SideTable<HexPair, CitationFloor, Named> =
    SideTable::new(&side_table::ENTITY_DOC_CITATION_FLOOR);

/// Hex incarnation id leading every qualified frontier.
const INCARNATION_LEN: usize = 32;

fn entity_prefix(entity: &EntityId) -> Vec<u8> {
    format!("{}:", entity.to_hex()).into_bytes()
}

/// The bare document frontier of a qualified one, which must name `incarnation`.
fn bare<'a>(qualified: &'a [u8], incarnation: &str) -> Result<&'a [u8]> {
    let (named, frontier) = qualified
        .split_at_checked(INCARNATION_LEN)
        .ok_or(invalid("cited frontier names no document incarnation"))?;
    if named != incarnation.as_bytes() {
        return Err(invalid("cited frontier names another document incarnation"));
    }
    decode_frontier(frontier)?;
    Ok(frontier)
}

/// Records, in the citing write's own transaction, that `citer` quotes
/// `entity` at `frontier` (incarnation-qualified, of the live document), or
/// at its birth state when the entity has no document (`None`). Repeated
/// citations by one citer accumulate.
pub(crate) fn record_citation_floor_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    citer: &EntityId,
    frontier: Option<&[u8]>,
) -> Result<()> {
    if entity == citer {
        return Err(invalid("a record cannot cite its own document"));
    }
    let key = HexPair(HexId(*entity), HexId(*citer));
    let mut floor = ENTITY_DOC_CITATION_FLOOR
        .get(store, txn, &key)?
        .unwrap_or_default();
    match frontier {
        Some(qualified) => {
            let head = storage::ENTITY_DOC_HEAD
                .get(store, txn, &HexId(*entity))?
                .ok_or(invalid("cited frontier names no live document"))?;
            bare(qualified, &head.incarnation)?;
            if !floor.frontiers.iter().any(|known| known == qualified) {
                floor.frontiers.push(qualified.to_vec());
            }
        }
        None => floor.birth = true,
    }
    ENTITY_DOC_CITATION_FLOOR.put(store, txn, &key, &floor)
}

/// The bare frontiers every live citer of `entity` quoted, checked against the
/// document's current `incarnation`. Citers that are gone, deleted or stale
/// hold nothing. A live citer of another incarnation, or of the birth state,
/// refuses: no purge frontier keeps that history.
pub(super) fn live_frontiers(
    store: &Store,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    incarnation: &str,
) -> Result<Vec<Vec<u8>>> {
    let mut frontiers = Vec::new();
    for (HexPair(_, HexId(citer)), floor) in
        ENTITY_DOC_CITATION_FLOOR.scan_from(store, txn, &entity_prefix(entity))?
    {
        if !live_entity_row_in_txn(store, txn, &citer)?.is_live() {
            continue;
        }
        if floor.birth {
            return Err(invalid(
                "history drop crosses a citation of the birth state",
            ));
        }
        for qualified in &floor.frontiers {
            frontiers.push(bare(qualified, incarnation)?.to_vec());
        }
    }
    Ok(frontiers)
}

/// A value-only rebuild keeps none of the document's history: every live citer
/// that recorded a floor on `entity` is staled (and queued for regeneration)
/// in the caller's transaction, then the floors go. Other dependents of the
/// entity are untouched.
pub(super) fn invalidate_citers_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let prefix = entity_prefix(entity);
    for HexPair(_, HexId(citer)) in ENTITY_DOC_CITATION_FLOOR.scan_keys(store, txn, &prefix)? {
        if live_entity_row_in_txn(store, txn, &citer)?.is_live() {
            crate::ports::invalidate_dependent_in_txn(store, txn, entity, &citer)?;
        }
    }
    ENTITY_DOC_CITATION_FLOOR.delete_from(store, txn, &prefix)?;
    Ok(())
}

/// Erasure removes the floors with the history they held; the citers are
/// staled by the erasure's own dependency index.
pub(super) fn erase_in_txn(store: &Store, txn: &mut RwTxn<'_>, entity: &EntityId) -> Result<()> {
    ENTITY_DOC_CITATION_FLOOR.delete_from(store, txn, &entity_prefix(entity))?;
    Ok(())
}
