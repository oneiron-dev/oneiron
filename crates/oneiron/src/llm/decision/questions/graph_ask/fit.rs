//! FIX 1711: which of a graph unit's readable neighbours one answer can
//! rest on beside it, judged by the scope law a written answer is held to,
//! and the ones it leaves out, named with why.

use super::super::records::{OmittedNeighbor, SourceConflict};
use super::super::standing::{ScopeFold, Source};
use super::{GraphContextSource, GraphUnitContext, asker, source, source_eligible};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::ScopedRead;
use crate::{EntityId, Error, Result, Vault};

/// Whether the unit's `neighbors`, judged by `lane` in `txn` as the prepared
/// ones were ([`fit_neighbors`]), keep the same neighbours and leave out the
/// same ones for the same reasons.
pub(super) fn same_fitted_neighbors(
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    neighbors: Option<Vec<(EntityId, u8, Vec<u8>)>>,
    context: &GraphUnitContext,
) -> Result<bool> {
    let (Some(neighbors), Some(unit)) = (neighbors, context.sources.first()) else {
        return Ok(false);
    };
    let eligible = eligible_sources(lane.vault(), txn, neighbors)?;
    let Some((kept, omitted)) = fit_neighbors(lane, txn, unit, eligible)? else {
        return Ok(false);
    };
    let shown = context.sources.iter().skip(1).map(|source| source.id);
    Ok(omitted == context.omitted && kept.iter().map(|source| source.id).eq(shown))
}

/// Each of `neighbors` that may inform an answer.
pub(super) fn eligible_sources(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    neighbors: Vec<(EntityId, u8, Vec<u8>)>,
) -> Result<Vec<GraphContextSource>> {
    let mut sources = Vec::with_capacity(neighbors.len());
    for (id, kind, body) in neighbors {
        if source_eligible(vault, txn, &id, kind)? {
            sources.push(source(id, kind, body));
        }
    }
    Ok(sources)
}

/// `neighbors` split into those one answer can rest on beside `unit`, in
/// the order read, and those it leaves out, each with why, by the scope law
/// a written answer is held to ([`ScopeFold`]). The unit's own position, as
/// `lane` reads it, anchors the answer; where the unit sets no relationship
/// or scope term, neighbours are judged in EntityId order and the first
/// value kept wins (FIX 1711 tie-break). A unit that bounds no answer on its
/// own keeps every neighbour, and its write refuses as before. `None` when a
/// source changed or went out of reach while judged.
pub(super) fn fit_neighbors(
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    unit: &GraphContextSource,
    neighbors: Vec<GraphContextSource>,
) -> Result<Option<(Vec<GraphContextSource>, Vec<OmittedNeighbor>)>> {
    let Some(anchor) = source_in_txn(lane, txn, unit)? else {
        return Ok(None);
    };
    let mut fold = ScopeFold::new(asker(lane)?);
    let anchored = match anchor {
        Ok(anchor) => fold.admit(&anchor).is_none(),
        Err(_) => false,
    };
    if !anchored {
        return Ok(Some((neighbors, Vec::new())));
    }
    let mut order: Vec<usize> = (0..neighbors.len()).collect();
    order.sort_by_key(|&at| neighbors[at].id);
    let mut left_out = vec![false; neighbors.len()];
    let mut omitted = Vec::new();
    for at in order {
        let Some(row) = source_in_txn(lane, txn, &neighbors[at])? else {
            return Ok(None);
        };
        let conflict = match row {
            Ok(row) => fold.admit(&row),
            Err(conflict) => Some(conflict),
        };
        if let Some(reason) = conflict {
            left_out[at] = true;
            omitted.push(OmittedNeighbor {
                id: neighbors[at].id,
                reason,
            });
        }
    }
    let kept = neighbors
        .into_iter()
        .zip(left_out)
        .filter_map(|(source, out)| (!out).then_some(source))
        .collect();
    Ok(Some((kept, omitted)))
}

/// What `shown` puts on an answer as `lane` reads it in `txn`, at the kind
/// and bytes it was shown and still eligible: its conflict when its scope
/// bounds no answer. `None` when it changed, went out of reach or holds no
/// record scope.
pub(super) fn source_in_txn(
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    shown: &GraphContextSource,
) -> Result<Option<std::result::Result<Source, SourceConflict>>> {
    let Some(raw) = lane.graph_ask_raw_in_txn(txn, &shown.id)? else {
        return Ok(None);
    };
    let kind = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("graph ask source header"))?
        .entity_type;
    // A file-plane ASSET's row holds its manifest: the hash is the logical
    // body's own, which the manifest carries, never the manifest's bytes
    // (FIX 5398).
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    let hash = if kind == crate::registry::ENTITY_TYPE_ASSET {
        match crate::store::asset_file_in_txn(&lane.vault().store, txn, &shown.id, body)? {
            Some(manifest) => manifest.facts.blake3,
            None => *blake3::hash(body).as_bytes(),
        }
    } else {
        *blake3::hash(body).as_bytes()
    };
    if kind != shown.entity_type
        || hash != shown.hash
        || !source_eligible(lane.vault(), txn, &shown.id, kind)?
    {
        return Ok(None);
    }
    let Some(scope) =
        crate::federation::record_scope::scope_for_blob(&lane.store_read(), txn, shown.id, &raw)?
    else {
        return Ok(None);
    };
    // A NOTE source sits at one world it is in that the lane holds, else at
    // base reality as before (FIX-LIST 9433).
    let scope = crate::federation::record_scope::note_world::source_position(
        &lane.store_read(),
        txn,
        shown.id,
        kind,
        scope,
        &[&lane.actor_key().world_ceiling().worlds],
    );
    Source::fitted(kind, &raw, &scope).map(Some)
}
