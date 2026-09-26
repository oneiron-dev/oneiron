//! Enforcement of gate-resolved retrieval authority. No caller requests enter here.

use crate::claim::ClaimBody;
use crate::gate::ResolvedRetrievalFilter;
use crate::registry::{ENTITY_TYPE_CLAIM, EntityClassification, entity_type_registry_entry};
use crate::store::Store;

use super::filters::claim_status_gate_allows;
use super::types::{ClaimStatusGateCache, EntityMetadataCache, ScoredEntity};

/// Retrieval admission for one claim: the surfaceable status half and the
/// resolved ceiling half, both required.
pub(super) fn claim_allowed(filter: &ResolvedRetrievalFilter, body: &ClaimBody) -> bool {
    crate::claim::ClaimReadStatus::Surfaceable.admits(filter, body)
        && claim_ceiling_allowed(filter, body)
}

/// The ceiling half of claim admission: the actor's resolved scalar floor
/// (sensitivity band, confidence and salience minima), never a status rule.
pub(crate) fn claim_ceiling_allowed(filter: &ResolvedRetrievalFilter, body: &ClaimBody) -> bool {
    !filter.deny_all
        && crate::claim::claim_sensitivity_band(body)
            .is_some_and(|band| band <= filter.max_sensitivity_band)
        && body.confidence.is_finite()
        && (filter.min_confidence..=1.0).contains(&body.confidence)
        && body.salience.unwrap_or(0.0).is_finite()
        && (filter.min_salience..=1.0).contains(&body.salience.unwrap_or(0.0))
}

/// Entity-type authority and the default kind scope. When the filter names
/// no types, maintenance records (audit, policy, federation and authority
/// carriers, ARCH-0002) stay out of retrieval: they are not context
/// entities. A caller that names a maintenance kind, in the filter or in
/// its own kind filter (`named`), still reaches it.
pub(super) fn type_allowed(
    filter: &ResolvedRetrievalFilter,
    named: Option<&[u8]>,
    store: &Store,
    kind: u8,
) -> bool {
    !filter.deny_all
        && store.validate_entity_type(kind).is_ok()
        && match filter.entity_types.as_ref() {
            Some(types) => types.contains(&kind),
            None => !is_maintenance(kind) || named.is_some_and(|named| named.contains(&kind)),
        }
}

fn is_maintenance(kind: u8) -> bool {
    entity_type_registry_entry(kind)
        .is_some_and(|entry| entry.classification == EntityClassification::Maintenance)
}

pub(super) fn apply_types(
    scores: &mut Vec<ScoredEntity>,
    filter: &ResolvedRetrievalFilter,
    named: Option<&[u8]>,
    store: &Store,
    txn: &heed::RoTxn<'_>,
    metadata: &mut EntityMetadataCache,
) -> crate::Result<()> {
    let mut kept = Vec::with_capacity(scores.len());
    for scored in scores.iter().copied() {
        if let Some(meta) = metadata.get(store, txn, &scored.id)? {
            if type_allowed(filter, named, store, meta.entity_type) {
                kept.push(scored);
            } else {
                metadata.read_suppressed.insert(scored.id);
            }
        }
    }
    *scores = kept;
    Ok(())
}

pub(super) fn candidate_allowed(
    filter: &ResolvedRetrievalFilter,
    named: Option<&[u8]>,
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &crate::EntityId,
    metadata: &mut EntityMetadataCache,
    gate: &mut ClaimStatusGateCache,
) -> crate::Result<bool> {
    let Some(meta) = metadata.get(store, txn, id)? else {
        return Ok(false);
    };
    if !type_allowed(filter, named, store, meta.entity_type) {
        metadata.read_suppressed.insert(*id);
        return Ok(false);
    }
    if meta.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(true);
    }
    if !claim_status_gate_allows(store, txn, id, metadata, gate)? {
        return Ok(false);
    }
    let allowed = gate
        .decisions
        .get(id)
        .and_then(Option::as_ref)
        .is_some_and(|body| claim_allowed(filter, body));
    if !allowed {
        metadata.read_suppressed.insert(*id);
    }
    Ok(allowed)
}

pub(super) fn apply(
    scores: &mut Vec<ScoredEntity>,
    filter: &ResolvedRetrievalFilter,
    named: Option<&[u8]>,
    store: &Store,
    txn: &heed::RoTxn<'_>,
    metadata: &mut EntityMetadataCache,
    gate: &mut ClaimStatusGateCache,
) -> crate::Result<()> {
    let mut kept = Vec::with_capacity(scores.len());
    for scored in scores.iter().copied() {
        if candidate_allowed(filter, named, store, txn, &scored.id, metadata, gate)? {
            kept.push(scored);
        }
    }
    *scores = kept;
    Ok(())
}
