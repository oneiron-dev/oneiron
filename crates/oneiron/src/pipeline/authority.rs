//! Enforcement of gate-resolved retrieval authority. No caller requests enter here.

use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus};
use crate::gate::ResolvedRetrievalFilter;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;

use super::filters::claim_status_gate_allows;
use super::types::{ClaimStatusGateCache, EntityMetadataCache, ScoredEntity};

pub(crate) fn claim_allowed(filter: &ResolvedRetrievalFilter, body: &ClaimBody) -> bool {
    !filter.deny_all
        && matches!(
            body.approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        )
        && body.lifecycle == ClaimLifecycleStatus::Active
        && (filter.include_stale || !body.stale)
        && crate::claim::claim_sensitivity_band(body)
            .is_some_and(|band| band <= filter.max_sensitivity_band)
        && body.confidence.is_finite()
        && (filter.min_confidence..=1.0).contains(&body.confidence)
        && body.salience.unwrap_or(0.0).is_finite()
        && (filter.min_salience..=1.0).contains(&body.salience.unwrap_or(0.0))
}

pub(super) fn type_allowed(filter: &ResolvedRetrievalFilter, store: &Store, kind: u8) -> bool {
    !filter.deny_all
        && store.validate_entity_type(kind).is_ok()
        && filter
            .entity_types
            .as_ref()
            .is_none_or(|types| types.contains(&kind))
}

pub(super) fn apply_types(
    scores: &mut Vec<ScoredEntity>,
    filter: &ResolvedRetrievalFilter,
    store: &Store,
    txn: &heed::RoTxn<'_>,
    metadata: &mut EntityMetadataCache,
) -> crate::Result<()> {
    let mut kept = Vec::with_capacity(scores.len());
    for scored in scores.iter().copied() {
        if metadata
            .get(store, txn, &scored.id)?
            .is_some_and(|meta| type_allowed(filter, store, meta.entity_type))
        {
            kept.push(scored);
        }
    }
    *scores = kept;
    Ok(())
}

pub(super) fn candidate_allowed(
    filter: &ResolvedRetrievalFilter,
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &crate::EntityId,
    metadata: &mut EntityMetadataCache,
    gate: &mut ClaimStatusGateCache,
) -> crate::Result<bool> {
    let Some(meta) = metadata.get(store, txn, id)? else {
        return Ok(false);
    };
    if !type_allowed(filter, store, meta.entity_type) {
        return Ok(false);
    }
    if meta.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(true);
    }
    if !claim_status_gate_allows(store, txn, id, metadata, gate)? {
        return Ok(false);
    }
    Ok(gate
        .decisions
        .get(id)
        .and_then(Option::as_ref)
        .is_some_and(|body| claim_allowed(filter, body)))
}

pub(super) fn apply(
    scores: &mut Vec<ScoredEntity>,
    filter: &ResolvedRetrievalFilter,
    store: &Store,
    txn: &heed::RoTxn<'_>,
    metadata: &mut EntityMetadataCache,
    gate: &mut ClaimStatusGateCache,
) -> crate::Result<()> {
    let mut kept = Vec::with_capacity(scores.len());
    for scored in scores.iter().copied() {
        if candidate_allowed(filter, store, txn, &scored.id, metadata, gate)? {
            kept.push(scored);
        }
    }
    *scores = kept;
    Ok(())
}
