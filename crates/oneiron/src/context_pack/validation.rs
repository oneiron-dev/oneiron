//! Post-assembly integrity checks over a context pack.
//!
//! Duplicate ids, missing or deleted payloads, impossible time ordering,
//! disclosure gating (OF-365), and claim/edge reference consistency.

use std::collections::{HashMap, HashSet};

use heed::RoTxn;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimSubject, claim_surfaceable};
use crate::disclosure::{DisclosureContext, DisclosureMode};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::pipeline::ScoredEntity;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;

use super::quarantine::PackQuarantineIndex;
use super::types::ContextEntity;

pub(super) const PACK_VALIDATION_DUPLICATE_ID: &str = "conflicting duplicate id";
pub(super) const PACK_VALIDATION_MISSING_PAYLOAD: &str = "missing referenced payload";
pub(super) const PACK_VALIDATION_IMPOSSIBLE_TIME: &str = "impossible time ordering";
pub(super) const PACK_VALIDATION_MISSING_EVIDENCE: &str = "missing required evidence";
pub(super) const PACK_VALIDATION_DELETED_PAYLOAD: &str = "deleted payload reference";
pub(super) const PACK_VALIDATION_QUARANTINED_PAYLOAD: &str = "quarantined payload reference";

fn context_pack_validation_error(id: EntityId, reason: &'static str) -> Error {
    Error::ContextPackValidation { id, reason }
}

/// OF-365 candidate-sweep admission (enforcement point 1). Fail-closed: a
/// scored id whose payload row is missing is not admitted.
pub(super) fn disclosure_admits_candidate(
    store: &Store,
    rtxn: &RoTxn<'_>,
    ctx: &DisclosureContext,
    id: &EntityId,
    claim_bodies: &HashMap<EntityId, ClaimBody>,
) -> Result<bool> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(false);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("entity metadata header"));
    };
    ctx.admits(store, rtxn, id, header.entity_type, claim_bodies.get(id))
}

/// OF-365 edge-target admission (enforcement points 2 and 3): a non-admitted
/// target is neither admitted as a neighbor, traversed through, nor exposed
/// in a serialized edge list — even the bare target id names the room.
/// `None` clamp admits everything (legacy behavior).
pub(super) fn disclosure_admits_target(
    store: &Store,
    rtxn: &RoTxn<'_>,
    clamp: Option<&DisclosureContext>,
    id: &EntityId,
) -> Result<bool> {
    let Some(ctx) = clamp else {
        return Ok(true);
    };
    if ctx.mode() == DisclosureMode::OwnerAlone {
        return Ok(true);
    }
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(false);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("entity metadata header"));
    };
    ctx.admits(store, rtxn, id, header.entity_type, None)
}

/// OF-365 enforcement point 4 — the final fail-closed sweep: re-checks every
/// surviving entity id (results, neighbors, and every edge target inside
/// them) and FAILS the pack build on any non-admitted survivor instead of
/// serving a leaky pack. The red-team suite asserts this cannot fire
/// spuriously.
pub(super) fn validate_pack_disclosure(
    store: &Store,
    rtxn: &RoTxn<'_>,
    ctx: &DisclosureContext,
    results: &[ContextEntity],
    neighbors: &[ContextEntity],
) -> Result<()> {
    if ctx.mode() == DisclosureMode::OwnerAlone {
        return Ok(());
    }
    for entity in results.iter().chain(neighbors.iter()) {
        if !ctx.admits(store, rtxn, &entity.id, entity.entity_type, None)? {
            return Err(Error::DisclosureClampViolation(
                "non-admitted entity survived pack assembly",
            ));
        }
        let Some(edges) = &entity.edges else {
            continue;
        };
        for edge in edges {
            if !disclosure_admits_target(store, rtxn, Some(ctx), &edge.target)? {
                return Err(Error::DisclosureClampViolation(
                    "non-admitted edge target survived pack assembly",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_scored_candidates(scored: &[ScoredEntity]) -> Result<()> {
    let mut seen = HashSet::with_capacity(scored.len());
    for entry in scored {
        if !seen.insert(entry.id) {
            return Err(context_pack_validation_error(
                entry.id,
                PACK_VALIDATION_DUPLICATE_ID,
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_hydrated_pack_entities(
    results: &[ContextEntity],
    neighbors: &[ContextEntity],
) -> Result<()> {
    let mut seen = HashSet::with_capacity(results.len() + neighbors.len());
    for entity in results.iter().chain(neighbors.iter()) {
        if !seen.insert(entity.id) {
            return Err(context_pack_validation_error(
                entity.id,
                PACK_VALIDATION_DUPLICATE_ID,
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_pack_edge_references(
    store: &Store,
    rtxn: &RoTxn<'_>,
    entities: &[ContextEntity],
    claim_bodies: &mut HashMap<EntityId, ClaimBody>,
    quarantine_index: &PackQuarantineIndex,
) -> Result<()> {
    for entity in entities {
        let Some(edges) = &entity.edges else {
            continue;
        };
        for edge in edges {
            validate_pack_entity_reference(
                store,
                rtxn,
                &edge.target,
                claim_bodies,
                quarantine_index,
            )?;
        }
    }
    Ok(())
}

pub(super) fn validate_pack_entity_reference(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    claim_bodies: &mut HashMap<EntityId, ClaimBody>,
    quarantine_index: &PackQuarantineIndex,
) -> Result<()> {
    validate_pack_payload_reference(store, rtxn, id, quarantine_index)?;
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Err(context_pack_validation_error(
            *id,
            PACK_VALIDATION_MISSING_PAYLOAD,
        ));
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("entity metadata header"));
    };
    validate_entity_time_ordering(*id, header)?;

    if header.entity_type == ENTITY_TYPE_CLAIM {
        if let Some(body) = claim_bodies.get(id) {
            validate_claim_pack_consistency(store, rtxn, *id, body, quarantine_index)?;
        } else {
            let Ok(body) = raw
                .get(ENTITY_METADATA_HEADER_LEN..)
                .ok_or(Error::CorruptedIndex("entity metadata header"))
                .and_then(|payload| crate::claim::decode_claim_body(payload, true))
            else {
                return Ok(());
            };
            validate_claim_pack_consistency(store, rtxn, *id, &body, quarantine_index)?;
            if claim_surfaceable(&body) {
                claim_bodies.insert(*id, body);
            }
        }
    }
    Ok(())
}

fn validate_pack_payload_reference(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    quarantine_index: &PackQuarantineIndex,
) -> Result<()> {
    if store
        .sync_state
        .get(rtxn, &crate::deletion::local_hard_delete_key(id))?
        .is_some()
    {
        return Err(context_pack_validation_error(
            *id,
            PACK_VALIDATION_DELETED_PAYLOAD,
        ));
    }
    if quarantine_index.contains_entity(id) {
        return Err(context_pack_validation_error(
            *id,
            PACK_VALIDATION_QUARANTINED_PAYLOAD,
        ));
    }

    if store.entities.get(rtxn, id.as_bytes())?.is_none() {
        return Err(context_pack_validation_error(
            *id,
            PACK_VALIDATION_MISSING_PAYLOAD,
        ));
    }
    Ok(())
}

fn validate_entity_time_ordering(id: EntityId, header: EntityMetadataHeader) -> Result<()> {
    if header.occurred_start > header.occurred_end {
        return Err(context_pack_validation_error(
            id,
            PACK_VALIDATION_IMPOSSIBLE_TIME,
        ));
    }
    Ok(())
}

fn validate_claim_pack_consistency(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: EntityId,
    body: &ClaimBody,
    quarantine_index: &PackQuarantineIndex,
) -> Result<()> {
    if let (Some(valid_from), Some(valid_to)) = (body.valid_from, body.valid_to)
        && valid_from > valid_to
    {
        return Err(context_pack_validation_error(
            id,
            PACK_VALIDATION_IMPOSSIBLE_TIME,
        ));
    }

    validate_claim_subject_references(store, rtxn, body, quarantine_index)?;
    validate_claim_value_references(store, rtxn, body, quarantine_index)?;

    if body.predicate == crate::provenance::PREDICATE_EDGE_PROVENANCE {
        let record = crate::provenance::decode_edge_provenance_body(&body.value)
            .map_err(|_| context_pack_validation_error(id, PACK_VALIDATION_MISSING_EVIDENCE))?;
        crate::provenance::resolve_persisted_actor_class(&record, body.evidence.as_ref())
            .map_err(|_| context_pack_validation_error(id, PACK_VALIDATION_MISSING_EVIDENCE))?;
    }
    Ok(())
}

fn validate_claim_subject_references(
    store: &Store,
    rtxn: &RoTxn<'_>,
    body: &ClaimBody,
    quarantine_index: &PackQuarantineIndex,
) -> Result<()> {
    match body.subject {
        ClaimSubject::Entity(id) => {
            validate_pack_payload_reference(store, rtxn, &id, quarantine_index)?;
        }
        ClaimSubject::Edge { source, target, .. } => {
            validate_pack_payload_reference(store, rtxn, &source, quarantine_index)?;
            validate_pack_payload_reference(store, rtxn, &target, quarantine_index)?;
        }
    }
    Ok(())
}

fn validate_claim_value_references(
    store: &Store,
    rtxn: &RoTxn<'_>,
    body: &ClaimBody,
    quarantine_index: &PackQuarantineIndex,
) -> Result<()> {
    let Some(value) = crate::affect::decode_affect_trigger_claim(body)? else {
        return Ok(());
    };
    validate_pack_payload_reference(store, rtxn, &value.trigger_ref(), quarantine_index)
}
