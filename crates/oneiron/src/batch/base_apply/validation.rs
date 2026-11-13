use super::*;
use crate::error::RegistryError;
use crate::registry::{ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_OUTBOUND_GRANT, ENTITY_TYPE_SKILL};

type PreflightDecisionIds = HashMap<EntityId, VecDeque<Option<crate::store::GateDecisionId>>>;

pub(super) fn mark_unapplied_preflight_decisions(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    ids: &PreflightDecisionIds,
) -> Result<()> {
    for id in ids.values().flat_map(|queue| queue.iter().flatten()) {
        store.mark_unapplied_preflight_decision_in_txn(wtxn, *id)?;
    }
    Ok(())
}

pub(super) fn consume_preflight_decisions(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    ids: impl IntoIterator<Item = Option<crate::store::GateDecisionId>>,
) -> Result<()> {
    for id in ids.into_iter().flatten() {
        store.consume_unapplied_preflight_decision_in_txn(wtxn, id)?;
    }
    Ok(())
}

pub(super) fn take_lapse_decisions(
    preflight: &mut PreflightDecisionIds,
    ids: &[EntityId],
) -> PreflightDecisionIds {
    let mut decisions = PreflightDecisionIds::new();
    for id in ids {
        let decision_id = preflight
            .get_mut(id)
            .and_then(VecDeque::pop_front)
            .flatten();
        decisions.entry(*id).or_default().push_back(decision_id);
    }
    decisions
}

/// Resolves pack handles and enforces the public/maintenance put-type boundary.
pub(super) fn validate_put_type(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    (mut entity_type, data): (u8, &mut Vec<u8>),
    allow_maintenance: bool,
    allow_reserved_predicate: bool,
    hub_sync_imported: bool,
) -> Result<u8> {
    // Replay/import resolves GLOBAL identity before local-byte validation.
    // Foreign byte and generation never select the destination kind.
    if allow_maintenance
        && allow_reserved_predicate
        && crate::registry::zone_of(entity_type) == crate::registry::TypeByteZone::PackHandle
    {
        let source = crate::registry::pack_byte_map::PackInstanceEnvelope::from_bytes(data)?;
        let (local_handle, local_envelope) = store.remap_pack_instance_in_txn(wtxn, &source)?;
        entity_type = local_handle;
        *data = local_envelope.to_bytes()?;
    }
    if hub_sync_imported
        && (entity_type != ENTITY_TYPE_SKILL || allow_maintenance || allow_reserved_predicate)
    {
        return Err(Error::InvariantViolation(
            "hub-sync imported flag is only valid for a local SKILL Put",
        ));
    }
    // Public writes reject engine-authored system kinds via
    // the public entity-type gate; the sync rematerialization path
    // sets `allow_maintenance` so REDACTION_AUDIT receipts
    // survive CRDT→LMDB replay (registry-only entity-type validation
    // still rejects genuinely unknown type bytes).
    if allow_maintenance
        && allow_reserved_predicate
        && matches!(
            entity_type,
            ENTITY_TYPE_ACCESS_GRANT | ENTITY_TYPE_OUTBOUND_GRANT
        )
    {
        return Err(Error::Registry(RegistryError::MaintenanceKindNotWritable(
            entity_type,
        )));
    }
    // A replayed custody body carries no owner proof, so no replica stores
    // one: a peer could otherwise rewrite a value or revive a revoked record.
    if allow_maintenance
        && allow_reserved_predicate
        && entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY
    {
        return Err(crate::secret_record::reject_secret_custody_byte());
    }
    if crate::registry::zone_of(entity_type) == crate::registry::TypeByteZone::PackHandle {
        store.validate_pack_handle_in_txn(wtxn, entity_type)?;
        store.validate_pack_instance_in_txn(wtxn, entity_type, data)?;
    } else if allow_maintenance {
        store.validate_entity_type(entity_type)?;
    } else {
        store.validate_public_entity_type(entity_type)?;
    }
    // A local write to a thin-cached id waits for its window's promotion.
    #[cfg(feature = "sync")]
    if !(allow_maintenance && allow_reserved_predicate) {
        crate::sync::residence::require_promoted_for_cached_id(store, wtxn, id)?;
    }
    #[cfg(not(feature = "sync"))]
    let _ = id;
    Ok(entity_type)
}

/// The ids this batch writes a `DerivedFrom` edge from: a text put among
/// them names its sources in that edge, whatever its put names.
pub(super) fn derived_from_edge_sources(ops: &[BatchOp]) -> BTreeSet<EntityId> {
    ops.iter()
        .filter_map(|op| match op {
            BatchOp::Edge {
                src,
                kind: crate::edge::EdgeKind::DerivedFrom,
                ..
            }
            | BatchOp::PublicEdgeWithCreatedAt {
                src,
                kind: crate::edge::EdgeKind::DerivedFrom,
                ..
            }
            | BatchOp::EdgeWithCreatedAt {
                src,
                kind: crate::edge::EdgeKind::DerivedFrom,
                ..
            } => Some(*src),
            _ => None,
        })
        .collect()
}

/// Whether a put of `entity_type` at `id` births a source-free ASSET_TEXT
/// (FIX 8741): a text whose put names no `sources`, in a batch that writes no
/// `DerivedFrom` edge from it (`derived`). A text that batch derives without
/// naming its sources at the put (a promotion replay, a raw edge op) is no
/// source-free birth; it keeps the reading such a text had, unplaced.
pub(super) fn source_free_text_birth(
    entity_type: u8,
    id: &EntityId,
    sources: Option<&[EntityId]>,
    derived: &BTreeSet<EntityId>,
) -> bool {
    entity_type == crate::registry::ENTITY_TYPE_ASSET_TEXT
        && sources.is_none()
        && !derived.contains(id)
}

/// The FACET a NOTE, ASSET, CLAIM, EVENT, TURN or TASK put at `id` is born
/// under. A CLAIM carries its facet in its body, so its birth edge follows the
/// body's `scopeFacetId` (FIX 7757); a NOTE, ASSET, EVENT, TURN or TASK uses
/// the batch mask, else the vault default. A TASK's mask is its writer's facet
/// (ARCH-0022 #facets, UNBUILT item 10: "With no active mask, the vault's
/// default facet stamps it"); an authority fact's is its TASK's. An ASSET_TEXT put
/// with the `sources` it was written from is born under the one facet they were
/// born under (facet rule C); a `source_free` one ([`source_free_text_birth`])
/// under the batch mask, else the vault default, as a NOTE is (FIX 8741).
/// `None` when the put births nothing that carries a stamp — a put over a
/// stored row, another kind, a text derived with unnamed sources, or a
/// replicated put, whose origin's `FacetOf` edge arrives in the same window.
pub(super) fn birth_stamp_target(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    entity_type: u8,
    replicated: bool,
    (mask, sources, source_free): (Option<EntityId>, Option<&[EntityId]>, bool),
    data: &[u8],
) -> Result<Option<EntityId>> {
    let sources = sources.filter(|_| entity_type == crate::registry::ENTITY_TYPE_ASSET_TEXT);
    if replicated
        || !(sources.is_some()
            || source_free
            || matches!(
                entity_type,
                crate::registry::ENTITY_TYPE_NOTE
                    | crate::registry::ENTITY_TYPE_ASSET
                    | crate::registry::ENTITY_TYPE_CLAIM
                    | crate::registry::ENTITY_TYPE_EVENT
                    | crate::registry::ENTITY_TYPE_TURN
                    | crate::registry::ENTITY_TYPE_TASK
            ))
        || crate::ports::EntityStoreRead::port_entity_present(store, txn, &id)?
    {
        return Ok(None);
    }
    if let Some(sources) = sources {
        return crate::federation::record_scope::asset_text::sources_birth_facet(
            store, txn, sources,
        )
        .map(Some);
    }
    if entity_type == crate::registry::ENTITY_TYPE_CLAIM {
        let body = crate::claim::decode_claim_body(data, true)?;
        return Ok(Some(body.scope_facet));
    }
    match mask {
        Some(mask) => Ok(Some(mask)),
        None => crate::claim::default_facet_in(store, txn).map(Some),
    }
}
