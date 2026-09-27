use super::*;
use crate::registry::{ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_OUTBOUND_GRANT, ENTITY_TYPE_SKILL};
use crate::secret_custody::validate_replicated_custody_put;

type PreflightDecisionIds = HashMap<EntityId, VecDeque<Option<crate::store::GateDecisionId>>>;

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
    // Same-vault custody replication is opt-out per credential. A
    // remote portable body cannot widen a locally narrowed record.
    if allow_maintenance
        && allow_reserved_predicate
        && entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY
    {
        validate_replicated_custody_put(store, wtxn, id, data)?;
    }
    if crate::registry::zone_of(entity_type) == crate::registry::TypeByteZone::PackHandle {
        store.validate_pack_handle_in_txn(wtxn, entity_type)?;
        store.validate_pack_instance_in_txn(wtxn, entity_type, data)?;
    } else if allow_maintenance {
        store.validate_entity_type(entity_type)?;
    } else {
        store.validate_public_entity_type(entity_type)?;
    }
    Ok(entity_type)
}

/// The FACET a NOTE or ASSET put at `id` is born under: the batch mask, else
/// the vault default. `None` when the put births nothing that carries a stamp —
/// a put over a stored row, another kind, or a replicated put, whose origin's
/// `FacetOf` edge arrives in the same window.
pub(super) fn birth_stamp_target(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    entity_type: u8,
    replicated: bool,
    mask: Option<EntityId>,
) -> Result<Option<EntityId>> {
    if replicated
        || !matches!(
            entity_type,
            crate::registry::ENTITY_TYPE_NOTE | crate::registry::ENTITY_TYPE_ASSET
        )
        || crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)?.is_some()
    {
        return Ok(None);
    }
    match mask {
        Some(mask) => Ok(Some(mask)),
        None => crate::claim::default_facet_in(store, txn).map(Some),
    }
}
