use super::*;

/// A sync replay deliberately bypasses the local claim gate. If it changes a
/// claim with a persisted critical-confirm attachment, that attachment binds
/// the old body and cannot authorize the new one: it closes in this same write
/// transaction, and the claim's owner-answer obligation stays open. The peer's
/// bytes land unchanged (FIX 9603): the obligation, this device's own, holds
/// the claim from every consolidation and effect reader until its owner
/// answers.
pub(super) fn reconcile_replicated_critical_confirm(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    data: &[u8],
) -> Result<()> {
    let body_changed = crate::ports::EntityStoreRead::port_entity_raw(store, wtxn, id)?
        .map(|old| {
            old.get(ENTITY_METADATA_HEADER_LEN..)
                .ok_or(Error::CorruptedIndex("entity header"))
                .map(|body| body != data)
        })
        .transpose()?
        // A live attachment can outlast an entity row during deletion or
        // rematerialization; recreating that row is an overwrite of the
        // ceremony-bound state, not an authority restoration.
        .unwrap_or(true);
    crate::gate::reconcile_critical_write_confirm_on_replicated_overwrite(
        store,
        wtxn,
        id,
        body_changed,
    )
}
