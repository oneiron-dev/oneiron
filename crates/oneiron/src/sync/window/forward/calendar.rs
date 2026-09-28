//! Deferred calendar-origin binding after entity/claim/edge replay settles.

use super::RematCtx;
use crate::ports::EntityStoreRead;
use crate::side_table::{self, Raw, SideTable};
use crate::sync::{loro_support::map_for_each_value_bytes, quarantine};
use crate::{EntityId, Error, Result};
use std::collections::BTreeMap;

/// Retired-EVENT-calendar reconciliation retry marker, keyed by entity id; the
/// value is the window key to retry against.
const CALENDAR_ORIGIN_PENDING: SideTable<EntityId, String, Raw> =
    SideTable::new(&side_table::SYNC_CALENDAR_ORIGIN_PENDING);

pub(super) fn reconcile(ctx: &RematCtx<'_>) -> Result<()> {
    let mut candidates = BTreeMap::new();
    map_for_each_value_bytes(&ctx.entities_map, |key, raw| {
        if raw
            .and_then(crate::batch::EntityMetadataHeader::parse)
            .is_some_and(|h| h.entity_type == crate::registry::ENTITY_TYPE_EVENT)
            && let Ok(id) = EntityId::from_hex(key)
        {
            candidates.insert(id, ctx.window_key.as_str().to_owned());
        }
    });
    ctx.vault.with_write_txn(|txn| {
        // A claim can arrive through a different window. Retry only pending
        // EVENTs rather than scanning every calendar row on every import.
        for (id, window) in CALENDAR_ORIGIN_PENDING.scan(&ctx.vault.store, txn)? {
            candidates.insert(id, window);
        }
        for (id, window) in &candidates {
            if crate::calendar::origin::replay_origin_bound(&ctx.vault.store, txn, *id)? {
                // Never clear someone else's hard-delete retry marker.
                if CALENDAR_ORIGIN_PENDING.delete(&ctx.vault.store, txn, id)? {
                    quarantine::clear_replay_remat_marker_in_txn(ctx.vault, txn, window, id)?;
                }
            } else {
                let row = ctx
                    .vault
                    .store
                    .port_entity_record(txn, id)?
                    .ok_or(Error::EntityNotFound)?;
                CALENDAR_ORIGIN_PENDING.put(&ctx.vault.store, txn, id, window)?;
                quarantine::quarantine_rejected_op_in_txn(
                    ctx.vault,
                    txn,
                    window,
                    quarantine::QuarantineContainer::Entities,
                    &id.to_hex(),
                    &Error::InvalidClaimBody("calendar origin claim has not been reconciled"),
                    &row.encode(),
                )?;
            }
        }
        Ok(())
    })
}
