//! Deferred calendar-origin binding after entity/claim/edge replay settles.

use super::RematCtx;
use crate::ports::EntityStoreRead;
use crate::sync::{loro_support::map_for_each_value_bytes, quarantine};
use crate::{EntityId, Error, Result};
use std::collections::BTreeMap;
const PENDING: &[u8] = b"calendar_origin_pending:v1:";

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
        for row in ctx.vault.store.vault_meta.prefix_iter(txn, PENDING)? {
            let (key, window) = row?;
            let id = EntityId::from_bytes(
                key[PENDING.len()..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("calendar pending id"))?,
            )?;
            let window = std::str::from_utf8(&window)
                .map_err(|_| Error::CorruptedIndex("calendar pending window"))?;
            candidates.insert(id, window.to_owned());
        }
        for (id, window) in &candidates {
            let key = [PENDING, id.as_bytes()].concat();
            if crate::calendar::origin::replay_origin_bound(&ctx.vault.store, txn, *id)? {
                // Never clear someone else's hard-delete retry marker.
                if ctx.vault.store.vault_meta.delete(txn, &key)? {
                    quarantine::clear_replay_remat_marker_in_txn(ctx.vault, txn, window, id)?;
                }
            } else {
                let row = ctx
                    .vault
                    .store
                    .port_entity_record(txn, id)?
                    .ok_or(Error::EntityNotFound)?;
                ctx.vault
                    .store
                    .vault_meta
                    .put(txn, &key, window.as_bytes())?;
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
