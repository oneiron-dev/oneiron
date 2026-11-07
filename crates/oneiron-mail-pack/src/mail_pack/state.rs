//! Lifted half of `oneiron::mail_pack::state` (core split, `oneiron-mail-pack`): the items below moved out of
//! `oneiron`; the items that stay there are re-exported here, so paths in this crate resolve as before.

use crate::EntityId;
use crate::Result;
use crate::Vault;
#[allow(unused_imports)]
use crate::ext::*;
pub use oneiron::mail_pack::state::*;

/// The key of the provider message `provider_id` of `source`.
pub(super) fn occurrence_key(source: EntityId, provider_id: &str) -> (EntityId, [u8; 32]) {
    (source, *blake3::hash(provider_id.as_bytes()).as_bytes())
}

/// Records that `rows` landed for the provider message keyed `key`, so an
/// erase of any of them reaches it.
pub(super) fn record_occurrence_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &(EntityId, [u8; 32]),
    rows: &[EntityId],
    at: u64,
) -> Result<()> {
    for row in rows {
        OCCURRENCE_ROWS.put(&vault.store, txn, &(*row, key.0, key.1), &at)?;
    }
    Ok(())
}

/// The provider ids of up to `limit` messages waiting for their bodies,
/// newest first.
pub(super) fn bodies_waiting_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: EntityId,
    limit: usize,
) -> Result<Vec<String>> {
    let mut waiting = Vec::new();
    for row in BODY_QUEUE.iter_from(&vault.store, txn, source.as_bytes())? {
        if waiting.len() >= limit {
            break;
        }
        waiting.push(row?.1);
    }
    Ok(waiting)
}
