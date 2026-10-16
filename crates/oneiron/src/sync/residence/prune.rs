//! Last-touch accounting and pruning for opened-item read caches.
//!
//! Only the thin read cache of an unpromoted item is pruned: its body
//! (`ri:b:`), text document (`ri:d:`), opened marker (`ro:e:`) and touch row
//! (`rt:e:`). The thin index, promoted windows, local writes, deletes and
//! authority stay. No tombstone or Loro operation is produced: a pruned item
//! is fetched again on its next touch.

use crate::EntityId;
use crate::Vault;
use crate::error::Result;

/// Recorded-clock seconds of an opened item's last touch. Key: hex32.
const TOUCH_PREFIX: &str = "rt:e:";

/// Stamp one opened item's last touch inside the caller's transaction.
pub(crate) fn record_item_touch_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    item: EntityId,
    now: u64,
) -> Result<()> {
    vault.store.sync_state.put(
        txn,
        &format!("{TOUCH_PREFIX}{}", item.to_hex()),
        &now.to_be_bytes(),
    )
}

/// Stamp one opened item's last touch. An item with no read cache has
/// nothing to age, so the stamp is skipped.
pub fn record_item_touch(vault: &Vault, item: EntityId) -> Result<()> {
    let now = vault.store.clock.wall_now();
    vault.with_write_txn_grouped(|txn| {
        if vault
            .store
            .sync_state
            .get(txn, &format!("ro:e:{}", item.to_hex()))?
            .is_some()
        {
            record_item_touch_in_txn(vault, txn, item, now)?;
        }
        Ok(())
    })
}

/// Drop the read caches of unpromoted items last touched before `before`
/// (recorded-clock seconds); `u64::MAX` drops every one. An item opened
/// before touches were recorded counts as touched at zero. Returns how many
/// items were pruned.
pub fn prune_thin_items(vault: &Vault, before: u64) -> Result<usize> {
    vault.with_write_txn_grouped(|txn| {
        let opened: Vec<(String, Vec<u8>)> = vault
            .store
            .sync_state
            .prefix_iter(txn, "ro:e:")?
            .map(|row| row.map(|(key, value)| (key.to_string(), value.to_vec())))
            .collect::<std::result::Result<_, _>>()?;
        let mut pruned = 0;
        for (key, window) in opened {
            let Some(id) = key.strip_prefix("ro:e:") else {
                continue;
            };
            let window = String::from_utf8_lossy(&window);
            if vault
                .store
                .sync_state
                .get(txn, &format!("rp:w:{window}"))?
                .is_some()
            {
                continue;
            }
            let touched = vault
                .store
                .sync_state
                .get(txn, &format!("{TOUCH_PREFIX}{id}"))?
                .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_ref()).ok())
                .map_or(0, u64::from_be_bytes);
            if touched >= before {
                continue;
            }
            for family in ["ri:b:", "ri:d:", TOUCH_PREFIX] {
                vault.store.sync_state.delete(txn, &format!("{family}{id}"))?;
            }
            vault.store.sync_state.delete(txn, &key)?;
            pruned += 1;
        }
        // A touch row whose cache already left (promotion, an earlier prune)
        // ages nothing.
        let touches: Vec<String> = vault
            .store
            .sync_state
            .prefix_iter(txn, TOUCH_PREFIX)?
            .map(|row| row.map(|(key, _)| key.to_string()))
            .collect::<std::result::Result<_, _>>()?;
        for key in touches {
            let Some(id) = key.strip_prefix(TOUCH_PREFIX) else {
                continue;
            };
            if vault
                .store
                .sync_state
                .get(txn, &format!("ro:e:{id}"))?
                .is_none()
            {
                vault.store.sync_state.delete(txn, &key)?;
            }
        }
        Ok(pruned)
    })
}
