//! Last-touch accounting and pruning for opened-item read caches, and the
//! demotion of a promoted canonical window.
//!
//! Only the thin read cache of an unpromoted item is pruned: its body
//! (`ri:b:`), text document (`ri:d:`), opened marker (`ro:e:`) and touch row
//! (`rt:e:`). The thin index, promoted windows, local writes, deletes and
//! authority stay, and so does the cache of an item a legal hold names. No
//! tombstone or Loro operation is produced: a pruned item is fetched again on
//! its next touch.
//!
//! A promoted window is demoted only on request, once the home holds every
//! op of it: its local replica goes with its `rp:w:` marker, and its items
//! read through the thin cache again. That writes nothing replicated either.

use loro::VersionVector;

use crate::EntityId;
use crate::Vault;
use crate::error::Result;
use crate::store::Store;
use crate::store::legal_hold::HoldActor;
use crate::store::local_replica::{KeepControls, remove_local_replica_window_in_txn};
use crate::sync::WindowKey;
use crate::sync::window_rows::{WINDOW_SNAPSHOT, WINDOW_UPDATE};

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
            // A legal hold keeps every byte of the rows it names, a cached
            // copy too: a held item's cache stays (OF-470).
            let Ok(item) = EntityId::from_hex(id) else {
                continue;
            };
            if vault
                .store
                .reject_legal_holds_in_txn(txn, &[item], &HoldActor::UNATTRIBUTED)
                .is_err()
            {
                continue;
            }
            for family in ["ri:b:", "ri:d:", TOUCH_PREFIX] {
                vault
                    .store
                    .sync_state
                    .delete(txn, &format!("{family}{id}"))?;
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

/// What one [`demote_resident_window`] call did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WindowDemotion {
    /// Entity rows removed with their projections.
    pub removed: usize,
    /// Members left in place: controls, tombstoned, pending or uncarried
    /// rows, which stay readable here.
    pub kept: usize,
    /// The replica and its `rp:w:` marker are gone: the window is thin again.
    /// `false` when the home lacks an op the window holds, or a queued write
    /// for it waits.
    pub complete: bool,
}

/// Demotes promoted canonical window `window` back to thin (OF-534). Nothing
/// goes unless `home`, the home's version vector for the window, covers every
/// op the persisted replica holds, so a later promotion gives each removed
/// row back. Then the replica goes in bounded steps with the window held
/// closed, and its `rp:w:` marker with the last step. A queued write for the
/// window defers it until the outbox drains. `None` while the window is live.
pub(crate) fn demote_resident_window(
    vault: &Vault,
    window: &WindowKey,
    home: &VersionVector,
) -> Result<Option<WindowDemotion>> {
    vault
        .while_window_closed(window, || {
            let mut demotion = WindowDemotion::default();
            let held = {
                let txn = vault.store.env.read_txn()?;
                persisted_window_vv(&vault.store, &txn, window)?
            };
            if !home.includes_vv(&held) {
                return Ok(demotion);
            }
            loop {
                let step = vault.with_write_txn_grouped(|txn| {
                    let step = remove_local_replica_window_in_txn(
                        &vault.store,
                        txn,
                        window,
                        KeepControls::default(),
                    )?;
                    if step.complete {
                        vault
                            .store
                            .sync_state
                            .delete(txn, &format!("rp:w:{window}"))?;
                    }
                    Ok(step)
                })?;
                demotion.removed += step.removed.len();
                demotion.kept = step.kept.len();
                if step.complete {
                    demotion.complete = true;
                    break;
                }
                // A queued write deferred the step, or nothing moved.
                if step.removed.is_empty() {
                    break;
                }
            }
            Ok(demotion)
        })
        .transpose()
}

/// The version vector of `window`'s persisted document: its `d:w:` snapshot
/// with every `u:w:` row on top.
fn persisted_window_vv(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    window: &WindowKey,
) -> Result<VersionVector> {
    let doc = match WINDOW_SNAPSHOT.get(store, txn, &window.as_str().to_owned())? {
        Some(bytes) => crate::sync::loro_support::doc_from_snapshot(&bytes)?,
        None => crate::sync::schema::create_window_doc("local", window),
    };
    let prefix = format!("{window}:");
    for (_, bytes) in WINDOW_UPDATE.scan_from(store, txn, prefix.as_bytes())? {
        crate::sync::loro_support::import_doc(&doc, &bytes)?;
    }
    Ok(doc.oplog_vv())
}
