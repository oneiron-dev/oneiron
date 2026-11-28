//! The by-item twin of the thin residence index: one `ri:i:{item}:{window}` row per
//! `ri:w:{window}:{item}` listing, written and deleted beside it, so a transaction finds the
//! windows that list an item by the `ri:i:{item}:` prefix without scanning every listing. The
//! rows are device-local and never synced: they live in `sync_state`, which no sync path
//! exports, and change no wire. The soft-drop marker (`ri:u:{item}`) and the listing reader live
//! here too: the marker records that the home stopped listing an item the device does not hold,
//! and the reader finds the item's first decodable listing in any window.
//!
//! A vault written before the twin existed holds listings without one until its next index fetch
//! rewrites the window's page. A shared-vault leave judges each pair once, by its listing's key,
//! and removes both rows in the same purge pass (`store/local_replica/left_env.rs`).

use crate::side_table::{self, Raw, SideTable};

/// The by-item twin rows (`ri:i:`). Key: `{item}:{window}`. Value: `[1]`.
const RESIDENCE_INDEX_BY_ITEM: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_INDEX_BY_ITEM);

/// The by-item twin key of one thin index listing, after the `ri:i:` prefix: `{item}:{window}`.
fn index_by_item_key(window: &str, item: &str) -> String {
    format!("{item}:{window}")
}

/// Puts the `[1]` by-item twin of one thin index listing.
pub(crate) fn put_index_by_item_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    window: &str,
    item: &str,
) -> crate::Result<()> {
    RESIDENCE_INDEX_BY_ITEM.put(store, txn, &index_by_item_key(window, item), &vec![1])
}

/// Deletes the by-item twin of one thin index listing; absent-ok.
pub(crate) fn delete_index_by_item_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    window: &str,
    item: &str,
) -> crate::Result<()> {
    RESIDENCE_INDEX_BY_ITEM.delete(store, txn, &index_by_item_key(window, item))?;
    Ok(())
}

/// Deletes the twin of one full `ri:w:{window}:{item}` key; an unparsable key deletes nothing.
pub(crate) fn delete_index_by_item_for_listing_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    listing_key: &str,
) -> crate::Result<()> {
    let Some((window, item)) = listing_key
        .strip_prefix("ri:w:")
        .and_then(|rest| rest.rsplit_once(':'))
    else {
        return Ok(());
    };
    delete_index_by_item_in_txn(store, txn, window, item)
}

/// The full twin key `ri:i:{item}:{window}` of one full listing key `ri:w:{window}:{item}`;
/// `None` for any other key.
pub(crate) fn index_by_item_key_of_listing(listing_key: &str) -> Option<String> {
    let (window, item) = listing_key.strip_prefix("ri:w:")?.rsplit_once(':')?;
    Some(format!("ri:i:{}", index_by_item_key(window, item)))
}

/// The full listing key `ri:w:{window}:{item}` that one full twin key `ri:i:{item}:{window}`
/// stands for; `None` for any other key.
pub(crate) fn listing_key_of_index_by_item(twin_key: &str) -> Option<String> {
    let (item, window) = twin_key.strip_prefix("ri:i:")?.split_once(':')?;
    Some(format!("ri:w:{window}:{item}"))
}

/// Deletes every by-item row of each of `items`, listed or orphaned; absent-ok.
pub(crate) fn delete_index_by_item_of_items_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    items: &[crate::EntityId],
) -> crate::Result<()> {
    for item in items {
        let prefix = format!("{}:", item.to_hex());
        RESIDENCE_INDEX_BY_ITEM.delete_from(store, txn, prefix.as_bytes())?;
    }
    Ok(())
}

/// Device-local `ri:u:{item}`: a thin source dropped by the home or a soft tombstone.
const SOFT_DROP: SideTable<String, [u8; 1], Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_INDEX_SOFT_DROP);

pub(crate) fn put_soft_drop_marker_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    item_hex: &str,
) -> crate::Result<()> {
    SOFT_DROP.put(store, txn, &item_hex.to_owned(), &[1])
}

pub(crate) fn delete_soft_drop_marker_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    item_hex: &str,
) -> crate::Result<()> {
    SOFT_DROP.delete(store, txn, &item_hex.to_owned())?;
    Ok(())
}

pub(crate) fn soft_drop_marker_exists_in_txn(
    dbs: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    item_hex: &str,
) -> crate::Result<bool> {
    SOFT_DROP.contains(dbs, txn, &item_hex.to_owned())
}

/// The first decodable thin index listing of `item_hex` in any window: the `ri:w:{window}:{item}`
/// twin behind a `ri:i:{item}:{window}` row, decoded as the home listed it. `None` when no window
/// lists the item or no twin decodes; an undecodable twin is skipped, never an error. Windows scan
/// in key order, so the answer is deterministic. Reads use the manifest's sync-state accessor.
pub(crate) fn index_listing_of_item_in_txn(
    dbs: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    item_hex: &str,
) -> crate::Result<Option<crate::sync::residence::window_index::WindowIndexEntry>> {
    let prefix = format!("ri:i:{item_hex}:");
    for row in dbs.sync_state().prefix_iter(txn, &prefix)? {
        let (key, _) = row?;
        let Some(window) = key.strip_prefix(&prefix) else {
            continue;
        };
        let twin = format!("ri:w:{window}:{item_hex}");
        let Some(raw) = dbs.sync_state().get(txn, &twin)? else {
            continue;
        };
        if let Ok(entry) =
            rmp_serde::from_slice::<crate::sync::residence::window_index::WindowIndexEntry>(&raw)
        {
            return Ok(Some(entry));
        }
    }
    Ok(None)
}

/// Marks entries dropped by the fresh page of a still-current window. A
/// window leaving the current set does not call this before purging its rows.
pub(crate) fn mark_index_items_absent_from_page_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    prefix: &str,
    old_keys: &[String],
    fresh_item_hex: &std::collections::HashSet<&str>,
) -> crate::Result<()> {
    for key in old_keys {
        if let Some(item) = key.strip_prefix(prefix)
            && !fresh_item_hex.contains(item)
        {
            put_soft_drop_marker_in_txn(store, txn, item)?;
        }
    }
    Ok(())
}
