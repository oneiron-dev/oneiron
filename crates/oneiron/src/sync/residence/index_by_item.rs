//! The by-item twin of the thin residence index: one `ri:i:{item}:{window}` row per
//! `ri:w:{window}:{item}` listing, written and deleted beside it, so a transaction finds the
//! windows that list an item by the `ri:i:{item}:` prefix without scanning every listing. The
//! rows are device-local and never synced: they live in `sync_state`, which no sync path
//! exports, and change no wire.

/// The by-item twin key of one thin index listing: `ri:i:{item}:{window}`.
fn index_by_item_key(window: &str, item: &str) -> String {
    format!("ri:i:{item}:{window}")
}

/// Puts the `[1]` by-item twin of one thin index listing.
pub(crate) fn put_index_by_item_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    window: &str,
    item: &str,
) -> crate::Result<()> {
    store
        .sync_state
        .put(txn, &index_by_item_key(window, item), &[1])
}

/// Deletes the by-item twin of one thin index listing; absent-ok.
pub(crate) fn delete_index_by_item_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    window: &str,
    item: &str,
) -> crate::Result<()> {
    store
        .sync_state
        .delete(txn, &index_by_item_key(window, item))?;
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

/// Deletes every by-item row of each of `items`, listed or orphaned; absent-ok.
pub(crate) fn delete_index_by_item_of_items_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    items: &[crate::EntityId],
) -> crate::Result<()> {
    for item in items {
        let prefix = format!("ri:i:{}:", item.to_hex());
        let keys: Vec<String> = store
            .sync_state
            .prefix_iter(txn, &prefix)?
            .map(|row| row.map(|(key, _)| key.to_string()))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for key in &keys {
            store.sync_state.delete(txn, key)?;
        }
    }
    Ok(())
}
