//! The fold a door judges arriving authority rows against (FIX 2535): this
//! vault's stored log with the arriving rows folded in as stored rows first
//! seen now, in the caller's snapshot. It is never cached, so no candidate
//! row reaches the committed authorization view before it is stored.

use super::*;

/// The fold of the stored log with `arriving` in it, or the history it
/// still needs.
pub(in crate::authority) enum ArrivingFold {
    Complete(AuthorityView),
    NeedHistory(AuthorityHistoryRequest),
}

/// This vault's log with `arriving` folded in, in `txn`'s snapshot, as
/// [`authority_view_readonly_for_store_in_txn`] folds the stored log alone,
/// from no cached base. Never cached.
pub(in crate::authority) fn authority_view_with_rows_for_store_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
    arriving: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
) -> Result<ArrivingFold> {
    let key = authority_cache_key(store, posture, txn)?;
    Ok(
        match fold_authority_checkpoint_tail_in_txn(
            store,
            posture,
            txn,
            key,
            None,
            &BTreeSet::new(),
            arriving,
        )? {
            AuthorityTailFold::Complete { view, .. } => ArrivingFold::Complete(view),
            AuthorityTailFold::NeedHistory(request) => ArrivingFold::NeedHistory(request),
        },
    )
}
