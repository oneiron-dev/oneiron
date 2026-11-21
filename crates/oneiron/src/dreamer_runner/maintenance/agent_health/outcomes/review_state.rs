//! One agent-health review state froze the card's DIAGNOSTICs and evidence
//! ids as an outcome found them (FIX 8082). They are stored once under the
//! state's `health_review:` digest and shared by every receipt of that state.
//! The rows hold ids only, never a body or brief text.

use crate::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

#[doc(hidden)]
pub use oneiron_records::dreamer_runner::maintenance::agent_health::outcomes::review_state::HealthReviewState;

const REVIEW_STATES: SideTable<[u8; 32], HealthReviewState, Named> =
    SideTable::new(&side_table::COACH_AGENT_HEALTH_REVIEW_STATE);

/// Stores a receipt's review state unless that digest already has its row.
pub(crate) fn put_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    receipt: &str,
    state: &HealthReviewState,
) -> Result<()> {
    let Some(digest) = super::super::receipt_index::receipt_digest(receipt) else {
        return Ok(());
    };
    if REVIEW_STATES.get(store, txn, &digest)?.is_none() {
        REVIEW_STATES.put(store, txn, &digest, state)?;
    }
    Ok(())
}

/// Reads the review state frozen under a receipt's digest.
pub(crate) fn get_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    receipt: &str,
) -> Result<Option<HealthReviewState>> {
    let Some(digest) = super::super::receipt_index::receipt_digest(receipt) else {
        return Ok(None);
    };
    REVIEW_STATES.get(store, txn, &digest)
}

/// Deletes the review state under `digest`.
pub(crate) fn delete_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    digest: &[u8; 32],
) -> Result<()> {
    REVIEW_STATES.delete(store, txn, digest)?;
    Ok(())
}
