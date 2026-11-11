//! One agent-health review state froze the card's DIAGNOSTICs and evidence
//! ids as an outcome found them (FIX 8082). They are stored once under the
//! state's `health_review:` digest and shared by every receipt of that state.
//! The rows hold ids only, never a body or brief text.

use serde::{Deserialize, Serialize};

use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::{EntityId, Result};

/// The DIAGNOSTICs and evidence one review state froze.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthReviewState {
    /// The card's DIAGNOSTICs when it was set, newest last.
    pub diagnostics: Vec<EntityId>,
    /// The card's receipt and attempt ids when it was set, newest last.
    pub evidence: Vec<EntityId>,
}

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
