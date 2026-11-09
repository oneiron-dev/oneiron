//! Candidate refs in retained audit decisions, scrubbed with their saved copies.

use super::AUDIT;
use crate::attempt_queue::AttemptId;
use crate::side_table::SideKey;
use crate::{EntityId, Result};

/// Scrubs valid canonical rows without making an unrelated malformed audit
/// refuse an otherwise working erase. Raw storage errors still abort the writer.
pub(crate) fn forget_audit_candidate_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let mut changed = Vec::new();
    for row in AUDIT.iter_raw_from(store, txn, &[])? {
        let (key, raw) = row?;
        let Some(attempt) = AttemptId::decode_key(&key) else {
            tracing::warn!("a sieve audit key did not decode; its candidate refs are unchanged");
            continue;
        };
        let mut audit = match AUDIT.decode_value(&raw) {
            Ok(audit) => audit,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a sieve audit did not decode; its candidate refs are unchanged"
                );
                continue;
            }
        };
        if audit.forget_decision_candidate(id) {
            changed.push((attempt, audit));
        }
    }
    for (attempt, audit) in changed {
        AUDIT.put(store, txn, &attempt, &audit)?;
    }
    Ok(())
}
