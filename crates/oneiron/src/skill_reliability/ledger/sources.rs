//! Native outcome values beside the bodies consulted by the same fold.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::{AttributedOutcome, OUTCOME, OutcomeRef, PAIRED_OUTCOME, is_displaced};

/// World labels beside their complete native read-body sources. The outcome,
/// amendment and displacement tables have no EntityId body carriers; a read
/// that encounters those rows is unknown, even when its result filters empty.
pub(crate) fn attributed_outcome_results_sourced(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<(Vec<(String, bool)>, Option<Vec<EntityId>>)> {
    let (outcomes, sources) = attributed_outcomes_weighted_sourced(vault, rtxn, skill)?;
    Ok((
        outcomes
            .into_iter()
            .map(|(receipt, outcome)| (receipt, outcome.win))
            .collect(),
        sources,
    ))
}

pub(crate) fn attributed_outcomes_weighted_sourced(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<(Vec<(String, AttributedOutcome)>, Option<Vec<EntityId>>)> {
    // An amended attempt is one record, a loss of its share, whatever the
    // attempt lane recorded for it.
    let (amended, mut sources) =
        super::super::amended::amended_receipt_shares_sourced_in_txn(vault, rtxn, skill)?;
    let mut outcomes = Vec::new();
    for (key, row) in OUTCOME.scan_from(&vault.store, rtxn, skill.as_bytes())? {
        sources = None;
        let outcome = OutcomeRef::Unknown(key);
        if amended.contains_key(outcome.receipt()) || is_displaced(vault, rtxn, &outcome)? {
            continue;
        }
        outcomes.push((outcome.into_receipt(), AttributedOutcome::whole(row.win)));
    }
    // Optimization's split is over receipts, across all executors. Pair
    // measurements remain separate; this read only supplies the evidence basis.
    for (key, row) in PAIRED_OUTCOME.scan_from(&vault.store, rtxn, skill.as_bytes())? {
        if key.receipt.is_empty() {
            return Err(Error::CorruptedIndex("skill reliability pair key"));
        }
        sources = None;
        let outcome = OutcomeRef::Paired(key);
        if amended.contains_key(outcome.receipt()) || is_displaced(vault, rtxn, &outcome)? {
            continue;
        }
        outcomes.push((outcome.into_receipt(), AttributedOutcome::whole(row.win)));
    }
    for (receipt, share) in amended {
        let outcome = AttributedOutcome {
            win: false,
            loss: share,
        };
        outcomes.push((receipt, outcome));
    }
    outcomes.sort_by(|a, b| a.0.cmp(&b.0));
    // One receipt is one outcome for the split, even when several executors
    // invoked a callable under it; a loss outranks a win, as in the ledger.
    outcomes.dedup_by(|next, kept| {
        next.0 == kept.0 && {
            kept.1.win &= next.1.win;
            kept.1.loss = kept.1.loss.max(next.1.loss);
            true
        }
    });
    Ok((outcomes, sources))
}
