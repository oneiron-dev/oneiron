//! Native outcome values beside the bodies consulted by the same fold.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::{AttributedOutcome, OUTCOME, OutcomeRef, PAIRED_OUTCOME};

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
    weighted_read(vault, rtxn, skill, None)
}

pub(in crate::skill_reliability) fn weighted_read(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
    mut observed: Option<&mut super::super::outcome_read::CanonicalOutcomeReads>,
) -> Result<(Vec<(String, AttributedOutcome)>, Option<Vec<EntityId>>)> {
    // An amended attempt is one record, a loss of its share, whatever the
    // attempt lane recorded for it.
    let (amended, mut sources) = super::super::amended::amended_receipt_shares_observed_in_txn(
        vault,
        rtxn,
        skill,
        observed.as_deref_mut(),
    )?;
    let mut outcomes = Vec::new();
    for (key, row) in super::super::outcome_read::scan_rows(
        vault,
        rtxn,
        &OUTCOME,
        skill.as_bytes(),
        crate::store::attempt_sources::OutcomeReadKind::Outcome,
        observed.as_deref_mut(),
    )? {
        sources = None;
        let outcome = OutcomeRef::Unknown(key);
        if amended.contains_key(outcome.receipt())
            || super::super::outcome_read::displaced_read(
                vault,
                rtxn,
                &outcome,
                observed.as_deref_mut(),
            )?
        {
            continue;
        }
        outcomes.push((outcome.into_receipt(), AttributedOutcome::whole(row.win)));
    }
    // Optimization's split is over receipts, across all executors. Pair
    // measurements remain separate; this read only supplies the evidence basis.
    for (key, row) in super::super::outcome_read::scan_rows(
        vault,
        rtxn,
        &PAIRED_OUTCOME,
        skill.as_bytes(),
        crate::store::attempt_sources::OutcomeReadKind::Paired,
        observed.as_deref_mut(),
    )? {
        if key.receipt.is_empty() {
            return Err(Error::CorruptedIndex("skill reliability pair key"));
        }
        sources = None;
        let outcome = OutcomeRef::Paired(key);
        if amended.contains_key(outcome.receipt())
            || super::super::outcome_read::displaced_read(
                vault,
                rtxn,
                &outcome,
                observed.as_deref_mut(),
            )?
        {
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
