//! The mint's input join (design pass 32 r2, section 4.3 inputs; row M2-E):
//! what the line's own arm rows and unit claims inside the window of a
//! period say about each family. Row M2-A defines the tally
//! ([`SettledTally`]) and the mint that reads it; this file fills it.
//!
//! - `cost_secs`: every second charged to a `Settled` claim of the family's
//!   arms whose `ended_at_ms` is in the window, whatever the rung's state:
//!   open, held, awaiting review or killed, the time was spent (LE-5 = A).
//!   Review checks are claims of the rung and count the same.
//! - `invalid_secs`: those seconds of a rung that closed invalid before the
//!   cutoff (the period's start), by the time of the verdict or review that
//!   closed it. A rung closed invalid after the cutoff counts as cost.
//! - `wins` and `losses`: rungs whose outcome was written before the cutoff
//!   and whose `work_done_at_ms` is in the window, so a result joins the
//!   window of its own work. An experiment (family, contract sha256) wins a
//!   rung at most once.
//! - Not inputs: open claims, released, box-lost and written-off claims, any
//!   generic team receipt, any row of another line.
//!
//! The family is the arm's project, so a seat that replaces an earlier one
//! (`replaces`) carries the earlier seat's history on.
use std::collections::{BTreeMap, BTreeSet};

use super::claim::{ClaimState, UnitEnd, claims_at_rung_in_txn};
use super::fold::GpuLine;
use super::mint::SettledTally;
use crate::experiment_arm::{ArmRung, RungEnd, RungState};
use crate::{EntityId, Vault};

/// What the line's own rows inside the window of period `index` say about
/// each family of `line`, keyed by the family's project. A family with no
/// row in the window has no entry; the mint reads it as zero.
///
/// # Errors
///
/// A store read failure.
pub fn settled_tallies_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    line: &GpuLine,
    index: u32,
) -> crate::Result<BTreeMap<EntityId, SettledTally>> {
    let Some((from, cutoff)) = line.window_of(index) else {
        return Ok(BTreeMap::new());
    };
    let in_window = |at_ms: u64| (from..cutoff).contains(&at_ms);
    let mut tallies: BTreeMap<EntityId, SettledTally> = BTreeMap::new();
    // (family, contract sha256, rung) of each win counted.
    let mut won: BTreeSet<(EntityId, String, u8)> = BTreeSet::new();
    for arm in vault
        .experiment_arms_in_txn(txn)?
        .into_iter()
        .filter(|arm| arm.line == line.project)
    {
        for rung in &arm.rungs {
            let invalid = closed_invalid_before(rung, cutoff);
            let charged = claims_at_rung_in_txn(vault, txn, &arm.id, rung.rung)?
                .into_iter()
                .filter_map(|claim| match claim.state {
                    ClaimState::Ended(terminal)
                        if terminal.end == UnitEnd::Settled && in_window(terminal.ended_at_ms) =>
                    {
                        Some(terminal.charged_secs)
                    }
                    _ => None,
                })
                .fold(0_u64, u64::saturating_add);
            let scored = rung.outcome.as_ref().filter(|outcome| {
                outcome.at_ms < cutoff && rung.work_done_at_ms.is_some_and(in_window)
            });
            if charged == 0 && scored.is_none() {
                continue;
            }
            let tally = tallies.entry(arm.family).or_default();
            if invalid {
                tally.invalid_secs = tally.invalid_secs.saturating_add(charged);
            } else {
                tally.cost_secs = tally.cost_secs.saturating_add(charged);
            }
            match scored {
                Some(outcome) if outcome.success => {
                    if won.insert((arm.family, arm.contract.sha256.clone(), rung.rung)) {
                        tally.wins = tally.wins.saturating_add(1);
                    }
                }
                Some(_) => tally.losses = tally.losses.saturating_add(1),
                None => {}
            }
        }
    }
    Ok(tallies)
}

/// Whether `rung` closed invalid before `cutoff`: by its review when a
/// review changed a promote to invalid, else by its verdict.
fn closed_invalid_before(rung: &ArmRung, cutoff: u64) -> bool {
    if !matches!(
        rung.state,
        RungState::Closed {
            end: RungEnd::Invalid { .. }
        }
    ) {
        return false;
    }
    let closed_at = rung
        .review
        .as_ref()
        .map(|review| review.at_ms)
        .or_else(|| rung.verdict.as_ref().map(|verdict| verdict.at_ms));
    closed_at.is_some_and(|at_ms| at_ms < cutoff)
}
