//! The seat behind a market submission (FIX MARKET-SEAT-MODEL-STAMP): the
//! harness its member ran in and the model behind it, frozen at the first
//! accepted submit, so a comparison groups scores per model (ARCH-0079).
//!
//! A call through an attached credential takes the seat the owner declared
//! on that credential's pairing link, and only that: the host's seat did not
//! write the candidate. A run the engine seated takes the engine's own seat
//! receipt. With neither, the seat is unknown. No slip id is kept or shown.

use super::Submission;
use crate::attempt_queue::AttemptId;
use crate::error::Result;
use crate::team::run::{TeamMarketSeat, TeamMarketSeatSource, TeamMarketSubmissionView};
use crate::{EntityId, Vault};

/// The harness of a run the engine seated: its own code mode.
pub const HOST_HARNESS: &str = "oneiron";

/// The seat of the member attempt `caller`'s submission: the owner's
/// declaration for `live_run_slip` when the call came through an attached
/// credential, else the engine's seat receipt for the run.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn submission_seat_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: AttemptId,
    live_run_slip: Option<[u8; 32]>,
) -> Result<Option<TeamMarketSeat>> {
    if let Some(slip_id) = live_run_slip {
        let paired = vault.paired_seat_in_txn(txn, &slip_id)?;
        return Ok(paired.map(|paired| TeamMarketSeat {
            harness: paired.harness,
            model: paired.model,
            source: TeamMarketSeatSource::OwnerPaired,
        }));
    }
    let run = EntityId::from_bytes(*caller.as_bytes())?;
    let receipt = vault.model_seat_receipt_in_txn(txn, run)?.filter(|_| false);
    Ok(receipt.map(|receipt| TeamMarketSeat {
        harness: HOST_HARNESS.to_owned(),
        model: receipt.model.as_str().to_owned(),
        source: TeamMarketSeatSource::HostSeat,
    }))
}

/// Each submission with its seat beside its score, in submission order.
pub(crate) fn submission_views(submissions: &[Submission]) -> Vec<TeamMarketSubmissionView> {
    submissions
        .iter()
        .map(|submission| TeamMarketSubmissionView {
            submission_ref: submission.submission_ref.clone(),
            participant: submission.agent.clone(),
            seat: submission.seat.clone(),
            score: submission.score,
            passed: submission.passed,
            unknown: submission
                .evidence
                .as_ref()
                .is_some_and(|evidence| evidence.unknown),
        })
        .collect()
}
