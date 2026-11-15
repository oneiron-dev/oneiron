//! A door for `tests/model_rung_hours.rs` (UNBUILT-14): whether a run's
//! live compaction fork would be bound to a ladder's rung now (FIX 4933),
//! as the rung that answered the run's latest completed call.

use oneiron::LlmRequest;

use crate::models::OfferLadder;

/// Whether a live fork of `request` would be bound to `ladder`'s rung at
/// `index`, in ladder order, now. `false` past the ladder's last rung.
#[must_use]
pub fn binds_live_fork_to_rung(ladder: &OfferLadder, index: usize, request: &LlmRequest) -> bool {
    ladder.binds_live_fork_to_rung(index, request)
}
