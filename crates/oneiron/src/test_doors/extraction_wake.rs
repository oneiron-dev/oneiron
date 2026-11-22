//! A prepared wake for one admitted extraction attempt, with its listings read for a stated
//! destination bound, for driver tests of the extraction lender that copies the wake's bound.
//!
//! `PreparedWake::prepare_one_for_bound` is crate-private: the driver crate cannot build a wake
//! for a bound itself, so it could not test that its lender states the bound of the wake its
//! attempt context carries (FIX row BOUND-PACK-AND-PAGE-DESTINATION-NO-TEST).

use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::PreparedWake;
use crate::dreamer_runner::DreamerConsolidationScope;
use crate::error::Result;
use crate::settings::ReadDestination;
use crate::vault::Vault;

/// Prepares the wake of Meso attempt `attempt` alone, as direct execution prepares it, with its
/// listings read for `bound` as a driven pass reads them for the bound its executors stated.
/// `None` states no bound.
///
/// # Errors
///
/// The wake preparation's own: a missing or unadmitted attempt, or the planner's reads.
pub fn prepare_extraction_wake_for_bound(
    vault: &Vault,
    attempt: AttemptId,
    bound: Option<&ReadDestination>,
) -> Result<PreparedWake> {
    PreparedWake::prepare_one_for_bound(vault, DreamerConsolidationScope::Meso, attempt, bound)
}
