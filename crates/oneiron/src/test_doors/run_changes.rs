//! Doors for `tests/run_changes_journal_cost.rs` (the stored size of a run's
//! change journal rows, `memory::run_review`), `tests/run_revert_unsettled.rs`
//! (a run's claim put that asks Auto) and `tests/run_changes_topology.rs` (a
//! run's journal read with no owner). Compiled only under
//! `--cfg oneiron_test_support`; never API.

use crate::Result;
use crate::claim::ClaimApprovalStatus;
use crate::code_run::{HostSelfDispatcher, SelfDispatchOutcome, SelfMemoryPutClaimCall};
use crate::vault::Vault;

/// Each stored journal row of `run`, in write order: its whole key's and its
/// value's byte lengths.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn journal_row_sizes(vault: &Vault, run: &str) -> Result<Vec<(usize, usize)>> {
    crate::memory::run_review::journal_row_sizes(vault, run)
}

/// The changes `run` wrote, each once and in write order, as
/// `vault.runs.changes.get` lists them, read with no owner.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn journal_changes(vault: &Vault, run: &str) -> Result<serde_json::Value> {
    crate::memory::run_review::journal_changes(vault, run)
}

/// The run's claim put asking Auto of the gates, as a caller's live run asks
/// first (`HostSelfDispatcher::put_claim_from_host`, FIX 3983), without the
/// live run's acquired lease. Code mode asks Proposed, so a run's claim lands
/// at once only this way. A gate that pends the request answers its refusal
/// here; nothing resubmits it Proposed.
///
/// # Errors
/// The gate's refusal, or the store's.
#[doc(hidden)]
pub fn put_claim_asking_auto(
    run: &HostSelfDispatcher<'_>,
    call: SelfMemoryPutClaimCall,
) -> Result<SelfDispatchOutcome> {
    run.dispatch_memory_put_claim_requesting(call, None, ClaimApprovalStatus::Auto, true)
}
