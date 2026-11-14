//! Typed owner trigger for the existing archive cron. No cleanup policy lives here.

use super::CleanupKind;
use crate::consent::AuthenticatedOwner;
use crate::store::attempt_id::AttemptId;
use crate::{EntityId, Result, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::vault_cleanup::surface::{CleanupRunRequest, CleanupRunView};

/// Runs the existing cleanup scan as the authenticated owner, each eligible
/// index read to its end. The proof, scan, proposal/archive decision and run
/// result share one transaction. This never enables the automatic posture.
///
/// # Errors
///
/// A lapsed owner proof, or the cleanup runner's storage and decoding errors.
pub fn run_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &CleanupRunRequest,
) -> Result<CleanupRunView> {
    run_sourced_as_owner(vault, owner, input).map(|(view, _)| view)
}

/// [`run_as_owner`] beside the run's additive attempt sources (FIX 10494):
/// the union of genuine known gated source rows over its completed-attempt
/// candidates, read in that same write transaction. The
/// queue bytes never move under archive marks, so the trace is exact. Each
/// unknown attempt contributes nothing; known rows contribute even while
/// another attempt stays unknown. The vector is additive named release
/// evidence only, never a complete whole-response assertion.
///
/// # Errors
///
/// As [`run_as_owner`].
pub fn run_sourced_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: &CleanupRunRequest,
) -> Result<(CleanupRunView, Vec<EntityId>)> {
    vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        let attempt = AttemptId::from_bytes(&vault.store.clock.ulid()?)?;
        let report = super::scan::run_in_txn(vault, txn, &attempt)?;
        let mut sources = Vec::new();
        for candidate in report
            .candidates
            .iter()
            .flatten()
            .filter(|candidate| candidate.kind == CleanupKind::CompletedAttempt)
        {
            if let Some(rows) =
                super::attempt_retention::attempt_source_rows_in_txn(vault, txn, candidate.entity)?
            {
                sources.extend(rows);
            }
        }
        sources.sort_unstable();
        sources.dedup();
        Ok((CleanupRunView::from(report), sources))
    })
}
