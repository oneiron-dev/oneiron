//! Typed owner trigger for the existing archive cron. No cleanup policy lives here.

use serde::{Deserialize, Serialize};

use super::{CleanupCandidate, CleanupPosture, CleanupRunReport, MAX_CLEANUP_SCAN_ROWS};
use crate::attempt_queue::AttemptId;
use crate::consent::AuthenticatedOwner;
use crate::{EntityId, Result, Vault};

/// One cleanup pass, with the vault's current posture and retention settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CleanupRunRequest {}

/// What the archive cron did. A propose-first run archives nothing.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CleanupRunView {
    /// The run's own 32-hex attempt id, minted by the engine.
    pub attempt: String,
    pub posture: CleanupPosture,
    pub candidates: Vec<CleanupCandidate>,
    pub proposal: Option<EntityId>,
    pub archived: Vec<EntityId>,
    pub digest: Option<EntityId>,
}

impl From<CleanupRunReport> for CleanupRunView {
    fn from(report: CleanupRunReport) -> Self {
        Self {
            attempt: report
                .attempt
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            posture: report.posture,
            candidates: report.candidates,
            proposal: report.proposal,
            archived: report.archived,
            digest: report.digest,
        }
    }
}

/// Runs the existing rotating cleanup scan as the authenticated owner.
/// The proof, scan cursors, proposal/archive decision and run result share
/// one transaction. This never enables the automatic posture.
///
/// # Errors
///
/// A lapsed owner proof, or the cleanup runner's storage and decoding errors.
pub fn run_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: &CleanupRunRequest,
) -> Result<CleanupRunView> {
    vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        let attempt = AttemptId::from_bytes(&vault.store.clock.ulid()?)?;
        super::scan::run_in_txn(vault, txn, &attempt, MAX_CLEANUP_SCAN_ROWS)
            .map(CleanupRunView::from)
    })
}
