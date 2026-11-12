//! Moved from `crates/oneiron/src/vault_cleanup/surface.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
use oneiron_store::vault_cleanup::cleanup_types::CleanupCandidate;
use oneiron_store::vault_cleanup::cleanup_types::CleanupKind;
use oneiron_store::vault_cleanup::cleanup_types::CleanupPosture;
use oneiron_store::vault_cleanup::cleanup_types::CleanupRunReport;
use serde::Deserialize;
use serde::Serialize;

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
            // The owner door mints a fresh run each call, so its report is
            // made here and never read from a stored row: no slot in it is
            // erased (FIX 7517).
            candidates: report.candidates.into_iter().flatten().collect(),
            proposal: report.proposal,
            archived: report.archived.into_iter().flatten().collect(),
            digest: report.digest,
        }
    }
}
