//! Moved from `crates/oneiron/src/task_verb/fanout_launch/scrub.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::receipt_identity::ERASED_CALL_IDENTITY;
use serde::Deserialize;
use serde::Serialize;

/// Truthful erasure-scrub marker: what recipient erasures scrubbed from one
/// launch, and the FIRST pre-scrub digest for audit. `None` on the row means
/// never scrubbed; old rows read as none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FanoutRecipientScrub {
    /// Vault seconds of the latest scrub.
    pub scrubbed_at: u64,
    /// FIRST pre-scrub digest (audit only, never a ruling binding).
    pub prior_digest: [u8; 32],
    /// Wave tasks whose assignee went default (`None`).
    pub wave_assignees: u32,
    /// `Ask.holders` entries removed.
    pub ask_holders: u32,
    /// `AdmittedAsk.recipients` entries removed.
    pub ask_recipients: u32,
    /// Consults merged into the `"erased"` plan bucket.
    pub erased_peer_count: u32,
    /// Unanswered width-check row retired by the scrub, kept as history;
    /// `None` when no check retired (held, answered, or none).
    pub retired_check_row: Option<String>,
}

/// Rewrites an erased actor's refs in pause/check pathology evidence
/// (REVIEW-4453 round 2): a rate-spike `peer_ref` or a consult-cycle
/// `peer_path` entry naming it becomes the erased identity, so receipts
/// and meter rows stop emitting the exact id after erasure.
pub fn scrub_pathology_for(
    pathology: Option<&mut crate::outbound_chokepoint::fanout::FanoutPathology>,
    hex: &str,
) -> bool {
    use crate::outbound_chokepoint::fanout::FanoutPathology;
    let Some(pathology) = pathology else {
        return false;
    };
    match pathology {
        FanoutPathology::PerPeerRateSpike { peer_ref, .. } => {
            if peer_ref == hex {
                *peer_ref = ERASED_CALL_IDENTITY.to_owned();
                true
            } else {
                false
            }
        }
        FanoutPathology::ConsultCycle { peer_path } => {
            let mut renamed = false;
            for peer in peer_path.iter_mut() {
                if peer == hex {
                    *peer = ERASED_CALL_IDENTITY.to_owned();
                    renamed = true;
                }
            }
            renamed
        }
    }
}
