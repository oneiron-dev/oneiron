//! Moved from `crates/oneiron/src/task_verb/world_privacy_wait.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_verb_wire::policy_model::owner_rows::world_privacy_will::record::WorldPrivacyRequest;
use oneiron_verb_wire::policy_model::owner_rows::world_privacy_will::record::WorldPrivacyRequestStatus;
use serde::Deserialize;
use serde::Serialize;

/// What a wait on a world-privacy request answers its author (FIX 4706,
/// redacted by the Engine 10-19 20:0x, CALLS `FIX 4706 wait result`): the
/// request, its world and where it stands, with the outcome's content-free
/// fields. No door shows the author the holders it went to, who said yes,
/// who answered or the credential lineage that opened it, so none is here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldPrivacyWaitResult {
    /// The request's id, as hex: the wait's id.
    pub request_id: String,
    /// The WORLD row, as hex.
    pub world: String,
    pub status: WorldPrivacyWaitStatus,
}

/// Where a waited-on world-privacy request stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum WorldPrivacyWaitStatus {
    Pending,
    /// A holder's yes applied it: the settings receipt.
    Applied {
        receipt_id: String,
    },
    /// A holder declined it, or cancelled it from its notice.
    Declined,
}

impl WorldPrivacyWaitResult {
    /// `request` as its author's wait reads it.
    fn of(request: &WorldPrivacyRequest) -> Self {
        Self {
            request_id: request.request_id.clone(),
            world: request.world.clone(),
            status: match &request.status {
                WorldPrivacyRequestStatus::Pending => WorldPrivacyWaitStatus::Pending,
                WorldPrivacyRequestStatus::Applied { receipt_id, .. } => {
                    WorldPrivacyWaitStatus::Applied {
                        receipt_id: receipt_id.clone(),
                    }
                }
                WorldPrivacyRequestStatus::Declined { .. } => WorldPrivacyWaitStatus::Declined,
            },
        }
    }
}
