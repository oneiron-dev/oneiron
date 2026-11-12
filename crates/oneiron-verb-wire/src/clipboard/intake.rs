//! Moved from `crates/oneiron/src/clipboard/intake.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::clipboard::world::ClipboardWorld;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_CLAIM;
use oneiron_contracts::claim::ClaimApprovalStatus;
use oneiron_contracts::claim::ClaimLifecycleStatus;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::temporal::TimeRange;
use oneiron_store::write_envelope::claim_body::ClaimBody;
use oneiron_store::write_envelope::claim_body::ClaimSubject;
use oneiron_store::write_envelope::claim_body::decode_claim_body;
use serde::Deserialize;
use serde::Serialize;

/// One ordinary clip, read back after the batch door's secret masking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClipboardEntry {
    pub clip: EntityId,
    pub copied_at: u64,
    pub text: String,
}
