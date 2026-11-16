//! Moved from `crates/oneiron/src/memory/channel_doors/passport.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::write_envelope::thread_claim::ThreadMask;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadPassportRequest {
    pub identity_ref: EntityId,
    pub message_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadPassportsRequest {
    pub thread_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ThreadMaskView {
    pub identity_ref: EntityId,
    pub actor_ref: EntityId,
    pub facet_ref: Option<EntityId>,
}

impl From<ThreadMask> for ThreadMaskView {
    fn from(mask: ThreadMask) -> Self {
        Self {
            identity_ref: mask.identity_ref,
            actor_ref: mask.actor_ref,
            facet_ref: mask.facet_ref,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ThreadPassportView {
    pub identity_ref: EntityId,
    pub message_id: String,
    pub thread_ref: String,
    pub mask: ThreadMaskView,
    pub observed_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ThreadPassportLookup {
    pub passport: Option<ThreadPassportView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ThreadPassportsView {
    pub canonical_thread_ref: String,
    pub passports: Vec<ThreadPassportView>,
    pub pinned_mask: Option<ThreadMaskView>,
}
