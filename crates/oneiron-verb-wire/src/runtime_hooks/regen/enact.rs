//! Moved from `crates/oneiron/src/runtime_hooks/regen/enact.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::runtime_hooks::regen::HookContractStamp;
use crate::runtime_hooks::regen::HookRegenOutcome;
use crate::runtime_hooks::regen::HookRegenPrior;
use crate::runtime_hooks::regen::HookRegenRecord;
use crate::runtime_hooks::regen::body_hash;
use crate::runtime_hooks::regen::history;
use crate::runtime_hooks::regen::history::HookRegenActor;
use crate::runtime_hooks::regen::history::HookRegenEvent;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::write_envelope::WriteActor;
use oneiron_store::write_envelope::skill_source::HubFile;
use serde::Deserialize;
use serde::Serialize;

/// What a cancel set aside.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookRegenCancel {
    /// The candidate set aside, as BLAKE3 hex; absent for a failed regen's
    /// decision, which holds none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_hash: Option<String>,
    /// The contract the decision targeted, now declined.
    pub declined: HookContractStamp,
}
