//! Hook regeneration binding, adoption and view records.
//! `HookRegenBindingRequest` is the first of its records.
//! These are local definitions; `crate::runtime_hooks` defines the `HookRegenRecord` they project.

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::runtime_hooks::HookRegenRecord;

#[doc(hidden)]
pub use oneiron_verb_wire::memory::hook_regen_doors::types::{
    HookRegenAdoptRequest, HookRegenBindingRequest, HookRegenCancelRequest,
    HookRegenHistoryRequest, HookRegenRevertRequest,
};

/// One binding's regen record as the engine keeps it, with the hash an
/// adoption names.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookRegenView {
    pub record: HookRegenRecord,
    /// The pending candidate body's BLAKE3, 64 lowercase hex, which
    /// `vault.hooks.regen.adopt` names. Absent when no candidate waits: no
    /// regen ran, it was adopted, or it rolled back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_hash: Option<String>,
}

impl From<HookRegenRecord> for HookRegenView {
    fn from(record: HookRegenRecord) -> Self {
        Self {
            candidate_hash: record.candidate_hash(),
            record,
        }
    }
}
