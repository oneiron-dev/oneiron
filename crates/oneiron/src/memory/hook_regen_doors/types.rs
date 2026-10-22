//! Hook regeneration binding, adoption and view records.
//! `HookRegenBindingRequest` is the first of its records.
//! These are local definitions; `crate::runtime_hooks` defines the `HookRegenRecord` they project.

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::runtime_hooks::HookRegenRecord;

/// Names one hook binding: the subscription claim `vault.packs.hooks.list`
/// and `vault.hooks.regen.due` name, never a pack, hook or CODE id. It is
/// not a capability.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookRegenBindingRequest {
    pub binding: EntityId,
}

/// The owner adopts the regen candidate pending on one binding, named by
/// the hash `vault.hooks.regen.get` shows. A candidate that replaced it
/// since refuses the adoption. The call itself is the owner's stamp; no
/// field stands in for it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookRegenAdoptRequest {
    pub binding: EntityId,
    /// The pending candidate body's BLAKE3, 64 lowercase hex.
    pub candidate_hash: String,
}

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
