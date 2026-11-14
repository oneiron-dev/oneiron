//! Moved from `crates/oneiron/src/memory/hook_regen_doors/types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

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

/// The owner sets aside the decision waiting on one binding: a candidate
/// named by the hash `vault.hooks.regen.get` shows, or a failed regen's
/// decision, which holds no candidate, named by none.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookRegenCancelRequest {
    pub binding: EntityId,
    /// The pending candidate body's BLAKE3, 64 lowercase hex; absent for a
    /// failed regen's decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_hash: Option<String>,
}

/// The owner reverts the adoption one binding stands on, named by the hash
/// of the adopted body it takes out (the record's `body_hash`).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookRegenRevertRequest {
    pub binding: EntityId,
    /// The adopted body's BLAKE3, 64 lowercase hex.
    pub adopted_hash: String,
}

/// One page of a binding's regen history, newest first.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookRegenHistoryRequest {
    pub binding: EntityId,
    /// Only receipts before this sequence: the last page's oldest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<u64>,
    /// At most this many receipts, capped at the engine's page bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}
