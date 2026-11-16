//! Moved from `crates/oneiron/src/federation/pending_act/matured.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// Durable, recipient-specific notice that a waiting act has matured: its
/// window passed on the store clock with no live objection, so a live Owner
/// may now execute it. A zero-wait act was told at its start instead.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingActMatured {
    pub act_id: String,
    #[serde(with = "crate::federation::vault_id_decimal")]
    pub vault_id: u64,
    pub act: String,
    pub recipient: String,
    pub deadline: u64,
    /// The store-clock time the housekeeping pass saw the act matured.
    pub noticed_at: u64,
}
