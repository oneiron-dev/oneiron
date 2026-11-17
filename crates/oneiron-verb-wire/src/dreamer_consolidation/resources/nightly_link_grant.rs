//! Moved from `crates/oneiron/src/dreamer_consolidation/resources/nightly_link_grant.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

/// The owner grants the vault's own Dreamer its existing nightly-link bound.
/// The writer is resolved by the vault, never supplied by the caller.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NightlyLinkGrantRequest {
    /// Another asker's approved check-in for this grant, 32 hex: the owner
    /// applies it on their own proof, and the mint's writer spends it
    /// (ROLES-CHECKIN 2k8). Omitted: the owner's own mint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in_ref: Option<String>,
}
