//! Moved from `crates/oneiron/src/federation/shared_act/owner_add.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// Payload of an `add_owner` act: `owner` gains the Owner role; nobody loses it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddOwnerPlan {
    pub v: u8,
    pub owner: String,
    /// The workspace whose stored preset names `owner` as its house mind,
    /// when the act seats that house at the Owner role
    /// (HOUSE-UNBIND-AUTHORITY = A, FIX HOUSE-OWNER-ROLE-VIA-ADD-OWNER). A
    /// person's add names none, and its stored plan reads as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub house_workspace: Option<String>,
}
