//! Moved from `crates/oneiron/src/verbs/shared.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// A shared vault, by the id its creation named.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedVaultRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
}

/// `vault.shared.propose_add_owner`'s input: a live Owner starts an
/// `add_owner` act making `owner` an Owner; nobody loses the role.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedAddOwnerRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    /// The new Owner's PERSON id, hex: a live person not yet an Owner.
    pub owner: String,
    /// An asker's approved check-in for this add, 32 hex: the starting Owner
    /// applies it on their own proof, and the act names its asker.
    #[serde(default)]
    pub check_in_ref: Option<String>,
}

/// `vault.shared.owner_change_wait.set`'s input: whole days, or `null` to
/// remove the common wait. `Some(0)` persists an explicit zero.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedOwnerChangeWaitSetRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    #[serde(default)]
    pub days: Option<u64>,
}

/// A started shared act, by the id its proposal answered.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedActRequest {
    pub act_id: String,
}

/// A shared-act or membership receipt, by id.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedReceiptRequest {
    pub receipt_id: String,
}

/// One member of a shared vault.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedMemberRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    /// PERSON id, hex.
    pub member: String,
}

/// The member change a Steward asks for (`vault.members.ask`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SharedMemberAskKind {
    /// Invite `member` at `role`, or at the preset's default member role.
    Add,
    /// Remove `member`.
    Remove,
    /// Move `member` to `role`.
    AssignRole,
}

/// One member ask in a shared vault, by its id.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedMemberAskIdRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    /// The ask's id, hex.
    pub ask: String,
}

/// A saved handoff alarm, by its retired key (`suite:hex`, as the alarm
/// names it).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffAlarmRequest {
    pub signer: String,
}
