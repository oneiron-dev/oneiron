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

/// `vault.shared.execute`'s input: a matured act, and the confirm a device
/// of the executing Owner signed for its owner-key move
/// (`vault.shared.owner_key_move_sign`). None is the plain run.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedActExecuteRequest {
    pub act_id: String,
    /// Each signed `RevokeDevice` row's encoded body, lowercase hex, in the
    /// order the device answered them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owner_key_revokes: Vec<String>,
}

/// One owner key a move's plan lets sign, and the sequence its first
/// revoke takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedOwnerKeyMoveSigner {
    /// The Ed25519 public key, 64 lowercase hex.
    pub public_key: String,
    pub seq: u64,
}

/// `vault.shared.owner_key_move_plan`'s answer and the plan
/// `vault.shared.owner_key_move_sign` confirms: the rows a device of the
/// executing Owner signs stand on `parents`, revoke each of `revoked`, and
/// are signed by one of `signers` at its `seq` and on. Byte fields are
/// lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedOwnerKeyMovePlan {
    /// The pending shared act the move runs for.
    pub act_id: String,
    /// The vault's authority id, 64 hex (not a shared vault's `vault_id`).
    pub authority_vault_id: String,
    /// The member whose Owner standing the move ends: PERSON id, hex.
    pub member: String,
    /// The heads the first revoke names, 64 hex each.
    pub parents: Vec<String>,
    /// The member's live owner keys, one revoke each, in hex: 64 digits for
    /// an Ed25519 key, 66 for a passkey's compressed P-256 key.
    pub revoked: Vec<String>,
    /// The executing Owner's keys that may sign.
    pub signers: Vec<SharedOwnerKeyMoveSigner>,
    /// When it was planned, advisory unix seconds: each revoke's time.
    pub at: u64,
}

/// `vault.shared.owner_key_move_sign`'s input: the plan the server answered,
/// and the member the Owner confirmed on this device.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedOwnerKeyMoveSignRequest {
    pub plan: SharedOwnerKeyMovePlan,
    /// The member whose owner keys the Owner confirmed ending, as the
    /// device's own copy shows them; never copied from `plan`. A plan of
    /// another member signs nothing.
    pub member: String,
}

/// `vault.shared.owner_key_move_sign`'s answer: the rows this device signed,
/// passed as they are to `vault.shared.execute`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedOwnerKeyMoveConfirm {
    /// Each signed `RevokeDevice` row's encoded body, lowercase hex.
    pub owner_key_revokes: Vec<String>,
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
