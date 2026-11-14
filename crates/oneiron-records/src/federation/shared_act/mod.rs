//! Moved from `crates/oneiron/src/federation/shared_act/mod.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::federation::shared_act::erase_ask::EraseAskStatus;
pub use crate::federation::shared_act::member_ask::MemberAskStatus;
pub use crate::federation::shared_act::membership::invitation::SharedInvitationState;
pub use crate::federation::shared_act::owner_add::AddOwnerPlan;
pub use crate::federation::shared_act::removal_import::ReceivedRemovalArchive;
pub use crate::federation::shared_act::removal_import::ReceivedRemovalArchiveState;
use std::collections::BTreeSet;

/// The acts the shared preset lists. Their names are the policy row names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedActKind {
    DeleteVault,
    Erase,
    AddOwner,
    TransferOwnership,
    RemoveOwner,
}

impl SharedActKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeleteVault => "delete_vault",
            Self::Erase => "erase",
            Self::AddOwner => "add_owner",
            Self::TransferOwnership => "transfer_ownership",
            Self::RemoveOwner => "remove_owner",
        }
    }

    pub fn parse(act: &str) -> Option<Self> {
        match act {
            "delete_vault" => Some(Self::DeleteVault),
            "erase" => Some(Self::Erase),
            "add_owner" => Some(Self::AddOwner),
            "transfer_ownership" => Some(Self::TransferOwnership),
            "remove_owner" => Some(Self::RemoveOwner),
            _ => None,
        }
    }
}

/// Payload of a `delete_vault` act. The vault id is the act's own.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteVaultPlan {
    pub v: u8,
}

/// What an export-first removal exported for `member`: the record count,
/// the BLAKE3 of the archive (OF-222), never its content, and the diaries
/// the export read (OF-490).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedActExport {
    pub member: String,
    pub records: u64,
    pub digest: String,
    pub diary_reads: Vec<oneiron_store::batch::export::archive_types::ExportDiaryRead>,
}

/// The local outcome of releasing an owner's bound Connect grants when a
/// member genuinely left (FIX 12555): the grants actually withdrawn here and
/// the per-grant typed remainder still standing. It names no peer delivery,
/// courtesy deletion or remote erasure.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachReport {
    /// Bound Connect grants actually withdrawn here, id hex.
    pub withdrawn: Vec<String>,
    /// Bound grants still standing, each with its typed remainder.
    pub remaining: Vec<DetachRemainder>,
}

/// One bound grant still standing after a genuine leave, and why.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachRemainder {
    /// The grant still standing, id hex.
    pub grant: String,
    /// Why it still stands.
    pub reason: DetachRemainderReason,
}

/// Why a bound grant still stands after a genuine leave.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetachRemainderReason {
    /// No host issuer signed in this writer; the membership still progressed.
    NoIssuer,
    /// The withdrawal failed with this stable error kind; the membership
    /// still progressed. The kind names the failure, never its payload.
    WithdrawalFailed {
        kind: oneiron_base::error::ErrorKind,
    },
}

/// Where an export-first removal's archive went (FIX 1300): to the removed
/// Owner, bound to them as its one recipient, retrievable by them until
/// `expires_at`. Never the archive's content.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovalExportDelivery {
    /// The removal's receipt id, which keys the archive.
    pub receipt_id: String,
    /// The removed Owner, PERSON hex.
    pub recipient: String,
    /// BLAKE3 of the archive, lowercase hex, as the receipt records it.
    pub digest: String,
    /// When it was last delivered: the removal, or a remaining Owner's re-run.
    pub delivered_at: u64,
    pub expires_at: u64,
}

/// The engine's record that the vault was deleted. Hosts stop serving it and
/// keep its backups until `backup_retain_until`, then let them go.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedVaultDeletion {
    #[serde(with = "crate::federation::vault_id_decimal")]
    pub vault_id: u64,
    pub act_id: String,
    pub receipt_id: String,
    pub deleted_at: u64,
    pub backup_retain_until: u64,
}
pub mod erase_ask;
pub mod member_ask;
pub mod membership;
pub mod owner_add;
pub mod removal_import;
