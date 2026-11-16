//! Moved from `crates/oneiron/src/verbs/record_erase.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::claims::DeleteReceipt;
pub use oneiron_verb_wire::verbs::record_erase::RecordEraseConfirmRequest;
pub use oneiron_verb_wire::verbs::record_erase::RecordEraseRequest;
use serde::Deserialize;
use serde::Serialize;

/// One live brief grant the erase revokes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EraseShare {
    pub grant: String,
    pub recipient: String,
}

/// One content hash the record holds, and the other records holding it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EraseHeldBytes {
    pub content_hash: String,
    pub other_holders: Vec<String>,
}

/// One LFS chunk the record's object shares, and the other owners of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EraseLfsChunk {
    pub chunk_hash: String,
    pub other_owners: Vec<String>,
}

/// `vault.records.erase_preview`'s answer. `preview_digest` is the BLAKE3 of
/// the rest of it; `erase_confirm` takes it back, so a record whose shares or
/// same-bytes holders changed since is refused, not erased.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordErasePreview {
    pub record: String,
    pub shared_with: Vec<EraseShare>,
    pub held_bytes: Vec<EraseHeldBytes>,
    pub lfs_chunks: Vec<EraseLfsChunk>,
    /// What `also_same_bytes` would also take.
    pub same_bytes: Vec<String>,
    /// Federation recipients may keep copies after a local erase.
    pub remote_copies_may_remain: bool,
    /// For a world whose keys this erase destroys (ARCH-0038
    /// #erase-sealed-bundles), the owner-ruled words: the world is erased now,
    /// and old backups keep only an unreadable copy until they expire. Absent
    /// for every other record, so its preview and digest stay as they were.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_backups_notice: Option<String>,
    /// Beside that notice, the days within which those old backups expire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_backups_expire_within_days: Option<u32>,
    pub preview_digest: String,
}

/// What became of one other record holding the same bytes: `erased`,
/// `held` (with its reason code, and the `erase` act it started, if any) or
/// `failed` (with the error).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EraseSameBytesRow {
    pub record: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<DeleteReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `vault.records.erase_confirm`'s answer: the confirmed record's receipt,
/// its own `erase` act when it waits on a veto window, and one row per other
/// record holding its bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordEraseOutcome {
    pub first: DeleteReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_act: Option<String>,
    pub same_bytes: Vec<EraseSameBytesRow>,
    /// The check-in decision the erase ran on (2j; P24-SHAPE Q7 and Q9 = A):
    /// the Owner on their own proof, and the approved check-in of another
    /// asker it applied, with its requester.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<oneiron_verb_wire::check_in::effect::CheckInDecision>,
    /// The preview's notice, once the erase destroyed the world's keys now;
    /// absent while the erase waits, and for every other record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_backups_notice: Option<String>,
    /// Beside that notice, the days within which those old backups expire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_backups_expire_within_days: Option<u32>,
}
