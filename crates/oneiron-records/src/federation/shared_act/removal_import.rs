//! Moved from `crates/oneiron/src/federation/shared_act/removal_import.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// One removal archive this vault took in for its owner, as the owner's
/// listing answers it (FIX 11797): never a byte of the archive.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReceivedRemovalArchive {
    /// The removal receipt that keys it.
    pub receipt_id: String,
    /// The shared vault it came from.
    #[serde(with = "crate::federation::vault_id_decimal")]
    pub vault_id: u64,
    /// The latest delivery taken in: when its home delivered it.
    pub delivered_at: u64,
    /// The end of that delivery's term: it stays readable here until then.
    pub expires_at: u64,
    /// Whether it is still kept here within that term.
    pub state: ReceivedRemovalArchiveState,
    /// When this vault took in its latest delivery, on its store clock.
    pub imported_at: u64,
}

/// Where a listed removal archive stands in this vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceivedRemovalArchiveState {
    /// Kept here and readable within its term
    /// ([`Vault::removed_owner_exports`]).
    Imported,
    /// Its term has ended: the copy is gone, or goes at the next pass, and
    /// only this record of it stays.
    Lapsed,
}
