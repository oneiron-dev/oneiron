//! Top-level `Vault` API: the crate's main entry point for all LMDB-backed
//! entity / vector / edge / text / temporal operations. Also hosts
//! edge-record helpers kept for Vault-facing compatibility.

mod actors_memory;
mod doctor_manifest;
mod edges;
mod entities;
mod open;
mod search_retrieval;
mod transactions;

use crate::analyzer::MultilingualAnalyzer;
use crate::config::{VaultConfig, VaultPrivacyConfig};
use crate::store::Store;

pub use crate::store::{VAULT_WRITER_LEASE_HELD, VAULT_WRITER_LOCK_FILE, VaultWriterLease};

pub use self::actors_memory::ActorBound;
pub use self::doctor_manifest::{
    TextIndexStatus, VaultDoctorDbManifestReport, VaultDoctorHnswRecordState,
    VaultDoctorHnswReport, VaultDoctorReport,
};
pub(crate) use self::doctor_manifest::{
    ensure_text_index_manifest_matches_wtxn, verify_text_index_manifest, write_text_index_manifest,
};
pub(crate) use self::edges::{
    CLAIM_OF_DEFAULT_WEIGHT, MAX_EDGE_QUERY_RESULTS, SUPERSEDES_DEFAULT_WEIGHT, edge_kind_prefix,
    parse_edge_record,
};
pub use self::entities::HydratedShortId;
/// The composed session census bounds itself exactly like [`Vault::entities_by_type`],
/// and that census has only in-crate test callers today.
#[cfg(test)]
pub(crate) use self::entities::MAX_TYPE_QUERY_RESULTS;
pub(crate) use self::entities::{
    LiveEntityRow, entity_id_from_type_index_key, live_entity_row_in_txn, require_key_len,
};

/// Main vault API wrapping LMDB storage and configuration.
pub struct Vault {
    pub(crate) store: Store,
    pub(crate) config: VaultConfig,
    pub(crate) analyzer: MultilingualAnalyzer,
    // Declared after Store: LMDB closes before process ownership is released.
    writer_lease: Option<VaultWriterLease>,
    /// Posture/custody pairing this handle was opened under, retained from the
    /// validated config so the honest read-only description below cannot drift
    /// from what the opener actually accepted. Private: callers read it through
    /// [`Vault::privacy_posture`], [`Vault::privacy_posture_label`], and
    /// [`Vault::is_host_readable`], never as raw state.
    privacy: VaultPrivacyConfig,
    /// `false` only when `Vault::open` ran with
    /// `skip_text_index_manifest_check = true` against a populated index.
    /// In that state the on-disk postings may have been written under a
    /// different analyzer manifest than the in-memory one, so scoring
    /// against them silently returns wrong results. `search_text` returns
    /// `Error::CorruptedIndex` until `MaintenanceBuilder::clear_text_index`
    /// rewrites the manifest. Reopening cleanly also restores trust via
    /// the regular handshake path.
    pub(crate) text_index_trusted: std::sync::atomic::AtomicBool,
    /// SLIM residency controller (ONE-1933 / OF-447). Holds the shed/resume
    /// state mutex and nothing else: the fixed-order drop transaction and the
    /// lazy resume hook are `impl Vault` blocks in [`crate::slim`]. It adds no
    /// outbound callback, no timer handle and no second connection owner.
    pub(crate) slim: crate::slim::SlimController,
    /// Live-window delete-routing seam (M4-10 / ONE-1135): a `Weak` to the
    /// production [`crate::sync::manager::WindowManager`], set by
    /// [`crate::sync::manager::WindowManager::attach_to_vault`]. When a
    /// deleted entity's window is OPEN, `write_crdt_tombstone` commits
    /// through the registry-owned live doc instead of a transient snapshot
    /// copy. `Weak` so the vault never keeps a dropped manager (and its
    /// observer subscriptions) alive.
    #[cfg(feature = "sync")]
    pub(crate) live_window_manager: std::sync::Mutex<std::sync::Weak<crate::sync::WindowManager>>,
    /// Distinguishes "no sync manager has ever been attached" from "a manager
    /// was attached but can no longer be queried". The latter is ambiguous for
    /// sweep safety and must defer.
    #[cfg(feature = "sync")]
    pub(crate) live_window_manager_attached: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
mod tests;

// The flat vault.rs module used to provide these names to the sibling test
// module through `use super::*`: the private helpers the tests name bare,
// and the crate/std names the old `vault.rs` use header supplied. After the
// directory split the seam re-imports both so `tests.rs` resolves exactly as
// it did before.
#[cfg(test)]
use self::doctor_manifest::{
    bm25_field_schema_hash_for_records, bm25_field_schema_records,
    write_text_index_manifest_if_empty,
};
#[cfg(test)]
use crate::analyzer::AnalyzerChannel;
#[cfg(test)]
use crate::bm25;
#[cfg(test)]
use crate::error::{Error, Result};
