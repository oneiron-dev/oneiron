//! Top-level `Vault` API: the crate's main entry point for all LMDB-backed
//! entity / vector / edge / text / temporal operations. Also hosts
//! edge-record helpers kept for Vault-facing compatibility.

mod actors_memory;
mod database_digests;
mod doctor_manifest;
mod edges;
mod entities;
pub(crate) mod entity_revision;
#[cfg(feature = "sync")]
pub(crate) use entity_revision::EntityRevisionChange;
pub use entity_revision::{
    IndexedRefreshReport, IndexedRevisionEmbedder, IndexedRevisionInput, PinnedCitation, ReadMode,
    ResolvedCitation, RevisionRef,
};
mod identity;
mod open;
mod places;

#[cfg(feature = "test-support")]
mod read_fixture;
mod reader_table;
mod retrieval_trace_key;
mod search_retrieval;
mod transactions;
mod vector_evidence;

use crate::analyzer::MultilingualAnalyzer;
use crate::config::{VaultConfig, VaultPrivacyConfig};
use crate::store::Store;

pub use crate::store::{VAULT_WRITER_LEASE_HELD, VAULT_WRITER_LOCK_FILE, VaultWriterLease};

pub use self::actors_memory::ActorBound;
#[cfg(test)]
pub(crate) use self::database_digests::{mask_embed_job_stamps, mask_unrepeatable_stamps};
pub use self::doctor_manifest::{
    TextIndexStatus, VaultDoctorDbManifestReport, VaultDoctorHnswRecordState,
    VaultDoctorHnswReport, VaultDoctorReport,
};
pub(crate) use self::doctor_manifest::{
    ensure_text_index_manifest_matches_wtxn, verify_text_index_manifest, write_text_index_manifest,
};
pub use self::edges::IdScanPage;
#[cfg(test)]
pub(crate) use self::edges::edge_kind_prefix;
pub(crate) use self::edges::{
    CLAIM_OF_DEFAULT_WEIGHT, MAX_EDGE_QUERY_RESULTS, SUPERSEDES_DEFAULT_WEIGHT,
    filtered_edge_peers_in,
};
pub use self::entities::HydratedShortId;
/// The composed session census bounds itself exactly like [`Vault::entities_by_type`],
/// and that census has only in-crate test callers today.
#[cfg(test)]
pub(crate) use self::entities::MAX_TYPE_QUERY_RESULTS;
pub(crate) use self::entities::{
    LiveEntityRow, entity_id_from_type_index_key, live_entity_row_in_txn, require_key_len,
};
pub(crate) use self::identity::VaultId;
pub(crate) use self::open::{embedded_owner_actor_id, encode_embedded_owner_actor_body};
pub use self::reader_table::ReaderTableShortfall;
#[cfg(test)]
pub(crate) use self::retrieval_trace_key::unkeyed_for_test;
#[cfg(feature = "sync")]
pub(crate) use self::transactions::MAX_SYNC_STATE_KEYS;
pub(crate) use self::vector_evidence::NoMatchFloors;

/// Main vault API wrapping LMDB storage and configuration.
pub struct Vault {
    /// Live seat prefixes are vault-owned, never process-global.
    pub(crate) model_seats: std::sync::Mutex<crate::llm::seat::SeatPool>,
    pub(crate) message_streams: crate::memory::MessageStreamRuntime,
    /// The rows over live work this vault holds open, and the host's door
    /// for their crossings ([`Vault::set_live_rows`]).
    pub(crate) live_rows: crate::live_rows::LiveRowsCell,
    /// Task work's one fair line on this vault, whichever door the work came
    /// in by ([`Vault::admit_task_work`]).
    pub(crate) task_work: crate::work_line::WorkLine<crate::EntityId>,
    /// World privacy P6b: this install's this-device-only keystore, the world
    /// keys this machine opened, and their OF-520 questions. In memory only,
    /// never persisted, and never shared across vaults.
    pub(crate) world_keys: crate::world_keys::WorldKeySession,
    /// Serializes per-request voice-ref uploads with consent withdrawal.
    pub(crate) voice_ref_guard: std::sync::RwLock<()>,
    /// Orders a trusted-contact notice's last consent read and send against
    /// revocation and re-naming.
    pub(crate) trusted_contact_send_order: std::sync::RwLock<()>,
    /// One housekeeping pass at a time on this handle.
    pub(crate) housekeeping: std::sync::Mutex<crate::housekeeping::HousekeepingHandle>,
    #[cfg(feature = "sync")]
    pub(crate) entity_docs: std::sync::Mutex<crate::entity_doc::EntityDocRegistry>,
    pub(crate) store: Store,
    pub(crate) config: VaultConfig,
    /// Where vector evidence starts now: the configured floors until the host
    /// sets others ([`Vault::set_vector_evidence`]), and any it set for one
    /// kind of item in one embedding space ([`Vault::set_vector_evidence_for`]).
    vector_evidence: std::sync::RwLock<vector_evidence::NoMatchFloors>,
    pub(crate) analyzer: MultilingualAnalyzer,
    /// Which vault this handle belongs to, resolved once at open.
    vault_id: VaultId,
    /// The key over this vault's stored retrieval-trace fork hashes,
    /// resolved once at open.
    retrieval_trace_key: self::retrieval_trace_key::RetrievalTraceKey,
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
    /// One in-process idle policy timer per open vault, released on wrapper drop.
    pub(crate) wake_policy_timer_owned: std::sync::atomic::AtomicBool,
    pub(crate) conversation_presence:
        std::sync::Mutex<std::collections::BTreeMap<crate::EntityId, Vec<crate::EntityId>>>,
    /// The host's USD quote for launch statements (OF-532), installed once
    /// by [`Vault::install_launch_usd_prices`]. Empty: dollars are unknown.
    pub(crate) launch_usd_prices:
        std::sync::OnceLock<std::sync::Arc<dyn crate::agent_dispatch::LaunchUsdPrices>>,
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
    /// This device's home search, lent by its own sync connection
    /// ([`crate::sync::HomeSearch`], OF-534). A `Weak`, so a dropped
    /// connection routes nothing.
    #[cfg(feature = "sync")]
    pub(crate) home_search: std::sync::Mutex<std::sync::Weak<crate::sync::HomeSearch>>,
    /// The speculative passes running on threads of their own (call mode on
    /// ASR partials), capped against the reader slots.
    pub(crate) speculative_passes: crate::speculative::SpeculativePasses,
    /// The room a host lends the origin for reading whole LFS manifests
    /// ([`Vault::set_lfs_read_room`]); none until it lends one.
    pub(crate) lfs_read_room:
        std::sync::RwLock<Option<std::sync::Arc<dyn crate::origin::lfs::LfsReadRoom>>>,
    /// The result bodies this handle's readers hold, which the body
    /// collector leaves alone (OF-597).
    pub(crate) result_body_pins: crate::result_body::ResultBodyPins,
    /// Verb hooks' in-memory state: the process switch, the cached binding
    /// list, the sandbox and the invocations in flight (ARCH-0080 §3).
    pub(crate) verb_hook_state: crate::runtime_hooks::verb::VerbHookState,
    /// The callable skill invocations running on this handle, each with the
    /// token an owner's suspension cancels it by (FIX 600). In memory only.
    pub(crate) skill_invocations: crate::skill::SkillInvocations,
    /// The deadline tests' slow retrieval stage, armed per vault.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) slow_retrieval_stage:
        std::sync::Mutex<Option<crate::retrieval_depth::SlowRetrievalStage>>,
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
