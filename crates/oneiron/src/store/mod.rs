//! LMDB store: one environment per vault plus the 28 named databases pinned
//! by the ARCH-0019 manifest, and the fail-closed open-time gates.
//!
//! # Canonical open-gate sequence (`Store::open` → `Vault::open`)
//!
//! Gates run in this exact order. The FIRST failing gate aborts the open with
//! its typed error and **no usable `Store`/`Vault` handle is returned**. Every
//! error path also releases the process-local path registration, so a retry
//! observes the same gate failure again rather than a phantom
//! "vault path is already open" error.
//!
//! `Store::open` — steps 1–4 run inside a single write transaction while
//! holding `lmdb_database_open_guard` (`mdb_dbi_open` is transaction-scoped:
//! the txn that opens a DBI must finish before another txn opens one):
//!
//! 0. **`preflight_vault_root`** — before the unsafe LMDB open, the root must
//!    contain either no LMDB files (new vault) or exactly one regular,
//!    non-symlink, single-link `data.mdb` plus one matching `lock.mdb`
//!    (existing vault). Partial, aliased, hard-linked, or already-live roots
//!    fail with [`VaultRootPreflight`].
//! 1. **`vault_meta` (manifest DB #5) is created/opened FIRST.** Rationale:
//!    the storage-version gate (step 2) reads its versions FROM `vault_meta`,
//!    so an existing vault with a missing/blank `vault_meta` is caught by the
//!    ABI gate as [`StorageAbiVersionChanged`]`{ stored: None, .. }` — not by
//!    the manifest gate. Creating it first cannot mask a genuinely missing
//!    database: the manifest-set gate (step 3) runs BEFORE the other 27
//!    manifest DBs are (re)created in this transaction, so any of those
//!    missing is still detected.
//! 2. **`gate_storage_versions`** — storage ABI gate, then schema gate.
//!    * `vault_meta["storage_abi_version"]` (u16 LE) ≠
//!      [`STORAGE_ABI_VERSION`], or absent on an existing vault →
//!      [`StorageAbiVersionChanged`].
//!    * `vault_meta["schema_version"]` (u16 LE) ≠ [`STORAGE_SCHEMA_VERSION`],
//!      or absent on an existing vault → [`StorageSchemaVersionChanged`].
//!    * New vaults stamp both current versions instead of gating.
//! 3. **`validate_db_manifest_set`** (existing vaults) — the named-database
//!    set in the environment must equal the 28-entry [`DB_MANIFEST`] exactly;
//!    any missing or unexpected name → [`DbManifestMismatch`]. New vaults run
//!    this validation after step 4 instead (nothing pre-exists to validate).
//! 4. The remaining 27 manifest DBs are created/opened, the transaction
//!    commits, and the DBI-open guard is released.
//! 5. **`preflight_hnsw_config`** — `hnsw_meta["hnsw_config"]` (27-byte v2
//!    record: dimensions, m_max_0, ef_construction, distance_metric,
//!    index_structure; `ef_search` is a search-time knob and deliberately
//!    excluded). A mismatch, or a legacy-shape record on a vault with
//!    persisted vector/HNSW data → [`HnswConfigChanged`]; a missing record on
//!    a populated vault → [`InvalidConfig`].
//! 6. **`preflight_embedding_model`** — `hnsw_meta["model_id"]` (UTF-8).
//!    Stored ≠ requested → [`EmbeddingModelChanged`]; a populated vault whose
//!    stored id is missing, or a populated vault opened without a requested
//!    model → [`InvalidConfig`].
//! 7. `migrate_temporal_long_intervals_if_needed`
//!    (`hnsw_meta["temporal_long_intervals_schema_version"]`), then the
//!    persist-if-missing writes for the HNSW config / model id validated above
//!    (each re-checks under its own write transaction).
//!
//! `Vault::open` — after `Store::open` returns:
//!
//! 8. **Analyzer / BM25F handshake** (`handshake_text_index_manifest`) — keys
//!    `vault_meta["text_index_schema_version"]`,
//!    `vault_meta["text_analyzer_manifest"]` /
//!    `vault_meta["text_analyzer_manifest_hash"]`, and
//!    `vault_meta["text_bm25_field_schema_hash"]`. On a populated text index:
//!    a per-language analyzer mode flip (or a pre-ONE-317 / corrupt manifest)
//!    → [`IncompatibleAnalyzer`]; a diverged BM25F field schema →
//!    [`Bm25FieldSchemaChanged`]. The
//!    [`VaultConfig::skip_text_index_manifest_check`] escape hatch sits HERE
//!    and only here: it bypasses this analyzer gate so
//!    `MaintenanceBuilder::clear_text_index` can run; on a populated index it
//!    marks the text index untrusted so text reads/writes fail closed with
//!    `Error::CorruptedIndex` until the clear commits.
//! 9. The independent skill content-hash index sentinel migration
//!    (`vault_meta["skill_hub/content_hash_index_schema_version"]`) runs after
//!    the Vault claim doors are assembled, so pre-global scan verdicts can be
//!    reconciled transactionally. It still finishes before `Vault::open`
//!    returns a handle.
//!
//! # Compat-key homes (ONE-1097 owner decision: documented, not consolidated)
//!
//! `vault_meta` (#5) owns the storage/schema and text-index identity keys,
//! plus the per-type short-id counters (`b"sid_counter:" ‖ type_byte` → u64
//! LE, see `SHORT_ID_COUNTER_KEY_PREFIX`); `hnsw_meta` (#8) owns the
//! vector-side compatibility keys (`model_id`, `hnsw_config`) alongside HNSW
//! runtime metadata (`entry_point`, `count`, graph/vector version counters).
//! Consolidating the vector compat keys into `vault_meta` would be a storage
//! migration with no behavioral win, so the split is intentional and
//! documented here instead.
//!
//! [`StorageAbiVersionChanged`]: crate::error::Error::StorageAbiVersionChanged
//! [`StorageSchemaVersionChanged`]: crate::error::Error::StorageSchemaVersionChanged
//! [`DbManifestMismatch`]: crate::error::Error::DbManifestMismatch
//! [`VaultRootPreflight`]: crate::error::Error::VaultRootPreflight
//! [`HnswConfigChanged`]: crate::error::Error::HnswConfigChanged
//! [`EmbeddingModelChanged`]: crate::error::Error::EmbeddingModelChanged
//! [`InvalidConfig`]: crate::error::Error::InvalidConfig
//! [`IncompatibleAnalyzer`]: crate::error::Error::IncompatibleAnalyzer
//! [`Bm25FieldSchemaChanged`]: crate::error::Error::Bm25FieldSchemaChanged
//! [`VaultConfig::skip_text_index_manifest_check`]: crate::config::VaultConfig::skip_text_index_manifest_check

mod channel_identity_receipts;
mod gate_decision;
mod handle;
mod key_encoding;
mod open_gates;
mod outbound_send_receipt;
mod pending_embedding;
mod pending_gate_consent;
mod retrieval_telemetry;
mod short_id_alias;
mod structural_kind_registry;

#[cfg(test)]
pub(crate) mod test_hooks;
#[cfg(test)]
mod tests;

pub use channel_identity_receipts::*;
pub use gate_decision::*;
pub use handle::*;
pub(crate) use key_encoding::*;
pub use open_gates::*;
pub(crate) use outbound_send_receipt::*;
pub(in crate::store) use pending_embedding::*;
pub use pending_gate_consent::*;
pub use retrieval_telemetry::*;
pub use short_id_alias::*;
pub(crate) use structural_kind_registry::*;
