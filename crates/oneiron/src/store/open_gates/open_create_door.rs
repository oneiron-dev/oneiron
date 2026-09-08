//! Create-capable open door: `Store::open` and its helpers.

use std::path::Path;

use heed::EnvOpenOptions;

use crate::config::VaultConfig;
use crate::error::{Error, Result};
use crate::overlay_db::OverlayDb;
#[cfg(test)]
use crate::store::test_hooks;
use crate::store::{
    RawDatabases, Store, TYPE_BYTE_REKEY_V3, VaultWriterLease, rekey_type_bytes_v3_in_txn,
    seed_default_policy_manifest_in_txn,
};

use super::hnsw_model_gates::{
    migrate_temporal_long_intervals_if_needed, persist_hnsw_config_if_missing,
    persist_model_id_if_missing, preflight_embedding_model, preflight_hnsw_config,
};
use super::manifest_storage_gates::{
    OwnedEnv, RegisteredPath, StorageAbiGate, TornCreationCleanup, create_manifest_db,
    create_manifest_dupsort_db, create_manifest_str_db, gate_storage_versions,
    lmdb_database_open_guard, rekey_short_ids_if_needed_in_txn, validate_db_manifest_set,
    validate_fast_dims, vault_root_open_guard,
};
use super::open_version_keys::{
    DefaultPolicySeedMode, MAX_DBS, STORAGE_ABI_VERSION, STORAGE_ABI_VERSION_KEY,
    STORAGE_ABI_VERSION_V3_REKEY_PREDECESSOR, VAULT_ROOT_IDENTITY_CHECKS_AVAILABLE,
};
use super::vault_root_bind::{preflight_rejected_aliased_root, preflight_vault_root};

impl Store {
    /// Opens or creates a store at `path` and initializes all named databases.
    pub fn open(path: impl AsRef<Path>, config: &VaultConfig) -> Result<Self> {
        Self::open_with_storage_abi_version(
            path,
            config,
            STORAGE_ABI_VERSION,
            DefaultPolicySeedMode::Required,
        )
    }

    #[cfg(test)]
    pub(crate) fn open_with_storage_abi_version_for_test(
        path: impl AsRef<Path>,
        config: &VaultConfig,
        storage_abi_version: u16,
    ) -> Result<Self> {
        Self::open_with_storage_abi_version(
            path,
            config,
            storage_abi_version,
            DefaultPolicySeedMode::Required,
        )
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn open_unseeded_for_test(
        path: impl AsRef<Path>,
        config: &VaultConfig,
    ) -> Result<Self> {
        Self::open_with_storage_abi_version(
            path,
            config,
            STORAGE_ABI_VERSION,
            DefaultPolicySeedMode::TestUnseeded,
        )
    }

    pub(super) fn open_with_storage_abi_version(
        path: impl AsRef<Path>,
        config: &VaultConfig,
        storage_abi_version: u16,
        seed_mode: DefaultPolicySeedMode,
    ) -> Result<Self> {
        Self::open_with_lease(path, config, storage_abi_version, seed_mode, None)
    }

    pub(in crate::store) fn open_with_lease(
        path: impl AsRef<Path>,
        config: &VaultConfig,
        storage_abi_version: u16,
        seed_mode: DefaultPolicySeedMode,
        lease: Option<&VaultWriterLease>,
    ) -> Result<Self> {
        // Declared before the environment so its Drop runs after the env has
        // closed, releasing LMDB's file handles before removing torn files.
        let mut torn_creation_cleanup = TornCreationCleanup { root: None };
        let (env, registered_path, is_new_vault) = {
            let _vault_root_open_guard = vault_root_open_guard()?;

            std::fs::create_dir_all(path.as_ref())?;
            let canonical_path = path.as_ref().canonicalize()?;
            if let Some(lease) = lease {
                lease.validate_directory(&canonical_path)?;
            }
            #[cfg(target_os = "linux")]
            let storage_path = lease.map_or_else(
                || canonical_path.clone(),
                VaultWriterLease::environment_path,
            );
            #[cfg(not(target_os = "linux"))]
            let storage_path = canonical_path.clone();
            let root_preflight = preflight_vault_root(&storage_path)?;
            let is_new_vault = root_preflight.is_new_vault;
            if is_new_vault {
                torn_creation_cleanup.arm(storage_path.clone());
            }
            let mut registered_path =
                RegisteredPath::reserve(canonical_path.clone(), root_preflight.identity)?;

            // SAFETY: heed/LMDB require a single Env per filesystem path, the
            // path must not be on NFS or another unsupported network
            // filesystem, and map_size must not be changed concurrently while
            // the environment is open elsewhere. The path
            // existence/writability precondition is established by
            // create_dir_all plus the root preflight above. The caller must
            // not retarget the canonicalized filesystem path while it is being
            // opened. The process-local root-open guard keeps the initial
            // preflight, path reservation, unsafe LMDB open, and post-create
            // identity refresh indivisible against other openers; the
            // path/identity registry then rejects later duplicate live Env
            // opens for the same canonical path or known LMDB file identity.
            let env = unsafe {
                let mut options = EnvOpenOptions::new();
                options
                    .map_size(config.map_size)
                    .max_readers(config.max_readers)
                    .max_dbs(MAX_DBS);
                #[cfg(target_os = "linux")]
                let opened = if let Some(lease) = lease {
                    // Keep the directory capability intact, just like the
                    // existing-only door; the canonical path is cache identity.
                    options.open_with_cache_identity(
                        &lease.environment_path(),
                        canonical_path.clone(),
                        || {
                            #[cfg(test)]
                            test_hooks::run_before_lmdb_open(&canonical_path);
                        },
                        || {
                            #[cfg(test)]
                            test_hooks::run_after_lmdb_open(&canonical_path);
                        },
                    )?
                } else {
                    options.open(&canonical_path)?
                };
                #[cfg(not(target_os = "linux"))]
                let opened = options.open(&canonical_path)?;
                opened
            };
            // Wrap IMMEDIATELY so every `?` early-return below (failed open
            // gates) also releases the environment instead of leaking it into
            // heed's process-global registry (ONE-1142).
            let env = OwnedEnv {
                env,
                _bound_root_dir: None,
            };
            #[cfg(test)]
            test_hooks::run_after_lmdb_open(&canonical_path);
            if let Some(lease) = lease {
                lease.validate_directory(&canonical_path)?;
            }
            if VAULT_ROOT_IDENTITY_CHECKS_AVAILABLE {
                // A root whose LMDB files gained a SECOND HARD LINK while this
                // open was creating them is an ALIAS, not a torn creation, and
                // the difference decides whether the next opener of that alias
                // can still see it. Torn-creation cleanup exists to unlink
                // files this open created so a retry starts clean; here the
                // inode is reachable through another name, so unlinking our
                // side cannot restore a clean root (the inode survives) and it
                // destroys the one fact that makes the alias rejectable —
                // `link_count >= 2`. An opener arriving at the alias afterwards
                // would find a single-link root holding an LMDB environment
                // with no committed `vault_meta`, and would report the ABI gate
                // (`StorageAbiVersionChanged { stored: None }`) instead of the
                // alias, admitting a second environment over shared files.
                //
                // So: disarm cleanup for exactly that verdict and let the
                // preflight error stand. Rejection is not weakened anywhere —
                // this open still fails closed with the SAME
                // `VaultRootPreflight(MultipleHardLinks)`, returns no handle,
                // and releases its path reservation; only the destructive
                // unlink is withheld. Every other failure keeps cleanup armed.
                let refreshed = match preflight_vault_root(&storage_path) {
                    Ok(refreshed) => refreshed,
                    Err(error) => {
                        if preflight_rejected_aliased_root(&error) {
                            torn_creation_cleanup.disarm();
                        }
                        return Err(error);
                    }
                };
                registered_path.refresh_identity(refreshed.identity)?;
            }

            (env, registered_path, is_new_vault)
        };

        let db_open_guard = lmdb_database_open_guard()?;
        let mut wtxn = env.write_txn()?;
        let vault_meta = create_manifest_db(&env, &mut wtxn, 4)?;
        let vault_meta_view = OverlayDb::canonical(vault_meta);
        let abi_gate = gate_storage_versions(
            &vault_meta_view,
            &mut wtxn,
            is_new_vault,
            storage_abi_version,
        )?;
        if !is_new_vault {
            validate_db_manifest_set(&env, &wtxn)?;
        }

        let entities = create_manifest_db(&env, &mut wtxn, 0)?;
        let type_index = create_manifest_db(&env, &mut wtxn, 1)?;
        let short_ids = create_manifest_db(&env, &mut wtxn, 2)?;
        let short_ids_reverse = create_manifest_db(&env, &mut wtxn, 3)?;
        let vectors = create_manifest_db(&env, &mut wtxn, 5)?;
        let hnsw_neighbors = create_manifest_db(&env, &mut wtxn, 6)?;
        let hnsw_meta = create_manifest_db(&env, &mut wtxn, 7)?;
        let text_postings = create_manifest_dupsort_db(&env, &mut wtxn, 8)?;
        let text_meta = create_manifest_db(&env, &mut wtxn, 9)?;
        let text_forward = create_manifest_db(&env, &mut wtxn, 10)?;
        let text_bm25_field_stats = create_manifest_db(&env, &mut wtxn, 11)?;
        let text_doc_field_lengths = create_manifest_db(&env, &mut wtxn, 12)?;
        let edges_out = create_manifest_db(&env, &mut wtxn, 13)?;
        let edges_in = create_manifest_db(&env, &mut wtxn, 14)?;
        let ppr_cache = create_manifest_db(&env, &mut wtxn, 15)?;
        let ppr_cache_deps = create_manifest_db(&env, &mut wtxn, 16)?;
        let temporal_occurred_start = create_manifest_db(&env, &mut wtxn, 17)?;
        let temporal_occurred_end = create_manifest_db(&env, &mut wtxn, 18)?;
        let temporal_learned = create_manifest_db(&env, &mut wtxn, 19)?;
        let temporal_long_intervals = create_manifest_db(&env, &mut wtxn, 20)?;
        let phonetic_index = create_manifest_db(&env, &mut wtxn, 21)?;
        let phonetic_forward = create_manifest_db(&env, &mut wtxn, 22)?;
        let sync_state = create_manifest_str_db(&env, &mut wtxn, 23)?;
        let sync_queue = create_manifest_db(&env, &mut wtxn, 24)?;
        let attempt_records = create_manifest_db(&env, &mut wtxn, 25)?;
        let attempt_ready = create_manifest_db(&env, &mut wtxn, 26)?;
        let attempt_dedupe = create_manifest_db(&env, &mut wtxn, 27)?;
        if is_new_vault {
            validate_db_manifest_set(&env, &wtxn)?;
        }

        let raw = RawDatabases {
            entities,
            edges_out,
            edges_in,
            vectors,
            hnsw_neighbors,
            hnsw_meta,
            text_postings,
            text_meta,
            text_forward,
            text_bm25_field_stats,
            text_doc_field_lengths,
            vault_meta,
            ppr_cache,
            ppr_cache_deps,
            type_index,
            temporal_occurred_start,
            temporal_occurred_end,
            temporal_learned,
            temporal_long_intervals,
            phonetic_index,
            phonetic_forward,
            short_ids,
            short_ids_reverse,
            sync_state,
            sync_queue,
            attempt_records,
            attempt_ready,
            attempt_dedupe,
        };

        // ONE-1754: the one sanctioned migration branch. It runs in THIS
        // transaction, after every database exists and before the commit, so a
        // failure aborts the whole open — old bytes and the predecessor stamp
        // both survive, and the vault stays openable by the previous engine.
        // The new stamp is written only once the re-key's own count and id-set
        // assertions have passed.
        if abi_gate == StorageAbiGate::RekeyByteSpaceV3 {
            let edges_out_before = raw.edges_out.len(&wtxn)?;
            let edges_in_before = raw.edges_in.len(&wtxn)?;
            let counts = rekey_type_bytes_v3_in_txn(&raw, &mut wtxn, TYPE_BYTE_REKEY_V3)?;
            // Edges carry entity ids and edge data, never endpoint type bytes.
            // Asserting the totals is how "we did not touch them" stops being
            // a claim in a comment and becomes a checked fact.
            if raw.edges_out.len(&wtxn)? != edges_out_before
                || raw.edges_in.len(&wtxn)? != edges_in_before
            {
                return Err(Error::CorruptedIndex("byte-space v3 edge total changed"));
            }
            tracing::info!(
                entities = counts.entities,
                type_index = counts.type_index,
                short_id_counters = counts.short_id_counters,
                kind_registrations = counts.kind_registrations,
                kind_registrations_rezoned = counts.kind_registrations_rezoned,
                from = STORAGE_ABI_VERSION_V3_REKEY_PREDECESSOR,
                to = storage_abi_version,
                "byte-space v3 type-byte re-key applied"
            );
            vault_meta_view.put(
                &mut wtxn,
                STORAGE_ABI_VERSION_KEY,
                &storage_abi_version.to_le_bytes(),
            )?;
        }

        // ONE-1930: the presentation-prefix re-key. Runs in THIS transaction,
        // after the byte-space pass above so entity envelopes and
        // `sid_counter:<byte>` keys are already at their final v3 bytes — this
        // pass changes prefixes, never type bytes.
        rekey_short_ids_if_needed_in_txn(&raw, &vault_meta_view, &mut wtxn)?;

        if is_new_vault && matches!(seed_mode, DefaultPolicySeedMode::Required) {
            let id = crate::gate::default_policy_manifest_id()?;
            let entities = OverlayDb::canonical(raw.entities);
            let type_index = OverlayDb::canonical(raw.type_index);
            let temporal_occurred_start = OverlayDb::canonical(raw.temporal_occurred_start);
            let temporal_learned = OverlayDb::canonical(raw.temporal_learned);
            seed_default_policy_manifest_in_txn(
                &entities,
                &type_index,
                &temporal_occurred_start,
                &temporal_learned,
                &mut wtxn,
                &id,
            )?;
        }
        #[cfg(test)]
        if is_new_vault
            && matches!(seed_mode, DefaultPolicySeedMode::Required)
            && test_hooks::take_fail_initial_seed_commit_for(&registered_path.path)
        {
            return Err(Error::InvalidConfig(
                "test: initial seed transaction interrupted".to_owned(),
            ));
        }
        wtxn.commit()?;
        // The initial creation transaction is durable; later open failures
        // must preserve this committed vault.
        torn_creation_cleanup.disarm();
        drop(db_open_guard);

        let store = Self::assemble(env, raw, registered_path)?;

        // EMB-2 preflight: an out-of-range fast_dims is a caller bug and
        // fails closed before the HNSW compat check below can compare it.
        validate_fast_dims(config)?;

        let should_persist_hnsw_config = preflight_hnsw_config(
            &store.env,
            &store.hnsw_meta,
            &store.vectors,
            &store.hnsw_neighbors,
            config,
        )?;
        let should_persist_model_id = preflight_embedding_model(
            &store.env,
            &store.hnsw_meta,
            &store.vectors,
            &store.hnsw_neighbors,
            config.embedding_model.as_deref(),
        )?;
        migrate_temporal_long_intervals_if_needed(
            &store.env,
            &store.hnsw_meta,
            &store.temporal_long_intervals,
        )?;

        if should_persist_hnsw_config {
            persist_hnsw_config_if_missing(
                &store.env,
                &store.hnsw_meta,
                &store.vectors,
                &store.hnsw_neighbors,
                config,
            )?;
        }

        if should_persist_model_id {
            let requested = config
                .embedding_model
                .as_deref()
                .ok_or_else(|| Error::InvalidConfig("missing embedding model".to_owned()))?;
            persist_model_id_if_missing(
                &store.env,
                &store.hnsw_meta,
                &store.vectors,
                &store.hnsw_neighbors,
                requested,
            )?;
        }

        store.ensure_receipt_family_indexes_on_open()?;
        store.ensure_gate_claim_index_flag_on_open()?;
        if matches!(seed_mode, DefaultPolicySeedMode::Required) {
            store.ensure_default_policy_manifest_on_open()?;
        }
        Ok(store)
    }
}
