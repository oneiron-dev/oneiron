//! Vault open path: LMDB env exclusivity, manifest set, doctor, ABI gate matrix.

use super::*;
use crate::error::StoreError;

#[test]
fn vault_open_rejects_second_live_env_for_same_path() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();

    let first_vault = Vault::open(path, test_config())?;
    let Err(err) = Vault::open(path, test_config()) else {
        panic!("expected second live vault open to fail");
    };
    assert_matches!(
        err,
        Error::Store(StoreError::VaultRootPreflight {
            problem: VaultRootProblem::DuplicateOpenRoot { .. },
            ..
        })
    );

    drop(first_vault);
    let reopened = Vault::open(path, test_config())?;
    drop(reopened);
    Ok(())
}

#[cfg(unix)]
#[test]
fn vault_open_rejects_second_live_env_for_symlinked_path() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let real_path = temp_dir.path().join("vault");
    let link_path = temp_dir.path().join("vault-link");
    std::fs::create_dir_all(&real_path)?;
    std::os::unix::fs::symlink(&real_path, &link_path)?;

    let first_vault = Vault::open(&real_path, test_config())?;
    let Err(err) = Vault::open(&link_path, test_config()) else {
        panic!("expected symlinked second live vault open to fail");
    };
    assert_matches!(
        err,
        Error::Store(StoreError::VaultRootPreflight {
            problem: VaultRootProblem::DuplicateOpenRoot { .. },
            ..
        })
    );

    drop(first_vault);
    let reopened = Vault::open(&link_path, test_config())?;
    drop(reopened);
    Ok(())
}

#[test]
fn dropping_last_vault_handle_closes_lmdb_env() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();

    let vault = Vault::open(path, test_config())?;
    // heed registers opened environments by canonicalized path; a live
    // registration is observable as `Some(closing_event)`.
    let canonical = path.canonicalize()?;
    let closing_event =
        heed::env_closing_event(&canonical).expect("open vault must have a live env registration");

    drop(vault);
    // `Store`'s drop runs `prepare_for_closing` and the wrapped env is the
    // last clone, so the close is synchronous by the time `drop` returns;
    // the timeout only bounds the failure mode.
    assert!(
        closing_event.wait_timeout(std::time::Duration::from_secs(5)),
        "LMDB env did not close after dropping the last vault handle"
    );
    assert!(
        heed::env_closing_event(&canonical).is_none(),
        "closed env still present in heed's process-global registry"
    );

    // Single-writer reopen of the same path works after the close.
    let reopened = Vault::open(path, test_config())?;
    drop(reopened);
    assert!(heed::env_closing_event(&canonical).is_none());
    Ok(())
}

#[test]
fn vault_open_rejects_partial_lmdb_root_before_open() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    let canonical = path.canonicalize()?;
    std::fs::write(path.join("lock.mdb"), b"stale lock")?;

    let Err(err) = Vault::open(path, test_config()) else {
        panic!("expected partial LMDB root to fail preflight");
    };
    assert_matches!(
        err,
        Error::Store(StoreError::VaultRootPreflight {
            ref path,
            problem: VaultRootProblem::IncompleteLmdbPair {
                present: VaultRootEntry::Lock,
                missing: VaultRootEntry::Data,
            },
        }) if path == &canonical
    );
    assert!(
        !temp_dir.path().join("data.mdb").exists(),
        "preflight must reject before LMDB creates data.mdb"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn vault_open_rejects_hardlinked_lmdb_root_before_open() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let real_path = temp_dir.path().join("vault");
    let duplicate_path = temp_dir.path().join("vault-hardlink");
    let _vault = Vault::open(&real_path, test_config())?;
    std::fs::create_dir_all(&duplicate_path)?;
    std::fs::hard_link(real_path.join("data.mdb"), duplicate_path.join("data.mdb"))?;
    std::fs::hard_link(real_path.join("lock.mdb"), duplicate_path.join("lock.mdb"))?;
    let canonical_duplicate = duplicate_path.canonicalize()?;

    let Err(err) = Vault::open(&duplicate_path, test_config()) else {
        panic!("expected hardlinked LMDB root to fail preflight");
    };
    assert_matches!(
        err,
        Error::Store(StoreError::VaultRootPreflight {
            ref path,
            problem: VaultRootProblem::MultipleHardLinks {
                entry: VaultRootEntry::Data,
                link_count,
            },
        }) if path == &canonical_duplicate && link_count >= 2
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn vault_open_rejects_new_vault_hardlink_alias_before_second_lmdb_open() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let real_path = temp_dir.path().join("vault");
    let duplicate_path = temp_dir.path().join("vault-hardlink");
    let duplicate_for_hook = duplicate_path.clone();
    std::fs::create_dir_all(&real_path)?;
    let canonical_real_path = real_path.canonicalize()?;

    let (hardlinks_ready_tx, hardlinks_ready_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    crate::store::test_hooks::arm_after_lmdb_open(canonical_real_path, move |canonical_root| {
        let result = (|| -> std::io::Result<()> {
            std::fs::create_dir_all(&duplicate_for_hook)?;
            std::fs::hard_link(
                canonical_root.join("data.mdb"),
                duplicate_for_hook.join("data.mdb"),
            )?;
            std::fs::hard_link(
                canonical_root.join("lock.mdb"),
                duplicate_for_hook.join("lock.mdb"),
            )?;
            Ok(())
        })();
        hardlinks_ready_tx
            .send(result)
            .expect("hardlink readiness receiver dropped");
        resume_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("test did not resume paused vault open");
    });

    let first_path = real_path;
    let first_open = std::thread::spawn(move || Vault::open(&first_path, test_config()).map(drop));
    match hardlinks_ready_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("paused vault open did not create hardlink alias")
    {
        Ok(()) => {}
        Err(err) => {
            let _ = resume_tx.send(());
            panic!("failed to create hardlink alias during vault open: {err}");
        }
    }

    let second_path = duplicate_path;
    let second_open =
        std::thread::spawn(move || Vault::open(&second_path, test_config()).map(drop));

    std::thread::sleep(std::time::Duration::from_millis(50));
    resume_tx.send(()).expect("paused vault open exited early");

    let first_err = match first_open.join().expect("first vault open panicked") {
        Ok(()) => panic!("first vault open must fail closed on new hardlink alias"),
        Err(err) => err,
    };
    let second_err = match second_open.join().expect("second vault open panicked") {
        Ok(()) => panic!("second vault open must fail closed on new hardlink alias"),
        Err(err) => err,
    };

    assert_matches!(
        first_err,
        Error::Store(StoreError::VaultRootPreflight {
            problem: VaultRootProblem::MultipleHardLinks { link_count, .. },
            ..
        }) if link_count >= 2
    );
    assert_matches!(
        second_err,
        Error::Store(StoreError::VaultRootPreflight {
            problem: VaultRootProblem::MultipleHardLinks { link_count, .. },
            ..
        }) if link_count >= 2
    );
    Ok(())
}

/// ONE-1142 regression: without the `OwnedEnv` close path every
/// `Vault::open` leaks one pthread TLS key (LMDB allocates it in
/// `mdb_env_setup_locks`; only `mdb_env_close` frees it), and macOS caps a
/// process at `PTHREAD_KEYS_MAX = 512` keys — open #~509 fails with
/// `Io(EAGAIN)`. 600 sequential open→drop cycles in ONE process must all
/// succeed; only one env is alive at a time, so the loop is cheap.
#[test]
fn vault_open_drop_cycles_survive_pthread_key_limit() -> Result<()> {
    let mut config = test_config();
    config.map_size = 4 << 20;

    for i in 0..600_usize {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), config.clone()).unwrap_or_else(|err| {
            panic!("vault open #{i} failed (pthread-key leak regression): {err:?}")
        });
        drop(vault);
    }
    Ok(())
}

#[test]
fn creates_contract_manifest_databases() -> Result<()> {
    // Also pins ONE-1093 feature-independence (formerly a separate test,
    // consolidated by ONE-1145): this test compiles and runs under BOTH the
    // default and `--features sync` configs and asserts the same 28-name
    // materialized set, including the sync_state/sync_queue rows below.
    let (_dir, vault) = open_test_vault();

    let expected_materialized: Vec<String> = expected_manifest_names()
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    let materialized = materialized_database_names(&vault)?;
    assert_eq!(materialized, expected_materialized);

    for required_name in [
        "sync_state",
        "sync_queue",
        "job_records",
        "job_ready",
        "job_dedupe",
    ] {
        assert!(materialized.iter().any(|name| name == required_name));
    }

    Ok(())
}

#[test]
fn open_valid_existing_vault_passes_manifest_set_gate() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    {
        let vault = Vault::open(path, test_config())?;
        assert_eq!(
            materialized_database_names(&vault)?,
            expected_manifest_names()
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>()
        );
    }

    let reopened = Vault::open(path, test_config())?;
    drop(reopened);
    Ok(())
}

#[test]
fn open_rejects_rogue_manifest_database_name() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    {
        let vault = Vault::open(path, test_config())?;
        drop(vault);
    }
    create_raw_named_database(path, "future_manifest_26")?;

    let err = match Vault::open(path, test_config()) {
        Ok(_) => panic!("expected Vault::open to fail closed on rogue named DB"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            Error::Store(StoreError::DbManifestMismatch {
                ref missing,
                ref unexpected
            }) if missing.is_empty() && unexpected == &vec!["future_manifest_26".to_owned()]
        ),
        "expected DB manifest mismatch for rogue name, got {err:?}"
    );
    Ok(())
}

/// Consolidated from name-only clones (ONE-1145/ONE-1206): one core DB plus
/// sync-era and attempt-queue DBs. Removing ANY required manifest name must fail
/// closed with the exact missing-name payload.
#[test]
fn open_rejects_missing_required_manifest_database_name() -> Result<()> {
    for missing_name in [
        "hnsw_meta",
        "sync_state",
        "sync_queue",
        "job_records",
        "job_ready",
        "job_dedupe",
    ] {
        let temp_dir = tempfile::tempdir()?;
        create_raw_vault_missing_manifest_name(temp_dir.path(), missing_name)?;

        let err = match Vault::open(temp_dir.path(), test_config()) {
            Ok(_) => panic!("expected Vault::open to fail closed on missing {missing_name}"),
            Err(err) => err,
        };
        assert!(
            matches!(
                err,
                Error::Store(StoreError::DbManifestMismatch {
                    ref missing,
                    ref unexpected
                }) if missing == &vec![missing_name.to_owned()] && unexpected.is_empty()
            ),
            "expected DB manifest mismatch for missing {missing_name}, got {err:?}"
        );
    }
    Ok(())
}

#[test]
fn open_rejects_pre_fix_manifest_shape_at_storage_abi_gate() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    // Two back, not one: the immediate predecessor is ONE-1754's sanctioned
    // migration stamp and would open rather than trip the ABI gate.
    let stale_abi = STORAGE_ABI_VERSION - 2;
    create_raw_vault_missing_manifest_name(path, "sync_state")?;
    set_raw_storage_abi_version(path, Some(stale_abi))?;

    let err = match Vault::open(path, test_config()) {
        Ok(_) => panic!("expected Vault::open to reject stale ABI before manifest validation"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            Error::Store(StoreError::StorageAbiVersionChanged {
                stored: Some(stored),
                current: STORAGE_ABI_VERSION
            }) if stored == stale_abi
        ),
        "expected storage ABI rejection for pre-fix manifest shape, got {err:?}"
    );
    Ok(())
}

#[test]
fn open_persists_storage_versions_on_create() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    assert_eq!(
        read_meta_u16(&vault, STORAGE_ABI_VERSION_KEY)?,
        Some(STORAGE_ABI_VERSION)
    );
    assert_eq!(
        read_meta_u16(&vault, STORAGE_SCHEMA_VERSION_KEY)?,
        Some(STORAGE_SCHEMA_VERSION)
    );
    Ok(())
}

#[test]
fn doctor_reflects_persisted_open_compatibility_values() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = Some("test/doctor-model@v1".to_owned());
    let vault = Vault::open(temp_dir.path(), cfg)?;

    let report = vault.doctor()?;
    serde_json::to_value(&report).expect("doctor report must serialize");

    assert_eq!(report.storage_abi_version, Some(STORAGE_ABI_VERSION));
    assert_eq!(report.storage_schema_version, Some(STORAGE_SCHEMA_VERSION));
    assert_eq!(
        report.embedding_model_id,
        Some("test/doctor-model@v1".to_owned())
    );
    assert_eq!(
        report.hnsw.record_state,
        VaultDoctorHnswRecordState::Current
    );
    assert_eq!(report.hnsw.vector_dimensions, Some(4));
    assert_eq!(report.hnsw.m_max_0, Some(64));
    assert_eq!(report.hnsw.ef_construction, Some(200));
    assert_eq!(report.hnsw.distance_metric.as_deref(), Some("cosine"));
    assert_eq!(report.hnsw.index_structure.as_deref(), Some("flat_nsw"));
    // Pinned hash of the portable analyzer manifest at ANALYZER_VERSION
    // "v3" (ONE-1118 emoji grapheme lane). Any manifest-affecting change
    // (version bump, channel set, normalization policy) must re-pin this.
    assert_eq!(
        report.analyzer_manifest_hash.as_deref(),
        Some("e0da35956883bf26e26881b73c515f2c9c7d11087ef813da026dc51c303e1002")
    );
    // Sha256 over the field-schema records with
    // POSTINGS_VALUE_FORMAT_VERSION = 2 (ONE-299 DUP_SORT postings).
    assert_eq!(
        report.bm25_field_schema_hash.as_deref(),
        Some("b7b78821908fdabc95ac85de7e17f157b0482d105037e8f6ecfa71e1ff158d6f")
    );
    assert_eq!(report.text_index_schema_version, Some(2));
    assert!(report.unreadable_fields.is_empty());
    assert_eq!(report.db_manifest.expected_count, 28);
    assert_eq!(report.db_manifest.present_count, 28);
    assert!(report.db_manifest.missing_names.is_empty());
    assert!(report.db_manifest.unexpected_names.is_empty());
    assert!(
        report
            .db_manifest
            .present_names
            .contains(&"vault_meta".to_owned())
    );
    assert!(
        report
            .db_manifest
            .present_names
            .contains(&"hnsw_meta".to_owned())
    );
    Ok(())
}

#[test]
fn doctor_reads_persisted_text_hash_keys() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let analyzer_hash = [0xAB; 32];
    let field_schema_hash = [0xCD; 32];

    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(
            &mut wtxn,
            crate::store::TEXT_ANALYZER_MANIFEST_HASH_KEY,
            &analyzer_hash,
        )?;
        vault.store.vault_meta.put(
            &mut wtxn,
            crate::store::TEXT_BM25_FIELD_SCHEMA_HASH_KEY,
            &field_schema_hash,
        )?;
        wtxn.commit()?;
    }

    let report = vault.doctor()?;
    assert_eq!(
        report.analyzer_manifest_hash.as_deref(),
        Some("abababababababababababababababababababababababababababababababab")
    );
    assert_eq!(
        report.bm25_field_schema_hash.as_deref(),
        Some("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")
    );
    assert!(report.unreadable_fields.is_empty());
    Ok(())
}

#[test]
fn doctor_does_not_write_data_file() -> Result<()> {
    let (temp_dir, vault) = open_test_vault();
    let data_file = temp_dir.path().join("data.mdb");
    let before = std::fs::metadata(&data_file)?;
    let before_modified = before.modified()?;
    let before_digest = Sha256::digest(std::fs::read(&data_file)?);

    let report = vault.doctor()?;
    assert_eq!(report.db_manifest.present_count, 28);

    let after = std::fs::metadata(&data_file)?;
    let after_digest = Sha256::digest(std::fs::read(&data_file)?);
    assert_eq!(after.len(), before.len());
    assert_eq!(after.modified()?, before_modified);
    assert_eq!(after_digest, before_digest);
    Ok(())
}

#[test]
fn doctor_reports_missing_and_legacy_metadata_without_gating() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let cfg = test_config();
    let vault = Vault::open(temp_dir.path(), cfg.clone())?;

    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .vault_meta
            .delete(&mut wtxn, STORAGE_ABI_VERSION_KEY)?;
        vault
            .store
            .vault_meta
            .delete(&mut wtxn, STORAGE_SCHEMA_VERSION_KEY)?;
        vault
            .store
            .vault_meta
            .delete(&mut wtxn, crate::store::TEXT_INDEX_SCHEMA_VERSION_KEY)?;
        vault
            .store
            .vault_meta
            .delete(&mut wtxn, crate::store::TEXT_ANALYZER_MANIFEST_HASH_KEY)?;
        vault
            .store
            .vault_meta
            .delete(&mut wtxn, crate::store::TEXT_BM25_FIELD_SCHEMA_HASH_KEY)?;
        vault.store.hnsw_meta.delete(&mut wtxn, MODEL_ID_KEY)?;
        vault.store.hnsw_meta.delete(&mut wtxn, HNSW_CONFIG_KEY)?;
        wtxn.commit()?;
    }

    let report = vault.doctor()?;
    assert_eq!(report.storage_abi_version, None);
    assert_eq!(report.storage_schema_version, None);
    assert_eq!(report.embedding_model_id, None);
    assert_eq!(
        report.hnsw.record_state,
        VaultDoctorHnswRecordState::Missing
    );
    assert_eq!(report.hnsw.vector_dimensions, None);
    assert_eq!(report.hnsw.distance_metric, None);
    assert_eq!(report.analyzer_manifest_hash, None);
    assert_eq!(report.bm25_field_schema_hash, None);
    assert_eq!(report.text_index_schema_version, None);
    assert!(report.unreadable_fields.is_empty());

    let legacy = legacy_hnsw_compatibility_record(&cfg);
    write_hnsw_config_record(&vault, &legacy)?;
    let report = vault.doctor()?;
    assert_eq!(report.hnsw.record_state, VaultDoctorHnswRecordState::Legacy);
    assert_eq!(report.hnsw.vector_dimensions, Some(4));
    assert_eq!(report.hnsw.m_max_0, Some(64));
    assert_eq!(report.hnsw.ef_construction, Some(200));
    assert_eq!(report.hnsw.distance_metric, None);
    assert_eq!(report.hnsw.index_structure, None);
    assert!(report.unreadable_fields.is_empty());
    Ok(())
}

#[test]
fn doctor_surfaces_corrupt_metadata_without_gating() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .vault_meta
            .put(&mut wtxn, STORAGE_ABI_VERSION_KEY, &[0x01])?;
        wtxn.commit()?;
    }

    let report = vault.doctor()?;
    assert_eq!(report.storage_abi_version, None);
    assert!(
        report
            .unreadable_fields
            .contains(&"vault_meta.storage_abi_version".to_owned())
    );
    assert!(
        !report
            .unreadable_fields
            .contains(&"vault_meta.schema_version".to_owned())
    );
    Ok(())
}

#[test]
fn open_rejects_missing_or_stale_storage_abi_version() -> Result<()> {
    for (case_name, stale_value) in [("missing", None), ("older", Some(0_u16))] {
        let temp_dir = tempfile::tempdir()?;
        let path = temp_dir.path();
        {
            let _vault = Vault::open(path, test_config())?;
        }

        set_raw_storage_abi_version(path, stale_value)?;
        let err = match Vault::open(path, test_config()) {
            Ok(_) => panic!("case {case_name}: expected Vault::open to fail closed"),
            Err(err) => err,
        };
        assert!(
            matches!(
                err,
                Error::Store(StoreError::StorageAbiVersionChanged { .. })
            ),
            "case {case_name}: expected storage ABI version error, got {err:?}"
        );
    }

    Ok(())
}

/// ONE-1097: fail-closed open-gate integration matrix.
///
/// Spec-derived from the canonical gate sequence documented at the top of
/// `crate::store` (ARCH-0019 storage invariants: "Schema versioned in
/// vault_meta. Reopen fails closed on analyzer or field-schema mismatch" +
/// the ARCH-0031 manifest-handshake state table). Every incompatible
/// config/model/analyzer state must abort `Vault::open` with its specific
/// typed [`ErrorKind`] BEFORE any usable `Vault` handle exists.
///
/// Per case this asserts:
/// 1. `Vault::open` fails with the contract-expected `ErrorKind` (the `Err`
///    return means no partial `Vault` is observable — there is no handle to
///    read or write through);
/// 2. a second open of the same directory reproduces the same gate error —
///    a leaked path registration would instead surface as
///    `VaultRootPreflight(DuplicateOpenRoot)`, and
///    partially-initialized state would change the error.
///
/// The `*_precedes_*` cases pin the documented gate ORDERING: ABI gate before
/// the DB-manifest gate (vault_meta is created first because the ABI gate
/// reads the version from it, so a missing `storage_abi_version` row is an
/// ABI-gate failure, not a manifest-gate failure), HNSW/dimension gate before
/// the embedding-model gate, and the model gate before the analyzer/BM25F
/// handshake in `Vault::open`.
#[test]
fn open_gate_matrix_fails_closed() -> Result<()> {
    struct GateCase {
        name: &'static str,
        /// Builds the vault directory in the incompatible state under test.
        prepare: fn(&Path) -> Result<()>,
        /// Config used for the (expected-to-fail) open attempts.
        open_config: fn() -> VaultConfig,
        expected_kind: ErrorKind,
    }

    fn create_default_vault(path: &Path) -> Result<()> {
        let _vault = Vault::open(path, test_config())?;
        Ok(())
    }

    fn populate_vector_data(vault: &Vault) -> Result<()> {
        let id = EntityId::now();
        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"gate-node")?;
        vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
        Ok(())
    }

    fn create_populated_vector_vault(path: &Path) -> Result<()> {
        let vault = Vault::open(path, test_config())?;
        populate_vector_data(&vault)
    }

    fn create_populated_text_vault(path: &Path) -> Result<()> {
        let vault = Vault::open(path, test_config())?;
        let id = EntityId::now();
        vault
            .batch()
            .put(&id, 1, test_time_range(1, 1), 1, b"gate-text")
            .text(&id, &[("body", "open gate matrix corpus")])
            .commit()?;
        Ok(())
    }

    fn put_vault_meta_row(path: &Path, key: &[u8], value: &[u8]) -> Result<()> {
        let vault = Vault::open(path, test_config())?;
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(&mut wtxn, key, value)?;
        wtxn.commit()?;
        Ok(())
    }

    fn delete_hnsw_meta_row(path: &Path, key: &[u8]) -> Result<()> {
        let vault = Vault::open(path, test_config())?;
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.hnsw_meta.delete(&mut wtxn, key)?;
        wtxn.commit()?;
        Ok(())
    }

    fn config_with_model(model: &str) -> VaultConfig {
        let mut cfg = test_config();
        cfg.embedding_model = Some(model.to_owned());
        cfg
    }

    // ── prepare fns, one per matrix row ────────────────────────────────

    // NOT `- 1`: ONE-1754 made the immediate predecessor the one sanctioned
    // migration stamp, so it no longer exercises the fail-closed gate. Two
    // back is genuinely stale and still must fail closed.
    fn prep_stale_abi(path: &Path) -> Result<()> {
        create_default_vault(path)?;
        set_raw_storage_abi_version(path, Some(STORAGE_ABI_VERSION - 2))
    }
    fn prep_missing_abi_row(path: &Path) -> Result<()> {
        create_default_vault(path)?;
        set_raw_storage_abi_version(path, None)
    }
    fn prep_unknown_schema(path: &Path) -> Result<()> {
        create_default_vault(path)?;
        put_vault_meta_row(
            path,
            STORAGE_SCHEMA_VERSION_KEY,
            &(STORAGE_SCHEMA_VERSION + 1).to_le_bytes(),
        )
    }
    fn prep_missing_manifest_db(path: &Path) -> Result<()> {
        create_raw_vault_missing_manifest_name(path, "edges_in")
    }
    fn prep_rogue_manifest_db(path: &Path) -> Result<()> {
        create_default_vault(path)?;
        create_raw_named_database(path, "rogue_gate_db_26")
    }
    fn prep_stale_abi_and_missing_manifest_db(path: &Path) -> Result<()> {
        create_raw_vault_missing_manifest_name(path, "edges_in")?;
        set_raw_storage_abi_version(path, Some(STORAGE_ABI_VERSION - 2))
    }
    fn prep_hnsw_metric_structure_flip(path: &Path) -> Result<()> {
        let vault = Vault::open(path, test_config())?;
        let mut raw = read_hnsw_config_record(&vault)?;
        assert!(
            raw.len() >= 27,
            "hnsw config record too short ({}) to flip metric/structure bytes",
            raw.len()
        );
        raw[25] = 2;
        raw[26] = 2;
        write_hnsw_config_record(&vault, &raw)
    }
    fn prep_legacy_hnsw_on_populated(path: &Path) -> Result<()> {
        let vault = Vault::open(path, test_config())?;
        populate_vector_data(&vault)?;
        let legacy = legacy_hnsw_compatibility_record(&test_config());
        write_hnsw_config_record(&vault, &legacy)
    }
    fn prep_populated_missing_hnsw_compat(path: &Path) -> Result<()> {
        create_populated_vector_vault(path)?;
        delete_hnsw_meta_row(path, HNSW_CONFIG_KEY)
    }
    fn prep_populated_missing_model_id(path: &Path) -> Result<()> {
        create_populated_vector_vault(path)?;
        delete_hnsw_meta_row(path, MODEL_ID_KEY)
    }
    fn prep_analyzer_hash_flip(path: &Path) -> Result<()> {
        create_populated_text_vault(path)?;
        put_vault_meta_row(
            path,
            crate::store::TEXT_ANALYZER_MANIFEST_HASH_KEY,
            &[0xCC; 32],
        )
    }
    fn prep_bm25_field_schema_flip(path: &Path) -> Result<()> {
        create_populated_text_vault(path)?;
        put_vault_meta_row(
            path,
            crate::store::TEXT_BM25_FIELD_SCHEMA_HASH_KEY,
            &[0xEE; 32],
        )
    }
    fn prep_text_and_vector_with_analyzer_flip(path: &Path) -> Result<()> {
        let vault = Vault::open(path, test_config())?;
        let id = EntityId::now();
        vault
            .batch()
            .put(&id, 1, test_time_range(1, 1), 1, b"gate-both")
            .text(&id, &[("body", "ordering corpus")])
            .commit()?;
        populate_vector_data(&vault)?;
        drop(vault);
        put_vault_meta_row(
            path,
            crate::store::TEXT_ANALYZER_MANIFEST_HASH_KEY,
            &[0xCC; 32],
        )
    }

    // ── open-config fns ────────────────────────────────────────────────

    fn cfg_default() -> VaultConfig {
        test_config()
    }
    fn cfg_dimensions_8() -> VaultConfig {
        let mut cfg = test_config();
        cfg.dimensions = 8;
        cfg
    }
    fn cfg_model_b() -> VaultConfig {
        config_with_model("matrix/model@b")
    }
    fn cfg_no_model() -> VaultConfig {
        let mut cfg = test_config();
        cfg.embedding_model = None;
        cfg
    }
    fn cfg_dimensions_8_and_model_b() -> VaultConfig {
        let mut cfg = config_with_model("matrix/model@b");
        cfg.dimensions = 8;
        cfg
    }

    let cases: Vec<GateCase> = vec![
        // Gate 2a: storage ABI (vault_meta["storage_abi_version"], u16 LE).
        GateCase {
            name: "stale_storage_abi_version",
            prepare: prep_stale_abi,
            open_config: cfg_default,
            expected_kind: ErrorKind::StorageAbiVersionChanged,
        },
        // The vault_meta-ordering rationale: a missing version row on an
        // existing vault is an ABI-gate failure (stored: None), NOT a
        // manifest-gate failure, because vault_meta is created/opened first
        // and the ABI gate reads from it.
        GateCase {
            name: "missing_storage_abi_row_is_abi_gate_not_manifest_gate",
            prepare: prep_missing_abi_row,
            open_config: cfg_default,
            expected_kind: ErrorKind::StorageAbiVersionChanged,
        },
        // Gate 2b: storage schema (vault_meta["schema_version"], u16 LE).
        GateCase {
            name: "unknown_storage_schema_version",
            prepare: prep_unknown_schema,
            open_config: cfg_default,
            expected_kind: ErrorKind::StorageSchemaVersionChanged,
        },
        // Gate 3: the 28-name DB manifest set (M1-1).
        GateCase {
            name: "missing_required_manifest_db",
            prepare: prep_missing_manifest_db,
            open_config: cfg_default,
            expected_kind: ErrorKind::DbManifestMismatch,
        },
        GateCase {
            name: "rogue_manifest_db",
            prepare: prep_rogue_manifest_db,
            open_config: cfg_default,
            expected_kind: ErrorKind::DbManifestMismatch,
        },
        // Ordering: ABI gate runs BEFORE the manifest gate.
        GateCase {
            name: "abi_gate_precedes_manifest_gate",
            prepare: prep_stale_abi_and_missing_manifest_db,
            open_config: cfg_default,
            expected_kind: ErrorKind::StorageAbiVersionChanged,
        },
        // Gate 5: HNSW/dimension compatibility (hnsw_meta["hnsw_config"], M1-3).
        GateCase {
            name: "hnsw_dimension_mismatch",
            prepare: create_default_vault,
            open_config: cfg_dimensions_8,
            expected_kind: ErrorKind::HnswConfigChanged,
        },
        GateCase {
            name: "hnsw_distance_metric_and_structure_mismatch",
            prepare: prep_hnsw_metric_structure_flip,
            open_config: cfg_default,
            expected_kind: ErrorKind::HnswConfigChanged,
        },
        GateCase {
            name: "legacy_hnsw_record_on_populated_vault",
            prepare: prep_legacy_hnsw_on_populated,
            open_config: cfg_default,
            expected_kind: ErrorKind::HnswConfigChanged,
        },
        GateCase {
            name: "populated_vault_missing_hnsw_compat_metadata",
            prepare: prep_populated_missing_hnsw_compat,
            open_config: cfg_default,
            expected_kind: ErrorKind::InvalidConfig,
        },
        // Gate 6: embedding-model identity (hnsw_meta["model_id"], M1-2).
        GateCase {
            name: "embedding_model_changed",
            prepare: create_populated_vector_vault,
            open_config: cfg_model_b,
            expected_kind: ErrorKind::EmbeddingModelChanged,
        },
        GateCase {
            name: "populated_vault_missing_model_id",
            prepare: prep_populated_missing_model_id,
            open_config: cfg_default,
            expected_kind: ErrorKind::InvalidConfig,
        },
        GateCase {
            name: "populated_vault_opened_without_model",
            prepare: create_populated_vector_vault,
            open_config: cfg_no_model,
            expected_kind: ErrorKind::InvalidConfig,
        },
        // Ordering: HNSW gate runs BEFORE the model gate.
        GateCase {
            name: "hnsw_gate_precedes_model_gate",
            prepare: create_populated_vector_vault,
            open_config: cfg_dimensions_8_and_model_b,
            expected_kind: ErrorKind::HnswConfigChanged,
        },
        // Gate 8: analyzer / BM25F handshake (vault_meta text-index keys,
        // ARCH-0031 state table: lang-flip → IncompatibleAnalyzer,
        // field-schema → Bm25FieldSchemaChanged).
        GateCase {
            name: "analyzer_manifest_hash_changed",
            prepare: prep_analyzer_hash_flip,
            open_config: cfg_default,
            expected_kind: ErrorKind::IncompatibleAnalyzer,
        },
        GateCase {
            name: "bm25_field_schema_changed",
            prepare: prep_bm25_field_schema_flip,
            open_config: cfg_default,
            expected_kind: ErrorKind::Bm25FieldSchemaChanged,
        },
        // Ordering: the model gate (Store::open) runs BEFORE the analyzer
        // handshake (Vault::open).
        GateCase {
            name: "model_gate_precedes_analyzer_gate",
            prepare: prep_text_and_vector_with_analyzer_flip,
            open_config: cfg_model_b,
            expected_kind: ErrorKind::EmbeddingModelChanged,
        },
    ];

    for case in &cases {
        let temp_dir = tempfile::tempdir()?;
        let path = temp_dir.path();
        (case.prepare)(path)
            .unwrap_or_else(|e| panic!("case {}: prepare failed: {e:?}", case.name));

        let err = match Vault::open(path, (case.open_config)()) {
            Ok(_) => panic!(
                "case {}: expected Vault::open to fail closed with {:?}",
                case.name, case.expected_kind
            ),
            Err(err) => err,
        };
        assert_eq!(
            err.kind(),
            case.expected_kind,
            "case {}: wrong gate fired: {err:?}",
            case.name
        );

        // Fail-closed also means no partial state survives the rejected
        // open: a second attempt must hit the SAME gate. A leaked path
        // registration would yield VaultRootPreflight(DuplicateOpenRoot)
        // instead; partially-initialized vault state would change which gate
        // fires.
        let second = match Vault::open(path, (case.open_config)()) {
            Ok(_) => panic!(
                "case {}: second open must fail closed identically",
                case.name
            ),
            Err(err) => err,
        };
        assert_eq!(
            second.kind(),
            case.expected_kind,
            "case {}: second open hit a different gate (partial state or \
             leaked path registration?): {second:?}",
            case.name
        );
        // Assert the re-open re-hit the GATE, not a leaked registration.
        assert!(
            !matches!(
                second,
                Error::Store(StoreError::VaultRootPreflight {
                    problem: VaultRootProblem::DuplicateOpenRoot { .. },
                    ..
                })
            ),
            "case {}: second open leaked a path registration instead of \
             re-hitting the gate: {second:?}",
            case.name
        );
    }

    Ok(())
}
