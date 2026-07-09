use core::assert_matches;
use std::path::PathBuf;

use super::*;
use crate::config::{HnswConfig, TextAnalyzerConfig, VaultConfig};
use crate::registry::{ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_TASK, ENTITY_TYPE_TASK_LIST};
use crate::store::{
    TEXT_ANALYZER_MANIFEST_HASH_KEY, TEXT_ANALYZER_MANIFEST_KEY, TEXT_BM25_FIELD_SCHEMA_HASH_KEY,
    TEXT_INDEX_SCHEMA_VERSION_KEY,
};
use crate::temporal::TimeRange;

fn test_config() -> VaultConfig {
    VaultConfig {
        map_size: 32 * 1024 * 1024,
        dimensions: 4,
        embedding_model: Some("test-model-v1".to_owned()),
        max_readers: 16,
        hnsw: HnswConfig {
            m_max_0: 64,
            ef_construction: 200,
            ef_search: 128,
        },
        text_analyzer: TextAnalyzerConfig::default(),
        dict_search_paths: Vec::<PathBuf>::new(),
        skip_text_index_manifest_check: false,
    }
}

fn entity(byte: u8) -> EntityId {
    EntityId::from_bytes_unchecked([byte; ENTITY_ID_LEN])
}

fn range(start: u64, end: u64) -> TimeRange {
    TimeRange { start, end }
}

fn resolve_policy_manifest(vault: &Vault) -> Result<crate::gate::PolicyManifestResolution> {
    let rtxn = vault.store.env.read_txn()?;
    crate::gate::resolve_policy_manifest(&vault.store, &rtxn)
}

fn remove_default_policy_manifest(vault: &Vault) -> Result<()> {
    let id = crate::gate::default_policy_manifest_id()?;
    vault.with_write_txn(|wtxn| {
        crate::batch::deindex_entity_for_test(&vault.store, wtxn, &id)?;
        Ok(())
    })
}

#[test]
fn public_deletes_reject_fresh_default_policy_manifest() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let vault = Vault::open(tmp.path(), test_config())?;
    let id = crate::gate::default_policy_manifest_id()?;

    let err = vault
        .delete_entity(&id)
        .expect_err("public hard delete must reject the default policy manifest");
    assert_matches!(
        err,
        Error::MaintenanceKindNotWritable(ENTITY_TYPE_POLICY_MANIFEST)
    );
    assert!(vault.get_raw(&id)?.is_some());

    let err = vault
        .batch()
        .delete(&id)
        .commit()
        .expect_err("batch delete must reject the default policy manifest");
    assert_matches!(
        err,
        Error::MaintenanceKindNotWritable(ENTITY_TYPE_POLICY_MANIFEST)
    );
    assert!(vault.get_raw(&id)?.is_some());
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn sync_replayed_tombstone_noops_for_delete_protected_engine_record() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let vault = Vault::open(tmp.path(), test_config())?;
    let id = crate::gate::default_policy_manifest_id()?;

    let outcome = vault.apply_replayed_tombstone_for_sync(&id, b"malformed-hard-tombstone")?;
    assert_eq!(
        outcome,
        ReplayedTombstoneOutcome::HardPurged {
            erased: false,
            receipt_id: None,
            sweep_key: None,
        }
    );
    assert!(vault.get_raw(&id)?.is_some());
    Ok(())
}

#[test]
fn count_entities_by_type_uses_type_index_prefix_counts() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let vault = Vault::open(tmp.path(), test_config())?;
    let task_list_a = entity(0x11);
    let task_list_b = entity(0x12);
    let task = entity(0x13);

    vault
        .batch()
        .put(
            &task_list_a,
            ENTITY_TYPE_TASK_LIST,
            range(1, 1),
            2,
            b"list-a",
        )
        .put(
            &task_list_b,
            ENTITY_TYPE_TASK_LIST,
            range(3, 3),
            4,
            b"list-b",
        )
        .put(
            &task,
            ENTITY_TYPE_TASK,
            range(5, 5),
            6,
            &crate::types::task_body_for_test(crate::types::TaskRole::Task),
        )
        .commit()?;

    assert_eq!(vault.count_entities_by_type(ENTITY_TYPE_TASK_LIST)?, 2);
    assert_eq!(vault.count_entities_by_type(ENTITY_TYPE_TASK)?, 1);
    assert_eq!(
        vault.count_entities_by_type(crate::registry::ENTITY_TYPE_MACHINE)?,
        0
    );
    Ok(())
}

#[test]
fn count_entities_by_type_rejects_corrupted_type_index_key() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let vault = Vault::open(tmp.path(), test_config())?;

    vault.with_write_txn(|wtxn| {
        vault
            .store
            .type_index
            .put(wtxn, &[ENTITY_TYPE_TASK_LIST, 0xaa], &[])?;
        Ok(())
    })?;

    let err = vault
        .count_entities_by_type(ENTITY_TYPE_TASK_LIST)
        .expect_err("short type index key should fail loud");
    assert_matches!(err, Error::CorruptedIndex("type index key"));
    Ok(())
}

#[test]
fn latest_learned_at_uses_temporal_index_tail() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let vault = Vault::open(tmp.path(), test_config())?;

    assert_eq!(
        vault.latest_learned_at()?,
        Some(crate::gate::DEFAULT_POLICY_MANIFEST_TIMESTAMP)
    );

    vault
        .batch()
        .put(
            &entity(0x21),
            ENTITY_TYPE_TASK,
            range(1, 1),
            10,
            &crate::types::task_body_for_test(crate::types::TaskRole::Task),
        )
        .put(
            &entity(0x22),
            ENTITY_TYPE_TASK,
            range(2, 2),
            30,
            &crate::types::task_body_for_test(crate::types::TaskRole::Task),
        )
        .put(
            &entity(0x23),
            ENTITY_TYPE_TASK,
            range(3, 3),
            20,
            &crate::types::task_body_for_test(crate::types::TaskRole::Task),
        )
        .commit()?;

    assert_eq!(vault.latest_learned_at()?, Some(30));
    Ok(())
}

#[test]
fn latest_learned_at_excluding_entity_types_skips_policy_manifest() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let vault = Vault::open(tmp.path(), test_config())?;

    assert_eq!(
        vault.latest_learned_at_excluding_entity_types(&[ENTITY_TYPE_POLICY_MANIFEST])?,
        None
    );

    vault
        .batch()
        .put(
            &entity(0x21),
            ENTITY_TYPE_TASK,
            range(1, 1),
            10,
            &crate::types::task_body_for_test(crate::types::TaskRole::Task),
        )
        .commit()?;

    assert_eq!(
        vault.latest_learned_at_excluding_entity_types(&[ENTITY_TYPE_POLICY_MANIFEST])?,
        Some(10)
    );
    assert_eq!(
        vault.latest_learned_at_excluding_entity_types(&[
            ENTITY_TYPE_POLICY_MANIFEST,
            ENTITY_TYPE_TASK
        ])?,
        None
    );
    Ok(())
}

#[test]
fn latest_learned_at_rejects_corrupted_temporal_key() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let vault = Vault::open(tmp.path(), test_config())?;

    vault.with_write_txn(|wtxn| {
        vault.store.temporal_learned.put(wtxn, &[0xff], &[])?;
        Ok(())
    })?;

    let err = vault
        .latest_learned_at()
        .expect_err("short temporal learned key should fail loud");
    assert_matches!(err, Error::CorruptedIndex("temporal learned key"));
    Ok(())
}

#[test]
fn new_empty_vault_writes_manifest_keys() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let vault = Vault::open(tmp.path(), test_config())?;

    let status = vault.text_index_status()?;
    assert_eq!(status.total_docs, 0);
    assert_eq!(status.schema_version, Some(2));
    assert!(!status.analyzer_manifest.channels.is_empty());

    let rtxn = vault.store.env.read_txn()?;
    for key in [
        TEXT_INDEX_SCHEMA_VERSION_KEY,
        TEXT_ANALYZER_MANIFEST_KEY,
        TEXT_ANALYZER_MANIFEST_HASH_KEY,
        TEXT_BM25_FIELD_SCHEMA_HASH_KEY,
    ] {
        assert!(
            vault.store.vault_meta.get(&rtxn, key)?.is_some(),
            "missing handshake key {:?}",
            std::str::from_utf8(key).unwrap(),
        );
    }
    Ok(())
}

#[test]
fn fresh_vault_resolves_default_policy_manifest() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let vault = Vault::open(tmp.path(), test_config())?;

    let policy = resolve_policy_manifest(&vault)?;
    let first_party_eiri_actor_ref = crate::gate::first_party_eiri_connector_actor_ref();

    assert_eq!(policy.diagnostics().manifest_count, 1);
    assert!(policy.enforces_write_gate());
    assert_eq!(
        policy.actor_ceiling("agent", Some(&first_party_eiri_actor_ref)),
        crate::gate::PolicyApprovalCeiling::Auto
    );
    assert_eq!(policy.signatures().len(), 1);
    assert_ne!(policy.read_frontier_hash()?, [0; 32]);
    Ok(())
}

#[test]
fn existing_vault_without_policy_manifest_is_not_backfilled() -> Result<()> {
    let tmp = tempfile::tempdir()?;

    {
        let vault = Vault::open(tmp.path(), test_config())?;
        remove_default_policy_manifest(&vault)?;

        let policy = resolve_policy_manifest(&vault)?;
        assert_eq!(policy.diagnostics().manifest_count, 0);
        assert!(!policy.enforces_write_gate());
    }

    let vault = Vault::open(tmp.path(), test_config())?;
    let policy = resolve_policy_manifest(&vault)?;
    assert_eq!(policy.diagnostics().manifest_count, 0);
    assert!(!policy.enforces_write_gate());
    Ok(())
}

#[test]
fn bypass_on_empty_persists_manifest_for_normal_reopen() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a = entity(10);

    {
        let mut cfg = test_config();
        cfg.skip_text_index_manifest_check = true;
        let vault = Vault::open(tmp.path(), cfg)?;
        vault
            .batch()
            .put(&a, 1, range(1, 1), 1, b"a")
            .text(&a, &[("body", "hello world")])
            .commit()?;
    }

    let vault = Vault::open(tmp.path(), test_config())?;
    assert_eq!(vault.search_text("hello", 10)?.len(), 1);
    Ok(())
}

#[test]
fn reopen_same_manifest_preserves_text_index() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a = entity(11);

    {
        let vault = Vault::open(tmp.path(), test_config())?;
        vault
            .batch()
            .put(&a, 1, range(1, 1), 1, b"a")
            .text(&a, &[("body", "hello world")])
            .commit()?;
        assert_eq!(vault.search_text("hello", 10)?.len(), 1);
    }

    let vault = Vault::open(tmp.path(), test_config())?;
    assert_eq!(vault.search_text("hello", 10)?.len(), 1);
    Ok(())
}

/// `Vault::open` runs the handshake. Each variant corrupts a different
/// `vault_meta` row on a populated vault and asserts the expected
/// handshake error.
///
/// Variants:
/// - `reopen_missing_manifest_on_populated_vault`:
///   `delete(TEXT_ANALYZER_MANIFEST_HASH_KEY)` simulates pre-ONE-317
///   populated vault. Expects `IncompatibleAnalyzer`.
/// - `field_schema_hash_mismatch`:
///   `put(TEXT_BM25_FIELD_SCHEMA_HASH_KEY, &[0xEE; 32])` simulates
///   `Bm25Config` field schema flip. Expects `Bm25FieldSchemaChanged`.
/// - `analyzer_manifest_hash_mismatch`:
///   `put(TEXT_ANALYZER_MANIFEST_HASH_KEY, &[0xCC; 32])` simulates a
///   dict mode flip. Expects `IncompatibleAnalyzer`.
/// - `truncated_stored_hash`:
///   `put(TEXT_ANALYZER_MANIFEST_HASH_KEY, &[0xCC; 16])` — half-length
///   payload should fail closed, not be silently rehashed. Expects
///   `CorruptedIndex`.
#[test]
fn handshake_rejects_corrupted_manifest() -> Result<()> {
    enum Corrupt {
        Delete(&'static [u8]),
        Put(&'static [u8], Vec<u8>),
    }
    enum Expect {
        IncompatibleAnalyzer,
        Bm25FieldSchemaChanged,
        CorruptedIndex,
    }

    let cases: Vec<(&str, u8, Corrupt, Expect)> = vec![
        (
            "reopen_missing_manifest_on_populated_vault",
            21,
            Corrupt::Delete(TEXT_ANALYZER_MANIFEST_HASH_KEY),
            Expect::IncompatibleAnalyzer,
        ),
        (
            "field_schema_hash_mismatch",
            31,
            Corrupt::Put(TEXT_BM25_FIELD_SCHEMA_HASH_KEY, vec![0xEE; 32]),
            Expect::Bm25FieldSchemaChanged,
        ),
        (
            "analyzer_manifest_hash_mismatch",
            41,
            Corrupt::Put(TEXT_ANALYZER_MANIFEST_HASH_KEY, vec![0xCC; 32]),
            Expect::IncompatibleAnalyzer,
        ),
        (
            "truncated_stored_hash",
            51,
            Corrupt::Put(TEXT_ANALYZER_MANIFEST_HASH_KEY, vec![0xCC; 16]),
            Expect::CorruptedIndex,
        ),
    ];

    for (case_name, byte, corrupt, expect) in cases {
        let tmp = tempfile::tempdir()?;
        let a = entity(byte);

        {
            let vault = Vault::open(tmp.path(), test_config())?;
            vault
                .batch()
                .put(&a, 1, range(1, 1), 1, b"a")
                .text(&a, &[("body", "hello world")])
                .commit()?;
        }

        {
            let vault = Vault::open(tmp.path(), test_config())?;
            let mut wtxn = vault.store.env.write_txn()?;
            match &corrupt {
                Corrupt::Delete(key) => {
                    vault.store.vault_meta.delete(&mut wtxn, key)?;
                }
                Corrupt::Put(key, value) => {
                    vault.store.vault_meta.put(&mut wtxn, key, value)?;
                }
            }
            wtxn.commit()?;
        }

        let err = match Vault::open(tmp.path(), test_config()) {
            Ok(_) => panic!("case {case_name}: expected Vault::open to fail"),
            Err(e) => e,
        };
        let ok = match expect {
            Expect::IncompatibleAnalyzer => {
                matches!(err, Error::IncompatibleAnalyzer { .. })
            }
            Expect::Bm25FieldSchemaChanged => matches!(err, Error::Bm25FieldSchemaChanged),
            Expect::CorruptedIndex => matches!(err, Error::CorruptedIndex(_)),
        };
        assert!(ok, "case {case_name}: unexpected error {err:?}");
    }
    Ok(())
}

#[test]
fn bm25_field_schema_hash_binds_on_disk_semantics() {
    let records = bm25_field_schema_records(
        &bm25::Bm25Config::default(),
        bm25::POSTINGS_VALUE_FORMAT_VERSION,
    );
    let baseline = bm25_field_schema_hash_for_records(&records);

    let mut changed = records.clone();
    changed[0].field_id = changed[0].field_id.saturating_add(1);
    assert_ne!(baseline, bm25_field_schema_hash_for_records(&changed));

    let mut changed = records.clone();
    changed[0].channel_name = "renamed_surface";
    assert_ne!(baseline, bm25_field_schema_hash_for_records(&changed));

    let mut changed = records.clone();
    changed[0].length_policy = bm25::FieldLengthPolicy::NoNorm;
    assert_ne!(baseline, bm25_field_schema_hash_for_records(&changed));

    let mut changed = records.clone();
    changed[0].permits_zero_doc_field_length = !changed[0].permits_zero_doc_field_length;
    assert_ne!(baseline, bm25_field_schema_hash_for_records(&changed));

    let mut changed = records;
    changed[0].postings_value_format_version += 1;
    assert_ne!(baseline, bm25_field_schema_hash_for_records(&changed));
}

#[test]
fn bm25_field_schema_hash_ignores_scoring_knobs() {
    let default = bm25::Bm25Config::default();
    let mut fields = default.fields;
    fields[AnalyzerChannel::Surface.field_id() as usize].weight = 9.0;
    fields[AnalyzerChannel::Surface.field_id() as usize].b = 0.1;
    let scoring = bm25::Bm25Config {
        k1: 2.0,
        formula: bm25::Bm25Formula::Plus { delta: 0.5 },
        fields,
    };

    assert_eq!(
        bm25_field_schema_hash_for_records(&bm25_field_schema_records(
            &default,
            bm25::POSTINGS_VALUE_FORMAT_VERSION,
        )),
        bm25_field_schema_hash_for_records(&bm25_field_schema_records(
            &scoring,
            bm25::POSTINGS_VALUE_FORMAT_VERSION,
        )),
    );
}

/// AC2 (ONE-1119): the rank profile stays OUT of the on-disk
/// manifest handshake. Querying through both public profile paths
/// with a thoroughly non-default profile must leave every
/// `vault_meta` handshake row byte-identical, and a plain reopen
/// must still pass the handshake — a profile change never requires
/// a reindex (ARCH-0031).
#[test]
fn rank_profile_change_does_not_require_reindex() -> Result<()> {
    use crate::analyzer::AnalyzerChannel;
    use crate::config::Bm25RankProfile;

    const HANDSHAKE_KEYS: [&[u8]; 4] = [
        TEXT_INDEX_SCHEMA_VERSION_KEY,
        TEXT_ANALYZER_MANIFEST_KEY,
        TEXT_ANALYZER_MANIFEST_HASH_KEY,
        TEXT_BM25_FIELD_SCHEMA_HASH_KEY,
    ];

    fn handshake_rows(vault: &Vault) -> Result<Vec<Option<Vec<u8>>>> {
        let rtxn = vault.store.env.read_txn()?;
        let mut rows = Vec::with_capacity(HANDSHAKE_KEYS.len());
        for key in HANDSHAKE_KEYS {
            rows.push(vault.store.vault_meta.get(&rtxn, key)?.map(<[u8]>::to_vec));
        }
        Ok(rows)
    }

    let tmp = tempfile::tempdir()?;
    let a = entity(81);

    let vault = Vault::open(tmp.path(), test_config())?;
    vault
        .batch()
        .put(&a, 1, range(1, 1), 1, b"a")
        .text(&a, &[("body", "hello world")])
        .commit()?;

    let before = handshake_rows(&vault)?;
    assert!(
        before.iter().all(Option::is_some),
        "handshake rows must exist after first index write",
    );

    let profile = Bm25RankProfile::default()
        .with_formula(bm25::Bm25Formula::Plus { delta: 1.0 })
        .with_channel_weight(AnalyzerChannel::Stem, 0.0)
        .with_channel_b(AnalyzerChannel::Surface, 0.2);

    let hits = vault.search_text_with_profile("hello", 10, &profile)?;
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, a);

    let hits = vault
        .query()
        .search_text("hello", 10)
        .rank_profile(profile)
        .run()?;
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, a);

    let after = handshake_rows(&vault)?;
    assert_eq!(
        before, after,
        "rank profile must never touch the vault_meta handshake rows",
    );
    drop(vault);

    // Plain reopen passes the handshake — no clear_text_index, no
    // reindex, and the default profile still finds the doc.
    let vault = Vault::open(tmp.path(), test_config())?;
    assert_eq!(vault.search_text("hello", 10)?.len(), 1);
    Ok(())
}

// `analyzer_manifest_hash_mismatch` and `handshake_rejects_truncated_stored_hash`
// are folded into `handshake_rejects_corrupted_manifest` above.

#[test]
fn skip_manifest_check_unblocks_clear_text_index_recovery() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a = entity(61);

    {
        let vault = Vault::open(tmp.path(), test_config())?;
        vault
            .batch()
            .put(&a, 1, range(1, 1), 1, b"a")
            .text(&a, &[("body", "hello world")])
            .commit()?;
    }

    // Corrupt the analyzer manifest hash so a normal open fails closed.
    {
        let vault = Vault::open(tmp.path(), test_config())?;
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .vault_meta
            .put(&mut wtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY, &[0xAB; 32])?;
        wtxn.commit()?;
    }

    let Err(err) = Vault::open(tmp.path(), test_config()) else {
        panic!("expected incompatible analyzer rejection");
    };
    assert_matches!(err, Error::IncompatibleAnalyzer { .. });

    // Bypass the handshake just long enough to rebuild.
    {
        let mut cfg = test_config();
        cfg.skip_text_index_manifest_check = true;
        let vault = Vault::open(tmp.path(), cfg)?;
        vault.maintain().clear_text_index().run()?;
    }

    // Normal open now succeeds — clear_text_index rewrote the manifest.
    let vault = Vault::open(tmp.path(), test_config())?;
    assert_eq!(vault.text_index_status()?.total_docs, 0);
    Ok(())
}

#[test]
fn search_text_fails_closed_when_handshake_bypassed_on_populated_index() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a = entity(71);

    {
        let vault = Vault::open(tmp.path(), test_config())?;
        vault
            .batch()
            .put(&a, 1, range(1, 1), 1, b"a")
            .text(&a, &[("body", "hello world")])
            .commit()?;
    }

    // Open with the bypass set — the index has rows but the handshake
    // didn't run. `search_text` would otherwise score against postings
    // that may have been written under a different analyzer manifest.
    let mut cfg = test_config();
    cfg.skip_text_index_manifest_check = true;
    let vault = Vault::open(tmp.path(), cfg)?;
    let err = vault
        .search_text("hello", 10)
        .expect_err("search_text must refuse on bypassed-and-populated state");
    assert!(
        matches!(err, Error::CorruptedIndex(_)),
        "expected CorruptedIndex, got {err:?}",
    );

    // After clear_text_index, trust is restored within the same vault.
    vault.maintain().clear_text_index().run()?;
    assert!(vault.search_text("hello", 10).is_ok());
    Ok(())
}

#[test]
fn text_write_fails_closed_when_trust_bypassed() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a = entity(73);
    let b = entity(74);

    {
        let vault = Vault::open(tmp.path(), test_config())?;
        vault
            .batch()
            .put(&a, 1, range(1, 1), 1, b"a")
            .text(&a, &[("body", "hello world")])
            .commit()?;
    }

    let mut cfg = test_config();
    cfg.skip_text_index_manifest_check = true;
    let vault = Vault::open(tmp.path(), cfg)?;
    let err = vault
        .batch()
        .put(&b, 1, range(1, 1), 1, b"b")
        .text(&b, &[("body", "new text")])
        .commit()
        .expect_err("text write must refuse bypassed populated index");
    assert!(
        matches!(err, Error::CorruptedIndex(_)),
        "expected CorruptedIndex, got {err:?}",
    );
    Ok(())
}

#[test]
fn text_write_fails_closed_when_stored_manifest_diverged() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a = entity(75);
    let b = entity(76);
    let vault = Vault::open(tmp.path(), test_config())?;
    vault
        .batch()
        .put(&a, 1, range(1, 1), 1, b"a")
        .text(&a, &[("body", "hello world")])
        .commit()?;

    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .vault_meta
            .put(&mut wtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY, &[0xCC; 32])?;
        wtxn.commit()?;
    }

    let err = vault
        .batch()
        .put(&b, 1, range(1, 1), 1, b"b")
        .text(&b, &[("body", "new text")])
        .commit()
        .expect_err("text write must refuse manifest divergence");
    assert!(
        matches!(err, Error::IncompatibleAnalyzer { .. }),
        "expected IncompatibleAnalyzer, got {err:?}",
    );
    Ok(())
}

#[test]
fn manifest_write_fails_closed_if_index_populated_during_writer() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let vault = Vault::open(tmp.path(), test_config())?;
    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .text_postings
        .put(&mut wtxn, b"residual", b"x")?;

    let err = write_text_index_manifest_if_empty(&vault.store, &mut wtxn, &vault.analyzer)
        .expect_err("manifest write must re-check emptiness in writer");
    assert!(
        matches!(err, Error::CorruptedIndex(_)),
        "expected CorruptedIndex, got {err:?}",
    );
    Ok(())
}

#[test]
fn handshake_rejects_residual_rows_with_missing_total_docs_sentinel() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a = entity(72);

    {
        let vault = Vault::open(tmp.path(), test_config())?;
        vault
            .batch()
            .put(&a, 1, range(1, 1), 1, b"a")
            .text(&a, &[("body", "alpha")])
            .commit()?;

        // Wipe the `total_docs` sentinel out of `text_meta` while
        // leaving `text_postings` / `text_forward` /
        // `text_doc_field_lengths` / `text_bm25_field_stats` populated.
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.text_meta.clear(&mut wtxn)?;
        wtxn.commit()?;
    }

    let err = match Vault::open(tmp.path(), test_config()) {
        Ok(_) => panic!("expected Vault::open to fail closed"),
        Err(e) => e,
    };
    assert!(
        matches!(err, Error::CorruptedIndex(_)),
        "expected CorruptedIndex, got {err:?}",
    );
    Ok(())
}

#[test]
fn text_index_status_reflects_indexed_docs() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let vault = Vault::open(tmp.path(), test_config())?;
    let a = entity(51);
    let b = entity(52);

    vault
        .batch()
        .put(&a, 1, range(1, 1), 1, b"a")
        .put(&b, 1, range(1, 1), 1, b"b")
        .text(&a, &[("body", "first")])
        .text(&b, &[("body", "second")])
        .commit()?;

    assert_eq!(vault.text_index_status()?.total_docs, 2);
    Ok(())
}
