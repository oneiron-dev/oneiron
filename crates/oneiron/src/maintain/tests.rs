use core::assert_matches;

use super::*;
use crate::attempt_queue::{
    AttemptQueue, AttemptQueueRetryReason, ClaimAttempt, ClaimOutcome, EnqueueAttempt,
    EnqueueOutcome,
};
use crate::config::{HnswConfig, VaultConfig};
use crate::edge::EdgeKind;
use crate::store::{
    GRAPH_VERSION_KEY, MODEL_ID_KEY, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY, VECTOR_VERSION_KEY,
};
use crate::temporal::TimeRange;

fn test_config() -> VaultConfig {
    VaultConfig {
        failure_signals: Default::default(),
        store_clock: crate::ports::StoreClock::default(),
        ppr_vad_alpha: crate::config::PPR_VAD_ALPHA_DEFAULT,
        ppr_community: crate::config::PprCommunityConfig::default(),
        retrieval_telemetry_capture: false,
        map_size: 32 * 1024 * 1024,
        dimensions: 4,
        fast_dims: None,
        embedding_model: Some("test/model@v1".to_owned()),
        embedding_transform: None,
        tagging: None,
        max_readers: 16,
        hnsw: HnswConfig {
            m_max_0: 64,
            ef_construction: 200,
            ef_search: 128,
        },
        text_analyzer: crate::config::TextAnalyzerConfig::default(),
        dict_search_paths: Vec::new(),
        assistant_display_names: Vec::new(),
        skip_text_index_manifest_check: false,
        off_record_enabled: true,
        off_record_overlay_budget_bytes: crate::config::DEFAULT_OFF_RECORD_OVERLAY_BUDGET_BYTES,
        privacy: crate::config::VaultPrivacyConfig::default(),
    }
}

fn test_time_range(start: u64, end: u64) -> TimeRange {
    TimeRange { start, end }
}

use crate::test_util::entity;

fn read_u64_meta(vault: &Vault, key: &[u8]) -> Result<u64> {
    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .hnsw_meta
        .get(&rtxn, key)?
        .ok_or(Error::EntityNotFound)?;
    let value = u64::from_le_bytes(raw.as_ref().try_into().map_err(|_| Error::InvalidKey)?);
    Ok(value)
}

fn count_entries(db: &crate::overlay_db::OverlayDb, vault: &Vault) -> Result<usize> {
    let rtxn = vault.store.env.read_txn()?;
    let mut count = 0;
    for entry in db.iter(&rtxn)? {
        entry?;
        count += 1;
    }
    Ok(count)
}

fn read_neighbor_bytes(vault: &Vault, id: &EntityId) -> Result<Vec<u8>> {
    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .hnsw_neighbors
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    Ok(raw.to_vec())
}

/// `rebuild_hnsw` must not touch unrelated `hnsw_meta` rows. Each variant
/// seeds a different key and confirms its value survives the rebuild.
///
/// Variants:
/// - `graph_version`: `GRAPH_VERSION_KEY` is bumped by edge writes, then
///   the rebuild's `u64` value must match the pre-rebuild snapshot.
/// - `long_interval_schema_version`: raw bytes at
///   `TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY` must match.
/// - `model_id_when_config_matches`: closing the vault and reopening with
///   the same `embedding_model` must leave `MODEL_ID_KEY` untouched
///   (still `"test/model@v1"`).
/// - `unrelated_hnsw_meta`: a custom key `b"custom-meta" -> b"keep-me"`
///   must not be scrubbed.
#[test]
fn rebuild_hnsw_preserves_unrelated_meta() -> Result<()> {
    // graph_version
    {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(80);
        let b = entity(81);

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        let before = read_u64_meta(&vault, GRAPH_VERSION_KEY)?;

        let report = vault.maintain().rebuild_hnsw().run()?;
        assert_eq!(
            report.hnsw_dead_nodes_removed, 0,
            "case graph_version: unexpected dead nodes removed"
        );

        let after = read_u64_meta(&vault, GRAPH_VERSION_KEY)?;
        assert_eq!(
            before, after,
            "case graph_version: GRAPH_VERSION_KEY changed by rebuild"
        );
    }

    // long_interval_schema_version
    {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let before = {
            let rtxn = vault.store.env.read_txn()?;
            vault
                .store
                .hnsw_meta
                .get(&rtxn, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY)?
                .ok_or(Error::EntityNotFound)?
                .to_vec()
        };

        vault.maintain().rebuild_hnsw().run()?;

        let after = {
            let rtxn = vault.store.env.read_txn()?;
            vault
                .store
                .hnsw_meta
                .get(&rtxn, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY)?
                .ok_or(Error::EntityNotFound)?
                .to_vec()
        };
        assert_eq!(
            before, after,
            "case long_interval_schema_version: schema version changed"
        );
    }

    // model_id_when_config_matches
    {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let id = entity(84);
        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
        vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;
        drop(vault);

        let vault = Vault::open(temp_dir.path(), test_config())?;

        vault.maintain().rebuild_hnsw().run()?;

        let rtxn = vault.store.env.read_txn()?;
        let stored = vault.store.hnsw_meta.get(&rtxn, MODEL_ID_KEY)?;
        assert_eq!(
            stored.as_deref(),
            Some(b"test/model@v1".as_slice()),
            "case model_id_when_config_matches: MODEL_ID_KEY changed"
        );
    }

    // unrelated_hnsw_meta
    {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let id = entity(85);

        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
        vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

        {
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .hnsw_meta
                .put(&mut wtxn, b"custom-meta", b"keep-me")?;
            wtxn.commit()?;
        }

        vault.maintain().rebuild_hnsw().run()?;

        let rtxn = vault.store.env.read_txn()?;
        let custom_meta = vault.store.hnsw_meta.get(&rtxn, b"custom-meta")?;
        assert_eq!(
            custom_meta.as_deref(),
            Some(b"keep-me".as_slice()),
            "case unrelated_hnsw_meta: custom row scrubbed"
        );
    }

    Ok(())
}

#[test]
fn rebuild_hnsw_strict_preserves_committed_graph_on_invalid_vector() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let a = entity(86);
    let b = entity(87);

    for (id, vector) in [(a, [1.0, 0.0, 0.0, 0.0]), (b, [0.0, 1.0, 0.0, 0.0])] {
        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
        vault.put_vector(&id, &vector)?;
    }

    let count_before = read_u64_meta(&vault, COUNT_KEY)?;
    let neighbors_before = read_neighbor_bytes(&vault, &a)?;

    {
        let mut invalid = Vec::new();
        invalid.extend_from_slice(&1.0_f32.to_le_bytes());
        invalid.extend_from_slice(&2.0_f32.to_le_bytes());
        invalid.extend_from_slice(&3.0_f32.to_le_bytes());

        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vectors.put(&mut wtxn, b.as_bytes(), &invalid)?;
        wtxn.commit()?;
    }

    let err = vault.maintain().rebuild_hnsw().run().unwrap_err();
    assert_matches!(err, Error::CorruptedIndex(_));

    let count_after = read_u64_meta(&vault, COUNT_KEY)?;
    let neighbors_after = read_neighbor_bytes(&vault, &a)?;
    assert_eq!(count_before, count_after);
    assert_eq!(neighbors_before, neighbors_after);
    assert_eq!(count_entries(&vault.store.hnsw_neighbors, &vault)?, 2);
    Ok(())
}

#[test]
fn rebuild_hnsw_rejects_stale_vector_snapshot() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let a = entity(94);
    let b = entity(95);

    for (id, vector) in [(a, [1.0, 0.0, 0.0, 0.0]), (b, [0.0, 1.0, 0.0, 0.0])] {
        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
        vault.put_vector(&id, &vector)?;
    }

    let count_before = read_u64_meta(&vault, COUNT_KEY)?;
    let vector_version_before = read_u64_meta(&vault, VECTOR_VERSION_KEY)?;
    let neighbors_before = read_neighbor_bytes(&vault, &a)?;

    let prepared = prepare_rebuild_hnsw(&vault, false)?;
    assert_eq!(prepared.vector_version, vector_version_before);
    assert_eq!(prepared.invalid_vectors_skipped, 0);

    vault.put_vector(&b, &[0.0, 0.5, 0.5, 0.0])?;

    let err = commit_rebuilt_hnsw(&vault, &prepared.rebuilt, prepared.vector_version).unwrap_err();
    assert_matches!(err, Error::ConcurrentWrite(_));

    let count_after = read_u64_meta(&vault, COUNT_KEY)?;
    let vector_version_after = read_u64_meta(&vault, VECTOR_VERSION_KEY)?;
    let neighbors_after = read_neighbor_bytes(&vault, &a)?;
    assert_eq!(count_before, count_after);
    assert_eq!(neighbors_before, neighbors_after);
    assert!(vector_version_after > vector_version_before);
    assert_eq!(count_entries(&vault.store.hnsw_neighbors, &vault)?, 2);
    Ok(())
}

#[test]
fn compact_postings_removes_empty_lists() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;

    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.text_postings.put(&mut wtxn, b"empty-a", &[])?;
        vault.store.text_postings.put(&mut wtxn, b"empty-b", &[])?;
        vault
            .store
            .text_postings
            .put(&mut wtxn, b"keep", &[1, 2, 3])?;
        wtxn.commit()?;
    }

    let report = vault.maintain().compact_postings().run()?;
    assert_eq!(report.postings_compacted, 2);

    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.store.text_postings.get(&rtxn, b"empty-a")?.is_none());
    assert!(vault.store.text_postings.get(&rtxn, b"empty-b")?.is_none());
    assert!(vault.store.text_postings.get(&rtxn, b"keep")?.is_some());
    Ok(())
}

/// ONE-1930 end to end: a presentation-prefix move followed by a content-hash
/// refresh must leave BOTH spellings resolving to the same entity.
///
/// Covers all four kinds the ticket re-keys (CLAIM / PERSON / SKILL / WORLD).
/// The destination spellings are two-letter stand-ins rather than the ticket's
/// `c/p/s/w`: those one-letter forms are blocked twice over on this base — canon
/// (`tests/byte_space_v3_conformance.rs`) still pins `cl/pr/sk/wd`, and `s`
/// collides with `session_overlay.rs`'s room-alias sigil. The machinery under
/// test is identical either way; only the strings differ.
#[test]
fn short_id_aliases_survive_prefix_rekey() -> Result<()> {
    use crate::registry::{
        ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_SKILL, ENTITY_TYPE_WORLD,
    };
    use crate::store::{ShortIdAliasTarget, ShortIdPrefixRekey, short_id_counter_key};

    const REKEY: &[ShortIdPrefixRekey] = &[
        ShortIdPrefixRekey {
            kind: "CLAIM",
            type_byte: ENTITY_TYPE_CLAIM,
            old_prefix: "cl",
            new_prefix: "cm",
        },
        ShortIdPrefixRekey {
            kind: "PERSON",
            type_byte: ENTITY_TYPE_PERSON,
            old_prefix: "pr",
            new_prefix: "pn",
        },
        ShortIdPrefixRekey {
            kind: "SKILL",
            type_byte: ENTITY_TYPE_SKILL,
            old_prefix: "sk",
            new_prefix: "sl",
        },
        ShortIdPrefixRekey {
            kind: "WORLD",
            type_byte: ENTITY_TYPE_WORLD,
            old_prefix: "wd",
            new_prefix: "wr",
        },
    ];

    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open_unseeded_for_test(temp_dir.path(), test_config())?;

    let kinds = [
        (ENTITY_TYPE_CLAIM, entity(0x51), "cl1", "cm1"),
        (ENTITY_TYPE_PERSON, entity(0x52), "pr1", "pn1"),
        (ENTITY_TYPE_SKILL, entity(0x53), "sk1", "sl1"),
        (ENTITY_TYPE_WORLD, entity(0x54), "wd1", "wr1"),
    ];
    // Every kind rides the replay door, which skips the admission gate but
    // still enforces each kind's body schema — so CLAIM and SKILL get real
    // bodies while PERSON and WORLD store opaque bytes.
    for (type_byte, id, legacy, _) in kinds {
        let body = match type_byte {
            ENTITY_TYPE_CLAIM => crate::claim::encode_claim_body(&crate::claim::ClaimBody::new(
                "dream.symbol",
                crate::claim::ClaimSubject::Entity(entity(0x55)),
                rmpv::Value::from(legacy),
                0.9,
                crate::claim::ClaimApprovalStatus::Approved,
                crate::claim::ClaimLifecycleStatus::Active,
            )?)?,
            ENTITY_TYPE_SKILL => {
                crate::skill::encode_skill_record(&crate::skill::SkillRecord::new(
                    "oneiron.skill.rekey",
                    "Prefix re-key fixture",
                    "1.0.0",
                    crate::claim::ClaimApprovalStatus::Approved,
                    crate::skill::SkillLifecycle::Candidate,
                    crate::claim::ClaimSource::UserStated,
                    1.0,
                    false,
                    true,
                    Vec::new(),
                    rmpv::Value::Map(vec![(
                        rmpv::Value::from("source"),
                        rmpv::Value::from("fixture"),
                    )]),
                ))?
            }
            _ => format!("body-for-{legacy}").into_bytes(),
        };
        vault
            .batch()
            .put_replicated(&id, type_byte, test_time_range(100, 100), 101, &body)
            .commit()?;
    }

    // Counters are recorded BEFORE the move: this pass renames, it never
    // re-numbers, so every `sid_counter:<type_byte>` must come back untouched.
    let counters_before: Vec<Option<Vec<u8>>> = {
        let rtxn = vault.store.env.read_txn()?;
        kinds
            .iter()
            .map(|(type_byte, ..)| {
                vault
                    .store
                    .vault_meta
                    .get(&rtxn, &short_id_counter_key(*type_byte))
                    .map(|raw| raw.map(|bytes| bytes.to_vec()))
            })
            .collect::<Result<_>>()?
    };

    let hashes_before: Vec<u8> = {
        let rtxn = vault.store.env.read_txn()?;
        kinds
            .iter()
            .map(|(_, id, legacy, _)| {
                let value = vault
                    .store
                    .short_ids_reverse
                    .get(&rtxn, id.as_bytes())?
                    .ok_or(Error::EntityNotFound)?;
                let (short_id, hash) = parse_short_id_value(&value)?;
                assert_eq!(short_id, *legacy, "pre-move spelling");
                Ok(hash)
            })
            .collect::<Result<_>>()?
    };

    let moved = {
        let mut wtxn = vault.store.env.write_txn()?;
        let moved = vault.store.rekey_short_ids_v1(&mut wtxn, REKEY)?;
        wtxn.commit()?;
        moved
    };
    assert_eq!(moved, 4, "one move per kind");

    // Re-running is a no-op: the legacy prefixes are gone from the reverse
    // rows, so nothing matches the map a second time.
    {
        let mut wtxn = vault.store.env.write_txn()?;
        assert_eq!(vault.store.rekey_short_ids_v1(&mut wtxn, REKEY)?, 0);
        wtxn.commit()?;
    }

    {
        let rtxn = vault.store.env.read_txn()?;
        for ((type_byte, id, legacy, canonical), (hash, counter_before)) in kinds
            .iter()
            .zip(hashes_before.iter().zip(counters_before.iter()))
        {
            // The reverse row now names the canonical spelling, with the
            // decimal counter and content-hash byte carried across verbatim.
            let value = vault
                .store
                .short_ids_reverse
                .get(&rtxn, id.as_bytes())?
                .ok_or(Error::EntityNotFound)?;
            let (short_id, moved_hash) = parse_short_id_value(&value)?;
            assert_eq!(short_id, *canonical, "post-move spelling");
            assert_eq!(moved_hash, *hash, "content hash must survive the move");

            // Both forward rows resolve: the new canonical one AND the retained
            // legacy one that already-published references still use.
            for spelling in [*legacy, *canonical] {
                let key = encode_short_id_forward_key(spelling, *hash);
                assert_eq!(
                    vault.store.short_ids.get(&rtxn, &key)?.as_deref(),
                    Some(id.as_bytes().as_slice()),
                    "{spelling} forward row"
                );
            }

            // The alias records the one hop from the retired id to the new row.
            assert_eq!(
                vault.store.resolve_short_id_alias(&rtxn, legacy)?,
                Some(ShortIdAliasTarget::EntityForwardKey(
                    encode_short_id_forward_key(canonical, *hash)
                )),
                "{legacy} alias"
            );

            assert_eq!(
                vault
                    .store
                    .vault_meta
                    .get(&rtxn, &short_id_counter_key(*type_byte))?
                    .map(|bytes| bytes.to_vec()),
                *counter_before,
                "sid_counter for type {type_byte} must not move"
            );
        }
    }

    // ─── now drift one entity's content hash and run maintenance ───
    // PERSON, whose body is opaque bytes, so the raw rewrite below cannot
    // smuggle a malformed CLAIM record into the store.
    let (_, drifted_id, drifted_legacy, drifted_canonical) = kinds[1];
    let old_hash = hashes_before[1];
    let mut new_payload = b"drifted-payload".to_vec();
    while ((xxh32(&new_payload, 0) % 256) as u8) == old_hash {
        new_payload.push(0);
    }
    {
        let mut wtxn = vault.store.env.write_txn()?;
        let record = vault
            .store
            .entities
            .get(&wtxn, drifted_id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let mut updated = record[..ENTITY_METADATA_HEADER_LEN].to_vec();
        updated.extend_from_slice(&new_payload);
        vault
            .store
            .entities
            .put(&mut wtxn, drifted_id.as_bytes(), &updated)?;
        wtxn.commit()?;
    }

    let report = vault.maintain().recompute_short_id_hashes().run()?;
    assert_eq!(report.short_id_hashes_updated, 1);
    assert_eq!(
        report.orphan_short_ids_deleted, 0,
        "a legacy forward row backed by a valid alias is owned, not orphan garbage"
    );

    let new_hash = (xxh32(&new_payload, 0) % 256) as u8;
    {
        let rtxn = vault.store.env.read_txn()?;
        // The alias followed the canonical row to its new content hash.
        assert_eq!(
            vault.store.resolve_short_id_alias(&rtxn, drifted_legacy)?,
            Some(ShortIdAliasTarget::EntityForwardKey(
                encode_short_id_forward_key(drifted_canonical, new_hash)
            )),
        );
        // The retained legacy forward row survived the orphan sweep.
        assert!(
            vault
                .store
                .short_ids
                .get(
                    &rtxn,
                    &encode_short_id_forward_key(drifted_legacy, old_hash)
                )?
                .is_some(),
            "the retained legacy forward row must survive maintenance"
        );
    }

    // Old and new references resolve to the SAME entity at the refreshed hash —
    // the legacy one through its alias, the canonical one directly.
    for spelling in [drifted_legacy, drifted_canonical] {
        let hydrated = vault
            .hydrate_short_id(spelling, new_hash)?
            .unwrap_or_else(|| panic!("{spelling} must resolve after the hash refresh"));
        assert_eq!(hydrated.id, drifted_id, "{spelling} resolves");
    }

    // A wrong hash is still a miss: an alias relocates a name, it does not
    // waive the version check that makes a short ref a versioned reference.
    let wrong_hash = new_hash.wrapping_add(1);
    assert!(
        vault
            .hydrate_short_id(drifted_legacy, wrong_hash)?
            .is_none()
            || wrong_hash == old_hash,
        "the alias must not resolve under an unrelated content hash"
    );
    Ok(())
}

#[test]
fn corrupt_reverse_row_never_reaps_healthy_forward_one_1114() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let healthy = entity(103);

    vault
        .batch()
        .put(&healthy, 1, test_time_range(100, 100), 101, b"payload")
        .commit()?;

    let healthy_forward_key = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, healthy.as_bytes())?
            .ok_or(Error::EntityNotFound)?
            .to_vec()
    };

    // Corrupt reverse KEY (not a 16-byte entity id) with a VALUE that
    // aliases the healthy entity's legitimate forward key. ONE-1114 pins
    // that this row may prune only itself, never the healthy forward row.
    let corrupt_reverse_key = b"bad-key";
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .short_ids_reverse
            .put(&mut wtxn, corrupt_reverse_key, &healthy_forward_key)?;
        wtxn.commit()?;
    }

    let report = vault.maintain().recompute_short_id_hashes().run()?;
    assert_eq!(report.orphan_short_ids_deleted, 1);

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, corrupt_reverse_key)?
            .is_none(),
        "corrupt reverse row should be pruned"
    );
    assert_eq!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, healthy.as_bytes())?
            .as_deref(),
        Some(healthy_forward_key.as_slice()),
        "healthy reverse row must survive"
    );
    assert_eq!(
        vault
            .store
            .short_ids
            .get(&rtxn, &healthy_forward_key)?
            .as_deref(),
        Some(healthy.as_bytes().as_slice()),
        "healthy forward row must not be reaped by a corrupt reverse row"
    );
    Ok(())
}

#[test]
fn valid_key_absent_entity_aliased_value_never_reaps_healthy_forward_one_1173() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let healthy = entity(104);
    let orphan = entity(105);

    vault
        .batch()
        .put(&healthy, 1, test_time_range(100, 100), 101, b"payload")
        .commit()?;

    let healthy_forward_key = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, healthy.as_bytes())?
            .ok_or(Error::EntityNotFound)?
            .to_vec()
    };

    // Valid reverse KEY with no backing entity, but a VALUE that aliases
    // the healthy entity's forward key. ONE-1173 pins that this can prune
    // only the absent entity's reverse row, never the healthy forward row.
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .short_ids_reverse
            .put(&mut wtxn, orphan.as_bytes(), &healthy_forward_key)?;
        wtxn.commit()?;
    }

    let report = vault.maintain().recompute_short_id_hashes().run()?;
    assert_eq!(report.orphan_short_ids_deleted, 1);

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, orphan.as_bytes())?
            .is_none(),
        "absent entity reverse row should be pruned"
    );
    assert_eq!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, healthy.as_bytes())?
            .as_deref(),
        Some(healthy_forward_key.as_slice()),
        "healthy reverse row must survive"
    );
    assert_eq!(
        vault
            .store
            .short_ids
            .get(&rtxn, &healthy_forward_key)?
            .as_deref(),
        Some(healthy.as_bytes().as_slice()),
        "healthy forward row must not be reaped by an aliased reverse value"
    );
    Ok(())
}

#[test]
fn valid_key_aliased_value_never_overwrites_healthy_forward_one_1173() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let healthy = entity(106);
    let aliased = entity(107);

    vault
        .batch()
        .put(&healthy, 1, test_time_range(100, 100), 101, b"payload")
        .commit()?;

    let (healthy_forward_key, healthy_hash) = {
        let rtxn = vault.store.env.read_txn()?;
        let value = vault
            .store
            .short_ids_reverse
            .get(&rtxn, healthy.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let (_, hash) = parse_short_id_value(&value)?;
        (value.to_vec(), hash)
    };

    let mut aliased_payload = b"aliased-payload".to_vec();
    while ((xxh32(&aliased_payload, 0) % 256) as u8) != healthy_hash {
        aliased_payload.push(0);
    }

    vault
        .batch()
        .put(
            &aliased,
            1,
            test_time_range(100, 100),
            101,
            &aliased_payload,
        )
        .commit()?;

    let aliased_original_forward_key = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, aliased.as_bytes())?
            .ok_or(Error::EntityNotFound)?
            .to_vec()
    };

    // Valid reverse KEY with a backing entity, but a VALUE that aliases a
    // healthy entity's forward key. The hash is matched so the pass reaches
    // the forward-repair arm rather than the hash-refresh arm.
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .short_ids
            .delete(&mut wtxn, &aliased_original_forward_key)?;
        vault
            .store
            .short_ids_reverse
            .put(&mut wtxn, aliased.as_bytes(), &healthy_forward_key)?;
        wtxn.commit()?;
    }

    let report = vault.maintain().recompute_short_id_hashes().run()?;
    assert_eq!(report.short_id_hashes_updated, 0);
    assert_eq!(report.orphan_short_ids_deleted, 1);

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault
            .store
            .short_ids
            .get(&rtxn, &healthy_forward_key)?
            .as_deref(),
        Some(healthy.as_bytes().as_slice()),
        "healthy forward row must not be overwritten by an aliased reverse value"
    );
    assert_eq!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, healthy.as_bytes())?
            .as_deref(),
        Some(healthy_forward_key.as_slice()),
        "healthy reverse row must survive"
    );
    assert_eq!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, aliased.as_bytes())?,
        None,
        "backed aliased reverse row should be pruned without touching the healthy forward row"
    );
    assert!(
        vault
            .store
            .short_ids
            .get(&rtxn, &aliased_original_forward_key)?
            .is_none(),
        "the aliased entity's now-unpaired old forward row should be pruned by pass 2"
    );
    Ok(())
}

#[test]
fn recompute_short_id_hashes_keeps_in_pass_reserved_refresh_one_1176() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let id = entity(108);

    vault
        .batch()
        .put(&id, 1, test_time_range(100, 100), 101, b"payload-old")
        .commit()?;

    let (stale_forward_key, stale_hash) = {
        let rtxn = vault.store.env.read_txn()?;
        let value = vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let (_, hash) = parse_short_id_value(&value)?;
        (value.to_vec(), hash)
    };

    let mut payload = b"payload-new".to_vec();
    while ((xxh32(&payload, 0) % 256) as u8) == stale_hash {
        payload.push(0);
    }
    vault
        .batch()
        .put(&id, 1, test_time_range(100, 100), 102, &payload)
        .commit()?;

    let fresh_forward_key = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?
            .to_vec()
    };
    assert_ne!(stale_forward_key, fresh_forward_key);

    // Simulate a crash/replay split where the entity body has the new
    // hash, but reverse points at the old hash and the fresh forward row
    // is missing. Pass 1 must refresh/rewrite it; pass 2 must not reap
    // that just-reserved row as its own orphan.
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .short_ids_reverse
            .put(&mut wtxn, id.as_bytes(), &stale_forward_key)?;
        vault
            .store
            .short_ids
            .delete(&mut wtxn, &fresh_forward_key)?;
        wtxn.commit()?;
    }

    let report = vault.maintain().recompute_short_id_hashes().run()?;
    assert_eq!(report.short_id_hashes_updated, 1);

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())?
            .as_deref(),
        Some(fresh_forward_key.as_slice()),
        "reverse row should be refreshed to the current content hash"
    );
    assert_eq!(
        vault
            .store
            .short_ids
            .get(&rtxn, &fresh_forward_key)?
            .as_deref(),
        Some(id.as_bytes().as_slice()),
        "fresh forward row written by this pass must survive pass 2"
    );
    Ok(())
}

#[test]
fn attempt_queue_cleanup_maintenance_reports_counts_and_requeues() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let clock = crate::ports::ManualClock::new(1);
    let vault = Vault::open(
        temp_dir.path(),
        VaultConfig {
            store_clock: clock.bundle(),
            ..test_config()
        },
    )?;
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(EnqueueAttempt {
        kind: "claim_extraction".to_owned(),
        payload: b"payload".to_vec(),
        dedupe_key: Some("turn:maintenance".to_owned()),
        run_id: Some("run-maintenance".to_owned()),
        now: 1,
    })?
    else {
        panic!("expected enqueue");
    };
    clock.set(2);
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".to_owned(),
        now: 2,
    })?
    else {
        panic!("expected claim");
    };
    assert_eq!(claimed.id, attempt.id);

    clock.set(100);
    let report = vault.maintain().cleanup_attempt_queue_leases(1).run()?;
    assert_eq!(report.attempt_queue_cleanup.pending, 1);
    assert_eq!(report.attempt_queue_cleanup.running, 0);
    assert_eq!(report.attempt_queue_cleanup.failed, 0);
    assert_eq!(report.attempt_queue_cleanup.done, 0);
    assert_eq!(report.attempt_queue_cleanup.stale_requeued, 1);
    assert_eq!(
        report
            .attempt_queue_cleanup
            .retry_reason_count(AttemptQueueRetryReason::LeaseTimeout),
        1
    );

    let ClaimOutcome::Claimed(reclaimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-b".to_owned(),
        now: 100,
    })?
    else {
        panic!("expected reclaimed attempt");
    };
    assert_eq!(reclaimed.id, attempt.id);
    assert_eq!(reclaimed.lease_owner.as_deref(), Some("worker-b"));

    Ok(())
}

#[test]
fn attempt_queue_maintenance_warns_a_live_lease_before_cleanup_takes_it() -> Result<()> {
    // ONE-1896 §3: the WARNING rung has a production caller — this maintenance
    // lane — so a worker inside its expiry window is asked to land instead of
    // discovering its lease was reclaimed.
    const LEASE_TIMEOUT_SECS: u64 = 1_000;

    let temp_dir = tempfile::tempdir()?;
    let clock = crate::ports::ManualClock::new(1);
    let vault = Vault::open(
        temp_dir.path(),
        VaultConfig {
            store_clock: clock.bundle(),
            ..test_config()
        },
    )?;
    let queue = AttemptQueue::new(&vault);
    queue.enqueue(EnqueueAttempt {
        kind: "claim_extraction".to_owned(),
        payload: b"payload".to_vec(),
        dedupe_key: Some("turn:lease-warning".to_owned()),
        run_id: Some("run-lease-warning".to_owned()),
        now: 1,
    })?;
    // Claimed far enough in the past to sit inside the warning window
    // (>= 80% of the timeout) but well short of expiry.
    let claimed_at = 100;
    clock.set(claimed_at);
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".to_owned(),
        now: claimed_at,
    })?
    else {
        panic!("expected claim");
    };

    clock.set(1_000);
    let report = vault
        .maintain()
        .cleanup_attempt_queue_leases(LEASE_TIMEOUT_SECS)
        .run()?;
    assert_eq!(report.attempt_queue_lease_warnings.scanned, 1);
    assert_eq!(report.attempt_queue_lease_warnings.warned, 1);
    assert_eq!(report.attempt_queue_lease_warnings.expired, 0);
    // The warning is NOT a reclaim: cleanup left the live lease alone.
    assert_eq!(report.attempt_queue_cleanup.stale_requeued, 0);
    assert_eq!(report.attempt_queue_cleanup.running, 1);

    let warned = queue.get(claimed.id)?.expect("attempt row");
    assert_eq!(warned.state, crate::attempt_queue::AttemptState::Leased);
    assert_eq!(warned.lease_owner.as_deref(), Some("worker-a"));
    assert_eq!(warned.cancel_pressure().pending, 1);
    let receipt = warned.cancel_receipts().last().expect("warning receipt");
    assert_eq!(receipt.actor, crate::attempt_queue::ATTEMPT_RUNTIME_ACTOR);
    assert_eq!(
        receipt.trigger,
        Some(crate::attempt_queue::LandingTrigger::LeaseWarning)
    );

    // Re-running the lane does not inflate the ask: one outstanding request.
    let again = vault
        .maintain()
        .cleanup_attempt_queue_leases(LEASE_TIMEOUT_SECS)
        .run()?;
    assert_eq!(again.attempt_queue_lease_warnings.warned, 0);
    assert_eq!(again.attempt_queue_lease_warnings.already_requested, 1);
    assert_eq!(
        queue
            .get(claimed.id)?
            .expect("attempt row")
            .cancel_pressure()
            .requests,
        1
    );
    Ok(())
}

#[test]
fn clear_text_index_removes_all_text_rows_and_rewrites_manifest() -> Result<()> {
    use crate::store::{
        TEXT_ANALYZER_MANIFEST_HASH_KEY, TEXT_BM25_FIELD_SCHEMA_HASH_KEY,
        TEXT_INDEX_SCHEMA_VERSION_KEY,
    };

    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let a = entity(120);
    let b = entity(121);

    vault
        .batch()
        .put(&a, 1, test_time_range(1, 1), 1, b"a")
        .put(&b, 1, test_time_range(1, 1), 1, b"b")
        .text(&a, &[("body", "hello world")])
        .text(&b, &[("body", "world of rust")])
        .commit()?;

    let hits = vault.search_text("world", 10)?;
    assert_eq!(hits.len(), 2);

    let manifest_hash_before = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .vault_meta
            .get(&rtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY)?
            .map(|b| b.to_vec())
    };
    assert!(manifest_hash_before.is_some());

    let report = vault.maintain().clear_text_index().run()?;
    assert!(report.text_postings_removed > 0);
    assert!(report.text_meta_removed > 0);
    assert!(report.text_forward_removed > 0);
    assert!(report.text_doc_field_lengths_removed > 0);
    assert!(report.text_bm25_field_stats_removed > 0);

    assert_eq!(count_entries(&vault.store.text_postings, &vault)?, 0);
    assert_eq!(count_entries(&vault.store.text_meta, &vault)?, 0);
    assert_eq!(count_entries(&vault.store.text_forward, &vault)?, 0);
    assert_eq!(
        count_entries(&vault.store.text_doc_field_lengths, &vault)?,
        0
    );
    assert_eq!(
        count_entries(&vault.store.text_bm25_field_stats, &vault)?,
        0
    );

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .vault_meta
            .get(&rtxn, TEXT_INDEX_SCHEMA_VERSION_KEY)?
            .is_some()
    );
    assert!(
        vault
            .store
            .vault_meta
            .get(&rtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY)?
            .is_some()
    );
    assert!(
        vault
            .store
            .vault_meta
            .get(&rtxn, TEXT_BM25_FIELD_SCHEMA_HASH_KEY)?
            .is_some()
    );
    drop(rtxn);

    // Entities still present — clear_text_index only touches text DBs.
    assert!(vault.get_entity_type(&a)?.is_some());
    assert!(vault.get_entity_type(&b)?.is_some());

    // Index reusable after clear.
    vault
        .batch()
        .text(&a, &[("body", "hello again")])
        .commit()?;
    let hits = vault.search_text("hello", 10)?;
    assert!(!hits.is_empty());
    Ok(())
}
