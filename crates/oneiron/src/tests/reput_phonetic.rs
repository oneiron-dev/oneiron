//! Re-put reindexing, phonetic/forward-code index, delete deindexing.

use super::*;

#[test]
fn batch_put_updates_content_hash_on_reput() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let data1 = b"initial";
    let mut data2 = b"updated".to_vec();
    while content_hash(data1) == content_hash(&data2) {
        data2.push(0_u8);
    }

    vault
        .batch()
        .put(&id, 1, test_time_range(10, 10), 11, data1)
        .commit()?;
    let (short_id1, hash1) = decode_short_id_value(&read_short_id_value(&vault, &id)?)?;

    vault
        .batch()
        .put(&id, 1, test_time_range(10, 10), 11, &data2)
        .commit()?;
    let (short_id2, hash2) = decode_short_id_value(&read_short_id_value(&vault, &id)?)?;

    assert_eq!(short_id1, short_id2);
    assert_eq!(hash1, content_hash(data1));
    assert_eq!(hash2, content_hash(&data2));
    assert_ne!(hash1, hash2);

    // The content hash is part of the forward KEY (manifest row n3), so the
    // re-put must reap the stale forward row and write the refreshed one — an
    // implementation that leaves the old `(short_id, old_hash)` row FAILS.
    let mut stale_forward_key = short_id1.as_bytes().to_vec();
    stale_forward_key.push(hash1);
    let mut fresh_forward_key = short_id1.as_bytes().to_vec();
    fresh_forward_key.push(hash2);
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .short_ids
            .get(&rtxn, &stale_forward_key)?
            .is_none(),
        "stale forward short_ids row must be deleted on content update"
    );
    assert_eq!(
        vault
            .store
            .short_ids
            .get(&rtxn, &fresh_forward_key)?
            .as_deref(),
        Some(id.as_bytes().as_slice())
    );
    Ok(())
}

#[test]
fn reput_deindexes_stale_secondary_indexes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    // The type byte is immutable on re-put (D2, RegistryError::EntityTypeImmutable);
    // re-typing coverage lives in the EntityTypeImmutable tests. This test
    // pins that a same-type re-put re-homes the temporal indexes while the
    // short id stays stable and the content hash refreshes. Type byte 2
    // (SESSION) keeps the body opaque — type 0 is reserved for CLAIM, whose
    // bodies are structurally validated (D18).
    let entity_type = 2_u8;
    let old_occurred = test_time_range(100, 200);
    let old_learned = 300_u64;
    let old_data = b"old-data";
    let new_occurred = test_time_range(400, 500);
    let new_learned = 600_u64;
    let mut new_data = b"new-data".to_vec();
    while content_hash(old_data) == content_hash(&new_data) {
        new_data.push(0_u8);
    }

    vault
        .batch()
        .put(&id, entity_type, old_occurred, old_learned, old_data)
        .commit()?;

    let type_key = Store::encode_type_key(entity_type, &id);
    let old_start_key = Store::encode_temporal_key(old_occurred.start, &id);
    let old_end_key = Store::encode_temporal_key(old_occurred.end, &id);
    let old_learned_key = Store::encode_temporal_key(old_learned, &id);

    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.type_index.get(&rtxn, &type_key)?.is_some());
        assert!(
            vault
                .store
                .temporal_occurred_start
                .get(&rtxn, &old_start_key)?
                .is_some()
        );
        assert!(
            vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &old_end_key)?
                .is_some()
        );
        assert!(
            vault
                .store
                .temporal_learned
                .get(&rtxn, &old_learned_key)?
                .is_some()
        );
    }

    let (short_id_before, hash_before) = decode_short_id_value(&read_short_id_value(&vault, &id)?)?;

    vault
        .batch()
        .put(&id, entity_type, new_occurred, new_learned, &new_data)
        .commit()?;

    let new_start_key = Store::encode_temporal_key(new_occurred.start, &id);
    let new_end_key = Store::encode_temporal_key(new_occurred.end, &id);
    let new_learned_key = Store::encode_temporal_key(new_learned, &id);

    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.type_index.get(&rtxn, &type_key)?.is_some());
        assert!(
            vault
                .store
                .temporal_occurred_start
                .get(&rtxn, &old_start_key)?
                .is_none()
        );
        assert!(
            vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &old_end_key)?
                .is_none()
        );
        assert!(
            vault
                .store
                .temporal_learned
                .get(&rtxn, &old_learned_key)?
                .is_none()
        );
        assert!(
            vault
                .store
                .temporal_occurred_start
                .get(&rtxn, &new_start_key)?
                .is_some()
        );
        assert!(
            vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &new_end_key)?
                .is_some()
        );
        assert!(
            vault
                .store
                .temporal_learned
                .get(&rtxn, &new_learned_key)?
                .is_some()
        );
    }

    assert_eq!(vault.get(&id)?.ok_or(Error::EntityNotFound)?, new_data);
    let (short_id_after, hash_after) = decode_short_id_value(&read_short_id_value(&vault, &id)?)?;
    assert_eq!(short_id_before, short_id_after);
    assert_eq!(hash_before, content_hash(old_data));
    assert_eq!(hash_after, content_hash(&new_data));
    assert_ne!(hash_before, hash_after);

    Ok(())
}

#[test]
fn reput_range_to_point_deindexes_stale_end_key() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault
        .batch()
        .put(&id, 1, test_time_range(100, 200), 300, b"range")
        .commit()?;

    let old_end_key = Store::encode_temporal_key(200, &id);
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &old_end_key)?
                .is_some()
        );
    }

    vault
        .batch()
        .put(&id, 1, test_time_range(200, 200), 300, b"point")
        .commit()?;

    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &old_end_key)?
                .is_none(),
            "stale occurred_end key should be deleted on range→point transition"
        );
    }

    assert!(vault.delete_entity(&id)?);
    Ok(())
}

#[test]
fn reput_rekeys_long_interval_index_and_drops_shortened_range() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let old_end = 1_000 + crate::batch::LONG_INTERVAL_THRESHOLD_SECS + 10;
    let new_end = 5_000 + crate::batch::LONG_INTERVAL_THRESHOLD_SECS + 20;

    vault
        .batch()
        .put(&id, 1, test_time_range(1_000, old_end), 300, b"long-old")
        .commit()?;

    let old_key = Store::encode_temporal_key(old_end, &id);
    let new_key = Store::encode_temporal_key(new_end, &id);

    vault
        .batch()
        .put(&id, 1, test_time_range(5_000, new_end), 300, b"long-new")
        .commit()?;

    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .temporal_long_intervals
                .get(&rtxn, &old_key)?
                .is_none()
        );
        let value = vault
            .store
            .temporal_long_intervals
            .get(&rtxn, &new_key)?
            .ok_or(Error::EntityNotFound)?;
        assert_eq!(
            u64::from_be_bytes(value.as_ref().try_into().map_err(|_| Error::InvalidKey)?),
            5_000
        );
    }

    vault
        .batch()
        .put(&id, 1, test_time_range(10_000, 10_001), 300, b"short")
        .commit()?;

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .temporal_long_intervals
            .get(&rtxn, &new_key)?
            .is_none()
    );
    Ok(())
}

#[test]
fn batch_phonetic_index() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault
        .batch()
        .put(&id, 1, test_time_range(1, 1), 2, b"phonetic")
        .phonetic(&id, &["SMTH", "SMT"])
        .commit()?;

    let rtxn = vault.store.env.read_txn()?;
    for code in ["SMTH", "SMT"] {
        let posting = vault
            .store
            .phonetic_index
            .get(&rtxn, code.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        assert!(posting.len().is_multiple_of(16));
        assert!(posting.chunks_exact(16).any(|chunk| chunk == id.as_bytes()));
    }

    let forward = vault
        .store
        .phonetic_forward
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(
        decode_forward_codes(&forward)?,
        vec!["SMT".to_owned(), "SMTH".to_owned()]
    );
    Ok(())
}

#[test]
fn phonetic_dedup_on_reindex() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault
        .batch()
        .put(&id, 1, test_time_range(1, 2), 3, b"dedup")
        .phonetic(&id, &["ABC"])
        .commit()?;

    vault.batch().phonetic(&id, &["ABC"]).commit()?;

    let rtxn = vault.store.env.read_txn()?;
    let posting = vault
        .store
        .phonetic_index
        .get(&rtxn, b"ABC")?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(posting.len(), 16);
    let count = posting
        .chunks_exact(16)
        .filter(|chunk| *chunk == id.as_bytes())
        .count();
    assert_eq!(count, 1);

    let forward = vault
        .store
        .phonetic_forward
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(decode_forward_codes(&forward)?, vec!["ABC".to_owned()]);
    Ok(())
}

#[test]
fn phonetic_dedups_duplicate_codes_within_single_batch() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault
        .batch()
        .put(&id, 1, test_time_range(1, 2), 3, b"dedup-in-batch")
        .phonetic(&id, &["ABC", "ABC"])
        .commit()?;

    let rtxn = vault.store.env.read_txn()?;
    let posting = vault
        .store
        .phonetic_index
        .get(&rtxn, b"ABC")?
        .ok_or(Error::EntityNotFound)?;
    assert!(posting.len().is_multiple_of(ENTITY_ID_LEN));
    let count = posting
        .chunks_exact(ENTITY_ID_LEN)
        .filter(|chunk| *chunk == id.as_bytes())
        .count();
    assert_eq!(count, 1);

    let forward = vault
        .store
        .phonetic_forward
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(decode_forward_codes(&forward)?, vec!["ABC".to_owned()]);
    Ok(())
}

#[test]
fn phonetic_reindex_remains_additive() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault
        .batch()
        .put(&id, 1, test_time_range(1, 2), 3, b"union")
        .phonetic(&id, &["ABC"])
        .commit()?;

    vault.batch().phonetic(&id, &["DEF"]).commit()?;

    let rtxn = vault.store.env.read_txn()?;
    for code in ["ABC", "DEF"] {
        let posting = vault
            .store
            .phonetic_index
            .get(&rtxn, code.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        assert!(posting.chunks_exact(16).any(|chunk| chunk == id.as_bytes()));
    }

    let forward = vault
        .store
        .phonetic_forward
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(
        decode_forward_codes(&forward)?,
        vec!["ABC".to_owned(), "DEF".to_owned()]
    );
    Ok(())
}

#[test]
fn phonetic_reindex_repairs_missing_forward_codes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault
        .batch()
        .put(&id, 1, test_time_range(1, 2), 3, b"migrated")
        .phonetic(&id, &["ABC"])
        .commit()?;

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .phonetic_forward
        .delete(&mut wtxn, id.as_bytes())?;
    wtxn.commit()?;

    vault.batch().phonetic(&id, &["ABC", "DEF"]).commit()?;

    let rtxn = vault.store.env.read_txn()?;
    let forward = vault
        .store
        .phonetic_forward
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(
        decode_forward_codes(&forward)?,
        vec!["ABC".to_owned(), "DEF".to_owned()]
    );
    drop(rtxn);

    assert!(vault.delete_entity(&id)?);

    let rtxn = vault.store.env.read_txn()?;
    for code in ["ABC", "DEF"] {
        if let Some(posting) = vault.store.phonetic_index.get(&rtxn, code.as_bytes())? {
            assert!(!posting.chunks_exact(16).any(|chunk| chunk == id.as_bytes()));
        }
    }
    Ok(())
}

#[test]
fn phonetic_rejects_invalid_codes_atomically() -> Result<()> {
    // (case_name, invalid_code, payload)
    let cases: &[(&str, &str, &[u8])] = &[
        ("embedded_nul", "BAD\0CODE", b"phonetic-invalid"),
        ("empty", "", b"phonetic-empty"),
    ];

    for (name, code, payload) in cases {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::now();

        let result = vault
            .batch()
            .put(&id, 1, test_time_range(1, 1), 2, payload)
            .phonetic(&id, &[*code])
            .commit();
        let err = result
            .err()
            .unwrap_or_else(|| panic!("case {name}: expected invalid phonetic code to fail"));
        assert!(
            matches!(err, Error::InvalidKey),
            "case {name}: expected InvalidKey, got {err:?}"
        );
        assert!(
            vault.get(&id)?.is_none(),
            "case {name}: batch should remain atomic on phonetic validation failure"
        );
    }
    Ok(())
}

#[test]
fn full_delete_deindexes_everything() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let out_target = EntityId::now();
    let in_source = EntityId::now();
    let occurred = test_time_range(10_000, 20_000);
    let learned_at = 30_000;

    vault
        .batch()
        .put(&id, 1, occurred, learned_at, b"delete-me")
        .put(&out_target, 4, test_time_range(1, 1), 2, b"target")
        .put(&in_source, 4, test_time_range(3, 3), 4, b"source")
        .vector(&id, &[0.1, 0.2, 0.3, 0.4])
        .edge(&id, EdgeKind::Supports, &out_target, 0.9)
        .edge(&in_source, EdgeKind::Mentions, &id, 0.7)
        .phonetic(&id, &["SMTH", "SMT"])
        .commit()?;

    // The reverse VALUE bytes double as the forward KEY (short_id ‖ hash).
    let forward_key_before_delete = read_short_id_value(&vault, &id)?;
    let type_key = Store::encode_type_key(1, &id);
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.type_index.get(&rtxn, &type_key)?.is_some());
    }

    assert!(vault.delete_entity(&id)?);
    assert!(vault.get(&id)?.is_none());
    assert!(vault.get_vector(&id)?.is_none());
    assert!(vault.edges_out(&id)?.is_empty());
    assert!(vault.edges_in(&id)?.is_empty());
    assert!(vault.edges_in(&out_target)?.is_empty());
    assert!(vault.edges_out(&in_source)?.is_empty());

    let start_key = Store::encode_temporal_key(occurred.start, &id);
    let end_key = Store::encode_temporal_key(occurred.end, &id);
    let learned_key = Store::encode_temporal_key(learned_at, &id);
    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.store.type_index.get(&rtxn, &type_key)?.is_none());
    assert!(
        vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &start_key)?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &end_key)?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &learned_key)?
            .is_none()
    );

    for code in ["SMTH", "SMT"] {
        if let Some(posting) = vault.store.phonetic_index.get(&rtxn, code.as_bytes())? {
            assert!(!posting.chunks_exact(16).any(|chunk| chunk == id.as_bytes()));
        }
    }
    assert!(
        vault
            .store
            .phonetic_forward
            .get(&rtxn, id.as_bytes())?
            .is_none()
    );

    assert!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())?
            .is_none()
    );
    assert!(
        vault
            .store
            .short_ids
            .get(&rtxn, &forward_key_before_delete)?
            .is_none()
    );
    Ok(())
}

#[test]
fn delete_entity_phonetic_fallback_variants() -> Result<()> {
    /// What kind of phonetic-index corruption to inject before `delete_entity`.
    enum Corruption {
        /// `phonetic_forward[id]` row deleted entirely.
        Missing,
        /// One of the `phonetic_index[code]` postings deleted (forward row intact).
        StaleIndex,
        /// `phonetic_forward[id]` overwritten with empty bytes.
        EmptyForward,
        /// `phonetic_forward[id]` overwritten with a subset of original codes.
        SubsetForward,
    }

    // Every variant inserts an entity with the same two phonetic codes,
    // injects its corruption, then asserts:
    //  1. `delete_entity` returns Ok(true)
    //  2. Both phonetic postings no longer reference the deleted entity
    //  3. (variants StaleIndex, EmptyForward, SubsetForward) phonetic_forward is cleared
    let cases: &[(&str, &[u8], Corruption)] = &[
        ("missing", b"phonetic-fallback", Corruption::Missing),
        (
            "stale_index",
            b"phonetic-stale-forward",
            Corruption::StaleIndex,
        ),
        (
            "empty_forward",
            b"phonetic-empty-forward",
            Corruption::EmptyForward,
        ),
        (
            "subset_forward",
            b"phonetic-subset-forward",
            Corruption::SubsetForward,
        ),
    ];

    for (name, payload, corruption) in cases {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::now();

        vault
            .batch()
            .put(&id, 1, test_time_range(1, 1), 2, payload)
            .phonetic(&id, &["SMTH", "SMT"])
            .commit()?;

        let mut wtxn = vault.store.env.write_txn()?;
        match corruption {
            Corruption::Missing => {
                vault
                    .store
                    .phonetic_forward
                    .delete(&mut wtxn, id.as_bytes())?;
            }
            Corruption::StaleIndex => {
                vault.store.phonetic_index.delete(&mut wtxn, b"SMTH")?;
            }
            Corruption::EmptyForward => {
                vault
                    .store
                    .phonetic_forward
                    .put(&mut wtxn, id.as_bytes(), &[])?;
            }
            Corruption::SubsetForward => {
                vault
                    .store
                    .phonetic_forward
                    .put(&mut wtxn, id.as_bytes(), b"SMT")?;
            }
        }
        wtxn.commit()?;

        assert!(
            vault.delete_entity(&id)?,
            "case {name}: delete_entity should return true"
        );

        let rtxn = vault.store.env.read_txn()?;

        // Variants that wrote to phonetic_forward must end with it cleared.
        let must_clear_forward = matches!(
            corruption,
            Corruption::StaleIndex | Corruption::EmptyForward | Corruption::SubsetForward
        );
        if must_clear_forward {
            assert!(
                vault
                    .store
                    .phonetic_forward
                    .get(&rtxn, id.as_bytes())?
                    .is_none(),
                "case {name}: phonetic_forward should be cleared after delete"
            );
        }

        // For the stale_index variant the SMTH posting was already deleted; only
        // assert SMT (the surviving posting) no longer references the entity.
        let codes_to_check: &[&[u8]] = match corruption {
            Corruption::StaleIndex => &[b"SMT"],
            _ => &[b"SMTH", b"SMT"],
        };
        for code in codes_to_check {
            if let Some(posting) = vault.store.phonetic_index.get(&rtxn, code)? {
                assert!(
                    !posting.chunks_exact(16).any(|chunk| chunk == id.as_bytes()),
                    "case {name}: code {:?} still references deleted entity",
                    std::str::from_utf8(code).unwrap_or("<bin>")
                );
            }
        }
    }

    Ok(())
}

#[test]
fn delete_entity_corrupted_edge_record_returns_error_not_panic() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let target = EntityId::now();

    vault
        .batch()
        .put(&id, 1, test_time_range(1, 2), 3, b"exists")
        .commit()?;

    vault.with_write_txn(|wtxn| {
        let key = Store::encode_edge_key(&id, EdgeKind::Supports, &target);
        let value = [0_u8; 3];
        vault.store.edges_out.put(wtxn, &key, &value)?;
        Ok(())
    })?;

    let err = vault
        .delete_entity(&id)
        .expect_err("corrupted edge record should fail loud");
    assert_matches!(err, Error::CorruptedIndex(_));
    Ok(())
}

#[test]
fn delete_entity_cleans_edge_only_nodes_and_bumps_graph_version() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let src = EntityId::now();
    let tgt = EntityId::now();

    vault.put_edge(&src, EdgeKind::Supports, &tgt, 0.9)?;
    let before = read_hnsw_meta_u64(&vault, GRAPH_VERSION_KEY)?;

    assert!(!vault.delete_entity(&src)?);
    assert!(vault.edges_out(&src)?.is_empty());
    assert!(vault.edges_in(&tgt)?.is_empty());

    let after = read_hnsw_meta_u64(&vault, GRAPH_VERSION_KEY)?;
    assert_eq!(after, before + 1);
    Ok(())
}

#[test]
fn put_entity_simple_api_uses_batch() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let occurred = test_time_range(123, 456);
    let learned_at = 789;
    let data = b"simple-api";

    vault.put_entity(&id, 1, occurred, learned_at, data)?;
    assert_eq!(vault.get(&id)?.ok_or(Error::EntityNotFound)?, data);

    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .entities
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(raw.len(), ENTITY_METADATA_HEADER_LEN + data.len());
    assert_eq!(&raw[ENTITY_METADATA_HEADER_LEN..], data);

    let type_key = Store::encode_type_key(1, &id);
    let start_key = Store::encode_temporal_key(occurred.start, &id);
    let end_key = Store::encode_temporal_key(occurred.end, &id);
    let learned_key = Store::encode_temporal_key(learned_at, &id);
    assert!(vault.store.type_index.get(&rtxn, &type_key)?.is_some());
    assert!(
        vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &start_key)?
            .is_some()
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &end_key)?
            .is_some()
    );
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &learned_key)?
            .is_some()
    );
    assert!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())?
            .is_some()
    );

    Ok(())
}

#[test]
fn get_learned_at_rejects_truncated_entity_header() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault.with_write_txn(|wtxn| {
        let truncated = [0_u8; ENTITY_METADATA_HEADER_LEN - 1];
        vault.store.entities.put(wtxn, id.as_bytes(), &truncated)?;
        Ok(())
    })?;

    let err = vault
        .get_learned_at(&id)
        .expect_err("truncated entity header should fail loud");
    assert_matches!(err, Error::CorruptedIndex(_));

    Ok(())
}

#[test]
fn validates_dimensions_hnsw_and_map_size() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;

    let mut invalid_dims = test_config();
    invalid_dims.dimensions = 0;
    let err = match Vault::open(temp_dir.path(), invalid_dims) {
        Ok(_) => panic!("expected invalid config"),
        Err(err) => err,
    };
    assert_matches!(err, Error::InvalidConfig(_));

    let mut invalid_hnsw = test_config();
    invalid_hnsw.hnsw.m_max_0 = 0;
    let err = match Vault::open(temp_dir.path(), invalid_hnsw) {
        Ok(_) => panic!("expected invalid config"),
        Err(err) => err,
    };
    assert_matches!(err, Error::InvalidConfig(_));

    let mut invalid_map = test_config();
    invalid_map.map_size = 0;
    let err = match Vault::open(temp_dir.path(), invalid_map) {
        Ok(_) => panic!("expected invalid config"),
        Err(err) => err,
    };
    assert_matches!(err, Error::InvalidConfig(_));
    Ok(())
}
