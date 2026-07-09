use crate::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_TASK};
use crate::store::Store;
use crate::types::{EDGE_VALUE_STRUCTURAL_LEN, TaskRole, task_body_for_test};
use crate::*;
use core::assert_matches;

fn non_finite_edge_value(weight: f32) -> [u8; EDGE_VALUE_STRUCTURAL_LEN] {
    let mut value = [0_u8; EDGE_VALUE_STRUCTURAL_LEN];
    value[..4].copy_from_slice(&weight.to_le_bytes());
    value
}

fn task_body() -> Vec<u8> {
    task_body_for_test(TaskRole::Task)
}

#[test]
fn test_intra_batch_cycle() {
    let (_temp_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());

    let a = EntityId::now();
    let b = EntityId::now();

    vault
        .batch()
        .put(
            &a,
            ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            2,
            &task_body(),
        )
        .put(
            &b,
            ENTITY_TYPE_TASK,
            TimeRange { start: 3, end: 3 },
            4,
            &task_body(),
        )
        .commit()
        .unwrap();

    let result = vault
        .batch()
        .edge_checked(&a, &b, 1.0)
        .edge_checked(&b, &a, 1.0)
        .commit();

    assert!(
        matches!(result, Err(Error::CycleDetected)),
        "Intra-batch cycle should return CycleDetected, got {result:?}"
    );

    // Verify abort rolled back both edges
    assert!(
        !vault.edge_exists(&a, EdgeKind::ChildOf, &b).unwrap(),
        "a→b edge should not persist after cycle abort"
    );
    assert!(
        !vault.edge_exists(&b, EdgeKind::ChildOf, &a).unwrap(),
        "b→a edge should not persist after cycle abort"
    );
}

#[test]
fn learned_range_rejects_corrupted_key_length() {
    let (_temp_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());

    vault
        .with_write_txn(|wtxn| {
            vault
                .store
                .temporal_learned
                .put(wtxn, &[0_u8; 23], &[])
                .unwrap();
            Ok(())
        })
        .unwrap();

    let result = vault.entities_in_learned_range(0, 10);
    assert!(
        matches!(result, Err(Error::CorruptedIndex("temporal learned key"))),
        "expected corrupted temporal learned key, got {result:?}"
    );
}

#[test]
fn learned_range_seek_starts_at_lower_bound() {
    let (_temp_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let id = EntityId::now();

    vault
        .with_write_txn(|wtxn| {
            vault
                .store
                .temporal_learned
                .put(wtxn, &[0_u8; 23], &[])
                .unwrap();
            Ok(())
        })
        .unwrap();
    vault
        .put_entity(&id, 1, TimeRange { start: 20, end: 20 }, 20, b"in-range")
        .unwrap();

    let result = vault.entities_in_learned_range(10, 30).unwrap();
    assert_eq!(result, vec![id]);
}

#[test]
fn sources_reject_corrupted_edge_key_length() {
    let (_temp_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let parent = EntityId::now();

    vault
        .batch()
        .put(
            &parent,
            ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            2,
            &task_body(),
        )
        .commit()
        .unwrap();

    let mut bad_key = Vec::with_capacity(32);
    bad_key.extend_from_slice(parent.as_bytes());
    bad_key.push(EdgeKind::ChildOf as u8);
    bad_key.extend_from_slice(&[0_u8; 15]);

    vault
        .with_write_txn(|wtxn| {
            vault
                .store
                .edges_in
                .put(wtxn, &bad_key, &[0_u8; EDGE_VALUE_STRUCTURAL_LEN])
                .unwrap();
            Ok(())
        })
        .unwrap();

    let result = vault.sources(&parent, EdgeKind::ChildOf, None);
    assert!(
        matches!(result, Err(Error::CorruptedIndex("edge record"))),
        "expected corrupted edge record, got {result:?}"
    );
}

#[test]
fn targets_reject_non_finite_persisted_edge_payload() {
    let (_temp_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let src = EntityId::now();
    let tgt = EntityId::now();
    let value = non_finite_edge_value(f32::NAN);

    vault
        .with_write_txn(|wtxn| {
            let key = Store::encode_edge_key(&src, EdgeKind::BelongsTo, &tgt);
            vault.store.edges_out.put(wtxn, &key, &value).unwrap();
            Ok(())
        })
        .unwrap();

    let result = vault.targets(&src, EdgeKind::BelongsTo, None);
    assert!(
        matches!(result, Err(Error::CorruptedIndex("edge record"))),
        "expected corrupted edge record, got {result:?}"
    );
}

#[test]
fn topology_reads_reject_truncated_persisted_edge_payload() {
    let (_temp_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let truncated_value = [0_u8; 11];

    let targets_src = EntityId::now();
    let targets_tgt = EntityId::now();
    let sources_src = EntityId::now();
    let sources_tgt = EntityId::now();
    let subtree_root = EntityId::now();
    let subtree_child = EntityId::now();
    let ancestor_child = EntityId::now();
    let ancestor_parent = EntityId::now();
    let cycle_node = EntityId::now();
    let cycle_target = EntityId::now();
    let cycle_parent = EntityId::now();

    vault
        .with_write_txn(|wtxn| {
            let targets_key =
                Store::encode_edge_key(&targets_src, EdgeKind::BelongsTo, &targets_tgt);
            let sources_key =
                Store::encode_edge_key(&sources_tgt, EdgeKind::BelongsTo, &sources_src);
            let subtree_key =
                Store::encode_edge_key(&subtree_root, EdgeKind::ChildOf, &subtree_child);
            let ancestor_key =
                Store::encode_edge_key(&ancestor_child, EdgeKind::ChildOf, &ancestor_parent);
            let cycle_key = Store::encode_edge_key(&cycle_target, EdgeKind::ChildOf, &cycle_parent);

            vault
                .store
                .edges_out
                .put(wtxn, &targets_key, &truncated_value)
                .unwrap();
            vault
                .store
                .edges_in
                .put(wtxn, &sources_key, &truncated_value)
                .unwrap();
            vault
                .store
                .edges_in
                .put(wtxn, &subtree_key, &truncated_value)
                .unwrap();
            vault
                .store
                .edges_out
                .put(wtxn, &ancestor_key, &truncated_value)
                .unwrap();
            vault
                .store
                .edges_out
                .put(wtxn, &cycle_key, &truncated_value)
                .unwrap();
            Ok(())
        })
        .unwrap();

    let targets_result = vault.targets(&targets_src, EdgeKind::BelongsTo, None);
    assert!(
        matches!(targets_result, Err(Error::CorruptedIndex("edge record"))),
        "expected corrupted edge record from targets, got {targets_result:?}"
    );

    let sources_result = vault.sources(&sources_tgt, EdgeKind::BelongsTo, None);
    assert!(
        matches!(sources_result, Err(Error::CorruptedIndex("edge record"))),
        "expected corrupted edge record from sources, got {sources_result:?}"
    );

    let subtree_result = vault.subtree(&subtree_root, 1);
    assert!(
        matches!(subtree_result, Err(Error::CorruptedIndex("edge record"))),
        "expected corrupted edge record from subtree, got {subtree_result:?}"
    );

    let ancestors_result = vault.ancestors(&ancestor_child);
    assert!(
        matches!(ancestors_result, Err(Error::CorruptedIndex("edge record"))),
        "expected corrupted edge record from ancestors, got {ancestors_result:?}"
    );

    let cycle_result = vault.would_create_cycle(&cycle_node, &cycle_target);
    assert!(
        matches!(cycle_result, Err(Error::CorruptedIndex("edge record"))),
        "expected corrupted edge record from cycle check, got {cycle_result:?}"
    );
}

#[test]
fn non_finite_edge_payload_rejected_by_all_read_paths() {
    // Per-case setup signature: open vault, mutate it to inject a non-finite payload.
    // Returned `EntityId` is the value the API under test will be called with.
    type SetupFn = fn(&Vault) -> EntityId;
    // Per-case API invocation signature: call the read path; returns the Result.
    // We unify the OK type as () since we never inspect it.
    type ApiFn = fn(&Vault, EntityId) -> Result<()>;

    let cases: &[(&str, SetupFn, ApiFn)] = &[
        // subtree: corrupt edges_in with NaN, then call subtree(root, 1)
        (
            "subtree",
            |vault| {
                let root = EntityId::now();
                let child = EntityId::now();
                let value = non_finite_edge_value(f32::NAN);
                vault
                    .with_write_txn(|wtxn| {
                        let key = Store::encode_edge_key(&root, EdgeKind::ChildOf, &child);
                        vault.store.edges_in.put(wtxn, &key, &value).unwrap();
                        Ok(())
                    })
                    .unwrap();
                root
            },
            |vault, root| vault.subtree(&root, 1).map(|_| ()),
        ),
        // ancestors: corrupt edges_out with NaN, then call ancestors(child)
        (
            "ancestors",
            |vault| {
                let child = EntityId::now();
                let parent = EntityId::now();
                let value = non_finite_edge_value(f32::NAN);
                vault
                    .with_write_txn(|wtxn| {
                        let key = Store::encode_edge_key(&child, EdgeKind::ChildOf, &parent);
                        vault.store.edges_out.put(wtxn, &key, &value).unwrap();
                        Ok(())
                    })
                    .unwrap();
                child
            },
            |vault, child| vault.ancestors(&child).map(|_| ()),
        ),
        // edges_out: commit entities, corrupt edges_out with NaN, then call edges_out(src)
        (
            "edges_out",
            |vault| {
                let src = EntityId::now();
                let tgt = EntityId::now();
                vault
                    .batch()
                    .put(
                        &src,
                        ENTITY_TYPE_TASK,
                        TimeRange { start: 1, end: 1 },
                        2,
                        &task_body(),
                    )
                    .put(
                        &tgt,
                        ENTITY_TYPE_TASK,
                        TimeRange { start: 1, end: 1 },
                        2,
                        &task_body(),
                    )
                    .commit()
                    .unwrap();
                let key = Store::encode_edge_key(&src, EdgeKind::ChildOf, &tgt);
                let value = non_finite_edge_value(f32::NAN);
                vault
                    .with_write_txn(|wtxn| {
                        vault.store.edges_out.put(wtxn, &key, &value).unwrap();
                        Ok(())
                    })
                    .unwrap();
                src
            },
            |vault, src| vault.edges_out(&src).map(|_| ()),
        ),
        // delete_entity: commit entities, corrupt BOTH edges_out and edges_in with INFINITY,
        // then call delete_entity(src). Note the variant uses f32::INFINITY (not NaN) to
        // preserve the original test's coverage of both non-finite forms.
        (
            "delete_entity",
            |vault| {
                let src = EntityId::now();
                let tgt = EntityId::now();
                vault
                    .batch()
                    .put(
                        &src,
                        ENTITY_TYPE_TASK,
                        TimeRange { start: 1, end: 1 },
                        2,
                        &task_body(),
                    )
                    .put(
                        &tgt,
                        ENTITY_TYPE_TASK,
                        TimeRange { start: 1, end: 1 },
                        2,
                        &task_body(),
                    )
                    .commit()
                    .unwrap();
                let key_out = Store::encode_edge_key(&src, EdgeKind::ChildOf, &tgt);
                let key_in = Store::encode_edge_key(&tgt, EdgeKind::ChildOf, &src);
                let value = non_finite_edge_value(f32::INFINITY);
                vault
                    .with_write_txn(|wtxn| {
                        vault.store.edges_out.put(wtxn, &key_out, &value).unwrap();
                        vault.store.edges_in.put(wtxn, &key_in, &value).unwrap();
                        Ok(())
                    })
                    .unwrap();
                src
            },
            |vault, src| vault.delete_entity(&src).map(|_| ()),
        ),
    ];

    for (name, setup, api) in cases {
        let (_temp_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let id = setup(&vault);
        let result = api(&vault, id);
        assert!(
            matches!(result, Err(Error::CorruptedIndex("edge record"))),
            "case {name}: expected corrupted edge record, got {result:?}"
        );
    }
}

#[test]
fn batch_in_put_failure_does_not_commit_partial_entity_update() {
    let (_temp_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let id = EntityId::now();
    let old_occurred = TimeRange { start: 10, end: 10 };
    let new_occurred = TimeRange { start: 20, end: 25 };

    vault
        .put_entity(&id, ENTITY_TYPE_TASK, old_occurred, 11, &task_body())
        .unwrap();
    let before_raw = vault.get_raw(&id).unwrap().unwrap();

    vault
        .with_write_txn(|wtxn| {
            vault
                .store
                .short_ids_reverse
                .put(wtxn, id.as_bytes(), &[1])
                .unwrap();
            Ok(())
        })
        .unwrap();

    vault
        .with_write_txn(|wtxn| {
            let err = vault
                .batch_in()
                .put(&id, ENTITY_TYPE_MACHINE, new_occurred, 21, b"new")
                .apply(wtxn)
                .expect_err("expected malformed short id value to fail");
            assert_matches!(err, Error::CorruptedIndex("short id value"));
            Ok(())
        })
        .unwrap();

    let after_raw = vault.get_raw(&id).unwrap().unwrap();
    assert_eq!(after_raw, before_raw);

    let rtxn = vault.store.env.read_txn().unwrap();
    let old_type_key = Store::encode_type_key(ENTITY_TYPE_TASK, &id);
    let new_type_key = Store::encode_type_key(ENTITY_TYPE_MACHINE, &id);
    let old_start_key = Store::encode_temporal_key(old_occurred.start, &id);
    let new_start_key = Store::encode_temporal_key(new_occurred.start, &id);
    let new_end_key = Store::encode_temporal_key(new_occurred.end, &id);
    let old_learned_key = Store::encode_temporal_key(11, &id);
    let new_learned_key = Store::encode_temporal_key(21, &id);

    assert!(
        vault
            .store
            .type_index
            .get(&rtxn, &old_type_key)
            .unwrap()
            .is_some()
    );
    assert!(
        vault
            .store
            .type_index
            .get(&rtxn, &new_type_key)
            .unwrap()
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &old_start_key)
            .unwrap()
            .is_some()
    );
    assert!(
        vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &new_start_key)
            .unwrap()
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &new_end_key)
            .unwrap()
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &old_learned_key)
            .unwrap()
            .is_some()
    );
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &new_learned_key)
            .unwrap()
            .is_none()
    );
}
