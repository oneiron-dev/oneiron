//! Graph reads: type index, peers, hierarchy, cycles, child-of, learned-range scans.

use super::*;
use crate::error::RegistryError;

#[test]
fn entities_by_type_allows_exact_cap_and_overflows_on_next_row() -> Result<()> {
    const TYPE_CAP: usize = 100_000;

    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), large_test_config())?;

    vault.with_write_txn(|wtxn| {
        for i in 0..TYPE_CAP {
            let id = seeded_entity_id(i as u128);
            let key = Store::encode_type_key(ENTITY_TYPE_TASK_LIST, &id);
            vault.store.type_index.put(wtxn, &key, &[])?;
        }
        Ok(())
    })?;

    let ids = vault.entities_by_type(ENTITY_TYPE_TASK_LIST)?;
    assert_eq!(ids.len(), TYPE_CAP);

    let overflow_id = seeded_entity_id(TYPE_CAP as u128);
    vault.with_write_txn(|wtxn| {
        let key = Store::encode_type_key(ENTITY_TYPE_TASK_LIST, &overflow_id);
        vault.store.type_index.put(wtxn, &key, &[])?;
        Ok(())
    })?;

    let err = vault
        .entities_by_type(ENTITY_TYPE_TASK_LIST)
        .expect_err("type scan should fail loud once cap is exceeded");
    assert_matches!(err, Error::IndexOverflow("entities_by_type"));
    Ok(())
}

#[test]
fn targets_and_sources_fail_loud_when_type_filter_overscans_peer_cap() -> Result<()> {
    const EDGE_CAP: usize = 100_000;

    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), large_test_config())?;
    let src = seeded_entity_id(100_000);
    let tgt = seeded_entity_id(200_000);
    let value = valid_edge_value();

    vault.with_write_txn(|wtxn| {
        for i in 0..EDGE_CAP {
            let peer = seeded_entity_id(300_000 + i as u128);
            let row = encoded_entity_record(ENTITY_TYPE_TASK, &task_body(TaskRole::Task));
            let out_key = Store::encode_edge_key(&src, EdgeKind::BelongsTo, &peer);
            let in_key = Store::encode_edge_key(&tgt, EdgeKind::BelongsTo, &peer);
            vault.store.entities.put(wtxn, peer.as_bytes(), &row)?;
            vault.store.edges_out.put(wtxn, &out_key, &value)?;
            vault.store.edges_in.put(wtxn, &in_key, &value)?;
        }

        let matching_peer = seeded_entity_id(400_001);
        let matching_row = encoded_entity_record(ENTITY_TYPE_TASK_LIST, b"peer");
        let out_key = Store::encode_edge_key(&src, EdgeKind::BelongsTo, &matching_peer);
        let in_key = Store::encode_edge_key(&tgt, EdgeKind::BelongsTo, &matching_peer);
        vault
            .store
            .entities
            .put(wtxn, matching_peer.as_bytes(), &matching_row)?;
        vault.store.edges_out.put(wtxn, &out_key, &value)?;
        vault.store.edges_in.put(wtxn, &in_key, &value)?;
        Ok(())
    })?;

    let targets_err = vault
        .targets(&src, EdgeKind::BelongsTo, Some(ENTITY_TYPE_TASK_LIST))
        .expect_err("type-filtered targets should fail loud once scan cap is exceeded");
    assert_matches!(targets_err, Error::IndexOverflow("targets"));

    let sources_err = vault
        .sources(&tgt, EdgeKind::BelongsTo, Some(ENTITY_TYPE_TASK_LIST))
        .expect_err("type-filtered sources should fail loud once scan cap is exceeded");
    assert_matches!(sources_err, Error::IndexOverflow("sources"));
    Ok(())
}

#[test]
fn subtree_allows_exact_cap_and_overflows_on_next_descendant() -> Result<()> {
    const SUBTREE_CAP: usize = 50_000;

    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), large_test_config())?;
    let root = seeded_entity_id(1);
    let value = valid_edge_value();

    vault.with_write_txn(|wtxn| {
        for i in 0..SUBTREE_CAP {
            let child = seeded_entity_id(100 + i as u128);
            let key = Store::encode_edge_key(&root, EdgeKind::ChildOf, &child);
            vault.store.edges_in.put(wtxn, &key, &value)?;
        }
        Ok(())
    })?;

    let tree = vault.subtree(&root, 1)?;
    assert_eq!(tree.len(), SUBTREE_CAP);

    let overflow_child = seeded_entity_id(100 + SUBTREE_CAP as u128);
    vault.with_write_txn(|wtxn| {
        let key = Store::encode_edge_key(&root, EdgeKind::ChildOf, &overflow_child);
        vault.store.edges_in.put(wtxn, &key, &value)?;
        Ok(())
    })?;

    let err = vault
        .subtree(&root, 1)
        .expect_err("subtree should fail loud once cap is exceeded");
    assert_matches!(err, Error::IndexOverflow("subtree"));
    Ok(())
}

#[test]
fn test_deep_ancestor_chain() -> Result<()> {
    // Build a 200-deep ChildOf chain: node[0] ← node[1] ← ... ← node[200]
    // (each node[i+1] --ChildOf--> node[i])
    const DEPTH: usize = 200;

    let (_dir, vault) = open_test_vault();
    let mut nodes = Vec::with_capacity(DEPTH + 1);
    for _ in 0..=DEPTH {
        nodes.push(EntityId::now());
    }

    // Put all entities
    {
        let mut batch = put_tree_nodes(vault.batch(), &nodes);
        // Build ChildOf edges: node[i+1] --ChildOf--> node[i]
        for [parent, child] in nodes.array_windows::<2>() {
            batch = batch.edge(child, EdgeKind::ChildOf, parent, 1.0);
        }
        batch.commit()?;
    }

    // ancestors(node[200]) should return all 200 ancestors: node[199], ..., node[0]
    let anc = vault.ancestors(&nodes[DEPTH])?;
    assert_eq!(
        anc.len(),
        DEPTH,
        "expected {DEPTH} ancestors, got {}",
        anc.len()
    );
    // Verify order: nearest first (node[199]) to root (node[0])
    for (i, ancestor) in anc.iter().enumerate() {
        assert_eq!(
            *ancestor,
            nodes[DEPTH - 1 - i],
            "ancestor at position {i} should be node[{}]",
            DEPTH - 1 - i
        );
    }

    // would_create_cycle: making node[0] a child of node[200] would create a cycle
    assert!(vault.would_create_cycle(&nodes[0], &nodes[DEPTH])?);

    // would_create_cycle: an unrelated node should not create a cycle
    let unrelated = EntityId::now();
    vault.put_entity(
        &unrelated,
        ENTITY_TYPE_PERSON,
        test_time_range(999, 999),
        1000,
        b"tree node",
    )?;
    assert!(!vault.would_create_cycle(&unrelated, &nodes[DEPTH])?);

    Ok(())
}

#[test]
fn generic_child_of_writes_reject_cycles() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();

    put_tree_nodes(vault.batch(), &[a, b, c])
        .edge(&b, EdgeKind::ChildOf, &a, 1.0)
        .edge(&c, EdgeKind::ChildOf, &b, 1.0)
        .commit()?;

    let err = vault
        .put_edge(&a, EdgeKind::ChildOf, &c, 1.0)
        .expect_err("generic ChildOf write should reject cycles");
    assert_matches!(err, Error::Registry(RegistryError::CycleDetected));
    assert!(!vault.edge_exists(&a, EdgeKind::ChildOf, &c)?);
    Ok(())
}

#[test]
fn generic_child_of_writes_reject_second_parent() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let child = EntityId::now();
    let parent_a = EntityId::now();
    let parent_b = EntityId::now();

    put_tree_nodes(vault.batch(), &[child, parent_a, parent_b])
        .edge(&child, EdgeKind::ChildOf, &parent_a, 1.0)
        .commit()?;

    let err = vault
        .batch()
        .edge(&child, EdgeKind::ChildOf, &parent_b, 1.0)
        .commit()
        .expect_err("generic ChildOf write should reject second parent");
    assert_matches!(err, Error::Registry(RegistryError::ChildOfCardinality));
    assert!(!vault.edge_exists(&child, EdgeKind::ChildOf, &parent_b)?);

    vault.put_edge(&child, EdgeKind::ChildOf, &parent_a, 0.5)?;
    let parents = vault.targets(&child, EdgeKind::ChildOf, None)?;
    assert_eq!(parents, vec![parent_a]);
    Ok(())
}

#[test]
fn generic_child_of_reparent_is_order_independent() -> Result<()> {
    assert_reparent_order_independent(|vault, child, parent_a, parent_b| {
        vault
            .batch()
            .edge(&child, EdgeKind::ChildOf, &parent_b, 1.0)
            .delete_edge(&child, EdgeKind::ChildOf, &parent_a)
            .commit()
    })
}

#[test]
fn child_of_batch_allows_add_delete_then_reverse_edge() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let a = EntityId::now();
    let b = EntityId::now();

    put_tree_nodes(vault.batch(), &[a, b])
        .edge(&a, EdgeKind::ChildOf, &b, 1.0)
        .delete_edge(&a, EdgeKind::ChildOf, &b)
        .edge(&b, EdgeKind::ChildOf, &a, 1.0)
        .commit()?;

    assert!(!vault.edge_exists(&a, EdgeKind::ChildOf, &b)?);
    assert!(vault.edge_exists(&b, EdgeKind::ChildOf, &a)?);
    Ok(())
}

#[test]
fn edge_checked_detects_cycle_atomically() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // Build: a → b → c (ChildOf chain)
    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();

    put_tree_nodes(vault.batch(), &[a, b, c])
        .edge(&b, EdgeKind::ChildOf, &a, 1.0)
        .edge(&c, EdgeKind::ChildOf, &b, 1.0)
        .commit()?;

    // Try to make a a child of c — would create cycle a→b→c→a
    let result = vault.batch().edge_checked(&a, &c, 1.0).commit();
    assert!(
        matches!(result, Err(Error::Registry(RegistryError::CycleDetected))),
        "expected CycleDetected, got {result:?}"
    );

    // Verify the rejected edge was not written
    assert!(
        !vault.edge_exists(&a, EdgeKind::ChildOf, &c)?,
        "cyclic edge should not have been persisted"
    );

    // Non-cyclic edge should succeed
    let d = EntityId::now();
    put_tree_nodes(vault.batch(), &[d])
        .edge_checked(&d, &c, 1.0)
        .commit()?;

    // Verify d is a child of c
    let children = vault.sources(&c, EdgeKind::ChildOf, None)?;
    assert!(children.contains(&d));

    Ok(())
}

#[test]
fn edge_checked_rejects_self_cycle() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let node = EntityId::now();

    vault
        .batch()
        .put(
            &node,
            ENTITY_TYPE_TASK,
            test_time_range(1, 1),
            2,
            &task_body(TaskRole::Task),
        )
        .commit()?;

    let result = vault.batch().edge_checked(&node, &node, 1.0).commit();
    assert!(
        matches!(result, Err(Error::Registry(RegistryError::CycleDetected))),
        "self-cycle should be rejected, got {result:?}"
    );
    assert!(
        !vault.edge_exists(&node, EdgeKind::ChildOf, &node)?,
        "self-cycle edge should not have been persisted"
    );

    Ok(())
}
