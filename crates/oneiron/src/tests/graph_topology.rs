//! Graph reads: type index, peers, hierarchy, cycles, child-of, learned-range scans.

use super::*;
use crate::error::RegistryError;

#[test]
fn entities_by_type_returns_correct_ids() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let tl1 = EntityId::now();
    let tl2 = EntityId::now();
    let tk1 = EntityId::now();

    vault
        .batch()
        .put(
            &tl1,
            ENTITY_TYPE_TASK_LIST,
            test_time_range(1, 1),
            2,
            b"project-1",
        )
        .put(
            &tl2,
            ENTITY_TYPE_TASK_LIST,
            test_time_range(3, 3),
            4,
            b"project-2",
        )
        .put(
            &tk1,
            ENTITY_TYPE_TASK,
            test_time_range(5, 5),
            6,
            &task_body(TaskRole::Task),
        )
        .commit()?;

    let task_lists = vault.entities_by_type(ENTITY_TYPE_TASK_LIST)?;
    assert_eq!(task_lists.len(), 2);
    assert!(task_lists.contains(&tl1));
    assert!(task_lists.contains(&tl2));

    let tasks = vault.entities_by_type(ENTITY_TYPE_TASK)?;
    assert_eq!(tasks.len(), 1);
    assert!(tasks.contains(&tk1));

    let empty = vault.entities_by_type(ENTITY_TYPE_MACHINE)?;
    assert!(empty.is_empty());
    Ok(())
}

#[test]
fn entities_by_type_rejects_corrupted_type_index_key() -> Result<()> {
    let entity_type = ENTITY_TYPE_TASK_LIST;

    {
        let (_dir, vault) = open_test_vault();
        let short_key = [entity_type, 0xaa];

        vault.with_write_txn(|wtxn| {
            vault.store.type_index.put(wtxn, &short_key, &[])?;
            Ok(())
        })?;

        let err = vault
            .entities_by_type(entity_type)
            .expect_err("short type index key should fail loud");
        assert_matches!(err, Error::CorruptedIndex("type index key"));
    }

    {
        let (_dir, vault) = open_test_vault();
        let mut reserved_id_key = [0_u8; 17];
        reserved_id_key[0] = entity_type;

        vault.with_write_txn(|wtxn| {
            vault.store.type_index.put(wtxn, &reserved_id_key, &[])?;
            Ok(())
        })?;

        let err = vault
            .entities_by_type(entity_type)
            .expect_err("reserved-id type index key should fail loud");
        assert_matches!(err, Error::CorruptedIndex("type index key"));
    }

    Ok(())
}

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
fn entities_by_type_page_paginates_past_materialization_cap() -> Result<()> {
    const TYPE_CAP: usize = 100_000;
    const EXTRA_ROWS: usize = 3;
    const PAGE_SIZE: usize = 4_096;

    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), large_test_config())?;

    vault.with_write_txn(|wtxn| {
        for i in 0..(TYPE_CAP + EXTRA_ROWS) {
            let id = seeded_entity_id(i as u128);
            let key = Store::encode_type_key(ENTITY_TYPE_TASK_LIST, &id);
            vault.store.type_index.put(wtxn, &key, &[])?;
        }
        Ok(())
    })?;

    let mut after = None;
    let mut first = None;
    let mut last = None;
    let mut total = 0;
    loop {
        let page = vault.entities_by_type_page(ENTITY_TYPE_TASK_LIST, after.as_ref(), PAGE_SIZE)?;
        let Some(page_last) = page.last().copied() else {
            break;
        };
        if let Some(previous) = after {
            assert!(previous < page[0]);
        }
        first.get_or_insert(page[0]);
        total += page.len();
        last = Some(page_last);
        after = Some(page_last);
    }

    assert_eq!(total, TYPE_CAP + EXTRA_ROWS);
    assert_eq!(first, Some(seeded_entity_id(0)));
    assert_eq!(
        last,
        Some(seeded_entity_id((TYPE_CAP + EXTRA_ROWS - 1) as u128))
    );
    assert!(
        vault
            .entities_by_type_page(
                ENTITY_TYPE_TASK_LIST,
                Some(&seeded_entity_id((TYPE_CAP + EXTRA_ROWS - 1) as u128)),
                PAGE_SIZE
            )?
            .is_empty()
    );
    assert!(
        vault
            .entities_by_type_page(ENTITY_TYPE_TASK_LIST, None, 0)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn latest_entity_bodies_by_type_returns_bounded_latest_snapshot_rows() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let old = seeded_entity_id(0x2140);
    let newest = seeded_entity_id(0x2141);
    let other_type = seeded_entity_id(0x2142);

    vault
        .batch()
        .put(
            &old,
            ENTITY_TYPE_NOTIFICATION,
            test_time_range(1, 1),
            10,
            b"old",
        )
        .put(
            &newest,
            ENTITY_TYPE_NOTIFICATION,
            test_time_range(2, 2),
            30,
            b"new",
        )
        .put(
            &other_type,
            ENTITY_TYPE_TASK,
            test_time_range(3, 3),
            40,
            &task_body(TaskRole::Task),
        )
        .commit()?;

    let latest = vault.latest_entity_bodies_by_type(ENTITY_TYPE_NOTIFICATION, 2, 3)?;
    assert_eq!(
        latest,
        vec![(newest, 30, b"new".to_vec()), (old, 10, b"old".to_vec())]
    );

    let scan_limited = vault.latest_entity_bodies_by_type(ENTITY_TYPE_NOTIFICATION, 2, 1)?;
    assert!(scan_limited.is_empty());

    let result_limited = vault.latest_entity_bodies_by_type(ENTITY_TYPE_NOTIFICATION, 1, 3)?;
    assert_eq!(result_limited, vec![(newest, 30, b"new".to_vec())]);

    Ok(())
}

#[test]
fn targets_and_sources_with_kind_filter() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let child = EntityId::now();
    let parent = EntityId::now();
    let sibling = EntityId::now();
    let task_list = EntityId::now();

    let batch = put_tree_nodes(vault.batch(), &[child, parent, sibling]);
    batch
        .put(
            &task_list,
            ENTITY_TYPE_TASK_LIST,
            test_time_range(7, 7),
            8,
            b"project",
        )
        .edge(&child, EdgeKind::ChildOf, &parent, 1.0)
        .edge(&sibling, EdgeKind::ChildOf, &parent, 1.0)
        .edge(&child, EdgeKind::BelongsTo, &task_list, 1.0)
        .commit()?;

    // targets(child, ChildOf) should return the parent
    let parents = vault.targets(&child, EdgeKind::ChildOf, None)?;
    assert_eq!(parents, vec![parent]);

    // sources(parent, ChildOf) should return both children
    let children = vault.sources(&parent, EdgeKind::ChildOf, None)?;
    assert_eq!(children.len(), 2);
    assert!(children.contains(&child));
    assert!(children.contains(&sibling));

    // targets with type filter: child's BelongsTo targets of task-list type
    let lists = vault.targets(&child, EdgeKind::BelongsTo, Some(ENTITY_TYPE_TASK_LIST))?;
    assert_eq!(lists, vec![task_list]);

    // targets with wrong type filter: should be empty
    let wrong = vault.targets(&child, EdgeKind::BelongsTo, Some(ENTITY_TYPE_TASK))?;
    assert!(wrong.is_empty());
    Ok(())
}

#[test]
fn targets_and_sources_overflow_when_peer_cap_exceeded() -> Result<()> {
    const EDGE_CAP: usize = 100_000;

    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), large_test_config())?;
    let src = seeded_entity_id(1);
    let tgt = seeded_entity_id(2);
    let value = valid_edge_value();

    vault.with_write_txn(|wtxn| {
        for i in 0..EDGE_CAP {
            let peer = seeded_entity_id(10 + i as u128);
            let out_key = Store::encode_edge_key(&src, EdgeKind::BelongsTo, &peer);
            let in_key = Store::encode_edge_key(&tgt, EdgeKind::BelongsTo, &peer);
            vault.store.edges_out.put(wtxn, &out_key, &value)?;
            vault.store.edges_in.put(wtxn, &in_key, &value)?;
        }
        Ok(())
    })?;

    assert_eq!(
        vault.targets(&src, EdgeKind::BelongsTo, None)?.len(),
        EDGE_CAP
    );
    assert_eq!(
        vault.sources(&tgt, EdgeKind::BelongsTo, None)?.len(),
        EDGE_CAP
    );

    let overflow_target = seeded_entity_id(10 + EDGE_CAP as u128);
    let overflow_source = seeded_entity_id(11 + EDGE_CAP as u128);
    vault.with_write_txn(|wtxn| {
        let out_key = Store::encode_edge_key(&src, EdgeKind::BelongsTo, &overflow_target);
        let in_key = Store::encode_edge_key(&tgt, EdgeKind::BelongsTo, &overflow_source);
        vault.store.edges_out.put(wtxn, &out_key, &value)?;
        vault.store.edges_in.put(wtxn, &in_key, &value)?;
        Ok(())
    })?;

    let targets_err = vault
        .targets(&src, EdgeKind::BelongsTo, None)
        .expect_err("targets should fail loud once cap is exceeded");
    assert_matches!(targets_err, Error::IndexOverflow("targets"));

    let sources_err = vault
        .sources(&tgt, EdgeKind::BelongsTo, None)
        .expect_err("sources should fail loud once cap is exceeded");
    assert_matches!(sources_err, Error::IndexOverflow("sources"));
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
fn subtree_four_level_tree() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // Build: root → child1 → grandchild → great_grandchild
    //             → child2
    let root = EntityId::now();
    let child1 = EntityId::now();
    let child2 = EntityId::now();
    let grandchild = EntityId::now();
    let great_grandchild = EntityId::now();

    let batch = put_tree_nodes(
        vault.batch(),
        &[root, child1, child2, grandchild, great_grandchild],
    );
    batch
        .edge(&child1, EdgeKind::ChildOf, &root, 1.0)
        .edge(&child2, EdgeKind::ChildOf, &root, 1.0)
        .edge(&grandchild, EdgeKind::ChildOf, &child1, 1.0)
        .edge(&great_grandchild, EdgeKind::ChildOf, &grandchild, 1.0)
        .commit()?;

    let tree = vault.subtree(&root, 10)?;
    assert_eq!(tree.len(), 4); // child1, child2, grandchild, great_grandchild

    // Verify depths
    let depth_of = |id: EntityId| tree.iter().find(|(i, _)| *i == id).map(|(_, d)| *d);
    assert_eq!(depth_of(child1), Some(1));
    assert_eq!(depth_of(child2), Some(1));
    assert_eq!(depth_of(grandchild), Some(2));
    assert_eq!(depth_of(great_grandchild), Some(3));

    // max_depth=1 should only return direct children
    let shallow = vault.subtree(&root, 1)?;
    assert_eq!(shallow.len(), 2);
    assert!(shallow.iter().all(|(_, d)| *d == 1));

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
fn cycle_prevention_rejects_self_parent() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let node = EntityId::now();
    vault.put_entity(
        &node,
        ENTITY_TYPE_TASK,
        test_time_range(1, 1),
        2,
        &task_body(TaskRole::Task),
    )?;

    assert!(vault.would_create_cycle(&node, &node)?);
    Ok(())
}

#[test]
fn cycle_prevention_detects_ancestor_cycle() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // A → B → C (ChildOf chain)
    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();

    put_tree_nodes(vault.batch(), &[a, b, c])
        .edge(&b, EdgeKind::ChildOf, &a, 1.0)
        .edge(&c, EdgeKind::ChildOf, &b, 1.0)
        .commit()?;

    // Making A a child of C would create A → B → C → A
    assert!(vault.would_create_cycle(&a, &c)?);

    // Making D a child of C is fine (D doesn't appear in C's ancestors)
    let d = EntityId::now();
    vault.put_entity(
        &d,
        ENTITY_TYPE_PERSON,
        test_time_range(7, 7),
        8,
        b"tree node",
    )?;
    assert!(!vault.would_create_cycle(&d, &c)?);

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
fn ancestors_and_cycle_checks_overflow_on_depth_cap() -> Result<()> {
    const ANCESTOR_CAP: usize = MAX_ANCESTOR_DEPTH;

    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), large_test_config())?;
    let value = valid_edge_value();

    let exact_nodes: Vec<_> = (0..=ANCESTOR_CAP)
        .map(|i| seeded_entity_id(1_000_000 + i as u128))
        .collect();

    vault.with_write_txn(|wtxn| {
        for [parent, child] in exact_nodes.array_windows::<2>() {
            let key = Store::encode_edge_key(child, EdgeKind::ChildOf, parent);
            vault.store.edges_out.put(wtxn, &key, &value)?;
        }
        Ok(())
    })?;

    let ancestors = vault.ancestors(&exact_nodes[ANCESTOR_CAP])?;
    assert_eq!(ancestors.len(), ANCESTOR_CAP);

    let overflow_root = seeded_entity_id(2_000_000);
    vault.with_write_txn(|wtxn| {
        let key = Store::encode_edge_key(&exact_nodes[0], EdgeKind::ChildOf, &overflow_root);
        vault.store.edges_out.put(wtxn, &key, &value)?;
        Ok(())
    })?;

    let anc_err = vault
        .ancestors(&exact_nodes[ANCESTOR_CAP])
        .expect_err("ancestors should fail loud once depth cap is exceeded");
    assert_matches!(anc_err, Error::IndexOverflow("ancestors"));

    let unrelated = seeded_entity_id(3_000_000);
    let cycle_err = vault
        .would_create_cycle(&unrelated, &exact_nodes[ANCESTOR_CAP])
        .expect_err("public cycle check should fail loud once depth cap is exceeded");
    assert_matches!(cycle_err, Error::IndexOverflow("child_of_cycle_check"));

    // The chain above is raw edge rows; the batch door now also demands that
    // the named parent be a real entity, so the overflow is what the walk
    // reports rather than a dangling-parent rejection (ONE-1376).
    let batch_err = put_tree_nodes(vault.batch(), &[exact_nodes[ANCESTOR_CAP]])
        .edge_checked(&unrelated, &exact_nodes[ANCESTOR_CAP], 1.0)
        .commit()
        .expect_err("batch cycle check should fail loud once depth cap is exceeded");
    assert_matches!(batch_err, Error::IndexOverflow("child_of_cycle_check"));
    Ok(())
}

#[test]
fn cycle_checks_fail_loud_before_positive_match_beyond_traversal_cap() -> Result<()> {
    const TRAVERSAL_CAP: usize = MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS;

    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), large_test_config())?;
    let value = valid_edge_value();

    let nodes: Vec<_> = (0..=TRAVERSAL_CAP + 1)
        .map(|i| seeded_entity_id(4_000_000 + i as u128))
        .collect();

    vault.with_write_txn(|wtxn| {
        for [parent, child] in nodes.array_windows::<2>() {
            let key = Store::encode_edge_key(child, EdgeKind::ChildOf, parent);
            vault.store.edges_out.put(wtxn, &key, &value)?;
        }
        Ok(())
    })?;

    let public_err = vault
        .would_create_cycle(&nodes[0], &nodes[TRAVERSAL_CAP + 1])
        .expect_err("public cycle check should overflow before reporting a deep positive match");
    assert_matches!(public_err, Error::IndexOverflow("child_of_cycle_check"));

    // Same as above: the parent must be a real row before the walk is the
    // thing that fails (ONE-1376 dangling-parent check runs first).
    let batch_err = put_tree_nodes(vault.batch(), &[nodes[TRAVERSAL_CAP + 1]])
        .edge_checked(&nodes[0], &nodes[TRAVERSAL_CAP + 1], 1.0)
        .commit()
        .expect_err("batch cycle check should overflow before reporting a deep positive match");
    assert_matches!(batch_err, Error::IndexOverflow("child_of_cycle_check"));
    Ok(())
}

#[test]
fn get_entity_type_returns_correct_type() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let tl = EntityId::now();
    let tk = EntityId::now();

    vault
        .batch()
        .put(&tl, ENTITY_TYPE_TASK_LIST, test_time_range(1, 1), 2, b"tl")
        .put(
            &tk,
            ENTITY_TYPE_TASK,
            test_time_range(3, 3),
            4,
            &task_body(TaskRole::Task),
        )
        .commit()?;

    assert_eq!(vault.get_entity_type(&tl)?, Some(ENTITY_TYPE_TASK_LIST));
    assert_eq!(vault.get_entity_type(&tk)?, Some(ENTITY_TYPE_TASK));
    assert_eq!(vault.get_entity_type(&EntityId::now())?, None);
    Ok(())
}

/// ONE-1100 AC1 — `child_of` is NEVER traversed by PPR (contract
/// `lambda: null`, "Not traversed."): a deep ChildOf chain carries zero
/// propagated mass from any seed, while the tree remains reachable through
/// the dedicated `subtree` / `ancestors` read APIs.
#[test]
fn child_of_chain_carries_no_ppr_mass() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // Build a 5-level deep ChildOf chain: e → d → c → b → a (child → parent).
    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();
    let d = EntityId::now();
    let e = EntityId::now();

    put_tree_nodes(vault.batch(), &[a, b, c, d, e])
        .edge(&b, EdgeKind::ChildOf, &a, 1.0)
        .edge(&c, EdgeKind::ChildOf, &b, 1.0)
        .edge(&d, EdgeKind::ChildOf, &c, 1.0)
        .edge(&e, EdgeKind::ChildOf, &d, 1.0)
        .commit()?;

    // PPR from e must reach NOTHING: the only edges are ChildOf, which carry
    // no PPR weight regardless of the stored 1.0 weight bytes.
    {
        let rtxn = vault.store.env.read_txn()?;
        let scores = ppr::ppr_compute(&vault.store, &rtxn, &[e], 6, 0.15)?;
        assert_eq!(
            scores.len(),
            1,
            "ChildOf must not propagate; only the seed may be scored"
        );
        assert_eq!(scores[0].id, e);
    }

    // The tree APIs — not PPR — are the ChildOf read path: the full ancestor
    // chain stays reachable.
    let ancestors = vault.ancestors(&e)?;
    assert_eq!(ancestors, vec![d, c, b, a]);

    // PartOf comparison: its traversal is hop-capped at 2, so p1 (4 hops from
    // p5) is blocked.
    let p1 = EntityId::now();
    let p2 = EntityId::now();
    let p3 = EntityId::now();
    let p4 = EntityId::now();
    let p5 = EntityId::now();

    vault
        .batch()
        .put(&p1, 9, test_time_range(1, 1), 2, b"p1")
        .put(&p2, 9, test_time_range(3, 3), 4, b"p2")
        .put(&p3, 9, test_time_range(5, 5), 6, b"p3")
        .put(&p4, 9, test_time_range(7, 7), 8, b"p4")
        .put(&p5, 9, test_time_range(9, 9), 10, b"p5")
        .edge(&p2, EdgeKind::PartOf, &p1, 1.0)
        .edge(&p3, EdgeKind::PartOf, &p2, 1.0)
        .edge(&p4, EdgeKind::PartOf, &p3, 1.0)
        .edge(&p5, EdgeKind::PartOf, &p4, 1.0)
        .commit()?;

    {
        let rtxn = vault.store.env.read_txn()?;
        let part_of_scores = ppr::ppr_compute(&vault.store, &rtxn, &[p5], 6, 0.15)?;
        let p1_score = part_of_scores
            .iter()
            .find(|s| s.id == p1)
            .map_or(0.0, |s| s.score);
        // p1 is 4 PartOf hops from p5 — should be blocked (only 2 PartOf hops allowed)
        assert!(
            p1_score < 1e-6,
            "PartOf should block at 3rd hop, but p1 got score={p1_score}"
        );
    }

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
fn txn_batch_child_of_reparent_is_order_independent() -> Result<()> {
    assert_reparent_order_independent(|vault, child, parent_a, parent_b| {
        vault.with_write_txn(|wtxn| {
            vault
                .batch_in()
                .edge(&child, EdgeKind::ChildOf, &parent_b, 1.0)
                .delete_edge(&child, EdgeKind::ChildOf, &parent_a)
                .apply(wtxn)
        })
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

#[test]
fn learned_at_accessor() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();
    let id = EntityId::now();
    let learned = 1_772_000_000u64;

    vault
        .put_entity(
            &id,
            1,
            TimeRange {
                start: learned,
                end: learned,
            },
            learned,
            b"first",
        )
        .unwrap();

    assert_eq!(vault.get_learned_at(&id).unwrap(), learned);
}

#[test]
fn entity_exists_and_edge_exists() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();
    let id = EntityId::now();
    let other = EntityId::now();

    assert!(!vault.entity_exists(&id).unwrap());

    vault
        .put_entity(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"exists")
        .unwrap();
    vault
        .put_entity(&other, 1, TimeRange { start: 1, end: 1 }, 1, b"other")
        .unwrap();

    assert!(vault.entity_exists(&id).unwrap());
    assert!(!vault.edge_exists(&id, EdgeKind::Mentions, &other).unwrap());

    vault
        .put_edge(&id, EdgeKind::Mentions, &other, 0.5)
        .unwrap();
    assert!(vault.edge_exists(&id, EdgeKind::Mentions, &other).unwrap());
}

#[test]
fn entities_in_learned_range() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();

    let id1 = EntityId::now();
    let id2 = EntityId::now();
    let id3 = EntityId::now();

    vault
        .put_entity(
            &id1,
            1,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"a",
        )
        .unwrap();
    vault
        .put_entity(
            &id2,
            1,
            TimeRange {
                start: 200,
                end: 200,
            },
            200,
            b"b",
        )
        .unwrap();
    vault
        .put_entity(
            &id3,
            1,
            TimeRange {
                start: 300,
                end: 300,
            },
            300,
            b"c",
        )
        .unwrap();

    let range = vault.entities_in_learned_range(100, 300).unwrap();
    assert_eq!(range.len(), 2);
    assert!(range.contains(&id1));
    assert!(range.contains(&id2));
    assert!(!range.contains(&id3));
}
