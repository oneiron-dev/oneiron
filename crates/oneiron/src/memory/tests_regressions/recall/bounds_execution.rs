/// Builds a distinct, non-reserved entity id from a counter for bulk index
/// seeding (avoids the crate-root test helper, which is module-private).
fn seeded_bulk_id(tag: u8, counter: usize) -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&(counter as u64 + 1).to_le_bytes());
    bytes[15] = tag;
    EntityId::from_bytes(bytes).expect("seeded id is never reserved")
}

/// #482a regression: world-scoped recall enumerates out-of-scope worlds with
/// the bounded page primitive, so a CLAIM index larger than the
/// materialization ceiling does not hard-fail. The old
/// `entities_by_type().take(cap)` path errored with IndexOverflow before the
/// take could run.
#[test]
fn recall_scope_honesty_stays_bounded_on_a_large_claim_index() {
    use crate::registry::ENTITY_TYPE_CLAIM;
    use crate::store::Store;

    // One past MAX_TYPE_QUERY_RESULTS (module-private const, mirrored here).
    const OVER_MATERIALIZATION_CAP: usize = 100_000 + 1;

    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x5C);
    let facade = facade_for(&vault, actor);

    vault
        .with_write_txn(|wtxn| {
            for i in 0..OVER_MATERIALIZATION_CAP {
                let id = seeded_bulk_id(0xC1, i);
                let key = Store::encode_type_key(ENTITY_TYPE_CLAIM, &id);
                vault.store.type_index.put(wtxn, &key, &[])?;
            }
            Ok(())
        })
        .expect("seed claim type index");

    let world = EntityId::from_bytes([0x5D; 16]).unwrap();
    let pack = facade
        .recall(
            "anything",
            Effort::Medium,
            &RecallScope {
                world_ref: Some(world.to_hex()),
                facet: None,
                kinds: None,
            },
            5,
            None,
            None,
        )
        .expect("world-scoped recall must not hard-fail on a large claim index");
    assert!(
        pack.scope_honesty.out_of_scope_worlds.is_empty(),
        "no surfaceable out-of-scope claims among the bounded scan window"
    );
}

/// #482b regression: neighbors bounds the edge scan by `limit`, so a node with
/// more edges than the full-materialization ceiling returns a bounded result
/// instead of IndexOverflow. The old `edges_out()`/`edges_in()` path
/// materialized every edge up front.
#[test]
fn neighbors_stays_bounded_on_a_high_degree_node() {
    use crate::store::Store;

    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x5E);
    let center = put_person(&vault, 0x5F);
    let facade = facade_for(&vault, actor);

    // One past the edge materialization ceiling on a single source node.
    let edge_count = crate::vault::MAX_EDGE_QUERY_RESULTS + 1;
    let mut value = [0u8; 12];
    value[0..4].copy_from_slice(&0.9_f32.to_le_bytes());
    value[4..12].copy_from_slice(&1_u64.to_le_bytes());
    vault
        .with_write_txn(|wtxn| {
            let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, wtxn, &center)?
                .expect("readable person fixture")
                .to_vec();
            for i in 0..edge_count {
                let target = seeded_bulk_id(0xE1, i);
                // Neighbor visibility requires a real readable destination;
                // dangling edges are not a substitute for a high-degree graph.
                vault.store.entities.put(wtxn, target.as_bytes(), &raw)?;
                let key = Store::encode_edge_key(&center, EdgeKind::BelongsTo, &target);
                vault.store.edges_out.put(wtxn, &key, &value)?;
            }
            Ok(())
        })
        .expect("seed high-degree edges");

    let hits = facade
        .neighbors(
            &center.to_hex(),
            &NeighborOpts {
                edge_kind: None,
                min_weight: None,
                limit: 5,
            },
        )
        .expect("neighbors must not hard-fail on a high-degree node");
    assert_eq!(hits.len(), 5, "bounded by limit, not the full edge set");
    assert!(hits.iter().all(|hit| hit.direction == "out"));
}

#[test]
fn recall_raw_deadline_cuts_graph_expansion_but_keeps_direct_hits() {
    use crate::retrieval_depth::{RecallExecution, RetrievalDeadline};
    use std::sync::Arc;
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x71);
    let facade = facade_for(&vault, actor);
    let anchor = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "EVENT".into(),
            body: serde_json::json!({"name": "deadlineanchor"}),
            text_fields: Some(vec![TextIndexField {
                field: "name".into(),
                value: "deadlineanchor".into(),
            }]),
            edges: None,
            occurred_at: 1,
            learned_at: None,
        })
        .unwrap();
    let neighbor = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "EVENT".into(),
            body: serde_json::json!({"name": "graphneighbor"}),
            text_fields: None,
            edges: None,
            occurred_at: 1,
            learned_at: None,
        })
        .unwrap();
    let anchor_id = EntityId::from_hex(&anchor.id_hex).unwrap();
    let neighbor_id = EntityId::from_hex(&neighbor.id_hex).unwrap();
    vault
        .batch()
        .edge(&anchor_id, crate::EdgeKind::Mentions, &neighbor_id, 1.0)
        .commit()
        .unwrap();
    let complete = facade
        .recall(
            "deadlineanchor",
            Effort::Medium,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .unwrap();
    assert!(
        complete
            .items
            .iter()
            .any(|item| item.value_text.contains("graphneighbor"))
    );
    let deadline = Arc::new(RetrievalDeadline::at(
        std::time::Instant::now() + std::time::Duration::from_secs(60),
    ));
    let cut = deadline.clone();
    *vault.test_hooks().after_retrieval_text.lock().unwrap() = Some(Box::new(move || cut.cancel()));
    let partial = facade
        .recall_with_execution(
            "deadlineanchor",
            Effort::Medium,
            &RecallScope::default(),
            10,
            None,
            None,
            &RecallExecution {
                deadline: Some(&deadline),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(partial.retrieval_meta.partial);
    assert!(deadline.was_cut_short());
    assert!(
        partial
            .items
            .iter()
            .any(|item| item.value_text.contains("deadlineanchor"))
    );
    assert!(
        !partial
            .items
            .iter()
            .any(|item| item.value_text.contains("graphneighbor"))
    );
}

#[test]
fn recall_sparse_reports_completed_vector_execution_in_both_paths() {
    use crate::retrieval_depth::{RecallExecution, RetrievalDeadline};
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x71);
    let facade = facade_for(&vault, actor);
    let facet = EntityId::now();
    vault
        .put_entity(
            &facet,
            crate::registry::ENTITY_TYPE_FACET,
            crate::TimeRange { start: 1, end: 1 },
            1,
            b"facet",
        )
        .unwrap();
    let embedding = vec![1.0; vault.config.dimensions];
    for facet in [None, Some(facet.to_hex())] {
        let scope = RecallScope {
            facet,
            ..Default::default()
        };
        for mode in [0, 1, 2] {
            let deadline = RetrievalDeadline::at(if mode == 0 {
                std::time::Instant::now() - std::time::Duration::from_secs(1)
            } else {
                std::time::Instant::now() + std::time::Duration::from_secs(60)
            });
            if mode == 1 {
                deadline.cancel();
            }
            let pack = facade
                .recall_with_execution(
                    "no matching text",
                    Effort::Light,
                    &scope,
                    10,
                    None,
                    None,
                    &RecallExecution {
                        embedding: Some(&embedding),
                        deadline: Some(&deadline),
                        ..Default::default()
                    },
                )
                .unwrap();
            assert_eq!(pack.retrieval_meta.sparse, Some(mode != 2));
            assert_eq!(pack.retrieval_meta.partial, mode != 2);
        }
    }
}

// Two identical lexical hits: only the occurred time should decide the window.
