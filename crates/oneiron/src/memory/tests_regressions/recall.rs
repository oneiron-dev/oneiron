//! BRIDGE-02 retrieval surface regressions: BM25, neighbors, recall packs, scope honesty, limits.

use super::*;

// ═══ BRIDGE-02 (ONE-1455): query surface ═══════════════════════════════

#[test]
fn query_bm25_ranks_exact_match_above_partial() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x17);
    let facade = facade_for(&vault, actor);

    let conversation = EntityId::from_bytes([0x18; 16]).unwrap().to_hex();
    facade
        .witness(&WitnessTurn {
            conversation_ref: conversation,
            turn_ref: None,
            messages: vec![
                witness_message(0, WitnessAuthor::User, "solar panel maintenance guide"),
                witness_message(1, WitnessAuthor::User, "solar flare forecast"),
            ],
            occurred_at: 1300,
        })
        .expect("witness");

    let hits = facade.query_bm25("solar panel", 10).expect("bm25");
    assert!(hits.len() >= 2, "both docs match the shared term");
    assert!(
        hits[0]
            .snippet
            .as_deref()
            .is_some_and(|s| s.contains("panel")),
        "exact-term doc must rank first; got snippet {:?}",
        hits[0].snippet
    );
    for pair in hits.windows(2) {
        assert!(pair[0].score >= pair[1].score, "scores must be monotonic");
    }
    assert!(
        hits[0].score > hits[1].score,
        "exact match outranks partial"
    );
    assert_eq!(hits[0].kind, "MESSAGE");
}

#[test]
fn neighbors_filters_by_weight_and_kind() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x19);
    let facade = facade_for(&vault, actor);

    let strong = put_person(&vault, 0x1A);
    let weak = put_person(&vault, 0x1B);
    let attached = put_person(&vault, 0x1C);
    let anchor = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "EVENT".to_owned(),
            body: serde_json::json!({"name": "hanami"}),
            text_fields: None,
            edges: Some(vec![
                StructuralEdgeSpec {
                    edge_kind: "mentions".to_owned(),
                    target_ref: strong.to_hex(),
                    weight: Some(0.9),
                },
                StructuralEdgeSpec {
                    edge_kind: "mentions".to_owned(),
                    target_ref: weak.to_hex(),
                    weight: Some(0.2),
                },
                StructuralEdgeSpec {
                    edge_kind: "attached".to_owned(),
                    target_ref: attached.to_hex(),
                    weight: Some(0.8),
                },
            ]),
            occurred_at: 1400,
            learned_at: None,
        })
        .expect("anchor");

    // Kind + weight filters, engine-side.
    let hits = facade
        .neighbors(
            &anchor.id_hex,
            &NeighborOpts {
                edge_kind: Some("mentions".to_owned()),
                min_weight: Some(0.5),
                limit: 10,
            },
        )
        .expect("neighbors");
    assert_eq!(hits.len(), 1, "weak mention and attached edge filtered out");
    let hydrated = facade
        .hydrate(std::slice::from_ref(&hits[0].short_id))
        .expect("hit hydrates");
    assert_eq!(hydrated[0].id_hex, strong.to_hex());
    assert!((hits[0].weight - 0.9).abs() < 1e-6, "weight equals stored");
    assert_eq!(hits[0].edge_kind, "mentions");
    assert_eq!(hits[0].direction, "out");

    // Inbound direction from the target's side.
    let inbound = facade
        .neighbors(
            &strong.to_hex(),
            &NeighborOpts {
                edge_kind: Some("mentions".to_owned()),
                min_weight: None,
                limit: 10,
            },
        )
        .expect("inbound neighbors");
    let inbound_hit = inbound
        .iter()
        .find(|hit| hit.direction == "in")
        .expect("anchor visible as inbound neighbor");
    let hydrated = facade
        .hydrate(std::slice::from_ref(&inbound_hit.short_id))
        .expect("inbound hit hydrates");
    assert_eq!(hydrated[0].id_hex, anchor.id_hex);

    // Unknown edge kind fails closed.
    let err = facade
        .neighbors(
            &anchor.id_hex,
            &NeighborOpts {
                edge_kind: Some("linked".to_owned()),
                min_weight: None,
                limit: 10,
            },
        )
        .expect_err("unknown edge kind");
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);
}

#[test]
fn recall_returns_versioned_pack_with_provenance() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x1D);
    let facade = facade_for(&vault, actor);

    facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x1E; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: vec![witness_message(
                0,
                WitnessAuthor::User,
                "aurora borealis sighting over the fjord",
            )],
            occurred_at: 1500,
        })
        .expect("witness");

    for effort in [Effort::Light, Effort::Medium] {
        let pack = facade
            .recall("aurora", effort, &RecallScope::default(), 10, None, None)
            .expect("recall");
        assert_eq!(pack.pack_version, 1);
        assert!(!pack.items.is_empty(), "{effort:?} finds the message");
        for item in &pack.items {
            assert!(!item.provenance.source.is_empty());
            assert!(!item.provenance.source_revision_ids.is_empty());
            assert!(!item.hedge_bucket.is_empty());
        }
        assert_eq!(pack.retrieval_meta.sparse, Some(true));
        assert!(pack.retrieval_meta.deep_pending.is_none());
        assert!(pack.retrieval_meta.total_candidates >= 1);
    }

    // MESSAGE items carry their TURN as structural evidence.
    let pack = facade
        .recall(
            "aurora",
            Effort::Medium,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("recall");
    let message_item = pack
        .items
        .iter()
        .find(|item| item.kind == "MESSAGE")
        .expect("message item");
    assert!(!message_item.provenance.evidence_turn_ids.is_empty());
}

#[test]
fn recall_scope_honesty_lists_excluded_worlds() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x23);
    let facade = facade_for(&vault, actor);

    // The subject is MINTED through the structural door carrying its text
    // field, rather than pre-created and then overwritten: ONE-1889 made the
    // door create-only, and one create reaches the same state.
    let subject = EntityId::from_hex(
        &facade
            .put_structural(&StructuralPutInput {
                id: None,
                kind: "PERSON".to_owned(),
                body: serde_json::json!({"name": "atlantis explorer"}),
                text_fields: Some(vec![TextIndexField {
                    field: "name".to_owned(),
                    value: "atlantis explorer".to_owned(),
                }]),
                edges: None,
                occurred_at: 1600,
                learned_at: None,
            })
            .expect("subject text")
            .id_hex,
    )
    .expect("subject id");

    let world_one = EntityId::from_bytes([0x25; 16]).unwrap();
    let world_two = EntityId::from_bytes([0x26; 16]).unwrap();
    let mut input = claim_input(
        "profile.city",
        &subject,
        "user_stated",
        serde_json::json!("sunken city of gold"),
    );
    input.world_ref = Some(world_two.to_hex());
    let receipt = facade.claim_upsert(&input).expect("world claim");
    assert_eq!(receipt.approval, "auto");

    // Scoped to world ONE: world TWO is honestly reported as excluded and
    // its claim never appears in items (AC-4 narrowing).
    let pack = facade
        .recall(
            "atlantis",
            Effort::Medium,
            &RecallScope {
                world_ref: Some(world_one.to_hex()),
                facet: None,
            },
            10,
            None,
            None,
        )
        .expect("scoped recall");
    assert_eq!(
        pack.scope_honesty.out_of_scope_worlds,
        vec![world_two.to_hex()],
        "excluded world listed in scope honesty"
    );
    assert!(
        !pack
            .items
            .iter()
            .any(|item| item.world.as_deref() == Some(world_two.to_hex().as_str())),
        "out-of-world claim excluded from items"
    );

    // Vault floor (unset scope) excludes nothing.
    let floor = facade
        .recall(
            "atlantis",
            Effort::Medium,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("floor recall");
    assert!(floor.scope_honesty.out_of_scope_worlds.is_empty());
}

#[test]
fn recall_deep_requires_lease_and_marks_pending() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x27);
    let facade = facade_for(&vault, actor);

    let err = facade
        .recall(
            "anything",
            Effort::High,
            &RecallScope::default(),
            5,
            None,
            None,
        )
        .expect_err("deep without lease");
    assert_eq!(err.code, MEMORY_CODE_LEASE_REQUIRED);

    let lease = crate::llm::BudgetLease::for_test("recall-spike");
    let error = facade
        .recall(
            "anything",
            Effort::High,
            &RecallScope::default(),
            5,
            None,
            Some(&lease),
        )
        .expect_err("paid tier without a prepared scorer must not execute a lower tier");
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
}

#[test]
fn recall_and_query_verbs_respect_limits() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x28);
    let facade = facade_for(&vault, actor);

    // Seed limit + 3 matching docs (limit = 2).
    let messages = (0..5)
        .map(|i| witness_message(i, WitnessAuthor::User, &format!("pelican count {i}")))
        .collect();
    facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x29; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages,
            occurred_at: 1700,
        })
        .expect("witness");

    assert_eq!(facade.query_bm25("pelican", 2).expect("bm25").len(), 2);
    assert_eq!(
        facade
            .recall(
                "pelican",
                Effort::Light,
                &RecallScope::default(),
                2,
                None,
                None
            )
            .expect("recall")
            .items
            .len(),
        2
    );

    // Neighbors limit: an anchor with 5 outgoing edges returns exactly 2.
    let targets: Vec<String> = (0x30..0x35_u8)
        .map(|seed| put_person(&vault, seed).to_hex())
        .collect();
    let anchor = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "EVENT".to_owned(),
            body: serde_json::json!({"name": "flock"}),
            text_fields: None,
            edges: Some(
                targets
                    .iter()
                    .map(|target| StructuralEdgeSpec {
                        edge_kind: "mentions".to_owned(),
                        target_ref: target.clone(),
                        weight: Some(0.7),
                    })
                    .collect(),
            ),
            occurred_at: 1701,
            learned_at: None,
        })
        .expect("anchor");
    assert_eq!(
        facade
            .neighbors(
                &anchor.id_hex,
                &NeighborOpts {
                    edge_kind: None,
                    min_weight: None,
                    limit: 2,
                },
            )
            .expect("neighbors")
            .len(),
        2
    );
}

#[test]
fn recall_confidence_is_absolute_across_candidate_sets() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x36);
    let facade = facade_for(&vault, actor);

    // Minted through the create-only door with its text field (ONE-1889),
    // rather than pre-created and overwritten.
    let subject = EntityId::from_hex(
        &facade
            .put_structural(&StructuralPutInput {
                id: None,
                kind: "PERSON".to_owned(),
                body: serde_json::json!({"name": "quokka researcher"}),
                text_fields: Some(vec![TextIndexField {
                    field: "name".to_owned(),
                    value: "quokka researcher".to_owned(),
                }]),
                edges: None,
                occurred_at: 1800,
                learned_at: None,
            })
            .expect("subject")
            .id_hex,
    )
    .expect("subject id");
    let mut input = claim_input(
        "profile.name",
        &subject,
        "user_stated",
        serde_json::json!("Quokka"),
    );
    input.confidence = 0.8;
    facade.claim_upsert(&input).expect("claim");

    let find_claim_confidence = |pack: &MemoryPack| {
        pack.items
            .iter()
            .find(|item| item.kind == "CLAIM")
            .map(|item| item.confidence)
    };

    let first = facade
        .recall(
            "quokka",
            Effort::Medium,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("first recall");
    let first_confidence = find_claim_confidence(&first);

    // Grow the candidate set, then recall again: the same claim must carry
    // the identical calibrated-absolute confidence (never set-relative).
    let extra = (0..4)
        .map(|i| witness_message(i, WitnessAuthor::User, &format!("quokka field note {i}")))
        .collect();
    facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x38; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: extra,
            occurred_at: 1801,
        })
        .expect("extra docs");
    let second = facade
        .recall(
            "quokka",
            Effort::Medium,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("second recall");
    let second_confidence = find_claim_confidence(&second);

    assert!(
        first_confidence.is_some() && second_confidence.is_some(),
        "claim surfaces in both packs (first: {first_confidence:?}, second: {second_confidence:?})"
    );
    assert_eq!(first_confidence, second_confidence);
    assert!(
        (first_confidence.unwrap() - 0.8).abs() < 1e-6,
        "absolute value from the body"
    );
}

#[test]
fn recall_short_ids_hydrate_and_formats_render() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x39);
    let facade = facade_for(&vault, actor);

    facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x3A; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: vec![witness_message(
                0,
                WitnessAuthor::User,
                "ceramic kiln firing log",
            )],
            occurred_at: 1900,
        })
        .expect("witness");

    let pack = facade
        .recall(
            "ceramic",
            Effort::Medium,
            &RecallScope::default(),
            10,
            Some("md"),
            None,
        )
        .expect("recall");
    assert!(pack.rendered.as_deref().is_some_and(|r| !r.is_empty()));

    // Every shortId round-trips through hydrate (OF-096).
    let refs: Vec<String> = pack
        .items
        .iter()
        .map(|item| item.short_id.clone())
        .collect();
    assert!(!refs.is_empty());
    let views = facade.hydrate(&refs).expect("hydrate round-trip");
    assert_eq!(views.len(), refs.len());

    // BM25 hits hydrate too.
    let hits = facade.query_bm25("ceramic", 5).expect("bm25");
    let refs: Vec<String> = hits.iter().map(|hit| hit.short_id.clone()).collect();
    assert_eq!(facade.hydrate(&refs).expect("hydrate").len(), hits.len());

    // Unknown format fails closed.
    let err = facade
        .recall(
            "ceramic",
            Effort::Medium,
            &RecallScope::default(),
            10,
            Some("docx"),
            None,
        )
        .expect_err("unknown format");
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);
}

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
            let raw = vault
                .store
                .entities
                .get(wtxn, center.as_bytes())?
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

/// ARCH-0004: the blend over recency, salience, confidence and gravity is
/// constant at every effort level. The effort's default now anchor is no
/// host window, so it must not switch recency off. Two identical messages
/// tie on every other blend column; the older one is written first and so
/// holds the lower id, which is the order a recall without recency returns.
#[test]
fn recall_default_effort_ranks_the_newer_identical_message_first() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x61);
    let facade = facade_for(&vault, actor);
    let now = crate::unix_seconds_now();
    let text = "I prefer a window seat when I fly.";
    let mut witnessed = Vec::new();
    for (seed, days_ago) in [(0x62, 56), (0x63, 28)] {
        let receipt = facade
            .witness(&WitnessTurn {
                conversation_ref: EntityId::from_bytes([seed; 16]).unwrap().to_hex(),
                turn_ref: None,
                messages: vec![witness_message(0, WitnessAuthor::User, text)],
                occurred_at: now - days_ago * 86_400,
            })
            .expect("witness");
        witnessed.push(receipt.message_short_ids[0].clone());
    }
    let [older, newer] = <[String; 2]>::try_from(witnessed).expect("two messages");

    // Medium is the SDKs' default recall effort.
    let pack = facade
        .recall(
            "window seat",
            Effort::Medium,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("recall");
    let refs: Vec<&str> = pack
        .items
        .iter()
        .map(|item| item.short_id.split('@').next().unwrap_or_default())
        .collect();
    let position = |id: &str| refs.iter().position(|item| *item == id);
    let (Some(newer_at), Some(older_at)) = (position(&newer), position(&older)) else {
        panic!("both messages recalled: {refs:?}");
    };
    assert!(newer_at < older_at, "newer message first: {refs:?}");
}

/// ARCH-0002: AUTHORITY_LOG is a maintenance record with no short-id prefix,
/// so it never appears in a prompt-facing pack. A pairing appends a SlipMint
/// seconds before the recall, inside the effort's default now anchor, where
/// the temporal channel reaches it. Naming the kind still reaches it.
#[test]
fn recall_leaves_a_fresh_slip_mint_out_unless_the_kind_is_named() {
    use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
    use ed25519_dalek::{Signer, SigningKey};

    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x64);
    let facade = facade_for(&vault, actor);
    facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x65; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: vec![witness_message(
                0,
                WitnessAuthor::User,
                "I prefer a window seat when I fly.",
            )],
            occurred_at: crate::unix_seconds_now() - 28 * 86_400,
        })
        .expect("witness");

    let issuer = crate::authority::HostSlipIssuer::from_secret(b"recall pairing secret").unwrap();
    vault.ensure_host_root_slip(&issuer).expect("host root");
    let holder = SigningKey::from_bytes(&[0x66; 32]);
    let public = holder.verifying_key().to_bytes();
    let link = vault
        .issue_pairing_link(&issuer, crate::federation::Scope::top(), 3_600)
        .expect("pairing link");
    let transcript =
        crate::authority::pairing_binding_transcript(&link.code, &public, "recall-holder").unwrap();
    vault
        .redeem_pairing_link(
            &issuer,
            &link.code,
            "recall-holder",
            public,
            &holder.sign(&transcript).to_bytes(),
        )
        .expect("pair");

    // Medium is the SDKs' default recall effort; no vector makes it sparse.
    let pack = facade
        .recall(
            "window seat",
            Effort::Medium,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("recall");
    let kinds: Vec<&str> = pack.items.iter().map(|item| item.kind.as_str()).collect();
    assert_eq!(pack.retrieval_meta.sparse, Some(true));
    assert!(kinds.contains(&"MESSAGE"), "{kinds:?}");
    assert!(!kinds.contains(&"AUTHORITY_LOG"), "{kinds:?}");

    // The caller's own kind filter names it.
    let named = vault
        .context_pack()
        .search_text("window seat", 10)
        .limit(10)
        .retrieval_effort(Effort::Medium, &[])
        .filter_types(&[ENTITY_TYPE_AUTHORITY_LOG])
        .run()
        .expect("named pack");
    assert!(!named.results.is_empty());
    assert!(
        named
            .results
            .iter()
            .all(|entity| entity.entity_type == ENTITY_TYPE_AUTHORITY_LOG)
    );

    // So does an authority filter that lists it.
    let floor =
        crate::gate::resolve_policy_manifest(&vault.store, &vault.store.env.read_txn().unwrap())
            .unwrap()
            .retrieval_floor_for_actor(None);
    let filter = crate::gate::narrow_retrieval_filter(
        &floor,
        Some(&crate::gate::RetrievalFilter {
            entity_types: Some([ENTITY_TYPE_AUTHORITY_LOG].into()),
            ..Default::default()
        }),
    )
    .unwrap();
    let hits = vault
        .query()
        .search_text("window seat", 10)
        .limit(10)
        .retrieval_effort(Effort::Medium, &[])
        .authority_filter(filter)
        .run()
        .expect("named query");
    assert!(!hits.is_empty());
}

/// The Node SDK count-limits fixture: the embedded owner witnesses one
/// conversation with one turn "window seat" and claims on the turn. The store
/// clock ticks in whole seconds, so the first compared recall lands in the
/// tick the fixture was written and the second one tick later. The TURN and
/// the CONVERSATION tie on every blend column but recency, and both recalls
/// must rank them the same way. A first recall fills the PPR cache, as the
/// Node test's earlier recalls do, so the compared packs differ in nothing
/// but what the clock could move.
#[test]
fn identical_recalls_return_the_same_pack_across_a_clock_tick() {
    // The seconds are held still while ids stay time-ordered, as they are
    // under the system clock the SDK runs on.
    struct TimeOrderedIds;
    impl crate::ports::IdGen for TimeOrderedIds {
        fn ulid(&self) -> [u8; 16] {
            uuid::Uuid::now_v7().into_bytes()
        }
    }
    let written = crate::unix_seconds_now();
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = crate::ports::ManualClock::new(written);
    let config = crate::config::VaultConfig {
        store_clock: crate::ports::StoreClock::new(
            clock.clone(),
            std::sync::Arc::new(TimeOrderedIds),
        ),
        ..crate::config::VaultConfig::default()
    };
    let vault = crate::Vault::open(dir.path(), config).expect("open vault");
    let actor = vault.ensure_embedded_owner_actor().expect("owner actor");
    let facade = facade_for(&vault, actor);
    let witnessed = facade
        .witness(&WitnessTurn {
            conversation_ref: "11111111111111111111111111111111".to_owned(),
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "window seat")],
            occurred_at: written,
        })
        .expect("witness");
    facade
        .claim_upsert(&ClaimInput {
            id: None,
            predicate: "preference.travel.seat".to_owned(),
            subject_ref: witnessed.turn_short_id,
            value: serde_json::json!({ "seat": "window" }),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        })
        .expect("claim");

    let recall = || {
        facade
            .recall(
                "window seat",
                Effort::Medium,
                &RecallScope::default(),
                10,
                None,
                None,
            )
            .expect("recall")
    };
    recall();
    let in_the_written_tick = recall();
    clock.set(written + 1);
    let one_tick_later = recall();

    let kinds: Vec<&str> = in_the_written_tick
        .items
        .iter()
        .map(|item| item.kind.as_str())
        .collect();
    assert!(
        ["CLAIM", "TURN", "CONVERSATION"]
            .iter()
            .all(|kind| kinds.contains(kind)),
        "the fixture recalls the claim and the tied TURN and CONVERSATION: {kinds:?}"
    );
    assert_eq!(in_the_written_tick, one_tick_later);
}
