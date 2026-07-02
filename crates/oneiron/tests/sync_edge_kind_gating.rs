//! ONE-1122 seam-7 pin: sync ships ALL edge kinds; retrieval gates at read
//! time.
//!
//! ARCH-0004 marks `child_of` / `assigned_to` as `lambda: null` ("Not
//! traversed.") and the context-pack walk additionally skips
//! retracted-provenanced edges — those are RETRIEVAL semantics, not storage.
//! Nothing may filter edge kinds out of the sync path: `reverse_rematerialize`
//! must mirror every kind byte-identically into the CRDT edges map
//! (`encode_edge_value` / ARCH-0034 layout classes 12 B structural, 24 B
//! semantic-bare, 26 B semantic-provenanced) and `forward_rematerialize` must
//! land every kind back in LMDB. The kind gating lives ONLY in the
//! context-pack walk (`context_pack.rs` ChildOf/AssignedTo skip +
//! retracted-provenance skip), which this test pins from the consumer side.

#![cfg(feature = "sync")]

use std::collections::HashSet;
use std::sync::Arc;

use loro::{ExportMode, LoroDoc};
use oneiron::sync::bridge::{Materializer, encode_edge_value_for_crdt, format_edge_key};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window;
use oneiron::types::ENTITY_TYPE_POLICY_MANIFEST;
use oneiron::{
    EdgeActorClass, EdgeConfirmationStatus, EdgeInfo, EdgeKind, EdgeProvenanceClaimBody,
    EdgeProvenanceFlags, EdgeRef, EntityId, HnswConfig, SupersessionStatus, TimeRange, Vad, Vault,
    VaultConfig,
};

fn test_config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    cfg.max_readers = 16;
    cfg.hnsw = HnswConfig::default();
    cfg
}

fn edge_info(edges: &[EdgeInfo], kind: EdgeKind, target: &EntityId) -> EdgeInfo {
    edges
        .iter()
        .find(|edge| edge.kind == kind && edge.target == *target)
        .cloned()
        .unwrap_or_else(|| panic!("edge {kind:?} -> {} missing", target.to_hex()))
}

fn clear_policy_manifests(vault: &Vault) {
    for id in vault
        .entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
        .expect("list policy manifests")
    {
        vault
            .batch()
            .delete(&id)
            .commit()
            .expect("clear policy manifest fixture");
    }
    assert_eq!(
        vault
            .count_entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
            .expect("count policy manifests"),
        0
    );
}

/// Seam-7 pin (ONE-1122 AC5): an entity with `Mentions` + `ChildOf` +
/// `AssignedTo` + retracted-provenanced (26 B) edges
/// 1. `reverse_rematerialize` puts ALL four keys into the CRDT edges map
///    byte-identical to `encode_edge_value` output (ARCH-0034 layout
///    literals: 12 B structural, 24 B semantic-bare, 26 B
///    semantic-provenanced with `confirmation_status` at offset 24 and
///    `actor_class` at offset 25);
/// 2. `forward_rematerialize` into a fresh vault materializes all four;
/// 3. a context-pack walk from the same seed does NOT neighbor-expand the
///    `ChildOf` / `AssignedTo` / retracted targets while still expanding the
///    `Mentions` target.
#[test]
fn sync_ships_all_edge_kinds_and_context_pack_walk_gates_at_read_time() {
    let temp_a = tempfile::tempdir().unwrap();
    let vault_a = Arc::new(Vault::open(temp_a.path(), test_config()).unwrap());
    clear_policy_manifests(&vault_a);

    // 2026-03 window; provenance actor + claim stay OUTSIDE the window so the
    // mirrored maps hold exactly the seed, its four targets, and four edges.
    let learned_at = 1_772_400_000u64;
    let out_of_window_learned_at = 1_000u64;
    let occurred = TimeRange { start: 1, end: 1 };

    let seed = EntityId::now();
    let mentions_tgt = EntityId::now();
    let child_tgt = EntityId::now();
    let assigned_tgt = EntityId::now();
    let retracted_tgt = EntityId::now();
    let actor = EntityId::now();

    for (id, body) in [
        (&seed, b"seed".as_slice()),
        (&mentions_tgt, b"mentions-target"),
        (&child_tgt, b"child-target"),
        (&assigned_tgt, b"assigned-target"),
        (&retracted_tgt, b"retracted-target"),
    ] {
        vault_a
            .put_entity(id, 4, occurred, learned_at, body)
            .unwrap();
    }
    vault_a
        .put_entity(&actor, 4, occurred, out_of_window_learned_at, b"actor")
        .unwrap();

    vault_a
        .put_edge(&seed, EdgeKind::Mentions, &mentions_tgt, 0.6)
        .unwrap();
    vault_a
        .put_edge(&seed, EdgeKind::ChildOf, &child_tgt, 1.0)
        .unwrap();
    vault_a
        .put_edge(&seed, EdgeKind::AssignedTo, &assigned_tgt, 1.0)
        .unwrap();
    vault_a
        .put_edge(&seed, EdgeKind::Supports, &retracted_tgt, 0.9)
        .unwrap();

    // Provenance the Supports edge, then retract: with no live claim left the
    // 26 B hot flags pin `confirmation_status = retracted (3)` with the
    // retracted claim's own persisted `actor_class` (human = 0).
    let claim_id = EntityId::now();
    let subject = EdgeRef::new(seed, EdgeKind::Supports, retracted_tgt);
    let body = EdgeProvenanceClaimBody::new(actor, 0.75, SupersessionStatus::Confirmed);
    vault_a
        .put_edge_provenance(
            &claim_id,
            &subject,
            &body,
            EdgeActorClass::Human,
            out_of_window_learned_at,
        )
        .unwrap();
    vault_a
        .retract_edge_provenance(&claim_id, out_of_window_learned_at + 1_000)
        .unwrap();

    let edges_out = vault_a.edges_out(&seed).unwrap();
    assert_eq!(edges_out.len(), 4);
    let mentions = edge_info(&edges_out, EdgeKind::Mentions, &mentions_tgt);
    let child = edge_info(&edges_out, EdgeKind::ChildOf, &child_tgt);
    let assigned = edge_info(&edges_out, EdgeKind::AssignedTo, &assigned_tgt);
    let retracted = edge_info(&edges_out, EdgeKind::Supports, &retracted_tgt);
    assert_eq!(
        retracted.provenance,
        Some(EdgeProvenanceFlags {
            confirmation_status: EdgeConfirmationStatus::Retracted,
            actor_class: EdgeActorClass::Human,
        })
    );

    // 1. Reverse re-materialization mirrors ALL four kinds, byte-identical
    //    to the ARCH-0034 encoder output — sync is kind-agnostic.
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("test-user", &window_key);
    let mirrored = window::reverse_rematerialize(&vault_a, &doc, &window_key).unwrap();
    assert_eq!(mirrored, 5, "seed + four targets mirror into the window");

    let edges_map = doc.get_map("edges");
    let map_bytes = |kind: EdgeKind, tgt: &EntityId| -> Vec<u8> {
        let key = format_edge_key(&seed, kind, tgt);
        match edges_map.get(&key) {
            Some(loro::ValueOrContainer::Value(loro::LoroValue::Binary(bytes))) => bytes.to_vec(),
            other => panic!("edge key {key} missing or non-binary in CRDT map: {other:?}"),
        }
    };

    // Mentions: 24 B semantic-bare. weight LE at 0..4, created_at LE at
    // 4..12, neutral VAD = 12 zero bytes at 12..24.
    let mentions_bytes = map_bytes(EdgeKind::Mentions, &mentions_tgt);
    assert_eq!(mentions_bytes.len(), 24);
    assert_eq!(mentions_bytes[0..4], 0.6f32.to_le_bytes());
    assert_eq!(mentions_bytes[4..12], mentions.created_at.to_le_bytes());
    assert_eq!(mentions_bytes[12..24], [0u8; 12]);
    assert_eq!(
        mentions_bytes,
        encode_edge_value_for_crdt(
            EdgeKind::Mentions,
            0.6,
            mentions.created_at,
            Some(Vad::NEUTRAL),
            None,
        )
        .unwrap()
    );

    // ChildOf / AssignedTo: 12 B structural — shipped even though ARCH-0004
    // pins them `lambda: null` ("Not traversed."), which is retrieval-only.
    let child_bytes = map_bytes(EdgeKind::ChildOf, &child_tgt);
    assert_eq!(child_bytes.len(), 12);
    assert_eq!(child_bytes[0..4], 1.0f32.to_le_bytes());
    assert_eq!(child_bytes[4..12], child.created_at.to_le_bytes());
    assert_eq!(
        child_bytes,
        encode_edge_value_for_crdt(EdgeKind::ChildOf, 1.0, child.created_at, None, None).unwrap()
    );

    let assigned_bytes = map_bytes(EdgeKind::AssignedTo, &assigned_tgt);
    assert_eq!(assigned_bytes.len(), 12);
    assert_eq!(assigned_bytes[0..4], 1.0f32.to_le_bytes());
    assert_eq!(assigned_bytes[4..12], assigned.created_at.to_le_bytes());
    assert_eq!(
        assigned_bytes,
        encode_edge_value_for_crdt(EdgeKind::AssignedTo, 1.0, assigned.created_at, None, None)
            .unwrap()
    );

    // Retracted-provenanced: 26 B with the pinned hot-flag offsets —
    // confirmation_status retracted = 3 at 24, actor_class human = 0 at 25.
    let retracted_bytes = map_bytes(EdgeKind::Supports, &retracted_tgt);
    assert_eq!(retracted_bytes.len(), 26);
    assert_eq!(retracted_bytes[0..4], 0.9f32.to_le_bytes());
    assert_eq!(retracted_bytes[4..12], retracted.created_at.to_le_bytes());
    assert_eq!(retracted_bytes[24], 3, "confirmation_status retracted = 3");
    assert_eq!(retracted_bytes[25], 0, "actor_class human = 0");
    assert_eq!(
        retracted_bytes,
        encode_edge_value_for_crdt(
            EdgeKind::Supports,
            0.9,
            retracted.created_at,
            Some(Vad::NEUTRAL),
            Some(EdgeProvenanceFlags {
                confirmation_status: EdgeConfirmationStatus::Retracted,
                actor_class: EdgeActorClass::Human,
            }),
        )
        .unwrap()
    );

    // 2. Forward re-materialization into a FRESH vault lands all four kinds.
    let temp_b = tempfile::tempdir().unwrap();
    let vault_b = Arc::new(Vault::open(temp_b.path(), test_config()).unwrap());
    let materializer = Arc::new(Materializer::new());

    let snapshot = doc.export(ExportMode::Snapshot).unwrap();
    let doc_b = LoroDoc::from_snapshot(&snapshot).unwrap();
    let restored =
        window::forward_rematerialize(&vault_b, &doc_b, &materializer, &window_key).unwrap();
    assert_eq!(restored, 9, "five entities + four edges");

    assert!(
        vault_b
            .edge_exists(&seed, EdgeKind::Mentions, &mentions_tgt)
            .unwrap()
    );
    assert!(
        vault_b
            .edge_exists(&seed, EdgeKind::ChildOf, &child_tgt)
            .unwrap()
    );
    assert!(
        vault_b
            .edge_exists(&seed, EdgeKind::AssignedTo, &assigned_tgt)
            .unwrap()
    );
    assert!(
        vault_b
            .edge_exists(&seed, EdgeKind::Supports, &retracted_tgt)
            .unwrap()
    );

    // The 26 B provenance hot flags survived the round trip.
    let b_edges = vault_b.edges_out(&seed).unwrap();
    assert_eq!(b_edges.len(), 4);
    let b_retracted = edge_info(&b_edges, EdgeKind::Supports, &retracted_tgt);
    assert_eq!(
        b_retracted.provenance,
        Some(EdgeProvenanceFlags {
            confirmation_status: EdgeConfirmationStatus::Retracted,
            actor_class: EdgeActorClass::Human,
        }),
        "retracted hot flags must survive sync byte-for-byte"
    );

    // 3. Context-pack walk from the same seed on the synced vault: the kind
    //    gating lives at READ time (context_pack walk), not in sync.
    vault_b
        .batch()
        .text(&seed, &[("body", "seam7walkseed")])
        .commit()
        .unwrap();
    let pack = vault_b
        .context_pack()
        .search_text("seam7walkseed", 10)
        .edge_hop(1)
        .max_neighbors(10)
        .run()
        .unwrap();

    let result_ids: HashSet<EntityId> = pack.results.iter().map(|e| e.id).collect();
    assert!(result_ids.contains(&seed), "seed must anchor the walk");
    let neighbor_ids: HashSet<EntityId> = pack.neighbors.iter().map(|e| e.id).collect();
    assert!(
        neighbor_ids.contains(&mentions_tgt),
        "mentions target must still neighbor-expand"
    );
    assert!(
        !neighbor_ids.contains(&child_tgt),
        "child_of must contribute no neighbor (lambda null is retrieval-only)"
    );
    assert!(
        !neighbor_ids.contains(&assigned_tgt),
        "assigned_to must contribute no neighbor (lambda null is retrieval-only)"
    );
    assert!(
        !neighbor_ids.contains(&retracted_tgt),
        "retracted-provenanced edge must not neighbor-expand"
    );
}
