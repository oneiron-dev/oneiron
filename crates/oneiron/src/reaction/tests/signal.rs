//! Replay dependency order and all-audience signal laws.
use super::*;

#[cfg(feature = "sync")]
#[test]
fn body_then_soft_tombstone_then_binding_edges_flushes_both_signals() {
    for about_first in [false, true] {
        let (_dir, vault, alice, _, message) = fixture();
        let id = EntityId::now();
        let row = ReactionBody {
            v: 1,
            msg: message,
            by: alice,
            glyph: "👀".into(),
            at: 20,
            ext: None,
        };
        vault
            .with_write_txn(|txn| {
                vault
                    .batch_in()
                    .put_replicated(
                        &id,
                        ENTITY_TYPE_REACTION,
                        crate::TimeRange { start: 20, end: 20 },
                        22,
                        &row.to_bytes()?,
                    )
                    .apply(txn)
            })
            .unwrap();
        let tombstone = crate::deletion::TombstoneValueV2 {
            reason: crate::deletion::TombstoneReason::UserDelete,
            deleted_at: 30,
            request_id: [7; 16],
        };
        vault
            .apply_replayed_tombstone(&id, &tombstone.encode())
            .unwrap();
        assert!(vault.reactions_since(alice, 0).unwrap().is_empty());
        let edges = [
            (crate::EdgeKind::About, message),
            (crate::EdgeKind::AuthoredBy, alice),
        ];
        let order = if about_first {
            edges
        } else {
            [edges[1], edges[0]]
        };
        for (kind, target) in order {
            vault.put_edge(&id, kind, &target, 1.0).unwrap();
        }
        let rows: Vec<_> = vault
            .reactions_since(alice, 0)
            .unwrap()
            .into_iter()
            .filter(|signal| signal.reaction == id)
            .collect();
        assert_eq!(
            rows.len(),
            2,
            "put and revoke survive a scrub before bindings"
        );
        assert_eq!(rows[0].recorded_at, 22);
        assert_eq!(rows[1].recorded_at, 30);
        assert!(!rows[0].revoked && rows[1].revoked);
    }
}

#[cfg(feature = "sync")]
#[test]
fn target_author_before_room_ancestry_keeps_signal_pending_without_page_error() {
    let (_dir, vault, alice, _, message) = fixture();
    let source_turn = vault
        .edges_out(&message)
        .unwrap()
        .into_iter()
        .find(|e| e.kind == crate::EdgeKind::PartOf)
        .unwrap()
        .target;
    let room = vault
        .edges_out(&source_turn)
        .unwrap()
        .into_iter()
        .find(|e| e.kind == crate::EdgeKind::ChildOf)
        .unwrap()
        .target;
    let turn = EntityId::now();
    let raw = vault.get_raw(&source_turn).unwrap().unwrap();
    let h = crate::batch::EntityMetadataHeader::parse(&raw).unwrap();
    vault
        .with_write_txn(|txn| {
            vault
                .batch_in()
                .put_replicated(
                    &turn,
                    crate::registry::ENTITY_TYPE_TURN,
                    crate::TimeRange {
                        start: h.occurred_start,
                        end: h.occurred_end,
                    },
                    h.learned_at,
                    &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                )
                .apply(txn)
        })
        .unwrap();
    vault
        .put_edge(&turn, crate::EdgeKind::AuthoredBy, &alice, 1.0)
        .unwrap();
    let id = EntityId::now();
    let row = ReactionBody {
        v: 1,
        msg: turn,
        by: alice,
        glyph: "👀".into(),
        at: 20,
        ext: None,
    };
    vault
        .with_write_txn(|txn| {
            vault
                .batch_in()
                .put_replicated(
                    &id,
                    ENTITY_TYPE_REACTION,
                    crate::TimeRange { start: 20, end: 20 },
                    22,
                    &row.to_bytes()?,
                )
                .edge(&id, crate::EdgeKind::About, &turn, 1.0)
                .edge(&id, crate::EdgeKind::AuthoredBy, &alice, 1.0)
                .apply(txn)
        })
        .unwrap();
    assert!(
        vault.reactions_since(alice, 0).unwrap().is_empty(),
        "an unresolved room must not make the page fail or publish early"
    );
    vault
        .put_edge(&turn, crate::EdgeKind::ChildOf, &room, 1.0)
        .unwrap();
    assert!(
        vault
            .reactions_since(alice, 0)
            .unwrap()
            .iter()
            .any(|s| s.reaction == id)
    );
}
