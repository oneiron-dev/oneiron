//! Retrieval bound to a room reads its overlay ∪ base and writes nothing
//! derived from the room into base (ARCH-0052 §2, mode flip).

use super::*;
use crate::batch::BatchOp;
use crate::off_record::{OffRecordBackendClass, OffRecordSession};
use crate::registry::ENTITY_TYPE_TURN;
use crate::session_overlay::{JournalEntry, JournalRole, JournalScope};

/// Stages `ops` in the room through its own apply door, as a turn would.
fn stage_in_room(vault: &Vault, session: &OffRecordSession<'_>, ops: Vec<BatchOp>) -> Result<()> {
    let route = session.write_route()?;
    let overlay = session.overlay();
    let scope = JournalScope::new(EntityId::now(), EntityId::now());
    let entries = ops
        .into_iter()
        .map(|op| JournalEntry {
            scope,
            role: JournalRole::TurnPut,
            learned_at: 10,
            occurred: TimeRange { start: 10, end: 10 },
            op,
        })
        .collect();
    let segment = vault.with_write_txn_grouped(|wtxn| {
        let segment = overlay.install_txn_segment()?;
        let view = vault.store.session_view(overlay.clone())?;
        crate::batch::apply_ops_session(
            &view,
            &route,
            &vault.config,
            &vault.analyzer,
            wtxn,
            entries,
        )?;
        Ok(segment)
    })?;
    segment.commit()
}

fn room_put(id: EntityId) -> BatchOp {
    BatchOp::Put {
        id,
        entity_type: ENTITY_TYPE_TURN,
        occurred: TimeRange { start: 10, end: 10 },
        learned_at: 10,
        data: b"payload".to_vec(),
        allow_maintenance: false,
        allow_reserved_predicate: false,
        hub_sync_imported: false,
    }
}

fn room_vector(id: EntityId, vector: [f32; 4]) -> BatchOp {
    BatchOp::Vector {
        id,
        vector: vector.to_vec(),
        pending_embedding_token: None,
    }
}

fn enter<'v>(vault: &'v Vault, session_ref: &str) -> Result<OffRecordSession<'v>> {
    vault
        .off_record_session_vault()
        .enter(session_ref, OffRecordBackendClass::Local)
}

/// A room's HNSW rows are whole neighbour lists staged over base's. Once the
/// room is on record base keeps growing, and its newer nodes link only from
/// base's lists. A vector search in the room still finds them, and scores
/// the room's own vector exactly.
#[test]
fn a_vector_search_in_the_room_finds_base_rows_added_after_it_went_on_record() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let first = entity_id(0xB1);
    put_vector(&vault, first, [0.0, 1.0, 0.0, 0.0])?;
    let session = enter(&vault, "sess-room-hnsw")?;
    let staged = entity_id(0xB2);
    stage_in_room(
        &vault,
        &session,
        vec![room_put(staged), room_vector(staged, [0.8, 0.6, 0.0, 0.0])],
    )?;
    session.flip_on_record()?;
    let later = entity_id(0xB3);
    put_vector(&vault, later, [1.0, 0.0, 0.0, 0.0])?;

    let view = session.read_view()?;
    let hits = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 3)
        .reading(view.read())
        .run()?;
    let ids: Vec<_> = hits.iter().map(|hit| hit.id).collect();
    assert_eq!(
        ids.first(),
        Some(&later),
        "the base row added on record is the nearest, got {hits:?}"
    );
    let room_row = hits
        .iter()
        .find(|hit| hit.id == staged)
        .expect("the room's own row is found too");
    assert!(
        (room_row.score - 0.8).abs() < 1e-4,
        "and scored on its own vector, got {}",
        room_row.score
    );
    drop(view);
    session.close()?;
    Ok(())
}

/// A room that staged only a vector over a base row still scores by it. On
/// record, a run over that room keeps no run row in base: its scores are the
/// room's.
#[test]
fn on_record_a_run_over_a_room_that_staged_only_a_vector_keeps_no_base_run() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let row = entity_id(0xB4);
    put_vector(&vault, row, [0.0, 1.0, 0.0, 0.0])?;
    let session = enter(&vault, "sess-room-vector-only")?;
    stage_in_room(
        &vault,
        &session,
        vec![room_vector(row, [1.0, 0.0, 0.0, 0.0])],
    )?;
    session.flip_on_record()?;
    let base_runs = vault.retrieval_runs(64)?.len();

    let route = session.write_route()?;
    let door = session.retrieval_telemetry(&route)?;
    let view = session.read_view()?;
    let hits = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
        .in_session(&door)
        .reading(view.read())
        .run()?;
    assert_eq!(
        hits.first().map(|hit| hit.id),
        Some(row),
        "the run scores the row by the room's vector"
    );
    assert!(hits[0].score > 0.99, "got {hits:?}");
    assert_eq!(
        vault.retrieval_runs(64)?.len(),
        base_runs,
        "and keeps no run in base"
    );
    drop(view);
    session.close()?;
    Ok(())
}

/// A row the room holds is the room's, embedded inline there (K6). A base
/// pending-embedding marker under the same id names the body the room
/// replaced, so a run in the room hands no job for it to base.
#[test]
fn a_run_in_the_room_reports_no_pending_vector_for_a_row_the_room_holds() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = entity_id(0xB5);
    put_status_claim(
        &vault,
        claim,
        "roompendingneedle",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
        false,
    )?;
    let on_base = vault
        .query()
        .search_text("roompendingneedle", 10)
        .run_with_pending_vectors()?;
    assert_eq!(on_base.pending_vector_ids, vec![claim], "base has a marker");

    let session = enter(&vault, "sess-room-pending")?;
    stage_in_room(
        &vault,
        &session,
        vec![BatchOp::Put {
            id: claim,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: TimeRange { start: 10, end: 10 },
            learned_at: 10,
            data: claim_body_bytes(
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
                false,
            ),
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
    )?;
    let view = session.read_view()?;
    let in_room = vault
        .query()
        .search_text("roompendingneedle", 10)
        .reading(view.read())
        .run_with_pending_vectors()?;
    assert!(
        in_room.value.iter().any(|hit| hit.id == claim),
        "the room reads the row"
    );
    assert!(
        in_room.pending_vector_ids.is_empty(),
        "and reports no base job for it, got {:?}",
        in_room.pending_vector_ids
    );
    drop(view);
    session.close()?;
    Ok(())
}

/// A scoped read bound to a room searches the room, not only base: its text
/// search returns a row only the room holds.
#[test]
fn a_scoped_read_in_the_room_searches_the_room() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let session = enter(&vault, "sess-room-scoped-search")?;
    let staged = entity_id(0xB6);
    stage_in_room(
        &vault,
        &session,
        vec![
            room_put(staged),
            BatchOp::Text {
                id: staged,
                fields: vec![("body".to_owned(), "roomscopedneedle".to_owned())],
            },
        ],
    )?;
    let key = crate::claim::ScopedReadActorKey::new("agent:reader").expect("actor key");
    let outside = vault
        .scoped_read(key.clone())
        .search_text("roomscopedneedle", 10, None)?;
    assert!(outside.value.is_empty(), "base holds nothing of it");

    let view = session.read_view()?;
    let inside =
        vault
            .scoped_read_in_session(key, &view)
            .search_text("roomscopedneedle", 10, None)?;
    assert!(
        inside.value.iter().any(|hit| hit.id == staged),
        "the room's read finds the room's row, got {:?}",
        inside.value
    );
    drop(view);
    session.close()?;
    Ok(())
}
