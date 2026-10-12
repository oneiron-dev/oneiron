//! Retrieval bound to a room reads its overlay ∪ base and writes nothing
//! derived from the room into base (ARCH-0052 §2, mode flip).

use super::*;
use crate::batch::BatchOp;
use crate::off_record::{OffRecordBackendClass, OffRecordSession};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN, ENTITY_TYPE_WORLD};
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
        ids,
        vec![later, staged, first],
        "the base row added on record is the nearest, and the room's own row \
         ranks by its own vector, got {hits:?}"
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
    drop(door);
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
/// search returns a row only the room holds. The owner's lane: a room's rows
/// carry no record-scope stamp, which a grant-checked reader needs.
#[test]
fn a_scoped_read_in_the_room_searches_the_room() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
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
    let key = crate::claim::ScopedReadActorKey::vault_owner(owner);
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

/// A room that staged only text over a base row finds that row by the room's
/// words. A run over it queues base no embed job for the row: the job would
/// keep, after the room closes, that the room's search chose it.
#[cfg(feature = "sync")]
#[test]
fn a_run_over_a_room_that_staged_only_text_queues_no_base_embed_job() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let vault = std::sync::Arc::new(vault);
    let claim = entity_id(0xB7);
    put_status_claim(
        &vault,
        claim,
        "basewordsonly",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
        false,
    )?;
    vault.with_write_txn_grouped(|wtxn| {
        crate::sync::queue::delete_embed_job_in_txn(&vault.store, wtxn, &claim)
    })?;
    let queue = crate::sync::SyncQueue::new(std::sync::Arc::clone(&vault))?;
    let jobs_for_claim = || -> Result<usize> {
        Ok(queue
            .drain_embed_jobs()?
            .iter()
            .filter(|job| job.entity_id == claim)
            .count())
    };
    assert_eq!(jobs_for_claim()?, 0, "base queues no job for the row yet");

    let session = enter(&vault, "sess-room-text-only")?;
    stage_in_room(
        &vault,
        &session,
        vec![BatchOp::Text {
            id: claim,
            fields: vec![("body".to_owned(), "roomtextonlyneedle".to_owned())],
        }],
    )?;
    let view = session.read_view()?;
    let in_room = vault
        .query()
        .search_text("roomtextonlyneedle", 10)
        .reading(view.read())
        .run_with_pending_vectors()?;
    assert!(
        in_room.value.iter().any(|hit| hit.id == claim),
        "the room's words find the base row, got {:?}",
        in_room.value
    );
    assert_eq!(jobs_for_claim()?, 0, "and base queues no embed job for it");
    drop(view);
    session.close()?;
    Ok(())
}

/// A room that replaced the vector of base's nearest row leaves a vacancy
/// in base's hits. The search fills it from base's next rows before it
/// answers: the room's replacement alone does not.
#[test]
fn a_vector_search_in_the_room_looks_past_a_row_whose_vector_it_replaced() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let replaced = entity_id(0xB8);
    put_vector(&vault, replaced, [1.0, 0.0, 0.0, 0.0])?;
    let next = entity_id(0xB9);
    put_vector(&vault, next, [0.8, 0.6, 0.0, 0.0])?;
    let session = enter(&vault, "sess-room-replaced-vector")?;
    stage_in_room(
        &vault,
        &session,
        vec![room_vector(replaced, [0.0, 1.0, 0.0, 0.0])],
    )?;

    let view = session.read_view()?;
    let hits = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
        .reading(view.read())
        .run()?;
    assert_eq!(
        hits.first().map(|hit| hit.id),
        Some(next),
        "base's next row is the nearest in the room, got {hits:?}"
    );
    drop(view);
    session.close()?;
    Ok(())
}

/// A vector the room staged for an id that names no row is no hit: it takes
/// no place from a row the room reads.
#[test]
fn a_vector_search_in_the_room_skips_a_staged_vector_with_no_row() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let row = entity_id(0xBA);
    put_vector(&vault, row, [0.8, 0.6, 0.0, 0.0])?;
    let session = enter(&vault, "sess-room-rowless-vector")?;
    stage_in_room(
        &vault,
        &session,
        vec![room_vector(entity_id(0xBB), [1.0, 0.0, 0.0, 0.0])],
    )?;

    let view = session.read_view()?;
    let hits = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
        .reading(view.read())
        .run()?;
    assert_eq!(
        hits.first().map(|hit| hit.id),
        Some(row),
        "the row the room reads is found, got {hits:?}"
    );
    drop(view);
    session.close()?;
    Ok(())
}

/// A room stages its graph's count with its graph. Once it is on record base
/// keeps growing, and a filtered search widens over every vector, base's new
/// ones too: the one row the filter admits is found.
#[test]
fn a_filtered_vector_search_in_the_room_widens_over_base_rows_added_on_record() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    put_vector(&vault, entity_id(0xBC), [1.0, 0.0, 0.0, 0.0])?;
    let session = enter(&vault, "sess-room-widening")?;
    let staged = entity_id(0xBD);
    stage_in_room(
        &vault,
        &session,
        vec![room_put(staged), room_vector(staged, [0.0, 1.0, 0.0, 0.0])],
    )?;
    session.flip_on_record()?;
    put_vector(&vault, entity_id(0xBE), [0.96, 0.28, 0.0, 0.0])?;
    let wanted = entity_id(0xBF);
    put_vector(&vault, wanted, [0.8, 0.6, 0.0, 0.0])?;

    let view = session.read_view()?;
    let only_wanted = |_: &crate::store::StoreRead<'_>,
                       _: &heed::RoTxn<'_>,
                       id: &EntityId|
     -> Result<bool> { Ok(*id == wanted) };
    let hits = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
        .filter_candidates(&only_wanted)
        .reading(view.read())
        .run()?;
    assert_eq!(
        hits.iter().map(|hit| hit.id).collect::<Vec<_>>(),
        vec![wanted],
        "the filter's one row is found"
    );
    drop(view);
    session.close()?;
    Ok(())
}

/// A room stages its BM25 document count with its postings. Once it is on
/// record base keeps indexing, so the union's postings outnumber that count.
/// A text search in the room still answers, with base's new rows.
#[test]
fn a_text_search_in_the_room_reads_base_rows_indexed_after_it_went_on_record() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let first = entity_id(0xC1);
    put_text_and_vector(&vault, first, "unionneedle", [1.0, 0.0, 0.0, 0.0])?;
    let session = enter(&vault, "sess-room-bm25-count")?;
    let staged = entity_id(0xC2);
    stage_in_room(
        &vault,
        &session,
        vec![
            room_put(staged),
            BatchOp::Text {
                id: staged,
                fields: vec![("body".to_owned(), "unionneedle".to_owned())],
            },
        ],
    )?;
    session.flip_on_record()?;
    let later = [entity_id(0xC3), entity_id(0xC4)];
    for id in later {
        put_text_and_vector(&vault, id, "unionneedle", [0.0, 1.0, 0.0, 0.0])?;
    }

    let view = session.read_view()?;
    let hits = vault
        .query()
        .search_text("unionneedle", 10)
        .reading(view.read())
        .run()?;
    let ids: Vec<_> = hits.iter().map(|hit| hit.id).collect();
    for id in [first, staged, later[0], later[1]] {
        assert!(ids.contains(&id), "{id:?} is found, got {hits:?}");
    }
    drop(view);
    session.close()?;
    Ok(())
}

/// A room that cleared base's only indexed row stages a document count of
/// zero and hides base's field stats. Once it is on record base indexes
/// again, and a text search in the room finds base's new row.
#[test]
fn a_text_search_in_the_room_finds_base_rows_indexed_after_it_cleared_base_text() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let cleared = entity_id(0xC5);
    put_text(&vault, cleared, "unionneedle")?;
    let session = enter(&vault, "sess-room-bm25-stats")?;
    stage_in_room(
        &vault,
        &session,
        vec![BatchOp::Text {
            id: cleared,
            fields: Vec::new(),
        }],
    )?;
    session.flip_on_record()?;
    let later = entity_id(0xC6);
    put_text(&vault, later, "unionneedle")?;

    let view = session.read_view()?;
    let hits = vault
        .query()
        .search_text("unionneedle", 10)
        .reading(view.read())
        .run()?;
    assert_eq!(
        hits.iter().map(|hit| hit.id).collect::<Vec<_>>(),
        vec![later],
        "base's new row is found, and the row the room cleared is not"
    );
    drop(view);
    session.close()?;
    Ok(())
}

/// A verified credential for `holder`, the host root's narrowed to `worlds`.
fn read_credential(
    vault: &Vault,
    holder: EntityId,
    actor_class: &str,
    worlds: &[EntityId],
) -> Result<crate::authority::VerifiedSlip> {
    let issuer = crate::authority::HostSlipIssuer::from_secret(b"room count fixture")?;
    let mut claims = vault.ensure_host_root_slip(&issuer)?.claims;
    claims.slip_id = [0xD3; 32];
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some(actor_class.into());
    claims.scope.worlds = crate::federation::ScopeAxis::Some(
        worlds
            .iter()
            .map(|world| crate::federation::ScopeId(*world))
            .collect(),
    );
    let slip = vault.mint_capability_slip(&issuer, claims)?;
    let binding = b"room-count";
    let signature = issuer.binding_proof(&slip, binding)?;
    vault.verify_capability_slip(&issuer.public_key(), &slip, binding, &signature)
}

/// A reader whose verified credential grants one world alone, not base.
fn one_world_reader(vault: &Vault) -> Result<crate::claim::ScopedReadActorKey> {
    let holder = entity_id(0xD1);
    put_entity(vault, holder, ENTITY_TYPE_PERSON, 1, 1, 1)?;
    let world = entity_id(0xD2);
    put_entity(vault, world, ENTITY_TYPE_WORLD, 1, 1, 1)?;
    let verified = read_credential(vault, holder, "agent", &[world])?;
    Ok(crate::claim::ScopedReadActorKey::from_verified_slip(&verified).expect("slip reader"))
}

/// Stages a base-reality claim only the room holds, found by `word`.
fn stage_room_claim(
    vault: &Vault,
    session: &OffRecordSession<'_>,
    claim: EntityId,
    word: &str,
) -> Result<()> {
    stage_in_room(
        vault,
        session,
        vec![
            BatchOp::Put {
                id: claim,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: TimeRange { start: 10, end: 10 },
                learned_at: 10,
                data: active_claim_body(None),
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            },
            BatchOp::Text {
                id: claim,
                fields: vec![("body".to_owned(), word.to_owned())],
            },
        ],
    )
}

/// A credential that reads one world names no count of a row outside it
/// (DEC-0005: no name, no count). A claim only the room holds carries no
/// record-scope stamp to place it. So the room's read withholds it and
/// counts nothing, as the same read outside the room, where it does not
/// exist.
#[test]
fn a_credential_for_one_world_counts_no_claim_the_room_holds() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let key = one_world_reader(&vault)?;
    let session = enter(&vault, "sess-room-claim-count")?;
    let claim = entity_id(0xD4);
    stage_room_claim(&vault, &session, claim, "roomclaimcountneedle")?;

    let outside = vault
        .scoped_read(key.clone())
        .get_entity_parts_with_receipt(&claim, None)?;
    assert!(outside.value.is_none(), "base holds nothing of it");
    assert_eq!(outside.receipt.suppressed_count, 0);

    let view = session.read_view()?;
    let inside = vault
        .scoped_read_in_session(key, &view)
        .get_entity_parts_with_receipt(&claim, None)?;
    assert!(
        inside.value.is_none(),
        "the credential cannot read base reality"
    );
    assert_eq!(
        inside.receipt.suppressed_count, 0,
        "and names no count of the room's claim"
    );
    drop(view);
    session.close()?;
    Ok(())
}

/// The same credential's search in the room counts nothing either, where
/// the pipeline drops the room's claim before the read admits its hits.
#[test]
fn a_credential_for_one_world_searching_the_room_counts_no_claim_it_holds() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let key = one_world_reader(&vault)?;
    let session = enter(&vault, "sess-room-claim-search-count")?;
    let claim = entity_id(0xD5);
    stage_room_claim(&vault, &session, claim, "roomclaimsearchneedle")?;
    let strict = crate::gate::RetrievalFilter {
        min_confidence: Some(0.95),
        ..crate::gate::RetrievalFilter::default()
    };

    let view = session.read_view()?;
    let inside = vault.scoped_read_in_session(key, &view).search_text(
        "roomclaimsearchneedle",
        10,
        Some(&strict),
    )?;
    assert!(inside.value.is_empty(), "got {:?}", inside.value);
    assert_eq!(
        inside.receipt.suppressed_count, 0,
        "the search names no count of the room's claim"
    );
    drop(view);
    session.close()?;
    Ok(())
}

/// A credential that grants base reality alone reads base alone in a room,
/// and its recall there seeds from base alone. A word the room staged on a
/// base claim chooses nothing for it: not a seed, and not one more row it
/// was refused, so its receipt counts the same as for a word nobody wrote.
#[test]
fn a_base_only_credentials_recall_in_the_room_seeds_nothing_by_the_rooms_words() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let claim = entity_id(0xD6);
    let mut body = ClaimBody::new(
        "test.seed",
        ClaimSubject::Entity(owner),
        rmpv::Value::from("v"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    // Replicated: the fixture isolates the room's read, not the write gate.
    vault
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &crate::claim::encode_claim_body(&body)?,
        )
        .text(&claim, &[("body", "seedbaseword")])
        .edge(&claim, crate::EdgeKind::ClaimOf, &owner, 1.0)
        .commit()?;
    let base_only = read_credential(&vault, owner, "human", &[crate::claim::base_world_id()])?;
    let session = enter(&vault, "sess-room-seed-words")?;
    stage_in_room(
        &vault,
        &session,
        vec![BatchOp::Text {
            id: claim,
            fields: vec![("body".to_owned(), "seedroomword".to_owned())],
        }],
    )?;
    let owners = || vault.memory(owner, crate::edge::EdgeActorClass::Human);
    let scope = crate::memory::RecallScope::default();
    let the_room = owners()
        .recall_in_session(
            &session,
            "seedroomword",
            crate::memory::Effort::Light,
            &scope,
            10,
            None,
            None,
        )
        .expect("the owner's recall in the room");
    assert_eq!(the_room.items.len(), 1, "the room's word finds the claim");

    let credentials = |word: &str| {
        owners()
            .with_read_proof(&base_only)
            .recall_in_session(
                &session,
                word,
                crate::memory::Effort::Medium,
                &scope,
                10,
                None,
                None,
            )
            .expect("the credential's recall in the room")
    };
    let by_the_rooms_word = credentials("seedroomword");
    let by_no_word = credentials("seednobodysword");
    assert!(
        by_the_rooms_word.items.is_empty(),
        "got {:?}",
        by_the_rooms_word.items
    );
    assert_eq!(
        by_the_rooms_word.narrowing.suppressed_count, by_no_word.narrowing.suppressed_count,
        "the room's word counts no row the credential was refused"
    );
    session.close()?;
    Ok(())
}
