//! Retrieval bound to a room reads its overlay ∪ base and writes nothing
//! derived from the room into base (ARCH-0052 §2, mode flip).

use super::*;
use crate::batch::BatchOp;
use crate::off_record::{OffRecordBackendClass, OffRecordSession};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN, ENTITY_TYPE_WORLD};
use crate::session_overlay::{JournalEntry, JournalRole, JournalScope};

/// Stages `ops` in the room through its own apply door, as a turn would:
/// one op per apply, each on a fresh view of the overlay (a view reads the
/// overlay as it was when it was built). A put is staged under its own
/// stamps.
fn stage_in_room(vault: &Vault, session: &OffRecordSession<'_>, ops: Vec<BatchOp>) -> Result<()> {
    stage_in_room_then(vault, session, ops, || Ok(()))
}

/// [`stage_in_room`], running `between` once base's transaction has
/// committed and before the room's segment does, as a base write that takes
/// the writer next would.
fn stage_in_room_then(
    vault: &Vault,
    session: &OffRecordSession<'_>,
    ops: Vec<BatchOp>,
    between: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let route = session.write_route()?;
    let overlay = session.overlay();
    let scope = JournalScope::new(EntityId::now(), EntityId::now());
    let segment = vault.with_write_txn_grouped(|wtxn| {
        let segment = overlay.install_txn_segment()?;
        for op in ops {
            let (occurred, learned_at) = match &op {
                BatchOp::Put {
                    occurred,
                    learned_at,
                    ..
                } => (*occurred, *learned_at),
                _ => (TimeRange { start: 10, end: 10 }, 10),
            };
            let entry = JournalEntry {
                scope,
                role: JournalRole::TurnPut,
                learned_at,
                occurred,
                op,
            };
            crate::batch::apply_ops_session(
                &session.read_view()?,
                &route,
                &vault.config,
                &vault.analyzer,
                wtxn,
                vec![entry],
            )?;
        }
        Ok(segment)
    })?;
    between()?;
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
        provenance: None,
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

/// A claim on the owner holding `value`, as the owner states it.
fn owner_claim_body(owner: EntityId, value: &str) -> Result<Vec<u8>> {
    let mut body = ClaimBody::new(
        "test.replacement",
        ClaimSubject::Entity(owner),
        rmpv::Value::from(value),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    crate::claim::encode_claim_body(&body)
}

/// A claim on `owner` that a local put writes with no envelope. A local
/// body change leaves base's index to idle publication, where a replicated
/// one drops the old body's text at once.
fn local_claim_body(owner: EntityId, value: &str) -> Result<Vec<u8>> {
    let body = ClaimBody::new(
        "test.status",
        ClaimSubject::Entity(owner),
        rmpv::Value::from(value),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    crate::claim::encode_claim_body(&body)
}

/// The room's put of `claim` holding `body`, under the given stamps.
fn claim_put(claim: EntityId, (occurred, learned_at, body): (TimeRange, u64, Vec<u8>)) -> BatchOp {
    BatchOp::Put {
        id: claim,
        entity_type: ENTITY_TYPE_CLAIM,
        occurred,
        learned_at,
        data: body,
        allow_maintenance: false,
        allow_reserved_predicate: false,
        hub_sync_imported: false,
    }
}

fn room_text(id: EntityId, word: &str) -> BatchOp {
    BatchOp::Text {
        id,
        fields: vec![("body".to_owned(), word.to_owned())],
    }
}

/// Stages `body` for `claim` in the room, found by `word`: the room's put
/// and its text, with no vector.
fn replace_in_room(
    vault: &Vault,
    session: &OffRecordSession<'_>,
    claim: EntityId,
    put: (TimeRange, u64, Vec<u8>),
    word: &str,
) -> Result<()> {
    stage_in_room(
        vault,
        session,
        vec![claim_put(claim, put), room_text(claim, word)],
    )
}

/// The fields a pack in the room hydrates for `claim`, found by `word`.
fn room_pack_fields(
    vault: &Vault,
    session: &OffRecordSession<'_>,
    claim: EntityId,
    word: &str,
) -> Result<String> {
    let view = session.read_view()?;
    let pack = vault
        .context_pack()
        .search_text(word, 10)
        .reading(view.read())
        .run()?;
    let entity = pack
        .results
        .iter()
        .find(|entity| entity.id == claim)
        .unwrap_or_else(|| panic!("{word} finds the claim in the room, got {pack:?}"));
    Ok(serde_json::to_string(&entity.fields).expect("fields json"))
}

/// The ids a vector search in the room returns for `query`.
fn vector_hits_in_room(
    vault: &Vault,
    session: &OffRecordSession<'_>,
    query: [f32; 4],
) -> Result<Vec<EntityId>> {
    let view = session.read_view()?;
    let hits = vault
        .query()
        .search_vector(&query, 10)
        .reading(view.read())
        .run()?;
    Ok(hits.iter().map(|hit| hit.id).collect())
}

/// The room embeds `other` after it hid base's vector of `hidden`, base's
/// only graph node: the room's walk enters base's graph there (Sol R21).
/// The room's turn commits, and its search finds `other`, never `hidden`.
fn embed_past_a_hidden_entry(
    vault: &Vault,
    session: &OffRecordSession<'_>,
    hidden: EntityId,
    other: EntityId,
) -> Result<()> {
    stage_in_room(
        vault,
        session,
        vec![room_put(other), room_vector(other, [1.0, 0.0, 0.0, 0.0])],
    )?;
    let hits = vector_hits_in_room(vault, session, [1.0, 0.0, 0.0, 0.0])?;
    assert!(
        hits.contains(&other) && !hits.contains(&hidden),
        "the room finds the row it embedded and not the one it hid, got {hits:?}"
    );
    Ok(())
}

/// A room that replaces a base claim's body indexes the replacement at
/// once, so the replacement is the revision the room has indexed. A pack
/// and the owner's recall in the room find the claim by the room's words
/// and read the room's body, at the room's revision; base's vector, which
/// the room did not restage, no longer finds it there, and the room still
/// embeds another row. Base reads its own.
#[test]
fn a_claim_the_room_replaced_is_read_at_the_rooms_revision() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let claim = entity_id(0xD0);
    // Replicated: the fixture isolates the room's read, not the write gate.
    vault
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &owner_claim_body(owner, "basevalue")?,
        )
        .text(&claim, &[("body", "replacementbaseword")])
        .vector(&claim, &[1.0, 0.0, 0.0, 0.0])
        .edge(&claim, crate::EdgeKind::ClaimOf, &owner, 1.0)
        .commit()?;
    let base_revision = vault.indexed_revision(&claim)?.map(|revision| revision.0);
    let session = enter(&vault, "sess-room-replacement")?;
    replace_in_room(
        &vault,
        &session,
        claim,
        (
            TimeRange { start: 10, end: 10 },
            10,
            owner_claim_body(owner, "roomvalue")?,
        ),
        "roomreplacementneedle",
    )?;
    let fields = |entity: &crate::context_pack::ContextEntity| {
        serde_json::to_string(&entity.fields).expect("fields json")
    };

    let view = session.read_view()?;
    let pack = vault
        .context_pack()
        .search_text("roomreplacementneedle", 10)
        .reading(view.read())
        .run()?;
    let in_room = pack
        .results
        .iter()
        .find(|entity| entity.id == claim)
        .unwrap_or_else(|| panic!("the room's words find the claim, got {pack:?}"));
    let in_room_fields = fields(in_room);
    assert!(
        in_room_fields.contains("roomvalue") && !in_room_fields.contains("basevalue"),
        "the room's pack reads the room's body, got {in_room_fields}"
    );
    assert!(
        in_room.source_revision_ref.is_some() && in_room.source_revision_ref != base_revision,
        "at the room's revision, got {:?}",
        in_room.source_revision_ref
    );
    drop(view);
    assert!(
        !vector_hits_in_room(&vault, &session, [1.0, 0.0, 0.0, 0.0])?.contains(&claim),
        "base's vector belongs to base's body, not the room's"
    );
    embed_past_a_hidden_entry(&vault, &session, claim, entity_id(0xC9))?;

    let recalled = vault
        .memory(owner, crate::edge::EdgeActorClass::Human)
        .recall_in_session(
            &session,
            "roomreplacementneedle",
            crate::memory::Effort::Light,
            &crate::memory::RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("the owner's recall in the room");
    let values: Vec<_> = recalled
        .items
        .iter()
        .map(|item| item.value_text.as_str())
        .collect();
    assert!(
        values.iter().any(|value| value.contains("roomvalue"))
            && !values.iter().any(|value| value.contains("basevalue")),
        "the owner's recall in the room reads the room's body, got {values:?}"
    );

    let on_base = vault
        .context_pack()
        .search_text("replacementbaseword", 10)
        .run()?;
    let in_base = on_base
        .results
        .iter()
        .find(|entity| entity.id == claim)
        .unwrap_or_else(|| panic!("base's words find the claim, got {on_base:?}"));
    let in_base_fields = fields(in_base);
    assert!(
        in_base_fields.contains("basevalue") && !in_base_fields.contains("roomvalue"),
        "base reads its own body, got {in_base_fields}"
    );
    assert_eq!(in_base.source_revision_ref, base_revision);
    let base_hits = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .run()?;
    assert!(
        base_hits.iter().any(|hit| hit.id == claim),
        "base's vector still finds it in base"
    );
    session.close()?;
    Ok(())
}

/// Base holds a claim whose body changed after it was indexed: its text and
/// vector still name the old body. A room that stages that same body again,
/// with the room's words and no vector, indexes it at once. A pack in the
/// room reads the body the room indexed, and the old body's vector no
/// longer finds it there.
#[test]
fn a_room_that_restages_a_pending_base_body_reads_it_at_its_own_revision() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let claim = entity_id(0xDB);
    let occurred = TimeRange { start: 1, end: 1 };
    let body = |value: &str| local_claim_body(owner, value);
    vault
        .batch()
        .put(
            &claim,
            ENTITY_TYPE_CLAIM,
            occurred,
            1,
            &body("indexedvalue")?,
        )
        .text(&claim, &[("body", "pendingbaseword")])
        .vector(&claim, &[1.0, 0.0, 0.0, 0.0])
        .commit()?;
    let pending = body("pendingvalue")?;
    vault
        .batch()
        .put(&claim, ENTITY_TYPE_CLAIM, occurred, 1, &pending)
        .commit()?;
    let on_base = vault
        .context_pack()
        .search_text("pendingbaseword", 10)
        .run()?;
    let in_base = on_base
        .results
        .iter()
        .find(|entity| entity.id == claim)
        .unwrap_or_else(|| panic!("base's words find the claim, got {on_base:?}"));
    assert!(
        serde_json::to_string(&in_base.fields)
            .expect("fields json")
            .contains("indexedvalue"),
        "base has not indexed its new body yet"
    );
    let session = enter(&vault, "sess-room-pending-retry")?;
    replace_in_room(
        &vault,
        &session,
        claim,
        (occurred, 1, pending),
        "roomretryneedle",
    )?;

    let fields = room_pack_fields(&vault, &session, claim, "roomretryneedle")?;
    assert!(
        fields.contains("pendingvalue") && !fields.contains("indexedvalue"),
        "the room reads the body it indexed, got {fields}"
    );
    assert!(
        !vector_hits_in_room(&vault, &session, [1.0, 0.0, 0.0, 0.0])?.contains(&claim),
        "the old body's vector does not find it in the room"
    );
    session.close()?;
    Ok(())
}

/// Base holds a claim it has indexed and not embedded yet. A room replaces
/// its body with the room's words and no vector, and before the room's turn
/// commits, base's embedding of its own body lands. That vector describes
/// base's body, so it does not find the claim in the room, and the room
/// still embeds another row; base's search finds it.
#[test]
fn a_room_hides_a_base_vector_that_lands_while_its_turn_is_open() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let claim = entity_id(0xD3);
    vault
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &owner_claim_body(owner, "basevalue")?,
        )
        .text(&claim, &[("body", "unembeddedbaseword")])
        .commit()?;
    let session = enter(&vault, "sess-room-late-embedding")?;
    stage_in_room_then(
        &vault,
        &session,
        vec![
            claim_put(
                claim,
                (
                    TimeRange { start: 10, end: 10 },
                    10,
                    owner_claim_body(owner, "roomvalue")?,
                ),
            ),
            room_text(claim, "lateembeddingneedle"),
        ],
        || vault.batch().vector(&claim, &[1.0, 0.0, 0.0, 0.0]).commit(),
    )?;

    let fields = room_pack_fields(&vault, &session, claim, "lateembeddingneedle")?;
    assert!(
        fields.contains("roomvalue") && !fields.contains("basevalue"),
        "the room reads the body it indexed, got {fields}"
    );
    assert!(
        !vector_hits_in_room(&vault, &session, [1.0, 0.0, 0.0, 0.0])?.contains(&claim),
        "base's vector of its own body does not find the room's"
    );
    embed_past_a_hidden_entry(&vault, &session, claim, entity_id(0xCA))?;
    let base_hits = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .run()?;
    assert!(
        base_hits.iter().any(|hit| hit.id == claim),
        "base's embedding landed, got {base_hits:?}"
    );
    session.close()?;
    Ok(())
}

/// Base changed a claim's body after it indexed it, never embedded the old
/// body, and holds the new body's vector for its idle pass. A room stages
/// that same new body with its words and no vector, and base's idle pass
/// publishes the vector before the room's turn commits. That vector
/// describes the room's body too, so it finds the claim in the room.
#[test]
fn a_room_keeps_the_vector_base_publishes_for_the_body_it_restaged() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let claim = entity_id(0xC7);
    let occurred = TimeRange { start: 1, end: 1 };
    vault
        .batch()
        .put(
            &claim,
            ENTITY_TYPE_CLAIM,
            occurred,
            1,
            &local_claim_body(owner, "indexedvalue")?,
        )
        .text(&claim, &[("body", "idleoldword")])
        .commit()?;
    let pending = local_claim_body(owner, "pendingvalue")?;
    vault
        .batch()
        .put(&claim, ENTITY_TYPE_CLAIM, occurred, 1, &pending)
        .commit()?;
    vault.put_vector(&claim, &[1.0, 0.0, 0.0, 0.0])?;
    let session = enter(&vault, "sess-room-idle-vector")?;
    stage_in_room_then(
        &vault,
        &session,
        vec![
            claim_put(claim, (occurred, 1, pending)),
            room_text(claim, "idlevectorneedle"),
        ],
        || {
            vault.set_indexed_idle_delay_ms(0)?;
            vault.refresh_staged_indexed_at_idle(u64::MAX).map(drop)
        },
    )?;

    let base_hits = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .run()?;
    assert!(
        base_hits.iter().any(|hit| hit.id == claim),
        "base's idle pass published the vector, got {base_hits:?}"
    );
    assert!(
        vector_hits_in_room(&vault, &session, [1.0, 0.0, 0.0, 0.0])?.contains(&claim),
        "base's vector of the room's body finds it in the room"
    );
    session.close()?;
    Ok(())
}

/// Base holds a claim with the vector of the body it indexed, and has
/// changed the body since, with no vector of the new one yet. A room puts
/// back the body base indexed, with its words and no vector. Base's vector
/// describes the room's body, so it finds the claim in the room.
#[test]
fn a_room_that_puts_back_base_indexed_body_keeps_base_vector_of_it() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let claim = entity_id(0xC8);
    let occurred = TimeRange { start: 1, end: 1 };
    let indexed = local_claim_body(owner, "indexedvalue")?;
    vault
        .batch()
        .put(&claim, ENTITY_TYPE_CLAIM, occurred, 1, &indexed)
        .text(&claim, &[("body", "putbackbaseword")])
        .vector(&claim, &[1.0, 0.0, 0.0, 0.0])
        .commit()?;
    vault
        .batch()
        .put(
            &claim,
            ENTITY_TYPE_CLAIM,
            occurred,
            1,
            &local_claim_body(owner, "pendingvalue")?,
        )
        .commit()?;
    let session = enter(&vault, "sess-room-put-back")?;
    replace_in_room(
        &vault,
        &session,
        claim,
        (occurred, 1, indexed),
        "putbackneedle",
    )?;

    let fields = room_pack_fields(&vault, &session, claim, "putbackneedle")?;
    assert!(
        fields.contains("indexedvalue") && !fields.contains("pendingvalue"),
        "the room reads the body it put back, got {fields}"
    );
    assert!(
        vector_hits_in_room(&vault, &session, [1.0, 0.0, 0.0, 0.0])?.contains(&claim),
        "base's vector of the body the room put back finds it in the room"
    );
    session.close()?;
    Ok(())
}

/// A room moves a base claim to another world, and base's idle pass
/// publishes the words of base's newer body before the room's turn
/// commits. A credential for the room's world alone reads base alone in the
/// room (`scoped_read_in_session`), so neither base's new words nor the
/// room's find the claim for it: the window's stale words reach only a
/// reader of every world (Engine ruling on Sol R22).
#[test]
fn a_credential_for_one_world_finds_nothing_by_base_words_published_while_a_room_moved_its_claim()
-> Result<()> {
    let (_dir, vault) = open_test_vault();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let key = one_world_reader(&vault)?;
    let room_world = entity_id(0xD2);
    let claim = entity_id(0xCB);
    let occurred = TimeRange { start: 1, end: 1 };
    vault
        .batch()
        .put(
            &claim,
            ENTITY_TYPE_CLAIM,
            occurred,
            1,
            &local_claim_body(owner, "worldindexedvalue")?,
        )
        .text(&claim, &[("body", "worldindexedword")])
        .commit()?;
    vault
        .batch()
        .put(
            &claim,
            ENTITY_TYPE_CLAIM,
            occurred,
            1,
            &local_claim_body(owner, "worldpendingvalue")?,
        )
        .text(&claim, &[("body", "worldpendingneedle")])
        .commit()?;
    let mut moved = ClaimBody::new(
        "test.status",
        ClaimSubject::Entity(owner),
        rmpv::Value::from("worldroomvalue"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    moved.world = Some(room_world);
    let session = enter(&vault, "sess-room-world-move")?;
    stage_in_room_then(
        &vault,
        &session,
        vec![
            claim_put(
                claim,
                (
                    TimeRange { start: 10, end: 10 },
                    10,
                    crate::claim::encode_claim_body(&moved)?,
                ),
            ),
            room_text(claim, "worldroomneedle"),
        ],
        || {
            vault.set_indexed_idle_delay_ms(0)?;
            vault.refresh_staged_indexed_at_idle(u64::MAX).map(drop)
        },
    )?;

    let on_base = vault
        .context_pack()
        .search_text("worldpendingneedle", 10)
        .run()?;
    assert!(
        on_base.results.iter().any(|entity| entity.id == claim),
        "base's idle pass published its new words, got {on_base:?}"
    );
    let view = session.read_view()?;
    for word in ["worldpendingneedle", "worldroomneedle"] {
        let found = vault
            .scoped_read_in_session(key.clone(), &view)
            .search_text(word, 10, None)?;
        assert!(
            found.value.iter().all(|hit| hit.id != claim),
            "{word} finds nothing for the credential, got {:?}",
            found.value
        );
    }
    drop(view);
    session.close()?;
    Ok(())
}

/// Base's claim `claim` on `owner`, holding `value`, found by `word`, and
/// embedded at `vector` if given. Replicated: the fixture isolates the
/// room's read, not the write gate.
fn base_claim_for_the_room(
    vault: &Vault,
    owner: EntityId,
    claim: EntityId,
    (value, word): (&str, &str),
    vector: Option<[f32; 4]>,
) -> Result<()> {
    let mut batch = vault
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &owner_claim_body(owner, value)?,
        )
        .text(&claim, &[("body", word)])
        .edge(&claim, crate::EdgeKind::ClaimOf, &owner, 1.0);
    if let Some(vector) = vector {
        batch = batch.vector(&claim, &vector);
    }
    batch.commit()
}

/// A room embeds a base claim's body of its own, then changes the body
/// again and indexes it with its words and no vector. The vector the room
/// staged describes the earlier body, so it no longer finds the claim there
/// (Sol R23).
#[test]
fn a_room_that_changes_a_rows_body_again_hides_its_own_vector_of_the_last_one() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let claim = entity_id(0xCC);
    base_claim_for_the_room(&vault, owner, claim, ("ownbasevalue", "ownbaseword"), None)?;
    let session = enter(&vault, "sess-room-own-vector")?;
    stage_in_room(
        &vault,
        &session,
        vec![
            claim_put(
                claim,
                (
                    TimeRange { start: 10, end: 10 },
                    10,
                    owner_claim_body(owner, "ownembeddedvalue")?,
                ),
            ),
            room_vector(claim, [1.0, 0.0, 0.0, 0.0]),
            room_text(claim, "ownembeddedword"),
        ],
    )?;
    assert!(
        vector_hits_in_room(&vault, &session, [1.0, 0.0, 0.0, 0.0])?.contains(&claim),
        "the room's vector of its body finds the claim"
    );
    replace_in_room(
        &vault,
        &session,
        claim,
        (
            TimeRange { start: 11, end: 11 },
            11,
            owner_claim_body(owner, "ownchangedvalue")?,
        ),
        "ownchangedneedle",
    )?;

    let fields = room_pack_fields(&vault, &session, claim, "ownchangedneedle")?;
    assert!(
        fields.contains("ownchangedvalue") && !fields.contains("ownembeddedvalue"),
        "the room reads its new body, got {fields}"
    );
    assert!(
        !vector_hits_in_room(&vault, &session, [1.0, 0.0, 0.0, 0.0])?.contains(&claim),
        "the room's vector of its earlier body does not find the new one"
    );
    session.close()?;
    Ok(())
}

/// A room replaces a base claim's body and indexes it, which hides base's
/// vector, then puts base's body back in a later turn and indexes that. Base's
/// vector describes the body the room put back, so it finds the claim in
/// the room again (Sol R23).
#[test]
fn a_room_that_puts_base_body_back_after_another_serves_base_vector_of_it() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let claim = entity_id(0xCD);
    base_claim_for_the_room(
        &vault,
        owner,
        claim,
        ("backbasevalue", "backbaseword"),
        Some([1.0, 0.0, 0.0, 0.0]),
    )?;
    let session = enter(&vault, "sess-room-back-again")?;
    replace_in_room(
        &vault,
        &session,
        claim,
        (
            TimeRange { start: 10, end: 10 },
            10,
            owner_claim_body(owner, "backroomvalue")?,
        ),
        "backroomword",
    )?;
    assert!(
        !vector_hits_in_room(&vault, &session, [1.0, 0.0, 0.0, 0.0])?.contains(&claim),
        "base's vector of its body does not find the room's"
    );
    replace_in_room(
        &vault,
        &session,
        claim,
        (
            TimeRange { start: 1, end: 1 },
            1,
            owner_claim_body(owner, "backbasevalue")?,
        ),
        "backagainneedle",
    )?;

    let fields = room_pack_fields(&vault, &session, claim, "backagainneedle")?;
    assert!(
        fields.contains("backbasevalue") && !fields.contains("backroomvalue"),
        "the room reads the body it put back, got {fields}"
    );
    assert!(
        vector_hits_in_room(&vault, &session, [1.0, 0.0, 0.0, 0.0])?.contains(&claim),
        "base's vector of that body finds it in the room again"
    );
    session.close()?;
    Ok(())
}

/// Base sheds its rebuildable graph (SLIM) while its only vector is one a
/// room hides. The room's next vector rebuilds the graph the room inherits,
/// the hidden row still a node of it, so base's later graph leaves the
/// room's with an entry: the room embeds again, and its search finds both
/// rows it embedded and not the hidden one (Sol R23).
#[test]
fn a_room_embeds_over_a_shed_base_graph_whose_only_node_it_hides() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let claim = entity_id(0xCE);
    base_claim_for_the_room(
        &vault,
        owner,
        claim,
        ("shedbasevalue", "shedbaseword"),
        Some([1.0, 0.0, 0.0, 0.0]),
    )?;
    let session = enter(&vault, "sess-room-shed-graph")?;
    replace_in_room(
        &vault,
        &session,
        claim,
        (
            TimeRange { start: 10, end: 10 },
            10,
            owner_claim_body(owner, "shedroomvalue")?,
        ),
        "shedroomword",
    )?;
    vault.with_write_txn(|txn| crate::hnsw::drop_rebuildable_hnsw(&vault.store, txn).map(drop))?;
    let first = entity_id(0xCF);
    stage_in_room(
        &vault,
        &session,
        vec![room_put(first), room_vector(first, [0.8, 0.6, 0.0, 0.0])],
    )?;
    put_vector(&vault, entity_id(0xE3), [0.0, 1.0, 0.0, 0.0])?;
    let second = entity_id(0xE4);
    stage_in_room(
        &vault,
        &session,
        vec![room_put(second), room_vector(second, [0.6, 0.8, 0.0, 0.0])],
    )?;

    let hits = vector_hits_in_room(&vault, &session, [1.0, 0.0, 0.0, 0.0])?;
    assert!(
        hits.contains(&first) && hits.contains(&second) && !hits.contains(&claim),
        "the room finds the rows it embedded and not the one it hid, got {hits:?}"
    );
    session.close()?;
    Ok(())
}

/// A scoped read in the room fetches as many candidates as the room's read
/// holds, base's rows and the room's. A room row outside the worlds the
/// lane asks for then takes no place from a base row inside them.
#[test]
fn a_scoped_search_in_the_room_keeps_a_base_row_past_a_room_row_its_worlds_refuse() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let world = entity_id(0xD8);
    put_entity(&vault, world, ENTITY_TYPE_WORLD, 1, 1, 1)?;
    let base_claim = entity_id(0xD9);
    vault
        .batch()
        .put(
            &base_claim,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &active_claim_body(None),
        )
        .vector(&base_claim, &[0.8, 0.6, 0.0, 0.0])
        .commit()?;
    let base_only = || crate::pipeline::WorldAuthoritySet::new(true, []);
    let key = crate::claim::ScopedReadActorKey::vault_owner(owner);
    let outside = vault
        .scoped_read(key.clone())
        .within_worlds(base_only()?)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 1, None)?;
    assert_eq!(
        outside.value.iter().map(|hit| hit.id).collect::<Vec<_>>(),
        vec![base_claim],
        "base's read finds its claim"
    );

    let session = enter(&vault, "sess-room-scoped-bound")?;
    let room_claim = entity_id(0xDA);
    stage_in_room(
        &vault,
        &session,
        vec![
            BatchOp::Put {
                id: room_claim,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: TimeRange { start: 10, end: 10 },
                learned_at: 10,
                data: active_claim_body(Some(world)),
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            },
            room_vector(room_claim, [1.0, 0.0, 0.0, 0.0]),
        ],
    )?;
    let view = session.read_view()?;
    let inside = vault
        .scoped_read_in_session(key, &view)
        .within_worlds(base_only()?)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 1, None)?;
    assert_eq!(
        inside.value.iter().map(|hit| hit.id).collect::<Vec<_>>(),
        vec![base_claim],
        "the room's nearer claim in another world takes no place from it"
    );
    drop(view);
    session.close()?;
    Ok(())
}

/// A room puts another body for a row, then puts base's body back and
/// indexes the row with its own words. What it publishes is the body base
/// indexed: a pack in the room reads it by the room's words, and base's
/// vector of that body still finds the row there.
#[test]
fn a_room_that_puts_a_rows_body_back_keeps_the_index_of_that_body() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let claim = entity_id(0xDC);
    let occurred = TimeRange { start: 1, end: 1 };
    let kept = owner_claim_body(owner, "keptvalue")?;
    vault
        .batch()
        .put_replicated(&claim, ENTITY_TYPE_CLAIM, occurred, 1, &kept)
        .text(&claim, &[("body", "keptbaseword")])
        .vector(&claim, &[1.0, 0.0, 0.0, 0.0])
        .commit()?;
    let session = enter(&vault, "sess-room-two-puts")?;
    stage_in_room(
        &vault,
        &session,
        vec![
            claim_put(
                claim,
                (
                    TimeRange { start: 10, end: 10 },
                    10,
                    owner_claim_body(owner, "passingvalue")?,
                ),
            ),
            claim_put(claim, (occurred, 1, kept)),
            room_text(claim, "twoputneedle"),
        ],
    )?;

    let fields = room_pack_fields(&vault, &session, claim, "twoputneedle")?;
    assert!(
        fields.contains("keptvalue") && !fields.contains("passingvalue"),
        "the room reads the body its last put staged, got {fields}"
    );
    assert!(
        vector_hits_in_room(&vault, &session, [1.0, 0.0, 0.0, 0.0])?.contains(&claim),
        "and base's vector of that body still finds it"
    );
    session.close()?;
    Ok(())
}

/// A room that hid a row's text took it out of the BM25 totals it stages.
/// On record, base indexes another row, which those totals never counted.
/// Back off record, the room replaces that row as well, with a vector and
/// no text: hiding its text takes it out of totals that never held it,
/// and the write lands.
#[test]
fn a_room_hides_the_text_of_a_row_base_indexed_after_its_totals() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let base_claim = |id: EntityId, word: &str| -> Result<()> {
        vault
            .batch()
            .put_replicated(
                &id,
                ENTITY_TYPE_CLAIM,
                TimeRange { start: 1, end: 1 },
                1,
                &owner_claim_body(owner, "basevalue")?,
            )
            .text(&id, &[("body", word)])
            .commit()
    };
    let first = entity_id(0xDD);
    base_claim(first, "hiddenfirstword")?;
    let session = enter(&vault, "sess-room-hidden-totals")?;
    let replace_with_vector = |id: EntityId| -> Result<()> {
        stage_in_room(
            &vault,
            &session,
            vec![
                claim_put(
                    id,
                    (
                        TimeRange { start: 10, end: 10 },
                        10,
                        owner_claim_body(owner, "roomvalue")?,
                    ),
                ),
                room_vector(id, [1.0, 0.0, 0.0, 0.0]),
            ],
        )
    };
    replace_with_vector(first)?;
    session.flip_on_record()?;
    let later = entity_id(0xDE);
    base_claim(later, "hiddenlaterword")?;
    session.flip_off_record()?;

    replace_with_vector(later)?;
    let view = session.read_view()?;
    let by_words = vault
        .query()
        .search_text("hiddenlaterword", 10)
        .reading(view.read())
        .run()?;
    assert!(
        by_words.iter().all(|hit| hit.id != later),
        "base's words for the old body no longer find it in the room, got {by_words:?}"
    );
    drop(view);
    assert!(
        vector_hits_in_room(&vault, &session, [1.0, 0.0, 0.0, 0.0])?.contains(&later),
        "the room's vector finds it"
    );
    session.close()?;
    Ok(())
}

/// A room apply that writes one row twice (a put and its text, a put and
/// its vector, two puts) is refused before anything stages: its view reads
/// the overlay as it was before the call, so the second write would build
/// on the row as it was before the first.
#[test]
fn a_room_apply_that_writes_one_row_twice_is_refused() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let session = enter(&vault, "sess-room-put-and-index")?;
    let route = session.write_route()?;
    let overlay = session.overlay();
    let scope = JournalScope::new(EntityId::now(), EntityId::now());
    let entry = |op| JournalEntry {
        scope,
        role: JournalRole::TurnPut,
        learned_at: 10,
        occurred: TimeRange { start: 10, end: 10 },
        op,
    };
    let row = entity_id(0xDF);
    for second in [
        room_text(row, "refusedneedle"),
        room_vector(row, [1.0, 0.0, 0.0, 0.0]),
        room_put(row),
    ] {
        let refused = vault.with_write_txn_grouped(|wtxn| {
            let _segment = overlay.install_txn_segment()?;
            crate::batch::apply_ops_session(
                &session.read_view()?,
                &route,
                &vault.config,
                &vault.analyzer,
                wtxn,
                vec![entry(room_put(row)), entry(second.clone())],
            )
        });
        assert!(
            matches!(refused, Err(crate::error::Error::InvariantViolation(_))),
            "got {refused:?}"
        );
    }
    let view = session.read_view()?;
    assert!(!view.read().room_holds(&row)?, "nothing of it staged");
    drop(view);
    session.close()?;
    Ok(())
}
