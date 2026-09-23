use super::super::*;
use super::support::*;
use crate::{
    EdgeKind,
    error::Result,
    registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON},
};

fn query_and_regeneration<P: Backend>(ports: &P) -> Result<()> {
    let source = id(71);
    let dependent = id(72);
    let other = id(73);
    let span = SourceSpan {
        document: source,
        frontier: 1,
    };
    let mut txn = ports.write()?;
    let initial_count = ports.port_entity_count(&txn)?;
    // The LMDB write door mints a substrate FACET beside every PERSON; ORG rows
    // keep the counts and timelines below to these three.
    for id in [source, dependent, other] {
        ports.port_entity_put(&mut txn, &id, &row(ENTITY_TYPE_ORG, b"old"))?;
    }
    assert_eq!(
        ports
            .port_entity_ids_by_type(&txn, ENTITY_TYPE_ORG, Some(source))?
            .take(1)
            .collect::<Result<Vec<_>>>()?,
        vec![dependent]
    );
    assert_eq!(
        ports.port_entity_record(&txn, &dependent)?.unwrap().body,
        b"old"
    );
    ports.port_edge_upsert(&mut txn, &dependent, EdgeKind::DerivedFrom, &source, 1.0)?;
    ports.port_edge_upsert(&mut txn, &other, EdgeKind::DerivedFrom, &source, 1.0)?;
    assert_eq!(
        ports
            .port_edges(
                &txn,
                &source,
                EdgeDirection::In,
                Some(EdgeKind::DerivedFrom),
                Some(dependent)
            )?
            .take(1)
            .next()
            .unwrap()?
            .target,
        other
    );

    assert_eq!(ports.port_entity_count(&txn)?, initial_count + 3);
    assert_eq!(
        ports
            .port_entity_ids_by_type_descending(&txn, ENTITY_TYPE_ORG)?
            .take(2)
            .collect::<Result<Vec<_>>>()?,
        vec![other, dependent]
    );
    let q = TimelineQuery {
        after: Some(EntityTime {
            id: source,
            timestamp: 1,
        }),
        ..Default::default()
    };
    assert_eq!(
        ports
            .port_entity_timeline(&txn, q)?
            .map(|row| row.map(|row| row.id))
            .collect::<Result<Vec<_>>>()?,
        vec![dependent, other]
    );
    assert_eq!(
        ports
            .port_entity_timeline(
                &txn,
                TimelineQuery {
                    reverse: true,
                    ..Default::default()
                }
            )?
            .next()
            .unwrap()?
            .id,
        other
    );
    assert_eq!(
        ports.port_entity_records(&txn)?.count() as u64,
        initial_count + 3
    );
    ports.port_retrieval_phonetic_upsert(&mut txn, &source, &["SRS", "SRS"])?;
    ports.port_retrieval_phonetic_upsert(&mut txn, &dependent, &["SRS", "DPN"])?;
    let ranked =
        ports.port_retrieval_phonetic_search(&txn, &["SRS".into(), "DPN".into(), "SRS".into()])?;
    assert_eq!(
        ranked.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![dependent, source]
    );
    assert_eq!(ranked[0].score, 2.4);
    ports.port_retrieval_upsert(&mut txn, &dependent, Some(&[1.0, 0.0, 0.0, 0.0]), None)?;
    assert_eq!(
        ports.port_retrieval_vector_get(&txn, &dependent)?,
        Some(vec![1.0, 0.0, 0.0, 0.0])
    );
    assert!(ports.port_short_id_reference(&txn, &dependent)?.is_some());
    ports.port_retrieval_mark_stale(&mut txn, &dependent)?;
    assert!(safe_read_text(ports, &txn, &dependent)?.is_none());
    assert!(ports.port_retrieval_vector_get(&txn, &dependent)?.is_none());
    assert!(!ports.port_dependency_complete_regeneration(&mut txn, &dependent, 1, &[span])?);
    let mut fresh = row(ENTITY_TYPE_ORG, b"new");
    fresh.learned_at = 2;
    ports.port_entity_put(&mut txn, &dependent, &fresh)?;
    assert!(safe_read_text(ports, &txn, &dependent)?.is_none());
    // A stale input version cannot certify freshly written output.
    assert!(!ports.port_dependency_complete_regeneration(
        &mut txn,
        &dependent,
        2,
        &[SourceSpan {
            frontier: 0,
            ..span
        }]
    )?);
    assert!(ports.port_dependency_complete_regeneration(&mut txn, &dependent, 2, &[span])?);
    assert_eq!(
        safe_read_text(ports, &txn, &dependent)?,
        Some(b"new".to_vec())
    );
    // An invalidation that arrives after the write fences a delayed completion.
    ports.port_retrieval_mark_stale(&mut txn, &dependent)?;
    assert!(!ports.port_dependency_complete_regeneration(&mut txn, &dependent, 2, &[span])?);
    fresh.learned_at = 3;
    ports.port_entity_put(&mut txn, &dependent, &fresh)?;
    ports.port_tombstone_create(
        &mut txn,
        &source,
        crate::deletion::TombstoneValueV2 {
            reason: crate::deletion::TombstoneReason::UserDelete,
            deleted_at: 100,
            request_id: [1; 16],
        },
    )?;
    assert!(!ports.port_dependency_complete_regeneration(&mut txn, &dependent, 3, &[span])?);
    assert!(safe_read_text(ports, &txn, &dependent)?.is_none());
    assert!(matches!(
        ports.port_dependency_put(&mut txn, span, &id(79)),
        Err(crate::Error::EntityNotFound)
    ));
    // Abort includes both dependency changes and completion state.
    drop(txn);
    let txn = ports.read()?;
    assert!(ports.port_entity_record(&txn, &dependent)?.is_none());
    Ok(())
}
#[test]
fn lazy_queries_and_generation_fence_lmdb_and_memory() -> Result<()> {
    let (_temp, vault, memory, _clock) = fixtures();
    query_and_regeneration(&vault)?;
    query_and_regeneration(&memory)
}
#[test]
fn lazy_type_cursor_does_not_decode_rows_past_the_caller_budget() -> Result<()> {
    let (_temp, vault, _memory, _clock) = fixtures();
    let mut txn = vault.write()?;
    let good = id(74);
    vault.port_entity_put(&mut txn, &good, &row(ENTITY_TYPE_PERSON, b"good"))?;
    // Later malformed storage is deliberately beyond the one-row page.
    vault
        .store
        .type_index
        .put(&mut txn, &[ENTITY_TYPE_PERSON, 255], &[])?;
    let page = vault
        .port_entity_ids_by_type(&txn, ENTITY_TYPE_PERSON, None)?
        .take(1)
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(page, vec![good]);
    assert!(
        vault
            .port_entity_ids_by_type(&txn, ENTITY_TYPE_PERSON, None)?
            .collect::<Result<Vec<_>>>()
            .is_err()
    );
    Ok(())
}

#[test]
fn storage_port_queries_read_one_composed_session_snapshot() -> Result<()> {
    use crate::session_overlay::{OverlayKeyspace, SessionOverlay};
    let (_temp, vault, _memory, _clock) = fixtures();
    let entity = id(76);
    vault.put_entity(
        &entity,
        ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"base",
    )?;
    let overlay = SessionOverlay::new(4096);
    let segment = overlay.install_txn_segment()?;
    let session_row = row(ENTITY_TYPE_PERSON, b"session");
    overlay.put(
        OverlayKeyspace::Entities,
        entity.as_bytes(),
        &session_row.encode(),
    )?;
    segment.commit()?;
    let view = vault.store.session_view(overlay.clone())?;
    let txn = vault.read()?;
    assert_eq!(
        view.port_entity_record(&txn, &entity)?.unwrap().body,
        b"session"
    );
    assert_eq!(
        vault.port_entity_record(&txn, &entity)?.unwrap().body,
        b"base"
    );
    assert_eq!(
        view.port_entity_ids_by_type(&txn, ENTITY_TYPE_PERSON, None)?
            .collect::<Result<Vec<_>>>()?,
        vec![entity]
    );
    drop(view);
    drop(txn);
    drop(overlay);
    Ok(())
}

#[test]
fn scoped_text_port_gates_candidates_before_limit_on_both_backends() -> Result<()> {
    fn check<P: Backend + RetrievalIndexExecution>(p: &P) -> Result<()> {
        let mut txn = p.write()?;
        for entity in [id(80), id(81)] {
            p.port_entity_put(&mut txn, &entity, &row(ENTITY_TYPE_PERSON, b"asteroid"))?;
            p.port_retrieval_upsert(&mut txn, &entity, None, Some(&[("body", "asteroid")]))?;
        }
        let rank = crate::config::Bm25RankProfile::default().to_bm25_config()?;
        let mut scope = |entity: &crate::EntityId| Ok(*entity == id(81));
        for (limit, expected) in [(0, Vec::new()), (1, vec![id(81)])] {
            let rows = p.port_retrieval_text_scoped(
                &txn,
                TextQuery {
                    query: "asteroid",
                    limit,
                    rank: &rank,
                    filter_all: true,
                    matches_scope: &mut scope,
                },
            )?;
            assert_eq!(rows.iter().map(|row| row.id).collect::<Vec<_>>(), expected);
        }
        Ok(())
    }
    let (_temp, vault, memory, _clock) = fixtures();
    check(&vault)?;
    check(&memory)
}
