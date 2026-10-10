use super::super::*;
use super::support::*;
use crate::{EdgeKind, error::Result, registry::ENTITY_TYPE_ORG};

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
    assert_eq!(
        ports
            .port_entity_raw_records(&txn)?
            .find(|entry| entry.as_ref().is_ok_and(|(id, _)| *id == dependent))
            .expect("inserted dependent row")?
            .1,
        row(ENTITY_TYPE_ORG, b"old").encode()
    );
    ports.port_edge_upsert(&mut txn, &dependent, EdgeKind::DerivedFrom, &source, 1.0)?;
    assert!(ports.port_edge_has_any(&txn, &dependent, EdgeDirection::Out)?);
    assert!(ports.port_edge_has_any(&txn, &source, EdgeDirection::In)?);
    assert!(!ports.port_edge_has_any(&txn, &source, EdgeDirection::Out)?);
    let edge_key = crate::store::Store::encode_edge_key(&dependent, EdgeKind::DerivedFrom, &source);
    assert!(ports.port_edge_rows_raw(&txn)?.any(|entry| {
        entry
            .as_ref()
            .is_ok_and(|(key, value)| key == &edge_key && !value.is_empty())
    }));
    ports.port_edge_upsert(&mut txn, &other, EdgeKind::DerivedFrom, &source, 1.0)?;
    assert_eq!(
        ports
            .port_edge_peers(&txn, &source, EdgeDirection::In, EdgeKind::DerivedFrom)?
            .collect::<Result<Vec<_>>>()?,
        vec![dependent, other]
    );
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
