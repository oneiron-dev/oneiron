use super::super::*;
use super::support::*;
use crate::attempt_queue::{ClaimAttempt, ClaimOutcome};
use crate::deletion::{TombstoneReason, TombstoneValueV2};
use crate::error::Result;
use crate::registry::ENTITY_TYPE_PERSON;
use std::collections::BTreeSet;

fn indexes_and_delete<P: Backend>(ports: &P) -> Result<()> {
    let source = id(31);
    let derived = id(32);
    let older = id(33);
    let unrelated = id(34);
    let span = SourceSpan {
        document: source,
        frontier: 1,
    };
    let mut txn = ports.write()?;
    for entity in [source, derived, older, unrelated] {
        ports.port_entity_put(&mut txn, &entity, &row(ENTITY_TYPE_PERSON, b"nebula"))?;
    }
    let short = ports.port_short_id_get_or_create(&mut txn, &derived)?;
    assert_eq!(
        ports.port_short_id_get_or_create(&mut txn, &derived)?,
        short
    );
    let hash = (xxhash_rust::xxh32::xxh32(b"nebula", 0) % 256) as u8;
    assert_eq!(
        ports.port_short_id_resolve(&txn, &short, hash)?.unwrap().id,
        derived
    );
    assert!(
        ports
            .port_short_id_resolve(&txn, &short, hash.wrapping_add(1))?
            .is_none()
    );
    assert_eq!(
        ports
            .port_short_id_resolve_batch(&txn, &[(&short, hash), ("zz0", hash)])?
            .iter()
            .filter(|v| v.is_some())
            .count(),
        1
    );
    ports.port_retrieval_upsert(
        &mut txn,
        &derived,
        Some(&[1.0, 0.0, 0.0, 0.0]),
        Some(&[("body", "nebula")]),
    )?;
    assert_eq!(
        ports
            .port_retrieval_vector_search(&txn, &[1.0, 0.0, 0.0, 0.0], 10)?
            .iter()
            .map(|r| r.id)
            .collect::<Vec<_>>(),
        vec![derived]
    );
    assert_eq!(
        ports
            .port_retrieval_text_search(&txn, "nebula", 10)?
            .iter()
            .map(|r| r.id)
            .collect::<Vec<_>>(),
        vec![derived]
    );
    ports.port_dependency_put(&mut txn, span, &derived)?;
    ports.port_dependency_put(&mut txn, span, &derived)?;
    ports.port_dependency_put(
        &mut txn,
        SourceSpan {
            document: source,
            frontier: 0,
        },
        &older,
    )?;
    ports.port_dependency_put(
        &mut txn,
        SourceSpan {
            document: unrelated,
            frontier: 1,
        },
        &source,
    )?;
    assert_eq!(
        ports.port_dependency_list_by_source(&txn, span)?,
        vec![derived]
    );
    assert!(safe_read_asset_text(ports, &txn, &derived, &[1; 32], &[2; 32])?.is_none());
    assert_eq!(
        safe_read_asset_text(ports, &txn, &derived, &[1; 32], &[1; 32])?,
        Some(b"nebula".to_vec())
    );
    ports.commit(txn)?;
    // Aborting invalidation leaves both source and derived text readable.
    let mut txn = ports.write()?;
    ports.port_tombstone_create(
        &mut txn,
        &source,
        TombstoneValueV2 {
            reason: TombstoneReason::UserDelete,
            deleted_at: 100,
            request_id: [9; 16],
        },
    )?;
    drop(txn);
    let txn = ports.read()?;
    assert!(safe_read_text(ports, &txn, &derived)?.is_some());
    assert!(!ports.port_tombstone_is_deleted(&txn, &source)?);
    drop(txn);
    let mut txn = ports.write()?;
    ports.port_tombstone_create(
        &mut txn,
        &source,
        TombstoneValueV2 {
            reason: TombstoneReason::UserDelete,
            deleted_at: 100,
            request_id: [9; 16],
        },
    )?;
    assert!(ports.port_entity_delete(&mut txn, &source)?);
    assert!(ports.port_tombstone_is_deleted(&txn, &source)?);
    assert_eq!(
        ports.port_tombstone_clean_expired(&mut txn, u64::MAX, 100)?,
        0
    );
    for entity in [source, derived, older] {
        assert!(safe_read_text(ports, &txn, &entity)?.is_none());
    }
    assert_eq!(
        safe_read_text(ports, &txn, &unrelated)?,
        Some(b"nebula".to_vec())
    );
    assert!(
        ports
            .port_retrieval_vector_search(&txn, &[1.0, 0.0, 0.0, 0.0], 10)?
            .is_empty()
    );
    assert!(
        ports
            .port_retrieval_text_search(&txn, "nebula", 10)?
            .is_empty()
    );
    assert!(
        ports
            .port_short_id_resolve(&txn, &short, hash)?
            .unwrap()
            .body
            .is_none()
    );
    // Claiming the observable queue pins exactly the dependent set, not a counter.
    let mut queued = BTreeSet::new();
    while let ClaimOutcome::Claimed(job) = ports.port_job_claim(
        &mut txn,
        Some("derived.regenerate"),
        ClaimAttempt {
            lease_owner: "regenerator".into(),
            now: 999,
        },
    )? {
        assert_eq!(&job.payload[..16], source.as_bytes());
        queued.insert(crate::EntityId::from_bytes(
            job.payload[16..].try_into().unwrap(),
        )?);
    }
    assert_eq!(queued, BTreeSet::from([derived, older]));
    ports.commit(txn)
}
#[test]
fn indexes_and_exact_delete_dependents_lmdb_and_memory() -> Result<()> {
    let (_temp, vault, memory, _clock) = fixtures();
    indexes_and_delete(&vault)?;
    indexes_and_delete(&memory)
}
#[test]
fn derived_edges_register_dependencies_in_the_same_transaction() -> Result<()> {
    fn check<P: Backend>(ports: &P) -> Result<()> {
        let source = id(41);
        let dependent = id(42);
        let mut txn = ports.write()?;
        ports.port_entity_put(&mut txn, &source, &row(ENTITY_TYPE_PERSON, b"source"))?;
        ports.port_entity_put(&mut txn, &dependent, &row(ENTITY_TYPE_PERSON, b"derived"))?;
        ports.port_edge_upsert(
            &mut txn,
            &dependent,
            crate::EdgeKind::DerivedFrom,
            &source,
            1.0,
        )?;
        assert_eq!(
            ports.port_dependency_list_by_source(
                &txn,
                SourceSpan {
                    document: source,
                    frontier: 1
                }
            )?,
            vec![dependent]
        );
        drop(txn);
        let txn = ports.read()?;
        assert!(
            ports
                .port_dependency_list_by_source(
                    &txn,
                    SourceSpan {
                        document: source,
                        frontier: 1
                    }
                )?
                .is_empty()
        );
        Ok(())
    }
    let (_temp, vault, memory, _clock) = fixtures();
    check(&vault)?;
    check(&memory)
}
