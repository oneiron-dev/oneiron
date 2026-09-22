use super::super::*;
use super::support::*;
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::error::{Error, RegistryError, Result};
use crate::registry::*;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};
use crate::{EdgeKind, TimeRange};
use rmpv::Value;

fn entity_edge_place<P: Backend>(ports: &P) -> Result<()> {
    let a = id(1);
    let b = id(2);
    let session = id(3);
    let relationship = id(4);
    let turn = id(5);
    let summary = id(6);
    let asset = id(7);
    let body = map(&[
        ("provider", Value::from("registry")),
        ("providerId", Value::from("station-1")),
        ("name", Value::from("Station")),
    ]);
    let place = row(ENTITY_TYPE_PLACE, &body);
    let mut txn = ports.write()?;
    ports.port_place_put(&mut txn, &a, &place)?;
    ports.port_place_put(&mut txn, &b, &place)?;
    ports.port_entity_put(&mut txn, &relationship, &row(ENTITY_TYPE_PERSON, b"owner"))?;
    ports.port_entity_put(
        &mut txn,
        &session,
        &row(
            ENTITY_TYPE_SESSION,
            &map(&[("rel", Value::Binary(relationship.as_bytes().to_vec()))]),
        ),
    )?;
    ports.port_entity_put(&mut txn, &turn, &row(ENTITY_TYPE_TURN, b"turn"))?;
    ports.record_turn_session(&mut txn, &turn, &session)?;
    let other_turn = id(8);
    ports.port_entity_put(&mut txn, &other_turn, &row(ENTITY_TYPE_TURN, b"other turn"))?;
    ports.record_turn_session(&mut txn, &other_turn, &id(9))?;
    ports.port_entity_put(
        &mut txn,
        &summary,
        &row(ENTITY_TYPE_SUMMARY, &map(&[("level", Value::from(2))])),
    )?;
    ports.port_entity_put(
        &mut txn,
        &asset,
        &row(
            ENTITY_TYPE_ASSET,
            &map(&[("rel", Value::Binary(relationship.as_bytes().to_vec()))]),
        ),
    )?;
    assert_eq!(
        ports.port_entity_batch_get(&txn, &[a, id(99)])?,
        vec![Some(place.clone()), None]
    );
    assert_eq!(
        ports.port_list_turns_by_session(&txn, &session)?,
        vec![turn]
    );
    assert_eq!(
        ports.port_list_sessions_by_relationship(&txn, &relationship)?,
        vec![session]
    );
    assert_eq!(ports.port_list_summaries_by_level(&txn, 2)?, vec![summary]);
    assert_eq!(
        ports.port_list_assets_by_relationship(&txn, &relationship)?,
        vec![asset]
    );
    assert_eq!(
        ports.port_place_find_by_provider_id(&txn, "registry", "station-1")?,
        vec![a, b]
    );
    assert_eq!(ports.port_place_find_by_name(&txn, "Station")?, vec![a, b]);
    ports.port_edge_upsert(&mut txn, &b, EdgeKind::ChildOf, &a, 1.0)?;
    assert_eq!(ports.port_place_list_children(&txn, &a)?, vec![b]);
    let outbound =
        ports.port_edge_neighbors(&txn, &b, EdgeDirection::Out, Some(EdgeKind::ChildOf), 1)?;
    assert_eq!(outbound.len(), 1);
    assert_eq!(outbound[0].target, a);
    assert_eq!(
        ports.port_edge_list_by_dst(&txn, &a, Some(EdgeKind::ChildOf), None, 1)?,
        vec![b]
    );
    assert!(ports.port_edge_mark_stale(&mut txn, &b, EdgeKind::ChildOf, &a)?);
    assert!(
        ports
            .port_edge_neighbors(&txn, &a, EdgeDirection::Both, None, 10)?
            .is_empty()
    );
    assert!(!ports.port_edge_delete(&mut txn, &b, EdgeKind::ChildOf, &a)?);
    ports.commit(txn)?;
    let txn = ports.read()?;
    assert_eq!(ports.port_place_get(&txn, &a)?, Some(place));
    assert_eq!(
        ports.port_list_turns_by_session(&txn, &session)?,
        vec![turn]
    );
    drop(txn);
    let mut txn = ports.write()?;
    assert!(ports.port_entity_delete(&mut txn, &turn)?);
    assert!(ports.port_list_turns_by_session(&txn, &session)?.is_empty());
    ports.commit(txn)?;
    let txn = ports.read()?;
    drop(txn);
    // Drop without commit must leave the prior entity and edge snapshot intact.
    let mut txn = ports.write()?;
    assert!(ports.port_entity_delete(&mut txn, &a)?);
    drop(txn);
    let txn = ports.read()?;
    assert!(ports.port_entity_get(&txn, &a)?.is_some());
    drop(txn);
    let mut txn = ports.write()?;
    assert!(matches!(
        ports.port_entity_put(&mut txn, &a, &row(ENTITY_TYPE_PERSON, b"changed")),
        Err(Error::Registry(RegistryError::EntityTypeImmutable { .. }))
    ));
    Ok(())
}
fn claims<P: Backend>(ports: &P) -> Result<()> {
    let subject = id(21);
    let first = id(22);
    let second = id(23);
    let mut txn = ports.write()?;
    ports.port_entity_put(&mut txn, &subject, &row(ENTITY_TYPE_PERSON, b"subject"))?;
    let envelope = WriteEnvelope::new(
        WriteActor::new(subject, crate::edge::EdgeActorClass::Human),
        ClaimSource::Generated,
        WriteProvenance::new(Value::from("port conformance"))?,
        ClaimApprovalStatus::Proposed,
    );
    for (id, value, time) in [(first, "old", 1), (second, "new", 2)] {
        ports.port_claim_put(
            &mut txn,
            &id,
            ClaimCandidate::new(
                "profile.preference",
                ClaimSubject::Entity(subject),
                Value::from(value),
                1.0,
            ),
            &envelope,
            TimeRange {
                start: time,
                end: time,
            },
            time,
        )?;
    }
    assert_eq!(
        ports.port_claim_get(&txn, &first)?.unwrap().value,
        Value::from("old")
    );
    assert_eq!(ports.port_claim_list(&txn, &subject)?, vec![first, second]);
    assert_eq!(
        ports
            .port_claim_list_by_predicate(&txn, "profile.preference")?
            .len(),
        2
    );
    assert_eq!(
        ports
            .port_claim_get_active(&txn, &subject, "profile.preference")?
            .unwrap()
            .0,
        second
    );
    assert_eq!(
        ports
            .port_claim_find_conflicting(&txn, &subject, "profile.preference")?
            .unwrap()
            .0,
        second
    );
    assert_eq!(
        ports
            .port_claim_predicate_history(&txn, &subject, "profile.preference")?
            .into_iter()
            .map(|(id, _)| id)
            .collect::<Vec<_>>(),
        vec![first, second]
    );
    ports.port_edge_upsert(&mut txn, &second, EdgeKind::Supersedes, &first, 1.0)?;
    assert_eq!(
        ports.port_claim_supersede_chain(&txn, &first)?,
        vec![first, second]
    );
    ports.commit(txn)
}
#[test]
fn entity_edge_place_lmdb_and_memory() -> Result<()> {
    let (_temp, vault, memory, _clock) = fixtures();
    entity_edge_place(&vault)?;
    entity_edge_place(&memory)
}
#[test]
fn claims_lmdb_and_memory() -> Result<()> {
    let (_temp, vault, memory, _clock) = fixtures();
    claims(&vault)?;
    claims(&memory)
}

fn opaque_frontiers<P: Backend>(ports: &P) -> Result<()> {
    let mut txn = ports.write()?;
    for (n, entity_type) in [(80, ENTITY_TYPE_PERSON), (81, ENTITY_TYPE_ASSET)] {
        let entity = id(n);
        for value in [
            Value::from("consumer-owned"),
            Value::Array(vec![Value::Map(vec![])]),
        ] {
            let body = map(&[("sourceFrontiers", value)]);
            let expected = row(entity_type, &body);
            ports.port_entity_put(&mut txn, &entity, &expected)?;
            assert_eq!(ports.port_entity_get(&txn, &entity)?, Some(expected));
        }
    }
    ports.commit(txn)
}

#[test]
fn opaque_source_frontiers_roundtrip_on_both_backends() -> Result<()> {
    let (_temp, vault, memory, _clock) = fixtures();
    opaque_frontiers(&vault)?;
    opaque_frontiers(&memory)
}
