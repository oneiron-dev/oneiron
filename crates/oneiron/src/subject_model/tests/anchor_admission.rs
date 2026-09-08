use super::substrate_admission::{DOORS, admit};
use super::*;
use crate::claim::{encode_claim_body, validate_claim_body_and_decode};
use crate::edge::EdgeKind;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MACHINE};

#[test]
fn anchor_decoder_rejects_non_ids_sentinels_and_edge_subjects() -> Result<()> {
    let actor = entity(0xB1);
    let person = entity(0xB2);
    let mut body = subject_fact(
        PREDICATE_ACTOR_SUBJECT_REF,
        actor,
        Value::from(person.to_hex()),
        writer(),
        100,
    );
    for value in [
        Value::Nil,
        Value::from(1),
        Value::from(true),
        Value::Map(Vec::new()),
        Value::Binary(person.as_bytes().to_vec()),
        Value::from(""),
        Value::from("not-an-id"),
        Value::from("g".repeat(32)),
        Value::from("0".repeat(32)),
        Value::from("f".repeat(32)),
        Value::from(format!("04{}", "ff".repeat(15))),
        Value::from(format!(" {}", person.to_hex())),
    ] {
        body.value = value;
        assert!(matches!(
            validate_claim_body_and_decode(&encode_claim_body(&body)?, true),
            Err(Error::InvalidClaimBody(_))
        ));
    }
    for value in [person.to_hex(), person.to_hex().to_uppercase()] {
        body.value = Value::from(value);
        assert_eq!(
            validate_claim_body_and_decode(&encode_claim_body(&body)?, true)?,
            body
        );
    }
    body.subject = ClaimSubject::Edge {
        source: actor,
        kind: EdgeKind::Mentions,
        target: person,
    };
    assert!(matches!(
        validate_claim_body_and_decode(&encode_claim_body(&body)?, true),
        Err(Error::InvalidClaimBody(_))
    ));
    Ok(())
}

#[test]
fn anchor_admission_rejects_wrong_types_and_values_without_overwriting_history() -> Result<()> {
    for &door in DOORS {
        let (_dir, vault) = test_vault();
        let actor = seed(&vault, entity(0xB1), ENTITY_TYPE_AGENT_DEF);
        let person = seed(&vault, entity(0xB2), ENTITY_TYPE_PERSON);
        let wrong_actor = seed(&vault, entity(0xB3), ENTITY_TYPE_ORG);
        let place = seed(&vault, entity(0xB4), ENTITY_TYPE_PLACE);
        let id = anchor_actor_subject(&vault, actor, person, writer(), 100)?;
        let before = vault.get(&id)?;
        let new_id = entity(0xB5);
        for (subject, value) in [
            (actor, Value::Nil),
            (actor, Value::from(3)),
            (actor, Value::from("bad-id")),
            (actor, Value::from(place.to_hex())),
            (actor, Value::from(actor.to_hex())),
            (wrong_actor, Value::from(person.to_hex())),
            (place, Value::from(person.to_hex())),
        ] {
            let body = subject_fact(PREDICATE_ACTOR_SUBJECT_REF, subject, value, writer(), 100);
            for target in [id, new_id] {
                let error = admit(&vault, door, &target, &body).expect_err("hostile actor anchor");
                assert_eq!(error.kind(), ErrorKind::InvalidClaimBody, "{door:?}");
                assert_eq!(vault.get(&id)?, before);
                assert!(vault.get(&new_id)?.is_none());
                assert!(vault.edges_out(&new_id)?.is_empty());
                assert_eq!(vault.claims_for_subject(&actor)?, vec![id]);
                assert!(vault.claims_for_subject(&wrong_actor)?.is_empty());
                assert!(vault.claims_for_subject(&place)?.is_empty());
                assert_eq!(actor_subject_anchor(&vault, &actor, 100)?, Some(person));
            }
        }
    }
    Ok(())
}

#[test]
fn anchor_admission_requires_both_entities_and_accepts_the_actor_kind_matrix() -> Result<()> {
    for &door in DOORS {
        for actor_kind in [
            ENTITY_TYPE_PERSON,
            ENTITY_TYPE_AGENT_DEF,
            ENTITY_TYPE_MACHINE,
        ] {
            for subject_kind in [ENTITY_TYPE_PERSON, ENTITY_TYPE_ORG] {
                for actor_first in [false, true] {
                    let (_dir, vault) = test_vault();
                    let actor = entity(0xB1);
                    let subject = entity(0xB2);
                    let id = entity(0xB3);
                    let body = subject_fact(
                        PREDICATE_ACTOR_SUBJECT_REF,
                        actor,
                        Value::from(subject.to_hex()),
                        writer(),
                        100,
                    );
                    assert!(admit(&vault, door, &id, &body).is_err());
                    let dependencies = if actor_first {
                        [(actor, actor_kind), (subject, subject_kind)]
                    } else {
                        [(subject, subject_kind), (actor, actor_kind)]
                    };
                    seed(&vault, dependencies[0].0, dependencies[0].1);
                    assert!(admit(&vault, door, &id, &body).is_err());
                    assert!(vault.get(&id)?.is_none());
                    assert!(vault.claims_for_subject(&actor)?.is_empty());
                    seed(&vault, dependencies[1].0, dependencies[1].1);
                    admit(&vault, door, &id, &body)?;
                    vault
                        .batch()
                        .edge(&id, EdgeKind::ClaimOf, &actor, 1.0)
                        .commit()?;
                    assert_eq!(vault.get_claim(&id)?, Some(body));
                    assert_eq!(actor_subject_anchor(&vault, &actor, 100)?, Some(subject));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn anchor_replicated_batch_validates_at_each_op_and_rolls_back_earlier_dependencies() -> Result<()>
{
    // All six arrival orders. A future op is not an existing dependency.
    for order in [
        [0, 1, 2],
        [1, 0, 2],
        [0, 2, 1],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        for subject_kind in [ENTITY_TYPE_PERSON, ENTITY_TYPE_PLACE] {
            let (_dir, vault) = test_vault();
            let actor = entity(0xB1);
            let subject = entity(0xB2);
            let id = entity(0xB3);
            let body = subject_fact(
                PREDICATE_ACTOR_SUBJECT_REF,
                actor,
                Value::from(subject.to_hex()),
                writer(),
                100,
            );
            let data = encode_claim_body(&body)?;
            let occurred = TimeRange {
                start: 100,
                end: 100,
            };
            let mut batch = vault.batch();
            for op in order {
                batch = match op {
                    0 => batch.put(&actor, ENTITY_TYPE_PERSON, occurred, 100, b"actor"),
                    1 => batch.put(&subject, subject_kind, occurred, 100, b"subject"),
                    _ => batch.put_replicated(&id, ENTITY_TYPE_CLAIM, occurred, 100, &data),
                };
            }
            let result = batch.edge(&id, EdgeKind::ClaimOf, &actor, 1.0).commit();
            if order[2] == 2 && subject_kind == ENTITY_TYPE_PERSON {
                result?;
                assert_eq!(actor_subject_anchor(&vault, &actor, 100)?, Some(subject));
            } else {
                assert!(matches!(result, Err(Error::InvalidClaimBody(_))));
                for entity in [actor, subject, id] {
                    assert!(vault.get(&entity)?.is_none());
                    assert!(vault.edges_out(&entity)?.is_empty());
                }
                assert!(vault.claims_for_subject(&actor)?.is_empty());
            }
        }
    }
    Ok(())
}

#[test]
fn anchor_reader_refuses_existing_rows_with_invalid_actor_or_subject_types() -> Result<()> {
    for wrong_actor in [false, true] {
        let (_dir, vault) = test_vault();
        let actor = seed(&vault, entity(0xB1), ENTITY_TYPE_PERSON);
        let subject = seed(&vault, entity(0xB2), ENTITY_TYPE_PERSON);
        anchor_actor_subject(&vault, actor, subject, writer(), 100)?;
        let wrong = if wrong_actor { actor } else { subject };
        // Deliberately bypass admission to model corrupt stored state. Public
        // writes cannot change a type byte or admit this anchor in the first place.
        vault.with_write_txn(|txn| {
            let mut raw = vault
                .store
                .entities
                .get(txn, wrong.as_bytes())?
                .expect("existing dependency")
                .to_vec();
            raw[0] = ENTITY_TYPE_PLACE;
            vault.store.entities.put(txn, wrong.as_bytes(), &raw)?;
            Ok(())
        })?;
        assert!(matches!(
            actor_subject_anchor(&vault, &actor, 100),
            Err(Error::InvalidClaimBody(_))
        ));
    }
    Ok(())
}
