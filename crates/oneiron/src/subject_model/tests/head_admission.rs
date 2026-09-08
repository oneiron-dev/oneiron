use super::*;
use crate::edge::EdgeKind;

type Exclude = fn(&mut ClaimBody);

/// Exercise both replacement and ensure-if-absent for both owned predicates.
/// Excluded claims remain byte-identical, including validity and approval.
pub(super) fn assert_excluded_history_survives(exclude: Exclude) -> Result<()> {
    for predicate in [PREDICATE_PERSON_SUBSTRATE, PREDICATE_ACTOR_SUBJECT_REF] {
        for replacing in [false, true] {
            let (_dir, vault) = test_vault();
            let first_person = seed(&vault, entity(0x81), ENTITY_TYPE_PERSON);
            let next_person = seed(&vault, entity(0x82), ENTITY_TYPE_PERSON);
            let subject = if predicate == PREDICATE_PERSON_SUBSTRATE {
                first_person
            } else {
                seed(&vault, entity(0x83), ENTITY_TYPE_AGENT_DEF)
            };
            let (old_value, next_value) = if predicate == PREDICATE_PERSON_SUBSTRATE {
                (Value::from("meat"), Value::from("model"))
            } else {
                (
                    Value::from(first_person.to_hex()),
                    Value::from(next_person.to_hex()),
                )
            };
            let excluded_id = entity(0x84);
            let mut excluded = subject_fact(predicate, subject, old_value.clone(), writer(), 100);
            exclude(&mut excluded);
            put_subject_fixture(&vault, &excluded_id, &excluded)?;
            let excluded_before = vault.get(&excluded_id)?;
            let mut prior_heads = Vec::new();
            if replacing {
                // Concurrent admissible heads must ALL close, including Approved.
                for (id, approval) in [
                    (entity(0x85), ClaimApprovalStatus::Auto),
                    (entity(0x86), ClaimApprovalStatus::Approved),
                ] {
                    let mut body =
                        subject_fact(predicate, subject, old_value.clone(), writer(), 100);
                    body.approval = approval;
                    put_subject_fixture(&vault, &id, &body)?;
                    prior_heads.push(id);
                }
            }
            {
                let txn = vault.store.env.read_txn()?;
                assert_eq!(
                    single_subject_value(&vault, &txn, &subject, predicate, 200)?,
                    replacing.then_some(old_value)
                );
            }
            if predicate == PREDICATE_PERSON_SUBSTRATE {
                if replacing {
                    set_person_substrate(&vault, subject, PersonSubstrate::Model, writer(), 200)?;
                } else {
                    ensure_model_person(&vault, subject, writer(), 200)?;
                }
                assert_eq!(
                    person_substrate(&vault, &subject, 200)?,
                    Some(PersonSubstrate::Model)
                );
            } else {
                if replacing {
                    anchor_actor_subject(&vault, subject, next_person, writer(), 200)?;
                } else {
                    ensure_actor_subject(&vault, subject, next_person, writer(), 200)?;
                }
                assert_eq!(
                    actor_subject_anchor(&vault, &subject, 200)?,
                    Some(next_person)
                );
            }
            let txn = vault.store.env.read_txn()?;
            assert_eq!(
                single_subject_value(&vault, &txn, &subject, predicate, 200)?,
                Some(next_value)
            );
            drop(txn);
            assert_eq!(vault.get(&excluded_id)?, excluded_before);
            assert_eq!(vault.get_claim(&excluded_id)?, Some(excluded));
            assert!(
                vault
                    .edges_in(&excluded_id)?
                    .iter()
                    .all(|edge| edge.kind != EdgeKind::Supersedes)
            );
            for id in prior_heads {
                let body = vault.get_claim(&id)?.expect("closed prior head");
                assert_eq!(body.lifecycle, ClaimLifecycleStatus::Superseded);
                assert_eq!(body.valid_to, Some(200));
                assert_eq!(
                    vault
                        .edges_in(&id)?
                        .iter()
                        .filter(|edge| edge.kind == EdgeKind::Supersedes)
                        .count(),
                    1
                );
            }
        }
    }
    Ok(())
}

#[test]
fn proposed_subject_history_is_not_a_supersession_target() -> Result<()> {
    assert_excluded_history_survives(|body| body.approval = ClaimApprovalStatus::Proposed)
}

#[test]
fn rejected_subject_history_is_not_a_supersession_target() -> Result<()> {
    assert_excluded_history_survives(|body| body.approval = ClaimApprovalStatus::Rejected)
}

#[test]
fn world_subject_history_is_not_a_supersession_target() -> Result<()> {
    assert_excluded_history_survives(|body| body.world = Some(entity(0x87)))
}

#[test]
fn scoped_subject_history_is_not_a_supersession_target() -> Result<()> {
    assert_excluded_history_survives(|body| {
        body.scope = Some(Value::Map(vec![(
            Value::from("facet"),
            Value::from("work"),
        )]));
    })
}

#[test]
fn relational_subject_history_is_not_a_supersession_target() -> Result<()> {
    assert_excluded_history_survives(|body| body.rel = Some(entity(0x88)))
}

#[test]
fn closed_subject_history_is_not_a_supersession_target() -> Result<()> {
    assert_excluded_history_survives(|body| {
        body.lifecycle = ClaimLifecycleStatus::Retracted;
        body.valid_to = Some(150);
    })?;
    assert_excluded_history_survives(|body| {
        body.lifecycle = ClaimLifecycleStatus::Superseded;
        body.valid_to = Some(150);
    })
}

#[test]
fn unrelated_predicate_history_is_not_a_supersession_target() -> Result<()> {
    assert_excluded_history_survives(|body| body.predicate = "person.other_fact".to_owned())
}

#[test]
fn another_subjects_indexed_head_is_neither_read_nor_superseded() -> Result<()> {
    for predicate in [PREDICATE_PERSON_SUBSTRATE, PREDICATE_ACTOR_SUBJECT_REF] {
        let (_dir, vault) = test_vault();
        let first = seed(&vault, entity(0x89), ENTITY_TYPE_PERSON);
        let other = seed(&vault, entity(0x8A), ENTITY_TYPE_PERSON);
        let (subject, id) = if predicate == PREDICATE_PERSON_SUBSTRATE {
            (
                other,
                set_person_substrate(&vault, first, PersonSubstrate::Meat, writer(), 100)?,
            )
        } else {
            let actor = seed(&vault, entity(0x8B), ENTITY_TYPE_AGENT_DEF);
            let other_actor = seed(&vault, entity(0x8C), ENTITY_TYPE_AGENT_DEF);
            (
                other_actor,
                anchor_actor_subject(&vault, actor, first, writer(), 100)?,
            )
        };
        let before = vault.get(&id)?;
        // An extra ClaimOf index edge is not authority to move a stored fact.
        vault
            .batch()
            .edge(&id, EdgeKind::ClaimOf, &subject, 1.0)
            .commit()?;
        let txn = vault.store.env.read_txn()?;
        assert_eq!(
            single_subject_value(&vault, &txn, &subject, predicate, 200)?,
            None
        );
        drop(txn);
        if predicate == PREDICATE_PERSON_SUBSTRATE {
            set_person_substrate(&vault, subject, PersonSubstrate::Model, writer(), 200)?;
            assert_eq!(
                person_substrate(&vault, &first, 200)?,
                Some(PersonSubstrate::Meat)
            );
            assert_eq!(
                person_substrate(&vault, &subject, 200)?,
                Some(PersonSubstrate::Model)
            );
        } else {
            anchor_actor_subject(&vault, subject, other, writer(), 200)?;
            assert_eq!(
                actor_subject_anchor(&vault, &entity(0x8B), 200)?,
                Some(first)
            );
            assert_eq!(actor_subject_anchor(&vault, &subject, 200)?, Some(other));
        }
        assert_eq!(vault.get(&id)?, before);
        assert!(
            vault
                .edges_in(&id)?
                .iter()
                .all(|edge| edge.kind != EdgeKind::Supersedes)
        );
    }
    Ok(())
}
