use super::*;
use crate::edge::EdgeKind;

#[test]
fn subject_reads_apply_inclusive_start_exclusive_end_and_unbounded_absence() -> Result<()> {
    type Case = (Option<u64>, Option<u64>, &'static [(u64, bool)]);
    let cases: &[Case] = &[
        (
            Some(200),
            Some(201),
            &[(199, false), (200, true), (201, false)],
        ),
        (None, Some(200), &[(0, true), (199, true), (200, false)]),
        (
            Some(200),
            None,
            &[(199, false), (200, true), (u64::MAX, true)],
        ),
        (None, None, &[(0, true), (u64::MAX, true)]),
        (
            Some(u64::MAX),
            None,
            &[(u64::MAX - 1, false), (u64::MAX, true)],
        ),
        (None, Some(0), &[(0, false), (1, false)]),
        (
            Some(200),
            Some(200),
            &[(199, false), (200, false), (201, false)],
        ),
    ];
    for predicate in [PREDICATE_PERSON_SUBSTRATE, PREDICATE_ACTOR_SUBJECT_REF] {
        for &(from, to, evaluations) in cases {
            let (_dir, vault) = test_vault();
            let person = seed(&vault, entity(0x93), ENTITY_TYPE_PERSON);
            let subject = if predicate == PREDICATE_PERSON_SUBSTRATE {
                person
            } else {
                seed(&vault, entity(0x94), ENTITY_TYPE_AGENT_DEF)
            };
            let value = if predicate == PREDICATE_PERSON_SUBSTRATE {
                Value::from("model")
            } else {
                Value::from(person.to_hex())
            };
            let mut body = subject_fact(predicate, subject, value, writer(), 100);
            body.valid_from = from;
            body.valid_to = to;
            put_subject_fixture(&vault, &entity(0x95), &body)?;
            // Read times are caller data, and can be evaluated out of order.
            for &(at, present) in evaluations.iter().rev().chain(evaluations.iter()) {
                if predicate == PREDICATE_PERSON_SUBSTRATE {
                    assert_eq!(
                        person_substrate(&vault, &subject, at)?,
                        present.then_some(PersonSubstrate::Model),
                        "{from:?}..{to:?} at {at}",
                    );
                } else {
                    assert_eq!(
                        actor_subject_anchor(&vault, &subject, at)?,
                        present.then_some(person),
                        "{from:?}..{to:?} at {at}",
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn earlier_subject_writes_reject_future_overlap_without_changing_any_head() -> Result<()> {
    for predicate in [PREDICATE_PERSON_SUBSTRATE, PREDICATE_ACTOR_SUBJECT_REF] {
        for replacing in [false, true] {
            for same_value in [false, true] {
                let (_dir, vault) = test_vault();
                let person = seed(&vault, entity(0xB1), ENTITY_TYPE_PERSON);
                let other = seed(&vault, entity(0xB2), ENTITY_TYPE_PERSON);
                let subject = if predicate == PREDICATE_PERSON_SUBSTRATE {
                    person
                } else {
                    seed(&vault, entity(0xB3), ENTITY_TYPE_AGENT_DEF)
                };
                let next_value = if predicate == PREDICATE_PERSON_SUBSTRATE {
                    Value::from("model")
                } else {
                    Value::from(other.to_hex())
                };
                let future_value = if same_value {
                    next_value.clone()
                } else if predicate == PREDICATE_PERSON_SUBSTRATE {
                    Value::from("meat")
                } else {
                    Value::from(person.to_hex())
                };
                let future = entity(0xB4);
                let body = subject_fact(predicate, subject, future_value.clone(), writer(), 300);
                put_subject_fixture(&vault, &future, &body)?;
                // Replacement also encounters a current target: rejecting the
                // future overlap must leave that target active and byte-identical.
                let current = entity(0xB5);
                if replacing {
                    let body = subject_fact(predicate, subject, next_value, writer(), 100);
                    put_subject_fixture(&vault, &current, &body)?;
                }
                let before_future = vault.get(&future)?;
                let before_current = vault.get(&current)?;
                let before_claims = vault.claims_for_subject(&subject)?;
                let error = match (predicate, replacing) {
                    (PREDICATE_PERSON_SUBSTRATE, true) => {
                        set_person_substrate(&vault, subject, PersonSubstrate::Model, writer(), 200)
                            .map(|_| ())
                    }
                    (PREDICATE_PERSON_SUBSTRATE, false) => {
                        ensure_model_person(&vault, subject, writer(), 200)
                    }
                    (_, true) => {
                        anchor_actor_subject(&vault, subject, other, writer(), 200).map(|_| ())
                    }
                    (_, false) => ensure_actor_subject(&vault, subject, other, writer(), 200),
                }
                .expect_err("an earlier unbounded write must not overlap a future fact");
                assert!(matches!(error, Error::InvalidClaimBody(_)));
                assert_eq!(vault.get(&future)?, before_future);
                assert_eq!(vault.get(&current)?, before_current);
                assert_eq!(vault.claims_for_subject(&subject)?, before_claims);
                assert!(vault.edges_in(&future)?.is_empty());
                assert!(vault.edges_in(&current)?.is_empty());
                if !replacing {
                    let txn = vault.store.env.read_txn()?;
                    assert_eq!(
                        single_subject_value(&vault, &txn, &subject, predicate, 200)?,
                        None
                    );
                    assert_eq!(
                        single_subject_value(&vault, &txn, &subject, predicate, 300)?,
                        Some(future_value)
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn expired_subject_history_is_neither_current_nor_a_supersession_target() -> Result<()> {
    head_admission::assert_excluded_history_survives(|body| body.valid_to = Some(199))?;
    head_admission::assert_excluded_history_survives(|body| body.valid_to = Some(200))
}

#[test]
fn subject_supersession_closes_heads_at_the_inclusive_start_and_with_absent_bounds() -> Result<()> {
    for predicate in [PREDICATE_PERSON_SUBSTRATE, PREDICATE_ACTOR_SUBJECT_REF] {
        for (from, to) in [(Some(200), Some(201)), (None, None)] {
            let (_dir, vault) = test_vault();
            let person = seed(&vault, entity(0x93), ENTITY_TYPE_PERSON);
            let other = seed(&vault, entity(0x94), ENTITY_TYPE_PERSON);
            let subject = if predicate == PREDICATE_PERSON_SUBSTRATE {
                person
            } else {
                seed(&vault, entity(0x95), ENTITY_TYPE_AGENT_DEF)
            };
            let value = if predicate == PREDICATE_PERSON_SUBSTRATE {
                Value::from("meat")
            } else {
                Value::from(person.to_hex())
            };
            let id = entity(0x96);
            let mut body = subject_fact(predicate, subject, value, writer(), 100);
            body.valid_from = from;
            body.valid_to = to;
            put_subject_fixture(&vault, &id, &body)?;
            let new = if predicate == PREDICATE_PERSON_SUBSTRATE {
                set_person_substrate(&vault, subject, PersonSubstrate::Model, writer(), 200)?
            } else {
                anchor_actor_subject(&vault, subject, other, writer(), 200)?
            };
            let prior = vault.get_claim(&id)?.expect("prior head");
            assert_eq!(prior.lifecycle, ClaimLifecycleStatus::Superseded);
            assert_eq!(prior.valid_from, from);
            assert_eq!(prior.valid_to, Some(200));
            let supersedes: Vec<_> = vault
                .edges_out(&new)?
                .into_iter()
                .filter(|edge| edge.kind == EdgeKind::Supersedes)
                .collect();
            assert_eq!(supersedes.len(), 1);
            assert_eq!(supersedes[0].target, id);
        }
    }
    Ok(())
}

#[test]
fn replaced_subject_facts_remain_readable_before_each_replacement() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed(&vault, entity(0xB1), ENTITY_TYPE_AGENT_DEF);
    let person = seed(&vault, entity(0xB2), ENTITY_TYPE_PERSON);
    let org = seed(&vault, entity(0xB3), ENTITY_TYPE_ORG);
    let anchor = anchor_actor_subject(&vault, actor, person, writer(), 100)?;
    let substrate = set_person_substrate(&vault, person, PersonSubstrate::Meat, writer(), 100)?;
    let future_anchor = anchor_actor_subject(&vault, actor, org, writer(), 300)?;
    let future_substrate =
        set_person_substrate(&vault, person, PersonSubstrate::Model, writer(), 300)?;

    // The new fact is scheduled for 300. Present (200) and historical (100)
    // reads still see the closed fact, regardless of evaluation order.
    for at in [300, 200, 99, 100, 299, u64::MAX, 200] {
        assert_eq!(
            actor_subject_anchor(&vault, &actor, at)?,
            if at < 100 {
                None
            } else if at < 300 {
                Some(person)
            } else {
                Some(org)
            }
        );
        assert_eq!(
            person_substrate(&vault, &person, at)?,
            if at < 100 {
                None
            } else if at < 300 {
                Some(PersonSubstrate::Meat)
            } else {
                Some(PersonSubstrate::Model)
            }
        );
    }
    for id in [anchor, substrate] {
        let body = vault.get_claim(&id)?.expect("retained history");
        assert_eq!(body.lifecycle, ClaimLifecycleStatus::Superseded);
        assert_eq!(body.valid_from, Some(100));
        assert_eq!(body.valid_to, Some(300));
    }
    let before_anchor = vault.get(&anchor)?;
    let before_substrate = vault.get(&substrate)?;
    // Ensure can acknowledge matching history, but never insert over it.
    ensure_actor_subject(&vault, actor, person, writer(), 200)?;
    assert!(ensure_actor_subject(&vault, actor, org, writer(), 200).is_err());
    assert!(ensure_model_person(&vault, person, writer(), 200).is_err());
    for result in [
        anchor_actor_subject(&vault, actor, person, writer(), 200),
        set_person_substrate(&vault, person, PersonSubstrate::Meat, writer(), 200),
    ] {
        assert!(matches!(result, Err(Error::InvalidClaimBody(_))));
    }
    anchor_actor_subject(&vault, actor, person, writer(), 500)?;
    set_person_substrate(&vault, person, PersonSubstrate::Meat, writer(), 500)?;
    assert_eq!(vault.get(&anchor)?, before_anchor);
    assert_eq!(vault.get(&substrate)?, before_substrate);
    for id in [future_anchor, future_substrate] {
        let body = vault
            .get_claim(&id)?
            .expect("second interval closed only once");
        assert_eq!(body.lifecycle, ClaimLifecycleStatus::Superseded);
        assert_eq!(body.valid_to, Some(500));
        assert_eq!(vault.edges_in(&id)?.len(), 1);
    }
    assert_eq!(actor_subject_anchor(&vault, &actor, 499)?, Some(org));
    assert_eq!(actor_subject_anchor(&vault, &actor, 500)?, Some(person));
    assert_eq!(
        person_substrate(&vault, &person, 499)?,
        Some(PersonSubstrate::Model)
    );
    assert_eq!(
        person_substrate(&vault, &person, 500)?,
        Some(PersonSubstrate::Meat)
    );
    let before_claims = vault.claims_for_subject(&person)?;
    let before_model = vault.get(&future_substrate)?;
    ensure_model_person(&vault, person, writer(), 400)?;
    assert_eq!(vault.claims_for_subject(&person)?, before_claims);
    assert_eq!(vault.get(&future_substrate)?, before_model);
    assert_eq!(actor_subject_anchor(&vault, &actor, 200)?, Some(person));
    Ok(())
}

#[test]
fn only_bounded_superseded_history_is_readable_and_it_cannot_be_overwritten() -> Result<()> {
    for predicate in [PREDICATE_PERSON_SUBSTRATE, PREDICATE_ACTOR_SUBJECT_REF] {
        for (lifecycle, end, readable) in [
            (ClaimLifecycleStatus::Superseded, Some(300), true),
            (ClaimLifecycleStatus::Superseded, None, false),
            (ClaimLifecycleStatus::Retracted, Some(300), false),
            (ClaimLifecycleStatus::Retracted, None, false),
        ] {
            let (_dir, vault) = test_vault();
            let person = seed(&vault, entity(0xB1), ENTITY_TYPE_PERSON);
            let subject = if predicate == PREDICATE_PERSON_SUBSTRATE {
                person
            } else {
                seed(&vault, entity(0xB2), ENTITY_TYPE_AGENT_DEF)
            };
            let value = if predicate == PREDICATE_PERSON_SUBSTRATE {
                Value::from("model")
            } else {
                Value::from(person.to_hex())
            };
            let id = entity(0xB3);
            let mut body = subject_fact(predicate, subject, value.clone(), writer(), 100);
            body.lifecycle = lifecycle;
            body.valid_to = end;
            put_subject_fixture(&vault, &id, &body)?;
            if predicate == PREDICATE_PERSON_SUBSTRATE {
                assert_eq!(
                    person_substrate(&vault, &subject, 200)?,
                    readable.then_some(PersonSubstrate::Model)
                );
                assert_eq!(person_substrate(&vault, &subject, 300)?, None);
            } else {
                assert_eq!(
                    actor_subject_anchor(&vault, &subject, 200)?,
                    readable.then_some(person)
                );
                assert_eq!(actor_subject_anchor(&vault, &subject, 300)?, None);
            }
            if readable {
                // Even if its successor has not arrived, retained history is
                // not an active replacement target. Refuse overlap atomically.
                let result = if predicate == PREDICATE_PERSON_SUBSTRATE {
                    set_person_substrate(&vault, subject, PersonSubstrate::Meat, writer(), 200)
                } else {
                    anchor_actor_subject(&vault, subject, person, writer(), 200)
                };
                assert!(matches!(result, Err(Error::InvalidClaimBody(_))));
                assert_eq!(vault.claims_for_subject(&subject)?, vec![id]);
                assert_eq!(vault.get_claim(&id)?, Some(body));
                assert!(vault.edges_in(&id)?.is_empty());
            }
        }
    }
    Ok(())
}
