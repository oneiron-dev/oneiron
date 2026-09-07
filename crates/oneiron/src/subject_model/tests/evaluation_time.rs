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
fn future_subject_history_is_neither_current_nor_a_supersession_target() -> Result<()> {
    head_admission::assert_excluded_history_survives(|body| body.valid_from = Some(201))
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
