use super::*;
use crate::claim::{ClaimDemotionAction, encode_claim_body};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope, WriteProvenance};

#[derive(Clone, Copy, Debug)]
enum Door {
    Typed,
    TypedTxn,
    Raw,
    RawBatch,
    RawTxn,
    Candidate,
    CandidateTxn,
    CandidateHints,
    CandidateHintsTxn,
    CodeRunCandidate,
}

const DOORS: [Door; 10] = [
    Door::Typed,
    Door::TypedTxn,
    Door::Raw,
    Door::RawBatch,
    Door::RawTxn,
    Door::Candidate,
    Door::CandidateTxn,
    Door::CandidateHints,
    Door::CandidateHintsTxn,
    Door::CodeRunCandidate,
];

fn generic_write(vault: &Vault, door: Door, id: &EntityId, body: &ClaimBody) -> Result<()> {
    let at = TimeRange {
        start: 200,
        end: 200,
    };
    let data = encode_claim_body(body)?;
    let candidate = ClaimCandidate::new(
        body.predicate.clone(),
        body.subject,
        body.value.clone(),
        body.confidence,
    );
    let envelope = WriteEnvelope::new(
        writer(),
        ClaimSource::Observed,
        WriteProvenance::new(Value::from("subject write fixture"))?,
        ClaimApprovalStatus::Auto,
    );
    match door {
        Door::Typed => vault.put_claim(id, body, at, 200),
        Door::TypedTxn => {
            vault.with_write_txn(|txn| vault.put_claim_in_txn(txn, id, body, at, 200))
        }
        Door::Raw => vault.put_entity(id, ENTITY_TYPE_CLAIM, at, 200, &data),
        Door::RawBatch => vault
            .batch()
            .put(id, ENTITY_TYPE_CLAIM, at, 200, &data)
            .commit(),
        Door::RawTxn => vault.with_write_txn(|txn| {
            vault
                .batch_in()
                .put(id, ENTITY_TYPE_CLAIM, at, 200, &data)
                .apply(txn)
        }),
        Door::Candidate => vault
            .batch()
            .claim_candidate(id, candidate, &envelope, at, 200)
            .commit(),
        Door::CandidateTxn => vault.with_write_txn(|txn| {
            vault
                .batch_in()
                .claim_candidate(id, candidate, &envelope, at, 200)
                .apply(txn)
        }),
        Door::CandidateHints => vault
            .batch()
            .claim_candidate_with_lexical_hints(
                id,
                candidate,
                &envelope,
                at,
                200,
                &["fixture hint"],
            )
            .commit(),
        Door::CandidateHintsTxn => vault.with_write_txn(|txn| {
            vault
                .batch_in()
                .claim_candidate_with_lexical_hints(
                    id,
                    candidate,
                    &envelope,
                    at,
                    200,
                    &["fixture hint"],
                )
                .apply(txn)
        }),
        Door::CodeRunCandidate => vault
            .put_claim_candidate_without_lexical_query_reconcile(id, candidate, &envelope, at, 200),
    }
}

#[test]
fn substrate_is_reserved_at_every_generic_claim_write_door() -> Result<()> {
    for door in DOORS {
        let (_dir, vault) = test_vault();
        let person = seed(&vault, entity(0xB1), ENTITY_TYPE_PERSON);
        let id = entity(0xB2);
        let body = ClaimBody::new(
            PREDICATE_PERSON_SUBSTRATE,
            ClaimSubject::Entity(person),
            Value::from("model"),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        let err = generic_write(&vault, door, &id, &body).expect_err("owned predicate");
        assert_eq!(err.kind(), ErrorKind::ReservedPredicate, "{door:?}");
        assert!(vault.get(&id)?.is_none(), "{door:?}");
        assert!(vault.claims_for_subject(&person)?.is_empty(), "{door:?}");
        assert!(vault.edges_out(&id)?.is_empty(), "{door:?}");
        assert_eq!(person_substrate(&vault, &person, 201)?, None);
    }
    Ok(())
}

#[test]
fn generic_predicate_cannot_disguise_an_owned_claim_id_overwrite() -> Result<()> {
    for door in DOORS {
        for predicate in [PREDICATE_PERSON_SUBSTRATE, PREDICATE_ACTOR_SUBJECT_REF] {
            let (_dir, vault) = test_vault();
            let person = seed(&vault, entity(0xB3), ENTITY_TYPE_PERSON);
            let actor = seed(&vault, entity(0xB4), ENTITY_TYPE_AGENT_DEF);
            let (subject, id) = if predicate == PREDICATE_PERSON_SUBSTRATE {
                (
                    person,
                    set_person_substrate(&vault, person, PersonSubstrate::Meat, writer(), 100)?,
                )
            } else {
                (
                    actor,
                    anchor_actor_subject(&vault, actor, person, writer(), 100)?,
                )
            };
            let before = vault.get(&id)?;
            let original = vault.get_claim(&id)?;
            let body = ClaimBody::new(
                "person.other_fact",
                ClaimSubject::Entity(subject),
                Value::from("replacement"),
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            );
            let err = generic_write(&vault, door, &id, &body).expect_err("old id is owned");
            assert_eq!(
                err.kind(),
                ErrorKind::ReservedPredicate,
                "{door:?} {predicate}"
            );
            assert_eq!(vault.get(&id)?, before);
            assert_eq!(vault.get_claim(&id)?, original);
            assert_eq!(vault.claims_for_subject(&subject)?, vec![id]);
        }
    }
    Ok(())
}

#[test]
fn other_person_predicates_remain_writable_through_generic_doors() -> Result<()> {
    for door in DOORS {
        let (_dir, vault) = test_vault();
        let person = seed(&vault, entity(0xB5), ENTITY_TYPE_PERSON);
        for predicate in [
            "person.other_fact",
            "person.substrate_note",
            "person.substrate.note",
        ] {
            let id = EntityId::now();
            let body = ClaimBody::new(
                predicate,
                ClaimSubject::Entity(person),
                Value::from("ordinary fact"),
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            );
            generic_write(&vault, door, &id, &body)?;
            assert_eq!(
                vault.get_claim(&id)?.expect("public person fact").predicate,
                predicate
            );
        }
    }
    Ok(())
}

#[test]
fn substrate_lifecycle_is_closed_to_generic_retract_supersede_and_demotion() -> Result<()> {
    let (_dir, vault) = test_vault();
    let person = seed(&vault, entity(0xB6), ENTITY_TYPE_PERSON);
    let old = set_person_substrate(&vault, person, PersonSubstrate::Meat, writer(), 100)?;
    let other = entity(0xA7);
    let body = ClaimBody::new(
        "person.other_fact",
        ClaimSubject::Entity(person),
        Value::from("ordinary fact"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(
        &other,
        &body,
        TimeRange {
            start: 100,
            end: 100,
        },
        100,
    )?;
    let before = vault.get(&old)?;
    let other_before = vault.get(&other)?;
    let reject = |result: Result<()>| {
        assert_eq!(
            result.expect_err("owned lifecycle").kind(),
            ErrorKind::ProvenanceClaimLifecycle
        );
    };
    reject(vault.retract_claim(&old, 200));
    reject(vault.with_write_txn(|txn| vault.retract_claim_in_txn(txn, &old, 200).map(|_| ())));
    for (new, prior) in [(other, old), (old, other)] {
        reject(vault.supersede_claim(&new, &prior, 200));
        reject(vault.with_write_txn(|txn| vault.supersede_claim_in_txn(txn, &new, &prior, 200)));
    }
    for action in [
        ClaimDemotionAction::Decay {
            new_claim_of_weight: 0.1,
        },
        ClaimDemotionAction::Weaken {
            new_confidence: 0.1,
        },
        ClaimDemotionAction::MarkStale,
    ] {
        reject(vault.apply_claim_demotion(&old, action, 200).map(|_| ()));
    }
    reject(vault.require_named_claim_target_active(&old).map(|_| ()));
    let envelope = WriteEnvelope::new(
        writer(),
        ClaimSource::Observed,
        WriteProvenance::new(Value::from("lifecycle fixture"))?,
        ClaimApprovalStatus::Auto,
    );
    reject(vault.supersede_claim_for_code_run_trap(
        &other,
        &old,
        200,
        &envelope,
        EntityId::now(),
        &body,
        EntityId::now(),
        &body,
    ));
    assert_eq!(vault.get(&old)?, before);
    assert_eq!(vault.get(&other)?, other_before);
    assert_eq!(
        person_substrate(&vault, &person, 201)?,
        Some(PersonSubstrate::Meat)
    );
    assert!(
        vault
            .edges_in(&old)?
            .iter()
            .all(|edge| edge.kind != crate::edge::EdgeKind::Supersedes)
    );
    // The owner door retains lifecycle rights after the generic refusals.
    set_person_substrate(&vault, person, PersonSubstrate::Model, writer(), 201)?;
    assert_eq!(
        person_substrate(&vault, &person, 201)?,
        Some(PersonSubstrate::Model)
    );
    Ok(())
}

#[test]
fn substrate_replica_fixture_rematerializes_through_the_existing_reserved_door() -> Result<()> {
    let (_dir, vault) = test_vault();
    let person = seed(&vault, entity(0xA8), ENTITY_TYPE_PERSON);
    let id = entity(0xA9);
    let body = subject_fact(
        PREDICATE_PERSON_SUBSTRATE,
        person,
        Value::from("model"),
        writer(),
        100,
    );
    let data = encode_claim_body(&body)?;
    // This fixture door runs without sync too; no production replay exemption is widened.
    vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            &data,
        )
        .edge(&id, crate::edge::EdgeKind::ClaimOf, &person, 1.0)
        .commit()?;
    assert_eq!(vault.get_claim(&id)?, Some(body));
    assert_eq!(
        person_substrate(&vault, &person, 201)?,
        Some(PersonSubstrate::Model)
    );
    set_person_substrate(&vault, person, PersonSubstrate::Meat, writer(), 200)?;
    assert_eq!(
        person_substrate(&vault, &person, 201)?,
        Some(PersonSubstrate::Meat)
    );
    Ok(())
}
