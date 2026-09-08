use super::*;
use crate::claim::{encode_claim_body, validate_claim_body_and_decode};
use crate::edge::EdgeKind;
use crate::registry::ENTITY_TYPE_CLAIM;

#[derive(Clone, Copy, Debug)]
pub(super) enum AdmissionDoor {
    ReservedTyped,
    ReservedBatch,
    ReplicatedBatch,
    #[cfg(feature = "sync")]
    ReplicatedTxn,
}

pub(super) const DOORS: &[AdmissionDoor] = &[
    AdmissionDoor::ReservedTyped,
    AdmissionDoor::ReservedBatch,
    AdmissionDoor::ReplicatedBatch,
    #[cfg(feature = "sync")]
    AdmissionDoor::ReplicatedTxn,
];

pub(super) fn admit(
    vault: &Vault,
    door: AdmissionDoor,
    id: &EntityId,
    body: &ClaimBody,
) -> Result<()> {
    let data = encode_claim_body(body)?;
    let occurred = TimeRange {
        start: 100,
        end: 100,
    };
    match door {
        AdmissionDoor::ReservedTyped => put_subject_fixture(vault, id, body),
        AdmissionDoor::ReservedBatch => vault.with_write_txn(|txn| {
            vault
                .batch_in()
                .put_reserved_claim(id, occurred, 100, &data)
                .apply(txn)
        }),
        AdmissionDoor::ReplicatedBatch => vault
            .batch()
            .put_replicated(id, ENTITY_TYPE_CLAIM, occurred, 100, &data)
            .commit(),
        #[cfg(feature = "sync")]
        AdmissionDoor::ReplicatedTxn => vault.with_write_txn(|txn| {
            vault
                .batch_in()
                .put_replicated(id, ENTITY_TYPE_CLAIM, occurred, 100, &data)
                .apply(txn)
        }),
    }
}

#[test]
fn substrate_shared_decoder_rejects_invalid_values_and_edge_subjects() -> Result<()> {
    let person = entity(0x91);
    let mut body = subject_fact(
        PREDICATE_PERSON_SUBSTRATE,
        person,
        Value::from("model"),
        writer(),
        100,
    );
    for value in [
        Value::Nil,
        Value::from(1),
        Value::from(true),
        Value::Map(Vec::new()),
        Value::Binary(b"model".to_vec()),
        Value::from(""),
        Value::from("MODEL"),
        Value::from("Meat"),
        Value::from("model "),
        Value::from(" meat"),
        Value::from("model\0"),
        Value::from("unknown"),
    ] {
        body.value = value;
        assert!(matches!(
            validate_claim_body_and_decode(&encode_claim_body(&body)?, true),
            Err(Error::InvalidClaimBody(_))
        ));
    }
    for value in ["meat", "model"] {
        body.value = Value::from(value);
        assert_eq!(
            validate_claim_body_and_decode(&encode_claim_body(&body)?, true)?,
            body
        );
    }
    body.subject = ClaimSubject::Edge {
        source: person,
        kind: EdgeKind::Mentions,
        target: entity(0x92),
    };
    assert!(matches!(
        validate_claim_body_and_decode(&encode_claim_body(&body)?, true),
        Err(Error::InvalidClaimBody(_))
    ));
    Ok(())
}

#[test]
fn substrate_admission_rejects_hostile_values_without_creating_or_overwriting_rows() -> Result<()> {
    for &door in DOORS {
        let (_dir, vault) = test_vault();
        let person = seed(&vault, entity(0x91), ENTITY_TYPE_PERSON);
        let existing = set_person_substrate(&vault, person, PersonSubstrate::Meat, writer(), 100)?;
        let before = vault.get(&existing)?;
        let new_id = entity(0x92);
        for value in [
            Value::from("invalid"),
            Value::from("MODEL"),
            Value::Nil,
            Value::from(3),
        ] {
            let body = subject_fact(PREDICATE_PERSON_SUBSTRATE, person, value, writer(), 100);
            for id in [new_id, existing] {
                let error = admit(&vault, door, &id, &body).expect_err("hostile value");
                assert_eq!(error.kind(), ErrorKind::InvalidClaimBody, "{door:?}");
                assert!(vault.get(&new_id)?.is_none());
                assert_eq!(vault.get(&existing)?, before);
                assert_eq!(vault.claims_for_subject(&person)?, vec![existing]);
                assert!(vault.edges_out(&new_id)?.is_empty());
                assert_eq!(
                    person_substrate(&vault, &person, 100)?,
                    Some(PersonSubstrate::Meat)
                );
            }
        }
    }
    Ok(())
}

#[test]
fn substrate_admission_rejects_non_person_and_edge_subjects() -> Result<()> {
    for &door in DOORS {
        for kind in [
            ENTITY_TYPE_ORG,
            ENTITY_TYPE_PLACE,
            ENTITY_TYPE_FACET,
            ENTITY_TYPE_AGENT_DEF,
        ] {
            let (_dir, vault) = test_vault();
            let subject = seed(&vault, entity(0x91), kind);
            let id = entity(0x92);
            let mut body = subject_fact(
                PREDICATE_PERSON_SUBSTRATE,
                subject,
                Value::from("meat"),
                writer(),
                100,
            );
            for claim_subject in [
                ClaimSubject::Entity(subject),
                ClaimSubject::Edge {
                    source: subject,
                    kind: EdgeKind::Mentions,
                    target: subject,
                },
            ] {
                body.subject = claim_subject;
                let error = admit(&vault, door, &id, &body).expect_err("not a PERSON subject");
                assert_eq!(error.kind(), ErrorKind::InvalidClaimBody, "{door:?}");
                assert!(vault.get(&id)?.is_none());
                assert!(vault.claims_for_subject(&subject)?.is_empty());
                assert!(vault.edges_out(&id)?.is_empty());
            }
        }
    }
    Ok(())
}

#[test]
fn substrate_missing_person_is_rejected_until_the_actual_row_arrives() -> Result<()> {
    for &door in DOORS {
        let (_dir, vault) = test_vault();
        let person = entity(0x91);
        let id = entity(0x92);
        let body = subject_fact(
            PREDICATE_PERSON_SUBSTRATE,
            person,
            Value::from("model"),
            writer(),
            100,
        );
        assert!(admit(&vault, door, &id, &body).is_err(), "{door:?}");
        assert!(vault.get(&id)?.is_none());
        assert!(vault.get(&person)?.is_none());
        assert!(vault.claims_for_subject(&person)?.is_empty());
        seed(&vault, person, ENTITY_TYPE_PERSON);
        admit(&vault, door, &id, &body)?;
        assert_eq!(vault.get_claim(&id)?, Some(body));
    }
    Ok(())
}

#[test]
fn substrate_replicated_batch_checks_subject_at_the_applying_op_and_rolls_back() -> Result<()> {
    for person_first in [false, true] {
        for value in ["model", "invalid"] {
            let (_dir, vault) = test_vault();
            let person = entity(0x91);
            let id = entity(0x92);
            let body = subject_fact(
                PREDICATE_PERSON_SUBSTRATE,
                person,
                Value::from(value),
                writer(),
                100,
            );
            let data = encode_claim_body(&body)?;
            let occurred = TimeRange {
                start: 100,
                end: 100,
            };
            let batch = vault.batch();
            let batch = if person_first {
                batch
                    .put(&person, ENTITY_TYPE_PERSON, occurred, 100, b"person")
                    .put_replicated(&id, ENTITY_TYPE_CLAIM, occurred, 100, &data)
            } else {
                batch
                    .put_replicated(&id, ENTITY_TYPE_CLAIM, occurred, 100, &data)
                    .put(&person, ENTITY_TYPE_PERSON, occurred, 100, b"person")
            };
            let result = batch.edge(&id, EdgeKind::ClaimOf, &person, 1.0).commit();
            if person_first && value == "model" {
                result?;
                assert_eq!(
                    person_substrate(&vault, &person, 100)?,
                    Some(PersonSubstrate::Model)
                );
            } else {
                assert!(result.is_err());
                assert!(vault.get(&id)?.is_none());
                assert!(vault.get(&person)?.is_none());
                assert!(vault.edges_out(&id)?.is_empty());
                assert!(vault.claims_for_subject(&person)?.is_empty());
            }
        }
    }
    Ok(())
}

#[test]
fn substrate_session_batch_uses_the_same_value_and_person_admission() -> Result<()> {
    use crate::batch::BatchOp;
    use crate::off_record::OffRecordBackendClass;
    use crate::session_overlay::{JournalEntry, JournalRole, JournalScope, OverlayKeyspace};

    for (kind, value, accepted) in [
        (None, "model", false),
        (Some(ENTITY_TYPE_ORG), "model", false),
        (Some(ENTITY_TYPE_PERSON), "MODEL", false),
        (Some(ENTITY_TYPE_PERSON), "model", true),
    ] {
        let (_dir, vault) = test_vault();
        let person = entity(0x91);
        let id = entity(0x92);
        if let Some(kind) = kind {
            seed(&vault, person, kind);
        }
        let session = vault
            .off_record_session_vault()
            .enter("substrate-admission", OffRecordBackendClass::Local)?;
        let body = subject_fact(
            PREDICATE_PERSON_SUBSTRATE,
            person,
            Value::from(value),
            writer(),
            100,
        );
        let occurred = TimeRange {
            start: 100,
            end: 100,
        };
        let entry = JournalEntry {
            scope: JournalScope::new(EntityId::now(), id),
            role: JournalRole::TurnOwnedArtifact,
            learned_at: 100,
            occurred,
            op: BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred,
                learned_at: 100,
                data: encode_claim_body(&body)?,
                allow_maintenance: false,
                allow_reserved_predicate: true,
                hub_sync_imported: false,
            },
        };
        let route = session.write_route()?;
        let overlay = session.overlay();
        let mut txn = vault.store.env.write_txn()?;
        let segment = overlay.install_txn_segment()?;
        let result = crate::batch::apply_ops_session(
            &session.read_view()?,
            &route,
            &vault.config,
            &vault.analyzer,
            &mut txn,
            vec![entry],
        );
        if accepted {
            result?;
            txn.commit()?;
            segment.commit()?;
        } else {
            assert_eq!(
                result.expect_err("invalid substrate").kind(),
                ErrorKind::InvalidClaimBody
            );
            // Assert before abort too: a caller catching the error must not
            // find a staged malformed row or a successful journal entry.
            {
                let snapshot = overlay.snapshot()?;
                assert_eq!(snapshot.row_count(OverlayKeyspace::Entities), 0);
                assert!(snapshot.journal_entries().is_empty());
            }
            drop(segment);
            drop(txn);
        }
        {
            let snapshot = overlay.snapshot()?;
            assert_eq!(
                snapshot.row_count(OverlayKeyspace::Entities),
                usize::from(accepted)
            );
            assert_eq!(snapshot.journal_entries().len(), usize::from(accepted));
        }
        assert!(vault.get(&id)?.is_none());
        session.close()?;
    }
    Ok(())
}
