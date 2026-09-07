use super::*;
use crate::claim::encode_claim_body;
use crate::edge::EdgeKind;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::sync::WindowKey;
use crate::sync::bridge::{
    Materializer, encode_edge_value_for_crdt, format_edge_key, register_observer_b,
};
use crate::sync::loro_support::map_insert_bytes;
use crate::sync::quarantine::{pending_remat_entities, quarantined_records};
use crate::sync::window::forward_rematerialize;
use loro::LoroDoc;
use std::sync::Arc;

const WINDOW: &str = "2026-03";

fn blob(kind: u8, data: &[u8]) -> Vec<u8> {
    let mut blob = vec![kind];
    for stamp in [100_u64; 3] {
        blob.extend_from_slice(&stamp.to_be_bytes());
    }
    blob.extend_from_slice(data);
    blob
}

#[test]
fn substrate_sync_missing_person_retries_through_observer_and_remat() -> Result<()> {
    for live in [false, true] {
        let (_dir, vault) = test_vault();
        let vault = Arc::new(vault);
        let doc = LoroDoc::new();
        let materializer = Arc::new(Materializer::new());
        let _subscriptions = live.then(|| register_observer_b(&doc, &vault, &materializer, WINDOW));
        let entities = doc.get_map("entities");
        let person = entity(0x97);
        let id = entity(0x98);
        let body = subject_fact(
            PREDICATE_PERSON_SUBSTRATE,
            person,
            Value::from("model"),
            writer(),
            100,
        );
        let claim_blob = blob(ENTITY_TYPE_CLAIM, &encode_claim_body(&body)?);
        map_insert_bytes(&entities, &id.to_hex(), &claim_blob)?;
        doc.commit();
        if live {
            assert!(vault.get(&id)?.is_none());
            assert!(pending_remat_entities(&vault, WINDOW)?.contains(&id.to_hex()));
        }
        // Repeated recovery cannot turn absence into either a persisted fact
        // or a terminal success that discards the retry marker.
        for _ in 0..2 {
            assert_eq!(
                forward_rematerialize(&vault, &doc, &materializer, &WindowKey::new(WINDOW))?,
                0
            );
            assert!(vault.get(&id)?.is_none());
            assert!(pending_remat_entities(&vault, WINDOW)?.contains(&id.to_hex()));
            assert_eq!(person_substrate(&vault, &person, 100)?, None);
        }
        assert!(!quarantined_records(&vault)?.is_empty());
        map_insert_bytes(
            &entities,
            &person.to_hex(),
            &blob(ENTITY_TYPE_PERSON, b"person"),
        )?;
        doc.commit();
        forward_rematerialize(&vault, &doc, &materializer, &WindowKey::new(WINDOW))?;
        // Map order is not dependency order. A second recovery pass covers a
        // claim visited before the PERSON in the first cold pass.
        forward_rematerialize(&vault, &doc, &materializer, &WindowKey::new(WINDOW))?;
        assert_eq!(vault.get_claim(&id)?, Some(body));
        assert!(!pending_remat_entities(&vault, WINDOW)?.contains(&id.to_hex()));
        map_insert_bytes(
            &doc.get_map("edges"),
            &format_edge_key(&id, EdgeKind::ClaimOf, &person),
            &encode_edge_value_for_crdt(EdgeKind::ClaimOf, 1.0, 100, None, None)?,
        )?;
        doc.commit();
        forward_rematerialize(&vault, &doc, &materializer, &WindowKey::new(WINDOW))?;
        assert_eq!(
            person_substrate(&vault, &person, 100)?,
            Some(PersonSubstrate::Model)
        );
    }
    Ok(())
}

#[test]
fn substrate_sync_rejects_invalid_value_and_wrong_type_without_overwrite() -> Result<()> {
    for live in [false, true] {
        for wrong_subject in [false, true] {
            let (_dir, vault) = test_vault();
            let vault = Arc::new(vault);
            let person = seed(&vault, entity(0x97), ENTITY_TYPE_PERSON);
            let org = seed(&vault, entity(0x98), ENTITY_TYPE_ORG);
            let id = set_person_substrate(&vault, person, PersonSubstrate::Meat, writer(), 100)?;
            let before = vault.get(&id)?;
            let new_id = entity(0x99);
            let subject = if wrong_subject { org } else { person };
            let value = if wrong_subject { "model" } else { "MODEL" };
            let body = subject_fact(
                PREDICATE_PERSON_SUBSTRATE,
                subject,
                Value::from(value),
                writer(),
                100,
            );
            let claim_blob = blob(ENTITY_TYPE_CLAIM, &encode_claim_body(&body)?);
            let doc = LoroDoc::new();
            let materializer = Arc::new(Materializer::new());
            let _subscriptions =
                live.then(|| register_observer_b(&doc, &vault, &materializer, WINDOW));
            for target in [id, new_id] {
                map_insert_bytes(&doc.get_map("entities"), &target.to_hex(), &claim_blob)?;
            }
            doc.commit();
            forward_rematerialize(&vault, &doc, &materializer, &WindowKey::new(WINDOW))?;
            assert_eq!(vault.get(&id)?, before);
            assert!(vault.get(&new_id)?.is_none());
            assert_eq!(vault.claims_for_subject(&person)?, vec![id]);
            assert!(vault.claims_for_subject(&org)?.is_empty());
            assert_eq!(
                person_substrate(&vault, &person, 100)?,
                Some(PersonSubstrate::Meat)
            );
            assert!(pending_remat_entities(&vault, WINDOW)?.is_empty());
            assert!(!quarantined_records(&vault)?.is_empty());
        }
    }
    Ok(())
}

#[test]
fn substrate_sync_wrong_type_arrival_rejects_pending_claim() -> Result<()> {
    let (_dir, vault) = test_vault();
    let doc = LoroDoc::new();
    let materializer = Materializer::new();
    let subject = entity(0x97);
    let id = entity(0x98);
    let body = subject_fact(
        PREDICATE_PERSON_SUBSTRATE,
        subject,
        Value::from("model"),
        writer(),
        100,
    );
    map_insert_bytes(
        &doc.get_map("entities"),
        &id.to_hex(),
        &blob(ENTITY_TYPE_CLAIM, &encode_claim_body(&body)?),
    )?;
    doc.commit();
    forward_rematerialize(&vault, &doc, &materializer, &WindowKey::new(WINDOW))?;
    assert!(pending_remat_entities(&vault, WINDOW)?.contains(&id.to_hex()));
    seed(&vault, subject, ENTITY_TYPE_ORG);
    forward_rematerialize(&vault, &doc, &materializer, &WindowKey::new(WINDOW))?;
    assert!(vault.get(&id)?.is_none());
    assert!(pending_remat_entities(&vault, WINDOW)?.is_empty());
    assert!(vault.claims_for_subject(&subject)?.is_empty());
    Ok(())
}

#[test]
fn substrate_sync_edge_outcomes_cannot_discharge_a_missing_person_retry() -> Result<()> {
    for malformed_edge in [false, true] {
        let (_dir, vault) = test_vault();
        let person = seed(&vault, entity(0x97), ENTITY_TYPE_PERSON);
        let missing = entity(0x98);
        let id = set_person_substrate(&vault, person, PersonSubstrate::Meat, writer(), 100)?;
        let before = vault.get(&id)?;
        let body = subject_fact(
            PREDICATE_PERSON_SUBSTRATE,
            missing,
            Value::from("model"),
            writer(),
            100,
        );
        let doc = LoroDoc::new();
        let materializer = Materializer::new();
        map_insert_bytes(
            &doc.get_map("entities"),
            &id.to_hex(),
            &blob(ENTITY_TYPE_CLAIM, &encode_claim_body(&body)?),
        )?;
        doc.commit();
        forward_rematerialize(&vault, &doc, &materializer, &WindowKey::new(WINDOW))?;
        assert!(pending_remat_entities(&vault, WINDOW)?.contains(&id.to_hex()));
        let edge = if malformed_edge {
            Vec::new()
        } else {
            encode_edge_value_for_crdt(EdgeKind::Mentions, 1.0, 100, None, None)?
        };
        map_insert_bytes(
            &doc.get_map("edges"),
            &format_edge_key(&id, EdgeKind::Mentions, &person),
            &edge,
        )?;
        doc.commit();
        forward_rematerialize(&vault, &doc, &materializer, &WindowKey::new(WINDOW))?;
        assert_eq!(vault.get(&id)?, before);
        assert!(pending_remat_entities(&vault, WINDOW)?.contains(&id.to_hex()));
        seed(&vault, missing, ENTITY_TYPE_PERSON);
        forward_rematerialize(&vault, &doc, &materializer, &WindowKey::new(WINDOW))?;
        assert_eq!(vault.get_claim(&id)?, Some(body));
        assert!(!pending_remat_entities(&vault, WINDOW)?.contains(&id.to_hex()));
    }
    Ok(())
}
