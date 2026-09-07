use super::replicated_substrate::{WINDOW, blob};
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

#[test]
fn anchor_sync_waits_for_both_entities_in_every_arrival_order() -> Result<()> {
    for live in [false, true] {
        for order in [
            [0, 1, 2],
            [1, 0, 2],
            [0, 2, 1],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let (_dir, vault) = test_vault();
            let vault = Arc::new(vault);
            let doc = LoroDoc::new();
            let materializer = Arc::new(Materializer::new());
            let _subscriptions =
                live.then(|| register_observer_b(&doc, &vault, &materializer, WINDOW));
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
            let rows = [
                (actor, blob(ENTITY_TYPE_PERSON, b"actor")),
                (subject, blob(ENTITY_TYPE_ORG, b"subject")),
                (id, blob(ENTITY_TYPE_CLAIM, &encode_claim_body(&body)?)),
            ];
            // ClaimOf may precede the claim and either endpoint dependency.
            map_insert_bytes(
                &doc.get_map("edges"),
                &format_edge_key(&id, EdgeKind::ClaimOf, &actor),
                &encode_edge_value_for_crdt(EdgeKind::ClaimOf, 1.0, 100, None, None)?,
            )?;
            doc.commit();
            let mut arrived = [false; 3];
            for op in order {
                let (key, bytes) = &rows[op];
                map_insert_bytes(&doc.get_map("entities"), &key.to_hex(), bytes)?;
                doc.commit();
                arrived[op] = true;
                for _ in 0..2 {
                    forward_rematerialize(&vault, &doc, &materializer, &WindowKey::new(WINDOW))?;
                    if arrived[2] && !(arrived[0] && arrived[1]) {
                        assert!(vault.get(&id)?.is_none());
                        assert!(pending_remat_entities(&vault, WINDOW)?.contains(&id.to_hex()));
                        assert_eq!(actor_subject_anchor(&vault, &actor, 100)?, None);
                    }
                }
            }
            assert_eq!(vault.get_claim(&id)?, Some(body));
            assert!(!pending_remat_entities(&vault, WINDOW)?.contains(&id.to_hex()));
            assert_eq!(actor_subject_anchor(&vault, &actor, 100)?, Some(subject));
        }
    }
    Ok(())
}

#[test]
fn anchor_sync_rejects_hostile_actor_or_subject_without_overwriting_valid_anchor() -> Result<()> {
    for live in [false, true] {
        for hostile in 0..4 {
            let (_dir, vault) = test_vault();
            let vault = Arc::new(vault);
            let actor = seed(&vault, entity(0xB1), ENTITY_TYPE_AGENT_DEF);
            let subject = seed(&vault, entity(0xB2), ENTITY_TYPE_PERSON);
            let wrong = seed(&vault, entity(0xB3), ENTITY_TYPE_PLACE);
            let id = anchor_actor_subject(&vault, actor, subject, writer(), 100)?;
            let before = vault.get(&id)?;
            let new_id = entity(0xB4);
            let (claim_subject, value) = match hostile {
                0 => (wrong, Value::from(subject.to_hex())),
                1 => (actor, Value::from(wrong.to_hex())),
                2 => (actor, Value::from(actor.to_hex())),
                _ => (actor, Value::from(3)),
            };
            let body = subject_fact(
                PREDICATE_ACTOR_SUBJECT_REF,
                claim_subject,
                value,
                writer(),
                100,
            );
            let bytes = blob(ENTITY_TYPE_CLAIM, &encode_claim_body(&body)?);
            let doc = LoroDoc::new();
            let materializer = Arc::new(Materializer::new());
            let _subscriptions =
                live.then(|| register_observer_b(&doc, &vault, &materializer, WINDOW));
            for target in [id, new_id] {
                map_insert_bytes(&doc.get_map("entities"), &target.to_hex(), &bytes)?;
            }
            doc.commit();
            forward_rematerialize(&vault, &doc, &materializer, &WindowKey::new(WINDOW))?;
            assert_eq!(vault.get(&id)?, before);
            assert!(vault.get(&new_id)?.is_none());
            assert_eq!(vault.claims_for_subject(&actor)?, vec![id]);
            assert!(vault.claims_for_subject(&wrong)?.is_empty());
            assert_eq!(actor_subject_anchor(&vault, &actor, 100)?, Some(subject));
            assert!(pending_remat_entities(&vault, WINDOW)?.is_empty());
            assert!(!quarantined_records(&vault)?.is_empty());
        }
    }
    Ok(())
}

#[test]
fn anchor_sync_wrong_type_arrival_is_terminal_even_with_another_missing_dependency() -> Result<()> {
    for live in [false, true] {
        for wrong_actor in [false, true] {
            let (_dir, vault) = test_vault();
            let vault = Arc::new(vault);
            let actor = entity(0xB1);
            let subject = entity(0xB2);
            let id = entity(0xB3);
            let doc = LoroDoc::new();
            let materializer = Arc::new(Materializer::new());
            let _subscriptions =
                live.then(|| register_observer_b(&doc, &vault, &materializer, WINDOW));
            let body = subject_fact(
                PREDICATE_ACTOR_SUBJECT_REF,
                actor,
                Value::from(subject.to_hex()),
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
            let wrong = if wrong_actor { actor } else { subject };
            map_insert_bytes(
                &doc.get_map("entities"),
                &wrong.to_hex(),
                &blob(ENTITY_TYPE_PLACE, b"wrong"),
            )?;
            doc.commit();
            for _ in 0..2 {
                forward_rematerialize(&vault, &doc, &materializer, &WindowKey::new(WINDOW))?;
            }
            assert!(vault.get(&id)?.is_none());
            assert!(!pending_remat_entities(&vault, WINDOW)?.contains(&id.to_hex()));
            assert!(vault.claims_for_subject(&actor)?.is_empty());
            assert!(!quarantined_records(&vault)?.is_empty());
        }
    }
    Ok(())
}

#[test]
fn anchor_sync_edge_outcomes_do_not_discharge_missing_reference_retry() -> Result<()> {
    for malformed_edge in [false, true] {
        let (_dir, vault) = test_vault();
        let actor = seed(&vault, entity(0xB1), ENTITY_TYPE_PERSON);
        let person = seed(&vault, entity(0xB2), ENTITY_TYPE_PERSON);
        let missing = entity(0xB3);
        let id = anchor_actor_subject(&vault, actor, person, writer(), 100)?;
        let before = vault.get(&id)?;
        let body = subject_fact(
            PREDICATE_ACTOR_SUBJECT_REF,
            actor,
            Value::from(missing.to_hex()),
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
        assert_eq!(actor_subject_anchor(&vault, &actor, 100)?, Some(person));
        assert!(pending_remat_entities(&vault, WINDOW)?.contains(&id.to_hex()));
        seed(&vault, missing, ENTITY_TYPE_ORG);
        forward_rematerialize(&vault, &doc, &materializer, &WindowKey::new(WINDOW))?;
        assert_eq!(vault.get_claim(&id)?, Some(body));
        assert_eq!(actor_subject_anchor(&vault, &actor, 100)?, Some(missing));
        assert!(!pending_remat_entities(&vault, WINDOW)?.contains(&id.to_hex()));
    }
    Ok(())
}
