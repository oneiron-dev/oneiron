use super::*;
use crate::sync::bridge::{Materializer, register_observer_b};
use crate::sync::loro_support::map_insert_bytes;
use loro::LoroDoc;
use std::sync::Arc;

#[test]
fn observer_b_quarantines_malformed_alias_and_indexes_passport_before_owner_arrival() {
    let (_dir, vault) = test_vault();
    let vault = Arc::new(vault);
    let identity = entity(0x61);
    let doc = LoroDoc::new();
    let entities = doc.get_map("entities");
    let materializer = Arc::new(Materializer::new());
    let _subscription = register_observer_b(&doc, &vault, &materializer, "2027-01");
    let mut refs = [
        mid("a@x").minted_thread_ref(),
        mid("b@x").minted_thread_ref(),
    ];
    refs.sort();
    let mut malformed = alias_body(identity, &refs[1], &refs[0]);
    if let Value::Map(entries) = &mut malformed.value {
        entries.push(entries[0].clone());
    }
    let bad_id = EntityId::now();
    let blob = crate::test_util::entity_record(
        ENTITY_TYPE_CLAIM,
        interval(),
        OBSERVED_AT,
        &encode_claim_body(&malformed).unwrap(),
    );
    map_insert_bytes(&entities, &bad_id.to_hex(), &blob).unwrap();
    doc.commit();
    assert!(vault.get_claim(&bad_id).unwrap().is_none());
    assert_eq!(
        crate::sync::quarantine::quarantined_records(&vault)
            .unwrap()
            .len(),
        1
    );
    let id = EntityId::now();
    let body = passport_body(identity, "root@x");
    let blob = crate::test_util::entity_record(
        ENTITY_TYPE_CLAIM,
        interval(),
        OBSERVED_AT,
        &encode_claim_body(&body).unwrap(),
    );
    map_insert_bytes(&entities, &id.to_hex(), &blob).unwrap();
    doc.commit();
    assert!(vault.get_claim(&id).unwrap().is_some());
    assert!(
        vault
            .thread_passport(&identity, &mid("root@x"))
            .unwrap()
            .is_none()
    );
    seed_identity(&vault, identity, "agent@example.com");
    assert!(
        vault
            .thread_passport(&identity, &mid("root@x"))
            .unwrap()
            .is_some()
    );
    assert!(vault.claims_for_subject(&identity).unwrap().contains(&id));
}

#[test]
fn observer_b_reconciles_duplicate_passports_without_replicated_edge_rows() {
    let (_left_dir, left) = test_vault();
    let (_right_dir, right) = test_vault();
    let identity = entity(0x61);
    for vault in [&left, &right] {
        seed_identity(vault, identity, "agent@example.com");
    }
    left.record_thread_passport(input(identity, "left@x", OBSERVED_AT))
        .unwrap();
    right
        .record_thread_passport(input(identity, "right@x", OBSERVED_AT + 1))
        .unwrap();
    left.record_thread_passport(
        input(identity, "same@x", OBSERVED_AT + 2).with_in_reply_to(mid("left@x")),
    )
    .unwrap();
    right
        .record_thread_passport(
            ThreadPassportInput::new(identity, entity(0xB9), mid("same@x"), OBSERVED_AT + 3)
                .with_in_reply_to(mid("right@x")),
        )
        .unwrap();
    let rows: Vec<_> = family_rows(&left)
        .into_iter()
        .chain(family_rows(&right))
        .collect();
    let mut results = Vec::new();
    for reversed in [false, true] {
        let (_dir, target) = test_vault();
        let target = Arc::new(target);
        seed_identity(&target, identity, "agent@example.com");
        let doc = LoroDoc::new();
        let entities = doc.get_map("entities");
        let materializer = Arc::new(Materializer::new());
        let _subscription = register_observer_b(&doc, &target, &materializer, "2027-01");
        let mut ordered = rows.clone();
        if reversed {
            ordered.reverse();
        }
        for (id, body) in ordered {
            let blob = crate::test_util::entity_record(
                ENTITY_TYPE_CLAIM,
                interval(),
                OBSERVED_AT,
                &encode_claim_body(&body).unwrap(),
            );
            map_insert_bytes(&entities, &id.to_hex(), &blob).unwrap();
            doc.commit();
        }
        let canonical = target
            .canonical_thread_ref(&mid("left@x").minted_thread_ref())
            .unwrap();
        assert_eq!(
            target
                .canonical_thread_ref(&mid("right@x").minted_thread_ref())
                .unwrap(),
            canonical
        );
        let all = target.thread_passports(&canonical).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(
            target
                .thread_passport(&identity, &mid("same@x"))
                .unwrap()
                .unwrap()
                .mask
                .actor_ref,
            entity(0xA9)
        );
        assert!(
            crate::sync::quarantine::quarantined_records(&target)
                .unwrap()
                .is_empty()
        );
        results.push(all);
    }
    assert_eq!(results[0], results[1]);
}
