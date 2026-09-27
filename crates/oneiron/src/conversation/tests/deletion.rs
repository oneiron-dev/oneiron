use super::*;
use std::collections::BTreeMap;

fn second(vault: &Vault) -> WriteActor {
    let bob = EntityId::now();
    vault
        .put_entity(
            &bob,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 0, end: 0 },
            0,
            &encode(&serde_json::json!({})).unwrap(),
        )
        .unwrap();
    let actor = WriteActor::new(bob, EdgeActorClass::Human);
    crate::conversation_dag::fixtures::grant(vault, actor, true);
    actor
}

#[test]
fn role_codec_and_authority_are_bound_to_local_membership() {
    let (_dir, vault, owner, room, _) = fixture();
    let bob = second(&vault);
    let mut body = vault.conversation_body(room).unwrap();
    body.member_ids.push(bob.entity_ref());
    body.roles = BTreeMap::from([(bob.entity_ref().to_hex(), RoomRole::Admin)]);
    assert_eq!(
        body.to_bytes()
            .and_then(|bytes| ConversationBody::from_bytes(&bytes))
            .unwrap(),
        body
    );
    let unknown = EntityId::now();
    body.roles.insert(unknown.to_hex(), RoomRole::Owner);
    assert_eq!(
        body.to_bytes().unwrap_err().kind(),
        ErrorKind::InvalidConversationBody
    );
    vault
        .join_member(room, bob.entity_ref(), owner, 2, HistoryChoice::Share)
        .unwrap();
    let mut forged = vault.conversation_body(room).unwrap();
    forged
        .roles
        .insert(bob.entity_ref().to_hex(), RoomRole::Admin);
    assert_eq!(
        vault
            .batch()
            .put(
                &room,
                ENTITY_TYPE_CONVERSATION,
                TimeRange { start: 1, end: 1 },
                1,
                &forged.to_bytes().unwrap()
            )
            .commit()
            .unwrap_err()
            .kind(),
        ErrorKind::ConversationState
    );
    vault
        .set_room_role(room, bob.entity_ref(), RoomRole::Admin, owner)
        .unwrap();
    assert_eq!(
        vault.conversation_body(room).unwrap().roles[&bob.entity_ref().to_hex()],
        RoomRole::Admin
    );
    let txn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        roles::role_in(&vault, &txn, room, bob).unwrap(),
        RoomRole::Admin
    );
    drop(txn);
    vault
        .leave_member(room, bob.entity_ref(), owner, 3)
        .unwrap();
    assert!(
        !vault
            .conversation_body(room)
            .unwrap()
            .roles
            .contains_key(&bob.entity_ref().to_hex())
    );
    let txn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        roles::role_in(&vault, &txn, room, bob).unwrap_err().kind(),
        ErrorKind::ConversationDenied
    );
}

#[test]
fn author_and_admin_delete_require_authority_and_write_role_receipts() {
    let (_dir, vault, owner, room, _) = fixture();
    let bob = second(&vault);
    vault
        .join_member(room, bob.entity_ref(), owner, 2, HistoryChoice::Share)
        .unwrap();
    let first = vault
        .append_dag_record(&record(&vault, room, bob, 4))
        .unwrap()
        .id;
    assert_eq!(
        vault
            .delete_room_record(room, first, owner, crate::DeleteReason::UserDelete)
            .unwrap_err()
            .kind(),
        ErrorKind::ConversationDenied
    );
    assert_eq!(
        vault
            .delete_room_record(room, first, bob, crate::DeleteReason::PolicyDelete)
            .unwrap_err()
            .kind(),
        ErrorKind::ConversationDenied
    );
    let second = vault
        .append_dag_record(&record(&vault, room, owner, 5))
        .unwrap()
        .id;
    assert_eq!(
        vault
            .delete_entity_with_reason(&first, crate::DeleteReason::UserDelete)
            .unwrap_err()
            .kind(),
        ErrorKind::ConversationDenied
    );
    assert!(
        vault
            .delete_room_record(room, first, bob, crate::DeleteReason::UserDelete)
            .unwrap()
            .existed
    );
    assert!(vault.is_deleted_shell(&first).unwrap());
    vault
        .set_room_role(room, bob.entity_ref(), RoomRole::Admin, owner)
        .unwrap();
    let result = vault
        .delete_room_record(room, second, bob, crate::DeleteReason::PolicyDelete)
        .unwrap();
    assert!(result.existed);
    let receipt = result.receipt_id.unwrap();
    let raw = vault.get_raw_unsealed(&receipt).unwrap().unwrap();
    let body = crate::deletion::decode_redaction_audit_receipt(
        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    )
    .unwrap();
    assert_eq!(body.reason, "policy_delete");
    assert_eq!(
        body.actor_ref.as_deref(),
        Some(bob.entity_ref().to_hex().as_str())
    );
    assert_eq!(body.room_ref.as_deref(), Some(room.to_hex().as_str()));
    assert_eq!(body.room_role, Some(RoomRole::Admin));
    assert!(vault.get(&second).unwrap().is_none());
}

#[test]
fn erasure_covers_trunk_thread_and_sub_session_without_rewriting_ledger() {
    let (_dir, vault, owner, room, _) = fixture();
    let bob = second(&vault);
    vault
        .join_member(room, bob.entity_ref(), owner, 2, HistoryChoice::Share)
        .unwrap();
    let root = vault
        .append_dag_record(&record(&vault, room, owner, 4))
        .unwrap()
        .id;
    let trunk = vault
        .append_dag_record(&record(&vault, room, bob, 5))
        .unwrap()
        .id;
    let thread = vault
        .reply_in_thread(root, &record(&vault, room, bob, 6))
        .unwrap()
        .id;
    let session = vault.spawn_dag_sub_session(&root, owner).unwrap();
    let mut worker = record(&vault, room, bob, 7);
    worker.parent = Some(root);
    worker.session = Some(session);
    worker.advance = false;
    let worker = vault.append_dag_record(&worker).unwrap().id;
    let mut reply = record(&vault, room, owner, 8);
    reply.reply_to = Some(trunk);
    reply.parent = Some(trunk);
    let pointer = vault.append_dag_record(&reply).unwrap().id;
    let only_erased = crate::actor_claims::write_actor_claim(
        &vault,
        crate::actor_claims::ActorClaimRow::Lesson {
            actor: bob.entity_ref(),
            text: "sole erased evidence".into(),
        },
        &crate::actor_claims::ActorClaimEvidence::chat(session, vec![worker], 10).unwrap(),
    )
    .unwrap();
    let corroborated = crate::actor_claims::write_actor_claim(
        &vault,
        crate::actor_claims::ActorClaimRow::Lesson {
            actor: bob.entity_ref(),
            text: "other surviving evidence".into(),
        },
        &crate::actor_claims::ActorClaimEvidence::chat(session, vec![worker, root], 10).unwrap(),
    )
    .unwrap();
    let ledger = vault.membership_ledger(room).unwrap();
    let outcomes = vault
        .erase_room_person(room, bob.entity_ref(), owner)
        .unwrap();
    assert!(vault.get_claim(&only_erased).unwrap().is_none());
    assert!(vault.get_claim(&corroborated).unwrap().is_some());
    assert_eq!(outcomes.len(), 3);
    for id in [trunk, thread, worker] {
        assert!(vault.get(&id).unwrap().is_none());
    }
    assert!(vault.get(&root).unwrap().is_some());
    assert_eq!(vault.membership_ledger(room).unwrap(), ledger);
    let append = AppendRecord {
        conversation: room,
        parent: Some(root),
        reply_to: None,
        kind: crate::registry::ENTITY_TYPE_TURN,
        session: None,
        text: vec![],
        advance: false,
        body: encode(&serde_json::json!({"txt":"must not return"})).unwrap(),
        occurred: TimeRange { start: 11, end: 11 },
        learned_at: 11,
        actor: bob,
    };
    assert_eq!(
        vault.append_dag_record(&append).unwrap_err().kind(),
        ErrorKind::InvalidConversationDag
    );
    let strip = vault.reply_strip(&pointer).unwrap().unwrap();
    assert!(strip.redacted && strip.stale && strip.text.is_none());
    for outcome in outcomes {
        let receipt = outcome.receipt_id.unwrap();
        let raw = vault.get_raw_unsealed(&receipt).unwrap().unwrap();
        assert_eq!(raw[0], crate::registry::ENTITY_TYPE_REDACTION_AUDIT);
        let body = crate::deletion::decode_redaction_audit_receipt(
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        )
        .unwrap();
        assert_eq!(body.reason, "gdpr_delete");
        assert_eq!(body.room_role, Some(RoomRole::Owner));
    }
    assert!(
        vault
            .erase_room_person(room, bob.entity_ref(), owner)
            .unwrap()
            .is_empty()
    );
}
