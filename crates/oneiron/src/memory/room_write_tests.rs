//! The rooms facade rechecks membership in each committing writer transaction.
use super::*;
use crate::{EdgeActorClass, EntityId, TimeRange, VaultConfig};

#[test]
fn room_membership_revocation_between_prepare_and_commit_refuses_both_writers() {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let actor = crate::test_util::entity(0x51);
    let room = crate::test_util::entity(0x52);
    let message = crate::test_util::entity(0x53);
    let claim = crate::test_util::entity(0x54);
    let at = TimeRange { start: 1, end: 1 };
    vault
        .put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            at,
            1,
            b"person",
        )
        .unwrap();
    let set_members = |members: Vec<EntityId>| {
        let body = rmp_serde::to_vec_named(&serde_json::json!({"kind":"channel", "memberIds":members.iter().map(EntityId::to_hex).collect::<Vec<_>>()})).unwrap();
        vault
            .put_entity(
                &room,
                crate::registry::ENTITY_TYPE_CONVERSATION,
                at,
                1,
                &body,
            )
            .unwrap();
    };
    set_members(vec![actor]);
    let memory = vault.memory(actor, EdgeActorClass::Human);
    let narrowed = memory.in_room(room);
    let turn = WitnessTurn {
        conversation_ref: room.to_hex(),
        turn_ref: None,
        occurred_at: 2,
        messages: vec![WitnessMessage {
            id: Some(message.to_hex()),
            author: WitnessAuthor::User,
            message_type: "dialogue".into(),
            content: "not admitted".into(),
            metadata: None,
            is_visible: true,
            order: 0,
        }],
    };
    assert!(
        narrowed
            .witness_with_pre_txn_hook(&turn, || set_members(vec![]))
            .is_err()
    );
    assert!(vault.get(&message).unwrap().is_none());
    set_members(vec![actor]);
    let input = ClaimInput {
        id: Some(claim.to_hex()),
        predicate: "room.posture.mode".into(),
        subject_ref: room.to_hex(),
        value: serde_json::json!("silent"),
        confidence: 1.0,
        source: "user_stated".into(),
        world_ref: None,
        scope: None,
        valid_from: None,
        valid_to: None,
        occurred_at: None,
        learned_at: None,
        salience: None,
    };
    assert!(
        narrowed
            .claim_upsert_with_pre_txn_hook(&input, || set_members(vec![]))
            .is_err()
    );
    assert!(vault.get(&claim).unwrap().is_none());
}
