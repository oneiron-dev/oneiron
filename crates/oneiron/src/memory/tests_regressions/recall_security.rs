//! Recall must not be a broader read side channel than point reads or BM25.
use super::*;
use crate::off_record::OffRecordBackendClass;

#[test]
fn grantless_actor_cannot_recall_private_messages_or_render_their_text() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0xb1);
    let agent = put_person(&vault, 0xb2);
    let written = facade_for(&vault, owner)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0xb4; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: vec![witness_message(
                0,
                WitnessAuthor::User,
                "aurora borealis private fjord",
            )],
            occurred_at: 1500,
        })
        .expect("witness private message");
    let grantless = vault.memory(agent, EdgeActorClass::Agent);
    let point = grantless
        .get_entity(&written.message_short_ids[0])
        .expect("point read");
    assert!(point.value.is_none());
    assert!(point.receipt.applied.deny_all);
    assert!(grantless.query_bm25("aurora", 10).unwrap().value.is_empty());
    for effort in [Effort::Light, Effort::Medium] {
        for format in [None, Some("json"), Some("md")] {
            let pack = grantless
                .recall("aurora", effort, &RecallScope::default(), 10, format, None)
                .expect("denied recall returns a receipted empty pack");
            assert!(pack.items.is_empty());
            assert!(pack.narrowing.applied.deny_all);
            assert!(
                pack.narrowing
                    .narrowed_axes
                    .contains(&"deny_all".to_owned())
            );
            assert_eq!(pack.retrieval_meta.total_candidates, 0);
            assert!(pack.scope_honesty.out_of_scope_worlds.is_empty());
            assert!(
                !pack
                    .rendered
                    .as_deref()
                    .unwrap_or_default()
                    .contains("aurora")
            );
        }
    }
    let session = vault
        .off_record_session_vault()
        .enter("recall-grantless", OffRecordBackendClass::Local)
        .unwrap();
    let pack = grantless
        .recall_in_session(
            &session,
            "aurora",
            Effort::Medium,
            &RecallScope::default(),
            10,
            Some("json"),
            None,
        )
        .expect("session read");
    assert!(pack.items.is_empty());
    assert!(pack.narrowing.applied.deny_all);
    assert_eq!(pack.retrieval_meta.total_candidates, 0);
}

#[test]
fn world_grant_recall_returns_only_admitted_claims_and_worlds_with_receipt() {
    use crate::claim::{
        ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    };
    let (_dir, vault) = open_vault();
    let reader = put_person(&vault, 0xc1);
    let subject = put_person(&vault, 0xc2);
    let allowed_world = EntityId::from_bytes([0xc3; 16]).unwrap();
    let denied_world = EntityId::from_bytes([0xc4; 16]).unwrap();
    let put = |world, text| {
        let id = EntityId::now();
        let mut body = ClaimBody::new(
            "profile.note",
            ClaimSubject::Entity(subject),
            rmpv::Value::from(text),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        body.world = Some(world);
        body.source = Some(ClaimSource::UserStated);
        vault
            .put_claim(&id, &body, crate::TimeRange { start: 10, end: 10 }, 10)
            .expect("put claim");
        id
    };
    let allowed = put(allowed_world, "aurora permitted coast");
    let denied = put(denied_world, "aurora private fjord");
    for (id, text) in [
        (allowed, "aurora permitted coast"),
        (denied, "aurora private fjord"),
    ] {
        vault
            .batch()
            .text(&id, &[("body", text)])
            .commit()
            .expect("index claim text");
    }
    crate::memory::tests::grant_world_reads(&vault, &reader.to_hex(), allowed_world);
    let memory = vault.memory(reader, EdgeActorClass::Agent);
    assert!(
        memory
            .get_entity(&allowed.to_hex())
            .unwrap()
            .value
            .is_some()
    );
    assert!(memory.get_entity(&denied.to_hex()).unwrap().value.is_none());
    for effort in [Effort::Light, Effort::Medium] {
        let pack = memory
            .recall(
                "aurora",
                effort,
                &RecallScope {
                    world_ref: Some(allowed_world.to_hex()),
                    facet: None,
                },
                10,
                Some("json"),
                None,
            )
            .expect("world-scoped recall");
        assert!(!pack.narrowing.applied.deny_all);
        assert!(
            pack.items
                .iter()
                .any(|item| item.value_text.contains("permitted coast"))
        );
        assert!(
            pack.items
                .iter()
                .all(|item| !item.value_text.contains("private fjord"))
        );
        assert!(
            !pack
                .rendered
                .as_deref()
                .unwrap_or_default()
                .contains("private fjord")
        );
        assert!(pack.scope_honesty.out_of_scope_worlds.is_empty());
        assert!(pack.retrieval_meta.total_candidates >= pack.items.len() as u64);
    }
}
