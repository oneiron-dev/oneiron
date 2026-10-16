use super::*;
use crate::TimeRange;
use crate::task_verb::ConsultPayloadRef;

#[test]
fn resident_keeps_goal_data_inbox_and_room_pointer_without_prompt_change() {
    let (dir, vault) =
        crate::test_util::open_test_vault_with(crate::config::VaultConfig::default());
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let (lead, definition) = vault
        .get_seeded_agent_definition_by_logical_id("sys.team_lead")
        .unwrap()
        .unwrap();
    let inbox = EntityId::now();
    vault
        .create_own_app_channel_identity(&inbox, lead, 1)
        .unwrap();
    let room = EntityId::now();
    let node = EntityId::now();
    let goal = EntityId::now();
    vault
        .put_entity(
            &goal,
            crate::registry::ENTITY_TYPE_TURN,
            TimeRange { start: 1, end: 1 },
            1,
            &[0x80],
        )
        .unwrap();
    vault
        .memory(owner, crate::edge::EdgeActorClass::Human)
        .witness(&crate::memory::WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: None,
            occurred_at: 2,
            messages: vec![crate::memory::WitnessMessage {
                id: Some(node.to_hex()),
                author: crate::memory::WitnessAuthor::User,
                message_type: "text".to_owned(),
                content: "room".to_owned(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
        })
        .unwrap();
    let auth = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap();
    let spec = ResidentAgentSpec {
        agent_def_ref: lead,
        inbox_identity_ref: inbox,
        home_conversation_ref: room,
        home_message_ref: node,
        goal: ResidentGoalRecord {
            goal: ConsultPayloadRef::Turn(goal),
            why: ConsultPayloadRef::Turn(goal),
            axes: vec![],
        },
        wake: ResidentWakeMode::HumanMessages,
    };
    vault.bind_resident_agent(&auth, &spec, 3).unwrap();
    assert_eq!(vault.resident_agent(lead).unwrap(), Some(spec.clone()));
    assert_eq!(
        vault
            .get_seeded_agent_definition_by_logical_id("sys.team_lead")
            .unwrap()
            .unwrap()
            .1
            .instructions,
        definition.instructions
    );
    assert!(
        AgentDispatcher::new(&vault)
            .dispatch_resident_inbox(lead, 16, 4)
            .unwrap()
            .is_empty()
    );
    // A code-mode root stays host-bound after restart; the resident is not an
    // in-memory executor session masquerading as persistent identity.
    drop(vault);
    let vault = crate::Vault::open(dir.path(), crate::config::VaultConfig::default()).unwrap();
    assert_eq!(vault.resident_agent(lead).unwrap(), Some(spec));
}

/// F18 (H397): owner doors take their actor from a proof this vault
/// authenticated. Another vault's proof for the same PERSON id acts on nothing.
mod foreign_owner_proof {
    use super::*;

    #[test]
    fn a_foreign_owner_proof_binds_no_resident() {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::config::VaultConfig::default());
        let owner = vault.ensure_embedded_owner_actor().unwrap();
        let (lead, _) = vault
            .get_seeded_agent_definition_by_logical_id("sys.team_lead")
            .unwrap()
            .unwrap();
        let inbox = EntityId::now();
        vault
            .create_own_app_channel_identity(&inbox, lead, 1)
            .unwrap();
        let (room, node, goal) = (EntityId::now(), EntityId::now(), EntityId::now());
        vault
            .put_entity(
                &goal,
                crate::registry::ENTITY_TYPE_TURN,
                TimeRange { start: 1, end: 1 },
                1,
                &[0x80],
            )
            .unwrap();
        vault
            .memory(owner, crate::edge::EdgeActorClass::Human)
            .witness(&crate::memory::WitnessTurn {
                conversation_ref: room.to_hex(),
                turn_ref: None,
                occurred_at: 2,
                messages: vec![crate::memory::WitnessMessage {
                    id: Some(node.to_hex()),
                    author: crate::memory::WitnessAuthor::User,
                    message_type: "text".to_owned(),
                    content: "room".to_owned(),
                    metadata: None,
                    is_visible: true,
                    order: 0,
                }],
            })
            .unwrap();
        let spec = ResidentAgentSpec {
            agent_def_ref: lead,
            inbox_identity_ref: inbox,
            home_conversation_ref: room,
            home_message_ref: node,
            goal: ResidentGoalRecord {
                goal: ConsultPayloadRef::Turn(goal),
                why: ConsultPayloadRef::Turn(goal),
                axes: vec![],
            },
            wake: ResidentWakeMode::HumanMessages,
        };
        let (_other_dir, _other, foreign) =
            crate::test_util::foreign_owner_proof(owner, &owner.to_hex());

        assert_eq!(
            vault
                .bind_resident_agent(&foreign, &spec, 3)
                .unwrap_err()
                .kind(),
            crate::ErrorKind::ConsentOwnerNotAuthenticated
        );
        assert_eq!(vault.resident_agent(lead).unwrap(), None);
        let own = vault
            .authenticate_owner(
                owner,
                &owner.to_hex(),
                true,
                crate::store::GateDecisionId::now(),
            )
            .unwrap();
        vault.bind_resident_agent(&own, &spec, 3).unwrap();
        assert_eq!(vault.resident_agent(lead).unwrap(), Some(spec));
    }
}

/// A binding awaiting its owner's critical confirm never wakes the inbox,
/// yet it still conflicts with a wider settled binding beside it. An
/// unreadable surface-event row shows whether the inbox scan ran.
#[test]
fn a_held_resident_binding_never_wakes_the_inbox_but_still_conflicts() {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::config::VaultConfig::default());
    let at = TimeRange { start: 1, end: 1 };
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let (lead, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.team_lead")
        .expect("seeded definitions")
        .expect("team lead");
    let inbox = EntityId::now();
    vault
        .create_own_app_channel_identity(&inbox, lead, 1)
        .expect("inbox identity");
    let (room, node, goal) = (EntityId::now(), EntityId::now(), EntityId::now());
    vault
        .put_entity(&goal, crate::registry::ENTITY_TYPE_TURN, at, 1, &[0x80])
        .expect("goal");
    vault
        .memory(owner, crate::edge::EdgeActorClass::Human)
        .witness(&crate::memory::WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: None,
            occurred_at: 2,
            messages: vec![crate::memory::WitnessMessage {
                id: Some(node.to_hex()),
                author: crate::memory::WitnessAuthor::User,
                message_type: "text".to_owned(),
                content: "room".to_owned(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
        })
        .expect("room");
    let auth = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("owner auth");
    let spec = ResidentAgentSpec {
        agent_def_ref: lead,
        inbox_identity_ref: inbox,
        home_conversation_ref: room,
        home_message_ref: node,
        goal: ResidentGoalRecord {
            goal: ConsultPayloadRef::Turn(goal),
            why: ConsultPayloadRef::Turn(goal),
            axes: vec![],
        },
        wake: ResidentWakeMode::HumanMessages,
    };
    let bound = vault.bind_resident_agent(&auth, &spec, 3).expect("bind");
    crate::attempt_queue::AttemptQueue::new(&vault)
        .enqueue(crate::attempt_queue::EnqueueAttempt {
            kind: crate::surface_event::SURFACE_EVENT_ATTEMPT_KIND.to_owned(),
            payload: vec![0xC1],
            dedupe_key: None,
            run_id: None,
            now: 3,
        })
        .expect("unreadable inbox row");
    let dispatch = || AgentDispatcher::new(&vault).dispatch_resident_inbox(lead, 16, 4);
    assert_eq!(
        dispatch().expect_err("a settled binding scans").kind(),
        crate::ErrorKind::InvalidAttemptQueueRecord
    );

    crate::test_util::hold_claim_for_critical_confirm(&vault, bound, 0x5B);
    assert!(dispatch().expect("a held binding scans nothing").is_empty());

    // A concurrent settled binding waking on every message does not replace
    // the held human-messages one: the two conflict and nothing is scanned.
    let mut wider = vault.get_claim(&bound).expect("read").expect("row").value;
    if let rmpv::Value::Array(fields) = &mut wider {
        fields[7] = rmpv::Value::from("all_addressed");
    }
    let envelope = crate::WriteEnvelope::new(
        crate::WriteActor::new(owner, crate::edge::EdgeActorClass::Human),
        crate::ClaimSource::UserStated,
        crate::WriteProvenance::new(rmpv::Value::from("concurrent binding")).expect("provenance"),
        crate::ClaimApprovalStatus::Approved,
    );
    vault
        .batch()
        .claim_candidate(
            &EntityId::now(),
            crate::write_envelope::ClaimCandidate::new(
                "agent.resident",
                crate::claim::ClaimSubject::Entity(lead),
                wider,
                1.0,
            ),
            &envelope,
            TimeRange { start: 5, end: 5 },
            5,
        )
        .commit()
        .expect("concurrent binding");
    assert_eq!(
        dispatch()
            .expect_err("the held binding still conflicts")
            .kind(),
        crate::ErrorKind::InvalidAgentDispatchInput
    );
}
