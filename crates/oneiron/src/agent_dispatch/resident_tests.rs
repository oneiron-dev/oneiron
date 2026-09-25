use super::*;
use crate::TimeRange;
use crate::task_verb::ConsultPayloadRef;

#[test]
fn resident_keeps_goal_data_inbox_and_room_pointer_without_prompt_change() {
    let (dir, vault) =
        crate::test_util::open_test_vault_with(crate::config::VaultConfig::default());
    let owner = EntityId::now();
    vault
        .put_entity(
            &owner,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )
        .unwrap();
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
