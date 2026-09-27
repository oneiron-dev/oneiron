use super::*;
#[test]
fn project_root_child_members_and_home_room_are_atomic() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root_id = vault.root_project()?;
    let root = vault.project(root_id)?.expect("root");
    let house_room = EntityId::from_hex(&root.home_room)?;
    assert_eq!(
        vault.project_room(house_room)?.unwrap().project_id,
        root_id.to_hex()
    );
    let child_id = EntityId::now();
    let leader = EntityId::from_hex(&root.leader)?;
    let mut child = ProjectRecord::new(child_id, Some(root_id), root_id, leader);
    child.sessions = vec![EntityId::now().to_hex()];
    child.tasks = vec![EntityId::now().to_hex()];
    child.branches = vec![EntityId::now().to_hex()];
    child.skill_forks = vec![EntityId::now().to_hex()];
    child.goal = Some(EntityId::now().to_hex());
    child.budget = Some(EntityId::now().to_hex());
    child.asks = vec![EntityId::now().to_hex()];
    vault.put_project(child_id, &child, 10)?;
    assert_eq!(vault.project(child_id)?, Some(child.clone()));
    let room_id = EntityId::from_hex(&child.home_room)?;
    assert_eq!(
        vault.project_room(room_id)?.unwrap().member_ids,
        child.roster
    );
    child.roster.push(EntityId::now().to_hex());
    vault.put_project(child_id, &child, 11)?;
    assert_eq!(
        vault.project_room(room_id)?.unwrap().member_ids,
        child.roster
    );
    let changes = vault.project_room_changes(child_id)?;
    assert_eq!(changes.len(), 2);
    assert_eq!(changes[1].previous_members, vec![leader.to_hex()]);
    assert_eq!(changes[1].member_ids, child.roster);
    assert!(
        vault
            .put_entity(
                &room_id,
                ENTITY_TYPE_CONVERSATION,
                TimeRange { start: 12, end: 12 },
                12,
                b"{}"
            )
            .is_err()
    );
    let mut forged_room = vault.project_room(room_id)?.unwrap();
    forged_room.member_ids.push(EntityId::now().to_hex());
    assert!(
        vault
            .put_entity(
                &room_id,
                ENTITY_TYPE_CONVERSATION,
                TimeRange { start: 12, end: 12 },
                12,
                &encode(&forged_room)?
            )
            .is_err()
    );
    let mut cycle = root.clone();
    cycle.parent = Some(child_id.to_hex());
    assert!(vault.put_project(root_id, &cycle, 12).is_err());
    drop(vault);
    let reopened = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert_eq!(reopened.root_project()?, root_id);
    assert_eq!(reopened.project(root_id)?, Some(root));
    assert_eq!(reopened.project_room_changes(root_id)?.len(), 1);
    Ok(())
}

#[test]
fn project_binding_does_not_hijack_a_preexisting_crm_slot() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let campaign = EntityId::now();
    {
        let vault = Vault::open_unseeded_for_test(dir.path(), crate::VaultConfig::device())?;
        crate::campaign::register_crm_pack(
            &vault,
            107,
            108,
            crate::registry::TypeByteFamily::Productivity,
        )?;
        vault.put_entity(
            &campaign,
            107,
            TimeRange { start: 1, end: 1 },
            1,
            b"existing campaign",
        )?;
    }
    let vault = Vault::open(dir.path(), crate::VaultConfig::device())?;
    // The static re-key freed 103; occupied CRM slots are not a lower bound.
    assert_eq!(vault.project_type_byte()?, 103);
    assert_eq!(vault.get_entity_type(&campaign)?, Some(107));
    let root = vault.root_project()?;
    assert_eq!(vault.get_entity_type(&root)?, Some(103));
    let project = vault.project(root)?.unwrap();
    assert!(
        vault
            .project_room(EntityId::from_hex(&project.home_room)?)?
            .is_some()
    );
    Ok(())
}

#[test]
fn deleting_project_removes_derived_room_and_member_access() -> Result<()> {
    for door in [0, 1, 2] {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
        let root = vault.root_project()?;
        let owner = EntityId::now();
        vault.put_entity(
            &owner,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"member",
        )?;
        let id = EntityId::now();
        let project = ProjectRecord::new(id, Some(root), root, owner);
        vault.put_project(id, &project, 2)?;
        let room = EntityId::from_hex(&project.home_room)?;
        let memory = vault.memory(owner, crate::edge::EdgeActorClass::Human);
        assert!(
            memory
                .rooms_list()
                .unwrap()
                .iter()
                .any(|(id, _)| *id == room)
        );
        if door == 0 {
            vault.batch().delete(&id).commit()?;
        } else if door == 1 {
            vault.delete_entity_with_reason(&id, crate::DeleteReason::UserDelete)?;
        } else {
            assert!(vault.delete_entity(&id)?);
        }
        if door != 1 {
            assert!(vault.project(id)?.is_none());
        }
        assert!(vault.get(&room)?.is_none());
        assert!(vault.project_room(room)?.is_none());
        assert!(
            !memory
                .rooms_list()
                .unwrap()
                .iter()
                .any(|(id, _)| *id == room)
        );
        assert!(memory.rooms_messages(room).is_err());
        assert!(vault.bind_room_handle(room, "@old", owner).is_err());
        // No stale owner marker treats a reused ordinary conversation as a room.
        // The ordinary conversation still needs its validated MessagePack body.
        vault.put_entity(
            &room,
            ENTITY_TYPE_CONVERSATION,
            TimeRange { start: 3, end: 3 },
            3,
            &crate::conversation::ConversationBody::default().to_bytes()?,
        )?;
    }
    Ok(())
}

#[test]
fn root_and_parent_projects_cannot_be_deleted_at_any_door() -> Result<()> {
    for door in [0, 1, 2] {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
        let root = vault.root_project()?;
        let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
        let parent = EntityId::now();
        vault.put_project(
            parent,
            &ProjectRecord::new(parent, Some(root), root, leader),
            1,
        )?;
        let child = EntityId::now();
        vault.put_project(
            child,
            &ProjectRecord::new(child, Some(parent), root, leader),
            2,
        )?;
        for id in [root, parent] {
            let before = vault.project(id)?.unwrap();
            let error = match door {
                0 => vault.batch().delete(&id).commit().unwrap_err(),
                1 => vault
                    .delete_entity_with_reason(&id, crate::DeleteReason::UserDelete)
                    .unwrap_err(),
                _ => vault.delete_entity(&id).unwrap_err(),
            };
            assert_eq!(error.kind(), crate::error::ErrorKind::InvalidProjectBody);
            assert_eq!(vault.project(id)?, Some(before.clone()));
            assert!(
                vault
                    .project_room(EntityId::from_hex(&before.home_room)?)?
                    .is_some()
            );
        }
        drop(vault);
        let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
        assert_eq!(vault.root_project()?, root);
        assert!(vault.project(root)?.is_some());
    }
    Ok(())
}

#[test]
fn erased_parent_is_invalid_not_a_pending_dependency() -> Result<()> {
    for hard in [false, true] {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
        let root = vault.root_project()?;
        let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
        let parent = EntityId::now();
        vault.put_project(
            parent,
            &ProjectRecord::new(parent, Some(root), root, leader),
            1,
        )?;
        if hard {
            vault.delete_entity(&parent)?;
        } else {
            vault.delete_entity_with_reason(&parent, crate::DeleteReason::UserDelete)?;
        }
        let child = EntityId::now();
        let body = ProjectRecord::new(child, Some(parent), root, leader);
        let error = vault.put_project(child, &body, 2).unwrap_err();
        assert_eq!(error.kind(), crate::error::ErrorKind::InvalidProjectBody);
        assert!(vault.get(&child)?.is_none());
        assert!(vault.get(&EntityId::from_hex(&body.home_room)?)?.is_none());
    }
    Ok(())
}

#[test]
fn leaders_open_direct_chat_under_own_scopes_and_root_rule_narrows() -> Result<()> {
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    use crate::edge::EdgeActorClass;
    use crate::error::{ErrorKind, RecordError};
    use crate::federation::{Scope, ScopeAxis, ScopeId};
    use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
    let (dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let root = vault.root_project()?;
    let alice = EntityId::now();
    let bob = EntityId::now();
    for person in [alice, bob] {
        vault.put_entity(
            &person,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )?;
        crate::conversation_dag::fixtures::grant(
            &vault,
            crate::WriteActor::new(person, EdgeActorClass::Human),
            true,
        );
    }
    let a = EntityId::now();
    let b = EntityId::now();
    vault.put_project(a, &ProjectRecord::new(a, Some(root), a, alice), 2)?;
    vault.put_project(b, &ProjectRecord::new(b, Some(root), b, bob), 2)?;
    let chat = EntityId::now();
    let opened = vault.open_leader_chat(
        chat,
        [a, b],
        crate::WriteActor::new(alice, EdgeActorClass::Human),
        3,
    )?;
    assert_eq!(opened.projects, [a, b]);
    assert_eq!(
        vault.conversation_body(chat)?.kind,
        crate::conversation::ConversationKind::Direct
    );
    assert_eq!(vault.members(chat)?, vec![alice, bob]);
    let mut scopes = Vec::new();
    for (actor, project, at) in [(alice, a, 4), (bob, b, 5)] {
        let message = EntityId::now();
        let turn = WitnessTurn {
            conversation_ref: chat.to_hex(),
            turn_ref: None,
            occurred_at: at,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "hello".into(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
        };
        let receipt = vault
            .memory(actor, EdgeActorClass::Human)
            .witness(&turn)
            .map_err(|e| Error::InvalidConfig(format!("witness: {e}")))?;
        let turn_id = crate::memory::resolve_entity_ref(&vault, &receipt.turn_short_id)
            .map_err(|e| Error::InvalidConfig(format!("turn ref: {e}")))?;
        for id in [message, turn_id] {
            assert_eq!(vault.leader_chat_message_scope(id)?, Some(project));
            scopes.push((id, project));
        }
    }
    // The other direct-chat turn door stamps the same speaker scope.
    let dag = vault.append_dag_record(&crate::conversation_dag::fixtures::input(
        chat,
        vault.head(&chat)?,
        true,
        crate::WriteActor::new(alice, EdgeActorClass::Human),
    ))?;
    assert_eq!(vault.leader_chat_message_scope(dag.id)?, Some(a));
    scopes.push((dag.id, a));
    // The audience axis is authoritative; an accessor label alone is not.
    for (record, project) in &scopes {
        assert_eq!(
            vault.record_scope(record)?.unwrap().audience,
            ScopeAxis::Some(BTreeSet::from([ScopeId(*project)]))
        );
    }
    for (project, own, foreign) in [(a, scopes[0].0, scopes[2].0), (b, scopes[2].0, scopes[0].0)] {
        let mut selector = Scope::top();
        selector.audience = ScopeAxis::Some(BTreeSet::from([ScopeId(project)]));
        for rows in [
            vault.records_in_scope(
                &selector,
                &Scope::top(),
                &Scope::top(),
                crate::federation::record_scope::ScopeView::Normal,
            )?,
            vault.export_records_in_scope(&selector, &Scope::top(), &Scope::top())?,
        ] {
            assert!(rows.iter().any(|row| row.id == own));
            assert!(!rows.iter().any(|row| row.id == foreign));
        }
    }
    // Raw body puts and ordinary creates cannot erase or forge this binding.
    let mut forged = vault.conversation_body(chat)?;
    forged.extra.remove(super::leader_chat::CHAT_FIELD);
    assert!(
        vault
            .batch()
            .put(
                &chat,
                crate::registry::ENTITY_TYPE_CONVERSATION,
                TimeRange { start: 5, end: 5 },
                5,
                &forged.to_bytes()?
            )
            .commit()
            .is_err()
    );
    let copied = vault.conversation_body(chat)?;
    assert!(
        vault
            .create_conversation(
                EntityId::now(),
                &copied,
                crate::WriteActor::new(alice, EdgeActorClass::Human),
                5
            )
            .is_err()
    );
    let rule = EntityId::now();
    let mut claim = ClaimBody::new(
        LEADER_CHAT_RULE_PREDICATE,
        ClaimSubject::Entity(root),
        rmpv::Value::Boolean(false),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    claim.scope_project = root;
    claim.valid_from = Some(6);
    // The test-only rule is authored through the ordinary CLAIM gate. Supply
    // its policy as data; the chat mechanism never installs policy for callers.
    let policy = serde_json::json!({
        "schema_version": "1.2", "pack_id": "leader-chat-rule-fixture",
        "pack_version": "1", "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {"criticality": "normal", "sensitivity": "normal"},
        "rules": [],
        "actor_ceilings": [{"actor_class": "first_party", "ceiling": "auto"}]
    });
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        EntityId::now(),
        &rmp_serde::to_vec_named(&policy).expect("fixture policy"),
    )?;
    vault.put_claim(&rule, &claim, TimeRange { start: 6, end: 6 }, 6)?;
    let rejected = vault
        .open_leader_chat(
            EntityId::now(),
            [a, b],
            crate::WriteActor::new(alice, EdgeActorClass::Human),
            7,
        )
        .unwrap_err();
    assert_eq!(rejected.kind(), ErrorKind::ConversationDenied);
    assert!(
        matches!(rejected, Error::Record(RecordError::LeaderChatRule { rule: found }) if found == rule)
    );
    // Event timestamps do not let a caller route around a rule in force now.
    let backdated = vault
        .open_leader_chat(
            EntityId::now(),
            [a, b],
            crate::WriteActor::new(alice, EdgeActorClass::Human),
            3,
        )
        .unwrap_err();
    assert!(
        matches!(backdated, Error::Record(RecordError::LeaderChatRule { rule: found }) if found == rule)
    );
    let blocked_dag = vault
        .append_dag_record(&crate::conversation_dag::fixtures::input(
            chat,
            vault.head(&chat)?,
            true,
            crate::WriteActor::new(alice, EdgeActorClass::Human),
        ))
        .unwrap_err();
    assert!(
        matches!(blocked_dag, Error::Record(RecordError::LeaderChatRule { rule: found }) if found == rule)
    );
    let message = EntityId::now();
    let turn = WitnessTurn {
        conversation_ref: chat.to_hex(),
        turn_ref: None,
        occurred_at: 4,
        messages: vec![WitnessMessage {
            id: Some(message.to_hex()),
            author: WitnessAuthor::User,
            message_type: "text".into(),
            content: "backdated".into(),
            metadata: None,
            is_visible: true,
            order: 0,
        }],
    };
    let denied = vault
        .memory(alice, EdgeActorClass::Human)
        .witness(&turn)
        .unwrap_err();
    assert!(denied.message.contains(&rule.to_hex()));
    assert_eq!(vault.leader_chat_message_scope(message)?, None);
    assert!(vault.get(&message)?.is_none());
    drop(vault);
    let reopened = Vault::open(dir.path(), crate::VaultConfig::default())?;
    for (message, project) in scopes {
        assert_eq!(reopened.leader_chat_message_scope(message)?, Some(project));
    }
    Ok(())
}

#[test]
fn cross_project_widen_asks_the_shared_ancestor_board_not_the_other_leader() -> Result<()> {
    use crate::edge::EdgeActorClass;
    use crate::task_verb::{ConsultPayloadRef, TaskAskQuestion};
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let root = vault.root_project()?;
    let alice = EntityId::now();
    let bob = EntityId::now();
    let board_member = crate::vault::embedded_owner_actor_id()?;
    for person in [alice, bob] {
        vault.put_entity(
            &person,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )?;
    }
    crate::conversation_dag::fixtures::grant(
        &vault,
        crate::WriteActor::new(alice, EdgeActorClass::Human),
        true,
    );
    let left = EntityId::now();
    let right = EntityId::now();
    vault.put_project(left, &ProjectRecord::new(left, Some(root), left, alice), 2)?;
    vault.put_project(right, &ProjectRecord::new(right, Some(root), right, bob), 2)?;
    assert_eq!(vault.project(root)?.unwrap().board, [board_member.to_hex()]);

    let scope = crate::federation::scope_codec::read_preset();
    let grants = [alice, board_member].map(|person| {
        serde_json::json!({
            "actor_ref": person.to_hex(), "effector": "core:read",
            "scope": scope, "receipt_required": false
        })
    });
    let policy = serde_json::json!({
        "schema_version": "1.2", "pack_id": "project-widen-read-fixture",
        "pack_version": "1", "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {"criticality": "normal", "sensitivity": "normal"},
        "rules": [],
        "actor_ceilings": [{"actor_class": "human", "actor_ref": alice.to_hex(), "ceiling": "auto"}],
        "scoped_grants": grants
    });
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        EntityId::now(),
        &rmp_serde::to_vec_named(&policy).expect("read policy"),
    )?;
    let question_ref = EntityId::now();
    vault.put_entity(
        &question_ref,
        crate::registry::ENTITY_TYPE_TURN,
        TimeRange { start: 4, end: 4 },
        4,
        &rmp_serde::to_vec_named(&serde_json::json!({"role":"question"})).expect("question"),
    )?;
    let memory = vault.memory(alice, EdgeActorClass::Human);
    let question = TaskAskQuestion::new(ConsultPayloadRef::Turn(question_ref));
    let receipt = memory
        .project_widen_ask(
            left,
            right,
            ProjectWidenAxis::Budget,
            question.clone(),
            u64::MAX,
        )
        .map_err(|e| Error::InvalidConfig(e.to_string()))?;
    let route = vault
        .project_widen_ask_route(receipt.handle.group_ref)?
        .unwrap();
    assert_eq!(route.board_project, root);
    assert_eq!(route.requesting_project, left);
    assert_eq!(route.other_project, right);
    assert_eq!(route.axis, ProjectWidenAxis::Budget);
    assert_eq!(receipt.task_refs.len(), 1);
    assert_eq!(
        vault.project(root)?.unwrap().asks,
        [receipt.handle.group_ref.to_hex()]
    );
    assert!(vault.project(right)?.unwrap().asks.is_empty());
    // A replay returns the same ask rather than doubling the board row.
    assert!(
        memory
            .project_widen_ask(left, right, ProjectWidenAxis::Budget, question, u64::MAX)
            .map_err(|e| Error::InvalidConfig(e.to_string()))?
            .idempotent_replay
    );
    assert_eq!(vault.project(root)?.unwrap().asks.len(), 1);
    Ok(())
}

#[test]
fn leader_chat_membership_keeps_binding_but_allows_history_leave_and_rejoin() -> Result<()> {
    use crate::conversation::HistoryChoice;
    use crate::edge::EdgeActorClass;
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let root = vault.root_project()?;
    let alice = EntityId::from_bytes([0xD1; 16])?;
    let bob = EntityId::from_bytes([0xB1; 16])?; // intentionally sorts ahead of alice
    for person in [alice, bob] {
        vault.put_entity(
            &person,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )?;
        crate::conversation_dag::fixtures::grant(
            &vault,
            crate::WriteActor::new(person, EdgeActorClass::Human),
            true,
        );
    }
    let a = EntityId::now();
    let b = EntityId::now();
    vault.put_project(a, &ProjectRecord::new(a, Some(root), a, alice), 2)?;
    vault.put_project(b, &ProjectRecord::new(b, Some(root), b, bob), 2)?;
    for (leaver, other) in [(alice, bob), (bob, alice)] {
        let room = EntityId::now();
        let writer = crate::WriteActor::new(alice, EdgeActorClass::Human);
        vault.open_leader_chat(room, [a, b], writer, 3)?;
        let binding = vault.conversation_body(room)?.extra[super::leader_chat::CHAT_FIELD].clone();
        vault.set_history_visibility(room, other, writer, 4, 0)?;
        assert_eq!(
            vault.conversation_body(room)?.member_ids,
            vec![bob, alice],
            "history update may reorder the set"
        );
        vault.leave_member(room, leaver, writer, 5)?;
        assert_eq!(vault.members(room)?, vec![other]);
        assert_eq!(
            vault.conversation_body(room)?.extra[super::leader_chat::CHAT_FIELD],
            binding
        );
        let refused = vault
            .append_dag_record(&crate::conversation_dag::fixtures::input(
                room,
                None,
                true,
                crate::WriteActor::new(leaver, EdgeActorClass::Human),
            ))
            .unwrap_err();
        assert_eq!(refused.kind(), crate::ErrorKind::ConversationDenied);
        vault.join_member(room, leaver, writer, 6, HistoryChoice::None)?;
        assert_eq!(vault.members(room)?, vec![bob, alice]);
        assert_eq!(vault.windows(room, leaver)?.len(), 2);
    }
    Ok(())
}

#[test]
fn raw_turn_and_edge_cannot_attach_to_leader_chat_before_or_after_dag_adoption() -> Result<()> {
    use crate::{EdgeActorClass, EdgeKind};
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let root = vault.root_project()?;
    let alice = EntityId::now();
    let bob = EntityId::now();
    for person in [alice, bob] {
        vault.put_entity(
            &person,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )?;
    }
    let a = EntityId::now();
    let b = EntityId::now();
    vault.put_project(a, &ProjectRecord::new(a, Some(root), a, alice), 2)?;
    vault.put_project(b, &ProjectRecord::new(b, Some(root), b, bob), 2)?;
    let chat = EntityId::now();
    vault.open_leader_chat(
        chat,
        [a, b],
        crate::WriteActor::new(alice, EdgeActorClass::Human),
        3,
    )?;
    for adopted in [false, true] {
        if adopted {
            vault.head(&chat)?;
        }
        let raw = EntityId::now();
        let body = rmp_serde::to_vec_named(&serde_json::json!({
            "dag_kind":"record", "actor":alice.to_hex(), "scope_project_id":a.to_hex()
        }))
        .expect("turn body");
        let err = vault
            .batch()
            .put(
                &raw,
                crate::registry::ENTITY_TYPE_TURN,
                TimeRange { start: 4, end: 4 },
                4,
                &body,
            )
            .edge(&raw, EdgeKind::ChildOf, &chat, 1.0)
            .commit()
            .unwrap_err();
        assert_eq!(err.kind(), crate::ErrorKind::ConversationDenied);
        assert!(
            vault.get(&raw)?.is_none(),
            "failed batch must roll back TURN"
        );
        vault.put_entity(
            &raw,
            crate::registry::ENTITY_TYPE_TURN,
            TimeRange { start: 4, end: 4 },
            4,
            &body,
        )?;
        assert!(vault.put_edge(&raw, EdgeKind::ChildOf, &chat, 1.0).is_err());
        assert_eq!(vault.leader_chat_message_scope(raw)?, None);
    }
    Ok(())
}

#[test]
fn replicated_chat_and_turn_cannot_self_attest_a_project_scope() -> Result<()> {
    use crate::{
        EdgeKind,
        registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN},
    };
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let person_a = EntityId::now();
    let person_b = EntityId::now();
    let false_leader_a = EntityId::now();
    let false_leader_b = EntityId::now();
    let project_a = EntityId::now();
    let project_b = EntityId::now();
    let room = EntityId::now();
    let turn = EntityId::now();
    let binding = super::leader_chat::LeaderChat {
        projects: [project_a, project_b],
        actors: [false_leader_a, false_leader_b],
        persons: [person_a, person_b],
    };
    let mut body = crate::conversation::ConversationBody {
        kind: crate::conversation::ConversationKind::Direct,
        member_ids: vec![person_a, person_b],
        ..Default::default()
    };
    body.extra.insert(
        super::leader_chat::CHAT_FIELD.into(),
        rmp_serde::from_slice(&super::encode(&binding)?).expect("binding"),
    );
    let forged_turn = rmp_serde::to_vec_named(&serde_json::json!({
        "dag_kind":"record", "actor":false_leader_a.to_hex(),
        "scope_project_id":project_a.to_hex()
    }))
    .expect("turn");
    let at = TimeRange { start: 1, end: 1 };
    vault
        .batch()
        .put_replicated(&room, ENTITY_TYPE_CONVERSATION, at, 1, &body.to_bytes()?)
        .put_replicated(&turn, ENTITY_TYPE_TURN, at, 1, &forged_turn)
        .edge_with_value_fields(
            &turn,
            EdgeKind::ChildOf,
            &room,
            crate::batch::EdgeValueFields {
                weight: 1.0,
                created_at: 1,
                vad: crate::affect::Vad::NEUTRAL,
                provenance: None,
            },
        )
        .commit()?;
    assert!(
        vault
            .conversation_body(room)?
            .extra
            .contains_key(super::leader_chat::CHAT_FIELD)
    );
    assert_eq!(vault.leader_chat_message_scope(turn)?, None);
    assert!(vault.record_scope(&turn)?.is_none());
    Ok(())
}
