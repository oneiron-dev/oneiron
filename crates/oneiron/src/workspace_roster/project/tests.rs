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

fn mint_fixture(
    vault: &Vault,
) -> Result<(
    crate::genui::ProjectProposalCard,
    crate::genui::ConsentActionRequest,
    crate::consent::AuthenticatedOwner,
    EntityId,
)> {
    use crate::genui::{
        ConsentActionKind, ConsentActorIdentity, ConsentSurface, PROJECT_PROPOSAL_MINT_ACTION_ID,
        ProjectGoalDraft, ProjectProposalCard, ProjectProposalPicks,
    };
    let person = crate::test_util::entity(0x78);
    let message = crate::test_util::entity(0x79);
    let skill = crate::test_util::entity(0x7A);
    let at = TimeRange { start: 20, end: 20 };
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        at,
        20,
        b"owner",
    )?;
    // A source message must go through the witness door, never a raw MESSAGE put.
    let staging = EntityId::now();
    let staging_project = ProjectRecord::new(
        staging,
        Some(vault.root_project()?),
        vault.root_project()?,
        person,
    );
    vault.put_project(staging, &staging_project, 20)?;
    let room = EntityId::from_hex(&staging_project.home_room)?;
    vault
        .memory(person, crate::edge::EdgeActorClass::Human)
        .rooms_speak(&crate::memory::WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(EntityId::now().to_hex()),
            messages: vec![crate::memory::WitnessMessage {
                id: Some(message.to_hex()),
                author: crate::memory::WitnessAuthor::User,
                message_type: "text".into(),
                content: "Does this sound like a project?".into(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
            occurred_at: 20,
        })
        .map_err(|err| crate::Error::InvalidConfig(err.to_string()))?;
    let source = crate::skill::SkillRecord::new(
        "example.base",
        "A base skill",
        "1",
        crate::claim::ClaimApprovalStatus::Approved,
        crate::skill::SkillLifecycle::Candidate,
        crate::claim::ClaimSource::UserStated,
        1.0,
        false,
        true,
        vec![],
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("fixture"),
        )]),
    );
    vault.put_skill_record(&skill, &source, at, 20)?;
    let leader = EntityId::from_hex(&vault.project(vault.root_project()?)?.unwrap().leader)?;
    let card = ProjectProposalCard::new(
        "card-2516",
        "owner",
        message.to_hex(),
        ProjectGoalDraft {
            goal: "Index evidence".into(),
            why: "Find records".into(),
            axes: vec!["coverage".into()],
        },
        ProjectProposalPicks {
            leader_agent_def_ref: leader.to_hex(),
            board_human_refs: vec![person.to_hex()],
            budget_share_bps: 1200,
            starting_skill_refs: vec![skill.to_hex()],
        },
    )?;
    let tap = crate::genui::ConsentActionRequest::new(
        card.card_id.clone(),
        PROJECT_PROPOSAL_MINT_ACTION_ID,
        ConsentActionKind::ProjectMint,
        ConsentActorIdentity::SurfaceActor {
            actor_ref: "owner".into(),
        },
        ConsentSurface::Dashboard,
        42,
    )?;
    let owner =
        vault.authenticate_owner(person, "owner", true, crate::store::GateDecisionId::now())?;
    Ok((card, tap, owner, skill))
}

#[test]
fn approved_project_card_mints_one_atomic_branch_and_grant() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let (card, tap, owner, source_skill) = mint_fixture(&vault)?;
    let root = vault.root_project()?;
    let receipt = vault.mint_project_from_card(&card, &tap, &owner)?;
    let id = EntityId::from_hex(&receipt.project_id)?;
    let project = vault.project(id)?.expect("minted project");
    assert_eq!(project.parent.as_deref(), Some(root.to_hex().as_str()));
    assert_eq!(project.why.as_deref(), Some(card.goal.why.as_str()));
    assert_eq!(
        project.born_from.as_deref(),
        Some(card.source_message_ref.as_str())
    );
    assert_eq!(project.leader, card.leader_agent_def_ref);
    assert_eq!(project.board, card.board_human_refs);
    assert_eq!(
        project.roster,
        vec![project.leader.clone(), card.board_human_refs[0].clone()]
    );
    assert_eq!(
        vault
            .project_room(EntityId::from_hex(&project.home_room)?)?
            .unwrap()
            .member_ids,
        project.roster
    );
    let goal = vault.project_goal_record(id)?.expect("goal record");
    assert_eq!(goal.goal, card.goal.goal);
    assert_eq!(goal.why, card.goal.why);
    assert_eq!(goal.axes, card.goal.axes);
    assert_eq!(vault.project_budget_share(id)?.unwrap().share_bps, 1200);
    assert_eq!(project.skill_forks.len(), 1);
    let fork = EntityId::from_hex(&project.skill_forks[0])?;
    assert_eq!(
        vault.get_skill_record(&fork)?.unwrap().forked_from,
        Some(source_skill)
    );
    let gate = vault
        .store
        .gate_decisions_for_grant_ref(&receipt.grant_ref)?;
    assert_eq!(gate.len(), 1);
    assert_eq!(gate[0].decision_id, receipt.grant_decision_id);
    let grant = vault
        .consent_grant(&receipt.grant_ref)?
        .expect("stored Grant");
    assert!(grant.is_active());
    assert_eq!(grant.owner_stamp.actor, owner.actor());
    let bound = grant.grant.bound();
    let crate::consent::BoundSubject::Actor(actor) = bound.subject() else {
        panic!("action Grant");
    };
    assert_eq!(actor.actor_ref(), project.leader);
    assert_eq!(actor.actor_class(), Some("agent"));
    let crate::consent::BoundClass::Action(class) = bound.class() else {
        panic!("action class");
    };
    assert_eq!(class.as_str(), "project.run");
    let crate::consent::BoundEnvelope::Action(envelope) = bound.envelope() else {
        panic!("action envelope");
    };
    assert_eq!(envelope.target(), Some(receipt.project_id.as_str()));
    assert_eq!(envelope.budget(), Some(1200));
    assert!(envelope.receipt_required());
    assert_eq!(envelope.selectors(), &[format!("project:{}", id.to_hex())]);
    let room = EntityId::from_hex(&project.home_room)?;
    let history = vault
        .memory(owner.actor(), crate::edge::EdgeActorClass::Human)
        .rooms_messages(room)
        .map_err(|err| Error::InvalidConfig(err.to_string()))?;
    assert_eq!(history.len(), 1, "one opening trunk header");
    assert!(history[0].thread_of.is_none());
    assert_eq!(history[0].message_ids.len(), 1);
    let source = EntityId::from_hex(&card.source_message_ref)?;
    let source_turn = vault
        .edges_out(&source)?
        .into_iter()
        .find(|edge| edge.kind == crate::edge::EdgeKind::PartOf)
        .expect("source turn")
        .target;
    let message_id = EntityId::from_hex(&history[0].message_ids[0])?;
    let txn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .entities
        .get(&txn, message_id.as_bytes())?
        .expect("header message");
    let body: rmpv::Value =
        rmp_serde::from_slice(&raw[ENTITY_METADATA_HEADER_LEN..]).map_err(|_| invalid())?;
    let fields = body.as_map().expect("witness body");
    let metadata = fields
        .iter()
        .find(|(k, _)| k.as_str() == Some("metadata"))
        .and_then(|(_, v)| v.as_map())
        .expect("source pointer metadata");
    assert_eq!(
        metadata
            .iter()
            .find(|(k, _)| k.as_str() == Some("project_source_message"))
            .and_then(|(_, v)| v.as_str()),
        Some(card.source_message_ref.as_str())
    );
    assert_eq!(
        metadata
            .iter()
            .find(|(k, _)| k.as_str() == Some("project_source_thread"))
            .and_then(|(_, v)| v.as_str()),
        Some(source_turn.to_hex().as_str())
    );
    drop(txn);
    assert_eq!(
        gate[0].actor_ref.as_deref(),
        Some(owner.actor().to_hex().as_str())
    );
    assert_eq!(vault.mint_project_from_card(&card, &tap, &owner)?, receipt);
    assert_eq!(vault.project_room_changes(id)?.len(), 1);
    assert_eq!(
        vault
            .memory(owner.actor(), crate::edge::EdgeActorClass::Human)
            .rooms_messages(room)
            .map_err(|err| Error::InvalidConfig(err.to_string()))?
            .len(),
        1
    );
    assert_eq!(
        vault
            .store
            .gate_decisions_for_grant_ref(&receipt.grant_ref)?
            .len(),
        1
    );
    drop(vault);
    let reopened = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert_eq!(
        reopened.mint_project_from_card(&card, &tap, &owner)?,
        receipt
    );
    assert_eq!(reopened.project(id)?, Some(project));
    reopened.revoke_consent_grant(&owner, &receipt.grant_ref)?;
    assert!(
        !reopened
            .consent_grant(&receipt.grant_ref)?
            .unwrap()
            .is_active()
    );
    assert_eq!(
        reopened.mint_project_from_card(&card, &tap, &owner)?,
        receipt
    );
    assert!(
        !reopened
            .consent_grant(&receipt.grant_ref)?
            .unwrap()
            .is_active()
    );
    Ok(())
}

#[test]
fn project_mint_rejects_unapproved_or_changed_cards_without_writes() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let (card, mut tap, owner, skill) = mint_fixture(&vault)?;
    let projects = vault.entities_by_type(vault.project_type_byte()?)?.len();
    let skills = vault
        .entities_by_type(crate::registry::ENTITY_TYPE_SKILL)?
        .len();
    tap.action = crate::genui::ConsentActionKind::Decline;
    assert!(vault.mint_project_from_card(&card, &tap, &owner).is_err());
    tap.action = crate::genui::ConsentActionKind::ProjectMint;
    let mut missing = card.clone();
    missing.starting_skill_refs[0] = EntityId::now().to_hex();
    assert!(
        vault
            .mint_project_from_card(&missing, &tap, &owner)
            .is_err()
    );
    assert_eq!(
        vault.entities_by_type(vault.project_type_byte()?)?.len(),
        projects
    );
    assert_eq!(
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_SKILL)?
            .len(),
        skills
    );
    assert!(vault.get_skill_record(&skill)?.is_some());
    let receipt = vault.mint_project_from_card(&card, &tap, &owner)?;
    let mut changed = card;
    changed.goal.why = "Different card".into();
    assert!(
        vault
            .mint_project_from_card(&changed, &tap, &owner)
            .is_err()
    );
    assert_eq!(
        vault
            .store
            .gate_decisions_for_grant_ref(&receipt.grant_ref)?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn project_born_from_is_message_at_typed_batch_and_replay_doors() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
    let id = EntityId::now();
    let mut project = ProjectRecord::new(id, Some(root), root, leader);
    let at = TimeRange { start: 21, end: 21 };
    for source in [root, crate::test_util::entity(0x79)] {
        project.born_from = Some(source.to_hex());
        let expected = if source == root {
            crate::error::ErrorKind::InvalidProjectBody
        } else {
            crate::error::ErrorKind::ProjectDependencyPending
        };
        assert_eq!(
            vault.put_project(id, &project, 21).unwrap_err().kind(),
            expected
        );
        let bytes = encode(&project)?;
        assert_eq!(
            vault
                .batch()
                .put(&id, vault.project_type_byte()?, at, 21, &bytes)
                .commit()
                .unwrap_err()
                .kind(),
            expected
        );
        assert_eq!(
            vault
                .batch()
                .put_replicated(&id, vault.project_type_byte()?, at, 21, &bytes)
                .commit()
                .unwrap_err()
                .kind(),
            expected
        );
        assert!(vault.project(id)?.is_none());
    }
    // The same absent source arrives through the witnessed message door.
    // Retrying the replicated PROJECT then admits it instead of permanently
    // quarantining a valid out-of-order reference.
    let (card, _, _, _) = mint_fixture(&vault)?;
    assert_eq!(
        project.born_from.as_deref(),
        Some(card.source_message_ref.as_str())
    );
    let bytes = encode(&project)?;
    vault
        .batch()
        .put_replicated(&id, vault.project_type_byte()?, at, 21, &bytes)
        .commit()?;
    assert_eq!(vault.project(id)?.unwrap().born_from, project.born_from);
    Ok(())
}

#[test]
fn updating_project_cannot_recreate_its_soft_deleted_home_room() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
    let id = EntityId::now();
    let project = ProjectRecord::new(id, Some(root), root, leader);
    vault.put_project(id, &project, 1)?;
    let room = EntityId::from_hex(&project.home_room)?;
    let changes = vault.project_room_changes(id)?;
    vault.delete_entity_with_reason(&room, crate::DeleteReason::UserDelete)?;
    let mut updated = project.clone();
    updated.roster.push(EntityId::now().to_hex());
    assert!(vault.put_project(id, &updated, 2).is_err());
    assert_eq!(vault.project(id)?, Some(project));
    assert!(vault.project_room(room)?.is_none());
    assert_eq!(vault.project_room_changes(id)?, changes);
    Ok(())
}
