mod support;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::edge::EdgeKind;
use rmpv::Value;

use super::*;
#[cfg(feature = "sync")]
pub(crate) use support::signed_birth as create_project_signed_for_test;
pub(crate) use support::signed_depth as set_project_depth_signed_for_test;
fn enable_leader_chat_policy(vault: &Vault) -> Result<()> {
    let policy = serde_json::json!({
        "schema_version": "1.2", "pack_id": "leader-chat-test-policy",
        "pack_version": "1", "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {"criticality":"normal", "sensitivity":"normal"},
        "rules": [], "actor_ceilings": [],
        "project_collaboration": {
            "leader_chat": {"default":"allow", "precedence":"nested_narrowing",
                            "holder_override_cap":"vault"},
            "cross_project_ask": {"fallback":"hold"}
        }
    });
    crate::test_util::put_policy_manifest_bytes(
        vault,
        EntityId::now(),
        &rmp_serde::to_vec_named(&policy).expect("policy"),
    )
}

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
    let mut child = ProjectRecord::new(child_id, Some(root_id), root_id, leader)?;
    child.sessions = vec![EntityId::now().to_hex()];
    child.tasks = vec![EntityId::now().to_hex()];
    child.branches = vec![EntityId::now().to_hex()];
    child.skill_forks = vec![EntityId::now().to_hex()];
    // Goals are installed only by the authenticated goal-intake door.
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
    cycle.parents.push(child_id.to_hex());
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
        let project = ProjectRecord::new(id, Some(root), root, owner)?;
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
            assert!(vault.delete_entity_with_options(
                &id,
                crate::deletion::DeleteEntityOptions { purge: true }
            )?);
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
            &ProjectRecord::new(parent, Some(root), root, leader)?,
            1,
        )?;
        let child = EntityId::now();
        vault.put_project(
            child,
            &ProjectRecord::new(child, Some(parent), root, leader)?,
            2,
        )?;
        for id in [root, parent] {
            let before = vault.project(id)?.unwrap();
            let error = match door {
                0 => vault.batch().delete(&id).commit().unwrap_err(),
                1 => vault
                    .delete_entity_with_reason(&id, crate::DeleteReason::UserDelete)
                    .unwrap_err(),
                _ => vault
                    .delete_entity_with_options(
                        &id,
                        crate::deletion::DeleteEntityOptions { purge: true },
                    )
                    .unwrap_err(),
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
            &ProjectRecord::new(parent, Some(root), root, leader)?,
            1,
        )?;
        if hard {
            vault.delete_entity_with_options(
                &parent,
                crate::deletion::DeleteEntityOptions { purge: true },
            )?;
        } else {
            vault.delete_entity_with_reason(&parent, crate::DeleteReason::UserDelete)?;
        }
        let child = EntityId::now();
        let body = ProjectRecord::new(child, Some(parent), root, leader)?;
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
    )
    .unwrap();
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
    assert_eq!(project.parents, vec![root.to_hex()]);
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
fn project_depth_is_person_editable_and_round_trips_with_member_refs() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    assert_eq!(
        vault.project(root)?.unwrap().depth,
        crate::gate::seeded_project_depth_default()
    );
    let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
    let child = EntityId::now();
    let mut body = ProjectRecord::new(child, Some(root), root, leader).unwrap();
    body.sessions.push(EntityId::now().to_hex());
    vault.put_project(child, &body, 1)?;
    assert_eq!(vault.project(child)?, Some(body.clone()));

    let person = EntityId::now();
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let writer = crate::write_envelope::WriteActor::new(person, crate::edge::EdgeActorClass::Human);
    let revoke = crate::subject_model::tests::authorization::root_owner(&vault, writer, 0xA3)?;
    let agent = crate::write_envelope::WriteActor::new(leader, crate::edge::EdgeActorClass::Agent);
    assert!(
        crate::workspace_roster::set_project_depth_signed_for_test(
            &vault, child, 2, &agent, 2, 0xA3
        )
        .is_err()
    );
    assert_eq!(vault.project(child)?, Some(body.clone()));
    crate::workspace_roster::set_project_depth_signed_for_test(&vault, child, 2, &writer, 2, 0xA3)?;
    let edited = vault.project(child)?.unwrap();
    assert_eq!(edited.depth, 2);
    assert_eq!(edited.sessions, body.sessions);
    assert_eq!(edited.depth, 2);
    body = edited;
    crate::workspace_roster::set_project_depth_signed_for_test(
        &vault, child, 12, &writer, 3, 0xA3,
    )?;
    let edited = vault.project(child)?.unwrap();
    assert_eq!(edited.depth, 12);
    assert_eq!(edited.sessions, body.sessions);
    assert_eq!(edited.depth, 12);
    body = edited;
    assert!(
        crate::workspace_roster::set_project_depth_signed_for_test(
            &vault, child, 17, &writer, 4, 0xA3
        )
        .is_err()
    );
    assert_eq!(vault.project(child)?, Some(body.clone()));
    vault.put_authority_log_entry(
        &revoke,
        TimeRange {
            start: 102,
            end: 102,
        },
        102,
    )?;
    assert_eq!(
        crate::workspace_roster::set_project_depth_signed_for_test(
            &vault, child, 1, &writer, 5, 0xA3
        )
        .unwrap_err()
        .kind(),
        crate::error::ErrorKind::WriteConcurrentWithRevocation
    );
    body.depth = 0; // A revoked controlling signer cannot authorize a wider slice.
    assert_eq!(vault.project(child)?, Some(body.clone()));
    drop(vault);
    let reopened = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert_eq!(reopened.project(child)?, Some(body));
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
fn raw_project_depth_outside_projection_bound_is_rejected() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    let mut body = vault.project(root)?.unwrap();
    body.depth = 17;
    assert_eq!(
        vault.put_project(root, &body, 1).unwrap_err().kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    assert_eq!(
        vault.project(root)?.unwrap().depth,
        crate::gate::seeded_project_depth_default()
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
    let mut project = ProjectRecord::new(id, Some(root), root, leader).unwrap();
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
fn leaders_open_direct_chat_under_own_scopes_and_root_rule_narrows() -> Result<()> {
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    use crate::edge::EdgeActorClass;
    use crate::error::{ErrorKind, RecordError};
    use crate::federation::{Scope, ScopeAxis, ScopeId};
    use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
    let (dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    enable_leader_chat_policy(&vault)?;
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
    vault.put_project(a, &ProjectRecord::new(a, Some(root), a, alice).unwrap(), 2)?;
    vault.put_project(b, &ProjectRecord::new(b, Some(root), b, bob).unwrap(), 2)?;
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
    // A TURN is a one-speaker run even when both speakers use the same
    // `user` bucket. An append by Bob cannot relabel Alice's existing TURN.
    let alice_turn = scopes[1].0;
    let alice_message = scopes[0].0;
    let append = |message: EntityId, order: u32, content: &str| WitnessTurn {
        conversation_ref: chat.to_hex(),
        turn_ref: Some(alice_turn.to_hex()),
        occurred_at: 5,
        messages: vec![WitnessMessage {
            id: Some(message.to_hex()),
            author: WitnessAuthor::User,
            message_type: "text".into(),
            content: content.into(),
            metadata: None,
            is_visible: true,
            order,
        }],
    };
    let bob_message = EntityId::now();
    let denied = vault
        .memory(bob, EdgeActorClass::Human)
        .witness(&append(bob_message, 1, "wrong speaker"))
        .unwrap_err();
    assert!(
        denied
            .message
            .contains("conversation actor is not authorized")
    );
    assert!(vault.get(&bob_message)?.is_none());
    assert_eq!(vault.leader_chat_message_scope(alice_turn)?, Some(a));
    assert_eq!(vault.leader_chat_message_scope(alice_message)?, Some(a));
    // The owning speaker may append and retry a deterministic MESSAGE without
    // changing the TURN's persisted project.
    let alice_more = EntityId::now();
    vault
        .memory(alice, EdgeActorClass::Human)
        .witness(&append(alice_more, 1, "more"))
        .map_err(|e| Error::InvalidConfig(e.to_string()))?;
    vault
        .memory(alice, EdgeActorClass::Human)
        .witness(&append(alice_message, 0, "hello"))
        .map_err(|e| Error::InvalidConfig(e.to_string()))?;
    assert_eq!(vault.leader_chat_message_scope(alice_turn)?, Some(a));
    scopes.push((alice_more, a));
    // Stream finalization may replace the MESSAGE body with an EntityDoc
    // pointer, but its proof and ordinary Scope must match the final body.
    let streamed_message = EntityId::now();
    let streamed = WitnessTurn {
        conversation_ref: chat.to_hex(),
        turn_ref: Some(EntityId::now().to_hex()),
        occurred_at: 5,
        messages: vec![WitnessMessage {
            id: Some(streamed_message.to_hex()),
            author: WitnessAuthor::User,
            message_type: "text".into(),
            content: String::new(),
            metadata: None,
            is_visible: true,
            order: 0,
        }],
    };
    let alice_memory = vault.memory(alice, EdgeActorClass::Human);
    let handle = alice_memory
        .begin_message_stream(&streamed, None)
        .map_err(|e| Error::InvalidConfig(e.to_string()))?;
    alice_memory
        .append_to_stream(handle, "streamed leader turn")
        .map_err(|e| Error::InvalidConfig(e.to_string()))?;
    alice_memory
        .finalize_stream(handle)
        .map_err(|e| Error::InvalidConfig(e.to_string()))?;
    assert_eq!(vault.leader_chat_message_scope(streamed_message)?, Some(a));
    scopes.push((streamed_message, a));
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
            assert_eq!(
                rows.iter().any(|row| row.id == streamed_message),
                project == a,
                "finalized stream must select only under its speaker project",
            );
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
    )
    .unwrap();
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
    vault.put_project(
        left,
        &ProjectRecord::new(left, Some(root), left, alice).unwrap(),
        2,
    )?;
    vault.put_project(
        right,
        &ProjectRecord::new(right, Some(root), right, bob).unwrap(),
        2,
    )?;
    assert_eq!(vault.project(root)?.unwrap().board, [board_member.to_hex()]);

    let scope = crate::federation::scope_codec::read_preset();
    let grants = [alice, board_member].map(|person| {
        serde_json::json!({
            "actor_ref": person.to_hex(), "effector": "core:read",
            "scope": scope, "receipt_required": false
        })
    });
    let mut policy = serde_json::json!({
        "schema_version": "1.2", "pack_id": "project-widen-read-fixture",
        "pack_version": "1", "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {"criticality": "normal", "sensitivity": "normal"},
        "rules": [],
        "actor_ceilings": [{"actor_class": "human", "actor_ref": alice.to_hex(), "ceiling": "auto"}],
        "scoped_grants": grants,
        "project_collaboration": {
            "leader_chat": {"default":"allow", "precedence":"nested_narrowing",
                            "holder_override_cap":"vault"},
            "cross_project_ask": {"fallback":"hold"}
        }
    });
    let policy_id = EntityId::now();
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        policy_id,
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
    let stored: serde_json::Value =
        rmp_serde::from_slice(&vault.get(&receipt.handle.group_ref)?.expect("ask group"))
            .expect("stored ask");
    assert_eq!(stored["effective"]["default"], "hold");
    // Owner policy can choose AskMe instead of the shipped Hold fallback.
    policy["project_collaboration"] = serde_json::json!({
        "leader_chat": {"default":"allow", "precedence":"nested_narrowing",
                        "holder_override_cap":"vault"},
        "cross_project_ask": {"fallback":"ask_me"}
    });
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        policy_id,
        &rmp_serde::to_vec_named(&policy).expect("updated policy"),
    )?;
    let mut next = TaskAskQuestion::new(ConsultPayloadRef::Turn(question_ref));
    next.revision = 2;
    let next_receipt = memory
        .project_widen_ask(left, right, ProjectWidenAxis::Roster, next, u64::MAX)
        .map_err(|error| Error::InvalidConfig(error.to_string()))?;
    let stored: serde_json::Value = rmp_serde::from_slice(
        &vault
            .get(&next_receipt.handle.group_ref)?
            .expect("second ask group"),
    )
    .expect("stored second ask");
    assert_eq!(stored["requested"]["default"], "ask_me");
    assert_eq!(stored["effective"]["default"], "ask_me");
    assert_eq!(vault.project(root)?.unwrap().asks.len(), 2);
    Ok(())
}

#[test]
fn leader_chat_membership_keeps_binding_but_allows_history_leave_and_rejoin() -> Result<()> {
    use crate::conversation::HistoryChoice;
    use crate::edge::EdgeActorClass;
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    enable_leader_chat_policy(&vault)?;
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
    vault.put_project(a, &ProjectRecord::new(a, Some(root), a, alice).unwrap(), 2)?;
    vault.put_project(b, &ProjectRecord::new(b, Some(root), b, bob).unwrap(), 2)?;
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
    enable_leader_chat_policy(&vault)?;
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
    vault.put_project(a, &ProjectRecord::new(a, Some(root), a, alice).unwrap(), 2)?;
    vault.put_project(b, &ProjectRecord::new(b, Some(root), b, bob).unwrap(), 2)?;
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
        let edge_first = EntityId::now();
        let err = vault
            .batch()
            .edge(&edge_first, EdgeKind::ChildOf, &chat, 1.0)
            .put(
                &edge_first,
                crate::registry::ENTITY_TYPE_TURN,
                TimeRange { start: 4, end: 4 },
                4,
                &body,
            )
            .commit()
            .unwrap_err();
        assert_eq!(err.kind(), crate::ErrorKind::ConversationDenied);
        assert!(vault.get(&edge_first)?.is_none());
        assert!(!vault.edge_exists(&edge_first, EdgeKind::ChildOf, &chat)?);
        // The edge may have landed in an earlier transaction while the TURN
        // was absent. A later raw TURN put still cannot adopt that edge.
        let prelinked = EntityId::now();
        vault.put_edge(&prelinked, EdgeKind::ChildOf, &chat, 1.0)?;
        let err = vault
            .put_entity(
                &prelinked,
                crate::registry::ENTITY_TYPE_TURN,
                TimeRange { start: 4, end: 4 },
                4,
                &body,
            )
            .unwrap_err();
        assert_eq!(err.kind(), crate::ErrorKind::ConversationDenied);
        assert!(vault.get(&prelinked)?.is_none());
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
fn project_dag_accepts_two_parents_and_diamond_but_rejects_secondary_cycles() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
    let left = EntityId::now();
    let right = EntityId::now();
    for parent in [left, right] {
        vault.put_project(
            parent,
            &ProjectRecord::new(parent, Some(root), root, leader).unwrap(),
            1,
        )?;
    }
    let shared = EntityId::now();
    let mut child = ProjectRecord::new(shared, Some(left), root, leader).unwrap();
    child.role = ProjectRole::Corpus;
    child.parents.push(right.to_hex());
    vault.put_project(shared, &child, 2)?;
    assert_eq!(vault.project(shared)?.unwrap().parents, child.parents);
    let linked = vault.targets(&shared, crate::edge::EdgeKind::BelongsTo, None)?;
    assert_eq!(linked.len(), 2);
    assert!(linked.contains(&left) && linked.contains(&right));
    for edge in vault.edges_out(&shared)? {
        assert_eq!(edge.weight, HUB_MEMBERSHIP_WEIGHT);
    }
    let mut cyclic = vault.project(right)?.unwrap();
    cyclic.parents.push(shared.to_hex());
    assert_eq!(
        vault.put_project(right, &cyclic, 3).unwrap_err().kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    assert_eq!(vault.project(right)?.unwrap().parents, vec![root.to_hex()]);
    let mut duplicate = child.clone();
    duplicate.parents.push(left.to_hex());
    assert_eq!(
        vault.put_project(shared, &duplicate, 3).unwrap_err().kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    for parent in [left, right] {
        assert_eq!(
            vault.batch().delete(&parent).commit().unwrap_err().kind(),
            crate::error::ErrorKind::InvalidProjectBody
        );
    }
    child.parents.retain(|parent| parent != &right.to_hex());
    vault.put_project(shared, &child, 4)?;
    assert_eq!(
        vault.targets(&shared, crate::edge::EdgeKind::BelongsTo, None)?,
        vec![left]
    );
    vault.batch().delete(&right).commit()?;
    Ok(())
}

fn stored_claim(vault: &Vault) -> Result<EntityId> {
    let subject = EntityId::now();
    vault.put_entity(
        &subject,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    let claim = EntityId::now();
    vault.put_claim(
        &claim,
        &ClaimBody::new(
            "test.project_membership",
            ClaimSubject::Entity(subject),
            Value::from("fixture"),
            0.9,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .unwrap(),
        TimeRange { start: 2, end: 2 },
        2,
    )?;
    Ok(claim)
}

#[test]
fn generic_edges_cannot_invent_or_retire_project_parents() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
    let child = EntityId::now();
    vault.put_project(
        child,
        &ProjectRecord::new(child, Some(root), root, leader).unwrap(),
        1,
    )?;
    for result in [
        vault.put_edge(&root, EdgeKind::BelongsTo, &child, 0.05),
        vault
            .batch()
            .edge(&root, EdgeKind::BelongsTo, &child, 0.05)
            .commit(),
        vault
            .batch()
            .delete_edge(&child, EdgeKind::BelongsTo, &root)
            .commit(),
        vault
            .delete_edge(&child, EdgeKind::BelongsTo, &root)
            .map(|_| ()),
        vault.set_edge_weight(&child, EdgeKind::BelongsTo, &root, 1.0),
    ] {
        assert_eq!(
            result.unwrap_err().kind(),
            crate::error::ErrorKind::InvalidProjectBody
        );
    }
    assert!(!vault.edge_exists(&root, EdgeKind::BelongsTo, &child)?);
    assert!(vault.edge_exists(&child, EdgeKind::BelongsTo, &root)?);
    let other = EntityId::now();
    vault.put_project(
        other,
        &ProjectRecord::new(other, Some(root), root, leader).unwrap(),
        2,
    )?;
    let mut new_body = vault.project(child)?.unwrap();
    new_body.parents = vec![other.to_hex()];
    vault.put_project(child, &new_body, 3)?;
    assert!(!vault.edge_exists(&child, EdgeKind::BelongsTo, &root)?);
    assert_eq!(
        vault
            .put_edge(&child, EdgeKind::BelongsTo, &root, 0.05)
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    assert_eq!(
        vault.targets(&child, EdgeKind::BelongsTo, None)?,
        vec![other]
    );
    // Ordinary non-project belongs_to edges remain writable.
    let a = EntityId::now();
    let b = EntityId::now();
    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 0.7)?;
    assert!(vault.delete_edge(&a, EdgeKind::BelongsTo, &b)?);
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

#[test]
fn generic_and_replay_edges_cannot_link_claims_to_hubs() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    let claim = stored_claim(&vault)?;
    assert_eq!(
        vault.get_entity_type(&claim)?,
        Some(crate::registry::ENTITY_TYPE_CLAIM)
    );
    for result in [
        vault.put_project_member(claim, root),
        vault.put_edge(&claim, EdgeKind::BelongsTo, &root, 0.05),
        vault
            .batch()
            .edge(&claim, EdgeKind::BelongsTo, &root, 0.05)
            .commit(),
        vault.with_write_txn(|txn| {
            vault
                .batch_in()
                .edge_with_value_fields(
                    &claim,
                    EdgeKind::BelongsTo,
                    &root,
                    crate::batch::EdgeValueFields {
                        weight: 0.05,
                        created_at: 2,
                        vad: crate::affect::Vad::NEUTRAL,
                        provenance: None,
                    },
                )
                .apply(txn)
        }),
    ] {
        assert!(result.is_err());
    }
    assert!(!vault.edge_exists(&claim, EdgeKind::BelongsTo, &root)?);
    assert!(!vault.edge_exists(&root, EdgeKind::BelongsTo, &claim)?);
    assert_eq!(
        vault
            .put_edge(&EntityId::now(), EdgeKind::BelongsTo, &root, 0.05)
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    // A future project ID can receive an ordinary edge while it is untyped,
    // but its project body must not later turn that edge into a CLAIM hub link.
    let future = EntityId::now();
    vault.put_edge(&claim, EdgeKind::BelongsTo, &future, 0.05)?;
    let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
    assert_eq!(
        vault
            .put_project(
                future,
                &ProjectRecord::new(future, Some(root), root, leader).unwrap(),
                3,
            )
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    assert!(vault.project(future)?.is_none());
    Ok(())
}

#[test]
fn collection_membership_is_low_weight_and_never_accepts_claims() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    let asset = EntityId::now();
    vault.put_entity(
        &asset,
        crate::registry::ENTITY_TYPE_ASSET,
        TimeRange { start: 1, end: 1 },
        1,
        b"document",
    )?;
    vault.put_project_member(asset, root)?;
    let edge = vault
        .edges_out(&asset)?
        .into_iter()
        .find(|edge| edge.kind == crate::edge::EdgeKind::BelongsTo && edge.target == root)
        .expect("asset belongs to collection");
    assert_eq!(edge.weight, HUB_MEMBERSHIP_WEIGHT);
    assert_eq!(
        vault.sources(&root, crate::edge::EdgeKind::BelongsTo, None)?,
        vec![asset]
    );
    let claim = stored_claim(&vault)?;
    let err = vault.put_project_member(claim, root).unwrap_err();
    assert!(matches!(err, Error::InvalidConfig(_)));
    let err = vault
        .put_project_member(asset, EntityId::now())
        .unwrap_err();
    assert!(matches!(err, Error::InvalidConfig(_)));
    Ok(())
}

#[test]
fn project_body_updates_preserve_venture_org_edge_and_retire_only_old_project_parent() -> Result<()>
{
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
    let second_parent = EntityId::now();
    vault.put_project(
        second_parent,
        &ProjectRecord::new(second_parent, Some(root), root, leader).unwrap(),
        1,
    )?;
    let venture = EntityId::now();
    let original = ProjectRecord::new(venture, Some(root), root, leader).unwrap();
    vault.put_project(venture, &original, 2)?;
    let org = EntityId::now();
    vault.put_entity(
        &org,
        crate::registry::ENTITY_TYPE_ORG,
        TimeRange { start: 3, end: 3 },
        3,
        b"org",
    )?;
    vault.put_edge(&venture, EdgeKind::BelongsTo, &org, 0.7)?;
    let org_edge = vault
        .edges_out(&venture)?
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::BelongsTo && edge.target == org)
        .expect("venture belongs to org");
    let check = |vault: &Vault, parent: EntityId| -> Result<()> {
        let edges = vault.edges_out(&venture)?;
        let org_after = edges
            .iter()
            .find(|edge| edge.kind == EdgeKind::BelongsTo && edge.target == org)
            .expect("org link survives");
        assert_eq!(org_after.weight, org_edge.weight);
        assert_eq!(org_after.created_at, org_edge.created_at);
        assert_eq!(org_after.vad, org_edge.vad);
        assert_eq!(org_after.provenance, org_edge.provenance);
        assert_eq!(vault.targets(&venture, EdgeKind::BelongsTo, None)?.len(), 2);
        assert!(vault.edge_exists(&venture, EdgeKind::BelongsTo, &parent)?);
        Ok(())
    };
    check(&vault, root)?;
    vault.put_project(venture, &original, 4)?;
    check(&vault, root)?;
    let mut edited = original;
    edited.roster.push(EntityId::now().to_hex());
    vault.put_project(venture, &edited, 5)?;
    check(&vault, root)?;
    // Same shared projection door as replay, with a replicated body op.
    vault
        .batch()
        .put_replicated(
            &venture,
            vault.project_type_byte()?,
            TimeRange { start: 6, end: 6 },
            6,
            &encode(&edited)?,
        )
        .commit()?;
    check(&vault, root)?;
    edited.parents = vec![second_parent.to_hex()];
    vault.put_project(venture, &edited, 7)?;
    check(&vault, second_parent)?;
    assert!(!vault.edge_exists(&venture, EdgeKind::BelongsTo, &root)?);
    Ok(())
}

#[test]
fn updating_project_cannot_recreate_its_soft_deleted_home_room() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
    let id = EntityId::now();
    let project = ProjectRecord::new(id, Some(root), root, leader).unwrap();
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

#[test]
fn a_project_whose_home_room_id_sorts_first_reimports() -> Result<()> {
    // The home-room id is derived (T50), so it can sort before its project's
    // id; the whole-vault import resolves the project first either way.
    let (_source_dir, source) = crate::test_util::open_test_vault_with(Default::default());
    let root_id = source.root_project()?;
    let leader = EntityId::from_hex(&source.project(root_id)?.expect("root").leader)?;
    let (child_id, child) = (1u64..)
        .map(|n| -> Result<_> {
            let mut bytes = [0xF0; 16];
            bytes[8..].copy_from_slice(&n.to_be_bytes());
            let id = EntityId::from_bytes(bytes)?;
            Ok((id, ProjectRecord::new(id, Some(root_id), root_id, leader)?))
        })
        .find(|candidate| {
            candidate
                .as_ref()
                .map_or(true, |(id, record)| record.home_room < id.to_hex())
        })
        .expect("the search is unbounded")?;
    source.put_project(child_id, &child, 10)?;
    let artifact = source.export_whole_vault(crate::context_pack::PackFormat::Json)?;
    let (_destination_dir, destination) =
        crate::test_util::open_test_vault_with(Default::default());
    destination.import_whole_vault_json(artifact.bytes())?;
    assert_eq!(destination.project(child_id)?, Some(child.clone()));
    let room_id = EntityId::from_hex(&child.home_room)?;
    assert_eq!(
        destination.project_room(room_id)?.expect("room").project_id,
        child_id.to_hex()
    );
    Ok(())
}

#[test]
fn in_range_depth_cannot_be_changed_through_generic_or_replicated_puts() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    let original = vault.project(root)?.unwrap();
    let kind = vault.project_type_byte()?;
    let mut forged = original.clone();
    forged.depth = 0;
    let bytes = encode(&forged)?;
    let range = TimeRange { start: 8, end: 8 };
    vault.put_project(root, &forged, 8)?;
    assert_eq!(vault.project(root)?, Some(original.clone()));
    vault.batch().put(&root, kind, range, 8, &bytes).commit()?;
    assert_eq!(vault.project(root)?, Some(original.clone()));
    #[cfg(feature = "sync")]
    vault.with_write_txn(|txn| {
        vault
            .batch_in()
            .put_replicated(&root, kind, range, 8, &bytes)
            .apply(txn)
    })?;
    assert_eq!(vault.project(root)?, Some(original.clone()));

    let child = EntityId::now();
    let leader = EntityId::from_hex(&original.leader)?;
    let mut nondefault_birth = ProjectRecord::new(child, Some(root), root, leader).unwrap();
    nondefault_birth.depth = 12;
    vault.put_project(child, &nondefault_birth, 9)?;
    assert_eq!(
        vault.project(child)?.unwrap().depth,
        crate::gate::seeded_project_depth_default()
    );

    let person = EntityId::now();
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        range,
        8,
        b"owner",
    )?;
    let owner = crate::write_envelope::WriteActor::new(person, crate::edge::EdgeActorClass::Human);
    let revoke = crate::subject_model::tests::authorization::root_owner(&vault, owner, 0xA5)?;
    crate::workspace_roster::set_project_depth_signed_for_test(&vault, root, 0, &owner, 10, 0xA5)?;
    assert_eq!(vault.project(root)?.unwrap().depth, 0);
    vault.put_authority_log_entry(
        &revoke,
        TimeRange {
            start: 102,
            end: 102,
        },
        102,
    )?;
    forged.depth = 12;
    #[cfg(feature = "sync")]
    let bytes = encode(&forged)?;
    assert_eq!(
        crate::workspace_roster::set_project_depth_signed_for_test(
            &vault, root, 12, &owner, 11, 0xA5
        )
        .unwrap_err()
        .kind(),
        crate::error::ErrorKind::WriteConcurrentWithRevocation
    );
    vault.put_project(root, &forged, 11)?;
    assert_eq!(vault.project(root)?.unwrap().depth, 0);
    #[cfg(feature = "sync")]
    vault.with_write_txn(|txn| {
        vault
            .batch_in()
            .put_replicated(&root, kind, range, 11, &bytes)
            .apply(txn)
    })?;
    assert_eq!(vault.project(root)?.unwrap().depth, 0);
    Ok(())
}

#[test]
fn delete_recreate_cannot_reset_owner_depth_for_existing_attempt() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
    let id = EntityId::now();
    let born = ProjectRecord::new(id, Some(root), root, leader).unwrap();
    vault.put_project(id, &born, 1)?;
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .unwrap();
    let dispatcher = crate::agent_dispatch::AgentDispatcher::new(&vault);
    let root_attempt = dispatcher.dispatch(crate::agent_dispatch::DispatchAgent {
        target: crate::agent_dispatch::AgentDispatchTarget::Custom(agent),
        parent_attempt: None,
        dedupe_key: None,
        run_id: None,
        now: 2,
    })?;
    let crate::agent_dispatch::AgentDispatchOutcome::Dispatched(root_attempt) = root_attempt else {
        panic!("root")
    };
    let child = dispatcher.dispatch_with_context(
        crate::agent_dispatch::DispatchAgent {
            target: crate::agent_dispatch::AgentDispatchTarget::Custom(agent),
            parent_attempt: Some(root_attempt.attempt.id),
            dedupe_key: None,
            run_id: None,
            now: 3,
        },
        crate::agent_dispatch::AgentSpawnContext::default().with_project(id),
    )?;
    let crate::agent_dispatch::AgentDispatchOutcome::Dispatched(child) = child else {
        panic!("child")
    };
    assert!(child.input.depth_remaining.unwrap() > 0);
    let person = EntityId::now();
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let writer = crate::write_envelope::WriteActor::new(person, crate::edge::EdgeActorClass::Human);
    crate::subject_model::tests::authorization::root_owner(&vault, writer, 0xB4)?;
    crate::workspace_roster::set_project_depth_signed_for_test(&vault, id, 0, &writer, 4, 0xB4)?;
    let stopped = vault.project(id)?.unwrap();
    let try_spawn = || {
        dispatcher.dispatch(crate::agent_dispatch::DispatchAgent {
            target: crate::agent_dispatch::AgentDispatchTarget::Custom(agent),
            parent_attempt: Some(child.attempt.id),
            dedupe_key: None,
            run_id: None,
            now: 5,
        })
    };
    assert!(try_spawn().is_err());
    let kind = vault.project_type_byte()?;
    let range = TimeRange { start: 6, end: 6 };
    vault
        .batch()
        .delete(&id)
        .put(&id, kind, range, 6, &encode(&born)?)
        .commit()?;
    assert_eq!(vault.project(id)?, Some(stopped.clone()));
    assert!(try_spawn().is_err());
    vault.batch().delete(&id).commit()?;
    assert!(vault.project(id)?.is_none());
    vault.put_project(id, &born, 7)?;
    assert_eq!(vault.project(id)?, Some(stopped.clone()));
    vault.put_project(id, &stopped, 8)?;
    assert_eq!(vault.project(id)?, Some(stopped));
    assert!(try_spawn().is_err());
    drop(vault);
    let reopened = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert_eq!(reopened.project(id)?.unwrap().depth, 0);
    Ok(())
}

#[test]
fn secondary_parent_rule_narrows_cross_project_leader_chat() -> Result<()> {
    use crate::claim::{ClaimBody, ClaimSubject};
    use crate::edge::EdgeActorClass;
    use crate::error::RecordError;
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    enable_leader_chat_policy(&vault)?;
    let root = vault.root_project()?;
    let alice = EntityId::now();
    let bob = EntityId::now();
    for id in [alice, bob] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"leader",
        )?;
        crate::conversation_dag::fixtures::grant(
            &vault,
            crate::WriteActor::new(id, EdgeActorClass::Human),
            true,
        );
    }
    let left = EntityId::now();
    let right = EntityId::now();
    vault.put_project(
        left,
        &ProjectRecord::new(left, Some(root), left, alice).unwrap(),
        2,
    )?;
    vault.put_project(
        right,
        &ProjectRecord::new(right, Some(root), right, bob).unwrap(),
        2,
    )?;
    let first = EntityId::now();
    let second = EntityId::now();
    let mut branch = ProjectRecord::new(first, Some(left), first, alice).unwrap();
    branch.parents.push(right.to_hex()); // shared ancestor only on the second path
    vault.put_project(first, &branch, 3)?;
    vault.put_project(
        second,
        &ProjectRecord::new(second, Some(right), second, bob).unwrap(),
        3,
    )?;
    vault.open_leader_chat(
        EntityId::now(),
        [first, second],
        crate::WriteActor::new(alice, EdgeActorClass::Human),
        4,
    )?;
    let mut policy = serde_json::json!({
        "schema_version": "1.2", "pack_id": "leader-chat-dag-rule",
        "pack_version": "1", "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {"criticality": "normal", "sensitivity": "normal"},
        "rules": [], "actor_ceilings": [{"actor_class": "first_party", "ceiling": "auto"}]
    });
    let policy_id = EntityId::now();
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        policy_id,
        &rmp_serde::to_vec_named(&policy).expect("policy"),
    )?;
    let rule = EntityId::now();
    let mut claim = ClaimBody::new(
        LEADER_CHAT_RULE_PREDICATE,
        ClaimSubject::Entity(right),
        rmpv::Value::Boolean(false),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    claim.scope_project = right;
    vault.put_claim(&rule, &claim, TimeRange { start: 5, end: 5 }, 5)?;
    let refusal = vault
        .open_leader_chat(
            EntityId::now(),
            [first, second],
            crate::WriteActor::new(alice, EdgeActorClass::Human),
            6,
        )
        .unwrap_err();
    assert!(
        matches!(refusal, Error::Record(RecordError::LeaderChatRule { rule: found }) if found == rule)
    );
    // A holder's true row never undoes a stricter shared-ancestor rule.
    let true_rule = EntityId::now();
    claim.value = rmpv::Value::Boolean(true);
    vault.put_claim(&true_rule, &claim, TimeRange { start: 7, end: 7 }, 7)?;
    let refusal = vault
        .open_leader_chat(
            EntityId::now(),
            [first, second],
            crate::WriteActor::new(alice, EdgeActorClass::Human),
            8,
        )
        .unwrap_err();
    assert!(
        matches!(refusal, Error::Record(RecordError::LeaderChatRule { rule: found }) if found == rule)
    );
    // A vault manifest deny also caps a holder's true rule.
    policy["project_collaboration"] = serde_json::json!({
        "leader_chat": {"default":"deny", "precedence":"nested_narrowing",
                        "holder_override_cap":"vault"},
        "cross_project_ask": {"fallback":"hold"}
    });
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        policy_id,
        &rmp_serde::to_vec_named(&policy).expect("deny policy"),
    )?;
    assert_eq!(
        vault
            .open_leader_chat(
                EntityId::now(),
                [first, second],
                crate::WriteActor::new(alice, EdgeActorClass::Human),
                10
            )
            .unwrap_err()
            .kind(),
        crate::ErrorKind::ConversationDenied
    );
    Ok(())
}
