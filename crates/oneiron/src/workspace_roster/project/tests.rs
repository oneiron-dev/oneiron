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
fn project_depth_is_person_editable_and_round_trips_with_member_refs() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    assert_eq!(vault.project(root)?.unwrap().depth, DEFAULT_PROJECT_DEPTH);
    let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
    let child = EntityId::now();
    let mut body = ProjectRecord::new(child, Some(root), root, leader);
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
    assert!(vault.set_project_depth(child, 2, &agent, 2).is_err());
    assert_eq!(vault.project(child)?, Some(body.clone()));
    vault.set_project_depth(child, 2, &writer, 2)?;
    body.depth = 2;
    assert_eq!(vault.project(child)?, Some(body.clone()));
    vault.set_project_depth(child, 12, &writer, 3)?;
    body.depth = 12;
    assert_eq!(vault.project(child)?, Some(body.clone()));
    assert!(vault.set_project_depth(child, 17, &writer, 4).is_err());
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
        vault
            .set_project_depth(child, 1, &writer, 5)
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::WriteConcurrentWithRevocation
    );
    assert_eq!(vault.project(child)?, Some(body.clone()));
    drop(vault);
    let reopened = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert_eq!(reopened.project(child)?, Some(body));
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
    assert_eq!(vault.project(root)?.unwrap().depth, DEFAULT_PROJECT_DEPTH);
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
    assert_eq!(
        vault.put_project(root, &forged, 8).unwrap_err().kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    assert_eq!(
        vault
            .batch()
            .put(&root, kind, range, 8, &bytes)
            .commit()
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    #[cfg(feature = "sync")]
    assert_eq!(
        vault
            .with_write_txn(|txn| {
                vault
                    .batch_in()
                    .put_replicated(&root, kind, range, 8, &bytes)
                    .apply(txn)
            })
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    assert_eq!(vault.project(root)?, Some(original.clone()));

    let child = EntityId::now();
    let leader = EntityId::from_hex(&original.leader)?;
    let mut nondefault_birth = ProjectRecord::new(child, Some(root), root, leader);
    nondefault_birth.depth = 12;
    assert_eq!(
        vault
            .put_project(child, &nondefault_birth, 9)
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    assert!(vault.project(child)?.is_none());

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
    vault.set_project_depth(root, 0, &owner, 10)?;
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
        vault
            .set_project_depth(root, 12, &owner, 11)
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::WriteConcurrentWithRevocation
    );
    assert_eq!(
        vault.put_project(root, &forged, 11).unwrap_err().kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    #[cfg(feature = "sync")]
    assert_eq!(
        vault
            .with_write_txn(|txn| {
                vault
                    .batch_in()
                    .put_replicated(&root, kind, range, 11, &bytes)
                    .apply(txn)
            })
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    assert_eq!(vault.project(root)?.unwrap().depth, 0);
    Ok(())
}
