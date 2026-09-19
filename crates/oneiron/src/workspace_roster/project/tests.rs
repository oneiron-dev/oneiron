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
        crate::campaign::register_crm_pack(&vault, 107, 108)?;
        vault.put_entity(
            &campaign,
            107,
            TimeRange { start: 1, end: 1 },
            1,
            b"existing campaign",
        )?;
    }
    let vault = Vault::open(dir.path(), crate::VaultConfig::device())?;
    assert_eq!(vault.project_type_byte()?, 109);
    assert_eq!(vault.get_entity_type(&campaign)?, Some(107));
    let root = vault.root_project()?;
    assert_eq!(vault.get_entity_type(&root)?, Some(109));
    let project = vault.project(root)?.unwrap();
    assert!(
        vault
            .project_room(EntityId::from_hex(&project.home_room)?)?
            .is_some()
    );
    Ok(())
}
