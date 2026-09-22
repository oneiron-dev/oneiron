use super::*;

#[test]
fn workflow_round_trips_updates_forks_and_rejects_dangling_steps() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let lead = vault
        .get_seeded_agent_definition_by_logical_id("sys.team_lead")?
        .unwrap()
        .0;
    let worker = vault
        .get_seeded_agent_definition_by_logical_id("sys.scout")?
        .unwrap()
        .0;
    let id = EntityId::now();
    let definition = WorkflowDefinition::new("two steps", vec![lead, worker])?;
    vault.save_workflow(&id, &definition, 10)?;
    assert_eq!(vault.get_workflow(&id)?, Some(definition.clone()));
    assert_eq!(decode_workflow(&encode_workflow(&definition)?)?, definition);
    assert_eq!(vault.get_entity_type(&id)?, Some(ENTITY_TYPE_WORKFLOW));
    let fork_id = EntityId::now();
    let fork = vault.fork_workflow(&id, &fork_id, 11)?;
    assert_eq!(fork.forked_from, Some(id));
    assert_eq!(vault.get_workflow(&id)?, Some(definition.clone()));
    let mut edited = definition.clone();
    edited.revision = 2;
    edited.steps.reverse();
    vault.update_workflow(&id, 1, &edited, 12)?;
    assert!(vault.update_workflow(&id, 1, &edited, 12).is_err());
    let bad = WorkflowDefinition::new("dangling", vec![EntityId::now()])?;
    let bad_id = EntityId::now();
    assert!(vault.save_workflow(&bad_id, &bad, 10).is_err());
    assert!(vault.get_raw(&bad_id)?.is_none());
    let replica = EntityId::now();
    vault
        .batch()
        .put_replicated(
            &replica,
            ENTITY_TYPE_WORKFLOW,
            TimeRange { start: 10, end: 10 },
            10,
            &encode_workflow(&definition)?,
        )
        .commit()?;
    assert_eq!(vault.get_workflow(&replica)?, Some(definition));
    Ok(())
}
