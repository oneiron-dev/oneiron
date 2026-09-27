//! Custom-agent retrospective grouping uses only committed failure rows.
use super::*;

#[test]
fn custom_agent_failures_group_by_class_with_member_refs_and_stay_in_vault() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (_other_dir, other) = open_vault();
    let agent = put_scope_agent(&vault, 0x31, "custom.one")?;
    let other_agent = put_scope_agent(&other, 0x31, "custom.one")?;

    for (i, class) in [
        FailureSignalClass::TaskFailure,
        FailureSignalClass::MemoryMiss,
        FailureSignalClass::TaskFailure,
    ]
    .into_iter()
    .enumerate()
    {
        let attempt = leased_dispatch(&vault, agent, 10 + i as u64)?;
        let FailureLadderOutcome::Human(surface) = FailureLadder::new(&vault)
            .handle_attempt_failure(
                failure_input(&attempt, indeterminate(), 20 + i as u64),
                policy_with(agent, 3, FailureEscalationMode::Human),
            )?
        else {
            panic!("expected terminal failure");
        };
        assert_eq!(surface.failed_attempt.id, attempt.id);
        vault.record_custom_agent_failure(attempt.id, class)?;
        // A duplicate producer callback is idempotent; it cannot move the row to another class.
        vault.record_custom_agent_failure(attempt.id, class)?;
    }
    let groups = vault.custom_agent_failure_groups()?;
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].class, FailureSignalClass::TaskFailure);
    assert_eq!(groups[0].count, 2);
    assert_eq!(groups[0].member_refs.len(), 2);
    assert_eq!(groups[1].class, FailureSignalClass::MemoryMiss);
    assert_eq!(groups[1].count, 1);
    assert_ne!(groups[0].member_refs[0], groups[0].member_refs[1]);
    let counts = vault.custom_agent_tier_one_counts()?;
    assert_eq!(counts.len(), 2);
    assert!(counts.iter().all(|row| row.agent_kind == AgentKind::Custom));
    assert_eq!(counts.iter().map(|row| row.count).sum::<u64>(), 3);
    let serialized = serde_json::to_string(&counts).expect("serialize content-free counts");
    assert!(!serialized.contains("member_refs"));
    assert!(!serialized.contains(&agent.to_hex()));

    assert!(other.custom_agent_failure_groups()?.is_empty());
    let other_attempt = leased_dispatch(&other, other_agent, 30)?;
    FailureLadder::new(&other).handle_attempt_failure(
        failure_input(&other_attempt, indeterminate(), 31),
        policy_with(other_agent, 3, FailureEscalationMode::Human),
    )?;
    other.record_custom_agent_failure(other_attempt.id, FailureSignalClass::Other)?;
    assert_eq!(vault.custom_agent_failure_groups()?, groups);
    assert_eq!(other.custom_agent_failure_groups()?[0].count, 1);
    Ok(())
}

#[test]
fn custom_failure_recording_refuses_nonfailed_or_foreign_attempts_and_conflicting_class()
-> Result<()> {
    let (_dir, vault) = open_vault();
    let (_other_dir, other) = open_vault();
    let agent = put_scope_agent(&vault, 0x32, "custom.two")?;
    let queued = dispatch_attempt(&vault, agent, 10)?;
    assert!(
        vault
            .record_custom_agent_failure(queued.id, FailureSignalClass::TaskFailure)
            .is_err()
    );
    assert!(
        other
            .record_custom_agent_failure(queued.id, FailureSignalClass::TaskFailure)
            .is_err()
    );
    let leased = claim(&vault, queued.id, 10)?;
    FailureLadder::new(&vault).handle_attempt_failure(
        failure_input(&leased, indeterminate(), 11),
        policy_with(agent, 3, FailureEscalationMode::Human),
    )?;
    vault.record_custom_agent_failure(queued.id, FailureSignalClass::TaskFailure)?;
    assert!(
        vault
            .record_custom_agent_failure(queued.id, FailureSignalClass::MemoryMiss)
            .is_err()
    );
    let system = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .expect("system definition seeded")
        .0;
    let system_attempt = leased_dispatch(&vault, system, 30)?;
    FailureLadder::new(&vault).handle_attempt_failure(
        failure_input(&system_attempt, indeterminate(), 31),
        policy_with(system, 3, FailureEscalationMode::Human),
    )?;
    assert!(
        vault
            .record_custom_agent_failure(system_attempt.id, FailureSignalClass::TaskFailure)
            .is_err()
    );
    assert_eq!(vault.custom_agent_failure_groups()?[0].count, 1);
    Ok(())
}
