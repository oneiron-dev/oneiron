//! Headless saved-workflow execution and authority regressions.

use super::*;
use crate::agent_def::{AgentCeiling, workflow::WorkflowDefinition};
use crate::attempt_queue::{
    AttemptRecord, AttemptResultRef, ClaimAttempt, ClaimOutcome, CompleteAttempt, RetryAttempt,
    SetAttemptResult,
};
use crate::context_projection::ContextSpec;
use crate::{TimeRange, VaultConfig};

fn fixture(vault: &Vault, ceiling: AgentCeiling, name: &str) -> Result<EntityId> {
    let (_, mut definition) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .expect("seeded default");
    definition.logical_id = None;
    definition.agent_id = format!("test.workflow.{name}");
    definition.ceiling = ceiling;
    definition.skills.clear();
    let id = EntityId::now();
    vault.put_agent_definition(&id, &definition, TimeRange { start: 1, end: 1 }, 1)?;
    Ok(id)
}
fn request(target: AgentDispatchTarget, parent: Option<AttemptId>) -> DispatchAgent {
    DispatchAgent {
        target,
        parent_attempt: parent,
        dedupe_key: Some("workflow-test".into()),
        run_id: Some("workflow-headless".into()),
        now: 10,
    }
}
fn claimed(queue: &AttemptQueue<'_>, now: u64) -> Result<AttemptRecord> {
    let ClaimOutcome::Claimed(row) = queue.claim_kind(
        "dreamer",
        ClaimAttempt {
            lease_owner: "test-host".into(),
            now,
        },
    )?
    else {
        panic!("ready leaf expected")
    };
    Ok(row)
}
fn deliver(queue: &AttemptQueue<'_>, row: &AttemptRecord, name: &str, now: u64) -> Result<()> {
    queue.set_result(SetAttemptResult {
        id: row.id,
        lease_owner: "test-host".into(),
        attempt_count: row.attempt_count,
        result_ref: AttemptResultRef::new(name)?,
        now,
    })?;
    queue.complete(CompleteAttempt {
        id: row.id,
        lease_owner: "test-host".into(),
        attempt_count: row.attempt_count,
        now,
    })?;
    Ok(())
}
fn workflow(outcome: AgentDispatchOutcome) -> WorkflowDispatchStatus {
    match outcome {
        AgentDispatchOutcome::WorkflowDispatched(status)
        | AgentDispatchOutcome::WorkflowExisting(status) => *status,
        other => panic!("workflow outcome expected: {other:?}"),
    }
}

#[test]
fn two_steps_execute_in_order_once_and_report_after_reopen() -> Result<()> {
    let (dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let first = fixture(&vault, AgentCeiling::Proposed, "first")?;
    let second = fixture(&vault, AgentCeiling::Proposed, "second")?;
    let id = EntityId::now();
    vault.save_workflow(
        &id,
        &WorkflowDefinition::new("ordered", vec![first, second])?,
        2,
    )?;
    let dispatch = request(AgentDispatchTarget::Workflow(id), None);
    let root = workflow(AgentDispatcher::new(&vault).dispatch(dispatch.clone())?)
        .attempt
        .id;
    let mut executed = Vec::new();
    let queue = AttemptQueue::new(&vault);
    let row = claimed(&queue, 11)?;
    let first_input = codec::record_dispatch_input(&row).expect("actual agent leaf");
    executed.push(first_input.target.agent_definition_ref()?);
    assert_eq!(executed, vec![first]);
    assert!(matches!(
        queue.claim(ClaimAttempt {
            lease_owner: "other-host".into(),
            now: 11
        })?,
        ClaimOutcome::Empty
    ));
    assert_eq!(
        AgentDispatcher::new(&vault).advance_workflow(root, 11)?,
        WorkflowProgress::Waiting(row.id)
    );
    deliver(&queue, &row, "artifact:first", 12)?;
    let WorkflowProgress::Advanced(second_attempt) =
        AgentDispatcher::new(&vault).advance_workflow(root, 13)?
    else {
        panic!("second step must release")
    };
    assert_eq!(
        AgentDispatcher::new(&vault).advance_workflow(root, 13)?,
        WorkflowProgress::Waiting(second_attempt)
    );
    // Rebuild handles from durable state; no process-global or host cursor exists.
    let row = claimed(&AttemptQueue::new(&vault), 14)?;
    executed.push(
        codec::record_dispatch_input(&row)
            .expect("actual leaf")
            .target
            .agent_definition_ref()?,
    );
    assert_eq!(executed, vec![first, second]);
    deliver(&AttemptQueue::new(&vault), &row, "artifact:second", 15)?;
    assert_eq!(
        AgentDispatcher::new(&vault).advance_workflow(root, 16)?,
        WorkflowProgress::Completed
    );
    assert_eq!(
        AgentDispatcher::new(&vault).advance_workflow(root, 17)?,
        WorkflowProgress::Completed
    );
    assert!(matches!(
        AgentDispatcher::new(&vault).dispatch(dispatch)?,
        AgentDispatchOutcome::WorkflowExisting(_)
    ));
    let report = AgentDispatcher::new(&vault).workflow_status(root)?;
    assert_eq!(report.attempt.state, AttemptState::Completed);
    assert_eq!(
        report
            .results
            .iter()
            .map(|result| (result.ordinal, result.result_ref.as_str()))
            .collect::<Vec<_>>(),
        vec![(0, "artifact:first"), (1, "artifact:second")]
    );
    let tree = crate::run_tree::RunTreeAdapter::new(&vault).read_run("workflow-headless")?;
    assert_eq!(tree.roots.len(), 1);
    assert_eq!(tree.roots[0].children.len(), 2);
    assert!(tree.roots[0].agent_id.is_none());
    assert!(tree.repairs.is_empty());
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    assert_eq!(
        AgentDispatcher::new(&vault).workflow_status(root)?.results,
        report.results
    );
    assert_eq!(
        AgentDispatcher::new(&vault).advance_workflow(root, 18)?,
        WorkflowProgress::Completed
    );
    Ok(())
}

#[test]
fn retry_tip_delivers_once_and_does_not_release_successor_early() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let agent = fixture(&vault, AgentCeiling::Proposed, "retry")?;
    let id = EntityId::now();
    vault.save_workflow(
        &id,
        &WorkflowDefinition::new("retry", vec![agent, agent])?,
        2,
    )?;
    let dispatcher = AgentDispatcher::new(&vault);
    let request = request(AgentDispatchTarget::Workflow(id), None);
    let root = workflow(dispatcher.dispatch(request.clone())?).attempt.id;
    let queue = AttemptQueue::new(&vault);
    let first = claimed(&queue, 11)?;
    let crate::attempt_queue::RetryOutcome::Retried(retry) = queue.retry(RetryAttempt {
        id: first.id,
        lease_owner: "test-host".into(),
        attempt_count: first.attempt_count,
        backoff_until: 20,
        last_error: Some("test-retry".into()),
        now: 12,
    })?;
    assert_eq!(
        dispatcher.advance_workflow(root, 13)?,
        WorkflowProgress::Waiting(retry.id)
    );
    assert_eq!(workflow(dispatcher.dispatch(request)?).attempt.id, root);
    assert!(matches!(
        queue.claim(ClaimAttempt {
            lease_owner: "test-host".into(),
            now: 19
        })?,
        ClaimOutcome::Empty
    ));
    let retry = claimed(&queue, 20)?;
    deliver(&queue, &retry, "artifact:retry", 21)?;
    let WorkflowProgress::Advanced(next) = dispatcher.advance_workflow(root, 22)? else {
        panic!("advance")
    };
    assert_eq!(
        dispatcher.advance_workflow(root, 22)?,
        WorkflowProgress::Waiting(next)
    );
    assert_eq!(dispatcher.workflow_status(root)?.results.len(), 1);
    assert_eq!(
        dispatcher.workflow_status(root)?.results[0].attempt_id,
        retry.id
    );
    let next = claimed(&queue, 23)?;
    deliver(&queue, &next, "artifact:after-retry", 24)?;
    assert_eq!(
        dispatcher.advance_workflow(root, 25)?,
        WorkflowProgress::Completed
    );
    assert_eq!(dispatcher.workflow_status(root)?.results.len(), 2);
    Ok(())
}

#[test]
fn wrapper_keeps_parent_depth_context_and_live_ceiling() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let parent = fixture(&vault, AgentCeiling::Proposed, "parent")?;
    let child = fixture(&vault, AgentCeiling::Auto, "child")?;
    let dispatcher = AgentDispatcher::new(&vault);
    let mut parent_request = request(AgentDispatchTarget::Custom(parent), None);
    parent_request.dedupe_key = None;
    let AgentDispatchOutcome::Dispatched(parent) = dispatcher.dispatch_with_context(
        parent_request,
        AgentSpawnContext::default()
            .with_context_spec(ContextSpec::excluded())
            .with_depth_remaining(1),
    )?
    else {
        panic!("parent")
    };
    let id = EntityId::now();
    vault.save_workflow(
        &id,
        &WorkflowDefinition::new("bounded", vec![child, child])?,
        2,
    )?;
    let status = workflow(dispatcher.dispatch_with_context(
        request(AgentDispatchTarget::Workflow(id), Some(parent.attempt.id)),
        AgentSpawnContext::default().with_context_spec(ContextSpec::excluded()),
    )?);
    let row = AttemptQueue::new(&vault).get(status.active_step)?.unwrap();
    let input = codec::record_dispatch_input(&row).unwrap();
    assert_eq!(input.depth_remaining, Some(0));
    assert_eq!(
        vault
            .get_agent_definition(&input.target.agent_definition_ref()?)?
            .unwrap()
            .ceiling,
        AgentCeiling::Proposed
    );
    assert_eq!(
        dispatcher.resolve_attempt_context(row.id)?,
        dispatcher.resolve_attempt_context(parent.attempt.id)?
    );
    assert!(
        dispatcher
            .dispatch(request(AgentDispatchTarget::Custom(child), Some(row.id)))
            .is_err()
    );
    assert!(
        dispatcher
            .dispatch(request(
                AgentDispatchTarget::Custom(child),
                Some(status.attempt.id)
            ))
            .is_err()
    );
    assert!(
        agent_dispatch_actor(&AgentDispatchInput::frozen(
            AgentDispatchTarget::Workflow(id),
            input.definition
        ))
        .is_err()
    );
    Ok(())
}

#[test]
fn invalid_later_step_rolls_back_wrapper_first_step_and_earlier_fork() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let parent_id = fixture(&vault, AgentCeiling::Proposed, "rollback-parent")?;
    let first = fixture(&vault, AgentCeiling::Auto, "rollback-first")?;
    let second = fixture(&vault, AgentCeiling::Auto, "rollback-second")?;
    let dispatcher = AgentDispatcher::new(&vault);
    let mut req = request(AgentDispatchTarget::Custom(parent_id), None);
    req.dedupe_key = None;
    let AgentDispatchOutcome::Dispatched(parent) = dispatcher.dispatch(req)? else {
        panic!("parent")
    };
    let id = EntityId::now();
    vault.save_workflow(
        &id,
        &WorkflowDefinition::new("rollback", vec![first, second])?,
        2,
    )?;
    let fingerprint = |id| {
        attenuation::source_content_fingerprint(&vault.get_agent_definition(&id).unwrap().unwrap())
    };
    let first_fork = attenuation::attenuated_fork_id(
        first,
        &fingerprint(first)?,
        parent.attempt.id,
        Some("workflow-headless"),
    )?;
    let second_fork = attenuation::attenuated_fork_id(
        second,
        &fingerprint(second)?,
        parent.attempt.id,
        Some("workflow-headless"),
    )?;
    // Occupy the deterministic later fork with a different valid definition.
    let foreign = vault.get_agent_definition(&parent_id)?.unwrap();
    vault.put_agent_definition(&second_fork, &foreign, TimeRange { start: 3, end: 3 }, 3)?;
    let before = AttemptQueue::new(&vault).list()?;
    assert!(
        dispatcher
            .dispatch(request(
                AgentDispatchTarget::Workflow(id),
                Some(parent.attempt.id)
            ))
            .is_err()
    );
    assert_eq!(AttemptQueue::new(&vault).list()?, before);
    assert!(vault.get_raw(&first_fork)?.is_none());
    Ok(())
}

#[test]
fn later_release_rechecks_live_parent_and_freezes_composition() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let parent_id = fixture(&vault, AgentCeiling::Auto, "live-parent")?;
    let child = fixture(&vault, AgentCeiling::Auto, "live-child")?;
    let dispatcher = AgentDispatcher::new(&vault);
    let mut req = request(AgentDispatchTarget::Custom(parent_id), None);
    req.dedupe_key = None;
    let AgentDispatchOutcome::Dispatched(parent) = dispatcher.dispatch(req)? else {
        panic!("parent")
    };
    let queue = AttemptQueue::new(&vault);
    let parent_lease = claimed(&queue, 10)?;
    deliver(&queue, &parent_lease, "artifact:parent", 10)?;
    let id = EntityId::now();
    vault.save_workflow(
        &id,
        &WorkflowDefinition::new("live", vec![child, child])?,
        2,
    )?;
    let status = workflow(dispatcher.dispatch(request(
        AgentDispatchTarget::Workflow(id),
        Some(parent.attempt.id),
    ))?);
    let first = claimed(&queue, 11)?;
    let frozen = codec::record_dispatch_input(&first).unwrap();
    deliver(&queue, &first, "artifact:first", 12)?;
    let mut parent_def = vault.get_agent_definition(&parent_id)?.unwrap();
    parent_def.ceiling = AgentCeiling::Proposed;
    parent_def.version = "live-narrowed".to_owned();
    vault.update_agent_definition(
        &parent_id,
        &parent_def,
        TimeRange { start: 13, end: 13 },
        13,
    )?;
    let mut updated_child = vault.get_agent_definition(&child)?.unwrap();
    updated_child.version = "2.0.0".to_owned();
    vault.update_agent_definition(&child, &updated_child, TimeRange { start: 13, end: 13 }, 13)?;
    let WorkflowProgress::Advanced(next) = dispatcher.advance_workflow(status.attempt.id, 14)?
    else {
        panic!("advance")
    };
    let next = codec::record_dispatch_input(&queue.get(next)?.unwrap()).unwrap();
    assert_eq!(next.definition.version, frozen.definition.version);
    assert_eq!(
        vault
            .get_agent_definition(&next.target.agent_definition_ref()?)?
            .unwrap()
            .ceiling,
        AgentCeiling::Proposed
    );
    Ok(())
}

#[test]
fn typed_host_executes_both_saved_steps_and_never_replays_completed_callbacks() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let first = fixture(&vault, AgentCeiling::Proposed, "host-first")?;
    let second = fixture(&vault, AgentCeiling::Proposed, "host-second")?;
    let id = EntityId::now();
    vault.save_workflow(
        &id,
        &WorkflowDefinition::new("host", vec![first, second])?,
        2,
    )?;
    let dispatcher = AgentDispatcher::new(&vault);
    let root = workflow(dispatcher.dispatch(request(AgentDispatchTarget::Workflow(id), None))?)
        .attempt
        .id;
    let mut executed = Vec::new();
    let first_progress = dispatcher.run_workflow_step(root, "host-a", 11, |status, _context| {
        // A competing host cannot execute even this leaf, much less step two.
        assert_eq!(
            dispatcher
                .run_workflow_step(root, "host-b", 11, |_, _| panic!("leased leaf replayed"))?,
            WorkflowProgress::Waiting(status.attempt.id)
        );
        assert!(matches!(
            AttemptQueue::new(&vault).claim(ClaimAttempt {
                lease_owner: "other".into(),
                now: 11
            })?,
            ClaimOutcome::Empty
        ));
        executed.push(status.input.target.agent_definition_ref()?);
        AttemptResultRef::new("artifact:host-first")
    })?;
    assert!(matches!(first_progress, WorkflowProgress::Advanced(_)));
    assert_eq!(executed, vec![first]);
    assert_eq!(
        dispatcher.run_workflow_step(root, "host-a", 12, |status, _| {
            executed.push(status.input.target.agent_definition_ref()?);
            AttemptResultRef::new("artifact:host-second")
        })?,
        WorkflowProgress::Completed
    );
    assert_eq!(
        dispatcher.run_workflow_step(root, "host-b", 13, |_, _| panic!(
            "completed callback replayed"
        ))?,
        WorkflowProgress::Completed
    );
    assert_eq!(executed, vec![first, second]);
    assert_eq!(dispatcher.workflow_status(root)?.results.len(), 2);
    Ok(())
}
