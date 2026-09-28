//! Headless saved-workflow execution and authority regressions.

use super::*;
use crate::agent_def::{AgentCeiling, workflow::WorkflowDefinition};
use crate::attempt_queue::{
    AttemptPlacement, AttemptRecord, AttemptResultRef, ClaimAttempt, ClaimOutcome,
    CleanupAttemptLeases, CompleteAttempt, RetryAttempt, SetAttemptResult,
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

#[test]
fn workflow_agent_output_is_durable_and_only_a_handle_enters_results() -> Result<()> {
    use crate::compaction::output::{OutputRef, restore_output};

    let (dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let agent = fixture(&vault, AgentCeiling::Proposed, "raw-output")?;
    let id = EntityId::now();
    vault.save_workflow(&id, &WorkflowDefinition::new("raw", vec![agent])?, 2)?;
    let dispatcher = AgentDispatcher::new(&vault);
    let root = workflow(dispatcher.dispatch(request(AgentDispatchTarget::Workflow(id), None))?)
        .attempt
        .id;
    let raw = b"agent\0result\xff with exact bytes";
    assert_eq!(
        dispatcher.run_workflow_step_output(root, "host-a", 11, |_, _| Ok(raw.to_vec()))?,
        WorkflowProgress::Completed
    );
    let report = dispatcher.workflow_status(root)?;
    assert_eq!(report.results.len(), 1);
    let handle = &report.results[0].result_ref;
    assert!(handle.starts_with("output:blake3:"));
    assert!(!handle.contains("agent"));
    let source = OutputRef::from_handle(handle)?;
    assert_eq!(restore_output(&vault, source)?, raw);
    assert_eq!(
        dispatcher.run_workflow_step_output(root, "host-a", 12, |_, _| panic!("replayed"))?,
        WorkflowProgress::Completed
    );
    drop(vault);
    let reopened = Vault::open(dir.path(), VaultConfig::default())?;
    let handle = &AgentDispatcher::new(&reopened)
        .workflow_status(root)?
        .results[0]
        .result_ref;
    assert_eq!(
        restore_output(&reopened, OutputRef::from_handle(handle)?)?,
        raw
    );
    Ok(())
}

#[test]
fn successor_receives_prior_raw_output_handle_after_reopen() -> Result<()> {
    use crate::compaction::output::{OutputRef, restore_output};

    let (dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let agent = fixture(&vault, AgentCeiling::Proposed, "handoff")?;
    let workflow_id = EntityId::now();
    vault.save_workflow(
        &workflow_id,
        &WorkflowDefinition::new("handoff", vec![agent, agent])?,
        2,
    )?;
    let dispatcher = AgentDispatcher::new(&vault);
    let root =
        workflow(dispatcher.dispatch(request(AgentDispatchTarget::Workflow(workflow_id), None))?)
            .attempt
            .id;
    let raw = b"tool\0and agent\xff full output";
    let mut initial = None;
    assert!(matches!(
        dispatcher.run_workflow_step_output(root, "host-a", 11, |_, context| {
            assert!(context.workflow_output_refs.is_empty());
            initial = Some(context);
            Ok(raw.to_vec())
        })?,
        WorkflowProgress::Advanced(_)
    ));
    let report = dispatcher.workflow_status(root)?;
    let source = OutputRef::from_handle(&report.results[0].result_ref)?;
    let producer = report.results[0].attempt_id;
    let next = report.active_step;
    drop(vault);

    let reopened = Vault::open(dir.path(), VaultConfig::default())?;
    let dispatcher = AgentDispatcher::new(&reopened);
    // Context assembly must be read-only even when the owner is already
    // composing another workflow write in this process.
    let writer = reopened.store.env.write_txn()?;
    let projected = dispatcher.resolve_attempt_context(next)?;
    drop(writer);
    assert_eq!(projected.workflow_output_refs.len(), 1);
    let carried = projected.workflow_output_refs[0];
    assert_eq!(carried.step_ordinal, 0);
    assert_eq!(carried.producing_attempt, producer);
    assert_eq!(carried.source, source);
    assert_eq!(restore_output(&reopened, carried.source)?, raw);
    let original = initial.expect("first callback context");
    assert_eq!(projected.memory_sections, original.memory_sections);
    assert_eq!(projected.chat_sections, original.chat_sections);
    assert_eq!(projected.layers, original.layers);
    assert_eq!(projected.sibling_result_refs, original.sibling_result_refs);
    assert_eq!(projected.briefing, original.briefing);
    assert_eq!(
        dispatcher.run_workflow_step_output(root, "host-b", 12, |_, context| {
            assert_eq!(context, projected);
            assert_eq!(
                restore_output(&reopened, context.workflow_output_refs[0].source)?,
                raw
            );
            Ok(b"second result".to_vec())
        })?,
        WorkflowProgress::Completed
    );
    assert_eq!(dispatcher.workflow_status(root)?.results.len(), 2);
    Ok(())
}

#[test]
fn a_redirected_workflow_leaf_is_not_claimed_by_its_old_host() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let first = fixture(&vault, AgentCeiling::Proposed, "redirect-first")?;
    let second = fixture(&vault, AgentCeiling::Proposed, "redirect-second")?;
    let id = EntityId::now();
    vault.save_workflow(
        &id,
        &WorkflowDefinition::new("redirect", vec![first, second])?,
        2,
    )?;
    let dispatcher = AgentDispatcher::new(&vault);
    let status = workflow(dispatcher.dispatch(request(AgentDispatchTarget::Workflow(id), None))?);
    let (root, leaf) = (status.attempt.id, status.active_step);
    let queue = AttemptQueue::new(&vault);
    queue.redirect(
        InterveneAttempt {
            id: leaf,
            kind: AttemptInterventionKind::Redirect,
            actor: "operator".into(),
            note: None,
            now: 11,
        },
        AttemptPlacement {
            parent: Some(root),
            worker: Some("host-b".into()),
        },
    )?;
    assert_eq!(
        dispatcher.run_workflow_step(root, "host-a", 12, |_, _| panic!(
            "the old host ran a redirected leaf"
        ))?,
        WorkflowProgress::Waiting(leaf)
    );
    let queued = queue.get(leaf)?.expect("leaf");
    assert_eq!(queued.state, AttemptState::Queued);
    assert_eq!(queued.lease_owner, None);
    assert_eq!(
        queued.placement.and_then(|placement| placement.worker),
        Some("host-b".to_owned())
    );
    let progress = dispatcher.run_workflow_step(root, "host-b", 13, |status, _| {
        assert_eq!(status.attempt.id, leaf);
        assert_eq!(status.attempt.lease_owner.as_deref(), Some("host-b"));
        AttemptResultRef::new("artifact:redirected")
    })?;
    assert!(matches!(progress, WorkflowProgress::Advanced(_)));
    Ok(())
}

#[test]
fn a_workflow_point_claim_stamps_the_recorded_clock() -> Result<()> {
    let clock = crate::ports::ManualClock::new(100);
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig {
        store_clock: clock.bundle(),
        ..VaultConfig::default()
    });
    let first = fixture(&vault, AgentCeiling::Proposed, "clock-first")?;
    let second = fixture(&vault, AgentCeiling::Proposed, "clock-second")?;
    let id = EntityId::now();
    vault.save_workflow(
        &id,
        &WorkflowDefinition::new("clock", vec![first, second])?,
        2,
    )?;
    let dispatcher = AgentDispatcher::new(&vault);
    let status = workflow(dispatcher.dispatch(request(AgentDispatchTarget::Workflow(id), None))?);
    let (root, leaf) = (status.attempt.id, status.active_step);
    // A host whose clock runs far ahead stops mid-step and leaves its lease.
    let stopped = dispatcher.run_workflow_step(root, "host-a", 1_000_000, |_, _| {
        Err(Error::InvariantViolation("host stopped mid-step"))
    });
    assert!(stopped.is_err());
    let queue = AttemptQueue::new(&vault);
    let leased = queue.get(leaf)?.expect("leaf");
    assert_eq!(leased.state, AttemptState::Leased);
    assert_eq!(leased.lease_owner.as_deref(), Some("host-a"));
    assert_eq!(leased.updated_at, 100);
    assert_eq!(leased.claimed_at, Some(100));
    let cleanup = |now| {
        queue.cleanup_leases(CleanupAttemptLeases {
            now,
            lease_timeout_secs: 30,
        })
    };
    assert_eq!(cleanup(129)?.stale_requeued, 0);
    assert_eq!(cleanup(130)?.stale_requeued, 1);
    assert_eq!(queue.get(leaf)?.expect("leaf").state, AttemptState::Queued);
    Ok(())
}

#[test]
fn workflow_child_project_transition_and_later_release_recheck_live_ancestor() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let agent = fixture(&vault, AgentCeiling::Proposed, "project-workflow")?;
    let root = vault.root_project()?;
    let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
    let child = EntityId::now();
    vault.put_project(
        child,
        &crate::workspace_roster::ProjectRecord::new(child, Some(root), root, leader),
        1,
    )?;
    let person = EntityId::now();
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let writer = crate::write_envelope::WriteActor::new(person, EdgeActorClass::Human);
    crate::subject_model::tests::authorization::root_owner(&vault, writer, 0xA8)?;
    let dispatcher = AgentDispatcher::new(&vault);
    let mut initial = request(AgentDispatchTarget::Custom(agent), None);
    initial.dedupe_key = None;
    let AgentDispatchOutcome::Dispatched(parent) = dispatcher.dispatch(initial)? else {
        panic!("parent")
    };
    let parent_lease = claimed(&AttemptQueue::new(&vault), 11)?;
    assert_eq!(parent_lease.id, parent.attempt.id);
    deliver(
        &AttemptQueue::new(&vault),
        &parent_lease,
        "project:parent",
        12,
    )?;
    let workflow_id = EntityId::now();
    vault.save_workflow(
        &workflow_id,
        &WorkflowDefinition::new("project-depth", vec![agent, agent])?,
        2,
    )?;
    let input = request(
        AgentDispatchTarget::Workflow(workflow_id),
        Some(parent.attempt.id),
    );
    let spawn = AgentSpawnContext::default().with_project(child);
    crate::workspace_roster::set_project_depth_signed_for_test(&vault, root, 0, &writer, 3, 0xA8)?;
    assert_eq!(
        dispatcher
            .dispatch_with_context(input.clone(), spawn.clone())
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::InvalidAgentDispatchInput
    );
    crate::workspace_roster::set_project_depth_signed_for_test(&vault, root, 2, &writer, 4, 0xA8)?;
    let status = workflow(dispatcher.dispatch_with_context(input.clone(), spawn.clone())?);
    let first = AttemptQueue::new(&vault).get(status.active_step)?.unwrap();
    assert_eq!(
        codec::record_dispatch_input(&first)
            .unwrap()
            .depth_remaining,
        Some(1)
    );
    let queued = AttemptQueue::new(&vault).list()?.len();
    crate::workspace_roster::set_project_depth_signed_for_test(&vault, root, 0, &writer, 5, 0xA8)?;
    assert_eq!(
        workflow(dispatcher.dispatch_with_context(input, spawn)?)
            .attempt
            .id,
        status.attempt.id,
        "identical workflow retry does not re-admit at live depth zero"
    );
    let first = claimed(&AttemptQueue::new(&vault), 21)?;
    assert_eq!(first.id, status.active_step);
    deliver(&AttemptQueue::new(&vault), &first, "project:first", 22)?;
    assert_eq!(
        dispatcher
            .advance_workflow(status.attempt.id, 23)
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::InvalidAgentDispatchInput
    );
    assert_eq!(AttemptQueue::new(&vault).list()?.len(), queued);
    Ok(())
}

#[test]
fn real_workflow_leaves_can_spawn_and_wrapper_costs_no_depth() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let agent = fixture(&vault, AgentCeiling::Proposed, "positive-depth-leaf")?;
    let id = EntityId::now();
    vault.save_workflow(&id, &WorkflowDefinition::new("spawn", vec![agent])?, 1)?;
    let dispatcher = AgentDispatcher::new(&vault);
    let root = workflow(dispatcher.dispatch(request(AgentDispatchTarget::Workflow(id), None))?);
    assert_eq!(dispatcher.child_depth_remaining(root.active_step)?, 9);
    let child = dispatcher.dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(agent),
        parent_attempt: Some(root.active_step),
        dedupe_key: None,
        run_id: Some("workflow-headless".into()),
        now: 11,
    })?;
    let AgentDispatchOutcome::Dispatched(child) = child else {
        panic!("root workflow leaf spawned")
    };
    assert_eq!(child.input.depth_remaining, Some(9));
    assert!(
        dispatcher
            .dispatch(DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: Some(root.attempt.id),
                dedupe_key: None,
                run_id: None,
                now: 11,
            })
            .is_err(),
        "wrapper is never a direct spawner"
    );

    let parent = dispatcher.dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(agent),
        parent_attempt: None,
        dedupe_key: None,
        run_id: Some("parented-run".into()),
        now: 12,
    })?;
    let AgentDispatchOutcome::Dispatched(parent) = parent else {
        panic!("parent")
    };
    let mut req = request(AgentDispatchTarget::Workflow(id), Some(parent.attempt.id));
    req.dedupe_key = Some("parented-workflow".into());
    req.run_id = Some("parented-run".into());
    let parented = workflow(dispatcher.dispatch(req)?);
    assert_eq!(dispatcher.child_depth_remaining(parented.active_step)?, 8);
    let branch = dispatcher.dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(agent),
        parent_attempt: Some(parented.active_step),
        dedupe_key: None,
        run_id: Some("parented-run".into()),
        now: 13,
    })?;
    let AgentDispatchOutcome::Dispatched(branch) = branch else {
        panic!("parented workflow leaf spawned")
    };
    assert_eq!(branch.input.depth_remaining, Some(8));

    let person = EntityId::now();
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let owner = crate::write_envelope::WriteActor::new(person, EdgeActorClass::Human);
    crate::subject_model::tests::authorization::root_owner(&vault, owner, 0xAA)?;
    crate::workspace_roster::set_project_depth_signed_for_test(
        &vault,
        vault.root_project()?,
        0,
        &owner,
        14,
        0xAA,
    )?;
    assert!(dispatcher.child_depth_remaining(root.active_step).is_err());
    assert!(
        dispatcher
            .child_depth_remaining(parented.active_step)
            .is_err()
    );
    Ok(())
}
