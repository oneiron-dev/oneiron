use rmpv::Value;

use crate::dreamer_runner::{
    DREAMER_RUNNER_JOB_KIND, DreamerJobPayload, DreamerRunnerStore, EnqueueDreamerJob,
    EnqueueDreamerJobOutcome, encode_dreamer_job_payload,
};
use crate::job_queue::{
    ClaimJob, ClaimOutcome, CompleteJob, CompleteOutcome, FailJob, FailOutcome, InterveneJob,
    JobEvent, JobInterventionKind, JobRecord, JobState, RetryJob, RetryOutcome,
};
use crate::{Error, Result, Vault, VaultConfig};

use super::{
    RunTreeAdapter, RunTreeEventKind, RunTreeRepair, RunTreeStatus, render_run_tree,
    run_tree_events,
};

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

#[test]
fn run_tree_renders_nested_subagent_jobs_deterministically() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);

    let root = enqueue(&runner, "orchestrator", None, 10, "run-a")?;
    let left = enqueue(&runner, "left-subagent", Some(root.job.id), 20, "run-a")?;
    let right = enqueue(&runner, "right-subagent", Some(root.job.id), 30, "run-a")?;
    let leaf = enqueue(&runner, "leaf-worker", Some(left.job.id), 40, "run-a")?;

    complete_next(&vault, root.job.id, 50)?;
    complete_next(&vault, left.job.id, 60)?;
    complete_next(&vault, right.job.id, 70)?;
    fail_next(&vault, leaf.job.id, 80, "left branch failed")?;

    let tree = RunTreeAdapter::new(&vault).read_run("run-a")?;

    assert!(tree.repairs.is_empty());
    assert_eq!(tree.roots.len(), 1);
    let root_node = &tree.roots[0];
    assert_eq!(root_node.job_id, hex(root.job.id));
    assert_eq!(root_node.run_id.as_deref(), Some("run-a"));
    assert_eq!(root_node.parent_id, None);
    assert_eq!(root_node.worker_kind, "orchestrator");
    assert_eq!(root_node.status, RunTreeStatus::Completed);
    assert_eq!(
        event_kinds(root_node),
        vec![
            RunTreeEventKind::Created,
            RunTreeEventKind::Claimed,
            RunTreeEventKind::Completed,
        ]
    );
    assert_eq!(root_node.children.len(), 2);

    assert_eq!(root_node.children[0].job_id, hex(left.job.id));
    assert_eq!(root_node.children[0].worker_kind, "left-subagent");
    assert_eq!(root_node.children[0].children.len(), 1);
    assert_eq!(root_node.children[0].children[0].job_id, hex(leaf.job.id));
    assert_eq!(
        root_node.children[0].children[0]
            .failure
            .as_ref()
            .map(|failure| failure.reason.as_str()),
        Some("left branch failed")
    );
    assert_eq!(
        root_node.children[0].children[0].status,
        RunTreeStatus::Failed
    );
    assert_eq!(
        event_kinds(&root_node.children[0].children[0]),
        vec![
            RunTreeEventKind::Created,
            RunTreeEventKind::Claimed,
            RunTreeEventKind::Failed,
        ]
    );

    assert_eq!(root_node.children[1].job_id, hex(right.job.id));
    assert_eq!(root_node.children[1].worker_kind, "right-subagent");

    Ok(())
}

#[test]
fn run_tree_event_stream_reports_lifecycle_statuses() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let running = enqueue(&runner, "running-subagent", None, 10, "run-lifecycle")?;
    let completed = enqueue(&runner, "completed-subagent", None, 20, "run-lifecycle")?;
    let failed = enqueue(&runner, "failed-subagent", None, 30, "run-lifecycle")?;
    let queue = crate::JobQueue::new(&vault);

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
        lease_owner: "stream-worker".to_owned(),
        now: 40,
    })?
    else {
        panic!("expected running claim");
    };
    assert_eq!(claimed.id, running.job.id);
    complete_next(&vault, completed.job.id, 50)?;
    fail_next(&vault, failed.job.id, 60, "terminal failure")?;

    let tree = RunTreeAdapter::new(&vault).read_run("run-lifecycle")?;

    assert_eq!(tree.roots.len(), 3);
    assert_eq!(tree.roots[0].job_id, hex(running.job.id));
    assert_eq!(tree.roots[0].status, RunTreeStatus::Running);
    assert_eq!(
        event_kinds(&tree.roots[0]),
        vec![RunTreeEventKind::Created, RunTreeEventKind::Claimed]
    );
    assert_eq!(tree.roots[0].events[0].sequence, 0);
    assert_eq!(tree.roots[0].events[0].at, 10);
    assert_eq!(tree.roots[0].events[1].sequence, 1);
    assert_eq!(tree.roots[0].events[1].at, 40);

    assert_eq!(tree.roots[1].job_id, hex(completed.job.id));
    assert_eq!(tree.roots[1].status, RunTreeStatus::Completed);
    assert_eq!(
        event_kinds(&tree.roots[1]),
        vec![
            RunTreeEventKind::Created,
            RunTreeEventKind::Claimed,
            RunTreeEventKind::Completed,
        ]
    );
    assert_eq!(tree.roots[1].events[1].at, 50);
    assert_eq!(tree.roots[1].events[2].at, 50);

    assert_eq!(tree.roots[2].job_id, hex(failed.job.id));
    assert_eq!(tree.roots[2].status, RunTreeStatus::Failed);
    assert_eq!(
        event_kinds(&tree.roots[2]),
        vec![
            RunTreeEventKind::Created,
            RunTreeEventKind::Claimed,
            RunTreeEventKind::Failed,
        ]
    );
    assert_eq!(tree.roots[2].events[1].at, 60);
    assert_eq!(tree.roots[2].events[2].at, 60);

    Ok(())
}

#[test]
fn run_tree_orders_claimed_before_running_interrupts() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let running = enqueue(&runner, "interruptible-subagent", None, 10, "run-interrupt")?;
    let queue = crate::JobQueue::new(&vault);

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
        lease_owner: "stream-worker".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim");
    };
    assert_eq!(claimed.id, running.job.id);
    queue.intervene(InterveneJob {
        id: running.job.id,
        kind: JobInterventionKind::Interrupt,
        actor: "dashboard".to_owned(),
        note: Some("stop current tool call".to_owned()),
        now: 30,
    })?;

    let tree = RunTreeAdapter::new(&vault).read_run("run-interrupt")?;

    assert_eq!(tree.roots.len(), 1);
    assert_eq!(
        event_kinds(&tree.roots[0]),
        vec![
            RunTreeEventKind::Created,
            RunTreeEventKind::Claimed,
            RunTreeEventKind::Interrupted,
        ]
    );
    assert_eq!(tree.roots[0].events[1].sequence, 1);
    assert_eq!(tree.roots[0].events[1].at, 20);
    assert_eq!(tree.roots[0].events[2].sequence, 2);
    assert_eq!(tree.roots[0].events[2].at, 30);

    Ok(())
}

#[test]
fn run_tree_preserves_claimed_event_after_terminal_transition() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let job = enqueue(&runner, "terminal-subagent", None, 10, "run-terminal")?;
    let queue = crate::JobQueue::new(&vault);

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
        lease_owner: "stream-worker".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim");
    };
    assert_eq!(claimed.id, job.job.id);

    let running_tree = RunTreeAdapter::new(&vault).read_run("run-terminal")?;
    let running_claimed = running_tree.roots[0].events[1].clone();

    let CompleteOutcome::Completed(_) = queue.complete(CompleteJob {
        id: job.job.id,
        lease_owner: "stream-worker".to_owned(),
        attempt_count: claimed.attempt_count,
        now: 30,
    })?
    else {
        panic!("expected completion");
    };

    let completed_tree = RunTreeAdapter::new(&vault).read_run("run-terminal")?;

    assert_eq!(
        event_kinds(&completed_tree.roots[0]),
        vec![
            RunTreeEventKind::Created,
            RunTreeEventKind::Claimed,
            RunTreeEventKind::Completed,
        ]
    );
    assert_eq!(completed_tree.roots[0].events[1], running_claimed);
    assert_eq!(completed_tree.roots[0].events[2].sequence, 2);
    assert_eq!(completed_tree.roots[0].events[2].at, 30);

    Ok(())
}

#[test]
fn run_tree_event_sequence_overflow_fails_closed() {
    let events = vec![JobEvent {
        sequence: u64::MAX,
        at: 20,
        actor: "dashboard".to_owned(),
        kind: JobInterventionKind::Pause,
        note: None,
    }];

    let result = run_tree_events(10, 30, 0, None, events, JobState::Completed);

    assert!(matches!(
        result,
        Err(Error::ArithmeticOverflow("run-tree event sequence"))
    ));
}

#[test]
fn run_tree_promotes_missing_parent_to_repaired_root() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);

    let missing_parent = enqueue(&runner, "missing-parent", None, 10, "run-b")?;
    let child = enqueue(
        &runner,
        "orphaned-subagent",
        Some(missing_parent.job.id),
        20,
        "run-b",
    )?;
    delete_job_record(&vault, missing_parent.job.id)?;

    let tree = RunTreeAdapter::new(&vault).read_run("run-b")?;

    assert_eq!(tree.roots.len(), 1);
    assert_eq!(tree.roots[0].job_id, hex(child.job.id));
    assert_eq!(
        tree.roots[0].parent_id.as_deref(),
        Some(hex(missing_parent.job.id).as_str())
    );
    assert_eq!(
        tree.repairs,
        vec![RunTreeRepair::MissingParent {
            job_id: hex(child.job.id),
            missing_parent_id: hex(missing_parent.job.id),
        }]
    );

    Ok(())
}

#[test]
fn run_tree_omits_retry_last_error_until_terminal_failure() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let queued = enqueue(&runner, "retrying-subagent", None, 10, "run-retry")?;
    let queue = crate::JobQueue::new(&vault);

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
        lease_owner: "retry-worker".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim");
    };
    assert_eq!(claimed.id, queued.job.id);
    let RetryOutcome::Retried(_) = queue.retry(RetryJob {
        id: claimed.id,
        lease_owner: "retry-worker".to_owned(),
        attempt_count: claimed.attempt_count,
        backoff_until: 40,
        last_error: Some("rate limited".to_owned()),
        now: 30,
    })?;

    let tree = RunTreeAdapter::new(&vault).read_run("run-retry")?;

    assert_eq!(tree.roots.len(), 1);
    assert_eq!(tree.roots[0].status, RunTreeStatus::Queued);
    assert_eq!(tree.roots[0].failure, None);

    Ok(())
}

#[test]
fn run_tree_projects_intervention_events_and_states() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let paused = enqueue(&runner, "paused-subagent", None, 10, "run-intervene")?;
    let cancelled = enqueue(&runner, "cancelled-subagent", None, 20, "run-intervene")?;
    let queue = crate::JobQueue::new(&vault);

    queue.intervene(InterveneJob {
        id: paused.job.id,
        kind: JobInterventionKind::Pause,
        actor: "dashboard".to_owned(),
        note: Some("hold branch".to_owned()),
        now: 30,
    })?;
    queue.intervene(InterveneJob {
        id: cancelled.job.id,
        kind: JobInterventionKind::Cancel,
        actor: "dashboard".to_owned(),
        note: None,
        now: 40,
    })?;

    let tree = RunTreeAdapter::new(&vault).read_run("run-intervene")?;

    assert_eq!(tree.roots.len(), 2);
    assert_eq!(tree.roots[0].job_id, hex(paused.job.id));
    assert_eq!(tree.roots[0].status, RunTreeStatus::Paused);
    assert_eq!(
        event_kinds(&tree.roots[0]),
        vec![RunTreeEventKind::Created, RunTreeEventKind::Paused]
    );
    assert_eq!(tree.roots[0].events[1].sequence, 1);
    assert_eq!(tree.roots[0].events[1].actor, "dashboard");
    assert_eq!(tree.roots[0].events[1].note.as_deref(), Some("hold branch"));
    assert_eq!(tree.roots[1].job_id, hex(cancelled.job.id));
    assert_eq!(tree.roots[1].status, RunTreeStatus::Cancelled);
    assert_eq!(
        event_kinds(&tree.roots[1]),
        vec![RunTreeEventKind::Created, RunTreeEventKind::Cancelled]
    );

    Ok(())
}

#[test]
fn run_tree_fails_closed_when_runtime_job_table_is_unavailable() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let queued = enqueue(&runner, "corrupt-subagent", None, 10, "run-corrupt")?;

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .job_records
        .put(&mut wtxn, queued.job.id.as_bytes(), b"not a job record")?;
    wtxn.commit()?;

    assert!(
        RunTreeAdapter::new(&vault).read_run("run-corrupt").is_err(),
        "run-tree reads must fail closed when a runtime job row cannot be decoded"
    );

    Ok(())
}

#[test]
fn run_tree_preserves_descendants_when_repairing_rootless_cycle() -> Result<()> {
    let a = fixed_job_id(0x11);
    let b = fixed_job_id(0x22);
    let c = fixed_job_id(0x33);

    let tree = render_run_tree(vec![
        dreamer_record(a, "cycle-a", Some(b), 10, "run-cycle")?,
        dreamer_record(b, "cycle-b", Some(a), 20, "run-cycle")?,
        dreamer_record(c, "cycle-child", Some(a), 30, "run-cycle")?,
    ])?;

    assert_eq!(
        tree.repairs,
        vec![RunTreeRepair::ParentCycle {
            job_id: hex(a),
            parent_id: hex(b),
        }]
    );
    assert_eq!(tree.roots.len(), 1);
    assert_eq!(tree.roots[0].job_id, hex(a));
    assert_eq!(tree.roots[0].parent_id.as_deref(), Some(hex(b).as_str()));
    assert_eq!(tree.roots[0].children.len(), 2);
    assert_eq!(tree.roots[0].children[0].job_id, hex(b));
    assert!(tree.roots[0].children[0].children.is_empty());
    assert_eq!(tree.roots[0].children[1].job_id, hex(c));

    Ok(())
}

fn enqueue(
    runner: &DreamerRunnerStore<'_>,
    job_type: &str,
    parent_job: Option<crate::JobId>,
    now: u64,
    run_id: &str,
) -> Result<crate::DreamerJobStatus> {
    match runner.enqueue(EnqueueDreamerJob {
        job_type: job_type.to_owned(),
        input: Value::from(format!("input:{job_type}")),
        parent_job,
        dedupe_key: None,
        run_id: Some(run_id.to_owned()),
        now,
    })? {
        EnqueueDreamerJobOutcome::Enqueued(status) | EnqueueDreamerJobOutcome::Existing(status) => {
            Ok(status)
        }
    }
}

fn complete_next(vault: &Vault, expected_id: crate::JobId, now: u64) -> Result<()> {
    let queue = crate::JobQueue::new(vault);
    let ClaimOutcome::Claimed(job) = queue.claim(ClaimJob {
        lease_owner: "test-worker".to_owned(),
        now,
    })?
    else {
        panic!("expected claim");
    };
    assert_eq!(job.id, expected_id);
    let CompleteOutcome::Completed(_) = queue.complete(CompleteJob {
        id: expected_id,
        lease_owner: "test-worker".to_owned(),
        attempt_count: job.attempt_count,
        now,
    })?
    else {
        panic!("expected completion");
    };
    Ok(())
}

fn fail_next(vault: &Vault, expected_id: crate::JobId, now: u64, reason: &str) -> Result<()> {
    let queue = crate::JobQueue::new(vault);
    let ClaimOutcome::Claimed(job) = queue.claim(ClaimJob {
        lease_owner: "test-worker".to_owned(),
        now,
    })?
    else {
        panic!("expected claim");
    };
    assert_eq!(job.id, expected_id);
    let FailOutcome::Failed(_) = queue.fail(FailJob {
        id: expected_id,
        lease_owner: "test-worker".to_owned(),
        attempt_count: job.attempt_count,
        reason: reason.to_owned(),
        now,
    })?
    else {
        panic!("expected failure");
    };
    Ok(())
}

fn delete_job_record(vault: &Vault, id: crate::JobId) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.job_records.delete(&mut wtxn, id.as_bytes())?;
    wtxn.commit()?;
    Ok(())
}

fn event_kinds(node: &super::RunTreeNode) -> Vec<RunTreeEventKind> {
    node.events.iter().map(|event| event.kind).collect()
}

fn dreamer_record(
    id: crate::JobId,
    job_type: &str,
    parent_job: Option<crate::JobId>,
    created_at: u64,
    run_id: &str,
) -> Result<JobRecord> {
    Ok(JobRecord {
        id,
        kind: DREAMER_RUNNER_JOB_KIND.to_owned(),
        payload: encode_dreamer_job_payload(&DreamerJobPayload {
            job_type: job_type.to_owned(),
            input: Value::from(format!("input:{job_type}")),
            parent_job,
        })?,
        state: JobState::Queued,
        lease_owner: None,
        attempt_count: 0,
        claimed_at: None,
        backoff_until: None,
        last_error: None,
        run_id: Some(run_id.to_owned()),
        dedupe_key: None,
        created_at,
        updated_at: created_at,
        events: Vec::new(),
    })
}

fn fixed_job_id(byte: u8) -> crate::JobId {
    crate::JobId::from_bytes(&[byte; 16]).expect("valid fixed job id")
}

fn hex(id: crate::JobId) -> String {
    crate::entity_id::bytes_to_hex_lower(id.as_bytes())
}

// AGENT-3 (ONE-1445) AC test 8: an agent dispatch renders as a child node of
// its parent with `worker_kind == "agent.dispatch"` and the definition's
// agent_id; a malformed inner input degrades to `agent_id: None` without
// killing the tree render.
#[test]
fn run_tree_renders_agent_branch() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let parent = enqueue(&runner, "orchestrator", None, 10, "run-agent")?;

    let def_id = crate::EntityId::from_bytes([0x31; 16]).expect("non-reserved test id");
    let def = crate::AgentDefinition::new(
        "eiri.agent.tree",
        "Run-tree dispatch fixture",
        "1.0.0",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        crate::AgentScope::All,
        crate::AgentCeiling::Proposed,
        None,
        crate::ClaimApprovalStatus::Approved,
        crate::ClaimLifecycleStatus::Active,
        crate::ClaimSource::UserStated,
        1.0,
        false,
        true,
        Value::Map(vec![(Value::from("definedVia"), Value::from("test"))]),
    );
    vault.put_agent_definition(&def_id, &def, crate::TimeRange { start: 1, end: 1 }, 1)?;

    let dispatcher = crate::AgentDispatcher::new(&vault);
    let crate::AgentDispatchOutcome::Dispatched(dispatched) =
        dispatcher.dispatch(crate::DispatchAgent {
            target: crate::AgentDispatchTarget::Custom(def_id),
            parent_job: Some(parent.job.id),
            dedupe_key: None,
            run_id: Some("run-agent".to_owned()),
            now: 20,
        })?
    else {
        panic!("expected fresh dispatch");
    };

    // A malformed inner input on the same payload job type (hand-enqueued
    // around the dispatch layer — the queue is deliberately open).
    let EnqueueDreamerJobOutcome::Enqueued(malformed) = runner.enqueue(EnqueueDreamerJob {
        job_type: crate::AGENT_DISPATCH_JOB_TYPE.to_owned(),
        input: Value::from("not an agent dispatch input"),
        parent_job: Some(parent.job.id),
        dedupe_key: None,
        run_id: Some("run-agent".to_owned()),
        now: 30,
    })?
    else {
        panic!("expected fresh enqueue");
    };

    let tree = RunTreeAdapter::new(&vault).read_run("run-agent")?;
    assert!(tree.repairs.is_empty());
    assert_eq!(tree.roots.len(), 1);
    let root = &tree.roots[0];
    assert_eq!(root.agent_id, None, "non-agent jobs carry no agent_id");
    assert_eq!(root.children.len(), 2);

    let agent_node = root
        .children
        .iter()
        .find(|child| child.job_id == hex(dispatched.job.id))
        .expect("dispatched agent child node");
    assert_eq!(agent_node.worker_kind, "agent.dispatch");
    assert_eq!(
        agent_node.parent_id.as_deref(),
        Some(hex(parent.job.id).as_str())
    );
    assert_eq!(agent_node.agent_id.as_deref(), Some("eiri.agent.tree"));

    let malformed_node = root
        .children
        .iter()
        .find(|child| child.job_id == hex(malformed.job.id))
        .expect("malformed child node renders");
    assert_eq!(malformed_node.worker_kind, "agent.dispatch");
    assert_eq!(
        malformed_node.agent_id, None,
        "a malformed inner input is a tolerant None, not an error"
    );
    Ok(())
}
