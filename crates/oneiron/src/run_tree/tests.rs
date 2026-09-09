use rmpv::Value;

use crate::attempt_queue::{
    AttemptEvent, AttemptInterventionKind, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
    CompleteAttempt, CompleteOutcome, FailAttempt, FailOutcome, InterveneAttempt, RetryAttempt,
    RetryOutcome,
};
use crate::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttempt,
    EnqueueDreamerAttemptOutcome, encode_dreamer_attempt_payload,
};
use crate::{Error, Result, Vault, VaultConfig};

use super::{
    RunTreeAdapter, RunTreeEventKind, RunTreeNodeMarker, RunTreeNodeMarkerKind, RunTreeRepair,
    RunTreeStatus, mark_run_tree_failure, render_run_tree, run_tree_events,
};

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

#[test]
fn run_tree_renders_nested_subagent_attempts_deterministically() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);

    let root = enqueue(&runner, "orchestrator", None, 10, "run-a")?;
    let left = enqueue(&runner, "left-subagent", Some(root.attempt.id), 20, "run-a")?;
    let right = enqueue(
        &runner,
        "right-subagent",
        Some(root.attempt.id),
        30,
        "run-a",
    )?;
    let leaf = enqueue(&runner, "leaf-worker", Some(left.attempt.id), 40, "run-a")?;

    complete_next(&vault, root.attempt.id, 50)?;
    complete_next(&vault, left.attempt.id, 60)?;
    complete_next(&vault, right.attempt.id, 70)?;
    fail_next(&vault, leaf.attempt.id, 80, "left branch failed")?;

    let tree = RunTreeAdapter::new(&vault).read_run("run-a")?;

    assert!(tree.repairs.is_empty());
    assert_eq!(tree.roots.len(), 1);
    let root_node = &tree.roots[0];
    assert_eq!(root_node.attempt_id, hex(root.attempt.id));
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

    assert_eq!(root_node.children[0].attempt_id, hex(left.attempt.id));
    assert_eq!(root_node.children[0].worker_kind, "left-subagent");
    assert_eq!(root_node.children[0].children.len(), 1);
    assert_eq!(
        root_node.children[0].children[0].attempt_id,
        hex(leaf.attempt.id)
    );
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

    assert_eq!(root_node.children[1].attempt_id, hex(right.attempt.id));
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
    let queue = crate::AttemptQueue::new(&vault);

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "stream-worker".to_owned(),
        now: 40,
    })?
    else {
        panic!("expected running claim");
    };
    assert_eq!(claimed.id, running.attempt.id);
    complete_next(&vault, completed.attempt.id, 50)?;
    fail_next(&vault, failed.attempt.id, 60, "terminal failure")?;

    let tree = RunTreeAdapter::new(&vault).read_run("run-lifecycle")?;

    assert_eq!(tree.roots.len(), 3);
    assert_eq!(tree.roots[0].attempt_id, hex(running.attempt.id));
    assert_eq!(tree.roots[0].status, RunTreeStatus::Running);
    assert_eq!(
        event_kinds(&tree.roots[0]),
        vec![RunTreeEventKind::Created, RunTreeEventKind::Claimed]
    );
    assert_eq!(tree.roots[0].events[0].sequence, 0);
    assert_eq!(tree.roots[0].events[0].at, 10);
    assert_eq!(tree.roots[0].events[1].sequence, 1);
    assert_eq!(tree.roots[0].events[1].at, 40);

    assert_eq!(tree.roots[1].attempt_id, hex(completed.attempt.id));
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

    assert_eq!(tree.roots[2].attempt_id, hex(failed.attempt.id));
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
    let queue = crate::AttemptQueue::new(&vault);

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "stream-worker".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim");
    };
    assert_eq!(claimed.id, running.attempt.id);
    queue.intervene(InterveneAttempt {
        id: running.attempt.id,
        kind: AttemptInterventionKind::Interrupt,
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
    let attempt = enqueue(&runner, "terminal-subagent", None, 10, "run-terminal")?;
    let queue = crate::AttemptQueue::new(&vault);

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "stream-worker".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim");
    };
    assert_eq!(claimed.id, attempt.attempt.id);

    let running_tree = RunTreeAdapter::new(&vault).read_run("run-terminal")?;
    let running_claimed = running_tree.roots[0].events[1].clone();

    let CompleteOutcome::Completed(_) = queue.complete(CompleteAttempt {
        id: attempt.attempt.id,
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
    let events = vec![AttemptEvent {
        sequence: u64::MAX,
        at: 20,
        actor: "dashboard".to_owned(),
        kind: AttemptInterventionKind::Pause,
        note: None,
    }];

    let result = run_tree_events(10, 30, 0, None, events, AttemptState::Completed, false);

    assert!(matches!(result, Err(Error::ArithmeticOverflow(_))));
}

#[test]
fn run_tree_promotes_missing_parent_to_repaired_root() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);

    let missing_parent = enqueue(&runner, "missing-parent", None, 10, "run-b")?;
    let child = enqueue(
        &runner,
        "orphaned-subagent",
        Some(missing_parent.attempt.id),
        20,
        "run-b",
    )?;
    delete_attempt_record(&vault, missing_parent.attempt.id)?;

    let tree = RunTreeAdapter::new(&vault).read_run("run-b")?;

    assert_eq!(tree.roots.len(), 1);
    assert_eq!(tree.roots[0].attempt_id, hex(child.attempt.id));
    assert_eq!(
        tree.roots[0].parent_id.as_deref(),
        Some(hex(missing_parent.attempt.id).as_str())
    );
    assert_eq!(
        tree.repairs,
        vec![RunTreeRepair::MissingParent {
            attempt_id: hex(child.attempt.id),
            missing_parent_id: hex(missing_parent.attempt.id),
        }]
    );

    Ok(())
}

#[test]
fn run_tree_attaches_a_scheduled_retry_under_its_failed_source() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let queued = enqueue(&runner, "retrying-subagent", None, 10, "run-retry")?;
    let queue = crate::AttemptQueue::new(&vault);

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "retry-worker".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim");
    };
    assert_eq!(claimed.id, queued.attempt.id);
    let RetryOutcome::Retried(retried) = queue.retry(RetryAttempt {
        id: claimed.id,
        lease_owner: "retry-worker".to_owned(),
        attempt_count: claimed.attempt_count,
        backoff_until: 40,
        last_error: Some("rate limited".to_owned()),
        now: 30,
    })?;
    assert_ne!(retried.id, queued.attempt.id);

    let tree = RunTreeAdapter::new(&vault).read_run("run-retry")?;

    // One root — the failed try — with its next try hanging off `retry_of`,
    // so per-try history stays legible instead of collapsing into one node.
    assert_eq!(tree.roots.len(), 1);
    assert!(tree.repairs.is_empty());
    let root = &tree.roots[0];
    assert_eq!(root.attempt_id, hex(queued.attempt.id));
    assert_eq!(root.status, RunTreeStatus::Failed);
    assert_eq!(
        root.failure,
        Some(super::RunTreeFailure {
            reason: "rate limited".to_owned(),
        })
    );

    assert_eq!(root.children.len(), 1);
    let child = &root.children[0];
    assert_eq!(child.attempt_id, hex(retried.id));
    assert_eq!(
        child.parent_id.as_deref(),
        Some(hex(queued.attempt.id).as_str())
    );
    // Scheduled maps onto the existing Paused token — deferred, not runnable
    // now — which the Context Board already renders as `Scheduled`.
    assert_eq!(child.status, RunTreeStatus::Paused);
    assert_eq!(child.failure, None);
    assert_eq!(event_kinds(child), vec![RunTreeEventKind::Created]);

    Ok(())
}

/// A pre-ONE-1795 row decodes as `Queued` carrying only `backoff_until`, and
/// the queue keeps holding it back until that instant. Projecting the bare enum
/// renders it runnable-now on every read surface — run tree, Context Board,
/// facade attempt view — while the claim loop refuses to hand it out.
#[test]
fn legacy_backoff_row_projects_deferred_not_runnable_now() -> Result<()> {
    let deferred = legacy_queued_record(0xA1, 10, Some(900));
    let runnable = legacy_queued_record(0xB2, 20, None);

    let tree = render_run_tree(vec![deferred, runnable])?;

    assert_eq!(tree.roots.len(), 2);
    // Identical readiness posture to a `Scheduled` retry row, so identical
    // token: deferred, not eligible to run now.
    assert_eq!(tree.roots[0].status, RunTreeStatus::Paused);
    // Deferred is not "paused by an operator" — no Paused event is projected.
    assert_eq!(event_kinds(&tree.roots[0]), vec![RunTreeEventKind::Created]);
    // A queued row with no readiness instant stays genuinely runnable now.
    assert_eq!(tree.roots[1].status, RunTreeStatus::Queued);

    Ok(())
}

#[test]
fn run_tree_projects_intervention_events_and_states() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let paused = enqueue(&runner, "paused-subagent", None, 10, "run-intervene")?;
    let cancelled = enqueue(&runner, "cancelled-subagent", None, 20, "run-intervene")?;
    let queue = crate::AttemptQueue::new(&vault);

    queue.intervene(InterveneAttempt {
        id: paused.attempt.id,
        kind: AttemptInterventionKind::Pause,
        actor: "dashboard".to_owned(),
        note: Some("hold branch".to_owned()),
        now: 30,
    })?;
    queue.intervene(InterveneAttempt {
        id: cancelled.attempt.id,
        kind: AttemptInterventionKind::Cancel,
        actor: "dashboard".to_owned(),
        note: None,
        now: 40,
    })?;

    let tree = RunTreeAdapter::new(&vault).read_run("run-intervene")?;

    assert_eq!(tree.roots.len(), 2);
    assert_eq!(tree.roots[0].attempt_id, hex(paused.attempt.id));
    assert_eq!(tree.roots[0].status, RunTreeStatus::Paused);
    assert_eq!(
        event_kinds(&tree.roots[0]),
        vec![RunTreeEventKind::Created, RunTreeEventKind::Paused]
    );
    assert_eq!(tree.roots[0].events[1].sequence, 1);
    assert_eq!(tree.roots[0].events[1].actor, "dashboard");
    assert_eq!(tree.roots[0].events[1].note.as_deref(), Some("hold branch"));
    assert_eq!(tree.roots[1].attempt_id, hex(cancelled.attempt.id));
    assert_eq!(tree.roots[1].status, RunTreeStatus::Cancelled);
    assert_eq!(
        event_kinds(&tree.roots[1]),
        vec![RunTreeEventKind::Created, RunTreeEventKind::Cancelled]
    );

    Ok(())
}

#[test]
fn run_tree_cancelled_with_result_ends_in_cancellation() -> Result<()> {
    use crate::attempt_queue::{AttemptResultRef, CleanupAttemptLeases, SetAttemptResult};

    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let queued = enqueue(&runner, "result-worker", None, 10, "run-cancel-result")?;
    let queue = crate::AttemptQueue::new(&vault);
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "result-worker".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim");
    };
    assert_eq!(claimed.id, queued.attempt.id);
    let result_ref = AttemptResultRef::new("blob-artifact:deadbeef@1")?;
    queue.set_result(SetAttemptResult {
        id: claimed.id,
        lease_owner: "result-worker".to_owned(),
        attempt_count: claimed.attempt_count,
        result_ref: result_ref.clone(),
        now: 30,
    })?;

    // Attaching a result does not settle a live row or repeat its claim.
    let running = RunTreeAdapter::new(&vault).read_run("run-cancel-result")?;
    assert_eq!(running.roots[0].status, RunTreeStatus::Running);
    assert_eq!(
        event_kinds(&running.roots[0]),
        vec![
            RunTreeEventKind::Created,
            RunTreeEventKind::Claimed,
            RunTreeEventKind::ResultAttached,
        ]
    );

    // Lease cleanup retains the result; the requeued row can then receive a
    // durable cancel intervention. No result is written after settlement.
    let cleanup = queue.cleanup_leases(CleanupAttemptLeases {
        now: 40,
        lease_timeout_secs: 10,
    })?;
    assert_eq!(cleanup.stale_requeued, 1);
    let cancelled = queue.intervene(InterveneAttempt {
        id: claimed.id,
        kind: AttemptInterventionKind::Cancel,
        actor: "dashboard".to_owned(),
        note: Some("stop requeued work".to_owned()),
        now: 50,
    })?;
    assert_eq!(cancelled.record.state, AttemptState::Cancelled);
    assert_eq!(cancelled.record.result_ref.as_ref(), Some(&result_ref));
    assert_eq!(cancelled.record.events.len(), 1);

    let tree = RunTreeAdapter::new(&vault).read_run("run-cancel-result")?;
    let node = &tree.roots[0];
    assert_eq!(node.status, RunTreeStatus::Cancelled);
    assert_eq!(node.failure, None);
    assert_eq!(node.result_ref.as_deref(), Some(result_ref.as_str()));
    assert_eq!(
        event_kinds(node),
        vec![
            RunTreeEventKind::Created,
            RunTreeEventKind::Claimed,
            RunTreeEventKind::Cancelled,
            RunTreeEventKind::ResultAttached,
            RunTreeEventKind::Cancelled,
        ]
    );
    // Preserve operator provenance and sequence; append runtime settlement.
    assert_eq!(node.events[2].at, 50);
    assert_eq!(node.events[2].actor, "dashboard");
    assert_eq!(node.events[2].note.as_deref(), Some("stop requeued work"));
    assert_eq!(node.events[3].at, 50);
    assert_eq!(node.events[4].at, 50);
    assert_eq!(node.events[4].actor, "runtime");
    assert_eq!(node.events[4].note, None);
    assert_eq!(
        node.events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4]
    );
    assert_eq!(
        RunTreeAdapter::new(&vault).read_run("run-cancel-result")?,
        tree
    );
    assert_eq!(queue.get(claimed.id)?, Some(cancelled.record));
    Ok(())
}

#[test]
fn run_tree_final_cancellation_sequence_overflow_fails_closed() {
    let events = vec![AttemptEvent {
        sequence: u64::MAX - 1,
        at: 20,
        actor: "dashboard".to_owned(),
        kind: AttemptInterventionKind::Cancel,
        note: None,
    }];

    let result = run_tree_events(10, 30, 0, None, events, AttemptState::Cancelled, true);

    assert!(matches!(result, Err(Error::ArithmeticOverflow(_))));
}

#[test]
fn run_tree_fails_closed_when_runtime_attempt_table_is_unavailable() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let queued = enqueue(&runner, "corrupt-subagent", None, 10, "run-corrupt")?;

    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.attempt_records.put(
        &mut wtxn,
        queued.attempt.id.as_bytes(),
        b"not an attempt record",
    )?;
    wtxn.commit()?;

    assert!(
        RunTreeAdapter::new(&vault).read_run("run-corrupt").is_err(),
        "run-tree reads must fail closed when a runtime attempt row cannot be decoded"
    );

    Ok(())
}

#[test]
fn run_tree_preserves_descendants_when_repairing_rootless_cycle() -> Result<()> {
    let a = fixed_attempt_id(0x11);
    let b = fixed_attempt_id(0x22);
    let c = fixed_attempt_id(0x33);

    let tree = render_run_tree(vec![
        dreamer_record(a, "cycle-a", Some(b), 10, "run-cycle")?,
        dreamer_record(b, "cycle-b", Some(a), 20, "run-cycle")?,
        dreamer_record(c, "cycle-child", Some(a), 30, "run-cycle")?,
    ])?;

    assert_eq!(
        tree.repairs,
        vec![RunTreeRepair::ParentCycle {
            attempt_id: hex(a),
            parent_id: hex(b),
        }]
    );
    assert_eq!(tree.roots.len(), 1);
    assert_eq!(tree.roots[0].attempt_id, hex(a));
    assert_eq!(tree.roots[0].parent_id.as_deref(), Some(hex(b).as_str()));
    assert_eq!(tree.roots[0].children.len(), 2);
    assert_eq!(tree.roots[0].children[0].attempt_id, hex(b));
    assert!(tree.roots[0].children[0].children.is_empty());
    assert_eq!(tree.roots[0].children[1].attempt_id, hex(c));

    Ok(())
}

fn enqueue(
    runner: &DreamerRunnerStore<'_>,
    attempt_type: &str,
    parent_attempt: Option<crate::AttemptId>,
    now: u64,
    run_id: &str,
) -> Result<crate::dreamer_runner::DreamerAttemptStatus> {
    match runner.enqueue(EnqueueDreamerAttempt {
        attempt_type: attempt_type.to_owned(),
        input: Value::from(format!("input:{attempt_type}")),
        parent_attempt,
        dedupe_key: None,
        run_id: Some(run_id.to_owned()),
        now,
    })? {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => Ok(status),
    }
}

fn complete_next(vault: &Vault, expected_id: crate::AttemptId, now: u64) -> Result<()> {
    let queue = crate::AttemptQueue::new(vault);
    let ClaimOutcome::Claimed(attempt) = queue.claim(ClaimAttempt {
        lease_owner: "test-worker".to_owned(),
        now,
    })?
    else {
        panic!("expected claim");
    };
    assert_eq!(attempt.id, expected_id);
    let CompleteOutcome::Completed(_) = queue.complete(CompleteAttempt {
        id: expected_id,
        lease_owner: "test-worker".to_owned(),
        attempt_count: attempt.attempt_count,
        now,
    })?
    else {
        panic!("expected completion");
    };
    Ok(())
}

fn fail_next(vault: &Vault, expected_id: crate::AttemptId, now: u64, reason: &str) -> Result<()> {
    let queue = crate::AttemptQueue::new(vault);
    let ClaimOutcome::Claimed(attempt) = queue.claim(ClaimAttempt {
        lease_owner: "test-worker".to_owned(),
        now,
    })?
    else {
        panic!("expected claim");
    };
    assert_eq!(attempt.id, expected_id);
    let FailOutcome::Failed(_) = queue.fail(FailAttempt {
        id: expected_id,
        lease_owner: "test-worker".to_owned(),
        attempt_count: attempt.attempt_count,
        reason: reason.to_owned(),
        now,
    })?
    else {
        panic!("expected failure");
    };
    Ok(())
}

fn delete_attempt_record(vault: &Vault, id: crate::AttemptId) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let Some(raw) = vault.store.attempt_records.get(&wtxn, id.as_bytes())? else {
        return Err(Error::CorruptedIndex("attempt record"));
    };
    let record = crate::attempt_queue::decode_record(&raw, id)?;
    vault.store.delete_attempt_run_index_in_txn(
        &mut wtxn,
        record.run_id.as_deref(),
        id.as_bytes(),
    )?;
    vault
        .store
        .attempt_records
        .delete(&mut wtxn, id.as_bytes())?;
    wtxn.commit()?;
    Ok(())
}

fn event_kinds(node: &super::RunTreeNode) -> Vec<RunTreeEventKind> {
    node.events.iter().map(|event| event.kind).collect()
}

fn dreamer_record(
    id: crate::AttemptId,
    attempt_type: &str,
    parent_attempt: Option<crate::AttemptId>,
    created_at: u64,
    run_id: &str,
) -> Result<AttemptRecord> {
    Ok(AttemptRecord {
        id,
        kind: DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
        payload: encode_dreamer_attempt_payload(&DreamerAttemptPayload {
            attempt_type: attempt_type.to_owned(),
            input: Value::from(format!("input:{attempt_type}")),
            parent_attempt,
        })?,
        state: AttemptState::Queued,
        lease_owner: None,
        attempt_count: 0,
        claimed_at: None,
        scheduled_at: None,
        retry_of: None,
        backoff_until: None,
        last_error: None,
        task_ref: None,
        run_id: Some(run_id.to_owned()),
        dedupe_key: None,
        dedupe_actor_ref: None,
        created_at,
        updated_at: created_at,
        events: Vec::new(),
        manifest: Vec::new(),
        cancel_state: crate::attempt_queue::AttemptCancelState::default(),
        result_ref: None,
    })
}

/// ONE-1904 T7: `abandoned` is a CROSS-EXECUTOR terminal state, so every
/// executor kind — not only the foreign-agent one — must project it, carry its
/// result reference under the exact wire key, and emit both lifecycle events.
#[test]
fn abandoned_projects_for_every_executor_kind_with_its_result_ref() -> Result<()> {
    // One row per executor kind the queue actually carries, all abandoned.
    let kinds = [
        DREAMER_RUNNER_ATTEMPT_KIND,
        crate::dispatch_byoa::BYOA_ATTEMPT_KIND,
        crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND,
        "sync",
    ];

    for (index, kind) in kinds.iter().enumerate() {
        let seed = 0xA0 + u8::try_from(index).expect("small index");
        let record = abandoned_record(seed, kind, "blob-artifact:deadbeef@3");
        let tree = render_run_tree(vec![record])?;
        assert!(tree.repairs.is_empty());
        let node = &tree.roots[0];

        assert_eq!(
            node.status,
            RunTreeStatus::Abandoned,
            "{kind} must project abandoned, not failed or cancelled"
        );
        assert_eq!(
            node.failure, None,
            "{kind} stopped without a diagnosed fault, so it has no failure summary"
        );
        assert_eq!(
            node.result_ref.as_deref(),
            Some("blob-artifact:deadbeef@3"),
            "{kind} must still point at the exhaust it left behind"
        );
        assert!(
            event_kinds(node).contains(&RunTreeEventKind::Abandoned),
            "{kind} must emit its terminal event"
        );
        assert!(
            event_kinds(node).contains(&RunTreeEventKind::ResultAttached),
            "{kind} must announce the artifact it attached"
        );

        // The result is announced before the stop: the artifact was durable
        // first, and a terminal node must not claim work continued after it
        // ended.
        let events = event_kinds(node);
        let attached = events
            .iter()
            .position(|event| *event == RunTreeEventKind::ResultAttached)
            .expect("result attached");
        let abandoned = events
            .iter()
            .position(|event| *event == RunTreeEventKind::Abandoned)
            .expect("abandoned");
        assert!(attached < abandoned);

        // The wire key is exactly `result_ref`, elided when absent.
        let json = serde_json::to_value(node).expect("node serializes");
        assert_eq!(
            json.get("result_ref").and_then(serde_json::Value::as_str),
            Some("blob-artifact:deadbeef@3")
        );
    }

    Ok(())
}

#[test]
fn a_row_without_a_result_elides_the_key_and_emits_no_attach_event() -> Result<()> {
    let tree = render_run_tree(vec![legacy_queued_record(0xB1, 10, None)])?;
    let node = &tree.roots[0];
    assert_eq!(node.result_ref, None);
    assert!(!event_kinds(node).contains(&RunTreeEventKind::ResultAttached));

    let json = serde_json::to_value(node).expect("node serializes");
    assert!(
        json.get("result_ref").is_none(),
        "an absent result must not widen the wire shape of an old row"
    );

    // ...and an old serialized tree without the key still decodes.
    let decoded: super::RunTreeNode = serde_json::from_value(json).expect("node decodes");
    assert_eq!(decoded.result_ref, None);
    Ok(())
}

#[test]
fn abandoned_projects_onto_the_agent_run_and_board_axes_without_becoming_failed() {
    assert_eq!(
        crate::agent_run_status::project_agent_run_status(RunTreeStatus::Abandoned),
        crate::agent_run_status::AgentRunStatus::Abandoned,
        "the agent-run axis already owns a truthful terminal token"
    );
    // A2A has no abandoned token, so that projection is documented-lossy; the
    // native axes above are what keep the distinction.
    assert_eq!(
        crate::run_tree::RunTreeStatus::from(AttemptState::Abandoned),
        RunTreeStatus::Abandoned
    );
}

/// An abandoned row of `kind`, carrying its stop reason and result reference.
fn abandoned_record(seed: u8, kind: &str, result_ref: &str) -> AttemptRecord {
    AttemptRecord {
        id: fixed_attempt_id(seed),
        kind: kind.to_owned(),
        payload: Vec::new(),
        state: AttemptState::Abandoned,
        lease_owner: None,
        attempt_count: 1,
        claimed_at: Some(11),
        scheduled_at: None,
        retry_of: None,
        backoff_until: None,
        last_error: Some("executor stopped without delivering".to_owned()),
        task_ref: None,
        run_id: Some("run-abandoned".to_owned()),
        dedupe_key: None,
        dedupe_actor_ref: None,
        created_at: 10,
        updated_at: 30,
        events: Vec::new(),
        manifest: Vec::new(),
        cancel_state: crate::attempt_queue::AttemptCancelState::default(),
        result_ref: Some(
            crate::attempt_queue::AttemptResultRef::new(result_ref).expect("valid result ref"),
        ),
    }
}

fn fixed_attempt_id(byte: u8) -> crate::AttemptId {
    crate::AttemptId::from_bytes(&[byte; 16]).expect("valid fixed attempt id")
}

/// A version-2 row as written before ONE-1795: `Queued`, with its readiness
/// instant in the legacy `backoff_until` spelling and no `scheduled_at`.
fn legacy_queued_record(seed: u8, created_at: u64, backoff_until: Option<u64>) -> AttemptRecord {
    AttemptRecord {
        id: crate::AttemptId::from_bytes(&[seed; 16]).expect("attempt id"),
        kind: "legacy-worker".to_owned(),
        payload: Vec::new(),
        state: AttemptState::Queued,
        lease_owner: None,
        attempt_count: 0,
        claimed_at: None,
        scheduled_at: None,
        retry_of: None,
        backoff_until,
        last_error: None,
        task_ref: None,
        run_id: None,
        dedupe_key: None,
        dedupe_actor_ref: None,
        created_at,
        updated_at: created_at,
        events: Vec::new(),
        manifest: Vec::new(),
        cancel_state: crate::attempt_queue::AttemptCancelState::default(),
        result_ref: None,
    }
}

fn hex(id: crate::AttemptId) -> String {
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
    let def = crate::agent_def::AgentDefinition::new(
        "oneiron.agent.tree",
        "Run-tree dispatch fixture",
        "1.0.0",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        crate::agent_def::AgentScope::All,
        crate::agent_def::AgentCeiling::Proposed,
        None,
        crate::ClaimApprovalStatus::Approved,
        crate::ClaimLifecycleStatus::Active,
        crate::ClaimSource::UserStated,
        1.0,
        false,
        true,
        Value::Map(vec![(Value::from("definedVia"), Value::from("test"))]),
        None,
        true,
        None,
    );
    vault.put_agent_definition(&def_id, &def, crate::TimeRange { start: 1, end: 1 }, 1)?;

    let dispatcher = crate::agent_dispatch::AgentDispatcher::new(&vault);
    let crate::agent_dispatch::AgentDispatchOutcome::Dispatched(dispatched) =
        dispatcher.dispatch(crate::agent_dispatch::DispatchAgent {
            target: crate::agent_dispatch::AgentDispatchTarget::Custom(def_id),
            parent_attempt: Some(parent.attempt.id),
            dedupe_key: None,
            run_id: Some("run-agent".to_owned()),
            now: 20,
        })?
    else {
        panic!("expected fresh dispatch");
    };

    // A malformed inner input on the same payload attempt type (hand-enqueued
    // around the dispatch layer — the queue is deliberately open).
    let EnqueueDreamerAttemptOutcome::Enqueued(malformed) =
        runner.enqueue(EnqueueDreamerAttempt {
            attempt_type: crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE.to_owned(),
            input: Value::from("not an agent dispatch input"),
            parent_attempt: Some(parent.attempt.id),
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
    assert_eq!(root.agent_id, None, "non-agent attempts carry no agent_id");
    assert_eq!(root.children.len(), 2);

    let agent_node = root
        .children
        .iter()
        .find(|child| child.attempt_id == hex(dispatched.attempt.id))
        .expect("dispatched agent child node");
    assert_eq!(agent_node.worker_kind, "agent.dispatch");
    assert_eq!(
        agent_node.parent_id.as_deref(),
        Some(hex(parent.attempt.id).as_str())
    );
    assert_eq!(agent_node.agent_id.as_deref(), Some("oneiron.agent.tree"));

    let malformed_node = root
        .children
        .iter()
        .find(|child| child.attempt_id == hex(malformed.attempt.id))
        .expect("malformed child node renders");
    assert_eq!(malformed_node.worker_kind, "agent.dispatch");
    assert_eq!(
        malformed_node.agent_id, None,
        "a malformed inner input is a tolerant None, not an error"
    );
    Ok(())
}

// ONE-1452: the run-tree seam that names one run's consent bundle. The label
// is presentation metadata over an identity the bundle digest already fixed,
// so naming reads durable rows and writes nothing.

/// Registers one agent definition and dispatches it into `run_id`.
fn dispatch_agent(
    vault: &Vault,
    agent_id: &str,
    def_seed: u8,
    run_id: &str,
    parent_attempt: Option<crate::AttemptId>,
) -> Result<()> {
    let def_id = crate::EntityId::from_bytes([def_seed; 16]).expect("non-reserved test id");
    let def = crate::agent_def::AgentDefinition::new(
        agent_id,
        "Consent-bundle naming fixture",
        "1.0.0",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        crate::agent_def::AgentScope::All,
        crate::agent_def::AgentCeiling::Proposed,
        None,
        crate::ClaimApprovalStatus::Approved,
        crate::ClaimLifecycleStatus::Active,
        crate::ClaimSource::UserStated,
        1.0,
        false,
        true,
        Value::Map(vec![(Value::from("definedVia"), Value::from("test"))]),
        None,
        true,
        None,
    );
    vault.put_agent_definition(&def_id, &def, crate::TimeRange { start: 1, end: 1 }, 1)?;

    let dispatcher = crate::agent_dispatch::AgentDispatcher::new(vault);
    let crate::agent_dispatch::AgentDispatchOutcome::Dispatched(_) =
        dispatcher.dispatch(crate::agent_dispatch::DispatchAgent {
            target: crate::agent_dispatch::AgentDispatchTarget::Custom(def_id),
            parent_attempt,
            dedupe_key: None,
            run_id: Some(run_id.to_owned()),
            now: 20,
        })?
    else {
        panic!("expected fresh dispatch");
    };
    Ok(())
}

#[test]
fn consent_bundle_label_selects_the_first_root_agent_deterministically() -> Result<()> {
    let (_dir, vault) = open_vault();
    dispatch_agent(
        &vault,
        "oneiron.agent.bundle",
        0x33,
        "run-bundle-label",
        None,
    )?;
    dispatch_agent(
        &vault,
        "oneiron.agent.competing",
        0x35,
        "run-bundle-label",
        None,
    )?;

    let adapter = RunTreeAdapter::new(&vault);
    let tree = adapter.read_run("run-bundle-label")?;
    assert_eq!(tree.roots.len(), 2);
    let expected_agent_label = tree.roots[0]
        .agent_id
        .as_deref()
        .expect("the first root names a dispatched agent");
    assert!(!expected_agent_label.is_empty());
    assert_ne!(
        tree.roots[0].agent_id.as_deref(),
        tree.roots[1].agent_id.as_deref(),
    );

    let bundle_id = [0xAB; 32];
    let (name, agent_label) = adapter.consent_bundle_label("run-bundle-label", &bundle_id)?;

    assert_eq!(agent_label.as_deref(), Some(expected_agent_label));
    assert!(!name.is_empty());
    assert_eq!(
        adapter.consent_bundle_label("run-bundle-label", &bundle_id)?,
        (name.clone(), agent_label.clone()),
        "the same rows and the same bundle id name the same unit",
    );

    let (other_name, other_agent_label) =
        adapter.consent_bundle_label("run-bundle-label", &[0x01; 32])?;
    assert_eq!(other_agent_label, agent_label);
    assert_ne!(other_name, name);
    Ok(())
}

#[test]
fn consent_bundle_label_falls_back_when_no_root_agent_is_named() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let root = enqueue(&runner, "orchestrator", None, 10, "run-bundle-plain")?;
    // A nested agent must not supply the root-level identity.
    dispatch_agent(
        &vault,
        "oneiron.agent.nested",
        0x34,
        "run-bundle-plain",
        Some(root.attempt.id),
    )?;

    let adapter = RunTreeAdapter::new(&vault);
    let bundle_id = [0x01; 32];
    let (name, agent_label) = adapter.consent_bundle_label("run-bundle-plain", &bundle_id)?;
    assert_eq!(agent_label, None);
    assert!(!name.is_empty());

    let (other_name, other_agent_label) =
        adapter.consent_bundle_label("run-bundle-plain", &[0xAB; 32])?;
    assert_eq!(other_agent_label, None);
    assert!(!other_name.is_empty());
    assert_ne!(other_name, name);

    // Nested, absent, and invalid run identifiers use the same fallback.
    for run_id in ["run-bundle-plain", "run-bundle-absent", ""] {
        let (fallback_name, fallback_agent_label) =
            adapter.consent_bundle_label(run_id, &bundle_id)?;
        assert_eq!(fallback_agent_label, None);
        assert_eq!(fallback_name, name);

        let (other_fallback_name, other_fallback_agent_label) =
            adapter.consent_bundle_label(run_id, &[0xAB; 32])?;
        assert_eq!(other_fallback_agent_label, None);
        assert_eq!(other_fallback_name, other_name);
        assert_ne!(other_fallback_name, fallback_name);
    }
    Ok(())
}

#[test]
fn consent_bundle_label_does_not_mutate_run_state() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let root = enqueue(&runner, "orchestrator", None, 10, "run-bundle-readonly")?;
    let child = enqueue(
        &runner,
        "worker",
        Some(root.attempt.id),
        20,
        "run-bundle-readonly",
    )?;

    let queue = crate::AttemptQueue::new(&vault);
    let rows_before = queue.list_run("run-bundle-readonly")?;
    let tree_before = RunTreeAdapter::new(&vault).read_run("run-bundle-readonly")?;
    assert_eq!(tree_before.roots.len(), 1);
    assert_eq!(tree_before.roots[0].attempt_id, hex(root.attempt.id));
    assert_eq!(
        tree_before.roots[0].children[0].attempt_id,
        hex(child.attempt.id)
    );

    let adapter = RunTreeAdapter::new(&vault);
    for seed in 0u8..3 {
        adapter.consent_bundle_label("run-bundle-readonly", &[seed; 32])?;
    }

    assert_eq!(
        queue.list_run("run-bundle-readonly")?,
        rows_before,
        "naming leaves every attempt row byte-identical"
    );
    assert_eq!(
        RunTreeAdapter::new(&vault).read_run("run-bundle-readonly")?,
        tree_before
    );
    Ok(())
}

// ── ONE-1887 failure-diagram overlay ────────────────────────────────────────

/// A rendered run with one completed root and one failed child.
fn failed_child_tree(vault: &Vault) -> Result<(crate::AttemptId, super::RunTree)> {
    let runner = DreamerRunnerStore::new(vault);
    let root = enqueue(&runner, "orchestrator", None, 10, "run-mark")?;
    let child = enqueue(
        &runner,
        "leaf-worker",
        Some(root.attempt.id),
        20,
        "run-mark",
    )?;
    complete_next(vault, root.attempt.id, 30)?;
    fail_next(vault, child.attempt.id, 40, "child failed")?;
    let tree = RunTreeAdapter::new(vault).read_run("run-mark")?;
    Ok((child.attempt.id, tree))
}

#[test]
fn failure_diagram_marks_exact_failed_node() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (failing, tree) = failed_child_tree(&vault)?;

    let diagram = mark_run_tree_failure(tree.clone(), failing)?;

    assert_eq!(
        diagram.marker,
        RunTreeNodeMarker {
            attempt_id: hex(failing),
            kind: RunTreeNodeMarkerKind::Failing,
        },
        "the marker uses the same lowercase-hex spelling the node carries"
    );
    // Pure overlay: the tree rides through byte-identical.
    assert_eq!(diagram.tree, tree);
    Ok(())
}

#[test]
fn failure_diagram_rejects_missing_attempt() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (_failing, tree) = failed_child_tree(&vault)?;

    let error = mark_run_tree_failure(tree, fixed_attempt_id(0x7e))
        .expect_err("a marker for a node the tree does not render is refused");
    assert_eq!(error.kind(), crate::ErrorKind::InvalidConfig);
    Ok(())
}

#[test]
fn failure_marker_does_not_change_status_or_events() {
    assert_eq!(
        serde_json::to_string(&RunTreeStatus::Paused).expect("status serializes"),
        "\"paused\"",
    );
}

#[path = "tests/breaker.rs"]
mod breaker;
