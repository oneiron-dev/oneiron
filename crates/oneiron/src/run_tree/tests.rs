use rmpv::Value;

use crate::attempt_queue::{
    AttemptInterventionKind, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
    CompleteAttempt, CompleteOutcome, InterveneAttempt,
};
use crate::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttempt,
    EnqueueDreamerAttemptOutcome, encode_dreamer_attempt_payload,
};
use crate::{Result, Vault, VaultConfig};

use super::{RunTreeAdapter, RunTreeEventKind, RunTreeRepair, RunTreeStatus, render_run_tree};

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

#[test]
fn run_tree_orders_claimed_before_running_interrupts() -> Result<()> {
    let clock = crate::ports::ManualClock::new(10);
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig {
        store_clock: clock.bundle(),
        ..VaultConfig::device()
    });
    let runner = DreamerRunnerStore::new(&vault);
    let running = enqueue(&runner, "interruptible-subagent", None, 10, "run-interrupt")?;
    let queue = crate::AttemptQueue::new(&vault);

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "stream-worker".to_owned(),
        now: {
            clock.set(20);
            20
        },
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
        now: {
            clock.set(30);
            30
        },
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
    let clock = crate::ports::ManualClock::new(10);
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig {
        store_clock: clock.bundle(),
        ..VaultConfig::device()
    });
    let runner = DreamerRunnerStore::new(&vault);
    let attempt = enqueue(&runner, "terminal-subagent", None, 10, "run-terminal")?;
    let queue = crate::AttemptQueue::new(&vault);

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "stream-worker".to_owned(),
        now: {
            clock.set(20);
            20
        },
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
        now: {
            clock.set(30);
            30
        },
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
        folded_retries: 0,
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
        executor_model: None,
        cancel_state: crate::attempt_queue::AttemptCancelState::default(),
        signals: Vec::new(),
        asks: Vec::new(),
        placement: None,
        result_ref: None,
    })
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
        folded_retries: 0,
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
        executor_model: None,
        cancel_state: crate::attempt_queue::AttemptCancelState::default(),
        signals: Vec::new(),
        asks: Vec::new(),
        placement: None,
        result_ref: None,
    }
}

fn hex(id: crate::AttemptId) -> String {
    crate::entity_id::bytes_to_hex_lower(id.as_bytes())
}

// ONE-1452: the run-tree seam that names one run's consent bundle. The label
// is presentation metadata over an identity the bundle digest already fixed,
// so naming reads durable rows and writes nothing.

// ── ONE-2030 branch Signal safe breakpoints ────────────────────────────────

#[test]
fn branch_signal_interject_is_isolated_and_acknowledged_replay_is_cached() -> Result<()> {
    use super::{RunSignalInput, RunSignalKind, RunSignalState};
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let root = enqueue(&runner, "root", None, 1, "run-signal")?;
    let left = enqueue(&runner, "left", Some(root.attempt.id), 2, "run-signal")?;
    let right = enqueue(&runner, "right", Some(root.attempt.id), 3, "run-signal")?;
    let queue = crate::AttemptQueue::new(&vault);
    let mut claimed = Vec::new();
    for id in [root.attempt.id, left.attempt.id, right.attempt.id] {
        let ClaimOutcome::Claimed(row) = queue.claim(ClaimAttempt {
            lease_owner: "signal-worker".into(),
            now: 10,
        })?
        else {
            panic!("expected claimed branch");
        };
        assert_eq!(row.id, id);
        claimed.push(row);
    }
    let adapter = RunTreeAdapter::new(&vault);
    let input = RunSignalInput {
        branch: left.attempt.id,
        run_id: "run-signal".into(),
        key: "effect-7".into(),
        actor: "operator".into(),
        kind: RunSignalKind::Interject {
            content: "new context".into(),
        },
    };
    let pending = adapter.signal(input.clone())?;
    assert_eq!(pending.state, RunSignalState::Pending);
    assert!(
        adapter
            .breakpoint(
                right.attempt.id,
                "run-signal",
                "signal-worker",
                claimed[2].attempt_count
            )?
            .is_empty()
    );
    assert_eq!(adapter.signal(input.clone())?, pending);
    assert_eq!(
        adapter
            .breakpoint(
                left.attempt.id,
                "run-signal",
                "signal-worker",
                claimed[1].attempt_count
            )?
            .len(),
        1
    );
    assert_eq!(
        adapter.signal(input.clone())?.state,
        RunSignalState::Pending
    );
    assert_eq!(
        adapter.breakpoint(
            left.attempt.id,
            "run-signal",
            "signal-worker",
            claimed[1].attempt_count
        )?,
        vec![pending]
    );
    let settled = adapter.acknowledge_signal(
        left.attempt.id,
        "run-signal",
        "signal-worker",
        claimed[1].attempt_count,
        "effect-7",
    )?;
    assert_eq!(settled.state, RunSignalState::Settled);
    assert_eq!(
        adapter.acknowledge_signal(
            left.attempt.id,
            "run-signal",
            "signal-worker",
            claimed[1].attempt_count,
            "effect-7"
        )?,
        settled
    );
    assert_eq!(adapter.signal(input)?, settled);
    assert!(
        adapter
            .breakpoint(
                left.attempt.id,
                "run-signal",
                "signal-worker",
                claimed[1].attempt_count
            )?
            .is_empty()
    );
    assert_eq!(queue.get(right.attempt.id)?.unwrap().signals.len(), 0);
    assert_eq!(queue.get(left.attempt.id)?.unwrap().signals.len(), 1);
    assert_eq!(
        adapter
            .signal(RunSignalInput {
                branch: left.attempt.id,
                run_id: "run-other".into(),
                key: "x".into(),
                actor: "operator".into(),
                kind: RunSignalKind::Steer {
                    instruction: "no".into()
                },
            })
            .unwrap_err()
            .kind(),
        crate::ErrorKind::InvalidConfig
    );
    assert_eq!(
        adapter
            .breakpoint(
                left.attempt.id,
                "run-signal",
                "stale-worker",
                claimed[1].attempt_count
            )
            .unwrap_err()
            .kind(),
        crate::ErrorKind::InvalidConfig
    );
    Ok(())
}

#[test]
fn branch_ask_signals_partial_answers_and_cancel_uses_soft_rail() -> Result<()> {
    use super::{RunAskAnswerKind, RunAskQuestion, RunAskState, RunSignalInput, RunSignalKind};
    use crate::attempt_queue::{AttemptCancelReceiptKind, CancelStanding};
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let row = enqueue(&runner, "worker", None, 1, "run-ask")?;
    let queue = crate::AttemptQueue::new(&vault);
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "signal-worker".into(),
        now: 2,
    })?
    else {
        panic!("expected claimed branch");
    };
    let adapter = RunTreeAdapter::new(&vault);
    let ask = adapter.open_ask(
        row.attempt.id,
        "run-ask",
        "signal-worker",
        claimed.attempt_count,
        "ask-1",
        vec![
            RunAskQuestion {
                who: "alice".into(),
                prompt: "Choose a route".into(),
                options: vec!["a".into()],
                deadline: None,
            },
            RunAskQuestion {
                who: "bob".into(),
                prompt: "Choose a time".into(),
                options: vec!["b".into()],
                deadline: Some(100),
            },
        ],
    )?;
    assert!(ask.answers.is_empty());
    assert_eq!(ask.questions[0].prompt, "Choose a route");
    assert!(matches!(
        adapter.peek_ask(row.attempt.id, "run-ask", "ask-1")?,
        Some(RunAskState::Pending(_))
    ));
    let answer = |key: &str, who: &str| RunSignalInput {
        branch: row.attempt.id,
        run_id: "run-ask".into(),
        key: key.into(),
        actor: who.into(),
        kind: RunSignalKind::AskAnswer {
            handle: "ask-1".into(),
            who: who.into(),
            answer: format!("answer-{who}"),
            kind: RunAskAnswerKind::Word,
        },
    };
    adapter.signal(answer("answer-a", "alice"))?;
    let Some(RunAskState::Pending(partial)) =
        adapter.peek_ask(row.attempt.id, "run-ask", "ask-1")?
    else {
        panic!("expected partial answer");
    };
    assert_eq!(partial.answers.len(), 1);
    adapter.signal(answer("answer-b", "bob"))?;
    assert!(matches!(
        adapter.peek_ask(row.attempt.id, "run-ask", "ask-1")?,
        Some(RunAskState::Ready(_))
    ));
    adapter.signal(RunSignalInput {
        branch: row.attempt.id,
        run_id: "run-ask".into(),
        key: "cancel-1".into(),
        actor: "operator".into(),
        kind: RunSignalKind::Cancel {
            standing: CancelStanding::Authority,
            reason: Some("stop after breakpoint".into()),
        },
    })?;
    assert!(
        queue
            .get(row.attempt.id)?
            .unwrap()
            .cancel_receipts()
            .is_empty()
    );
    assert_eq!(
        adapter
            .breakpoint(
                row.attempt.id,
                "run-ask",
                "signal-worker",
                claimed.attempt_count
            )?
            .len(),
        3
    );
    let record = queue.get(row.attempt.id)?.unwrap();
    assert_eq!(record.state, AttemptState::Leased);
    assert_eq!(record.cancel_receipts().len(), 1);
    assert_eq!(
        record.cancel_receipts()[0].kind,
        AttemptCancelReceiptKind::SoftRequested
    );
    assert!(
        adapter
            .breakpoint(
                row.attempt.id,
                "run-ask",
                "signal-worker",
                claimed.attempt_count
            )?
            .is_empty()
    );
    assert_eq!(
        queue.get(row.attempt.id)?.unwrap().cancel_receipts().len(),
        1
    );
    Ok(())
}

#[test]
fn cancel_signal_refuses_poison_inputs_without_blocking_interject() -> Result<()> {
    use super::{RunSignalInput, RunSignalKind, RunSignalState};
    use crate::attempt_queue::CancelStanding;
    let (_dir, vault) = open_vault();
    let row = enqueue(
        &DreamerRunnerStore::new(&vault),
        "worker",
        None,
        1,
        "run-cancel-poison",
    )?;
    let queue = crate::AttemptQueue::new(&vault);
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker".into(),
        now: 2,
    })?
    else {
        panic!("expected claimed branch");
    };
    let adapter = RunTreeAdapter::new(&vault);
    let cancel = |actor: String, reason: String| RunSignalInput {
        branch: row.attempt.id,
        run_id: "run-cancel-poison".into(),
        key: actor.clone(),
        actor,
        kind: RunSignalKind::Cancel {
            standing: CancelStanding::Authority,
            reason: Some(reason),
        },
    };
    for input in [
        cancel("runtime".into(), "stop".into()),
        cancel("a".repeat(129), "stop".into()),
        cancel("operator".into(), "r".repeat(2049)),
    ] {
        assert!(adapter.signal(input).is_err());
    }
    let interject = RunSignalInput {
        branch: row.attempt.id,
        run_id: "run-cancel-poison".into(),
        key: "good".into(),
        actor: "operator".into(),
        kind: RunSignalKind::Interject {
            content: "continue".into(),
        },
    };
    adapter.signal(interject)?;
    let delivered = adapter.breakpoint(
        row.attempt.id,
        "run-cancel-poison",
        "worker",
        claimed.attempt_count,
    )?;
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].state, RunSignalState::Pending);
    assert!(
        queue
            .get(row.attempt.id)?
            .unwrap()
            .cancel_receipts()
            .is_empty()
    );
    Ok(())
}

#[test]
fn run_ask_step_wait_wakes_only_bound_step_and_survives_reopen() -> Result<()> {
    use super::{RunAskAnswerKind, RunAskQuestion, RunAskWait, RunSignalInput, RunSignalKind};
    use crate::edge::EdgeActorClass;
    use crate::entity_id::EntityId;
    use crate::llm::DurableStepContext;
    use crate::registry::ENTITY_TYPE_PERSON;
    use crate::temporal::TimeRange;
    use crate::write_envelope::WriteActor;
    let (dir, vault) = open_vault();
    let actor = EntityId::now();
    vault.put_entity(
        &actor,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"actor",
    )?;
    let runner = DreamerRunnerStore::new(&vault);
    let first = enqueue(&runner, "first", None, 2, "run-wait")?;
    let sibling = enqueue(&runner, "sibling", None, 3, "run-wait")?;
    let queue = crate::AttemptQueue::new(&vault);
    for id in [first.attempt.id, sibling.attempt.id] {
        let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
            lease_owner: "worker".into(),
            now: 4,
        })?
        else {
            panic!("expected branch claim");
        };
        assert_eq!(claimed.id, id);
    }
    let ctx = DurableStepContext {
        vault: &vault,
        attempt_id: first.attempt.id,
        run_id: Some("run-wait".into()),
        envelope_actor: WriteActor::new(actor, EdgeActorClass::Agent),
        subject: actor,
        deadline: None,
        now_ms: 5_000,
    };
    let other_ctx = DurableStepContext {
        vault: &vault,
        attempt_id: sibling.attempt.id,
        run_id: Some("run-wait".into()),
        envelope_actor: ctx.envelope_actor,
        subject: actor,
        deadline: None,
        now_ms: 5_000,
    };
    let adapter = RunTreeAdapter::new(&vault);
    let questions = vec![
        RunAskQuestion {
            who: "alice".into(),
            prompt: "First?".into(),
            options: vec![],
            deadline: None,
        },
        RunAskQuestion {
            who: "bob".into(),
            prompt: "Second?".into(),
            options: vec![],
            deadline: None,
        },
    ];
    adapter.open_ask(
        first.attempt.id,
        "run-wait",
        "worker",
        1,
        "ask",
        questions.clone(),
    )?;
    adapter.open_ask(
        sibling.attempt.id,
        "run-wait",
        "worker",
        1,
        "other",
        questions,
    )?;
    let RunAskWait::Pending { .. } = adapter.wait_ask(&ctx, "ask", "step-1")? else {
        panic!("step must park");
    };
    let RunAskWait::Pending { .. } = adapter.wait_ask(&other_ctx, "other", "unrelated")? else {
        panic!("unrelated step must park independently");
    };
    assert!(adapter.consume_ask_wait(&ctx, "ask", "step-1")?.is_none());
    let answer = |who: &str| RunSignalInput {
        branch: first.attempt.id,
        run_id: "run-wait".into(),
        key: format!("answer-{who}"),
        actor: who.into(),
        kind: RunSignalKind::AskAnswer {
            handle: "ask".into(),
            who: who.into(),
            answer: format!("yes-{who}"),
            kind: RunAskAnswerKind::Word,
        },
    };
    adapter.signal(answer("alice"))?;
    let partial = adapter
        .consume_ask_wait(&ctx, "ask", "step-1")?
        .expect("signal woke step");
    assert_eq!(partial.answers.len(), 1);
    assert!(
        adapter
            .consume_ask_wait(&other_ctx, "other", "unrelated")?
            .is_none()
    );
    assert_eq!(
        queue.get(sibling.attempt.id)?.unwrap().state,
        AttemptState::Leased
    );
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    let ctx = DurableStepContext {
        vault: &vault,
        attempt_id: first.attempt.id,
        run_id: Some("run-wait".into()),
        envelope_actor: WriteActor::new(actor, EdgeActorClass::Agent),
        subject: actor,
        deadline: None,
        now_ms: 6_000,
    };
    let adapter = RunTreeAdapter::new(&vault);
    assert_eq!(
        adapter
            .consume_ask_wait(&ctx, "ask", "step-1")?
            .unwrap()
            .answers
            .len(),
        1
    );
    let RunAskWait::Pending { .. } = adapter.wait_ask(&ctx, "ask", "step-2")? else {
        panic!("next partial wait must park a new step");
    };
    adapter.signal(answer("bob"))?;
    assert_eq!(
        adapter
            .consume_ask_wait(&ctx, "ask", "step-2")?
            .unwrap()
            .answers
            .len(),
        2
    );
    assert!(matches!(
        adapter.wait_ask(&ctx, "ask", "late")?,
        RunAskWait::Available(_)
    ));
    Ok(())
}
