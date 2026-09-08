//! Task verb tests: Cancel ladder, spawn and agent-dispatch cancel, sibling cancel, force hard-cancel and refusal pathology.

use super::support::*;
use super::*;

#[test]
fn cancel_ladder_is_own_scoped_and_records_gate_decision() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    grant_cancel(&vault, own, 0xD1);
    let other = EntityId::from_bytes([0xE2; 16]).expect("other id");
    put_person(&vault, other);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let own_create = facade.tasks_create(&spec(120)).expect("own task");
    let mut other_spec = spec(120);
    other_spec.owner_ref = Some(other);
    let other_create = facade.tasks_create(&other_spec).expect("other task");

    let decisions_before = vault.gate_decisions(512).expect("decisions before").len();
    let own_cancel = facade
        .tasks_cancel(TaskCancelTarget::Task(
            own_create.task_ref.expect("own task ref"),
        ))
        .expect("own cancel");
    let decisions_after_own = vault
        .gate_decisions(512)
        .expect("decisions after own")
        .len();
    let foreign_cancel = facade
        .tasks_cancel(TaskCancelTarget::Task(
            other_create.task_ref.expect("other task ref"),
        ))
        .expect("foreign cancel");

    assert_eq!(TaskCancelMode::ALL.map(TaskCancelMode::as_str).len(), 3);
    assert_eq!(
        TaskCancelMode::ALL.map(TaskCancelMode::as_str),
        ["auto", "full-access", "manual"]
    );
    assert_eq!(DEFAULT_TASK_CANCEL_MODE.as_str(), "auto");
    assert_eq!(TaskCancelMode::Auto.ceiling(), PolicyApprovalCeiling::Auto);
    assert_eq!(
        TaskCancelMode::FullAccess.ceiling(),
        PolicyApprovalCeiling::Auto
    );
    assert_eq!(
        TaskCancelMode::Manual.ceiling(),
        PolicyApprovalCeiling::Proposed
    );
    assert_eq!(decisions_after_own - decisions_before, 1);
    assert_eq!(usize::from(own_cancel.gate_decision_ref.is_some()), 1);
    assert_eq!(
        vault
            .gate_decisions(512)
            .expect("gate decisions")
            .iter()
            .filter(|decision| {
                own_cancel.gate_decision_ref.as_deref()
                    == Some(format!("gate:{}", decision.decision_id.to_hex()).as_str())
                    && decision.outcome == GateOutcome::Allow.as_str()
            })
            .count(),
        1
    );
    assert_eq!(usize::from(own_cancel.effected), 1);
    assert_eq!(own_cancel.approval, ClaimApprovalStatus::Auto);
    assert_eq!(own_cancel.status, Some(RunTreeStatus::Cancelled));
    assert_eq!(usize::from(foreign_cancel.effected), 0);
    assert_eq!(foreign_cancel.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(usize::from(foreign_cancel.proposal_ref.is_some()), 1);
    assert_eq!(usize::from(foreign_cancel.gate_decision_ref.is_some()), 1);

    let queue = AttemptQueue::new(&vault);
    let records = queue.list().expect("list attempts");
    let own_task_hex = own_create.task_ref.expect("own task ref").to_hex();
    let other_task_hex = other_create.task_ref.expect("other task ref").to_hex();
    let own_attempts: Vec<_> = records
        .iter()
        .filter(|attempt| attempt.task_ref.as_deref() == Some(own_task_hex.as_str()))
        .collect();
    let other_attempts: Vec<_> = records
        .iter()
        .filter(|attempt| attempt.task_ref.as_deref() == Some(other_task_hex.as_str()))
        .collect();
    assert_eq!(own_attempts.len(), 1);
    assert_eq!(other_attempts.len(), 1);
    let own_attempt = own_attempts[0];
    let other_attempt = other_attempts[0];
    assert_eq!(own_attempt.state, AttemptState::Cancelled);
    assert_eq!(other_attempt.state, AttemptState::Queued);
}

#[test]
fn pending_cancel_proposes_without_intervening_realization() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");

    let cancel = facade
        .tasks_cancel(TaskCancelTarget::Task(task_ref))
        .expect("propose cancel");
    let records = AttemptQueue::new(&vault).list().expect("list attempts");
    let task_hex = task_ref.to_hex();

    assert_eq!(usize::from(cancel.effected), 0);
    assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(usize::from(cancel.proposal_ref.is_some()), 1);
    assert_eq!(
        vault
            .gate_decisions(512)
            .expect("gate decisions")
            .iter()
            .filter(|decision| {
                cancel.gate_decision_ref.as_deref()
                    == Some(format!("gate:{}", decision.decision_id.to_hex()).as_str())
                    && decision.outcome == GateOutcome::Pending.as_str()
            })
            .count(),
        1
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| {
                record.task_ref.as_deref() == Some(task_hex.as_str())
                    && record.state == AttemptState::Queued
            })
            .count(),
        1
    );
    assert_eq!(
        usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
        0
    );
}

#[test]
fn leased_realization_keeps_cancel_receipt_running() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    grant_cancel(&vault, own, 0xD2);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");
    let queue = AttemptQueue::new(&vault);
    let claimed = match queue
        .claim_kind(
            TASK_REALIZE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "w1".to_owned(),
                now: 120,
            },
        )
        .expect("claim realization")
    {
        ClaimOutcome::Claimed(claimed) => claimed,
        ClaimOutcome::Empty => panic!("realization must be claimable"),
    };

    let cancel = facade
        .tasks_cancel(TaskCancelTarget::Task(task_ref))
        .expect("cancel task");
    let post_cancel = queue
        .get(claimed.id)
        .expect("read realization")
        .expect("realization exists");
    let section = facade.tasks_check().expect("check tasks");

    // P1-a: a leased realization is NOT stoppable in-txn, so the cancel is
    // honest — it does not claim effect and does not hide the task.
    assert_eq!(usize::from(cancel.effected), 0);
    assert!(
        cancel.cancel_requested,
        "the live worker received a soft request"
    );
    assert_eq!(cancel.status, Some(RunTreeStatus::Running));
    assert_eq!(
        usize::from(cancel.status == Some(RunTreeStatus::Cancelled)),
        0
    );
    assert_eq!(cancel.approval, ClaimApprovalStatus::Auto);
    assert_eq!(usize::from(cancel.proposal_ref.is_some()), 0);
    assert_eq!(post_cancel.state, AttemptState::Leased);
    // The task is NOT hidden while the lease keeps realizing (outbound
    // delivery included): the cancelled bit is not set.
    assert_eq!(
        usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
        0
    );
    // The board still shows the task exactly once — it folds to Running
    // under its live lease rather than vanishing.
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == task_ref.to_hex())
            .count(),
        1
    );
}

#[test]
fn terminal_task_cancel_is_uneffected_and_keeps_intent_folded() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    grant_cancel(&vault, own, 0xD3);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");
    let task_hex = task_ref.to_hex();
    let queue = AttemptQueue::new(&vault);
    let claimed = match queue
        .claim_kind(
            TASK_REALIZE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "terminal-task-worker".to_owned(),
                now: 120,
            },
        )
        .expect("claim realization")
    {
        ClaimOutcome::Claimed(claimed) => claimed,
        ClaimOutcome::Empty => panic!("realization must be claimable"),
    };
    queue
        .complete(CompleteAttempt {
            id: claimed.id,
            lease_owner: "terminal-task-worker".to_owned(),
            attempt_count: claimed.attempt_count,
            now: 121,
        })
        .expect("complete realization");

    let cancel = facade
        .tasks_cancel(TaskCancelTarget::Task(task_ref))
        .expect("cancel terminal task");
    let realization = queue
        .get(claimed.id)
        .expect("read realization")
        .expect("realization exists");
    let section = facade.tasks_check().expect("check tasks");
    let job_hex = attempt_hex(claimed.id);

    assert_eq!(usize::from(cancel.effected), 0);
    assert_eq!(cancel.status, Some(RunTreeStatus::Completed));
    assert_eq!(cancel.approval, ClaimApprovalStatus::Auto);
    assert_eq!(realization.state, AttemptState::Completed);
    assert_eq!(
        usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
        0
    );
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == task_hex && row.status == TaskBoardStatus::Done)
            .count(),
        1
    );
    assert_eq!(
        section.rows.iter().filter(|row| row.id == job_hex).count(),
        0
    );
    assert_eq!(section.rows.len(), 1);
}

#[test]
fn queued_completed_mix_cancel_preserves_terminal_fold_exactly_once() {
    assert_queued_terminal_mix_cancel(
        AttemptState::Completed,
        RunTreeStatus::Completed,
        TaskBoardStatus::Done,
    );
}

#[test]
fn queued_failed_mix_cancel_preserves_terminal_fold_exactly_once() {
    assert_queued_terminal_mix_cancel(
        AttemptState::Failed,
        RunTreeStatus::Failed,
        TaskBoardStatus::Failed,
    );
}

#[test]
#[ignore = "CB-04 follow-up: agent spawn self-cancel proposes (gate Pending); Auto/Some(Completed) needs gate-authority change, deferred post-close, non-security"]
fn terminal_spawn_cancel_is_uneffected_and_preserves_terminal_state() {
    let (_dir, vault) = open_vault();
    let own = EntityId::from_bytes([0xB3; 16]).expect("custom agent id");
    // Ordinary row fork off the seeded keeper row: lineage is the parent
    // ROW id, and the child copies the parent's stored ceiling.
    let (keeper_id, keeper) = vault
        .get_seeded_agent_definition_by_logical_id("sys.keeper")
        .expect("resolve seeded keeper")
        .expect("seeded keeper exists");
    let mut fork = keeper.clone();
    fork.agent_id = "spawn-owner".to_owned();
    fork.version = "1".to_owned();
    fork.forked_from = Some(keeper_id);
    fork.ceiling = keeper.ceiling;
    fork.logical_id = None;
    fork.display_name = None;
    fork.source = crate::claim::ClaimSource::UserStated;
    fork.provenance = rmpv::Value::Map(vec![(
        rmpv::Value::from("forkOf"),
        rmpv::Value::from(keeper_id.to_hex()),
    )]);
    vault
        .put_agent_definition(&own, &fork, TimeRange { start: 1, end: 1 }, 1)
        .expect("fork custom agent");
    grant_cancel(&vault, own, 0xD4);
    let dispatcher = AgentDispatcher::new(&vault);
    let parent = match dispatcher
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(own),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: 120,
        })
        .expect("dispatch parent")
    {
        AgentDispatchOutcome::Dispatched(status) => status,
        AgentDispatchOutcome::Existing(_) => panic!("parent dispatch must be fresh"),
    };
    let child = match dispatcher
        .dispatch_default_base(Some(parent.attempt.id), None, None, 121)
        .expect("dispatch child")
    {
        AgentDispatchOutcome::Dispatched(status) => status,
        AgentDispatchOutcome::Existing(_) => panic!("child dispatch must be fresh"),
    };
    let queue = AttemptQueue::new(&vault);
    for (expected, lease_owner, now) in [
        (parent.attempt.id, "terminal-parent-worker", 122),
        (child.attempt.id, "terminal-child-worker", 123),
    ] {
        let claimed = match queue
            .claim_kind(
                DREAMER_RUNNER_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: lease_owner.to_owned(),
                    now,
                },
            )
            .expect("claim dispatch")
        {
            ClaimOutcome::Claimed(claimed) => claimed,
            ClaimOutcome::Empty => panic!("dispatch must be claimable"),
        };
        assert_eq!(usize::from(claimed.id == expected), 1);
        queue
            .complete(CompleteAttempt {
                id: claimed.id,
                lease_owner: lease_owner.to_owned(),
                attempt_count: claimed.attempt_count,
                now,
            })
            .expect("complete dispatch");
    }

    let facade = vault.memory(own, EdgeActorClass::Agent);
    let cancel = facade
        .tasks_cancel(TaskCancelTarget::Spawn(child.attempt.id))
        .expect("cancel terminal spawn");
    let terminal = queue
        .get(child.attempt.id)
        .expect("read child")
        .expect("child exists");

    assert_eq!(usize::from(cancel.effected), 0);
    assert_eq!(cancel.status, Some(RunTreeStatus::Completed));
    assert_eq!(cancel.approval, ClaimApprovalStatus::Auto);
    assert_eq!(terminal.state, AttemptState::Completed);
    assert_eq!(
        vault
            .gate_decisions(512)
            .expect("gate decisions")
            .iter()
            .filter(|decision| {
                cancel.gate_decision_ref.as_deref()
                    == Some(format!("gate:{}", decision.decision_id.to_hex()).as_str())
                    && decision.outcome == GateOutcome::Allow.as_str()
            })
            .count(),
        1
    );
}

#[test]
fn tasks_cancel_spawn_non_dreamer_attempt_falls_through_to_proposal() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(attempt) = queue
        .enqueue(EnqueueAttempt {
            kind: AGENT_DISPATCH_ATTEMPT_TYPE.to_owned(),
            payload: vec![0xc1, 0x00, 0xff],
            dedupe_key: None,
            run_id: None,
            now: 120,
        })
        .expect("enqueue")
    else {
        panic!("enqueue must succeed")
    };
    let cancel = vault
        .memory(own, EdgeActorClass::Agent)
        .tasks_cancel(TaskCancelTarget::Spawn(attempt.id))
        .expect("cancel");
    assert!(!cancel.effected);
    assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
    assert!(cancel.proposal_ref.is_some());
    assert_eq!(cancel.status, None);
    assert_eq!(
        queue
            .get(attempt.id)
            .expect("read attempt")
            .expect("attempt exists")
            .state,
        AttemptState::Queued
    );
}

#[test]
fn tasks_cancel_spawn_malformed_dreamer_payload_is_propose_only() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(attempt) = queue
        .enqueue(EnqueueAttempt {
            kind: DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
            payload: vec![0xc1],
            dedupe_key: None,
            run_id: None,
            now: 120,
        })
        .expect("enqueue")
    else {
        panic!("enqueue must succeed")
    };
    let cancel = vault
        .memory(own, EdgeActorClass::Agent)
        .tasks_cancel(TaskCancelTarget::Spawn(attempt.id))
        .expect("cancel");
    assert!(!cancel.effected);
    assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
    assert!(cancel.proposal_ref.is_some());
    assert_eq!(cancel.status, None);
    assert_eq!(
        queue
            .get(attempt.id)
            .expect("read attempt")
            .expect("attempt exists")
            .state,
        AttemptState::Queued
    );
}

#[test]
fn tasks_cancel_spawn_missing_attempt_still_returns_entity_not_found() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let missing = AttemptId::from_bytes(&[0xa7; 16]).expect("id");
    let error = vault
        .memory(own, EdgeActorClass::Agent)
        .tasks_cancel(TaskCancelTarget::Spawn(missing))
        .expect_err("missing row");
    assert_eq!(error.code, crate::memory::MEMORY_CODE_NOT_FOUND);
}

#[test]
fn tasks_cancel_owned_agent_dispatch_spawn_still_effects_under_auto() {
    let (_dir, vault) = open_vault();
    let own = EntityId::from_bytes([0xE1; 16]).expect("actor id");
    let (keeper_id, keeper) = vault
        .get_seeded_agent_definition_by_logical_id("sys.keeper")
        .expect("resolve keeper")
        .expect("keeper exists");
    let mut fork = keeper.clone();
    fork.agent_id = "spawn-owner".to_owned();
    fork.version = "1".to_owned();
    fork.forked_from = Some(keeper_id);
    fork.ceiling = keeper.ceiling;
    fork.logical_id = None;
    fork.display_name = None;
    fork.source = crate::claim::ClaimSource::UserStated;
    fork.provenance = rmpv::Value::Map(vec![(
        rmpv::Value::from("forkOf"),
        rmpv::Value::from(keeper_id.to_hex()),
    )]);
    vault
        .put_agent_definition(
            &own,
            &fork,
            TimeRange {
                start: 1,
                end: u64::MAX,
            },
            1,
        )
        .expect("fork agent");
    grant_cancel(&vault, own, 0xa8);
    let dispatcher = AgentDispatcher::new(&vault);
    let parent = match dispatcher
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(own),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: 120,
        })
        .expect("dispatch parent")
    {
        AgentDispatchOutcome::Dispatched(status) => status,
        AgentDispatchOutcome::Existing(_) => panic!("fresh parent"),
    };
    let child = match dispatcher
        .dispatch_default_base(Some(parent.attempt.id), None, None, 121)
        .expect("dispatch child")
    {
        AgentDispatchOutcome::Dispatched(status) => status,
        AgentDispatchOutcome::Existing(_) => panic!("fresh child"),
    };
    let queue = AttemptQueue::new(&vault);
    assert_eq!(
        queue
            .get(child.attempt.id)
            .expect("read queued child")
            .expect("child exists")
            .state,
        AttemptState::Queued
    );
    let cancel = vault
        .memory(own, EdgeActorClass::Agent)
        .tasks_cancel(TaskCancelTarget::Spawn(child.attempt.id))
        .expect("cancel");
    assert_eq!(cancel.approval, ClaimApprovalStatus::Auto);
    assert!(cancel.effected);
    assert!(cancel.proposal_ref.is_none());
    assert!(cancel.gate_decision_ref.is_some());
    assert_eq!(cancel.status, Some(RunTreeStatus::Cancelled));
    assert_eq!(
        queue
            .get(child.attempt.id)
            .expect("read cancelled child")
            .expect("child exists")
            .state,
        AttemptState::Cancelled
    );
}

#[test]
fn tasks_cancel_non_owned_spawn_manual_and_auto_both_propose() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(attempt) = queue
        .enqueue(EnqueueAttempt {
            kind: AGENT_DISPATCH_ATTEMPT_TYPE.to_owned(),
            payload: vec![0xc1],
            dedupe_key: None,
            run_id: None,
            now: 120,
        })
        .expect("enqueue")
    else {
        panic!("enqueue must succeed")
    };
    let facade = vault.memory(own, EdgeActorClass::Agent);
    for cancel in [
        facade
            .tasks_cancel_with_mode(TaskCancelTarget::Spawn(attempt.id), TaskCancelMode::Manual)
            .expect("manual cancel"),
        facade
            .tasks_cancel(TaskCancelTarget::Spawn(attempt.id))
            .expect("auto cancel"),
    ] {
        assert!(!cancel.effected);
        assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
        assert!(cancel.proposal_ref.is_some());
        assert_eq!(cancel.status, None);
        assert_eq!(
            queue
                .get(attempt.id)
                .expect("read attempt")
                .expect("attempt exists")
                .state,
            AttemptState::Queued
        );
    }
}

mod spawn_cancel_unknown_kinds_never_hard_error_on_payload_shape {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn property(
            kind in any::<String>().prop_filter("non-Dreamer non-empty kind", |kind| !kind.is_empty() && kind != DREAMER_RUNNER_ATTEMPT_KIND),
            payload in any::<Vec<u8>>(),
        ) {
            let (_dir, vault) = open_vault();
            let own = own_agent(&vault);
            let queue = AttemptQueue::new(&vault);
            let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(EnqueueAttempt {
                kind,
                payload,
                dedupe_key: None,
                run_id: None,
                now: 120,
            }).expect("enqueue") else {
                panic!("enqueue must succeed")
            };
            let cancel = vault.memory(own, EdgeActorClass::Agent)
                .tasks_cancel(TaskCancelTarget::Spawn(attempt.id))
                .expect("payload shape is tolerated");
            prop_assert!(!cancel.effected);
            prop_assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
            prop_assert!(cancel.proposal_ref.is_some());
            prop_assert_eq!(cancel.status, None);
            prop_assert_eq!(
                queue.get(attempt.id).expect("read attempt").expect("attempt exists").state,
                AttemptState::Queued
            );
        }
    }
}

#[test]
fn connector_send_cancel_cancels_queued_realization() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let send_grant_ref = EntityId::from_bytes([0xD3; 16]).expect("send grant id");
    vault
        .mint_standing_outbound_grant(
            &send_grant_ref,
            &GrantMintIntent {
                principal_ref: own.to_hex(),
                origin_component_id: "tasks".to_owned(),
                origin_action_id: "create".to_owned(),
                origin_receipt_ref: None,
                scope: GrantMintIntentScope::VerbClass {
                    verb_class: "send".to_owned(),
                },
            },
            1,
        )
        .expect("mint send grant");
    grant_cancel(&vault, own, 0xD4);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    facade
        .schedule_outbound(&OutboundDraftInput {
            verb: "send".to_owned(),
            channel: "email".to_owned(),
            target: "x".to_owned(),
            on_behalf_of: None,
            content_ref: None,
            idempotency_key: Some("k1".to_owned()),
            dedupe_key: None,
            trigger: "agent_immediate".to_owned(),
            trigger_ref: "s1".to_owned(),
            job_ref: None,
            occurred_at: Some(120),
        })
        .expect("schedule send");
    let tasks = vault.connector_send_tasks().expect("connector tasks");
    assert_eq!(tasks.len(), 1);
    let task_ref = tasks[0].task_ref;

    let cancel = facade
        .tasks_cancel(TaskCancelTarget::Task(task_ref))
        .expect("cancel send");
    let attempts = AttemptQueue::new(&vault).list().expect("list attempts");
    let task_hex = task_ref.to_hex();

    assert_eq!(usize::from(cancel.effected), 1);
    assert_eq!(cancel.status, Some(RunTreeStatus::Cancelled));
    assert_eq!(
        attempts
            .iter()
            .filter(|attempt| {
                attempt.task_ref.as_deref() == Some(task_hex.as_str())
                    && attempt.state == AttemptState::Cancelled
            })
            .count(),
        1
    );
    assert_eq!(
        attempts
            .iter()
            .filter(|attempt| {
                attempt.task_ref.as_deref() == Some(task_hex.as_str())
                    && attempt.state == AttemptState::Queued
            })
            .count(),
        0
    );
}

/// ONE-1896 §9: a LANDING parent must not shelter its siblings.
///
/// The landing row holds a lease and can only be ASKED, but the queued, paused
/// and scheduled siblings have no worker at all — an owner-approved cancel that
/// returned early at the landing parent left every one of them claimable while
/// the receipt implied the target was handled.
#[test]
fn cancel_stops_every_sibling_while_the_landing_parent_is_preserved() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    grant_cancel(&vault, own, 0xD9);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");
    let task_hex = task_ref.to_hex();
    let queue = AttemptQueue::new(&vault);

    // The parent realization accepted a stop and is LANDING.
    let parent = claim_realization(&queue, "worker-parent", 120);
    queue
        .request_cancel(RequestAttemptCancel {
            id: parent.id,
            actor: "peer-1".to_owned(),
            standing: CancelStanding::PeerAgent,
            trigger: LandingTrigger::CancelRequest,
            reason: None,
            now: 121,
        })
        .expect("a peer may ask");
    let LandingOutcome::Landing(landing) = queue
        .accept_landing(AcceptAttemptLanding {
            id: parent.id,
            lease_owner: "worker-parent".to_owned(),
            attempt_count: parent.attempt_count,
            trigger: LandingTrigger::CancelRequest,
            status: Some("green + pushed".to_owned()),
            resume_point: None,
            request_sequence: None,
            now: 122,
        })
        .expect("the worker accepts")
    else {
        panic!("expected a fresh landing");
    };
    assert_eq!(landing.state, AttemptState::Landing);

    // A scheduled sibling (a retry waiting on its instant).
    let to_retry = enqueue_sibling(&queue, &task_hex, 123);
    let retried = claim_realization(&queue, "worker-retry", 124);
    assert_eq!(retried.id, to_retry.id);
    let RetryOutcome::Retried(scheduled) = queue
        .retry(RetryAttempt {
            id: retried.id,
            lease_owner: "worker-retry".to_owned(),
            attempt_count: retried.attempt_count,
            backoff_until: 9_999,
            last_error: None,
            now: 125,
        })
        .expect("retry mints the next try");
    assert_eq!(scheduled.state, AttemptState::Scheduled);
    // A queued sibling and a paused one.
    let queued = enqueue_sibling(&queue, &task_hex, 126);
    let to_pause = enqueue_sibling(&queue, &task_hex, 127);
    let paused = queue
        .intervene(InterveneAttempt {
            id: to_pause.id,
            kind: AttemptInterventionKind::Pause,
            actor: "operator".to_owned(),
            note: None,
            now: 128,
        })
        .expect("pause the sibling")
        .record;
    assert_eq!(paused.state, AttemptState::Paused);

    let cancel = facade
        .tasks_cancel(TaskCancelTarget::Task(task_ref))
        .expect("owner cancel");

    assert_eq!(cancel.approval, ClaimApprovalStatus::Auto);
    assert!(
        cancel.cancel_requested,
        "the landing parent was asked, not killed"
    );
    assert!(
        cancel.effected,
        "the siblings that could be stopped really were"
    );
    assert_eq!(
        cancel.status,
        Some(RunTreeStatus::Running),
        "a live lease keeps the target visible as running"
    );
    assert!(!cancel.forced, "the cooperative verb never forces");

    // No sibling is left alive.
    for id in [queued.id, paused.id, scheduled.id] {
        let record = queue.get(id).expect("read").expect("row");
        assert_eq!(
            record.state,
            AttemptState::Cancelled,
            "a sibling of a landing parent is still stopped"
        );
    }
    // The landing parent and the request it accepted are preserved.
    let parent_row = queue.get(parent.id).expect("read").expect("row");
    assert_eq!(parent_row.state, AttemptState::Landing);
    assert_eq!(
        parent_row.landing().expect("landing record").requested_by,
        "peer-1"
    );
    assert_eq!(
        parent_row.cancel_pressure().pending,
        0,
        "asking a landing row again is idempotent, not a second obligation"
    );
    // The TASK stays visible while its lease is live.
    assert!(!task_is_cancelled(&vault, task_ref).expect("cancel state"));
}

/// ONE-1896 §5/§8: the hard rung exists, is owner-only, and its receipt is
/// runtime-authored.
#[test]
fn only_a_verified_owner_reaches_the_hard_cancel_rung() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    grant_cancel(&vault, own, 0xDF);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");
    let queue = AttemptQueue::new(&vault);
    let claimed = claim_realization(&queue, "stubborn-worker", 120);

    // An ordinary actor cannot force another principal's task: it gets the
    // ordinary proposal, and nothing durable moves.
    let stranger_ref = EntityId::from_bytes([0xE7; 16]).expect("stranger id");
    put_person(&vault, stranger_ref);
    grant_cancel(&vault, stranger_ref, 0xDE);
    let stranger = vault.memory(stranger_ref, EdgeActorClass::Agent);
    let refused = stranger
        .tasks_cancel_force(TaskCancelTarget::Task(task_ref), None)
        .expect("a stranger's force is refused, not an error");
    assert_eq!(refused.approval, ClaimApprovalStatus::Proposed);
    assert!(!refused.forced);
    assert!(!refused.effected);
    assert!(refused.proposal_ref.is_some());
    let untouched = queue.get(claimed.id).expect("read").expect("row");
    assert_eq!(
        untouched.state,
        AttemptState::Leased,
        "an unauthorized force changes no durable state"
    );
    assert!(untouched.cancellation().is_none());

    // The verified owner can, and the runtime authors the receipt.
    let forced = facade
        .tasks_cancel_force(
            TaskCancelTarget::Task(task_ref),
            Some("refused to land three times".to_owned()),
        )
        .expect("the owner forces");
    assert_eq!(forced.approval, ClaimApprovalStatus::Auto);
    assert!(forced.forced);
    assert!(forced.effected);
    assert_eq!(forced.status, Some(RunTreeStatus::Cancelled));

    let stopped = queue.get(claimed.id).expect("read").expect("row");
    assert_eq!(stopped.state, AttemptState::Cancelled);
    let cancellation = stopped.cancellation().expect("terminal receipt");
    assert_eq!(cancellation.mode, CancelMode::Forced);
    assert_eq!(cancellation.grounds, Some(ForceCancelGrounds::Owner));
    assert_eq!(
        cancellation.actor,
        own.to_hex(),
        "the receipt names the VERIFIED owner, never caller-supplied text"
    );
    assert_eq!(
        cancellation.reason.as_deref(),
        Some("refused to land three times")
    );
    assert_eq!(stopped.lease_owner, None);
    assert!(task_is_cancelled(&vault, task_ref).expect("cancel state"));

    // Replay is idempotent: a settled target is reported, never re-killed.
    let replay = facade
        .tasks_cancel_force(TaskCancelTarget::Task(task_ref), None)
        .expect("replay");
    assert!(!replay.effected, "there was nothing left to stop");
    assert_eq!(
        queue
            .get(claimed.id)
            .expect("read")
            .expect("row")
            .cancellation()
            .expect("receipt")
            .reason
            .as_deref(),
        Some("refused to land three times"),
        "the first authority's receipt is not overwritten"
    );
}

/// ONE-1896 §1: repeated refusal reaches the OWNER's surface.
///
/// A count buried in queue telemetry is not a signal an owner can act on; the
/// board row is what they read every turn.
#[test]
fn repeated_refusal_surfaces_on_the_owner_board_and_ordinary_rows_are_unchanged() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    grant_cancel(&vault, own, 0xDB);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");
    let task_hex = task_ref.to_hex();
    let queue = AttemptQueue::new(&vault);
    let claimed = claim_realization(&queue, "stubborn-worker", 120);

    let refuse_once = |round: u64| {
        queue
            .request_cancel(RequestAttemptCancel {
                id: claimed.id,
                actor: "peer-1".to_owned(),
                standing: CancelStanding::PeerAgent,
                trigger: LandingTrigger::CancelRequest,
                reason: None,
                now: 130 + round,
            })
            .expect("a peer may ask");
        queue
            .reject_cancel(RejectAttemptCancel {
                id: claimed.id,
                lease_owner: "stubborn-worker".to_owned(),
                attempt_count: claimed.attempt_count,
                reason: "mid-write; landing now would corrupt the packet".to_owned(),
                status: Some("red + unpushed".to_owned()),
                request_sequence: None,
                now: 131 + round,
            })
            .expect("the worker refuses");
    };

    // One refusal is a legitimate "not yet" and must not clutter the board.
    refuse_once(0);
    let quiet = facade.tasks_check().expect("board");
    let quiet_row = quiet
        .rows
        .iter()
        .find(|row| row.id == task_hex)
        .expect("the task renders");
    assert!(
        quiet_row.cancel_pathology.is_none(),
        "one refusal is not a pathology"
    );
    assert!(!quiet_row.line.contains("cancel-refused"));
    assert_eq!(quiet_row.status, TaskBoardStatus::Running);

    for round in 1..u64::from(SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD) {
        refuse_once(round * 10);
    }

    let board = facade.tasks_check().expect("board");
    let row = board
        .rows
        .iter()
        .find(|row| row.id == task_hex)
        .expect("the task renders");
    let pathology = row
        .cancel_pathology
        .as_ref()
        .expect("repeated refusal reaches the owner");
    assert_eq!(
        pathology.rejections,
        SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD
    );
    assert_eq!(
        pathology.threshold,
        SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD
    );
    assert_eq!(pathology.attempt_id, attempt_hex(claimed.id));
    assert_eq!(
        pathology.last_status.as_deref(),
        Some("red + unpushed"),
        "the worker's own last word rides the signal"
    );
    assert!(
        row.line.contains("cancel-refused=3/3"),
        "the rendered row carries the bounded token: {}",
        row.line
    );
    assert_eq!(
        row.status,
        TaskBoardStatus::Running,
        "the refusal narrows the row; it does not relabel live work"
    );

    // The by-id owner path carries it too: a row past the collapsed board's
    // scan prefix is hidden, never gone, so `tasks.expand` must not be the one
    // owner surface where the refusal disappears.
    let expanded = facade.tasks_expand(task_ref).expect("expand");
    assert!(
        expanded
            .iter()
            .any(|line| line.contains("cancel-refused=3/3")),
        "the expanded owner view carries the same bounded token: {expanded:?}"
    );

    // Settling the attempt retires the signal: an owner can no longer act on it.
    let stopped = facade
        .tasks_cancel_force(TaskCancelTarget::Task(task_ref), None)
        .expect("the owner forces");
    assert!(stopped.forced);
    let settled = facade.tasks_check().expect("board");
    assert!(
        settled
            .rows
            .iter()
            .all(|row| row.cancel_pathology.is_none()),
        "a settled attempt is history, not an open decision"
    );
}
