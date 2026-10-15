//! Task verb tests: Ack, cancel-vs-retry truth, owner proofs, board folding and poison-row isolation.

use super::support::*;
use super::*;

#[test]
fn role_only_task_is_present_and_cancel_fails_closed() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    grant_cancel(&vault, own, 0xD5);
    let task_ref = EntityId::from_bytes([0xB1; 16]).expect("task id");
    vault
        .put_entity(
            &task_ref,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: 120,
                end: 120,
            },
            120,
            &crate::habit::task_body_for_test(TaskRole::Task),
        )
        .expect("put task");
    let outcome = AttemptQueue::new(&vault)
        .enqueue_with_task_ref(
            EnqueueAttempt {
                kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                payload: Vec::new(),
                dedupe_key: None,
                run_id: None,
                now: 120,
            },
            Some(task_ref.to_hex()),
        )
        .expect("enqueue realization");
    let EnqueueOutcome::Enqueued(attempt) = outcome else {
        panic!("realization must enqueue");
    };
    let facade = vault.memory(own, EdgeActorClass::Agent);

    let section = facade.describe_section().expect("check tasks");
    assert_eq!(section.rows.len(), 1);
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == task_ref.to_hex())
            .count(),
        1
    );

    let cancel = facade
        .cancel(TaskCancelTarget::Task(task_ref))
        .expect("cancel task");
    let realization = AttemptQueue::new(&vault)
        .get(attempt.id)
        .expect("read realization")
        .expect("realization exists");

    // P1-c: a role-only TASK carries no stored owner provenance, so cancel
    // fails closed to the foreign ladder — a proposal, never a direct
    // effect. The realizing attempt is untouched (still Queued), and the
    // task stays visible (asserted above: fix-r1 F6 is preserved).
    assert_eq!(usize::from(cancel.effected), 0);
    assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(usize::from(cancel.proposal_ref.is_some()), 1);
    assert_eq!(realization.state, AttemptState::Queued);
}

#[test]
fn ack_persists_and_removes_failed_task_from_render() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");
    let queue = AttemptQueue::new(&vault);
    let claimed = match queue
        .claim_kind(
            TASK_REALIZE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "worker".to_owned(),
                now: 120,
            },
        )
        .expect("claim")
    {
        ClaimOutcome::Claimed(claimed) => claimed,
        ClaimOutcome::Empty => panic!("created task must be claimable"),
    };
    queue
        .fail(FailAttempt {
            id: claimed.id,
            lease_owner: "worker".to_owned(),
            attempt_count: claimed.attempt_count,
            reason: "failed".to_owned(),
            now: 121,
        })
        .expect("fail task");

    let before = facade.describe_section().expect("check before ack");
    assert_eq!(before.rows.len(), 1);
    assert_eq!(before.rows[0].status, TaskBoardStatus::Failed);
    assert!(!task_is_acked(&vault, task_ref).expect("read unacked state"));
    // An unacked failure is still expandable by id.
    assert!(facade.describe_card(task_ref).is_ok());
    let ack = facade.tasks_update(task_ref).expect("ack task");
    assert!(ack.acked);
    assert!(task_is_acked(&vault, task_ref).expect("read ack"));
    // Once acked, the failure has left the surface — expand agrees with check.
    assert_eq!(
        facade
            .describe_card(task_ref)
            .expect_err("acked failure is not expandable")
            .code,
        crate::memory::MEMORY_CODE_NOT_FOUND
    );
    let after = facade.describe_section().expect("check after ack");
    assert_eq!(after.rows.len(), 0);
}

#[test]
fn ack_before_failure_is_a_noop_and_failure_still_surfaces() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");

    // The task is Queued (not failed): acking it is a no-op — the bit stays
    // unset so a later failure is not pre-suppressed.
    let premature = facade.tasks_update(task_ref).expect("ack queued task");
    assert!(!premature.acked);
    assert!(!task_is_acked(&vault, task_ref).expect("no ack bit set"));

    // The realization now fails.
    let queue = AttemptQueue::new(&vault);
    let claimed = match queue
        .claim_kind(
            TASK_REALIZE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "worker".to_owned(),
                now: 120,
            },
        )
        .expect("claim")
    {
        ClaimOutcome::Claimed(claimed) => claimed,
        ClaimOutcome::Empty => panic!("created task must be claimable"),
    };
    queue
        .fail(FailAttempt {
            id: claimed.id,
            lease_owner: "worker".to_owned(),
            attempt_count: claimed.attempt_count,
            reason: "failed".to_owned(),
            now: 121,
        })
        .expect("fail task");

    // The failure STILL surfaces — the premature ack did not suppress it.
    let after_fail = facade.describe_section().expect("check after fail");
    assert_eq!(after_fail.rows.len(), 1);
    assert_eq!(after_fail.rows[0].status, TaskBoardStatus::Failed);

    // A real ack (now that it is failed) removes it from the surface.
    let acked = facade.tasks_update(task_ref).expect("ack failed task");
    assert!(acked.acked);
    assert_eq!(
        facade
            .describe_section()
            .expect("check after ack")
            .rows
            .len(),
        0
    );
}

#[test]
fn malformed_dreamer_row_does_not_poison_the_board() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    // A healthy TASK.
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");
    // A malformed dreamer-kind row enqueued through the public queue API (as
    // a downstream product could): 0xC1 is the reserved, never-valid
    // MessagePack marker, so the payload envelope never decodes.
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(_) = queue
        .enqueue(EnqueueAttempt {
            kind: DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
            payload: vec![0xC1],
            dedupe_key: None,
            run_id: None,
            now: 121,
        })
        .expect("enqueue malformed dreamer row")
    else {
        panic!("malformed row must enqueue");
    };
    // The board still reads for the unrelated healthy TASK — one bad row
    // degrades to a bare job in the run tree instead of poisoning the whole
    // read (previously the tree read errored and failed both describe arms).
    let section = facade
        .describe_section()
        .expect("board reads despite the malformed row");
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == task_ref.to_hex())
            .count(),
        1
    );
    // The typed read verb for the healthy TASK also works.
    assert!(facade.describe_card(task_ref).is_ok());
}

/// P1-a, as amended by ONE-1896 §9: a Queued+Leased mix stops what CAN be
/// stopped and asks what cannot.
///
/// The lease still cannot be killed in this transaction, so the task stays
/// visible under it and the receipt never claims the whole target was
/// cancelled. What changed is the queued sibling: leaving it claimable while
/// reporting the cancel handled was the hole — an owner-approved cancel that
/// stopped nothing.
#[test]
fn queued_leased_mix_cancel_is_honest_and_not_hidden() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    grant_cancel(&vault, own, 0xD6);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");
    let task_hex = task_ref.to_hex();
    let queue = AttemptQueue::new(&vault);
    // Second realizing attempt so the task has a Queued + Leased mix.
    assert!(matches!(
        queue
            .enqueue_with_task_ref(
                EnqueueAttempt {
                    kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                    payload: Vec::new(),
                    dedupe_key: None,
                    run_id: None,
                    now: 120,
                },
                Some(task_hex.clone()),
            )
            .expect("enqueue second realization"),
        EnqueueOutcome::Enqueued(_)
    ));
    // Lease exactly one realization; the other stays Queued.
    match queue
        .claim_kind(
            TASK_REALIZE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "w1".to_owned(),
                now: 120,
            },
        )
        .expect("claim one realization")
    {
        ClaimOutcome::Claimed(_) => {}
        ClaimOutcome::Empty => panic!("a realization must be claimable"),
    }

    let cancel = facade
        .cancel(TaskCancelTarget::Task(task_ref))
        .expect("cancel task");
    let records = queue.list().expect("list attempts");
    let section = facade.describe_section().expect("check tasks");

    assert_eq!(
        usize::from(cancel.effected),
        1,
        "the queued sibling really stopped"
    );
    assert_eq!(
        usize::from(cancel.cancel_requested),
        1,
        "the live lease was asked to land"
    );
    assert_eq!(
        cancel.status,
        Some(RunTreeStatus::Running),
        "a live lease keeps the target running, not cancelled"
    );
    assert_eq!(
        usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
        0,
        "nothing is hidden while a lease is live"
    );
    // The lease is untouched — it can only be asked — and the queued sibling
    // is terminal.
    let leased: Vec<_> = records
        .iter()
        .filter(|r| {
            r.task_ref.as_deref() == Some(task_hex.as_str()) && r.state == AttemptState::Leased
        })
        .collect();
    assert_eq!(leased.len(), 1);
    assert_eq!(
        leased[0].cancel_pressure().pending,
        1,
        "the running worker owes an answer"
    );
    assert_eq!(
        records
            .iter()
            .filter(|r| r.task_ref.as_deref() == Some(task_hex.as_str())
                && r.state == AttemptState::Queued)
            .count(),
        0,
        "no pre-lease sibling survives an owner-approved cancel"
    );
    assert_eq!(
        records
            .iter()
            .filter(|r| r.task_ref.as_deref() == Some(task_hex.as_str())
                && r.state == AttemptState::Cancelled)
            .count(),
        1
    );
    // The board still shows the task exactly once.
    assert_eq!(
        section.rows.iter().filter(|row| row.id == task_hex).count(),
        1
    );
}

/// P1-b (TOCTOU): the cancel acts on the transaction-current attempt state,
/// not a pre-txn snapshot. A stale `Leased` snapshot whose live state is now
/// `Queued` must still be cancelled in-txn.
#[test]
fn cancel_uses_in_txn_live_state_not_stale_leased_snapshot() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    grant_cancel(&vault, own, 0xDB);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");
    let task_hex = task_ref.to_hex();
    let queue = AttemptQueue::new(&vault);
    let records = queue.list().expect("list attempts");
    let attempt = records
        .iter()
        .find(|r| r.task_ref.as_deref() == Some(task_hex.as_str()))
        .expect("realizing attempt");
    // Live state is Queued (as if a lease-cleanup requeue already happened).
    assert_eq!(attempt.state, AttemptState::Queued);

    // A deliberately STALE snapshot claims the attempt is still Leased.
    let stale = CancelTargetState {
        owned: true,
        task_ref: Some(task_ref),
        attempts: vec![(attempt.id, AttemptState::Leased)],
        proposal_subject: task_ref,
        target_ref: task_hex.clone(),
    };
    let cancel = facade
        .cancel_with_injected_state_for_test(TaskCancelMode::Auto, stale)
        .expect("cancel with stale snapshot");
    let after = queue.list().expect("list after");

    // The in-txn re-read acts on the LIVE (Queued) state and cancels it,
    // despite the stale Leased snapshot. Trusting the snapshot would skip
    // intervention and leave the attempt claimable.
    assert_eq!(usize::from(cancel.effected), 1);
    assert_eq!(cancel.status, Some(RunTreeStatus::Cancelled));
    assert_eq!(
        after
            .iter()
            .filter(|r| r.task_ref.as_deref() == Some(task_hex.as_str())
                && r.state == AttemptState::Cancelled)
            .count(),
        1
    );
    assert_eq!(
        after
            .iter()
            .filter(|r| r.task_ref.as_deref() == Some(task_hex.as_str())
                && r.state == AttemptState::Queued)
            .count(),
        0
    );
}

/// Membership TOCTOU: a retry between the snapshot and the write txn
/// REPLACES the target's live realization with a new row under the same
/// `task_ref`. Re-reading only the snapshotted ids sees the dead source,
/// reports the task terminally failed, cancels nothing, and leaves the
/// scheduled successor to run and send.
#[test]
fn cancel_reaches_a_retry_minted_between_snapshot_and_write_txn() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    grant_cancel(&vault, own, 0xDC);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");
    let queue = AttemptQueue::new(&vault);
    let claimed = match queue
        .claim_kind(
            TASK_REALIZE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "worker".to_owned(),
                now: 121,
            },
        )
        .expect("claim")
    {
        ClaimOutcome::Claimed(claimed) => claimed,
        ClaimOutcome::Empty => panic!("created task must be claimable"),
    };

    // The snapshot the cancel would have taken: one leased realization.
    let snapshot = CancelTargetState {
        owned: true,
        task_ref: Some(task_ref),
        attempts: vec![(claimed.id, AttemptState::Leased)],
        proposal_subject: task_ref,
        target_ref: task_ref.to_hex(),
    };

    // The executor retries FIRST: the snapshotted row is now a terminal
    // Failed source and a fresh Scheduled row owns the pending send.
    let RetryOutcome::Retried(next) = queue
        .retry(RetryAttempt {
            id: claimed.id,
            lease_owner: "worker".to_owned(),
            attempt_count: claimed.attempt_count,
            backoff_until: 400,
            last_error: Some("rate limited".to_owned()),
            now: 122,
        })
        .expect("retry the leased realization");
    assert_ne!(next.id, claimed.id);

    let cancel = facade
        .cancel_with_injected_state_for_test(TaskCancelMode::Auto, snapshot)
        .expect("cancel with pre-retry snapshot");
    let after = queue.list().expect("list after");

    // The successor is STOPPED, not merely reported around.
    assert_eq!(
        after
            .iter()
            .find(|r| r.id == next.id)
            .expect("successor row")
            .state,
        AttemptState::Cancelled
    );
    // The task is not read off its superseded source: the cancel took
    // effect and the TASK itself is withdrawn, rather than the verb
    // reporting a terminal failure it did not stop.
    assert_eq!(usize::from(cancel.effected), 1);
    assert_eq!(cancel.status, Some(RunTreeStatus::Cancelled));
    assert!(task_is_cancelled(&vault, task_ref).expect("cancel state"));
    // Per-try history survives: the failed source stays point-readable.
    assert_eq!(
        after
            .iter()
            .find(|r| r.id == claimed.id)
            .expect("source row")
            .state,
        AttemptState::Failed
    );
}

/// A retry chain's HEAD carries the task's board status. Any-row precedence
/// (Failed > Scheduled > Done) reads the task off a superseded try: a held
/// retry folds up as `Failed`, and a chain that later SUCCEEDED keeps
/// folding up as `Failed` forever.
#[test]
fn board_reads_a_retry_chain_off_its_head_not_a_superseded_try() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");
    let task_hex = task_ref.to_hex();
    let queue = AttemptQueue::new(&vault);

    // Two retries: three rows, the first two terminally Failed sources.
    let mut head = None;
    for now in [121_u64, 141] {
        let claimed = match queue
            .claim_kind(
                TASK_REALIZE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "worker".to_owned(),
                    now,
                },
            )
            .expect("claim")
        {
            ClaimOutcome::Claimed(claimed) => claimed,
            ClaimOutcome::Empty => panic!("the chain head must be claimable"),
        };
        let RetryOutcome::Retried(next) = queue
            .retry(RetryAttempt {
                id: claimed.id,
                lease_owner: "worker".to_owned(),
                attempt_count: claimed.attempt_count,
                backoff_until: now + 10,
                last_error: Some("upstream refused".to_owned()),
                now: now + 1,
            })
            .expect("retry");
        head = Some(next.id);
    }
    let head = head.expect("chain head");

    // Held retry: the task is deferred, not failed — and only the head is
    // folded, so the board shows one live realization, not three rows.
    let section = facade.describe_section().expect("check tasks");
    let row = section
        .rows
        .iter()
        .find(|row| row.id == task_hex)
        .expect("task row");
    assert_eq!(row.status, TaskBoardStatus::Scheduled);
    assert_eq!(row.folded_job_count, 1);

    // The head SUCCEEDS: the logical task is done, not permanently failed.
    let claimed = match queue
        .claim_kind(
            TASK_REALIZE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "worker".to_owned(),
                now: 200,
            },
        )
        .expect("claim head")
    {
        ClaimOutcome::Claimed(claimed) => claimed,
        ClaimOutcome::Empty => panic!("the chain head must be claimable"),
    };
    assert_eq!(claimed.id, head);
    queue
        .complete(CompleteAttempt {
            id: head,
            lease_owner: "worker".to_owned(),
            attempt_count: claimed.attempt_count,
            now: 201,
        })
        .expect("complete the head");

    let done = facade.describe_section().expect("check after success");
    let row = done
        .rows
        .iter()
        .find(|row| row.id == task_hex)
        .expect("task row");
    assert_eq!(row.status, TaskBoardStatus::Done);
}

/// P1-c: a stored, `cancel`-granted actor cannot DIRECTLY cancel a
/// role-only task it cannot prove it owns — it surfaces a proposal. Role-only
/// ownership is not derivable from storage, so the fallback fails closed.
#[test]
fn role_only_task_cancel_by_foreign_granted_actor_proposes() {
    let (_dir, vault) = open_vault();
    let agent_b = own_agent(&vault);
    grant_cancel(&vault, agent_b, 0xD8);
    // Role-only TASK nominally belonging to some agent A; no stored
    // provenance links it to any actor.
    let task_ref = EntityId::from_bytes([0xB2; 16]).expect("task id");
    vault
        .put_entity(
            &task_ref,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: 120,
                end: 120,
            },
            120,
            &crate::habit::task_body_for_test(TaskRole::Task),
        )
        .expect("put role-only task");
    let outcome = AttemptQueue::new(&vault)
        .enqueue_with_task_ref(
            EnqueueAttempt {
                kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                payload: Vec::new(),
                dedupe_key: None,
                run_id: None,
                now: 120,
            },
            Some(task_ref.to_hex()),
        )
        .expect("enqueue realization");
    let EnqueueOutcome::Enqueued(attempt) = outcome else {
        panic!("realization must enqueue");
    };
    let facade = vault.memory(agent_b, EdgeActorClass::Agent);

    let cancel = facade
        .cancel(TaskCancelTarget::Task(task_ref))
        .expect("cancel role-only task");
    let realization = AttemptQueue::new(&vault)
        .get(attempt.id)
        .expect("read realization")
        .expect("realization exists");
    let section = facade.describe_section().expect("check tasks");

    assert_eq!(usize::from(cancel.effected), 0);
    assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(usize::from(cancel.proposal_ref.is_some()), 1);
    // The realizing attempt is untouched and the task stays visible.
    assert_eq!(realization.state, AttemptState::Queued);
    assert_eq!(
        usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
        0
    );
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == task_ref.to_hex())
            .count(),
        1
    );
}

/// The owner proof a create mints is a REPLICATED companion row, not a
/// node-local index: one role-6 TASK entity, reached from its subject by the
/// ordinary structural `ScopedTo` edge. Both are things the entity/edge CRDT
/// maps already carry, so the peer that materializes the task materializes the
/// authority to cancel it.
#[test]
fn create_mints_the_owner_proof_as_a_scoped_companion_entity() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let created = vault
        .memory(own, EdgeActorClass::Agent)
        .tasks_create(&spec(120))
        .expect("create task");
    let task_ref = created.task_ref.expect("task ref");

    assert_eq!(task_entity_census(&vault), 1);
    assert_eq!(task_authority_fact_census(&vault), 1);
    assert_eq!(
        vault.task_authority_state(task_ref).expect("authority"),
        Some(crate::task_authority::TaskAuthorityState {
            owner_ref: own,
            cancelled: false,
            acked: false,
        })
    );
    let proofs = vault
        .edges_in(&task_ref)
        .expect("inbound edges")
        .into_iter()
        .filter(|edge| edge.kind == crate::edge::EdgeKind::ScopedTo)
        // An inbound edge names the OTHER endpoint: here, the fact scoped to
        // this task.
        .map(|edge| edge.target)
        .filter(|fact_ref| {
            task_entity_role(&vault, *fact_ref).expect("role") == Some(TaskRole::AuthorityFact)
        })
        .count();
    assert_eq!(proofs, 1);
    assert_eq!(attempts_for(&vault, task_ref).len(), 1);
}

/// Cancel-wins reaches the BOARD, not just the fold. A task carrying both an
/// Acked and a Cancelled fact is off the active surface in EITHER order —
/// there is no arrival order in which the acknowledgement wins.
#[test]
fn a_cancelled_task_leaves_the_board_even_when_also_acked() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let create = || {
        facade
            .tasks_create(&spec(120))
            .expect("create task")
            .task_ref
            .expect("task ref")
    };
    let ack_first = create();
    let cancel_first = create();

    vault
        .with_write_txn(|wtxn| {
            ack_task_in_txn(&vault, wtxn, ack_first, own, 121)?;
            cancel_task_in_txn(&vault, wtxn, ack_first, own, 122)?;
            cancel_task_in_txn(&vault, wtxn, cancel_first, own, 121)?;
            ack_task_in_txn(&vault, wtxn, cancel_first, own, 122)
        })
        .expect("append authority facts");

    // Both TASK intents are gone from the surface. Their realizing jobs were
    // never intervened here — the facts were appended directly — so they stay
    // visible as the bare work they are, which is exactly the honesty the
    // board owes: cancelling the INTENT never hides live work.
    let section = facade.describe_section().expect("check tasks");
    assert_eq!(section.rows.iter().filter(|row| row.is_intent).count(), 0);
    for task_ref in [ack_first, cancel_first] {
        assert!(
            !section.rows.iter().any(|row| row.id == task_ref.to_hex()),
            "a cancelled task never renders as a row"
        );
        assert!(task_is_cancelled(&vault, task_ref).expect("cancel state"));
        assert!(task_is_acked(&vault, task_ref).expect("ack state"));
        assert_eq!(
            facade
                .describe_card(task_ref)
                .expect_err("a cancelled task is off the surface")
                .code,
            crate::memory::MEMORY_CODE_NOT_FOUND
        );
    }
}

/// FIX A: a valid typed body can claim any `owner_ref`, so that field is
/// never cancellation authority. The create-time owner record remains the
/// sole proof even if trusted low-level storage rewrites the body.
#[test]
fn typed_task_cancel_ignores_forged_body_owner() {
    let (_dir, vault) = open_vault();
    let attacker = own_agent(&vault);
    let owner = EntityId::from_bytes([0xE2; 16]).expect("owner id");
    put_person(&vault, owner);
    grant_cancel(&vault, attacker, 0xD9);
    let created = vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_create(&spec(120))
        .expect("owner creates task");
    let task_ref = created.task_ref.expect("task ref");
    let mut forged_body = task_verb_body(&vault, task_ref)
        .expect("decode created body")
        .expect("created task is typed");
    forged_body.owner_ref = attacker.to_hex();
    let forged_body = encode_task_verb_body(forged_body);
    vault
        .put_entity(
            &task_ref,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: 121,
                end: 121,
            },
            121,
            &forged_body,
        )
        .expect("rewrite body below facade");
    let forged = task_verb_body(&vault, task_ref)
        .expect("decode forged body")
        .expect("typed task");
    let cancel = vault
        .memory(attacker, EdgeActorClass::Agent)
        .cancel(TaskCancelTarget::Task(task_ref))
        .expect("cancel forged-owner task");
    let task_hex = task_ref.to_hex();
    let attempts = AttemptQueue::new(&vault).list().expect("list attempts");

    assert_eq!(usize::from(forged.owner_ref == attacker.to_hex()), 1);
    assert_eq!(
        task_create_owner(&vault, task_ref).expect("read proven owner"),
        Some(owner)
    );
    assert_eq!(usize::from(cancel.effected), 0);
    assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(usize::from(cancel.proposal_ref.is_some()), 1);
    assert_eq!(
        attempts
            .iter()
            .filter(|attempt| {
                attempt.task_ref.as_deref() == Some(task_hex.as_str())
                    && attempt.state == AttemptState::Queued
            })
            .count(),
        1
    );
    assert_eq!(
        attempts
            .iter()
            .filter(|attempt| {
                attempt.task_ref.as_deref() == Some(task_hex.as_str())
                    && attempt.state == AttemptState::Cancelled
            })
            .count(),
        0
    );
    assert_eq!(
        usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
        0
    );
}

/// P2 F7: a realizing job whose backlink names no surviving intent is
/// re-emitted as a bare job — rendered exactly once, never dropped.
#[test]
fn dangling_backlink_job_still_renders_once() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let missing_task_hex = EntityId::from_bytes([0xC1; 16])
        .expect("missing id")
        .to_hex();
    let outcome = AttemptQueue::new(&vault)
        .enqueue_with_task_ref(
            EnqueueAttempt {
                kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                payload: Vec::new(),
                dedupe_key: None,
                run_id: None,
                now: 120,
            },
            Some(missing_task_hex),
        )
        .expect("enqueue dangling attempt");
    let EnqueueOutcome::Enqueued(attempt) = outcome else {
        panic!("attempt must enqueue");
    };
    let facade = vault.memory(own, EdgeActorClass::Agent);

    let section = facade.describe_section().expect("check tasks");
    let job_id = attempt_hex(attempt.id);

    assert_eq!(
        section.rows.iter().filter(|row| row.id == job_id).count(),
        1
    );
    assert_eq!(section.rows.len(), 1);
}

/// FIX C: projection failure/non-membership cannot consume a live job.
/// Both jobs degrade to bare rows exactly once when their backlink entity
/// cannot produce a TASKS intent.
#[test]
fn unprojectable_task_backlinks_render_jobs_exactly_once() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let malformed = EntityId::from_bytes([0xC2; 16]).expect("malformed id");
    let non_task_role = EntityId::from_bytes([0xC3; 16]).expect("non-task role id");
    let malformed_body = {
        let value = Value::Map(vec![
            (Value::from("role"), Value::from(TaskRole::Task.role_byte())),
            (Value::from("subkind"), Value::from(TASK_VERB_BODY_SUBKIND)),
        ]);
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &value).expect("encode malformed body");
        bytes
    };
    vault
        .put_entity(
            &malformed,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: 120,
                end: 120,
            },
            120,
            &malformed_body,
        )
        .expect("put malformed task");
    vault
        .put_entity(
            &non_task_role,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: 120,
                end: 120,
            },
            120,
            &crate::habit::task_body_for_test(TaskRole::Habit),
        )
        .expect("put non-task role");
    let queue = AttemptQueue::new(&vault);
    let attempts: Vec<_> = [malformed, non_task_role]
        .into_iter()
        .map(|task_ref| {
            match queue
                .enqueue_with_task_ref(
                    EnqueueAttempt {
                        kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                        payload: Vec::new(),
                        dedupe_key: None,
                        run_id: None,
                        now: 120,
                    },
                    Some(task_ref.to_hex()),
                )
                .expect("enqueue realization")
            {
                EnqueueOutcome::Enqueued(attempt) => attempt,
                EnqueueOutcome::Existing(_) => panic!("realization must be fresh"),
            }
        })
        .collect();

    let section = vault
        .memory(own, EdgeActorClass::Agent)
        .describe_section()
        .expect("check tasks");
    let malformed_job = attempt_hex(attempts[0].id);
    let non_task_job = attempt_hex(attempts[1].id);
    let read_failures = task_presence(&vault)
        .expect("scan reports malformed body")
        .read_failures;
    assert_eq!(read_failures.len(), 1);
    assert_eq!(read_failures[0].task_ref, malformed);
    assert_eq!(read_failures[0].stage, TaskPresenceReadStage::PageSlot);
    assert_eq!(
        read_failures[0].kind,
        crate::error::ErrorKind::InvalidTaskBody
    );
    assert_eq!(
        task_presence_for_id(&vault, malformed)
            .expect_err("direct lookup must report invalid body")
            .kind(),
        crate::error::ErrorKind::InvalidTaskBody
    );
    let facade = vault.memory(own, EdgeActorClass::Agent);
    for code in [
        facade.describe_card(malformed).expect_err("bad card").code,
        facade.tasks_update(malformed).expect_err("bad update").code,
    ] {
        assert_ne!(code, crate::memory::MEMORY_CODE_NOT_FOUND);
    }

    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == malformed_job)
            .count(),
        1
    );
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == non_task_job)
            .count(),
        1
    );
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == malformed.to_hex())
            .count(),
        0
    );
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == non_task_role.to_hex())
            .count(),
        0
    );
    assert_eq!(section.rows.len(), 2);
}

/// P2 F8 reaches the AUTHORITY-fact read, not just the typed body: an owner
/// FORK on one task — two distinct Owner facts, which any peer can replicate
/// onto any TASK id — takes exactly THAT row off the board and leaves the rest
/// of the page rendering. Nothing about the fork is softened where it binds:
/// the authority lens still refuses to pick an owner, so the direct-cancel
/// door keeps failing closed on that one task while `describe` survives.
#[test]
fn a_forked_owner_companion_does_not_poison_the_board() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let create = || {
        facade
            .tasks_create(&spec(120))
            .expect("create task")
            .task_ref
            .expect("task ref")
    };
    let forked = create();
    let healthy = create();
    // A second Owner fact naming a DIFFERENT owner, minted through the engine
    // door that replication also writes through: this is the shape a peer's
    // conflicting proof arrives in.
    let intruder = EntityId::from_bytes([0xF7; 16]).expect("intruder id");
    vault
        .with_write_txn(|wtxn| {
            crate::task_authority::put_task_authority_fact_in_txn(
                &vault,
                wtxn,
                crate::task_authority::TaskAuthorityFact {
                    task_ref: forked,
                    kind: crate::task_authority::TaskAuthorityFactKind::Owner,
                    actor_ref: intruder,
                    assigned_ref: None,
                    occurred_at: 121,
                },
            )
            .map(|_fact_ref| ())
        })
        .expect("append the forked owner proof");

    assert!(matches!(
        vault.task_authority_state(forked),
        Err(crate::error::Error::InvariantViolation(_))
    ));

    let section = facade
        .describe_section()
        .expect("check tasks survives the fork");

    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == healthy.to_hex())
            .count(),
        1
    );
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == forked.to_hex())
            .count(),
        0
    );
    // P2 F7: the skipped row's realizing job re-emits as the bare work it is,
    // rather than vanishing with the row it can no longer fold under.
    let orphaned = attempts_for(&vault, forked);
    assert_eq!(orphaned.len(), 1);
    let orphaned_job = attempt_hex(orphaned[0].id);
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == orphaned_job && !row.is_intent)
            .count(),
        1
    );
    assert_eq!(section.rows.len(), 2);
    // The by-id door reports the poisoned proof instead of presenting it as
    // an absent task or answering with bits the fold could not verify.
    let read_failures = task_presence(&vault)
        .expect("scan reports the fork")
        .read_failures;
    assert!(read_failures.iter().any(|failure| {
        failure.task_ref == forked
            && failure.stage == TaskPresenceReadStage::RenderState
            && failure.kind == crate::error::ErrorKind::InvariantViolation
    }));
    assert_eq!(
        task_presence_for_id(&vault, forked)
            .expect_err("by-id door returns the forked proof")
            .kind(),
        crate::error::ErrorKind::InvariantViolation
    );
    for code in [
        facade.describe_card(forked).expect_err("forked card").code,
        facade.tasks_update(forked).expect_err("forked update").code,
    ] {
        assert_eq!(code, crate::memory::MEMORY_CODE_INTERNAL);
    }
}

/// P2 F8 for a MALFORMED authority-fact row: the edge is the index and the
/// body is the claim, so a fact reachable from a task it does not name is
/// refused by the fold — and any peer can ship that edge. The refusal hides
/// exactly one row; the task whose proof was re-pointed still renders and
/// still proves its own owner.
#[test]
fn a_malformed_authority_fact_row_does_not_poison_the_board() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let create = || {
        facade
            .tasks_create(&spec(120))
            .expect("create task")
            .task_ref
            .expect("task ref")
    };
    let poisoned = create();
    let healthy = create();
    let proof = vault
        .edges_in(&healthy)
        .expect("inbound edges")
        .into_iter()
        .find(|edge| {
            edge.kind == crate::edge::EdgeKind::ScopedTo
                && task_entity_role(&vault, edge.target).expect("role")
                    == Some(TaskRole::AuthorityFact)
        })
        .expect("the create minted an owner proof")
        .target;
    // Scoping `healthy`'s proof to `poisoned` as well makes `poisoned`'s fact
    // set unreadable without touching the proof `healthy` really carries.
    vault
        .batch()
        .edge(&proof, crate::edge::EdgeKind::ScopedTo, &poisoned, 0.7)
        .commit()
        .expect("re-point the proof at another task");

    assert!(matches!(
        vault.task_authority_state(poisoned),
        Err(crate::error::Error::Record(
            crate::error::RecordError::InvalidTaskBody(_)
        ))
    ));
    let authority = vault
        .task_authority_state(healthy)
        .expect("the re-pointed proof still names its own subject")
        .expect("healthy task still proves an owner");
    assert_eq!(authority.owner_ref, own);
    assert!(!authority.cancelled);
    assert!(!authority.acked);

    let section = facade
        .describe_section()
        .expect("check tasks survives the poison");

    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == healthy.to_hex())
            .count(),
        1
    );
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == poisoned.to_hex())
            .count(),
        0
    );
    let orphaned = attempts_for(&vault, poisoned);
    assert_eq!(orphaned.len(), 1);
    let orphaned_job = attempt_hex(orphaned[0].id);
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == orphaned_job && !row.is_intent)
            .count(),
        1
    );
    assert_eq!(section.rows.len(), 2);
    let read_failures = task_presence(&vault)
        .expect("scan reports the poison")
        .read_failures;
    assert!(read_failures.iter().any(|failure| {
        failure.task_ref == poisoned
            && failure.stage == TaskPresenceReadStage::RenderState
            && failure.kind == crate::error::ErrorKind::InvalidTaskBody
    }));
    assert_eq!(
        task_presence_for_id(&vault, poisoned)
            .expect_err("by-id door returns the malformed proof")
            .kind(),
        crate::error::ErrorKind::InvalidTaskBody
    );
}

/// SOL-9A-2-R2 F24: acknowledging a failed task only takes it off the board,
/// so a restore over the vault goes ahead past an acknowledgement made since
/// the backup.
#[test]
fn a_restore_goes_ahead_past_a_failure_acknowledged_since() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let task_ref = facade
        .tasks_create(&spec(120))
        .expect("create task")
        .task_ref
        .expect("task ref");
    let queue = AttemptQueue::new(&vault);
    let ClaimOutcome::Claimed(claimed) = queue
        .claim_kind(
            TASK_REALIZE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "worker".to_owned(),
                now: 120,
            },
        )
        .expect("claim")
    else {
        panic!("created task must be claimable");
    };
    queue
        .fail(FailAttempt {
            id: claimed.id,
            lease_owner: "worker".to_owned(),
            attempt_count: claimed.attempt_count,
            reason: "failed".to_owned(),
            now: 121,
        })
        .expect("fail task");
    let backups = tempfile::tempdir().expect("backups");
    let image = backups.path().join("backup");
    vault.snapshot_checkpoint(&image, 130).expect("backup");

    assert!(facade.tasks_update(task_ref).expect("ack task").acked);
    let (restored, _) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &backups.path().join("restored"),
        vault.config.clone(),
        &vault,
        200,
    )
    .expect("an acknowledgement does not block the restore");
    drop(restored);
}

/// Fails the one realization `tasks.create` queued, so its TASK renders FAILED.
fn fail_the_realization(vault: &Vault, now: u64) {
    let queue = AttemptQueue::new(vault);
    let ClaimOutcome::Claimed(claimed) = queue
        .claim_kind(
            TASK_REALIZE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "worker".to_owned(),
                now,
            },
        )
        .expect("claim")
    else {
        panic!("created task must be claimable");
    };
    queue
        .fail(FailAttempt {
            id: claimed.id,
            lease_owner: "worker".to_owned(),
            attempt_count: claimed.attempt_count,
            reason: "failed".to_owned(),
            now: now + 1,
        })
        .expect("fail task");
}

/// F15 / H162: `tasks.update` dismissed any FAILED task by id. A verified
/// actor that does not own the task hid its failure from every board, the
/// owner's included. A dismissal is the task owner's: anyone else gets a
/// typed refusal and the failure stays on the board.
#[test]
fn only_the_task_owner_dismisses_its_failure() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let owner = vault.memory(own, EdgeActorClass::Agent);
    let task_ref = owner
        .tasks_create(&spec(120))
        .expect("create task")
        .task_ref
        .expect("task ref");
    fail_the_realization(&vault, 120);
    let stranger_ref = EntityId::from_bytes([0xE7; 16]).expect("stranger id");
    put_person(&vault, stranger_ref);
    let stranger = vault.memory(stranger_ref, EdgeActorClass::Agent);

    let refused = stranger
        .tasks_update(task_ref)
        .expect_err("a stranger cannot dismiss another actor's failure");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN);
    assert!(!task_is_acked(&vault, task_ref).expect("ack state"));
    let board = owner.describe_section().expect("the owner's board");
    assert_eq!(board.rows.len(), 1);
    assert_eq!(board.rows[0].status, TaskBoardStatus::Failed);

    // A TASK no actor provably owns is nobody's to dismiss either.
    let role_only = EntityId::from_bytes([0xB7; 16]).expect("task id");
    vault
        .put_entity(
            &role_only,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: 130,
                end: 130,
            },
            130,
            &crate::habit::task_body_for_test(TaskRole::Task),
        )
        .expect("put role-only task");
    assert_eq!(
        stranger
            .tasks_update(role_only)
            .expect_err("an unowned task is not dismissable")
            .code,
        MEMORY_CODE_FORBIDDEN
    );

    // The owner's own dismissal lands.
    assert!(owner.tasks_update(task_ref).expect("owner ack").acked);
    assert!(task_is_acked(&vault, task_ref).expect("ack state"));
}

/// F15 / H162, denial as absence: a handle bound to a read credential has no
/// card for a TASK its credential does not read (`describe`), so it cannot
/// dismiss that TASK's failure either, even as the TASK's owner. The refusal
/// is the same NOT_FOUND an absent TASK gives.
#[test]
fn a_credential_dismisses_only_the_failures_it_reads() {
    let (_dir, vault) = open_vault();
    crate::test_support::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id().expect("policy id"),
        &crate::gate::default_policy_manifest().expect("default policy"),
    )
    .expect("install the default policy");
    let own = own_agent(&vault);
    let (near, far) = (
        EntityId::from_bytes([0x5D; 16]).expect("world id"),
        EntityId::from_bytes([0x5E; 16]).expect("world id"),
    );
    let withheld = vault
        .memory(own, EdgeActorClass::Agent)
        .with_birth_position(crate::federation::record_scope::BirthPosition {
            world: Some(far),
            facet: None,
        })
        .tasks_create(&spec(120))
        .expect("the agent creates a TASK")
        .task_ref
        .expect("the create mints a TASK");
    fail_the_realization(&vault, 120);

    let issuer = crate::test_support::test_host_issuer();
    let mut claims = vault
        .ensure_host_root_slip(&issuer)
        .expect("host root")
        .claims;
    claims.slip_id = *blake3::hash(b"one world task dismisser").as_bytes();
    claims.parent_id = None;
    claims.holder_ref = own.to_hex();
    claims.actor_class = Some("agent".into());
    claims.scope = crate::federation::scope_codec::read_preset();
    claims.scope.worlds = [near, crate::claim::base_world_id()]
        .into_iter()
        .map(crate::federation::ScopeId)
        .collect();
    let slip = vault.mint_capability_slip(&issuer, claims).expect("mint");
    let tag = b"one-world-dismiss";
    let proof = vault
        .verify_capability_slip(
            &issuer.public_key(),
            &slip,
            tag,
            &issuer.binding_proof(&slip, tag).expect("binding proof"),
        )
        .expect("verify");
    let bound = vault
        .memory(own, EdgeActorClass::Agent)
        .with_read_proof(&proof);

    assert_eq!(
        bound
            .tasks_update(withheld)
            .expect_err("a TASK the credential does not read is absent")
            .code,
        crate::memory::MEMORY_CODE_NOT_FOUND
    );
    assert!(!task_is_acked(&vault, withheld).expect("ack state"));
    // The unbound owner still dismisses it.
    assert!(
        vault
            .memory(own, EdgeActorClass::Agent)
            .tasks_update(withheld)
            .expect("owner ack")
            .acked
    );
}

/// A TASK body carrying only a `Task` role and `subkind`. It stores, since a
/// TASK put needs only a role that decodes, but neither the typed reader nor
/// the connector-send reader decodes it.
fn undecodable_task_body(subkind: &str) -> Vec<u8> {
    let value = Value::Map(vec![
        (Value::from("role"), Value::from(TaskRole::Task.role_byte())),
        (Value::from("subkind"), Value::from(subkind)),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value).expect("encode task body");
    bytes
}

fn put_task_body(vault: &Vault, task_ref: EntityId, body: &[u8]) {
    let now = crate::unix_seconds_now() + 5;
    vault
        .put_entity(
            &task_ref,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            body,
        )
        .expect("put task body");
}

/// The answer the dismissal's write transaction acts on.
fn owned_in_txn(vault: &Vault, actor: EntityId, task_ref: EntityId) -> Option<bool> {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    task_owned_in(vault, &rtxn, actor, task_ref)
        .expect("a TASK body never makes ownership an error")
}

/// F15 (Bugbot on #1444): the ownership check decoded the TASK body before it
/// read the Owner fact, so a body rewritten into a shape no reader decodes
/// turned the owner's own dismissal and cancel into errors. The Owner fact
/// decides first: the owner dismisses the failure and cancels directly. The
/// status such a row folds up from its jobs never reads live work as failed,
/// so dismissing a row whose job still runs stays a no-op.
#[test]
fn the_owner_dismisses_and_cancels_a_task_whose_body_no_longer_decodes() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    grant_cancel(&vault, own, 0xD6);
    let owner = vault.memory(own, EdgeActorClass::Agent);
    let create = || {
        owner
            .tasks_create(&spec(120))
            .expect("create task")
            .task_ref
            .expect("task ref")
    };
    let queue = AttemptQueue::new(&vault);
    for subkind in [
        TASK_VERB_BODY_SUBKIND,
        crate::outbound::CONNECTOR_SEND_TASK_SUBKIND,
    ] {
        let failed = create();
        fail_the_realization(&vault, 120);
        put_task_body(&vault, failed, &undecodable_task_body(subkind));
        assert!(
            owner.tasks_update(failed).expect("owner ack").acked,
            "{subkind}"
        );
        assert!(task_is_acked(&vault, failed).expect("ack state"));

        let queued = create();
        put_task_body(&vault, queued, &undecodable_task_body(subkind));
        let cancel = owner
            .cancel(TaskCancelTarget::Task(queued))
            .expect("owner cancel");
        assert_eq!(cancel.approval, ClaimApprovalStatus::Auto, "{subkind}");
        assert!(cancel.effected, "{subkind}");
        let realizations = attempts_for(&vault, queued);
        assert_eq!(realizations.len(), 1);
        assert_eq!(realizations[0].state, AttemptState::Cancelled);

        let running = create();
        let ClaimOutcome::Claimed(_) = queue
            .claim_kind(
                TASK_REALIZE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "worker".to_owned(),
                    now: 120,
                },
            )
            .expect("claim")
        else {
            panic!("created task must be claimable");
        };
        put_task_body(&vault, running, &undecodable_task_body(subkind));
        assert!(
            !owner.tasks_update(running).expect("no-op").acked,
            "{subkind}"
        );
        assert!(!task_is_acked(&vault, running).expect("ack state"));
    }
}

/// F15 (Bugbot on #1444): for a TASK whose body no longer decodes, anyone the
/// Owner fact does not name gets the answer an unowned TASK gives: a refused
/// dismissal and a cancel that only proposes. Never a body-decode error, never
/// a direct cancel. With no Owner fact at all, the TASK is nobody's.
#[test]
fn a_stranger_gets_the_proposal_answer_for_a_task_whose_body_no_longer_decodes() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let stranger_ref = EntityId::from_bytes([0xE7; 16]).expect("stranger id");
    put_person(&vault, stranger_ref);
    grant_cancel(&vault, own, 0xD6);
    let owner = vault.memory(own, EdgeActorClass::Agent);
    let stranger = vault.memory(stranger_ref, EdgeActorClass::Agent);
    for (subkind, seed) in [
        (TASK_VERB_BODY_SUBKIND, 0xB8),
        (crate::outbound::CONNECTOR_SEND_TASK_SUBKIND, 0xB9),
    ] {
        let owned = owner
            .tasks_create(&spec(120))
            .expect("create task")
            .task_ref
            .expect("task ref");
        put_task_body(&vault, owned, &undecodable_task_body(subkind));
        let ownerless = EntityId::from_bytes([seed; 16]).expect("task id");
        put_task_body(&vault, ownerless, &undecodable_task_body(subkind));

        for (facade, task_ref) in [
            (&stranger, owned),
            (&stranger, ownerless),
            (&owner, ownerless),
        ] {
            let refused = facade
                .tasks_update(task_ref)
                .expect_err("not the caller's failure to dismiss");
            assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{subkind}");
            let cancel = facade
                .cancel(TaskCancelTarget::Task(task_ref))
                .expect("a cancel proposal");
            assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed, "{subkind}");
            assert!(!cancel.effected);
        }
        assert!(!task_is_acked(&vault, owned).expect("ack state"));
        let realizations = attempts_for(&vault, owned);
        assert_eq!(realizations.len(), 1);
        assert_eq!(realizations[0].state, AttemptState::Queued);
    }
}

/// F15 (Bugbot on #1444): the dismissal's check, cancel's check and the
/// in-transaction re-check were two implementations that disagreed. Over every
/// TASK body shape both entry points now act exactly as the in-transaction
/// answer says. That answer is the Owner fact's, or else a validated
/// connector send's actor: a raw connector-shaped put naming an actor, with no
/// assignment to its connector, is not that actor's.
#[test]
fn both_entry_points_follow_the_in_transaction_ownership_answer() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let stranger_ref = EntityId::from_bytes([0xE7; 16]).expect("stranger id");
    put_person(&vault, stranger_ref);
    vault
        .mint_standing_outbound_grant(
            &EntityId::from_bytes([0xD3; 16]).expect("send grant id"),
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
    grant_cancel(&vault, own, 0xD6);
    let owner = vault.memory(own, EdgeActorClass::Agent);
    let stranger = vault.memory(stranger_ref, EdgeActorClass::Agent);
    let create = || {
        owner
            .tasks_create(&spec(120))
            .expect("create task")
            .task_ref
            .expect("task ref")
    };

    let typed = create();
    owner
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
    let connector = vault.connector_send_tasks().expect("connector tasks")[0].task_ref;
    let role_only = EntityId::from_bytes([0xB1; 16]).expect("task id");
    put_task_body(
        &vault,
        role_only,
        &crate::habit::task_body_for_test(TaskRole::Task),
    );
    let unassigned_copy = EntityId::from_bytes([0xB2; 16]).expect("task id");
    let connector_raw = vault
        .get_raw(&connector)
        .expect("read connector task")
        .expect("connector task");
    put_task_body(
        &vault,
        unassigned_copy,
        &connector_raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    );
    let undecodable_typed = create();
    put_task_body(
        &vault,
        undecodable_typed,
        &undecodable_task_body(TASK_VERB_BODY_SUBKIND),
    );
    let undecodable_connector = create();
    put_task_body(
        &vault,
        undecodable_connector,
        &undecodable_task_body(crate::outbound::CONNECTOR_SEND_TASK_SUBKIND),
    );
    let undecodable_ownerless = EntityId::from_bytes([0xB3; 16]).expect("task id");
    put_task_body(
        &vault,
        undecodable_ownerless,
        &undecodable_task_body(TASK_VERB_BODY_SUBKIND),
    );

    // (shape, TASK, the owner's answer); a stranger's is always `Some(false)`.
    for (shape, task_ref, owner_answer) in [
        ("typed", typed, true),
        ("connector send", connector, true),
        ("role-only", role_only, false),
        ("unassigned connector-shaped copy", unassigned_copy, false),
        ("undecodable typed", undecodable_typed, true),
        ("undecodable connector send", undecodable_connector, true),
        (
            "undecodable with no Owner fact",
            undecodable_ownerless,
            false,
        ),
    ] {
        for (caller, facade, expected) in [
            (stranger_ref, &stranger, false),
            (own, &owner, owner_answer),
        ] {
            assert_eq!(
                owned_in_txn(&vault, caller, task_ref),
                Some(expected),
                "{shape}: in-transaction answer"
            );
            let dismissed = match facade.tasks_update(task_ref) {
                Ok(_) => true,
                Err(error) if error.code == MEMORY_CODE_FORBIDDEN => false,
                Err(error) => panic!("{shape}: dismissal failed with {}", error.code),
            };
            assert_eq!(dismissed, expected, "{shape}: dismissal");
            let cancel = facade
                .cancel(TaskCancelTarget::Task(task_ref))
                .unwrap_or_else(|error| panic!("{shape}: cancel failed with {}", error.code));
            assert_eq!(
                cancel.approval == ClaimApprovalStatus::Auto,
                expected,
                "{shape}: cancel"
            );
        }
    }
}
