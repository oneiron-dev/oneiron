//! Tick commitment-lane tests: merge and tie, admission, and fire tests.

use oneiron::{commitment_schedule, commitment_wake};

use super::super::*;
use super::*;

/// CMT-2 (ONE-1539). Two independent durable sources, one merge rule:
/// the earlier instant arms the timer and a TIE keeps the attempt, so
/// wiring the commitment lane in can never displace a deadline the attempt
/// lane already surfaced. Projection runs INSIDE the read (ARCH-0026: no
/// scheduler, no poll), and `LifecycleDue` structurally cannot reach the
/// timer feed.
#[test]
fn commitment_due_deadline_merges_with_attempt_queue_min() {
    let micro_at_3s = CommitmentDeadline {
        due_at_ms: 3_000,
        scope: DreamerConsolidationScope::Micro,
    };

    // The index stores SECONDS; the tick lane speaks MILLISECONDS, and a
    // commitment deadline is always the Micro lane.
    assert_eq!(
        merged_deadline(5, DreamerConsolidationScope::Meso),
        Some(micro_at_3s),
        "attempt 5s vs commitment 3s: the commitment lane wins"
    );
    assert_eq!(
        merged_deadline(2, DreamerConsolidationScope::Meso),
        Some(CommitmentDeadline {
            due_at_ms: 2_000,
            scope: DreamerConsolidationScope::Meso,
        }),
        "attempt 2s vs commitment 3s: the attempt lane wins"
    );
    assert_eq!(
        merged_deadline(3, DreamerConsolidationScope::Meso),
        Some(CommitmentDeadline {
            due_at_ms: 3_000,
            scope: DreamerConsolidationScope::Meso,
        }),
        "equal timestamps keep the attempt deadline"
    );

    // A FUTURE Project row is read and NOT consumed.
    let (dir, vault) = open_vault();
    seed_project_row_at(&vault, 3);
    let (clock, now) = movable_clock(0);
    let mut source = CommitmentDueDeadlines::with_clock(&vault, Arc::clone(&now));
    assert_eq!(source.next_deadline().expect("read"), Some(micro_at_3s));
    let before = vault.commitment_due_index_snapshot().expect("snapshot");
    assert_eq!(
        before.phase_minimum(commitment_schedule::CommitmentDuePhase::Project),
        Some(3)
    );
    assert_eq!(
        before.phase_minimum(commitment_schedule::CommitmentDuePhase::Lead),
        None,
        "reading a future deadline must not mint anything"
    );

    // Advance past it: the row is work to DO. It is consumed, the
    // occurrence mints, and — since CMT-3 (ONE-1540) — the Lead row the
    // projection just left at that same instant is consumed too, so the
    // timer arms on what remains rather than on either row it spent.
    clock.store(3_000, Ordering::SeqCst);
    let due_at_103s = CommitmentDeadline {
        due_at_ms: 103_000,
        scope: DreamerConsolidationScope::Micro,
    };
    assert_eq!(
        source.next_deadline().expect("read"),
        Some(due_at_103s),
        "Project and Lead are both spent; the Due row is what is left to arm on"
    );
    let after = vault.commitment_due_index_snapshot().expect("snapshot");
    assert_eq!(
        after.phase_minimum(commitment_schedule::CommitmentDuePhase::Project),
        None
    );
    assert_eq!(
        after.phase_minimum(commitment_schedule::CommitmentDuePhase::Lead),
        None,
        "the minted occurrence's Lead row fired and settled in the same read"
    );
    assert_eq!(
        after.phase_minimum(commitment_schedule::CommitmentDuePhase::Due),
        Some(103)
    );
    assert_eq!(
        source.next_deadline().expect("read"),
        Some(due_at_103s),
        "the consumed timestamps never re-surface"
    );

    // A corrupt index is the one place "nothing is due" would be a lie.
    drop(source);
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("reopen");
    vault
        .corrupt_commitment_due_row_for_test(1)
        .expect("plant a malformed row");
    let mut corrupt = CommitmentDueDeadlines::with_clock(&vault, Arc::clone(&now));
    assert!(
        corrupt.next_deadline().is_err(),
        "a corrupt due index must surface as Err, never as Ok(None)"
    );
    let local = vault_client_node_id(&vault);
    let mut merged = AttemptQueueDeadlines::with_commitment_clock(&vault, local, now);
    assert!(
        merged.next_deadline().is_err(),
        "the merge must propagate the commitment lane's failure"
    );
}

/// CMT-3 (ONE-1540). The whole producer-side path in ONE caller read:
/// the extended source still consumes due Project work, the Lead row it
/// leaves behind commits exactly one durable Event/Micro Dreamer attempt,
/// the phase settles, and the EXISTING attempt-queue merge surfaces that
/// brand-new attempt's deadline. The supervisor sees an ordinary
/// `Tick::Deadline`; no `Tick::Wake` and no new tick variant exist.
#[tokio::test(start_paused = true)]
async fn due_commitment_phase_enqueues_then_returns_attempt_deadline() {
    let (_dir, vault) = open_vault();
    vault.clock.set(3);
    seed_project_row_at(&vault, 3);
    let local = vault_client_node_id(&vault);
    let (_clock, now) = movable_clock(3_000);
    assert!(
        micro_attempts(&vault).is_empty(),
        "nothing is queued before the read"
    );

    let deadline = AttemptQueueDeadlines::with_commitment_clock(&vault, local, Arc::clone(&now))
        .next_deadline()
        .expect("merged read")
        .expect("the newly enqueued attempt arms the timer");

    // The Project row was consumed and the occurrence minted.
    let snapshot = vault.commitment_due_index_snapshot().expect("snapshot");
    assert_eq!(
        snapshot.phase_minimum(commitment_schedule::CommitmentDuePhase::Project),
        None
    );
    // Exactly one durable attempt, tagged as the commitment wake event that
    // only the Event/Micro fire door produces, keyed by the phase key.
    let attempts = micro_attempts(&vault);
    assert_eq!(attempts.len(), 1, "one due phase, one durable attempt");
    let payload = oneiron::dreamer_runner::decode_dreamer_attempt_payload(&attempts[0].payload)
        .expect("dreamer payload");
    let event = commitment_wake::decode_commitment_wake_event(&payload.input)
        .expect("typed decode")
        .expect("the attempt carries a commitment wake event");
    assert_eq!(event.phase, commitment_wake::CommitmentWakePhase::Lead);
    assert_eq!(event.fire_at, 3);
    assert_eq!(event.due_at, 103);
    assert_eq!(
        attempts[0].run_id.as_deref(),
        Some(event.idempotency_key().as_str()),
        "the run id IS the phase key"
    );
    assert_eq!(
        payload.attempt_type,
        DreamerConsolidationScope::Micro.as_str()
    );

    // The Lead phase settled; only the Due row is still actionable.
    assert_eq!(
        snapshot.phase_minimum(commitment_schedule::CommitmentDuePhase::Lead),
        None
    );
    assert_eq!(
        snapshot.phase_minimum(commitment_schedule::CommitmentDuePhase::Due),
        Some(103)
    );

    // Every synthesized COMMITMENT deadline is Micro; the merge returned the
    // new attempt's deadline (3 s) rather than the commitment side's Due row
    // (103 s), which is the whole point of running the commitment lane first.
    assert_eq!(
        CommitmentDueDeadlines::with_clock(&vault, Arc::clone(&now))
            .next_deadline()
            .expect("commitment read"),
        Some(CommitmentDeadline {
            due_at_ms: 103_000,
            scope: DreamerConsolidationScope::Micro,
        })
    );
    assert_eq!(
        deadline,
        CommitmentDeadline {
            due_at_ms: 3_000,
            scope: DreamerConsolidationScope::Micro,
        },
        "the caller read surfaces the attempt the same read enqueued"
    );

    // The supervisor's view: an ordinary already-due Deadline tick.
    let timer = TimerTick::with_clock(
        ScriptedDeadlines::new(vec![Some(deadline)]),
        Arc::clone(&now),
    );
    let (push, wake, hint) = PushTick::channel(COALESCE_FLOOR_MS);
    drop(wake);
    drop(hint);
    let mut hybrid = HybridTick::new(timer, push);
    let tick = hybrid.next_tick().await;
    assert_eq!(tick, Some(Tick::Deadline(deadline)));
    assert!(
        !matches!(tick, Some(Tick::Wake(_))),
        "the timer layer never synthesizes a wake-class tick"
    );
}
