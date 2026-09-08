//! Tick commitment-lane tests: merge and tie, admission, and fire tests.

use oneiron::{commitment_schedule, commitment_wake};

use super::super::*;
use super::*;

#[test]
fn attempt_queue_deadlines_hide_macro_until_local_home_election() {
    let (_dir, vault) = open_vault();
    let local = vault_client_node_id(&vault);
    enqueue(
        &vault,
        DreamerConsolidationScope::Macro,
        "macro-attempt",
        10,
    );

    // No home node elected: macro admission would refuse (NoHomeNode)
    // without mutating the row, so the overdue deadline must not
    // surface and re-tick forever.
    let mut source = AttemptQueueDeadlines::new(&vault, local);
    assert_eq!(source.next_deadline().expect("read"), None);

    // Local vault identity elected home: both admission checks pass and
    // the same row surfaces on the very next re-read.
    elect_home(&vault, local, 15);
    assert_eq!(
        source.next_deadline().expect("read"),
        Some(CommitmentDeadline {
            due_at_ms: 10_000,
            scope: DreamerConsolidationScope::Macro,
        })
    );
}

#[test]
fn attempt_queue_deadlines_on_foreign_home_skip_macro_but_keep_other_lanes() {
    let (_dir, vault) = open_vault();
    let local = vault_client_node_id(&vault);
    let foreign = local.wrapping_add(1).max(1);
    enqueue(
        &vault,
        DreamerConsolidationScope::Macro,
        "macro-attempt",
        10,
    );
    enqueue(
        &vault,
        DreamerConsolidationScope::Micro,
        "micro-attempt",
        20,
    );
    elect_home(&vault, foreign, 25);

    // Local node is not the elected home: the earlier macro deadline is
    // filtered (admission would refuse NotHomeNode without progress)
    // while the micro lane keeps flowing — no spin, no starvation.
    let mut source = AttemptQueueDeadlines::new(&vault, local);
    assert_eq!(
        source.next_deadline().expect("read"),
        Some(CommitmentDeadline {
            due_at_ms: 20_000,
            scope: DreamerConsolidationScope::Micro,
        })
    );
}

#[test]
fn attempt_queue_deadlines_skip_macro_when_designation_matches_but_vault_identity_differs() {
    // P2 (codex r4): a host can pass local_node_id equal to a (stale/
    // copied) home designation that is NOT this vault's stable client
    // id. Admission errors with identity-mismatch without mutating the
    // row; the deadline filter must suppress that macro too.
    let (_dir, vault) = open_vault();
    let vault_id = vault_client_node_id(&vault);
    let spoofed = vault_id.wrapping_add(99).max(1);
    assert_ne!(spoofed, vault_id);
    enqueue(&vault, DreamerConsolidationScope::Macro, "macro-spoof", 10);
    enqueue(&vault, DreamerConsolidationScope::Micro, "micro-ok", 30);
    // Designation equals the spoofed local_node_id, not vault identity.
    elect_home(&vault, spoofed, 20);

    let mut source = AttemptQueueDeadlines::new(&vault, spoofed);
    assert_eq!(
        source.next_deadline().expect("read"),
        Some(CommitmentDeadline {
            due_at_ms: 30_000,
            scope: DreamerConsolidationScope::Micro,
        }),
        "macro must stay suppressed when vault identity ≠ local_node_id"
    );

    // Both match (honest local = vault id = designation): macro surfaces.
    elect_home(&vault, vault_id, 40);
    let mut honest = AttemptQueueDeadlines::new(&vault, vault_id);
    assert_eq!(
        honest.next_deadline().expect("read"),
        Some(CommitmentDeadline {
            due_at_ms: 10_000,
            scope: DreamerConsolidationScope::Macro,
        }),
        "macro surfaces when designation AND vault identity both match"
    );
}

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

/// CMT-3 (ONE-1540). `LifecycleDue` is a lapse marker and ONE-1541's sweep
/// input: it stays visible to `next_due_at()` for CROSS-ARCH-0022, but it
/// can neither arm the timer nor be acknowledged here, so a
/// LifecycleDue-only index is a quiet lane rather than a supervisor spin.
#[test]
fn lifecycle_due_never_arms_timer() {
    let (_dir, vault) = open_vault();
    seed_project_row_at(&vault, 3);
    let (clock, now) = movable_clock(3_000);
    let mut source = CommitmentDueDeadlines::with_clock(&vault, Arc::clone(&now));

    // Project + Lead spend themselves; the Due row arms the timer.
    assert_eq!(
        source.next_deadline().expect("read"),
        Some(CommitmentDeadline {
            due_at_ms: 103_000,
            scope: DreamerConsolidationScope::Micro,
        })
    );

    // Past the due instant the Due row fires and settles too. What is left
    // is a non-empty index whose only row is a lapse marker.
    clock.store(103_000, Ordering::SeqCst);
    assert_eq!(
        source.next_deadline().expect("read"),
        None,
        "a LifecycleDue-only index is a quiet timer lane"
    );
    let lifecycle_only = vault.commitment_due_index_snapshot().expect("snapshot");
    assert_eq!(lifecycle_only.next_due_at(), Some(103));
    assert_eq!(
        lifecycle_only.phase_minimum(commitment_schedule::CommitmentDuePhase::LifecycleDue),
        Some(103)
    );
    assert!(
        vault
            .next_actionable_wake_phase()
            .expect("wake read")
            .is_none(),
        "LifecycleDue is not an actionable wake phase"
    );

    // Re-reading does not spin: no deadline, no further attempt.
    assert_eq!(source.next_deadline().expect("read"), None);
    assert_eq!(
        micro_attempts(&vault).len(),
        2,
        "one attempt per phase — Lead and Due — and nothing more"
    );
}
