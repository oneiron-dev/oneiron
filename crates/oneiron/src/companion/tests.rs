use super::*;
pub(crate) mod support;
use crate::{
    AttemptQueue, VaultConfig, attempt_queue::AttemptState, attempt_queue::EnqueueAttempt,
    attempt_queue::EnqueueOutcome,
};

use crate::test_util::entity;

fn companion_task(kind: CompanionTaskKind, key: CompanionRecordKey) -> Result<CompanionTask> {
    CompanionTask::new(kind, key)
}

#[test]
fn companion_queue_fixture_enqueues_claims_completes_and_retries() -> Result<()> {
    let clock = crate::ports::ManualClock::new(0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
    let companion_queue = CompanionQueue::new(&vault);
    let generic_queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(generic) = generic_queue.enqueue(EnqueueAttempt {
        kind: "claim_extraction".to_owned(),
        payload: b"generic".to_vec(),
        dedupe_key: Some("turn:generic".to_owned()),
        run_id: Some("run-generic".to_owned()),
        now: {
            clock.set(5);
            5
        },
    })?
    else {
        panic!("expected generic enqueue");
    };

    let personal = CompanionScope::personal(entity(0x31));
    let context_task = companion_task(
        CompanionTaskKind::Context,
        CompanionRecordKey::relationship(personal.clone(), entity(0x32), entity(0x33)),
    )?;
    let context_dedupe_key = context_task.dedupe_key();
    let EnqueueCompanionTaskOutcome::Enqueued(context_status) =
        companion_queue.enqueue(EnqueueCompanionTask {
            task: context_task.clone(),
            run_id: Some("run-context".to_owned()),
            now: {
                clock.set(10);
                10
            },
        })?
    else {
        panic!("expected context enqueue");
    };
    assert_eq!(context_status.attempt.kind, COMPANION_TASK_ATTEMPT_KIND);
    assert_eq!(context_status.attempt.state, AttemptState::Queued);
    assert_eq!(
        context_status.attempt.dedupe_key.as_deref(),
        Some(context_dedupe_key.as_str())
    );
    assert_eq!(context_status.task, context_task);

    let EnqueueCompanionTaskOutcome::Existing(duplicate_context) =
        companion_queue.enqueue(EnqueueCompanionTask {
            task: context_task,
            run_id: Some("run-context-duplicate".to_owned()),
            now: {
                clock.set(11);
                11
            },
        })?
    else {
        panic!("expected context dedupe hit");
    };
    assert_eq!(duplicate_context.attempt.id, context_status.attempt.id);

    let ClaimCompanionTaskOutcome::Claimed(claimed_context) =
        companion_queue.claim(ClaimCompanionTask {
            lease_owner: "companion-worker".to_owned(),
            now: {
                clock.set(20);
                20
            },
        })?
    else {
        panic!("expected context claim");
    };
    assert_eq!(claimed_context.attempt.id, context_status.attempt.id);
    assert_eq!(claimed_context.attempt.state, AttemptState::Leased);
    assert_eq!(claimed_context.attempt.attempt_count, 1);
    assert_eq!(
        generic_queue
            .get(generic.id)?
            .expect("generic attempt")
            .state,
        AttemptState::Queued,
        "companion claim must skip non-companion attempts"
    );

    let CompleteCompanionTaskOutcome::Completed(completed_context) =
        companion_queue.complete(CompleteCompanionTask {
            id: claimed_context.attempt.id,
            lease_owner: "companion-worker".to_owned(),
            attempt_count: claimed_context.attempt.attempt_count,
            now: {
                clock.set(21);
                21
            },
        })?
    else {
        panic!("expected context complete");
    };
    assert_eq!(completed_context.attempt.state, AttemptState::Completed);
    assert_eq!(
        companion_queue
            .status(completed_context.attempt.id)?
            .expect("context status")
            .attempt
            .state,
        AttemptState::Completed
    );

    let profile_task = companion_task(
        CompanionTaskKind::Profile,
        CompanionRecordKey::persona(personal, entity(0x34)),
    )?;
    let EnqueueCompanionTaskOutcome::Enqueued(profile_status) =
        companion_queue.enqueue(EnqueueCompanionTask {
            task: profile_task.clone(),
            run_id: Some("run-profile".to_owned()),
            now: {
                clock.set(30);
                30
            },
        })?
    else {
        panic!("expected profile enqueue");
    };
    let ClaimCompanionTaskOutcome::Claimed(claimed_profile) =
        companion_queue.claim(ClaimCompanionTask {
            lease_owner: "companion-worker".to_owned(),
            now: {
                clock.set(31);
                31
            },
        })?
    else {
        panic!("expected profile claim");
    };
    assert_eq!(claimed_profile.attempt.id, profile_status.attempt.id);

    let RetryCompanionTaskOutcome::Retried(retried_profile) =
        companion_queue.retry(RetryCompanionTask {
            id: claimed_profile.attempt.id,
            lease_owner: "companion-worker".to_owned(),
            attempt_count: claimed_profile.attempt.attempt_count,
            backoff_until: 40,
            last_error: Some("profile model unavailable".to_owned()),
            now: {
                clock.set(32);
                32
            },
        })?;
    // Retry mints a fresh ATTEMPT carrying the same companion task forward; the
    // retryable reason stays on the finalized source try.
    assert_ne!(retried_profile.attempt.id, profile_status.attempt.id);
    assert_eq!(retried_profile.attempt.state, AttemptState::Scheduled);
    assert_eq!(retried_profile.attempt.scheduled_at, Some(40));
    assert_eq!(retried_profile.attempt.backoff_until, None);
    assert_eq!(
        retried_profile.attempt.retry_of,
        Some(profile_status.attempt.id)
    );
    assert_eq!(retried_profile.attempt.last_error, None);
    assert_eq!(retried_profile.task, profile_task);
    let failed_try = companion_queue
        .status(profile_status.attempt.id)?
        .expect("source try status");
    assert_eq!(failed_try.attempt.state, AttemptState::Failed);
    assert_eq!(
        failed_try.attempt.last_error.as_deref(),
        Some("profile model unavailable")
    );
    assert_eq!(
        companion_queue.claim(ClaimCompanionTask {
            lease_owner: "too-early".to_owned(),
            now: {
                clock.set(39);
                39
            },
        })?,
        ClaimCompanionTaskOutcome::Empty
    );

    let ClaimCompanionTaskOutcome::Claimed(reclaimed_profile) =
        companion_queue.claim(ClaimCompanionTask {
            lease_owner: "companion-worker".to_owned(),
            now: {
                clock.set(40);
                40
            },
        })?
    else {
        panic!("expected profile reclaim");
    };
    assert_eq!(reclaimed_profile.attempt.id, retried_profile.attempt.id);
    assert_eq!(reclaimed_profile.attempt.attempt_count, 1);
    let CompleteCompanionTaskOutcome::Completed(completed_profile) =
        companion_queue.complete(CompleteCompanionTask {
            id: reclaimed_profile.attempt.id,
            lease_owner: "companion-worker".to_owned(),
            attempt_count: reclaimed_profile.attempt.attempt_count,
            now: {
                clock.set(41);
                41
            },
        })?
    else {
        panic!("expected profile complete");
    };
    assert_eq!(completed_profile.attempt.state, AttemptState::Completed);
    assert_eq!(completed_profile.task, profile_task);

    let memory_task = companion_task(
        CompanionTaskKind::Memory,
        CompanionRecordKey::persona(CompanionScope::neutral(), entity(0x35)),
    )?;
    let EnqueueCompanionTaskOutcome::Enqueued(memory_status) =
        companion_queue.enqueue(EnqueueCompanionTask {
            task: memory_task.clone(),
            run_id: Some("run-memory".to_owned()),
            now: {
                clock.set(50);
                50
            },
        })?
    else {
        panic!("expected memory enqueue");
    };
    let ClaimCompanionTaskOutcome::Claimed(claimed_memory) =
        companion_queue.claim(ClaimCompanionTask {
            lease_owner: "companion-worker".to_owned(),
            now: {
                clock.set(51);
                51
            },
        })?
    else {
        panic!("expected memory claim");
    };
    assert_eq!(claimed_memory.attempt.id, memory_status.attempt.id);
    let FailCompanionTaskOutcome::Failed(failed_memory) =
        companion_queue.fail(FailCompanionTask {
            id: claimed_memory.attempt.id,
            lease_owner: "companion-worker".to_owned(),
            attempt_count: claimed_memory.attempt.attempt_count,
            reason: "memory task exhausted retries".to_owned(),
            now: {
                clock.set(52);
                52
            },
        })?
    else {
        panic!("expected memory fail");
    };
    assert_eq!(failed_memory.attempt.state, AttemptState::Failed);
    assert_eq!(
        companion_queue
            .status(failed_memory.attempt.id)?
            .expect("memory status")
            .attempt
            .last_error
            .as_deref(),
        Some("memory task exhausted retries")
    );
    assert_eq!(failed_memory.task, memory_task);

    let ClaimOutcome::Claimed(claimed_generic) = generic_queue.claim(ClaimAttempt {
        lease_owner: "generic-worker".to_owned(),
        now: {
            clock.set(60);
            60
        },
    })?
    else {
        panic!("expected generic claim after companion work");
    };
    assert_eq!(claimed_generic.id, generic.id);
    assert!(
        companion_queue
            .complete(CompleteCompanionTask {
                id: claimed_generic.id,
                lease_owner: "generic-worker".to_owned(),
                attempt_count: claimed_generic.attempt_count,
                now: {
                    clock.set(61);
                    61
                },
            })
            .is_err()
    );
    assert_eq!(
        generic_queue
            .get(claimed_generic.id)?
            .expect("generic attempt persisted")
            .state,
        AttemptState::Leased
    );

    Ok(())
}

#[test]
fn companion_queue_claim_fails_undecodable_task_payload() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let companion_queue = CompanionQueue::new(&vault);
    let generic_queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(invalid_task) = generic_queue.enqueue(EnqueueAttempt {
        kind: COMPANION_TASK_ATTEMPT_KIND.to_owned(),
        payload: b"not-msgpack".to_vec(),
        dedupe_key: Some("companion:invalid".to_owned()),
        run_id: Some("run-invalid".to_owned()),
        now: 70,
    })?
    else {
        panic!("expected invalid companion task enqueue");
    };

    assert_eq!(
        companion_queue.claim(ClaimCompanionTask {
            lease_owner: "companion-worker".to_owned(),
            now: 80,
        })?,
        ClaimCompanionTaskOutcome::Empty
    );

    let failed = generic_queue
        .get(invalid_task.id)?
        .expect("invalid companion task persisted");
    assert_eq!(failed.state, AttemptState::Failed);
    assert_eq!(failed.lease_owner, None);
    assert_eq!(failed.attempt_count, 1);
    assert_eq!(
        failed.last_error.as_deref(),
        Some(ERR_INVALID_COMPANION_TASK_PAYLOAD)
    );

    assert_eq!(
        companion_queue.claim(ClaimCompanionTask {
            lease_owner: "companion-worker".to_owned(),
            now: 81,
        })?,
        ClaimCompanionTaskOutcome::Empty
    );
    assert_eq!(
        generic_queue
            .get(invalid_task.id)?
            .expect("invalid companion task still persisted")
            .attempt_count,
        1
    );

    Ok(())
}
