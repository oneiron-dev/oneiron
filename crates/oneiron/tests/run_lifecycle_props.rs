//! Real queue operations agree with the lifecycle table for E1, E2 and E3.
//! Cleanup compares every row with its own reclaim cell.
//! Fan-out holds are not driven: their door needs a launch record.
//! A fixed sequence proves that each covered door accepts in this fixture, so
//! the random sequences compare real transitions and not refusals alone.
#![cfg(oneiron_test_support)]

use oneiron::Vault;
use oneiron::attempt_queue::{
    AbandonAttempt, AbandonOutcome, AcceptAttemptLanding, AttemptId, AttemptInterventionKind,
    AttemptPlacement, AttemptQueue, AttemptRecord, AttemptResultRef, AttemptResumePoint,
    AttemptState, ClaimAttempt, ClaimOutcome, CleanupAttemptLeases, CompleteAttempt,
    CompleteOutcome, EnqueueAttempt, EnqueueOutcome, FailAttempt, FailOutcome,
    FinishAttemptLanding, FinishLandingOutcome, ForceAttemptCancel, ForceCancelOutcome,
    HoldAttemptForBudget, InterveneAttempt, LandingOutcome, LandingTrigger, RequeueAttempt,
    RetryAttempt, RetryOutcome,
};
use oneiron::test_doors::run_hold;
use oneiron::test_doors::run_lifecycle::{
    TableAnswer, TableEvent, advance_retry, defer_enqueued, force_cancel_authority, pause_kind,
    release_lease, table_answer,
};
use oneiron_testkit::{FixtureVault, TestVault, fixture_cache};
use proptest::prelude::*;
use proptest::test_runner::{TestCaseError, TestCaseResult};

const KIND: &str = "test.run_lifecycle_props";
const OWNER: &str = "person:lifecycle-owner";
const WORKERS: [&str; 2] = ["worker:lifecycle-0", "worker:lifecycle-1"];
const CALLERS: [&str; 2] = ["person:lifecycle-0", "person:lifecycle-1"];
const LEASE_TIMEOUT: u64 = 10;
const MAX_OPERATIONS: usize = 24;

#[derive(Debug, Clone, Copy)]
enum Operation {
    Enqueue,
    Claim(bool),
    AdvanceClock(u64),
    CleanupLeases,
    Interrupt(u8),
    Pause(u8),
    Resume(u8),
    Cancel(u8),
    CallerPause(u8, bool),
    CallerResume(u8, bool),
    BudgetHold(u8, bool),
    HookHold(u8, bool, u8),
    Complete(u8, bool),
    Fail(u8, bool),
    Abandon(u8, bool),
    Requeue(u8, bool, u16),
    Redirect(u8, bool),
    Defer(u8, u16),
    AdvanceRetry(u8),
    Retry(u8, bool, u16),
    Release(u8, bool),
    AcceptLanding(u8, bool, bool),
    FinishLanding(u8, bool, bool, bool),
    ForceCancel(u8),
}

impl Operation {
    fn target(self, length: usize) -> Option<usize> {
        let index = match self {
            Self::Interrupt(index)
            | Self::Pause(index)
            | Self::Resume(index)
            | Self::Cancel(index)
            | Self::CallerPause(index, _)
            | Self::CallerResume(index, _)
            | Self::BudgetHold(index, _)
            | Self::HookHold(index, _, _)
            | Self::Complete(index, _)
            | Self::Fail(index, _)
            | Self::Abandon(index, _)
            | Self::Requeue(index, _, _)
            | Self::Redirect(index, _)
            | Self::Defer(index, _)
            | Self::AdvanceRetry(index)
            | Self::Retry(index, _, _)
            | Self::Release(index, _)
            | Self::AcceptLanding(index, _, _)
            | Self::FinishLanding(index, _, _, _)
            | Self::ForceCancel(index) => index,
            Self::Enqueue | Self::Claim(_) | Self::AdvanceClock(_) | Self::CleanupLeases => {
                return None;
            }
        };
        if length == 0 {
            None
        } else {
            Some(usize::from(index) % length)
        }
    }

    fn intervention(self) -> Option<(AttemptInterventionKind, TableEvent, Option<&'static str>)> {
        use AttemptInterventionKind as K;
        match self {
            Self::Interrupt(_) => Some((K::Interrupt, TableEvent::Interrupt, None)),
            Self::Pause(_) => Some((K::Pause, TableEvent::PersonPause, None)),
            Self::Resume(_) => Some((K::Resume, TableEvent::Resume, None)),
            Self::Cancel(_) => Some((K::Cancel, TableEvent::Cancel, None)),
            Self::CallerPause(_, actor) => Some((
                K::Pause,
                TableEvent::PersonPause,
                Some(CALLERS[usize::from(actor)]),
            )),
            Self::CallerResume(_, actor) => Some((
                K::Resume,
                TableEvent::Resume,
                Some(CALLERS[usize::from(actor)]),
            )),
            _ => None,
        }
    }
}

fn operation_strategy() -> BoxedStrategy<Operation> {
    let index = 0_u8..32;
    // Four matching fences for each bad fence. Bad fences alternate between a
    // wrong owner and a stale generation, except release, which has no generation.
    let valid = prop_oneof![4 => Just(true), 1 => Just(false)];
    prop_oneof![
        5 => Just(Operation::Enqueue),
        5 => any::<bool>().prop_map(Operation::Claim),
        3 => prop_oneof![Just(1_u64), Just(11_u64), Just(3_600_u64)]
            .prop_map(Operation::AdvanceClock),
        3 => Just(Operation::CleanupLeases),
        1 => index.clone().prop_map(Operation::Interrupt),
        3 => index.clone().prop_map(Operation::Pause),
        3 => index.clone().prop_map(Operation::Resume),
        2 => index.clone().prop_map(Operation::Cancel),
        2 => (index.clone(), any::<bool>()).prop_map(|(i, a)| Operation::CallerPause(i, a)),
        2 => (index.clone(), any::<bool>()).prop_map(|(i, a)| Operation::CallerResume(i, a)),
        3 => (index.clone(), valid.clone()).prop_map(|(i, v)| Operation::BudgetHold(i, v)),
        3 => (index.clone(), valid.clone(), 0_u8..2)
            .prop_map(|(i, v, invocation)| Operation::HookHold(i, v, invocation)),
        2 => (index.clone(), valid.clone()).prop_map(|(i, v)| Operation::Complete(i, v)),
        2 => (index.clone(), valid.clone()).prop_map(|(i, v)| Operation::Fail(i, v)),
        2 => (index.clone(), valid.clone()).prop_map(|(i, v)| Operation::Abandon(i, v)),
        3 => (index.clone(), valid.clone(), 1_u16..=60)
            .prop_map(|(i, v, delay)| Operation::Requeue(i, v, delay)),
        3 => (index.clone(), any::<bool>()).prop_map(|(i, moved)| Operation::Redirect(i, moved)),
        3 => (index.clone(), 0_u16..=60).prop_map(|(i, delay)| Operation::Defer(i, delay)),
        3 => index.clone().prop_map(Operation::AdvanceRetry),
        4 => (index.clone(), valid.clone(), 1_u16..=60)
            .prop_map(|(i, v, delay)| Operation::Retry(i, v, delay)),
        3 => (index.clone(), valid.clone()).prop_map(|(i, v)| Operation::Release(i, v)),
        4 => (index.clone(), valid.clone(), any::<bool>())
            .prop_map(|(i, v, checkpoint)| Operation::AcceptLanding(i, v, checkpoint)),
        4 => (index.clone(), valid, any::<bool>(), any::<bool>())
            .prop_map(|(i, v, hand_off, scheduled)| Operation::FinishLanding(i, v, hand_off, scheduled)),
        2 => index.prop_map(Operation::ForceCancel),
    ]
    .boxed()
}

fn sequence_strategy() -> BoxedStrategy<Vec<Operation>> {
    // Most sequences enter Leased before random operations. The unprefixed
    // branch also checks empty-list skips and sequences without an early claim.
    prop_oneof![
        3 => (any::<bool>(), proptest::collection::vec(operation_strategy(), 0..=MAX_OPERATIONS - 2))
            .prop_map(|(worker, tail)| {
                let mut operations = vec![Operation::Enqueue, Operation::Claim(worker)];
                operations.extend(tail);
                operations
            }),
        1 => proptest::collection::vec(operation_strategy(), 0..=MAX_OPERATIONS),
    ].boxed()
}

fn open_case() -> Result<(TestVault, Vault), TestCaseError> {
    let copy = FixtureVault::empty(&fixture_cache!())
        .and_then(|fixture| fixture.copy())
        .map_err(|error| TestCaseError::fail(format!("fixture: {error}")))?;
    let vault = copy
        .open()
        .map_err(|error| TestCaseError::fail(format!("open: {error}")))?;
    Ok((copy, vault))
}

fn read_rows(
    queue: &AttemptQueue<'_>,
    ids: &[AttemptId],
) -> Result<Vec<AttemptRecord>, TestCaseError> {
    ids.iter()
        .map(|id| {
            queue
                .get(*id)
                .map_err(|error| TestCaseError::fail(format!("get {id:?}: {error}")))?
                .ok_or_else(|| TestCaseError::fail(format!("missing row {id:?}")))
        })
        .collect()
}

fn lease_input(record: &AttemptRecord, valid: bool, index: u8) -> (String, u32) {
    let owner = record.lease_owner.as_deref().unwrap_or(WORKERS[0]);
    if valid {
        (owner.to_owned(), record.attempt_count)
    } else if index % 2 == 0 {
        ("worker:wrong-owner".to_owned(), record.attempt_count)
    } else {
        (owner.to_owned(), record.attempt_count.wrapping_sub(1))
    }
}

struct TableObservation {
    target: usize,
    event: TableEvent,
    accepted: bool,
    successor: Option<(AttemptId, Option<u64>)>,
    claimed_by: Option<&'static str>,
    due: Option<u64>,
}

fn apply_intervention(
    vault: &Vault,
    record: &AttemptRecord,
    kind: AttemptInterventionKind,
    caller: Option<&str>,
    now: u64,
) -> bool {
    match caller {
        Some(actor) => matches!(
            run_hold::intervene_as_caller(vault, record.id, kind, actor, now),
            Ok(Ok(_))
        ),
        None => AttemptQueue::new(vault)
            .intervene(InterveneAttempt {
                id: record.id,
                kind,
                actor: OWNER.to_owned(),
                note: None,
                now,
            })
            .is_ok(),
    }
}

fn apply_hold(
    operation: Operation,
    vault: &Vault,
    record: &AttemptRecord,
    now: u64,
) -> Option<(TableEvent, bool)> {
    match operation {
        Operation::BudgetHold(index, valid) => {
            let (lease_owner, attempt_count) = lease_input(record, valid, index);
            let accepted = AttemptQueue::new(vault)
                .hold_for_budget(HoldAttemptForBudget {
                    id: record.id,
                    lease_owner,
                    attempt_count,
                    resume_point: AttemptResumePoint::new("property-checkpoint", now),
                    now,
                })
                .is_ok();
            Some((TableEvent::BudgetHold, accepted))
        }
        Operation::HookHold(index, valid, invocation) => {
            let (lease_owner, attempt_count) = lease_input(record, valid, index);
            let invocation = [invocation; 16];
            let accepted = run_hold::hold_for_hook(
                vault,
                record.id,
                &lease_owner,
                attempt_count,
                invocation,
                AttemptResumePoint::new("property-hook", now),
                now,
            )
            .is_ok();
            Some((
                TableEvent::HookHold {
                    invocation,
                    attempt_count,
                },
                accepted,
            ))
        }
        _ => None,
    }
}

fn apply_settlement(
    operation: Operation,
    queue: &AttemptQueue<'_>,
    record: &AttemptRecord,
    now: u64,
) -> Result<Option<(TableEvent, bool)>, TestCaseError> {
    let answer = match operation {
        Operation::Complete(index, valid) => {
            let (lease_owner, attempt_count) = lease_input(record, valid, index);
            let accepted = match queue.complete(CompleteAttempt {
                id: record.id,
                lease_owner,
                attempt_count,
                now,
            }) {
                Ok(CompleteOutcome::Completed(_) | CompleteOutcome::AlreadyCompleted(_)) => true,
                Ok(_) => return Err(TestCaseError::fail("unknown complete outcome")),
                Err(_) => false,
            };
            (TableEvent::Complete, accepted)
        }
        Operation::Fail(index, valid) => {
            let (lease_owner, attempt_count) = lease_input(record, valid, index);
            let accepted = match queue.fail(FailAttempt {
                id: record.id,
                lease_owner,
                attempt_count,
                reason: "property-failure".to_owned(),
                now,
            }) {
                Ok(FailOutcome::Failed(_) | FailOutcome::AlreadyFailed(_)) => true,
                Ok(_) => return Err(TestCaseError::fail("unknown fail outcome")),
                Err(_) => false,
            };
            (TableEvent::Fail, accepted)
        }
        Operation::Abandon(index, valid) => {
            let (lease_owner, attempt_count) = lease_input(record, valid, index);
            let result_ref = AttemptResultRef::new("artifact:property-result")
                .map_err(|error| TestCaseError::fail(format!("result reference: {error}")))?;
            let accepted = match queue.abandon(AbandonAttempt {
                id: record.id,
                lease_owner,
                attempt_count,
                result_ref,
                reason: "property-abandonment".to_owned(),
                now,
            }) {
                Ok(AbandonOutcome::Abandoned(_) | AbandonOutcome::AlreadyAbandoned(_)) => true,
                Ok(_) => return Err(TestCaseError::fail("unknown abandon outcome")),
                Err(_) => false,
            };
            (TableEvent::Abandon, accepted)
        }
        _ => return Ok(None),
    };
    Ok(Some(answer))
}

fn apply_scheduling(
    operation: Operation,
    vault: &Vault,
    record: &AttemptRecord,
    target: usize,
    now: u64,
) -> Option<TableObservation> {
    let queue = AttemptQueue::new(vault);
    let mut due = None;
    let (event, accepted) = match operation {
        Operation::Requeue(index, valid, delay) => {
            let (lease_owner, attempt_count) = lease_input(record, valid, index);
            let due_at = now + u64::from(delay);
            due = Some(due_at);
            let accepted = queue
                .requeue(RequeueAttempt {
                    id: record.id,
                    lease_owner,
                    attempt_count,
                    reason: "property-requeue".to_owned(),
                    due_at,
                })
                .is_ok();
            (TableEvent::Requeue, accepted)
        }
        Operation::Redirect(_, moved) => {
            let old_worker = record
                .placement
                .as_ref()
                .and_then(|old| old.worker.as_deref());
            let worker = if moved {
                Some(
                    if old_worker == Some(WORKERS[0]) {
                        WORKERS[1]
                    } else {
                        WORKERS[0]
                    }
                    .to_owned(),
                )
            } else {
                old_worker.map(str::to_owned)
            };
            let placement = AttemptPlacement {
                worker,
                parent: None,
            };
            let worker_moved = placement.worker.as_deref()
                != record
                    .placement
                    .as_ref()
                    .and_then(|old| old.worker.as_deref());
            let accepted = queue
                .redirect(
                    InterveneAttempt {
                        id: record.id,
                        kind: AttemptInterventionKind::Redirect,
                        actor: OWNER.to_owned(),
                        note: None,
                        now,
                    },
                    placement,
                )
                .is_ok();
            (TableEvent::Redirect { worker_moved }, accepted)
        }
        Operation::Defer(_, delay) => {
            let scheduled_at = if delay == 0 {
                record.created_at
            } else {
                record.created_at.max(now) + u64::from(delay)
            };
            due = Some(scheduled_at);
            // No-op answers, including a Queued row already waiting or due by
            // creation, use the unchanged-row check rather than the Move cell.
            let moved = defer_enqueued(vault, record.id, scheduled_at)
                .is_ok_and(|deferred| deferred != *record);
            (TableEvent::Defer, moved)
        }
        Operation::AdvanceRetry(_) => {
            due = Some(now);
            // The table admits Scheduled, but the door also requires retry_of
            // and a later ready instant. A false answer must change no row.
            let moved = matches!(advance_retry(vault, record.id, now), Ok(true));
            (TableEvent::AdvanceRetry, moved)
        }
        _ => return None,
    };
    Some(TableObservation {
        target,
        event,
        accepted,
        successor: None,
        claimed_by: None,
        due,
    })
}

fn apply_finish_landing(
    operation: Operation,
    queue: &AttemptQueue<'_>,
    record: &AttemptRecord,
    now: u64,
) -> Result<(bool, Option<(AttemptId, Option<u64>)>), TestCaseError> {
    let Operation::FinishLanding(index, valid, hand_off, scheduled) = operation else {
        return Err(TestCaseError::fail("expected finish-landing operation"));
    };
    let (lease_owner, attempt_count) = lease_input(record, valid, index);
    let due = scheduled.then_some(now + 30);
    match queue.finish_landing(FinishAttemptLanding {
        id: record.id,
        lease_owner,
        attempt_count,
        hand_off,
        scheduled_at: due,
        now,
    }) {
        Ok(FinishLandingOutcome::Landed(_)) if !hand_off => Ok((true, None)),
        Ok(FinishLandingOutcome::HandedOff { successor, .. }) if hand_off => {
            Ok((true, Some((successor.id, due))))
        }
        Ok(_) => Err(TestCaseError::fail("unknown finish-landing outcome")),
        Err(_) => Ok((false, None)),
    }
}

fn apply_landing(
    operation: Operation,
    vault: &Vault,
    record: &AttemptRecord,
    target: usize,
    now: u64,
) -> Result<Option<TableObservation>, TestCaseError> {
    let queue = AttemptQueue::new(vault);
    let mut successor = None;
    let (event, accepted) = match operation {
        Operation::AcceptLanding(index, valid, checkpoint) => {
            let (lease_owner, attempt_count) = lease_input(record, valid, index);
            let outcome = queue.accept_landing(AcceptAttemptLanding {
                id: record.id,
                lease_owner,
                attempt_count,
                trigger: LandingTrigger::CancelRequest,
                status: None,
                resume_point: checkpoint.then(|| AttemptResumePoint::new("property-landing", now)),
                request_sequence: None,
                now,
            });
            let accepted = match outcome {
                Ok(LandingOutcome::Landing(_) | LandingOutcome::AlreadyLanding(_)) => true,
                Ok(_) => return Err(TestCaseError::fail("unknown accept-landing outcome")),
                Err(_) => false,
            };
            (TableEvent::AcceptLanding, accepted)
        }
        Operation::FinishLanding(..) => {
            let (accepted, next) = apply_finish_landing(operation, &queue, record, now)?;
            successor = next;
            (TableEvent::FinishLanding, accepted)
        }
        Operation::ForceCancel(_) => {
            let authority = force_cancel_authority(OWNER)
                .map_err(|error| TestCaseError::fail(format!("force authority: {error}")))?;
            let accepted = match queue.force_cancel(ForceAttemptCancel {
                id: record.id,
                authority,
                reason: None,
                now,
            }) {
                Ok(
                    ForceCancelOutcome::Cancelled(_)
                    | ForceCancelOutcome::AlreadyCancelled(_)
                    | ForceCancelOutcome::AlreadySettled(_),
                ) => true,
                Ok(_) => return Err(TestCaseError::fail("unknown force-cancel outcome")),
                Err(_) => false,
            };
            (TableEvent::ForceCancel, accepted)
        }
        _ => return Ok(None),
    };
    Ok(Some(TableObservation {
        target,
        event,
        accepted,
        successor,
        claimed_by: None,
        due: None,
    }))
}

fn apply_claim(
    queue: &AttemptQueue<'_>,
    worker: bool,
    before: &[AttemptRecord],
    now: u64,
) -> Result<Option<TableObservation>, TestCaseError> {
    let claimed_by = WORKERS[usize::from(worker)];
    match queue
        .claim_kind(
            KIND,
            ClaimAttempt {
                lease_owner: claimed_by.to_owned(),
                now,
            },
        )
        .map_err(|error| TestCaseError::fail(format!("claim: {error}")))?
    {
        ClaimOutcome::Claimed(record) => {
            let target = before
                .iter()
                .position(|row| row.id == record.id)
                .ok_or_else(|| TestCaseError::fail("claim returned an untracked row"))?;
            Ok(Some(TableObservation {
                target,
                event: TableEvent::Claim,
                accepted: true,
                successor: None,
                claimed_by: Some(claimed_by),
                due: None,
            }))
        }
        ClaimOutcome::Empty => Ok(None),
        _ => Err(TestCaseError::fail("unknown claim outcome")),
    }
}

fn apply_row(
    operation: Operation,
    vault: &Vault,
    record: &AttemptRecord,
    target: usize,
    now: u64,
) -> Result<Option<TableObservation>, TestCaseError> {
    let queue = AttemptQueue::new(vault);
    if matches!(
        operation,
        Operation::AcceptLanding(..) | Operation::FinishLanding(..) | Operation::ForceCancel(_)
    ) {
        return apply_landing(operation, vault, record, target, now);
    }
    if let Some(observation) = apply_scheduling(operation, vault, record, target, now) {
        return Ok(Some(observation));
    }
    let mut successor = None;
    let answer = if let Some((kind, event, caller)) = operation.intervention() {
        Some((event, apply_intervention(vault, record, kind, caller, now)))
    } else if let Some(answer) = apply_hold(operation, vault, record, now) {
        Some(answer)
    } else {
        match operation {
            Operation::Retry(index, valid, delay) => {
                let (lease_owner, attempt_count) = lease_input(record, valid, index);
                let due = now + u64::from(delay);
                let accepted = match queue.retry(RetryAttempt {
                    id: record.id,
                    lease_owner,
                    attempt_count,
                    backoff_until: due,
                    last_error: None,
                    now,
                }) {
                    Ok(RetryOutcome::Retried(next)) => {
                        successor = Some((next.id, Some(due)));
                        true
                    }
                    Ok(_) => return Err(TestCaseError::fail("unknown retry outcome")),
                    Err(_) => false,
                };
                Some((TableEvent::Retry, accepted))
            }
            Operation::Release(_, valid) => {
                let lease_owner = if valid {
                    record.lease_owner.as_deref().unwrap_or(WORKERS[0])
                } else {
                    "worker:wrong-owner"
                };
                let event = TableEvent::Release {
                    lease_holder: record.lease_owner.as_deref() == Some(lease_owner),
                };
                let accepted =
                    matches!(release_lease(vault, record.id, lease_owner, now), Ok(true));
                Some((event, accepted))
            }
            _ => apply_settlement(operation, &queue, record, now)?,
        }
    };
    Ok(answer.map(|(event, accepted)| TableObservation {
        target,
        event,
        accepted,
        successor,
        claimed_by: None,
        due: None,
    }))
}

fn apply_operation(
    operation: Operation,
    copy: &TestVault,
    vault: &Vault,
    before: &[AttemptRecord],
    ids: &mut Vec<AttemptId>,
) -> Result<Option<TableObservation>, TestCaseError> {
    let queue = AttemptQueue::new(vault);
    let now = copy.clock().now();
    let observation = match operation {
        Operation::Enqueue => {
            // EnqueueAttempt has no schedule input; retry reaches Scheduled.
            let outcome = queue
                .enqueue(EnqueueAttempt {
                    kind: KIND.to_owned(),
                    payload: b"run".to_vec(),
                    dedupe_key: None,
                    run_id: None,
                    now,
                })
                .map_err(|error| TestCaseError::fail(format!("enqueue: {error}")))?;
            let EnqueueOutcome::Enqueued(record) = outcome else {
                return Err(TestCaseError::fail("fresh enqueue did not create a row"));
            };
            ids.push(record.id);
            None
        }
        Operation::Claim(worker) => apply_claim(&queue, worker, before, now)?,
        Operation::AdvanceClock(seconds) => {
            copy.clock().advance(seconds);
            None
        }
        Operation::CleanupLeases => {
            queue
                .cleanup_leases(CleanupAttemptLeases {
                    now,
                    lease_timeout_secs: LEASE_TIMEOUT,
                })
                .map_err(|error| TestCaseError::fail(format!("cleanup: {error}")))?;
            None
        }
        _ => match operation.target(before.len()) {
            Some(target) => apply_row(operation, vault, &before[target], target, now)?,
            None => None,
        },
    };
    if let Some(TableObservation {
        successor: Some((id, _)),
        ..
    }) = &observation
    {
        ids.push(*id);
    }
    Ok(observation)
}

fn check_e3_move_fields(
    observation: &TableObservation,
    before: &AttemptRecord,
    after: &AttemptRecord,
    now: u64,
    context: &str,
) -> Result<bool, TestCaseError> {
    match observation.event {
        TableEvent::Complete | TableEvent::Fail => {
            prop_assert!(after.lease_owner.is_none(), "{}", context);
            prop_assert_eq!(after.scheduled_at, before.scheduled_at, "{}", context);
            prop_assert_eq!(after.settled_at, Some(after.updated_at), "{}", context);
            prop_assert!(after.updated_at >= now, "settled before now: {}", context);
        }
        TableEvent::Abandon => {
            prop_assert!(after.lease_owner.is_none(), "{}", context);
            prop_assert_eq!(after.scheduled_at, None, "{}", context);
            prop_assert_eq!(after.settled_at, Some(now), "{}", context);
        }
        TableEvent::Requeue => {
            prop_assert!(after.lease_owner.is_none(), "{}", context);
            prop_assert_eq!(after.scheduled_at, observation.due, "{}", context);
            prop_assert_eq!(after.attempt_count, before.attempt_count, "{}", context);
            prop_assert_eq!(after.settled_at, before.settled_at, "{}", context);
        }
        TableEvent::Redirect { .. } => {
            prop_assert!(after.lease_owner.is_none(), "{}", context);
            prop_assert_eq!(after.scheduled_at, None, "{}", context);
            prop_assert_eq!(after.attempt_count, before.attempt_count + 1, "{}", context);
            prop_assert_eq!(after.settled_at, before.settled_at, "{}", context);
        }
        TableEvent::Defer | TableEvent::AdvanceRetry => {
            prop_assert_eq!(&after.lease_owner, &before.lease_owner, "{}", context);
            prop_assert_eq!(after.scheduled_at, observation.due, "{}", context);
            prop_assert_eq!(after.attempt_count, before.attempt_count, "{}", context);
            prop_assert_eq!(after.settled_at, before.settled_at, "{}", context);
            prop_assert_eq!(&after.cancel_state, &before.cancel_state, "{}", context);
        }
        TableEvent::Reclaim { .. } => {
            prop_assert!(after.lease_owner.is_none(), "{}", context);
            prop_assert_eq!(after.scheduled_at, None, "{}", context);
            prop_assert_eq!(after.attempt_count, before.attempt_count, "{}", context);
            if before.state == AttemptState::Landing {
                prop_assert_eq!(after.settled_at, Some(now), "{}", context);
            } else {
                prop_assert_eq!(after.settled_at, before.settled_at, "{}", context);
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn check_move_fields(
    observation: &TableObservation,
    before: &AttemptRecord,
    after: &AttemptRecord,
    now: u64,
    context: &str,
) -> TestCaseResult {
    let event = observation.event;
    if check_e3_move_fields(observation, before, after, now, context)? {
        return Ok(());
    }
    if event == TableEvent::Claim {
        prop_assert_eq!(
            after.lease_owner.as_deref(),
            observation.claimed_by,
            "{}",
            context
        );
    } else if matches!(event, TableEvent::AcceptLanding)
        || (event == TableEvent::PersonPause && before.state == AttemptState::Paused)
    {
        prop_assert_eq!(&after.lease_owner, &before.lease_owner, "{}", context);
    } else {
        prop_assert!(
            after.lease_owner.is_none(),
            "lease not cleared: {}",
            context
        );
    }
    match event {
        TableEvent::Cancel | TableEvent::FinishLanding | TableEvent::ForceCancel => {
            prop_assert_eq!(after.state, AttemptState::Cancelled, "{}", context);
            prop_assert_eq!(after.scheduled_at, None, "{}", context);
            prop_assert_eq!(after.settled_at, Some(now), "{}", context);
        }
        // The retry door stamps the vault's recorded time, not the caller's:
        // it never runs behind the operation's time and may run ahead of it.
        TableEvent::Retry => {
            prop_assert_eq!(after.scheduled_at, None, "{}", context);
            prop_assert_eq!(after.settled_at, Some(after.updated_at), "{}", context);
            prop_assert!(
                after.updated_at >= now,
                "retry stamped before now: {}",
                context
            );
        }
        TableEvent::Claim => {
            prop_assert_eq!(after.state, AttemptState::Leased, "{}", context);
            prop_assert_eq!(after.attempt_count, before.attempt_count + 1, "{}", context);
            prop_assert_eq!(after.scheduled_at, None, "{}", context);
            prop_assert_eq!(after.settled_at, before.settled_at, "{}", context);
        }
        TableEvent::AcceptLanding => {
            prop_assert_eq!(after.state, AttemptState::Landing, "{}", context);
            prop_assert_eq!(after.attempt_count, before.attempt_count, "{}", context);
            prop_assert_eq!(after.scheduled_at, before.scheduled_at, "{}", context);
            prop_assert_eq!(after.settled_at, before.settled_at, "{}", context);
        }
        TableEvent::Release { .. } => {
            prop_assert_eq!(after.scheduled_at, None, "{}", context);
        }
        TableEvent::PersonPause | TableEvent::Resume => {
            prop_assert_eq!(after.scheduled_at, before.scheduled_at, "{}", context);
        }
        TableEvent::Interrupt | TableEvent::BudgetHold | TableEvent::HookHold { .. } => {}
        TableEvent::Complete
        | TableEvent::Fail
        | TableEvent::Abandon
        | TableEvent::Requeue
        | TableEvent::Redirect { .. }
        | TableEvent::Defer
        | TableEvent::AdvanceRetry
        | TableEvent::Reclaim { .. } => unreachable!("E3 move checked"),
    }
    Ok(())
}

fn check_successor(
    observation: &TableObservation,
    before: &[AttemptRecord],
    after: &[AttemptRecord],
    context: &str,
) -> TestCaseResult {
    if let Some((id, due)) = observation.successor {
        prop_assert!(
            !before.iter().any(|row| row.id == id),
            "successor not new: {}",
            context
        );
        let next = after
            .iter()
            .find(|row| row.id == id)
            .ok_or_else(|| TestCaseError::fail(format!("successor missing: {context}")))?;
        let expected = if due.is_some() {
            AttemptState::Scheduled
        } else {
            AttemptState::Queued
        };
        prop_assert_eq!(next.state, expected, "{}", context);
        prop_assert_eq!(pause_kind(next), None, "{}", context);
        prop_assert!(next.lease_owner.is_none(), "successor leased: {}", context);
        prop_assert_eq!(next.attempt_count, 0, "{}", context);
        prop_assert_eq!(next.scheduled_at, due, "{}", context);
        prop_assert_eq!(next.settled_at, None, "{}", context);
        prop_assert_eq!(
            next.retry_of,
            Some(before[observation.target].id),
            "{}",
            context
        );
    }
    Ok(())
}

fn check_table_row(
    observation: &TableObservation,
    previous: &AttemptRecord,
    current: &AttemptRecord,
    now: u64,
    context: &str,
) -> TestCaseResult {
    let answer = table_answer(previous, observation.event);
    if observation.event == TableEvent::Claim {
        prop_assert!(
            matches!(
                answer,
                TableAnswer::Move {
                    to: AttemptState::Leased,
                    ..
                }
            ),
            "claim was not admitted by the table: {}",
            context
        );
    }
    if !observation.accepted {
        prop_assert_eq!(current, previous, "refused target changed: {}", context);
    } else {
        match answer {
            TableAnswer::Move { to, pause } => {
                prop_assert_eq!(current.state, to, "{}", context);
                prop_assert_eq!(pause_kind(current), pause, "{}", context);
                check_move_fields(observation, previous, current, now, context)?;
            }
            TableAnswer::Stay => {
                if matches!(
                    observation.event,
                    TableEvent::AcceptLanding
                        | TableEvent::ForceCancel
                        | TableEvent::Complete
                        | TableEvent::Fail
                        | TableEvent::Abandon
                        | TableEvent::Reclaim { .. }
                ) {
                    prop_assert_eq!(current, previous, "replayed row changed: {}", context);
                }
                prop_assert_eq!(current.state, previous.state, "{}", context);
                prop_assert_eq!(pause_kind(current), pause_kind(previous), "{}", context);
                if matches!(observation.event, TableEvent::Redirect { .. }) {
                    prop_assert_eq!(&current.lease_owner, &previous.lease_owner, "{}", context);
                    prop_assert_eq!(current.scheduled_at, previous.scheduled_at, "{}", context);
                    prop_assert_eq!(current.attempt_count, previous.attempt_count, "{}", context);
                    prop_assert_eq!(current.settled_at, previous.settled_at, "{}", context);
                }
            }
            TableAnswer::Refuse => {
                return Err(TestCaseError::fail(format!(
                    "accepted table refusal: {context}"
                )));
            }
        }
    }
    Ok(())
}

fn check_table_operation(
    observation: &TableObservation,
    before: &[AttemptRecord],
    after: &[AttemptRecord],
    now: u64,
    context: &str,
) -> TestCaseResult {
    check_table_row(
        observation,
        &before[observation.target],
        &after[observation.target],
        now,
        context,
    )?;
    for (index, previous) in before.iter().enumerate() {
        if index != observation.target {
            prop_assert_eq!(&after[index], previous, "other row changed: {}", context);
        }
    }
    check_successor(observation, before, after, context)
}

fn check_cleanup(
    before: &[AttemptRecord],
    after: &[AttemptRecord],
    now: u64,
    context: &str,
) -> TestCaseResult {
    prop_assert_eq!(after.len(), before.len(), "{}", context);
    for (target, previous) in before.iter().enumerate() {
        // Exactly lease_expired's checked subtraction; held is false because
        // cleanup_leases supplies an empty held set and this fixture is serial.
        let expired = now
            .checked_sub(previous.updated_at)
            .is_some_and(|age| age >= LEASE_TIMEOUT);
        let observation = TableObservation {
            target,
            event: TableEvent::Reclaim {
                expired,
                held: false,
            },
            accepted: true,
            successor: None,
            claimed_by: None,
            due: None,
        };
        check_table_row(&observation, previous, &after[target], now, context)?;
    }
    Ok(())
}

fn check_row_invariants(
    after: &[AttemptRecord],
    terminal_states: &mut Vec<Option<AttemptState>>,
    context: &str,
) -> TestCaseResult {
    terminal_states.resize(after.len(), None);
    for (index, row) in after.iter().enumerate() {
        if let Some(state) = terminal_states[index] {
            prop_assert_eq!(row.state, state, "terminal row moved: {}", context);
        } else if row.state.is_terminal() {
            terminal_states[index] = Some(row.state);
        }
        if row.state == AttemptState::Paused {
            prop_assert!(pause_kind(row).is_some(), "pause missing: {}", context);
        }
        if matches!(row.state, AttemptState::Leased | AttemptState::Landing) {
            prop_assert!(row.lease_owner.is_some(), "owner missing: {}", context);
        }
    }
    Ok(())
}

/// Runs `operations` under every check. Answers, per operation, whether its
/// door accepted it; `None` for an operation the table does not cover.
fn run_sequence(operations: &[Operation]) -> Result<Vec<Option<bool>>, TestCaseError> {
    let (copy, vault) = open_case()
        .map_err(|error| TestCaseError::fail(format!("{error}; sequence={operations:?}")))?;
    let queue = AttemptQueue::new(&vault);
    let mut ids = Vec::new();
    let mut terminal_states = Vec::new();
    let mut accepted = Vec::with_capacity(operations.len());
    for (index, operation) in operations.iter().enumerate() {
        let before = read_rows(&queue, &ids).map_err(|error| {
            TestCaseError::fail(format!(
                "{error}; operation {index}: {operation:?}; sequence={operations:?}"
            ))
        })?;
        let now = copy.clock().now();
        let result = apply_operation(*operation, &copy, &vault, &before, &mut ids);
        let after = read_rows(&queue, &ids).map_err(|error| TestCaseError::fail(format!(
            "{error}; operation {index}: {operation:?}; before={before:?}; after=unreadable; sequence={operations:?}"
        )))?;
        let context = format!(
            "operation {index}: {operation:?}; now={now}; before={before:?}; after={after:?}; sequence={operations:?}"
        );
        let observation =
            result.map_err(|error| TestCaseError::fail(format!("{error}; {context}")))?;
        accepted.push(if matches!(operation, Operation::CleanupLeases) {
            Some(true)
        } else {
            observation.as_ref().map(|observation| observation.accepted)
        });
        if matches!(operation, Operation::CleanupLeases) {
            check_cleanup(&before, &after, now, &context)?;
        } else if let Some(observation) = observation {
            check_table_operation(&observation, &before, &after, now, &context)?;
        } else if matches!(operation, Operation::Claim(_)) {
            // No row of this fixture has a TASK, so a claim's scan can put an
            // annotation hold on none: a claim that leases nothing changes no row.
            prop_assert_eq!(&after, &before, "empty claim changed rows: {}", context);
        }
        check_row_invariants(&after, &mut terminal_states, &context)?;
    }
    Ok(accepted)
}

/// Every covered door accepts in this fixture: both interventions of the owner
/// and of a caller, the budget and hook holds, a person's takeover of each
/// hold, the lease release, retry, cancel, landing hand-off and force cancel,
/// settlement, placement changes, same-try requeue, deferral and acceleration.
/// Without it a run whose every operation is refused would pass the property
/// and compare nothing.
#[test]
fn each_covered_door_accepts_in_a_fixed_sequence() {
    use Operation as O;
    let operations = [
        O::Enqueue,
        O::Interrupt(0),
        O::Pause(0),
        O::Resume(0),
        O::CallerPause(0, false),
        O::CallerResume(0, false),
        O::Claim(false),
        O::BudgetHold(0, true),
        O::Pause(0),
        O::Resume(0),
        O::Claim(false),
        O::HookHold(0, true, 0),
        O::Pause(0),
        O::Resume(0),
        O::Claim(true),
        O::Release(0, true),
        O::Claim(false),
        O::Retry(0, true, 30),
        O::Cancel(1),
        O::Enqueue,
        O::Claim(false),
        O::AcceptLanding(2, true, true),
        O::FinishLanding(2, true, true, true),
        O::ForceCancel(3),
        O::Enqueue,
        O::Claim(false),
        O::Complete(4, true),
        O::Complete(4, false),
        O::Enqueue,
        O::Claim(false),
        O::Fail(5, true),
        O::Fail(5, false),
        O::Enqueue,
        O::Claim(false),
        O::AcceptLanding(6, true, true),
        O::Abandon(6, true),
        O::Abandon(6, false),
        O::Enqueue,
        O::Defer(7, 30),
        O::Pause(7),
        O::Resume(7),
        O::ForceCancel(7),
        O::Enqueue,
        O::Claim(false),
        O::Redirect(8, false),
        O::Redirect(8, true),
        O::Claim(false),
        O::Requeue(8, true, 30),
        O::Pause(8),
        O::Resume(8),
        O::ForceCancel(8),
        O::Enqueue,
        O::Claim(false),
        O::Retry(9, true, 30),
        O::AdvanceRetry(10),
        O::Claim(false),
        O::Requeue(10, true, 30),
        O::AdvanceRetry(10),
        O::Claim(false),
        O::Redirect(10, true),
        O::Claim(false),
        O::AcceptLanding(10, true, true),
        O::AdvanceClock(3_600),
        O::CleanupLeases,
    ];
    let accepted = run_sequence(&operations).unwrap_or_else(|error| panic!("{error}"));
    for (index, operation) in operations.iter().enumerate() {
        let expected = (!matches!(operation, O::Enqueue | O::AdvanceClock(_))).then_some(true);
        assert_eq!(
            accepted[index], expected,
            "operation {index}: {operation:?}"
        );
    }
}

proptest! {
    // A fixture copy and synchronous LMDB writes per case: 32 cases of at most
    // 24 operations and 64 shrink iterations bound filesystem work. No source
    // regression file, child process, timeout or async runtime is needed.
    #![proptest_config(ProptestConfig {
        cases: 32,
        max_shrink_iters: 64,
        failure_persistence: None,
        fork: false,
        timeout: 0,
        ..ProptestConfig::default()
    })]
    #[test]
    fn queue_operations_follow_the_lifecycle_table(operations in sequence_strategy()) {
        run_sequence(&operations)?;
    }
}
