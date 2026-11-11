//! Real queue operations agree with the lifecycle table for E1-covered events.
//! Claim, completion, failure and cleanup are checked only for row invariants.
//! Fan-out holds are not driven: their door needs a launch record.
//! A fixed sequence proves that each covered door accepts in this fixture, so
//! the random sequences compare real transitions and not refusals alone.
#![cfg(oneiron_test_support)]

use oneiron::Vault;
use oneiron::attempt_queue::{
    AttemptId, AttemptInterventionKind, AttemptQueue, AttemptRecord, AttemptResumePoint,
    AttemptState, ClaimAttempt, CleanupAttemptLeases, CompleteAttempt, EnqueueAttempt,
    EnqueueOutcome, FailAttempt, HoldAttemptForBudget, InterveneAttempt, RetryAttempt,
    RetryOutcome,
};
use oneiron::test_doors::run_hold;
use oneiron::test_doors::run_lifecycle::{
    TableAnswer, TableEvent, pause_kind, release_lease, table_answer,
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
    Retry(u8, bool, u16),
    Release(u8, bool),
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
            | Self::Retry(index, _, _)
            | Self::Release(index, _) => index,
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
        4 => (index.clone(), valid.clone(), 1_u16..=60)
            .prop_map(|(i, v, delay)| Operation::Retry(i, v, delay)),
        3 => (index, valid).prop_map(|(i, v)| Operation::Release(i, v)),
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
    successor: Option<(AttemptId, u64)>,
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
) {
    match operation {
        Operation::Complete(index, valid) => {
            let (lease_owner, attempt_count) = lease_input(record, valid, index);
            let _ = queue.complete(CompleteAttempt {
                id: record.id,
                lease_owner,
                attempt_count,
                now,
            });
        }
        Operation::Fail(index, valid) => {
            let (lease_owner, attempt_count) = lease_input(record, valid, index);
            let _ = queue.fail(FailAttempt {
                id: record.id,
                lease_owner,
                attempt_count,
                reason: "property-failure".to_owned(),
                now,
            });
        }
        _ => {}
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
                        successor = Some((next.id, due));
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
            _ => {
                apply_settlement(operation, &queue, record, now);
                None
            }
        }
    };
    Ok(answer.map(|(event, accepted)| TableObservation {
        target,
        event,
        accepted,
        successor,
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
        Operation::Claim(worker) => {
            queue
                .claim_kind(
                    KIND,
                    ClaimAttempt {
                        lease_owner: WORKERS[usize::from(worker)].to_owned(),
                        now,
                    },
                )
                .map_err(|error| TestCaseError::fail(format!("claim: {error}")))?;
            None
        }
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

fn check_move_fields(
    event: TableEvent,
    before: &AttemptRecord,
    after: &AttemptRecord,
    now: u64,
    context: &str,
) -> TestCaseResult {
    if event == TableEvent::PersonPause && before.state == AttemptState::Paused {
        prop_assert_eq!(&after.lease_owner, &before.lease_owner, "{}", context);
    } else {
        prop_assert!(
            after.lease_owner.is_none(),
            "lease not cleared: {}",
            context
        );
    }
    match event {
        TableEvent::Cancel => {
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
        TableEvent::Release { .. } => {
            prop_assert_eq!(after.scheduled_at, None, "{}", context);
        }
        TableEvent::PersonPause | TableEvent::Resume => {
            prop_assert_eq!(after.scheduled_at, before.scheduled_at, "{}", context);
        }
        TableEvent::Interrupt | TableEvent::BudgetHold | TableEvent::HookHold { .. } => {}
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
        prop_assert_eq!(next.state, AttemptState::Scheduled, "{}", context);
        prop_assert_eq!(pause_kind(next), None, "{}", context);
        prop_assert!(next.lease_owner.is_none(), "successor leased: {}", context);
        prop_assert_eq!(next.attempt_count, 0, "{}", context);
        prop_assert_eq!(next.scheduled_at, Some(due), "{}", context);
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

fn check_table_operation(
    observation: &TableObservation,
    before: &[AttemptRecord],
    after: &[AttemptRecord],
    now: u64,
    context: &str,
) -> TestCaseResult {
    let previous = &before[observation.target];
    let current = &after[observation.target];
    let answer = table_answer(previous, observation.event);
    if !observation.accepted {
        prop_assert_eq!(current, previous, "refused target changed: {}", context);
    } else {
        match answer {
            TableAnswer::Move { to, pause } => {
                prop_assert_eq!(current.state, to, "{}", context);
                prop_assert_eq!(pause_kind(current), pause, "{}", context);
                check_move_fields(observation.event, previous, current, now, context)?;
            }
            TableAnswer::Stay => {
                prop_assert_eq!(current.state, previous.state, "{}", context);
                prop_assert_eq!(pause_kind(current), pause_kind(previous), "{}", context);
            }
            TableAnswer::Refuse => {
                return Err(TestCaseError::fail(format!(
                    "accepted table refusal: {context}"
                )));
            }
        }
    }
    for (index, previous) in before.iter().enumerate() {
        if index != observation.target {
            prop_assert_eq!(&after[index], previous, "other row changed: {}", context);
        }
    }
    check_successor(observation, before, after, context)
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
        if row.state == AttemptState::Leased {
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
        accepted.push(observation.as_ref().map(|observation| observation.accepted));
        if let Some(observation) = observation {
            check_table_operation(&observation, &before, &after, now, &context)?;
        }
        check_row_invariants(&after, &mut terminal_states, &context)?;
    }
    Ok(accepted)
}

/// Every covered door accepts in this fixture: both interventions of the owner
/// and of a caller, the budget and hook holds, a person's takeover of each
/// hold, the lease release, the retry and the cancel. Without it a run whose
/// every operation is refused would pass the property and compare nothing.
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
    ];
    let accepted = run_sequence(&operations).unwrap_or_else(|error| panic!("{error}"));
    for (index, operation) in operations.iter().enumerate() {
        let expected = (!matches!(operation, O::Enqueue | O::Claim(_))).then_some(true);
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
