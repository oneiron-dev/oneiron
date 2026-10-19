//! The wake observation (DOOR-144): what one wake pass recorded of itself.
//!
//! A root mints one [`WakeRef`] once its hooks allow the pass, before any
//! work, and its rows record the pass's clock, the attempt generations it
//! admitted, each model call bound to the actual lease that admitted it, the
//! Checkpoint parks it cut, and the later pass that resumed them.
//!
//! Every write is best-effort: one that fails is logged and skipped, and the
//! work it observes runs, settles, parks and resumes exactly as it would
//! unobserved. A write riding another (a park, a terminal step claim) runs in
//! a savepoint of it. The family is node-local Runtime state: it outlives a
//! restart, never enters a checkpoint image, and no stored row is a live
//! lease.
//!
//! Rows, after the family prefix (ids 16 bytes, counts big-endian u32):
//! `w` + wake, the header; `a` + attempt + count, one admitted generation;
//! `l` + attempt, its latest; `m` + wake + attempt + count, a pass's members;
//! `c` + wake + attempt + call, one admitted call; `s` + attempt + step, the
//! call a step's terminal claim closes; `p` + park, one Checkpoint park.

mod checkpoint;
mod live;
mod read;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

use super::deadline::WakePassDeadline;
use super::types::{RunWakePass, WakePassStop, WakeTrigger};

pub(super) use self::checkpoint::{LaterWake, resume_checkpoints_for_wake};
pub(crate) use self::checkpoint::{checkpoint_resumable_in_txn, record_checkpoint_in_txn};
pub(super) use self::live::WakeBinding;
pub(crate) use self::live::{ActiveWakes, StepCalls};
pub use self::read::{
    WAKE_OBSERVATION_PAGE_DEFAULT, WAKE_OBSERVATION_PAGE_MAX, WakeLiveCall, WakeLiveState,
    WakeObservation, WakeObservationCursor, WakeObservationRequest, WakeObservationSelector,
    WakeObservedGeneration,
};

/// One wake pass's observation handle: the store-issued id its rows are
/// keyed by. A pass, never a recipe, attempt or budget id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WakeRef(EntityId);

impl WakeRef {
    /// The pass a stored id names.
    #[must_use]
    pub const fn from_entity_id(id: EntityId) -> Self {
        Self(id)
    }

    /// The id the pass's rows are keyed by.
    #[must_use]
    pub const fn entity_id(self) -> EntityId {
        self.0
    }
}

/// The `w` row: one pass's clock and where it ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeObservedHeader {
    /// What woke the pass.
    pub trigger: String,
    pub scope: String,
    /// The worker label the pass leases its attempts under.
    pub worker: String,
    pub node_id: u64,
    /// The pass's wake-budget line, a diagnostic name.
    pub budget_id: String,
    /// Unix ms the wall clock read at the deadline's origin, before the pass
    /// assembled its guard and executors; `None` under an injected clock.
    pub origin_unix_ms: Option<u64>,
    pub ceiling_ms: u64,
    /// When its hooks allowed the pass: wall Unix ms, and ms on its clock.
    pub entered_unix_ms: u64,
    pub entered_elapsed_ms: u64,
    /// Set once every worker settled; `None` while it runs, and for good
    /// when its process died first.
    pub ended: Option<WakeObservedEnd>,
}

impl WakeObservedHeader {
    /// The ceiling anchored to the wall origin.
    #[must_use]
    pub fn ceiling_unix_ms(&self) -> Option<u64> {
        self.origin_unix_ms?.checked_add(self.ceiling_ms)
    }
}

/// How a pass ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeObservedEnd {
    pub unix_ms: u64,
    pub elapsed_ms: u64,
    /// Why it stopped; `None` when it returned an error.
    pub stop: Option<String>,
}

/// The `a` row: one attempt generation a pass admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeObservedAttempt {
    pub attempt: AttemptId,
    /// The queue generation (`attempt_count`) its admission leased.
    pub attempt_count: u32,
    pub wake: WakeRef,
    /// The worker label holding its lease.
    pub worker: String,
    /// The run correlation its queue row carried.
    pub run_id: Option<String>,
    /// Ms on the pass's clock when its admission was observed.
    pub admitted_elapsed_ms: u64,
    /// The Checkpoint park this generation's pass cut, once it parked.
    pub park: Option<EntityId>,
    /// The cut of the attempt's previous observed generation, which this one
    /// continues from as the same try.
    pub after_cut: Option<EntityId>,
}

/// The `c` row: one model call a pass admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeObservedCall {
    pub call: EntityId,
    pub attempt: AttemptId,
    pub attempt_count: u32,
    /// The logical step's canonical request hash.
    pub step_hash: [u8; 32],
    /// 0 for the step's own call, n for its nth schema correction.
    pub ordinal: u32,
    /// The id of the lease its guard issued: a diagnostic, not a capability.
    pub lease_id: String,
    /// Ms on the pass's clock just after its guard admitted it: an upper
    /// bound on the allocation, never a time inside the guard.
    pub admitted_elapsed_ms: u64,
    pub end: Option<WakeObservedCallEnd>,
}

/// How one call closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeObservedCallEnd {
    pub state: WakeCallState,
    pub at_unix_ms: u64,
    /// Units its lease charged; on a claimed step's own call, the usage the
    /// step's response reports, its corrections' included.
    pub used_units: Option<u64>,
    /// The terminal `dreamer.step` claim that recorded its step.
    pub claim: Option<EntityId>,
}

/// A call's last recorded state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeCallState {
    /// Its step's terminal claim recorded the response.
    Claimed,
    /// Its lease settled the units it charged; no claim recorded a response.
    Settled,
    /// Its lease was released untouched.
    Aborted,
    /// It closed with its lease still open, or one its guard no longer knows.
    Unsettled,
}

/// The `p` row: one Checkpoint park a pass cut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeObservedCheckpoint {
    pub attempt: AttemptId,
    pub attempt_count: u32,
    /// The pass that cut it.
    pub wake: WakeRef,
    /// Unix seconds, as the park row records them.
    pub parked_at: u64,
    /// The steps whose terminal claims the cutting pass recorded: what the
    /// same try replays from its memo once resumed.
    pub saved_steps: Vec<[u8; 32]>,
    pub resumed: Option<WakeObservedResume>,
}

/// The later pass that resumed a Checkpoint park, as the same try.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeObservedResume {
    pub wake: WakeRef,
    /// Unix seconds.
    pub at: u64,
    pub worker: String,
}

/// The `l` row: an attempt's latest observed generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct LatestGeneration {
    attempt_count: u32,
    wake: WakeRef,
}

/// The `m` row: one attempt generation a pass admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct WakeMember {
    attempt: AttemptId,
    attempt_count: u32,
}

/// The `s` row: the call a step's terminal claim closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct StepCall {
    wake: WakeRef,
    call: EntityId,
}

/// One row kind of the family, keyed by its bytes after the prefix.
type Rows<V> = SideTable<Vec<u8>, V, Named>;

const WAKES: Rows<WakeObservedHeader> = SideTable::new(&side_table::DREAMER_WAKE_OBSERVATION);
const ATTEMPTS: Rows<WakeObservedAttempt> = SideTable::new(&side_table::DREAMER_WAKE_OBSERVATION);
const LATEST: Rows<LatestGeneration> = SideTable::new(&side_table::DREAMER_WAKE_OBSERVATION);
const MEMBERS: Rows<WakeMember> = SideTable::new(&side_table::DREAMER_WAKE_OBSERVATION);
const CALLS: Rows<WakeObservedCall> = SideTable::new(&side_table::DREAMER_WAKE_OBSERVATION);
const STEPS: Rows<StepCall> = SideTable::new(&side_table::DREAMER_WAKE_OBSERVATION);
const CHECKPOINTS: Rows<WakeObservedCheckpoint> =
    SideTable::new(&side_table::DREAMER_WAKE_OBSERVATION);

/// One row key after the family prefix: its kind byte, then its parts.
fn row_key(kind: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut key = vec![kind];
    for part in parts {
        key.extend_from_slice(part);
    }
    key
}

fn wake_key(wake: WakeRef) -> Vec<u8> {
    row_key(b'w', &[wake.0.as_bytes().as_slice()])
}

fn attempt_key(attempt: AttemptId, attempt_count: u32) -> Vec<u8> {
    row_key(
        b'a',
        &[
            attempt.as_bytes().as_slice(),
            attempt_count.to_be_bytes().as_slice(),
        ],
    )
}

fn latest_key(attempt: AttemptId) -> Vec<u8> {
    row_key(b'l', &[attempt.as_bytes().as_slice()])
}

fn member_key(wake: WakeRef, attempt: AttemptId, attempt_count: u32) -> Vec<u8> {
    row_key(
        b'm',
        &[
            wake.0.as_bytes().as_slice(),
            attempt.as_bytes().as_slice(),
            attempt_count.to_be_bytes().as_slice(),
        ],
    )
}

fn call_key(wake: WakeRef, attempt: AttemptId, call: EntityId) -> Vec<u8> {
    row_key(
        b'c',
        &[
            wake.0.as_bytes().as_slice(),
            attempt.as_bytes().as_slice(),
            call.as_bytes().as_slice(),
        ],
    )
}

fn step_key(attempt: AttemptId, step_hash: &[u8; 32]) -> Vec<u8> {
    row_key(b's', &[attempt.as_bytes().as_slice(), step_hash.as_slice()])
}

fn checkpoint_key(park: EntityId) -> Vec<u8> {
    row_key(b'p', &[park.as_bytes().as_slice()])
}

/// One bound call's row key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CallKey {
    wake: WakeRef,
    attempt: AttemptId,
    call: EntityId,
}

impl CallKey {
    fn bytes(self) -> Vec<u8> {
        call_key(self.wake, self.attempt, self.call)
    }
}

/// Logs one skipped observation write; the work it observes goes on.
fn skipped(error: &Error, what: &'static str) {
    tracing::warn!(kind = ?error.kind(), %error, what, "wake observation write skipped");
}

/// Runs `write` in a savepoint of `wtxn`, for an observation riding another
/// write: its failure rolls back alone and is logged, so `wtxn` commits
/// exactly as it would have.
fn in_savepoint(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    what: &'static str,
    write: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<()>,
) {
    let mut savepoint = match vault.store.env.nested_write_txn(wtxn) {
        Ok(savepoint) => savepoint,
        Err(error) => {
            skipped(&Error::from(error), what);
            return;
        }
    };
    match write(&mut savepoint) {
        Ok(()) => {
            if let Err(error) = savepoint.commit() {
                skipped(&Error::from(error), what);
            }
        }
        Err(error) => skipped(&error, what),
    }
}

/// Whether `record` still holds the lease `worker` took at `attempt_count`.
fn holds_lease(record: &AttemptRecord, worker: &str, attempt_count: u32) -> bool {
    record.state == AttemptState::Leased
        && record.lease_owner.as_deref() == Some(worker)
        && record.attempt_count == attempt_count
}

/// The stored name of a wake trigger, fixed apart from any derive.
const fn trigger_name(trigger: WakeTrigger) -> &'static str {
    match trigger {
        WakeTrigger::Compaction => "compaction",
        WakeTrigger::SessionEnd => "session_end",
        WakeTrigger::Event => "event",
        WakeTrigger::Timer => "timer",
    }
}

/// The stored name of why a pass stopped.
const fn stop_name(stop: WakePassStop) -> &'static str {
    match stop {
        WakePassStop::QueueEmpty => "queue_empty",
        WakePassStop::BudgetExhausted => "budget_exhausted",
        WakePassStop::DeadlineHardCut => "deadline_hard_cut",
        WakePassStop::Trapped => "trapped",
        WakePassStop::NotHomeNode => "not_home_node",
        WakePassStop::NoHomeNode => "no_home_node",
        WakePassStop::Cancelled => "cancelled",
        WakePassStop::BacklogLeft => "backlog_left",
        WakePassStop::HookSkipped => "hook_skipped",
    }
}

/// Opens one pass's observation once its hooks allowed it, before any work:
/// registers it live, then commits its header in one short write. `None`,
/// logged, when either fails: the pass runs unobserved.
pub(super) fn start_wake_observation(
    vault: &Vault,
    deadline: &WakePassDeadline,
    input: &RunWakePass,
    budget_id: &str,
) -> Option<WakeBinding> {
    let wake = match vault.store.clock.entity_id() {
        Ok(id) => WakeRef(id),
        Err(error) => {
            skipped(&error, "wake header");
            return None;
        }
    };
    let header = WakeObservedHeader {
        trigger: trigger_name(input.trigger).to_owned(),
        scope: input.scope.as_str().to_owned(),
        worker: input.lease_owner.clone(),
        node_id: input.local_node_id,
        budget_id: budget_id.to_owned(),
        origin_unix_ms: deadline.origin_unix_ms(),
        ceiling_ms: deadline.ceiling_ms(),
        entered_unix_ms: crate::unix_millis_now(),
        entered_elapsed_ms: deadline.elapsed_ms(),
        ended: None,
    };
    // Live before visible: whoever reads the header finds the pass.
    let binding = vault.active_wakes.register(wake, deadline);
    match vault.with_write_txn_grouped(|wtxn| WAKES.put(vault, wtxn, &wake_key(wake), &header)) {
        Ok(()) => Some(binding),
        Err(error) => {
            skipped(&error, "wake header");
            None
        }
    }
}

/// Closes the observation `deadline` carries once every worker settled,
/// errors included (`stop` is `None` then).
pub(super) fn finish_wake_observation(
    vault: &Vault,
    deadline: &WakePassDeadline,
    stop: Option<WakePassStop>,
) {
    let Some(wake) = deadline.wake_ref() else {
        return;
    };
    let ended = WakeObservedEnd {
        unix_ms: crate::unix_millis_now(),
        elapsed_ms: deadline.elapsed_ms(),
        stop: stop.map(|stop| stop_name(stop).to_owned()),
    };
    let written = vault.with_write_txn_grouped(|wtxn| {
        let key = wake_key(wake);
        let Some(mut header) = WAKES.get(&vault.store, wtxn, &key)? else {
            return Ok(());
        };
        header.ended = Some(ended);
        WAKES.put(vault, wtxn, &key, &header)
    });
    if let Err(error) = written {
        skipped(&error, "wake end");
    }
}

/// Records one attempt generation `wake` just admitted, after queue
/// admission and before dispatch. `false`, writing nothing, when the queue
/// row no longer holds the lease admission took.
fn observe_attempt_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    wake: WakeRef,
    admitted: &AttemptRecord,
    admitted_elapsed_ms: u64,
) -> Result<bool> {
    let Some(worker) = admitted.lease_owner.as_deref() else {
        return Ok(false);
    };
    let Some(current) = AttemptQueue::new(vault).get_in_txn(wtxn, admitted.id)? else {
        return Ok(false);
    };
    if !holds_lease(&current, worker, admitted.attempt_count) {
        return Ok(false);
    }
    let attempt = admitted.id;
    let attempt_count = admitted.attempt_count;
    let after_cut = match LATEST.get(&vault.store, wtxn, &latest_key(attempt))? {
        Some(previous) if previous.attempt_count != attempt_count => ATTEMPTS
            .get(
                &vault.store,
                wtxn,
                &attempt_key(attempt, previous.attempt_count),
            )?
            .and_then(|previous| previous.park),
        _ => None,
    };
    let row = WakeObservedAttempt {
        attempt,
        attempt_count,
        wake,
        worker: worker.to_owned(),
        run_id: admitted.run_id.clone(),
        admitted_elapsed_ms,
        park: None,
        after_cut,
    };
    ATTEMPTS.put(vault, wtxn, &attempt_key(attempt, attempt_count), &row)?;
    let latest = LatestGeneration {
        attempt_count,
        wake,
    };
    LATEST.put(vault, wtxn, &latest_key(attempt), &latest)?;
    let member = WakeMember {
        attempt,
        attempt_count,
    };
    MEMBERS.put(
        vault,
        wtxn,
        &member_key(wake, attempt, attempt_count),
        &member,
    )?;
    Ok(true)
}

/// [`observe_attempt_in_txn`] in one short write of its own, best-effort.
pub(super) fn observe_attempt(
    vault: &Vault,
    wake: WakeRef,
    admitted: &AttemptRecord,
    admitted_elapsed_ms: u64,
) {
    let observed = vault.with_write_txn_grouped(|wtxn| {
        observe_attempt_in_txn(vault, wtxn, wake, admitted, admitted_elapsed_ms)
    });
    match observed {
        Ok(true) => {}
        Ok(false) => tracing::warn!(
            attempt = %bytes_to_hex_lower(admitted.id.as_bytes()),
            "an admitted attempt no longer held its lease; its generation is unobserved"
        ),
        Err(error) => skipped(&error, "admitted attempt"),
    }
}

/// One call a guard just admitted, before its row is bound.
struct AdmittedCall {
    key: CallKey,
    step_hash: [u8; 32],
    ordinal: u32,
    lease_id: String,
    admitted_elapsed_ms: u64,
}

/// Binds one admitted call to the generation its pass observed: `false`,
/// writing nothing, when that generation is not the attempt's latest in this
/// pass or its queue row no longer holds that lease. The step's own call
/// becomes the call its terminal claim closes.
fn bind_call_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    call: &AdmittedCall,
) -> Result<bool> {
    let CallKey {
        wake,
        attempt,
        call: call_id,
    } = call.key;
    let Some(latest) = LATEST.get(&vault.store, wtxn, &latest_key(attempt))? else {
        return Ok(false);
    };
    if latest.wake != wake {
        return Ok(false);
    }
    let generation = attempt_key(attempt, latest.attempt_count);
    let Some(admitted) = ATTEMPTS.get(&vault.store, wtxn, &generation)? else {
        return Ok(false);
    };
    let Some(current) = AttemptQueue::new(vault).get_in_txn(wtxn, attempt)? else {
        return Ok(false);
    };
    if !holds_lease(&current, &admitted.worker, admitted.attempt_count) {
        return Ok(false);
    }
    let row = WakeObservedCall {
        call: call_id,
        attempt,
        attempt_count: admitted.attempt_count,
        step_hash: call.step_hash,
        ordinal: call.ordinal,
        lease_id: call.lease_id.clone(),
        admitted_elapsed_ms: call.admitted_elapsed_ms,
        end: None,
    };
    CALLS.put(vault, wtxn, &call.key.bytes(), &row)?;
    if call.ordinal == 0 {
        let step = StepCall {
            wake,
            call: call_id,
        };
        STEPS.put(vault, wtxn, &step_key(attempt, &call.step_hash), &step)?;
    }
    Ok(true)
}

/// Records how one bound call closed, in one short write once its lease
/// settled or aborted. A call its step's terminal claim closed keeps it.
fn record_call_closed(vault: &Vault, key: CallKey, end: WakeObservedCallEnd) {
    let written = vault.with_write_txn_grouped(|wtxn| {
        let bytes = key.bytes();
        let Some(mut row) = CALLS.get(&vault.store, wtxn, &bytes)? else {
            return Ok(());
        };
        if row
            .end
            .as_ref()
            .is_some_and(|end| end.state == WakeCallState::Claimed)
        {
            return Ok(());
        }
        row.end = Some(end);
        CALLS.put(vault, wtxn, &bytes, &row)
    });
    if let Err(error) = written {
        skipped(&error, "call close");
    }
}

/// Which call a terminal step claim closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StepTerminal {
    /// A response this execution's call answered: the step's own call, when
    /// this execution bound one.
    Fresh { bound: bool },
    /// A stored response finished on recovery: the call that received it,
    /// in whichever pass admitted it.
    Recovered,
}

/// One terminal step claim, as its call's end.
pub(crate) struct StepClaimed {
    pub(crate) attempt_id: AttemptId,
    pub(crate) step_hash: [u8; 32],
    pub(crate) claim: EntityId,
    pub(crate) used_units: u64,
    pub(crate) terminal: StepTerminal,
}

/// Records `claimed` on the call its step names, in a savepoint of the
/// terminal claim's own write: nothing here refuses or rolls back that write.
pub(crate) fn record_call_terminal_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claimed: &StepClaimed,
) {
    if matches!(claimed.terminal, StepTerminal::Fresh { bound: false }) {
        return;
    }
    let found = step_call_in_txn(vault, wtxn, claimed.attempt_id, &claimed.step_hash);
    let (key, mut row) = match found {
        Ok(Some(found)) => found,
        Ok(None) => return,
        Err(error) => {
            skipped(&error, "call terminal");
            return;
        }
    };
    row.end = Some(WakeObservedCallEnd {
        state: WakeCallState::Claimed,
        at_unix_ms: crate::unix_millis_now(),
        used_units: Some(claimed.used_units),
        claim: Some(claimed.claim),
    });
    in_savepoint(vault, wtxn, "call terminal", |txn| {
        CALLS.put(vault, txn, &key, &row)
    });
}

/// The call `attempt`'s step names for its terminal claim, with its key.
fn step_call_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    step_hash: &[u8; 32],
) -> Result<Option<(Vec<u8>, WakeObservedCall)>> {
    let Some(step) = STEPS.get(&vault.store, txn, &step_key(attempt, step_hash))? else {
        return Ok(None);
    };
    let key = call_key(step.wake, attempt, step.call);
    Ok(CALLS.get(&vault.store, txn, &key)?.map(|row| (key, row)))
}
