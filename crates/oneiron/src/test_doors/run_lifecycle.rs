//! Doors for `tests/run_lifecycle_props.rs`: the lifecycle table's answer,
//! the stored pause kind, and the production lease release of a parked run.

use crate::Vault;
use crate::attempt_queue::lifecycle::{EngineHold, RunEvent, RunLifecycle, RunRow, RunStep};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState, PauseKind};
use crate::error::Result;
use crate::store::attempt_record::AttemptPause;

/// The event of a queue operation, with the facts the table reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableEvent {
    /// An owner's interrupt intervention.
    Interrupt,
    /// A pause intervention by an actor that is no hold's reserved actor.
    PersonPause,
    /// A resume intervention.
    Resume,
    /// A cancel intervention.
    Cancel,
    /// A budget hold by the lease holder.
    BudgetHold,
    /// A hook hold at the caller's invocation and lease generation.
    HookHold {
        /// The hook invocation the caller supplies.
        invocation: [u8; 16],
        /// The lease generation the caller supplies.
        attempt_count: u32,
    },
    /// A lease release, matching the row's owner when `lease_holder` is true.
    Release {
        /// Whether the caller's lease owner is the row's.
        lease_holder: bool,
    },
    /// A retry that settles the source and schedules a new try.
    Retry,
}

/// The table's answer, as a test reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableAnswer {
    /// The row moves to the answered state and pause kind.
    Move {
        /// The answered state.
        to: AttemptState,
        /// The answered pause kind, if any.
        pause: Option<PauseKind>,
    },
    /// The row keeps its state and pause: the table's Note, Replay and Keep.
    Stay,
    /// The table refuses this event in this row.
    Refuse,
}

/// What `RunLifecycle::step` answers for the stored row and the event.
pub fn table_answer(record: &AttemptRecord, event: TableEvent) -> TableAnswer {
    let event = match event {
        TableEvent::Interrupt => RunEvent::Interrupt,
        TableEvent::PersonPause => RunEvent::Pause {
            pause: AttemptPause::Person,
            by_hold_actor: false,
        },
        TableEvent::Resume => RunEvent::Resume,
        TableEvent::Cancel => RunEvent::Cancel,
        TableEvent::BudgetHold => RunEvent::Hold(EngineHold::Budget),
        TableEvent::HookHold {
            invocation,
            attempt_count,
        } => RunEvent::Hold(EngineHold::Hook {
            invocation,
            attempt_count,
        }),
        TableEvent::Release { lease_holder } => RunEvent::Release { lease_holder },
        TableEvent::Retry => RunEvent::Retry,
    };
    match RunLifecycle::step(RunRow::of(record), event) {
        RunStep::Move { to, pause } => TableAnswer::Move {
            to,
            pause: pause.map(PauseKind::of),
        },
        RunStep::Note { clock: _ } | RunStep::Replay | RunStep::Keep => TableAnswer::Stay,
        RunStep::Refuse => TableAnswer::Refuse,
    }
}

/// The kind of the row's crate-private `active_pause`.
pub fn pause_kind(record: &AttemptRecord) -> Option<PauseKind> {
    record.active_pause.map(PauseKind::of)
}

/// Releases `id`'s lease as its parked run's resume does, in its own write
/// transaction, committed when the production writer answers without an error.
///
/// # Errors
/// Returns the production writer's missing-row or storage error, or a commit error.
pub fn release_lease(vault: &Vault, id: AttemptId, lease_owner: &str, now: u64) -> Result<bool> {
    let mut wtxn = vault.store.env.write_txn()?;
    let released =
        AttemptQueue::new(vault).release_lease_in_txn(&mut wtxn, id, lease_owner, now)?;
    wtxn.commit()?;
    Ok(released)
}
