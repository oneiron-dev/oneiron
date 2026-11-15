//! RUN-HOLD (lead 18:5x, shape agreed 20:44): the hold follows the override.
//!
//! A generic Resume of a row an engine hold paused, by any admitted caller
//! other than the hold's own release door, moves the hold's own record in
//! the same transaction ([`AttemptQueue::follow_hold_override_in_txn`]):
//! - budget: the attempt leaves its run's plan hold, and the hold reads
//!   Resumed, owing no held notice, once no attempt is left on it;
//! - fan-out: the planning attempt leaves its launch's held list and is
//!   recorded as resumed by override, so the launch's next apply does not
//!   park it again;
//! - annotation: the release is recorded for that attempt and that drift of
//!   the thread ([`AttemptHoldOverride`]), so the next claim does not pause
//!   it again; a later drift of the same thread holds it again;
//! - hook: the saved wait stays, so the next claim meets the hook boundary on
//!   the same ask. An override never grants consent.
//!
//! The Resume event's note names the override under the caller's actor.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

use super::AttemptQueue;
use super::types::{AttemptId, AttemptPause, AttemptRecord};

/// An engine hold released on one attempt by a generic Resume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AttemptHoldOverride {
    pub(crate) hold: OverriddenHold,
    /// The Resume's actor.
    pub(crate) actor: String,
    pub(crate) at: u64,
}

#[doc(hidden)]
pub(crate) use oneiron_records::attempt_queue::hold_override::OverriddenHold;

/// Key: id16.
const HOLD_OVERRIDE: SideTable<AttemptId, AttemptHoldOverride, Named> =
    SideTable::new(&side_table::ATTEMPT_HOLD_OVERRIDE);

/// Whether `id`'s recorded override releases the annotation hold on
/// `artifact_id`/`thread_id` at its current drift `drifted_at_version`.
pub(super) fn annotation_hold_released_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: AttemptId,
    artifact_id: EntityId,
    thread_id: EntityId,
    drifted_at_version: Option<u64>,
) -> Result<bool> {
    Ok(HOLD_OVERRIDE.get(store, txn, &id)?.is_some_and(|row| {
        row.hold
            == OverriddenHold::Annotation {
                artifact_id,
                thread_id,
                drifted_at_version,
            }
    }))
}

/// The actor of `id`'s override record; `None` when it has none.
#[cfg(oneiron_test_support)]
pub(crate) fn hold_override_actor_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: AttemptId,
) -> Result<Option<String>> {
    Ok(HOLD_OVERRIDE.get(store, txn, &id)?.map(|row| row.actor))
}

/// Deletes `id`'s override record with its row; an id with none is left as it is.
pub(super) fn delete_hold_override_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: AttemptId,
) -> Result<()> {
    HOLD_OVERRIDE.delete(store, wtxn, &id)?;
    Ok(())
}

/// The table's actor scrub (an actor's erase, and a restore's rerun of it):
/// every override record `actor` made reads as made by an erased actor. The
/// release stands, and the record names no erased person.
pub(crate) fn erase_hold_override_actor_in_txn(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let actor = actor.to_hex();
    for (id, mut row) in HOLD_OVERRIDE.scan(&vault.store, wtxn)? {
        if row.actor == actor {
            row.actor = crate::receipt::ERASED_CALL_IDENTITY.to_owned();
            HOLD_OVERRIDE.put(&vault.store, wtxn, &id, &row)?;
        }
    }
    Ok(())
}

impl AttemptQueue<'_> {
    /// Moves the record of the engine hold `pause` that a generic Resume
    /// just released from `attempt` (the row as it stood before the Resume),
    /// in the Resume's transaction. A store-only handle reads and writes no
    /// vault record; the annotation override is still recorded.
    pub(super) fn follow_hold_override_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        pause: AttemptPause,
        attempt: &AttemptRecord,
        actor: &str,
        now: u64,
    ) -> Result<()> {
        match pause {
            // A person's pause is no engine hold, and a hook's saved wait
            // stays: the next claim meets the hook boundary on the same ask.
            AttemptPause::Person | AttemptPause::Hook { .. } => Ok(()),
            AttemptPause::Budget => match self.vault {
                Some(vault) => crate::agent_dispatch::AgentDispatcher::new(vault)
                    .follow_budget_hold_override_in_txn(wtxn, attempt, actor, now),
                None => Ok(()),
            },
            AttemptPause::Fanout { launch_ref } => match self.vault {
                Some(vault) => crate::task_verb::follow_fanout_hold_override_in_txn(
                    vault, wtxn, launch_ref, attempt.id, actor, now,
                ),
                None => Ok(()),
            },
            AttemptPause::Annotation {
                artifact_id,
                thread_id,
            } => {
                let drifted_at_version = match self.vault {
                    Some(vault) => vault
                        .annotation_thread_drift_in_txn(wtxn, &artifact_id, &thread_id)?
                        .map(|drift| drift.drifted_at_version),
                    None => None,
                };
                HOLD_OVERRIDE.put(
                    self.store,
                    wtxn,
                    &attempt.id,
                    &AttemptHoldOverride {
                        hold: OverriddenHold::Annotation {
                            artifact_id,
                            thread_id,
                            drifted_at_version,
                        },
                        actor: actor.to_owned(),
                        at: now,
                    },
                )
            }
        }
    }
}

/// The note of an override's Resume event: it names the hold, then the
/// caller's own note.
pub(super) fn override_note(pause: AttemptPause, note: Option<String>) -> Option<String> {
    let hold = match pause {
        AttemptPause::Person => return note,
        AttemptPause::Annotation { .. } => "annotation",
        AttemptPause::Budget => "budget",
        AttemptPause::Fanout { .. } => "fan-out",
        AttemptPause::Hook { .. } => "hook",
    };
    Some(match note {
        Some(note) => format!("override of the {hold} hold: {note}"),
        None => format!("override of the {hold} hold"),
    })
}
