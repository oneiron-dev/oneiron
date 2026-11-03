//! Keyed indexes over the program tables (FIX 5735, FIX 5774, FIX 5838):
//! an actor's erase, its receipt's count and a restore's rerun of that
//! erase for each erased id read the actor's attempt stamps, admissions and
//! owed wakes by key, and a turn's admissions read by their turn, never
//! every row of each table. Each index row is written and deleted in the
//! writer that writes or deletes the row it names, so the index holds
//! exactly the rows its table holds.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

use super::types::TurnProgramWake;

/// Each program attempt stamped as an actor, keyed by the actor, then the
/// attempt.
const ACTOR_ATTEMPT: SideTable<(EntityId, AttemptId), (), Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_ACTOR_ATTEMPT);
/// Each admission of a wake an actor's turn owed, keyed by the actor, then
/// the admission.
const ACTOR_ADMISSION: SideTable<(EntityId, [u8; 32]), (), Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_ACTOR_ADMISSION);
/// Each admission of a wake a turn owed, keyed by the turn, then the
/// admission: a turn's admissions in admission order.
pub(super) const TURN_ADMISSION: SideTable<(EntityId, [u8; 32]), (), Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_TURN_ADMISSION);
/// Each wake owed for an actor's turn, keyed by the actor, then the wake's
/// own key: the turn, then the registration it woke.
const ACTOR_WAKE: SideTable<(EntityId, EntityId, EntityId), (), Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_ACTOR_WAKE);

/// Indexes `attempt` under the actor its stamp names, in the stamp's writer.
pub(super) fn index_attempt_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    attempt: AttemptId,
) -> Result<()> {
    ACTOR_ATTEMPT.put(vault, txn, &(actor, attempt), &())
}

/// The program attempts stamped as `actor`, in key order.
pub(super) fn actor_attempts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<Vec<AttemptId>> {
    Ok(ACTOR_ATTEMPT
        .scan_keys(vault, txn, actor.as_bytes())?
        .into_iter()
        .map(|(_, attempt)| attempt)
        .collect())
}

/// Indexes `admission`, the admission of `wake`, under its waking actor and
/// its turn, in the writer that first writes it. A later rewrite keeps both,
/// so it needs none.
pub(super) fn index_admission_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    wake: &TurnProgramWake,
    admission: &[u8; 32],
) -> Result<()> {
    ACTOR_ADMISSION.put(vault, txn, &(wake.authority.actor(), *admission), &())?;
    TURN_ADMISSION.put(vault, txn, &(wake.turn.turn, *admission), &())
}

/// The admissions of wakes `actor`'s turns owed, in key order.
pub(super) fn actor_admissions_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<Vec<[u8; 32]>> {
    Ok(ACTOR_ADMISSION
        .scan_keys(vault, txn, actor.as_bytes())?
        .into_iter()
        .map(|(_, admission)| admission)
        .collect())
}

/// Indexes the wake keyed `(turn, registration)` under `actor`, in the
/// wake's writer.
pub(super) fn index_wake_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    (turn, registration): (EntityId, EntityId),
) -> Result<()> {
    ACTOR_WAKE.put(vault, txn, &(actor, turn, registration), &())
}

/// Drops the index row of the wake keyed `(turn, registration)` under
/// `actor`, in the writer that deletes the wake.
pub(super) fn unindex_wake_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    (turn, registration): (EntityId, EntityId),
) -> Result<()> {
    ACTOR_WAKE
        .delete(vault, txn, &(actor, turn, registration))
        .map(drop)
}

/// The keys of the wakes owed for `actor`'s turns, in key order.
pub(super) fn actor_wakes_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<Vec<(EntityId, EntityId)>> {
    Ok(ACTOR_WAKE
        .scan_keys(vault, txn, actor.as_bytes())?
        .into_iter()
        .map(|(_, turn, registration)| (turn, registration))
        .collect())
}
