//! Keyed indexes over the program tables (FIX 5735, FIX 5774, FIX 5838):
//! an actor's erase, its receipt's count and a restore's rerun of that
//! erase for each erased id read the actor's attempt stamps, admissions and
//! owed wakes by key, and a turn's admissions read by their turn, never
//! every row of each table. Each index row is written and deleted in the
//! writer that writes or deletes the row it names, so the index holds
//! exactly the rows its table holds.
//!
//! A decision another machine made (`DECIDED`) is keyed by its turn and
//! registration and names no actor, so its actor is kept beside it, by the
//! decision's key and by the actor (FIX TURNPROGRAM-ERASE-KEEPS-DECIDED).
//! These two hold only the decisions whose actor this machine learned: a
//! decision kept from a row that named none has neither row. Both rows go
//! with their actor's erase, and so does the decision they name; none is
//! written for an actor erased here.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Result;
#[cfg(feature = "sync")]
use crate::side_table::SideKey;
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

/// The actor of each decision kept here (`DECIDED`) whose actor this machine
/// learned, keyed as the decision is: the turn, then the registration.
#[cfg(feature = "sync")]
const DECIDED_ACTOR: SideTable<(EntityId, EntityId), EntityId, Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_DECIDED_ACTOR);
/// Each decision [`DECIDED_ACTOR`] names an actor for, keyed by that actor,
/// then the decision's own key: the turn, then the registration.
#[cfg(feature = "sync")]
const ACTOR_DECIDED: SideTable<(EntityId, EntityId, EntityId), (), Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_ACTOR_DECIDED);

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
/// `actor`, in the writer that deletes the wake, and with it the marks this
/// machine kept for the wake as its recorder or as the home that took it
/// (`retraction`).
pub(super) fn unindex_wake_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    (turn, registration): (EntityId, EntityId),
) -> Result<()> {
    #[cfg(feature = "sync")]
    super::retraction::forget_wake_in_txn(vault, txn, actor, (turn, registration))?;
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

/// The actor kept for the decision held under `(turn, registration)`; none
/// for a decision whose actor this machine never learned.
#[cfg(feature = "sync")]
pub(super) fn decided_actor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: (EntityId, EntityId),
) -> Result<Option<EntityId>> {
    DECIDED_ACTOR.get(vault, txn, &key)
}

/// Keeps `actor` as the actor of the decision held under `key`, in the
/// writer that keeps the decision or learns its actor, under both keys;
/// `None` keeps none. An actor kept for an earlier decision under the key
/// goes from both.
#[cfg(feature = "sync")]
pub(super) fn index_decided_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: (EntityId, EntityId),
    actor: Option<EntityId>,
) -> Result<()> {
    let held = DECIDED_ACTOR.get(vault, &*txn, &key)?;
    if held == actor {
        return Ok(());
    }
    if let Some(held) = held {
        ACTOR_DECIDED.delete(vault, txn, &(held, key.0, key.1))?;
    }
    match actor {
        Some(actor) => {
            DECIDED_ACTOR.put(vault, txn, &key, &actor)?;
            ACTOR_DECIDED.put(vault, txn, &(actor, key.0, key.1), &())
        }
        None => DECIDED_ACTOR.delete(vault, txn, &key).map(drop),
    }
}

/// Deletes, in the erase's writer, each decision kept here of one of
/// `actor`'s wakes, with the actor kept beside it under both keys: an erase
/// leaves no decision of its actor, and no row that names it. The decisions
/// are read by the actor's own prefix alone, so a decision whose actor this
/// machine never learned stays, and so does one kept under another actor. An
/// index row whose key does not decode goes with the rest under the actor's
/// prefix, and a decision whose kept actor does not decode goes by its key
/// (FIX 5736).
#[cfg(feature = "sync")]
pub(super) fn erase_actor_decisions_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let mut keys = Vec::new();
    for row in ACTOR_DECIDED.iter_raw_from(vault, &*txn, actor.as_bytes())? {
        let (key, _) = row?;
        if let Some((_, turn, registration)) =
            <(EntityId, EntityId, EntityId) as SideKey>::decode_key(&key)
        {
            keys.push((turn, registration));
        }
    }
    for key in keys {
        if DECIDED_ACTOR
            .get_lenient(vault, &*txn, &key)?
            .is_none_or(|kept| kept == *actor)
        {
            DECIDED_ACTOR.delete(vault, txn, &key)?;
            super::DECIDED.delete(vault, txn, &key)?;
        }
    }
    ACTOR_DECIDED
        .delete_from(vault, txn, actor.as_bytes())
        .map(drop)
}
