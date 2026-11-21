//! The decided wakes of a vault's linked machines: what a carried
//! `Admitted` row does on this machine, and the `Admitted` rows this machine
//! writes for the decisions it holds. Moved whole out of `replica`, which
//! says what each carried row is and merges the other three.

use super::replica::{RowMerge, WakeRow, decode_wake, wake_key, wake_key_ids};
#[cfg(oneiron_test_support)]
use super::types::TurnProgramWake;
use super::{ADMISSION, DECIDED, WAKE};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

#[doc(hidden)]
use oneiron_records::dreamer_runner::program::replica::encode;

/// Whether `actor` is erased here (FIX TURNPROGRAM-ERASE-KEEPS-DECIDED). This
/// machine keeps no decision of such an actor's wake and writes no decision
/// row for one: the erase deleted what was kept, the merge refuses a row
/// that names the actor, and the scrub takes such rows out of the windows.
/// A decision whose actor this machine never learned (`None`) is no erased
/// actor's by anything it holds, and is taken as before.
pub(super) fn erased_here_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: Option<EntityId>,
) -> Result<bool> {
    match actor {
        Some(actor) => vault.carrier_actor_erased_in_txn(txn, &actor),
        None => Ok(false),
    }
}

/// The actor of the decision this machine holds for the wake keyed `key`
/// under `admission`, from its own rows alone: its admission record's actor,
/// else the actor kept beside the decision it imported. Never the actor a
/// carried `Retracted` or `Released` row asserts, which no digest proves.
/// The caller writes no row for an actor erased here
/// ([`erased_here_in_txn`]).
pub(super) fn decision_actor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: (EntityId, EntityId),
    admission: [u8; 32],
) -> Result<Option<EntityId>> {
    let own = ADMISSION
        .get(vault, txn, &admission)?
        .filter(|record| record.wake.key() == key)
        .map(|record| record.wake.authority.actor());
    match own {
        Some(actor) => Ok(Some(actor)),
        None if DECIDED.get(vault, txn, &key)? == Some(admission) => {
            super::index::decided_actor_in_txn(vault, txn, key)
        }
        None => Ok(None),
    }
}

/// Consumes, in the caller's writer, the wake an `Admitted` row decided: the
/// machine that admitted it (the home, or the recording machine) wrote that
/// terminal row, or a machine that imported the decision wrote it again, so
/// this machine never admits it again, whatever its own home role or the arming's state now (a
/// machine elected home after the old home decided still holds the wake it
/// recorded). The decision's identity is kept here (`DECIDED`), with or
/// without a wake to consume, so no later landing of the turn records the
/// wake again (FIX 5266). Only a wake whose own authority rides and whose
/// admission the row names goes. An occurrence's wake is admitted where it
/// was recorded, so a row that names one is refused, and no decision is kept
/// for it.
///
/// The decision's actor is kept beside it (FIX
/// TURNPROGRAM-ERASE-KEEPS-DECIDED): the actor of the wake the row consumes
/// here, which the admission proves (it is a digest over that actor), else
/// `named`, the actor the row itself names. A row that names none and
/// consumes no wake here keeps none, as every row did before the row named
/// its actor. A decision kept before gains its actor from a later row of the
/// same admission; an actor a wake proved is replaced by no row's word.
///
/// A row of an actor erased here is refused before any write: the actor of
/// the wake it would consume here, else the one it names. The erase deleted
/// the actor's decisions (`erase_turn_program_actor_in_txn`), and no row that
/// arrives after it keeps one again. A row that names another actor than the
/// wake owed here proves is never refused for that: it consumes the wake
/// under the proven actor, since a refusal would leave a live actor's wake
/// owed here for a second decision. A row that names no actor is refused for
/// no erase: nothing ties it to one.
pub(super) fn consume_decided_wake_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    map_key: &str,
    admission: [u8; 32],
    named: Option<EntityId>,
) -> Result<RowMerge> {
    let Some(key) = wake_key_ids(map_key) else {
        return Ok(RowMerge::Held);
    };
    let owed = WAKE.get(vault, &*txn, &key)?;
    if owed.as_ref().is_some_and(|wake| wake.occurrence.is_some()) {
        return Ok(RowMerge::Refused("names an occurrence's wake"));
    }
    // The wake this row decides, where it is owed here.
    let decided =
        owed.filter(|wake| wake.authority.rides_to_home() && wake.admission_id() == admission);
    let proven = decided.as_ref().map(|wake| wake.authority.actor());
    if erased_here_in_txn(vault, &*txn, proven.or(named))? {
        return Ok(RowMerge::Refused("names an actor erased here"));
    }
    let marked = DECIDED.get(vault, &*txn, &key)? == Some(admission);
    let kept = if marked || ADMISSION.contains(vault, &*txn, &admission)? {
        RowMerge::Held
    } else {
        DECIDED.put(vault, txn, &key, &admission)?;
        RowMerge::Written
    };
    if marked || kept == RowMerge::Written {
        let actor = match (kept, proven) {
            (_, Some(actor)) => Some(actor),
            // A decision first kept here: what its row says, and nothing an
            // earlier decision under the key left.
            (RowMerge::Written, None) => named,
            (_, None) => super::index::decided_actor_in_txn(vault, &*txn, key)?.or(named),
        };
        super::index::index_decided_in_txn(vault, txn, key, actor)?;
    }
    let Some(wake) = decided else {
        return Ok(kept);
    };
    WAKE.delete(vault, txn, &key)?;
    super::index::unindex_wake_in_txn(vault, txn, wake.authority.actor(), key)?;
    Ok(RowMerge::Written)
}

/// The `Admitted` rows TURN `turn` owes the window from this machine's own
/// decisions (FIX 5266): each wake of the turn this machine admitted whose
/// authority rides (never an occurrence's, which is admitted where it was
/// recorded),
/// whether or not a machine carried it as owed (the home admits its own
/// turns' wakes, which no `Owed` row ever carried), and each decision it
/// imported. A machine elected home later then holds every decision, and no
/// landing of the turn there wakes the program again. Each row names its
/// wake's actor where this machine knows it: its own admission's, an
/// imported decision's where its actor was kept with it. A decision of an
/// actor erased here owes no row (FIX TURNPROGRAM-ERASE-KEEPS-DECIDED): the
/// admission this machine keeps of it past the erase writes none.
pub(crate) fn turn_decided_rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut rows = Vec::new();
    for row in super::index::TURN_ADMISSION.iter_from(vault, txn, turn.as_bytes())? {
        let ((_, admission), ()) = row?;
        let Some(record) = ADMISSION.get(vault, txn, &admission)? else {
            continue;
        };
        if record.wake.occurrence.is_some() || !record.wake.authority.rides_to_home() {
            continue;
        }
        let actor = Some(record.wake.authority.actor());
        if erased_here_in_txn(vault, txn, actor)? {
            continue;
        }
        let (turn, registration) = record.wake.key();
        rows.push((
            wake_key((turn, registration)),
            encode(&WakeRow::Admitted {
                turn,
                registration,
                actor,
                admission,
            })?,
        ));
    }
    for row in DECIDED.iter_from(vault, txn, turn.as_bytes())? {
        let ((turn, registration), admission) = row?;
        let actor = super::index::decided_actor_in_txn(vault, txn, (turn, registration))?;
        if erased_here_in_txn(vault, txn, actor)? {
            continue;
        }
        rows.push((
            wake_key((turn, registration)),
            encode(&WakeRow::Admitted {
                turn,
                registration,
                actor,
                admission,
            })?,
        ));
    }
    Ok(rows)
}

/// Whether the carried wake row `bytes` is decided, so no machine writes
/// its wake over it.
pub(crate) fn wake_row_decided(bytes: &[u8]) -> bool {
    matches!(decode_wake(bytes), Ok(WakeRow::Admitted { .. }))
}

/// The `Admitted` row that replaces the carried `Owed` row `bytes` once this
/// machine holds its admission; `None` for any other row, and for the wake
/// of an actor erased here, whose decision goes into no window. It names the
/// carried wake's actor, which the admission it is matched by is a digest
/// over.
pub(crate) fn admitted_row_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    bytes: &[u8],
) -> Result<Option<Vec<u8>>> {
    let Ok(WakeRow::Owed(wake)) = decode_wake(bytes) else {
        return Ok(None);
    };
    // An occurrence's wake is admitted where it was recorded, never through
    // a carried row.
    if wake.occurrence.is_some() {
        return Ok(None);
    }
    let admission = wake.admission_id();
    let actor = Some(wake.authority.actor());
    if !ADMISSION.contains(vault, txn, &admission)? || erased_here_in_txn(vault, txn, actor)? {
        return Ok(None);
    }
    let (turn, registration) = wake.key();
    Ok(Some(encode(&WakeRow::Admitted {
        turn,
        registration,
        actor,
        admission,
    })?))
}

/// The `Admitted` row for the owed wake `wake`: its map key and bytes, as
/// the decision mirror encodes them. For the integration tests alone, which
/// carry a row no emitter builds: an occurrence's decision.
#[cfg(oneiron_test_support)]
pub(super) fn admitted_row_for_test(wake: &TurnProgramWake) -> Result<(String, Vec<u8>)> {
    let (turn, registration) = wake.key();
    Ok((
        wake_key((turn, registration)),
        encode(&WakeRow::Admitted {
            turn,
            registration,
            actor: Some(wake.authority.actor()),
            admission: wake.admission_id(),
        })?,
    ))
}
