//! The acknowledged retraction of a carried wake (FIX
//! TURNPROGRAM-LATE-WITHHOLD-DOUBLE-DECIDE).
//!
//! A riding wake is the elected home's to admit, and the home may hold a copy
//! of it that it has not decided. When the wake stops riding from the machine
//! that recorded it (its TURN is withheld, say), that machine must not admit
//! it by itself: both machines would decide it. It asks for the wake back
//! instead, through the window that carried it.
//!
//! - The recording machine marks a wake before the window carries its `Owed`
//!   row ([`mark_carried_wakes`]). While another machine is the home, a marked
//!   wake is admitted here by no door, whether or not it still rides.
//! - Once a marked wake no longer rides, the mark turns `Retracted`
//!   ([`Vault::retract_unridden_turn_program_wakes`]) and the window carries a
//!   `Retracted` row in the `Owed` row's place. The retraction is final: no
//!   `Owed` row is written for that wake again.
//! - The home answers in one writer ([`merge_retracted_in_txn`]). A decision
//!   it holds stands, and its `Admitted` row consumes the wake on the
//!   recording machine as before. Otherwise it drops the copy it took from the
//!   window, keeps the release, and the window carries a `Released` row.
//! - A `Released` row turns the mark `Released` ([`merge_released_in_txn`]):
//!   the recording machine admits the wake, whatever rides by then.
//!
//! On one key the rows are ordered `Owed`, `Retracted`, `Released`,
//! `Admitted`, and no machine writes a row over a later one. A window keeps
//! one writer's row when two write at once, so each machine writes the latest
//! row it knows again on every pass ([`outranking_wake_row_in_txn`]).
//!
//! A wake recorded while this machine's own view names it the home, or names
//! no home, is admitted where it was recorded, mark or no mark, as before.
//!
//! A copy the home took from a window is the home's alone to admit (FIX
//! TURNPROGRAM-HOME-CHANGE-CARRIED-COPY-DOUBLE-DECIDE). On a machine that is
//! the home no more, the copy is admitted by no door and rides under no row,
//! and that machine's next pass drops it
//! ([`Vault::drop_imported_turn_program_wakes_off_home`]). The wake stays with
//! its recording machine, which carries it to the home the election names now,
//! or admits it itself once it is that home or no home is elected.

use serde::{Deserialize, Serialize};

use super::replica::{self, RowMerge, WakeRow};
use super::types::TurnProgramWake;
use super::{ADMISSION, DECIDED, WAKE};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::sync::WindowKey;

#[doc(hidden)]
use oneiron_records::dreamer_runner::program::replica::encode;

/// How far the recording machine has come with a wake it carried as owed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CarriedState {
    /// The window carries its `Owed` row, or is about to.
    Owed,
    /// It no longer rides from here: the home is asked to release it.
    Retracted,
    /// The home released it: this machine admits it.
    Released,
}

/// The recording machine's mark of one wake it carried as owed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CarriedWake {
    /// The marked wake's admission identity.
    admission: [u8; 32],
    /// The base window that carries the wake's row.
    window: String,
    state: CarriedState,
}

/// The key of every table here: the wake's actor, then the wake's own key
/// (its turn, then its registration), so an actor's erase takes its rows by
/// their prefix.
type ActorWakeKey = (EntityId, EntityId, EntityId);

/// One wake this machine recorded and carried as owed.
const CARRIED: SideTable<ActorWakeKey, CarriedWake, Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_WAKE_CARRIED);
/// One owed wake this machine took from a window as the home.
const IMPORTED: SideTable<ActorWakeKey, (), Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_WAKE_IMPORTED);
/// One retracted wake this machine released as the home: the admission
/// identity it released.
const RELEASED: SideTable<ActorWakeKey, [u8; 32], Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_WAKE_RELEASED);

fn actor_wake_key(actor: EntityId, (turn, registration): (EntityId, EntityId)) -> ActorWakeKey {
    (actor, turn, registration)
}

impl WakeRow {
    /// The row's place in its key's order: no machine writes a row over one
    /// that comes later.
    fn rank(&self) -> u8 {
        match self {
            Self::Owed(_) => 0,
            Self::Retracted { .. } => 1,
            Self::Released { .. } => 2,
            Self::Admitted { .. } => 3,
        }
    }
}

/// The state of the mark this machine keeps for `wake`; `None` for a wake it
/// never carried as owed.
pub(super) fn carried_state_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    wake: &TurnProgramWake,
) -> Result<Option<CarriedState>> {
    Ok(CARRIED
        .get(
            vault,
            txn,
            &actor_wake_key(wake.authority.actor(), wake.key()),
        )?
        .filter(|carried| carried.admission == wake.admission_id())
        .map(|carried| carried.state))
}

/// Whether `wake` waits here for the elected home to release it: this
/// machine retracted it, and another machine is the home.
pub(super) fn wake_awaits_release_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    wake: &TurnProgramWake,
) -> Result<bool> {
    Ok(replica::home_here_in_txn(vault, txn)? == Some(false)
        && carried_state_in_txn(vault, txn, wake)? == Some(CarriedState::Retracted))
}

/// Marks the owed wake keyed `key` as one this machine took from a window,
/// in the writer that takes it.
pub(super) fn mark_imported_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    key: (EntityId, EntityId),
) -> Result<()> {
    IMPORTED.put(vault, txn, &actor_wake_key(actor, key), &())
}

/// Whether `wake` is a copy this machine took from a window as the home,
/// not a wake it recorded.
pub(super) fn imported_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    wake: &TurnProgramWake,
) -> Result<bool> {
    IMPORTED.contains(
        vault,
        txn,
        &actor_wake_key(wake.authority.actor(), wake.key()),
    )
}

/// Whether this machine, as the home, released the wake keyed `key` under
/// `admission`: it takes no `Owed` row of that wake again.
pub(super) fn released_here_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    key: (EntityId, EntityId),
    admission: [u8; 32],
) -> Result<bool> {
    Ok(RELEASED.get(vault, txn, &actor_wake_key(actor, key))? == Some(admission))
}

/// Drops the marks of the owed wake keyed `key`, in the writer that deletes
/// the wake.
pub(super) fn forget_wake_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    key: (EntityId, EntityId),
) -> Result<()> {
    let key = actor_wake_key(actor, key);
    CARRIED.delete(vault, txn, &key)?;
    IMPORTED.delete(vault, txn, &key).map(drop)
}

/// Drops every mark and release kept for `actor`'s wakes, in the erase's
/// writer: a row whose wake does not decode goes too.
pub(super) fn erase_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    CARRIED.delete_from(vault, txn, actor.as_bytes())?;
    IMPORTED.delete_from(vault, txn, actor.as_bytes())?;
    RELEASED.delete_from(vault, txn, actor.as_bytes()).map(drop)
}

/// Whether this machine holds a decision of the riding wake keyed `key`
/// under `admission`: its own admission, or one another machine carried here.
fn decided_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: (EntityId, EntityId),
    admission: [u8; 32],
) -> Result<bool> {
    if DECIDED.get(vault, txn, &key)? == Some(admission) {
        return Ok(true);
    }
    Ok(ADMISSION
        .get(vault, txn, &admission)?
        .is_some_and(|record| {
            record.wake.key() == key
                && record.wake.occurrence.is_none()
                && record.wake.authority.rides_to_home()
        }))
}

/// What the window may carry for one wake about to ride as owed from here.
enum Ride {
    /// Nothing: the wake went, this machine retracted it, or it is a copy
    /// taken from a window, which its own recording machine carries.
    Never,
    /// Its `Owed` row: its mark stands.
    Owed,
    /// Its `Owed` row, once this mark is written.
    Unmarked(ActorWakeKey, [u8; 32]),
}

fn ride_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, map_key: &str) -> Result<Ride> {
    let Some(key) = replica::wake_key_ids(map_key) else {
        return Ok(Ride::Never);
    };
    let Some(wake) = WAKE.get(vault, txn, &key)? else {
        return Ok(Ride::Never);
    };
    let mark = actor_wake_key(wake.authority.actor(), key);
    if IMPORTED.contains(vault, txn, &mark)? {
        return Ok(Ride::Never);
    }
    Ok(match CARRIED.get(vault, txn, &mark)? {
        Some(carried) if carried.admission == wake.admission_id() => {
            if carried.state == CarriedState::Owed {
                Ride::Owed
            } else {
                Ride::Never
            }
        }
        _ => Ride::Unmarked(mark, wake.admission_id()),
    })
}

/// Marks each wake about to ride base window `window` as owed under one of
/// `map_keys`, before the window carries its row, and answers the keys whose
/// `Owed` rows may be written. The mark commits first: a wake the window
/// carries without one could be admitted here later while the home holds its
/// copy. A wake admitted or retracted since the caller read it rides no more.
pub(crate) fn mark_carried_wakes(
    vault: &Vault,
    window: &WindowKey,
    map_keys: &[String],
) -> Result<Vec<String>> {
    {
        let txn = vault.store.env.read_txn()?;
        let mut rides = Vec::new();
        let mut unmarked = false;
        for map_key in map_keys {
            match ride_in_txn(vault, &txn, map_key)? {
                Ride::Never => {}
                Ride::Owed => rides.push(map_key.clone()),
                Ride::Unmarked(..) => unmarked = true,
            }
        }
        if !unmarked {
            return Ok(rides);
        }
    }
    vault.with_write_txn_grouped(|txn| {
        let mut rides = Vec::new();
        for map_key in map_keys {
            match ride_in_txn(vault, &*txn, map_key)? {
                Ride::Never => {}
                Ride::Owed => rides.push(map_key.clone()),
                Ride::Unmarked(mark, admission) => {
                    let carried = CarriedWake {
                        admission,
                        window: window.as_str().to_owned(),
                        state: CarriedState::Owed,
                    };
                    CARRIED.put(vault, txn, &mark, &carried)?;
                    rides.push(map_key.clone());
                }
            }
        }
        Ok(rides)
    })
}

/// The marked wakes that no longer ride from this machine while another
/// machine is the home.
fn unridden_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Vec<ActorWakeKey>> {
    if replica::home_here_in_txn(vault, txn)? != Some(false) {
        return Ok(Vec::new());
    }
    let mut unridden = Vec::new();
    for row in CARRIED.iter_from(vault, txn, &[])? {
        let (mark, carried) = row?;
        if carried.state != CarriedState::Owed {
            continue;
        }
        let Some(wake) = WAKE.get(vault, txn, &(mark.1, mark.2))? else {
            continue;
        };
        if wake.admission_id() == carried.admission
            && !replica::wake_rides_in_txn(vault, txn, &wake)?
        {
            unridden.push(mark);
        }
    }
    Ok(unridden)
}

/// Turns `Retracted`, in one writer, the mark of each wake
/// [`unridden_in_txn`] names there. Answers how many.
fn retract_unridden(vault: &Vault) -> Result<usize> {
    let none = {
        let txn = vault.store.env.read_txn()?;
        unridden_in_txn(vault, &txn)?.is_empty()
    };
    if none {
        return Ok(0);
    }
    vault.with_write_txn_grouped(|txn| {
        let unridden = unridden_in_txn(vault, &*txn)?;
        for mark in &unridden {
            if let Some(mut carried) = CARRIED.get(vault, &*txn, mark)? {
                carried.state = CarriedState::Retracted;
                CARRIED.put(vault, txn, mark, &carried)?;
            }
        }
        Ok(unridden.len())
    })
}

impl Vault {
    /// Retracts each wake this machine carried as owed that no longer rides
    /// from it while another machine is the home: its mark turns `Retracted`
    /// in one writer, and the pass then writes its `Retracted` row. The wake
    /// stays owed here until the home releases it or decides it. Housekeeping
    /// runs it on every pass, before it admits what is owed. A failure is
    /// logged and waits for the next pass: the wake is admitted by no door
    /// meanwhile.
    pub(crate) fn retract_unridden_turn_program_wakes(&self) {
        match retract_unridden(self) {
            Ok(0) => {}
            Ok(retracted) => tracing::debug!(retracted, "turn program wakes retracted"),
            Err(error) => {
                tracing::warn!(%error, "turn program wakes not retracted; they wait for the next pass");
            }
        }
    }
}

/// Drops, in one writer, each owed wake this machine took from a window as
/// the home, unless it is the home. Answers how many.
fn drop_imported_off_home(vault: &Vault) -> Result<usize> {
    let none = {
        let txn = vault.store.env.read_txn()?;
        replica::home_here_in_txn(vault, &txn)? == Some(true)
            || IMPORTED.scan_keys(vault, &txn, &[])?.is_empty()
    };
    if none {
        return Ok(0);
    }
    vault.with_write_txn_grouped(|txn| {
        if replica::home_here_in_txn(vault, &*txn)? == Some(true) {
            return Ok(0);
        }
        let copies = IMPORTED.scan_keys(vault, &*txn, &[])?;
        for (actor, turn, registration) in &copies {
            let key = (*turn, *registration);
            WAKE.delete(vault, txn, &key)?;
            super::index::unindex_wake_in_txn(vault, txn, *actor, key)?;
        }
        Ok(copies.len())
    })
}

impl Vault {
    /// Drops each owed wake this machine took from a window as the home, once
    /// it is the home no more: another machine is, or none is elected (FIX
    /// TURNPROGRAM-HOME-CHANGE-CARRIED-COPY-DOUBLE-DECIDE). The copy goes
    /// undecided, in one writer. Its recording machine still owes the wake
    /// and carries it to the home elected now, so a machine elected the home
    /// again takes it from the window again. A wake this machine recorded
    /// itself is no copy and stays. Housekeeping runs it on every pass,
    /// before it admits what is owed. A failure is logged and waits for the
    /// next pass: a copy is admitted by no door off the home meanwhile.
    pub(crate) fn drop_imported_turn_program_wakes_off_home(&self) {
        match drop_imported_off_home(self) {
            Ok(0) => {}
            Ok(dropped) => {
                tracing::debug!(dropped, "turn program wake copies dropped off the home");
            }
            Err(error) => {
                tracing::warn!(%error, "turn program wake copies not dropped off the home; they wait for the next pass");
            }
        }
    }
}

/// Whether this machine waits for the home's answer to a wake it retracted.
pub(crate) fn awaits_release_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    for row in CARRIED.iter_from(vault, txn, &[])? {
        if row?.1.state == CarriedState::Retracted {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The home's answer to a `Retracted` row, in the caller's writer, on the
/// machine its own view names the home. A decision held here stands, and its
/// `Admitted` row answers. Otherwise the copy this machine took from a window
/// goes, undecided, and the release is kept, so no `Owed` row of that wake is
/// taken here again; the window then carries `Released`. A wake this machine
/// recorded itself under the same key is its own to decide: it stays, and its
/// decision answers. A row that names an occurrence's wake, or another wake
/// than the one held under its key, is refused.
pub(super) fn merge_retracted_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: (EntityId, EntityId),
    actor: EntityId,
    admission: [u8; 32],
) -> Result<RowMerge> {
    if replica::home_here_in_txn(vault, txn)? != Some(true) {
        return Ok(RowMerge::Held);
    }
    if vault.carrier_actor_erased_in_txn(txn, &actor)? {
        return Ok(RowMerge::Refused("names an actor erased here"));
    }
    let mark = actor_wake_key(actor, key);
    if RELEASED.get(vault, &*txn, &mark)? == Some(admission)
        || decided_in_txn(vault, &*txn, key, admission)?
    {
        return Ok(RowMerge::Held);
    }
    if let Some(wake) = WAKE.get(vault, &*txn, &key)? {
        if wake.occurrence.is_some() {
            return Ok(RowMerge::Refused("names an occurrence's wake"));
        }
        if wake.authority.actor() != actor || wake.admission_id() != admission {
            return Ok(RowMerge::Refused(
                "names another wake than the one owed here",
            ));
        }
        if !IMPORTED.contains(vault, &*txn, &mark)? {
            return Ok(RowMerge::Held);
        }
        WAKE.delete(vault, txn, &key)?;
        super::index::unindex_wake_in_txn(vault, txn, actor, key)?;
    }
    RELEASED.put(vault, txn, &mark, &admission)?;
    Ok(RowMerge::Written)
}

/// Takes a `Released` row, in the caller's writer. On the machine that
/// retracted the wake under the same admission, the mark turns `Released`:
/// its drain admits the wake, once no hold of the wake's own and no deferred
/// edge of its TURN keeps it. A machine that holds a copy of that wake
/// it took from a window drops the copy: the recording machine admits the
/// wake. Any other machine keeps what it holds.
pub(super) fn merge_released_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: (EntityId, EntityId),
    actor: EntityId,
    admission: [u8; 32],
) -> Result<RowMerge> {
    let mark = actor_wake_key(actor, key);
    if let Some(mut carried) = CARRIED.get(vault, &*txn, &mark)? {
        if carried.admission != admission || carried.state != CarriedState::Retracted {
            return Ok(RowMerge::Held);
        }
        carried.state = CarriedState::Released;
        CARRIED.put(vault, txn, &mark, &carried)?;
        return Ok(RowMerge::Written);
    }
    if IMPORTED.contains(vault, &*txn, &mark)?
        && WAKE
            .get(vault, &*txn, &key)?
            .is_some_and(|wake| wake.authority.actor() == actor && wake.admission_id() == admission)
    {
        WAKE.delete(vault, txn, &key)?;
        super::index::unindex_wake_in_txn(vault, txn, actor, key)?;
        return Ok(RowMerge::Written);
    }
    Ok(RowMerge::Held)
}

/// The row this machine knows that comes later in its key's order than the
/// carried row `bytes`, filed under `map_key`: `Admitted` for a decision held
/// here, `Released` for a release kept or taken here, `Retracted` for a wake
/// retracted here. `None` when the carried row is the latest this machine
/// knows, or names an occurrence's wake, which no carried row decides.
pub(crate) fn outranking_wake_row_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    map_key: &str,
    bytes: &[u8],
) -> Result<Option<Vec<u8>>> {
    let Ok(carried) = replica::decode_wake(bytes) else {
        return Ok(None);
    };
    let key = carried.key();
    let (turn, registration) = key;
    let (actor, admission) = match &carried {
        WakeRow::Owed(wake) if wake.occurrence.is_none() => {
            (wake.authority.actor(), wake.admission_id())
        }
        WakeRow::Retracted {
            actor, admission, ..
        }
        | WakeRow::Released {
            actor, admission, ..
        } => (*actor, *admission),
        WakeRow::Owed(_) | WakeRow::Admitted { .. } => return Ok(None),
    };
    if replica::wake_key(key) != map_key {
        return Ok(None);
    }
    let mark = actor_wake_key(actor, key);
    let state = CARRIED
        .get(vault, txn, &mark)?
        .filter(|carried| carried.admission == admission)
        .map(|carried| carried.state);
    let known = if decided_in_txn(vault, txn, key, admission)? {
        WakeRow::Admitted {
            turn,
            registration,
            admission,
        }
    } else if state == Some(CarriedState::Released)
        || RELEASED.get(vault, txn, &mark)? == Some(admission)
    {
        WakeRow::Released {
            turn,
            registration,
            actor,
            admission,
        }
    } else if state == Some(CarriedState::Retracted) {
        WakeRow::Retracted {
            turn,
            registration,
            actor,
            admission,
        }
    } else {
        return Ok(None);
    };
    if known.rank() <= carried.rank() {
        return Ok(None);
    }
    Ok(Some(encode(&known)?))
}

/// The `Retracted` and `Released` rows base window `window` carries from
/// this machine's marks, whether or not the window still holds their keys: a
/// retraction whose `Owed` row never reached the window is answered too.
pub(crate) fn retracted_wake_rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    window: &WindowKey,
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut rows = Vec::new();
    for row in CARRIED.iter_from(vault, txn, &[])? {
        let ((actor, turn, registration), carried) = row?;
        if carried.window != window.as_str() {
            continue;
        }
        let admission = carried.admission;
        let row = match carried.state {
            CarriedState::Owed => continue,
            CarriedState::Retracted => WakeRow::Retracted {
                turn,
                registration,
                actor,
                admission,
            },
            CarriedState::Released => WakeRow::Released {
                turn,
                registration,
                actor,
                admission,
            },
        };
        rows.push((replica::wake_key((turn, registration)), encode(&row)?));
    }
    Ok(rows)
}
