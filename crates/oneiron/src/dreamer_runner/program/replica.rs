//! A vault's turn programs across its linked machines (FIX 5266; ruled by
//! the Engine 10-20: replicate the arming as a synced row, with the elected
//! home as the single admitting machine). The sync carriers
//! (`sync::turn_programs`) move the rows; this module says what rides and
//! what a carried row does here.
//!
//! - An arming rides the base window of the month it was armed in, as
//!   `Armed`; a disarm rides the base window of its own month, as
//!   `Disarmed`, and each machine that learns it keeps it (`DISARMED`) with
//!   its time. A carried arming arms a registration only when absent and
//!   only after any disarm of it this machine knows; a carried disarm ends
//!   only an arming made before it. Months that are never opened again need
//!   no write, and the order the windows arrive in changes nothing.
//! - An arming whose pinned arguments name a custody handle stays on its own
//!   machine, as before: custody never leaves the machine that holds it, so
//!   that program is run where its secrets are.
//! - A wake rides to the elected home when its authority verifies on any of
//!   the vault's machines (a capability slip with its signed instrument) and
//!   its arming rides. It rides the base window of its TURN; only the home
//!   takes it, when it holds neither that wake nor its admission, and the
//!   home's admission takes the row out of the window, which clears the
//!   machine that recorded it. A machine that is not the home admits no
//!   riding wake while a home is elected; every other wake, and every wake
//!   on a vault with no elected home, is admitted where it was recorded, as
//!   before.
//!
//! The carried rows trust the vault's own linked machines as the room rows
//! beside them do; each program still runs under its waking turn's own
//! authority, judged at admission.

use serde::{Deserialize, Serialize};

use super::types::{TurnProgramArming, TurnProgramDisarm, TurnProgramWake};
use super::{ADMISSION, ARM, DISARMED, WAKE};
use crate::Vault;
use crate::batch::secret_scan::LiftedKeys;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::sync::WindowKey;

/// The largest row either map carries whole; an arming past it stays on its
/// machine, as one that names a custody handle does.
pub(crate) const MAX_ROW_BYTES: usize = 1 << 16;

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("turn program row refused: {reason}"))
}

/// What a carried arming row says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ArmingRow {
    Armed(TurnProgramArming),
    Disarmed {
        actor: EntityId,
        registration: EntityId,
        at: u64,
    },
}

impl ArmingRow {
    fn registration(&self) -> EntityId {
        match self {
            Self::Armed(arming) => arming.registration,
            Self::Disarmed { registration, .. } => *registration,
        }
    }

    fn actor(&self) -> EntityId {
        match self {
            Self::Armed(arming) => arming.actor,
            Self::Disarmed { actor, .. } => *actor,
        }
    }
}

fn encode<T: Serialize>(row: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(row).map_err(|_| refused("does not encode"))
}

fn decode_arming(bytes: &[u8]) -> Result<ArmingRow> {
    if bytes.len() > MAX_ROW_BYTES {
        return Err(refused("too large"));
    }
    serde_json::from_slice(bytes).map_err(|_| refused("not an arming row"))
}

fn decode_wake(bytes: &[u8]) -> Result<TurnProgramWake> {
    if bytes.len() > MAX_ROW_BYTES {
        return Err(refused("too large"));
    }
    serde_json::from_slice(bytes).map_err(|_| refused("not a wake row"))
}

/// The map key an arming row rides under: its registration.
fn arming_key(registration: EntityId) -> String {
    registration.to_hex()
}

/// The map key a wake row rides under: its turn, then its registration.
fn wake_key(wake: &TurnProgramWake) -> String {
    format!("{}{}", wake.turn.turn.to_hex(), wake.registration.to_hex())
}

/// The turn and registration a wake map key names, in their one spelling.
pub(crate) fn wake_key_ids(map_key: &str) -> Option<(EntityId, EntityId)> {
    if map_key.len() != 64 || !map_key.is_char_boundary(32) {
        return None;
    }
    let (turn, registration) = map_key.split_at(32);
    let ids = (
        EntityId::from_hex(turn).ok()?,
        EntityId::from_hex(registration).ok()?,
    );
    (ids.0.to_hex() == turn && ids.1.to_hex() == registration).then_some(ids)
}

/// Whether `arming` rides the window plane: its pinned arguments name no
/// custody handle and its row fits a window.
fn arming_rides(arming: &TurnProgramArming) -> bool {
    !LiftedKeys::names_a_handle(&arming.definition.args)
        && encode(&ArmingRow::Armed(arming.clone())).is_ok_and(|row| row.len() <= MAX_ROW_BYTES)
}

/// Whether `wake` rides to the elected home: its authority verifies on any
/// machine and its arming, held here, rides.
fn wake_rides_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, wake: &TurnProgramWake) -> Result<bool> {
    if !wake.authority.rides_to_home() {
        return Ok(false);
    }
    Ok(ARM
        .get(vault, txn, &(wake.authority.actor(), wake.registration))?
        .is_some_and(|arming| arming_rides(&arming)))
}

/// Whether this machine is the vault's elected home; `None` when no home is
/// elected.
pub(crate) fn home_here_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Option<bool>> {
    let Some(home) =
        crate::dreamer_runner::DreamerRunnerStore::new(vault).home_node_designation_in_txn(txn)?
    else {
        return Ok(None);
    };
    let here = crate::identity::read_client_id_in_txn(vault, txn)?;
    Ok(Some(here.is_some_and(|id| id != 0 && id == home.node_id)))
}

/// Whether the drain on this machine passes `wake` by: a riding wake, while
/// another machine is the elected home, is the home's to admit.
pub(super) fn wake_is_the_homes_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    wake: &TurnProgramWake,
) -> Result<bool> {
    Ok(home_here_in_txn(vault, txn)? == Some(false) && wake_rides_in_txn(vault, txn, wake)?)
}

/// The checks every carried arming row passes, by its bytes alone: whole,
/// filed under its own registration, an `Armed` row's revision its pin's and
/// its arguments naming no custody handle.
pub(crate) fn admit_arming_row(map_key: &str, bytes: &[u8]) -> Result<()> {
    let row = decode_arming(bytes)?;
    if arming_key(row.registration()) != map_key {
        return Err(refused("filed under another registration"));
    }
    if let ArmingRow::Armed(arming) = &row
        && (arming.revision != arming.definition.revision()
            || LiftedKeys::names_a_handle(&arming.definition.args))
    {
        return Err(refused("an arming that does not ride"));
    }
    Ok(())
}

/// The checks every carried wake row passes, by its bytes alone: whole,
/// filed under its own turn and registration, sealed by an authority that
/// rides, and holding no owed status.
pub(crate) fn admit_wake_row(map_key: &str, bytes: &[u8]) -> Result<()> {
    let wake = decode_wake(bytes)?;
    if wake_key(&wake) != map_key {
        return Err(refused("filed under another wake"));
    }
    if !wake.authority.rides_to_home() || wake.held.is_some() {
        return Err(refused("a wake that does not ride"));
    }
    Ok(())
}

/// The actor a carried row of either map names, when it decodes.
pub(crate) fn arming_row_actor(bytes: &[u8]) -> Option<EntityId> {
    decode_arming(bytes).ok().map(|row| row.actor())
}

/// The actor a carried wake row names, when it decodes.
pub(crate) fn wake_row_actor(bytes: &[u8]) -> Option<EntityId> {
    decode_wake(bytes).ok().map(|wake| wake.authority.actor())
}

/// What merging one carried row did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RowMerge {
    Written,
    Held,
    Refused(&'static str),
}

/// Merges one carried arming row into this machine's armings, in the
/// caller's writer: an `Armed` row arms its registration when no arming of
/// it is held and no disarm of it this machine knows was made after it; a
/// `Disarmed` row ends an arming of it made before it, and is kept. A row
/// of an actor erased here, or one that differs from the arming held for
/// its registration, is refused.
pub(crate) fn merge_arming_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    map_key: &str,
    bytes: &[u8],
) -> Result<RowMerge> {
    if admit_arming_row(map_key, bytes).is_err() {
        return Ok(RowMerge::Refused("malformed"));
    }
    let row = decode_arming(bytes)?;
    if vault.carrier_actor_erased_in_txn(txn, &row.actor())? {
        return Ok(RowMerge::Refused("names an actor erased here"));
    }
    let key = (row.actor(), row.registration());
    match row {
        ArmingRow::Armed(arming) => {
            if let Some(held) = ARM.get(vault, &*txn, &key)? {
                return Ok(if held == arming {
                    RowMerge::Held
                } else {
                    RowMerge::Refused("differs from the arming held here")
                });
            }
            if DISARMED
                .get(vault, &*txn, &key)?
                .is_some_and(|disarm| disarm.at >= arming.armed_at)
            {
                return Ok(RowMerge::Held);
            }
            DISARMED.delete(vault, txn, &key)?;
            ARM.put(vault, txn, &key, &arming)?;
            Ok(RowMerge::Written)
        }
        ArmingRow::Disarmed { at, .. } => {
            if let Some(held) = ARM.get(vault, &*txn, &key)? {
                if held.armed_at > at {
                    return Ok(RowMerge::Held);
                }
                ARM.delete(vault, txn, &key)?;
            } else if DISARMED
                .get(vault, &*txn, &key)?
                .is_some_and(|disarm| disarm.at >= at)
            {
                return Ok(RowMerge::Held);
            }
            DISARMED.put(vault, txn, &key, &TurnProgramDisarm { at })?;
            Ok(RowMerge::Written)
        }
    }
}

/// Merges one carried wake row on the elected home, in the caller's writer:
/// owed here when its arming is held here and wakes on it, and neither the
/// wake nor its admission is. Anywhere but the home, and before its arming
/// arrives, it is left in the window.
pub(crate) fn merge_wake_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    map_key: &str,
    bytes: &[u8],
) -> Result<RowMerge> {
    if admit_wake_row(map_key, bytes).is_err() {
        return Ok(RowMerge::Refused("malformed"));
    }
    if home_here_in_txn(vault, txn)? != Some(true) {
        return Ok(RowMerge::Held);
    }
    let wake = decode_wake(bytes)?;
    let actor = wake.authority.actor();
    if vault.carrier_actor_erased_in_txn(txn, &actor)? {
        return Ok(RowMerge::Refused("names an actor erased here"));
    }
    if WAKE.contains(vault, &*txn, &wake.key())?
        || ADMISSION.contains(vault, &*txn, &wake.admission_id())?
    {
        return Ok(RowMerge::Held);
    }
    let Some(arming) = ARM.get(vault, &*txn, &(actor, wake.registration))? else {
        return Ok(RowMerge::Held);
    };
    if arming.revision != wake.revision || !arming.wakes_on(&wake.authority, &wake.turn) {
        return Ok(RowMerge::Refused("its arming here does not wake on it"));
    }
    WAKE.put(vault, txn, &wake.key(), &wake)?;
    super::index::index_wake_in_txn(vault, txn, actor, wake.key())?;
    Ok(RowMerge::Written)
}

/// Drops, in the caller's writer, the riding wake this machine recorded
/// under `map_key` once its row left the window: the home admitted it, or an
/// erase took it. The home keeps what it owes; a wake that does not ride was
/// never carried. Answers whether a wake went.
pub(crate) fn drop_wake_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    map_key: &str,
) -> Result<bool> {
    let Some(key) = wake_key_ids(map_key) else {
        return Ok(false);
    };
    if home_here_in_txn(vault, txn)? == Some(true) {
        return Ok(false);
    }
    let Some(wake) = WAKE.get(vault, &*txn, &key)? else {
        return Ok(false);
    };
    if !wake_rides_in_txn(vault, txn, &wake)? {
        return Ok(false);
    }
    WAKE.delete(vault, txn, &key)?;
    super::index::unindex_wake_in_txn(vault, txn, wake.authority.actor(), key)?;
    Ok(true)
}

/// The arming rows base window `window` carries from this machine's state:
/// each riding arming armed in its month, and each disarm this machine
/// knows made in it, keyed by registration.
pub(crate) fn month_arming_rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    window: &WindowKey,
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut rows = Vec::new();
    for row in ARM.iter_from(vault, txn, &[])? {
        let (_, arming) = row?;
        if WindowKey::from_timestamp(arming.armed_at) == *window && arming_rides(&arming) {
            rows.push((
                arming_key(arming.registration),
                encode(&ArmingRow::Armed(arming))?,
            ));
        }
    }
    for row in DISARMED.iter_from(vault, txn, &[])? {
        let ((actor, registration), disarm) = row?;
        if WindowKey::from_timestamp(disarm.at) == *window {
            rows.push((
                arming_key(registration),
                encode(&ArmingRow::Disarmed {
                    actor,
                    registration,
                    at: disarm.at,
                })?,
            ));
        }
    }
    Ok(rows)
}

/// Whether the carried arming row `bytes` is one this machine knows ended:
/// an `Armed` row a later disarm here ended, so a live window drops it.
pub(crate) fn arming_row_ended_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    bytes: &[u8],
) -> Result<bool> {
    let Ok(ArmingRow::Armed(arming)) = decode_arming(bytes) else {
        return Ok(false);
    };
    Ok(DISARMED
        .get(vault, txn, &(arming.actor, arming.registration))?
        .is_some_and(|disarm| disarm.at >= arming.armed_at))
}

/// The wake rows TURN `turn`'s base window carries from this machine's
/// state: each riding wake it owes for the turn, unless this machine is the
/// home, which admits its own.
pub(crate) fn turn_wake_rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Vec<(String, Vec<u8>)>> {
    if home_here_in_txn(vault, txn)? == Some(true) {
        return Ok(Vec::new());
    }
    let mut rows = Vec::new();
    for row in WAKE.iter_from(vault, txn, turn.as_bytes())? {
        let (_, wake) = row?;
        if wake.held.is_none() && wake_rides_in_txn(vault, txn, &wake)? {
            rows.push((wake_key(&wake), encode(&wake)?));
        }
    }
    Ok(rows)
}

/// Whether the carried wake row `bytes` is settled here, so the window
/// drops it: this machine holds its admission.
pub(crate) fn wake_row_admitted_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    bytes: &[u8],
) -> Result<bool> {
    let Ok(wake) = decode_wake(bytes) else {
        return Ok(false);
    };
    ADMISSION.contains(vault, txn, &wake.admission_id())
}
