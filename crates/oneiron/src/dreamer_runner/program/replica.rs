//! A vault's turn programs across its linked machines (FIX 5266; ruled by
//! the Engine 10-20: replicate the arming as a synced row, with the elected
//! home as the single admitting machine). The sync carriers
//! (`sync::turn_programs`) move the rows; this module says what rides and
//! what a carried row does here.
//!
//! - Each registration is armed once: its disarm always orders after its
//!   arming. Between intents of the same kind, the writer's recorded time,
//!   then the row's content digest decide. An arming rides the month it was
//!   armed in, as `Armed`; a disarm rides the base window of its own month,
//!   as `Disarmed`, and each machine that learns it keeps it (`DISARMED`).
//!   A carried row takes its registration only when it comes later in that
//!   order than the intent held here, so every machine that holds the same
//!   rows holds the same intent, whatever order they arrived in, and a
//!   machine never writes its own intent over a later one a window carries.
//! - An arming whose pinned arguments name a custody handle stays on its own
//!   machine, as before: custody never leaves the machine that holds it, so
//!   that program is run where its secrets are.
//! - A wake rides to the elected home when its authority verifies on any of
//!   the vault's machines (a capability slip with its signed instrument) and
//!   its arming rides, and its stored TURN can pack into a base window. A
//!   TURN excluded by world settings, off-record membership or source audience
//!   keeps its wake on the recording machine, which admits it there. A riding
//!   wake travels in the base window of its TURN, as `Owed`; only the home
//!   takes it, when it holds neither that wake nor its admission.
//!   Once the home decides it, the home writes `Admitted` in its place: the
//!   terminal row clears the machine that recorded the wake, also through a
//!   history-free replacement, and that machine never writes its wake over
//!   it. A machine that is not the home admits no riding wake while a home
//!   is elected; every other wake, and every wake on a vault with no elected
//!   home, is admitted where it was recorded, as before.
//!
//! The carried rows trust the vault's own linked machines as the room rows
//! beside them do; each program still runs under its waking turn's own
//! authority, judged at admission.

use serde::{Deserialize, Serialize};

use super::types::{TurnProgramArming, TurnProgramDisarm, TurnProgramWake};
use super::{ADMISSION, ARM, DECIDED, DISARMED, WAKE};
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
#[serde(rename_all = "snake_case", deny_unknown_fields)]
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

    /// The row's place in its registration's intent order: disarmed after
    /// armed, then the writer's recorded time and content digest between
    /// rows of the same kind.
    fn order(&self) -> Result<(u8, u64, [u8; 32])> {
        let (at, rank) = match self {
            Self::Armed(arming) => (arming.armed_at, 0),
            Self::Disarmed { at, .. } => (*at, 1),
        };
        Ok((rank, at, *blake3::hash(&encode(self)?).as_bytes()))
    }
}

/// What a carried wake row says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum WakeRow {
    /// A riding wake its recording machine still owes the home.
    Owed(TurnProgramWake),
    /// The home decided the wake: its admission's identity, and no more.
    Admitted {
        turn: EntityId,
        registration: EntityId,
        admission: [u8; 32],
    },
}

impl WakeRow {
    fn key(&self) -> (EntityId, EntityId) {
        match self {
            Self::Owed(wake) => wake.key(),
            Self::Admitted {
                turn, registration, ..
            } => (*turn, *registration),
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

fn decode_wake(bytes: &[u8]) -> Result<WakeRow> {
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
fn wake_key((turn, registration): (EntityId, EntityId)) -> String {
    format!("{}{}", turn.to_hex(), registration.to_hex())
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
/// machine, its arming held here rides, and its TURN can pack into a base
/// window in this snapshot.
fn wake_rides_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, wake: &TurnProgramWake) -> Result<bool> {
    if !wake.authority.rides_to_home() {
        return Ok(false);
    }
    if !ARM
        .get(vault, txn, &(wake.authority.actor(), wake.registration))?
        .is_some_and(|arming| arming_rides(&arming))
    {
        return Ok(false);
    }
    crate::sync::window::turn_packs_in_base_window_in_txn(vault, txn, &wake.turn.turn)
}

/// The intent this machine holds for `key`: its arming, else its disarm.
fn held_intent_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: (EntityId, EntityId),
) -> Result<Option<ArmingRow>> {
    if let Some(arming) = ARM.get(vault, txn, &key)? {
        return Ok(Some(ArmingRow::Armed(arming)));
    }
    Ok(DISARMED
        .get(vault, txn, &key)?
        .map(|disarm| ArmingRow::Disarmed {
            actor: key.0,
            registration: key.1,
            at: disarm.at,
        }))
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

/// The checks every carried wake row passes, by its bytes alone: whole and
/// filed under its own turn and registration; an `Owed` row sealed by an
/// authority that rides and holding no owed status.
pub(crate) fn admit_wake_row(map_key: &str, bytes: &[u8]) -> Result<()> {
    let row = decode_wake(bytes)?;
    if wake_key(row.key()) != map_key {
        return Err(refused("filed under another wake"));
    }
    if let WakeRow::Owed(wake) = &row {
        if !wake.authority.rides_to_home() {
            return Err(refused("a wake that does not ride"));
        }
        // A wake held on its lapsed slip rides with its hold (a home that
        // held it, then lost the election, hands it to the next): only the
        // lapse's own hold, never past the wake's own expiry.
        if let Some(held) = &wake.held
            && (held.reason != super::admit::AUTHORITY_LAPSED
                || held.expires_at
                    > wake
                        .turn
                        .landed_at
                        .saturating_add(super::admit::LAPSED_WAKE_HOLD_SECS))
        {
            return Err(refused("a hold that is not a lapsed slip's"));
        }
    }
    Ok(())
}

/// The actor a carried arming row names, when it decodes.
pub(crate) fn arming_row_actor(bytes: &[u8]) -> Option<EntityId> {
    decode_arming(bytes).ok().map(|row| row.actor())
}

/// The actor a carried `Owed` wake row names; an `Admitted` row names none.
pub(crate) fn wake_row_actor(bytes: &[u8]) -> Option<EntityId> {
    match decode_wake(bytes).ok()? {
        WakeRow::Owed(wake) => Some(wake.authority.actor()),
        WakeRow::Admitted { .. } => None,
    }
}

/// What merging one carried row did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RowMerge {
    Written,
    Held,
    Refused(&'static str),
}

/// Merges one carried arming row into this machine's intents, in the
/// caller's writer: it takes its registration when it comes later in the
/// registration's intent order than the intent held here, an `Armed` row
/// as the arming, a `Disarmed` row as the disarm this machine keeps. An
/// earlier row changes nothing. A row of an actor erased here is refused.
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
    if let Some(held) = held_intent_in_txn(vault, txn, key)?
        && held.order()? >= row.order()?
    {
        return Ok(RowMerge::Held);
    }
    match row {
        ArmingRow::Armed(arming) => {
            DISARMED.delete(vault, txn, &key)?;
            ARM.put(vault, txn, &key, &arming)?;
        }
        ArmingRow::Disarmed { at, .. } => {
            ARM.delete(vault, txn, &key)?;
            DISARMED.put(vault, txn, &key, &TurnProgramDisarm { at })?;
        }
    }
    Ok(RowMerge::Written)
}

/// Merges one carried wake row, in the caller's writer. An `Owed` row is
/// owed here on the elected home alone, when its arming is held here and
/// wakes on it and neither the wake nor its admission is; before its
/// arming, its pinned SKILL and its TURN arrive it is left in the window,
/// and a held row keeps its hold. An `Admitted` row consumes the riding wake
/// this machine recorded under its key, on any machine.
pub(crate) fn merge_wake_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    map_key: &str,
    bytes: &[u8],
) -> Result<RowMerge> {
    if admit_wake_row(map_key, bytes).is_err() {
        return Ok(RowMerge::Refused("malformed"));
    }
    let wake = match decode_wake(bytes)? {
        WakeRow::Owed(wake) => wake,
        WakeRow::Admitted { admission, .. } => {
            return Ok(
                if consume_decided_wake_in_txn(vault, txn, map_key, admission)? {
                    RowMerge::Written
                } else {
                    RowMerge::Held
                },
            );
        }
    };
    if home_here_in_txn(vault, txn)? != Some(true) {
        return Ok(RowMerge::Held);
    }
    let actor = wake.authority.actor();
    if vault.carrier_actor_erased_in_txn(txn, &actor)? {
        return Ok(RowMerge::Refused("names an actor erased here"));
    }
    if WAKE.contains(vault, &*txn, &wake.key())?
        || ADMISSION.contains(vault, &*txn, &wake.admission_id())?
        || DECIDED.get(vault, &*txn, &wake.key())? == Some(wake.admission_id())
    {
        return Ok(RowMerge::Held);
    }
    let Some(arming) = ARM.get(vault, &*txn, &(actor, wake.registration))? else {
        return Ok(RowMerge::Held);
    };
    if arming.revision != wake.revision || !arming.wakes_on(&wake.authority, &wake.turn) {
        return Ok(RowMerge::Refused("its arming here does not wake on it"));
    }
    // Every record the admission reads must have arrived here first: the
    // pinned SKILL and the TURN that owes the wake. Each syncs in its own
    // window, and a record not here yet is no moved pin and no missing turn:
    // the wake waits in the window and merges on a later pass. A record here
    // and since deleted is the admission's to judge.
    for record in [arming.definition.skill, wake.turn.turn] {
        if matches!(
            crate::vault::live_entity_row_in_txn(&vault.store, txn, &record)?,
            crate::vault::LiveEntityRow::Absent
        ) {
            return Ok(RowMerge::Held);
        }
    }
    WAKE.put(vault, txn, &wake.key(), &wake)?;
    super::index::index_wake_in_txn(vault, txn, actor, wake.key())?;
    Ok(RowMerge::Written)
}

/// Consumes, in the caller's writer, the wake an `Admitted` row decided: the
/// home that admitted it wrote that terminal row, so this machine never
/// admits it again, whatever its own home role or the arming's state now (a
/// machine elected home after the old home decided still holds the wake it
/// recorded). The decision's identity is kept here (`DECIDED`), with or
/// without a wake to consume, so no later landing of the turn records the
/// wake again (FIX 5266). Only a wake whose own authority rides and whose
/// admission the row names goes. Answers whether a row changed.
fn consume_decided_wake_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    map_key: &str,
    admission: [u8; 32],
) -> Result<bool> {
    let Some(key) = wake_key_ids(map_key) else {
        return Ok(false);
    };
    let kept = if DECIDED.get(vault, &*txn, &key)? == Some(admission)
        || ADMISSION.contains(vault, &*txn, &admission)?
    {
        false
    } else {
        DECIDED.put(vault, txn, &key, &admission)?;
        true
    };
    let Some(wake) = WAKE.get(vault, &*txn, &key)? else {
        return Ok(kept);
    };
    if !wake.authority.rides_to_home() || wake.admission_id() != admission {
        return Ok(kept);
    }
    WAKE.delete(vault, txn, &key)?;
    super::index::unindex_wake_in_txn(vault, txn, wake.authority.actor(), key)?;
    Ok(true)
}

/// Drops, in the caller's writer, the riding wake this machine recorded
/// under `map_key` once the window no longer holds it: an erase took it (a
/// decided wake arrives as an `Admitted` row instead). The home keeps what
/// it owes; a wake that does not ride was never carried. Answers whether a
/// wake went.
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

/// Whether the carried arming row `carried` comes no earlier in its
/// registration's intent order than `ours`, this machine's row for the same
/// key: then this machine leaves the window's row as it is, and its forward
/// merge takes it.
pub(crate) fn arming_row_outranks(carried: &[u8], ours: &[u8]) -> bool {
    match (decode_arming(carried), decode_arming(ours)) {
        (Ok(carried), Ok(ours)) => match (carried.order(), ours.order()) {
            (Ok(carried), Ok(ours)) => carried >= ours,
            _ => false,
        },
        _ => false,
    }
}

/// Whether the carried arming row `bytes` comes earlier in its
/// registration's intent order than the intent this machine holds, so a
/// live window drops it.
pub(crate) fn arming_row_outranked_here_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    bytes: &[u8],
) -> Result<bool> {
    let Ok(row) = decode_arming(bytes) else {
        return Ok(false);
    };
    let Some(held) = held_intent_in_txn(vault, txn, (row.actor(), row.registration()))? else {
        return Ok(false);
    };
    Ok(held.order()? > row.order()?)
}

/// The `Owed` rows TURN `turn`'s base window carries from this machine's
/// state: each riding wake it owes for the turn, unless this machine is the
/// home, which admits its own. A wake held on its lapsed slip rides with its
/// hold: one this machine held while it was the home goes to the home
/// elected since, which admits it at its rebind or its expiry.
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
        if wake_rides_in_txn(vault, txn, &wake)? {
            rows.push((wake_key(wake.key()), encode(&WakeRow::Owed(wake))?));
        }
    }
    Ok(rows)
}

/// The `Admitted` rows TURN `turn` owes the window from this machine's own
/// decisions (FIX 5266): each riding wake of the turn this machine admitted,
/// whether or not a machine carried it as owed (the home admits its own
/// turns' wakes, which no `Owed` row ever carried), and each decision it
/// imported. A machine elected home later then holds every decision, and no
/// landing of the turn there wakes the program again.
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
        if !record.wake.authority.rides_to_home() {
            continue;
        }
        let (turn, registration) = record.wake.key();
        rows.push((
            wake_key((turn, registration)),
            encode(&WakeRow::Admitted {
                turn,
                registration,
                admission,
            })?,
        ));
    }
    for row in DECIDED.iter_from(vault, txn, turn.as_bytes())? {
        let ((turn, registration), admission) = row?;
        rows.push((
            wake_key((turn, registration)),
            encode(&WakeRow::Admitted {
                turn,
                registration,
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
/// machine holds its admission; `None` for any other row.
pub(crate) fn admitted_row_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    bytes: &[u8],
) -> Result<Option<Vec<u8>>> {
    let Ok(WakeRow::Owed(wake)) = decode_wake(bytes) else {
        return Ok(None);
    };
    let admission = wake.admission_id();
    if !ADMISSION.contains(vault, txn, &admission)? {
        return Ok(None);
    }
    let (turn, registration) = wake.key();
    Ok(Some(encode(&WakeRow::Admitted {
        turn,
        registration,
        admission,
    })?))
}

/// Where a carried row of either map goes in a checkpoint.
pub(crate) enum RowPlacement {
    /// In its actor's compartment, held while each dependency is.
    Owned {
        owner: EntityId,
        dependencies: Vec<EntityId>,
    },
    /// Ids alone, dropped with each entity it names.
    Structure { dependencies: Vec<EntityId> },
}

/// Where the arming row `bytes` goes: its actor's, held while the
/// conversation it listens to is.
pub(crate) fn arming_row_placement(bytes: &[u8]) -> Option<RowPlacement> {
    Some(match decode_arming(bytes).ok()? {
        ArmingRow::Armed(arming) => RowPlacement::Owned {
            owner: arming.actor,
            dependencies: arming.conversation.into_iter().collect(),
        },
        ArmingRow::Disarmed { actor, .. } => RowPlacement::Owned {
            owner: actor,
            dependencies: Vec::new(),
        },
    })
}

/// Where the wake row `bytes` goes: an `Owed` row is its actor's, held while
/// its turn and conversation are; an `Admitted` row is ids alone, held while
/// its turn is.
pub(crate) fn wake_row_placement(bytes: &[u8]) -> Option<RowPlacement> {
    Some(match decode_wake(bytes).ok()? {
        WakeRow::Owed(wake) => RowPlacement::Owned {
            owner: wake.authority.actor(),
            dependencies: vec![wake.turn.turn, wake.turn.conversation],
        },
        WakeRow::Admitted { turn, .. } => RowPlacement::Structure {
            dependencies: vec![turn],
        },
    })
}
