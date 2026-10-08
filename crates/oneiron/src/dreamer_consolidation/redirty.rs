//! The re-dirty carrier: the latest dirty POSITION of a TURN whose final words
//! changed after a round may have consumed it.
//!
//! Selection reads TURNs at their `learned_at` temporal key, strictly after a
//! scope cursor. A changed TURN cannot always move its own row ahead of that
//! cursor: a DAG record TURN is append-only, and a caller's backdated
//! occurrence can land a re-put behind a cursor that a later TURN already
//! advanced. This vault-local table holds the position such a TURN takes
//! instead. Its EFFECTIVE position is its row's `learned_at`, or its carrier
//! when the carrier is later and the TURN is live. Selection, settlement and
//! the partition-round identity read the effective position; the fence's
//! source pins keep the row's own `learned_at`, which a carrier never touches.
//!
//! One latest row per TURN, never cleared by a round: each scope cursor moves
//! past it on its own. Like stream finality, the row is local to this vault.
use super::watermark::{ConsolidationWatermark, read_watermark_in_txn};
use crate::Vault;
use crate::dreamer_runner::DreamerConsolidationScope;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EntityStoreRead, EntityTime, PortRows, TombstoneStoreRead};
use crate::registry::ENTITY_TYPE_TURN;
use crate::side_table::{self, Named, SideTable};
use std::collections::BTreeMap;
use std::iter::Peekable;

/// Latest re-dirty position of one TURN. Key: id16 (TURN id).
const REDIRTY: SideTable<EntityId, u64, Named> = SideTable::new(&side_table::DREAMER_TURN_REDIRTY);

fn overflow() -> Error {
    Error::ArithmeticOverflow("dreamer turn re-dirty position")
}

/// Re-dirties `turn` in the caller's write transaction. Its carrier takes a
/// position strictly after every persisted scope cursor and after the TURN's
/// current effective position, and no earlier than the writer clock or the
/// caller's `occurred_at`, so the next scan of every scope selects it again
/// and its round gets a new identity. The TURN row is left byte-identical. A
/// deleted TURN has no dirty work and is left alone.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when no row exists, a corrupted-index error when
/// the row is not a TURN, and [`Error::ArithmeticOverflow`] when no later
/// position exists.
pub(crate) fn redirty_turn_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
    occurred_at: u64,
) -> Result<()> {
    let row = vault
        .store
        .port_entity_record(txn, turn)?
        .ok_or(Error::EntityNotFound)?;
    if row.entity_type != ENTITY_TYPE_TURN {
        return Err(Error::CorruptedIndex("re-dirtied row is not a TURN"));
    }
    if !is_live(vault, txn, turn)? {
        return Ok(());
    }
    let current = REDIRTY
        .get(&vault.store, txn, turn)?
        .map_or(row.learned_at, |carried| carried.max(row.learned_at));
    let mut position = current
        .checked_add(1)
        .ok_or_else(overflow)?
        .max(occurred_at)
        .max(crate::ports::recorded_at_in_txn(&vault.store, txn)?);
    for scope in [
        DreamerConsolidationScope::Micro,
        DreamerConsolidationScope::Meso,
        DreamerConsolidationScope::Macro,
    ] {
        let cursor = read_watermark_in_txn(vault, txn, scope)?;
        position = position.max(first_position_after(&cursor, turn)?);
    }
    REDIRTY.put(&vault.store, txn, turn, &position)
}

/// The effective dirty position of `turn`, whose row carries `stored`, in the
/// caller's snapshot: its carrier when that is later and the TURN is live,
/// else `stored`.
pub(super) fn effective_learned_at_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    stored: u64,
) -> Result<u64> {
    effective(
        vault,
        txn,
        turn,
        stored,
        REDIRTY.get(&vault.store, txn, turn)?,
    )
}

fn effective(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    stored: u64,
    carried: Option<u64>,
) -> Result<u64> {
    let Some(carried) = carried.filter(|carried| *carried > stored) else {
        return Ok(stored);
    };
    Ok(if is_live(vault, txn, turn)? {
        carried
    } else {
        stored
    })
}

fn is_live(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    let state = vault.store.port_deletion_state(txn, id)?;
    Ok(!(state.deleted || state.stale))
}

/// The first position at which `turn` lies strictly after `cursor`, exactly as
/// the temporal seek reads it: anywhere after a before-first rescan, past the
/// whole second of an end-of-second cursor, and inside the cursor's own second
/// only for an id above its exact key.
fn first_position_after(cursor: &ConsolidationWatermark, turn: &EntityId) -> Result<u64> {
    if cursor.before_first {
        return Ok(0);
    }
    match cursor.last_turn_id {
        Some(last) if *turn > last => Ok(cursor.last_learned_at),
        _ => cursor.last_learned_at.checked_add(1).ok_or_else(overflow),
    }
}

fn after_cursor(cursor: &ConsolidationWatermark, position: u64, turn: &EntityId) -> bool {
    if cursor.before_first {
        return true;
    }
    match cursor.last_turn_id {
        None => position > cursor.last_learned_at,
        Some(last) => (position, *turn) > (cursor.last_learned_at, last),
    }
}

/// One entry of the merged dirty stream, at a temporal or carried position.
pub(super) struct DirtyCandidate {
    pub(super) position: u64,
    pub(super) turn: EntityId,
    carried: bool,
}

/// Every carrier row of one snapshot, merged into the temporal scan so each
/// TURN is enumerated once, at its effective position.
pub(super) struct DirtyCarriers {
    latest: BTreeMap<EntityId, u64>,
}

impl DirtyCarriers {
    pub(super) fn read(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Self> {
        Ok(Self {
            latest: REDIRTY.scan(&vault.store, txn)?.into_iter().collect(),
        })
    }

    /// The temporal stream and every carrier strictly after `cursor` (and
    /// through `upper_inclusive`), in one `(position, id)` order. A carrier
    /// that does not lead its row still appears here; [`Self::stands`] drops
    /// whichever of the two entries is not the TURN's effective position.
    pub(super) fn merge<'t>(
        &self,
        timeline: PortRows<'t, EntityTime>,
        cursor: &ConsolidationWatermark,
        upper_inclusive: Option<u64>,
    ) -> Merged<'t> {
        let mut carried: Vec<(u64, EntityId)> = self
            .latest
            .iter()
            .filter(|(turn, position)| {
                after_cursor(cursor, **position, turn)
                    && upper_inclusive.is_none_or(|upper| **position <= upper)
            })
            .map(|(turn, position)| (*position, *turn))
            .collect();
        carried.sort_unstable();
        Merged {
            timeline: timeline.peekable(),
            carried: carried.into_iter().peekable(),
        }
    }

    /// Whether `candidate` is its TURN's effective position, given the row's
    /// own `learned_at`: a carried entry stands only when its carrier leads a
    /// live row, and a temporal entry only when no such carrier does. A
    /// carrier never resurrects a deleted TURN.
    pub(super) fn stands(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        candidate: &DirtyCandidate,
        stored: u64,
    ) -> Result<bool> {
        let carried = self.latest.get(&candidate.turn).copied();
        let at = effective(vault, txn, &candidate.turn, stored, carried)?;
        Ok(candidate.carried == (at > stored))
    }
}

/// [`DirtyCarriers::merge`]'s lazy stream: the temporal scan is never
/// materialized.
pub(super) struct Merged<'t> {
    timeline: Peekable<PortRows<'t, EntityTime>>,
    carried: Peekable<std::vec::IntoIter<(u64, EntityId)>>,
}

impl Iterator for Merged<'_> {
    type Item = Result<DirtyCandidate>;

    fn next(&mut self) -> Option<Self::Item> {
        let carried_first = match (self.timeline.peek(), self.carried.peek()) {
            (_, None) | (Some(Err(_)), Some(_)) => false,
            (None, Some(_)) => true,
            (Some(Ok(time)), Some(&(position, turn))) => {
                (position, turn) < (time.timestamp, time.id)
            }
        };
        if carried_first {
            let (position, turn) = self.carried.next()?;
            return Some(Ok(DirtyCandidate {
                position,
                turn,
                carried: true,
            }));
        }
        let time = self.timeline.next()?;
        Some(time.map(|time| DirtyCandidate {
            position: time.timestamp,
            turn: time.id,
            carried: false,
        }))
    }
}
