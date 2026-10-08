//! The re-dirty carrier: a TURN whose final words changed after a round may
//! have consumed it is pending again for every scope.
//!
//! Selection walks the temporal index strictly after a scope cursor; a TURN
//! row stands at its temporal key `(learned_at, TURN id)`. A changed TURN
//! cannot always move its own row past every cursor: a DAG record TURN is
//! append-only, and a caller's backdated occurrence lands a re-put behind a
//! cursor a later TURN already advanced. This vault-local table gives such a
//! TURN a carrier instead, pending for each scope until a round of that scope
//! consumes it. A pending carrier is selected wherever the scope cursor
//! stands, and settling it never moves that cursor, which names TURN keys
//! only: a carrier strands no TURN the cursor had not already passed. Its key,
//! the writer clock's second and a fresh id from the store's monotonic id
//! source, only orders it among the temporal entries (the round cap reads
//! that order) and names the change in the partition-round identity.
//!
//! While the TURN is live and its row has not moved past the carrier, the
//! carrier is the TURN's EFFECTIVE key, consumed or not: its temporal entry
//! does not stand. Selection, settlement and the partition-round identity
//! read the effective key; the fence's source pins keep the row's own
//! `learned_at`, which a carrier never touches.
//!
//! One latest row per TURN: a newer change replaces it, pending for every
//! scope again. Like stream finality, the row is local to this vault.
use super::watermark::WorkingSetTurn;
use crate::Vault;
use crate::dreamer_runner::DreamerConsolidationScope;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EntityStoreRead, EntityTime, PortRows, TombstoneStoreRead};
use crate::registry::ENTITY_TYPE_TURN;
use crate::side_table::{self, Named, SideTable};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::iter::Peekable;

/// Latest re-dirty carrier of one TURN. Key: id16 (TURN id).
const REDIRTY: SideTable<EntityId, Carrier, Named> =
    SideTable::new(&side_table::DREAMER_TURN_REDIRTY);

/// A TURN's carrier key `(position, order)`, the row `learned_at` it was
/// taken against, and the scopes whose rounds consumed it.
#[derive(Clone, Copy, Serialize, Deserialize)]
struct Carrier {
    position: u64,
    order: EntityId,
    row_learned_at: u64,
    /// One [`scope_bit`] per scope that consumed this carrier.
    consumed: u8,
}

impl Carrier {
    /// Whether this carrier, not the row, keys its TURN: the row has not moved
    /// since the carrier was taken, or has not moved past it.
    const fn leads(&self, stored: u64) -> bool {
        self.row_learned_at == stored || self.position >= stored
    }

    const fn pending(&self, bit: u8) -> bool {
        self.consumed & bit == 0
    }
}

const fn scope_bit(scope: DreamerConsolidationScope) -> u8 {
    match scope {
        DreamerConsolidationScope::Micro => 1,
        DreamerConsolidationScope::Meso => 2,
        DreamerConsolidationScope::Macro => 4,
    }
}

/// Re-dirties `turn` in the caller's write transaction: its carrier takes the
/// writer clock's second and a fresh id from the store's id source, pending
/// for every scope, so each scope's next round selects the TURN again under a
/// new round identity, even for a second change in one second. The TURN row
/// is left byte-identical. A deleted TURN has no dirty work and is left
/// alone.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when no row exists, and a corrupted-index error
/// when the row is not a TURN.
pub(crate) fn redirty_turn_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
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
    // Drawn before the clock read, which persists the id floor in this commit.
    let order = vault.store.clock.entity_id()?;
    let position = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let carrier = Carrier {
        position,
        order,
        row_learned_at: row.learned_at,
        consumed: 0,
    };
    REDIRTY.put(&vault.store, txn, turn, &carrier)
}

/// Marks the carriers a settled round of `scope` selected, each `(turn,
/// order)`, consumed for that scope. A carrier a newer change replaced since
/// (another order) stays pending.
pub(super) fn consume_carriers_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    scope: DreamerConsolidationScope,
    selected: impl IntoIterator<Item = (EntityId, EntityId)>,
) -> Result<()> {
    let bit = scope_bit(scope);
    for (turn, order) in selected {
        let Some(mut carrier) = REDIRTY.get(&vault.store, txn, &turn)? else {
            continue;
        };
        if carrier.order == order && carrier.pending(bit) {
            carrier.consumed |= bit;
            REDIRTY.put(&vault.store, txn, &turn, &carrier)?;
        }
    }
    Ok(())
}

/// The effective selection key of `turn`, whose row carries `stored`, in the
/// caller's snapshot: its carrier's key while that leads a live row, else the
/// row's own temporal key `(stored, turn)`.
pub(super) fn effective_key_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    stored: u64,
) -> Result<(u64, EntityId)> {
    let carrier = REDIRTY.get(&vault.store, txn, turn)?;
    let leading = leading_carrier(vault, txn, turn, stored, carrier.as_ref())?;
    Ok(leading.unwrap_or((stored, *turn)))
}

/// The second of [`effective_key_in_txn`].
pub(super) fn effective_learned_at_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    stored: u64,
) -> Result<u64> {
    Ok(effective_key_in_txn(vault, txn, turn, stored)?.0)
}

/// The carrier ids of those `turns` keyed by their carriers, for the
/// partition-round identity: a carried TURN hashes the key it was selected at.
pub(super) fn carried_orders_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turns: &[WorkingSetTurn],
) -> Result<BTreeMap<EntityId, EntityId>> {
    let mut orders = BTreeMap::new();
    for turn in turns.iter().map(|turn| turn.turn_id) {
        let Some(row) = vault.store.port_entity_record(txn, &turn)? else {
            continue;
        };
        let carrier = REDIRTY.get(&vault.store, txn, &turn)?;
        let leading = leading_carrier(vault, txn, &turn, row.learned_at, carrier.as_ref())?;
        if let Some((_, order)) = leading {
            orders.insert(turn, order);
        }
    }
    Ok(orders)
}

/// `carrier`'s key while it leads the live row of `turn`, which carries
/// `stored`.
fn leading_carrier(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    stored: u64,
    carrier: Option<&Carrier>,
) -> Result<Option<(u64, EntityId)>> {
    let Some(carrier) = carrier.filter(|carrier| carrier.leads(stored)) else {
        return Ok(None);
    };
    Ok(is_live(vault, txn, turn)?.then_some((carrier.position, carrier.order)))
}

fn is_live(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    let state = vault.store.port_deletion_state(txn, id)?;
    Ok(!(state.deleted || state.stale))
}

/// One entry of the merged dirty stream: a TURN at a temporal or carried key.
pub(super) struct DirtyCandidate {
    pub(super) position: u64,
    /// The key's id: the TURN id for a temporal entry, the carrier's own id
    /// for a carried one.
    pub(super) key: EntityId,
    pub(super) turn: EntityId,
    /// A carried entry settles by consuming its carrier, never by moving the
    /// scope cursor.
    pub(super) carried: bool,
}

/// Every carrier row of one snapshot, read for one scope: its pending
/// carriers merge into the temporal scan, and every leading carrier keeps
/// its TURN's temporal entry out, so each TURN is enumerated at most once.
pub(super) struct DirtyCarriers {
    latest: BTreeMap<EntityId, Carrier>,
    bit: u8,
}

impl DirtyCarriers {
    pub(super) fn read(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        scope: DreamerConsolidationScope,
    ) -> Result<Self> {
        Ok(Self {
            latest: REDIRTY.scan(&vault.store, txn)?.into_iter().collect(),
            bit: scope_bit(scope),
        })
    }

    /// The temporal stream (already cut after the scope cursor) and every
    /// carrier still pending for the scope through `upper_inclusive`, in one
    /// `(position, id)` order. A pending carrier is merged wherever the
    /// cursor stands. A carrier that does not lead its row still appears
    /// here; [`Self::stands`] drops whichever of the two entries is not the
    /// TURN's effective key.
    pub(super) fn merge<'t>(
        &self,
        timeline: PortRows<'t, EntityTime>,
        upper_inclusive: Option<u64>,
    ) -> Merged<'t> {
        let mut carried: Vec<(u64, EntityId, EntityId)> = self
            .latest
            .iter()
            .filter(|(_, carrier)| {
                carrier.pending(self.bit)
                    && upper_inclusive.is_none_or(|upper| carrier.position <= upper)
            })
            .map(|(turn, carrier)| (carrier.position, carrier.order, *turn))
            .collect();
        carried.sort_unstable();
        Merged {
            timeline: timeline.peekable(),
            carried: carried.into_iter().peekable(),
        }
    }

    /// Whether `candidate` is its TURN's effective key, given the row's own
    /// `learned_at`: a carried entry stands only when its carrier leads a live
    /// row, and a temporal entry only when no such carrier does. A carrier
    /// never resurrects a deleted TURN.
    pub(super) fn stands(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        candidate: &DirtyCandidate,
        stored: u64,
    ) -> Result<bool> {
        let carrier = self.latest.get(&candidate.turn);
        let leading = leading_carrier(vault, txn, &candidate.turn, stored, carrier)?;
        Ok(candidate.carried == leading.is_some())
    }
}

/// [`DirtyCarriers::merge`]'s lazy stream: the temporal scan is never
/// materialized.
pub(super) struct Merged<'t> {
    timeline: Peekable<PortRows<'t, EntityTime>>,
    carried: Peekable<std::vec::IntoIter<(u64, EntityId, EntityId)>>,
}

impl Iterator for Merged<'_> {
    type Item = Result<DirtyCandidate>;

    fn next(&mut self) -> Option<Self::Item> {
        let carried_first = match (self.timeline.peek(), self.carried.peek()) {
            (_, None) | (Some(Err(_)), Some(_)) => false,
            (None, Some(_)) => true,
            (Some(Ok(time)), Some(&(position, key, _))) => {
                (position, key) < (time.timestamp, time.id)
            }
        };
        if carried_first {
            let (position, key, turn) = self.carried.next()?;
            return Some(Ok(DirtyCandidate {
                position,
                key,
                turn,
                carried: true,
            }));
        }
        let time = self.timeline.next()?;
        Some(time.map(|time| DirtyCandidate {
            position: time.timestamp,
            key: time.id,
            turn: time.id,
            carried: false,
        }))
    }
}
