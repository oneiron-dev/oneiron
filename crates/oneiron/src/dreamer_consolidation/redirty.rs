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
//! For each scope, while the TURN is live, a pending carrier is the TURN's
//! EFFECTIVE key, and a consumed one stays it while the row stands where that
//! scope's consuming round read it: its temporal entry does not stand. A row
//! moved since (a generic re-put) is new work on its own temporal key again.
//! Selection, settlement and the partition-round identity read the effective
//! key; the fence's source pins keep the row's own `learned_at`, which a
//! carrier never touches.
//!
//! One latest row per TURN: a newer change replaces it, pending for every
//! scope again. Like stream finality, the row is local to this vault.
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

/// A TURN's carrier key `(position, order)` and, per scope, whether a round
/// of it consumed the carrier and the row `learned_at` that round read.
#[derive(Clone, Copy, Serialize, Deserialize)]
struct Carrier {
    position: u64,
    order: EntityId,
    /// One `1 << slot(scope)` bit per scope that consumed this carrier.
    consumed: u8,
    /// The row `learned_at` each scope's consuming round read, by [`slot`].
    read_at: [u64; 3],
}

impl Carrier {
    /// Whether this carrier, not the row, keys its TURN for `scope`, whose
    /// row carries `stored`: while pending, and once consumed while the row
    /// stands where the consuming round read it.
    const fn leads(&self, scope: DreamerConsolidationScope, stored: u64) -> bool {
        self.pending(scope) || self.read_at[slot(scope)] == stored
    }

    const fn pending(&self, scope: DreamerConsolidationScope) -> bool {
        self.consumed & (1 << slot(scope)) == 0
    }

    /// Consumes this carrier for `scope`, whose round read the row at `stored`.
    const fn consume(&mut self, scope: DreamerConsolidationScope, stored: u64) {
        self.consumed |= 1 << slot(scope);
        self.read_at[slot(scope)] = stored;
    }
}

const fn slot(scope: DreamerConsolidationScope) -> usize {
    match scope {
        DreamerConsolidationScope::Micro => 0,
        DreamerConsolidationScope::Meso => 1,
        DreamerConsolidationScope::Macro => 2,
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
        consumed: 0,
        read_at: [0; 3],
    };
    REDIRTY.put(&vault.store, txn, turn, &carrier)
}

/// Marks the carriers a settled round of `scope` selected, each `(turn,
/// order)`, consumed for that scope at the row it read, capped at `through`.
/// A carrier a newer change replaced since (another order) stays pending.
/// The complete-second door passes its settled second as `through`: the
/// caller enqueued its round in an earlier commit, so a row re-put past the
/// settled seconds since is new work on its own temporal key. A fenced
/// round passes `u64::MAX`.
pub(super) fn consume_carriers_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    scope: DreamerConsolidationScope,
    through: u64,
    selected: impl IntoIterator<Item = (EntityId, EntityId)>,
) -> Result<()> {
    for (turn, order) in selected {
        let Some(carrier) = REDIRTY.get(&vault.store, txn, &turn)? else {
            continue;
        };
        if carrier.order == order && carrier.pending(scope) {
            consume_in_txn(vault, txn, scope, &turn, carrier, through)?;
        }
    }
    Ok(())
}

/// The administrative rescan from second `from`, inclusive: every carrier
/// `scope` consumed at or after `from`, by its own key or by the row its
/// round read, is pending for that scope again. Other scopes keep theirs.
pub(super) fn reopen_carriers_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    scope: DreamerConsolidationScope,
    from: u64,
) -> Result<()> {
    for (turn, mut carrier) in REDIRTY.scan(&vault.store, txn)? {
        if !carrier.pending(scope)
            && (carrier.position >= from || carrier.read_at[slot(scope)] >= from)
        {
            carrier.consumed &= !(1 << slot(scope));
            REDIRTY.put(&vault.store, txn, &turn, &carrier)?;
        }
    }
    Ok(())
}

/// Consumes `carrier` for `scope` at the TURN row's `learned_at`, read here,
/// capped at `through`: a row past it is not marked read.
fn consume_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    scope: DreamerConsolidationScope,
    turn: &EntityId,
    mut carrier: Carrier,
    through: u64,
) -> Result<()> {
    let Some(row) = vault.store.port_entity_record(txn, turn)? else {
        return Ok(());
    };
    carrier.consume(scope, row.learned_at.min(through));
    REDIRTY.put(&vault.store, txn, turn, &carrier)
}

/// The key `(position, order)` of the carrier that keys `turn` for `scope`,
/// whose row carries `stored`, in the caller's snapshot: `Some` while it
/// leads a live row, else `None` and the TURN stands at its own temporal key
/// `(stored, turn)`.
pub(super) fn carrier_key_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: DreamerConsolidationScope,
    turn: &EntityId,
    stored: u64,
) -> Result<Option<(u64, EntityId)>> {
    let carrier = REDIRTY.get(&vault.store, txn, turn)?;
    leading_carrier(vault, txn, scope, turn, stored, carrier.as_ref())
}

/// `carrier`'s key while it leads the live row of `turn` for `scope`; the
/// row carries `stored`.
fn leading_carrier(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: DreamerConsolidationScope,
    turn: &EntityId,
    stored: u64,
    carrier: Option<&Carrier>,
) -> Result<Option<(u64, EntityId)>> {
    let Some(carrier) = carrier.filter(|carrier| carrier.leads(scope, stored)) else {
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
    scope: DreamerConsolidationScope,
}

impl DirtyCarriers {
    pub(super) fn read(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        scope: DreamerConsolidationScope,
    ) -> Result<Self> {
        Ok(Self {
            latest: REDIRTY.scan(&vault.store, txn)?.into_iter().collect(),
            scope,
        })
    }

    /// The temporal stream (already cut after the scope cursor) and every
    /// carrier still pending for the scope through `upper_inclusive`, in one
    /// `(position, id)` order. A pending carrier is merged wherever the
    /// cursor stands; [`Self::stands`] drops whichever of a TURN's two
    /// entries is not its effective key.
    pub(super) fn merge<'t>(
        &self,
        timeline: PortRows<'t, EntityTime>,
        upper_inclusive: Option<u64>,
    ) -> Merged<'t> {
        let mut carried: Vec<(u64, EntityId, EntityId)> = self
            .latest
            .iter()
            .filter(|(_, carrier)| {
                carrier.pending(self.scope)
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
        let leading = leading_carrier(vault, txn, self.scope, &candidate.turn, stored, carrier)?;
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
