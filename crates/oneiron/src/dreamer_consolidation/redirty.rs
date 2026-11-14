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
//!
//! The same carrier is the one shared carrier for a TURN without its
//! conversation edge (ARCH-0026, the #1353 follow-up). A cursor passing such
//! a TURN parks it here instead of stopping at it, and selection leaves a
//! carried TURN out until its edge lands, so one missing edge never holds
//! back later turns, and the parked TURN keeps its own scope: it is planned
//! under its own conversation once it has one.
use crate::Vault;
use crate::batch::BatchOp;
use crate::dreamer_runner::DreamerConsolidationScope;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{
    EdgeDirection, EdgeStoreRead, EntityStoreRead, EntityTime, PortRows, TombstoneStoreRead,
};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
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
    put_carrier_in_txn(&vault.store, txn, turn)?;
    // Changed words are new work for the sieve too, and end their hold.
    crate::dreamer_wake::words_changed_in_txn(&vault.store, txn, turn)
}

/// Parks an edge-less TURN a scope cursor is passing on the same carrier: its
/// words did not change, so the sieve owes it nothing. Selection leaves a
/// carried TURN out while it has no conversation edge, so it stops no later
/// turn, and takes it like any re-dirtied TURN once its edge lands.
pub(super) fn park_turn_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
) -> Result<()> {
    put_carrier_in_txn(&vault.store, txn, turn)
}

/// Puts a TURN whose words did not change back on the carrier, pending for
/// every scope, because what a round read of it is gone: the projector's
/// riders and queued batch-mates of a source since erased. An id that no
/// longer names a live TURN is left alone.
pub(crate) fn requeue_turn_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
) -> Result<()> {
    if store
        .port_entity_record(txn, turn)?
        .is_none_or(|row| row.entity_type != ENTITY_TYPE_TURN)
    {
        return Ok(());
    }
    put_carrier_in_txn(store, txn, turn)
}

/// Whether an edge of `kind` binds a TURN's words: a MESSAGE's `PartOf` to its
/// TURN, its `BelongsTo` to the conversation and its `AuthoredBy` to its
/// speaker, and the TURN's `ChildOf` to the conversation. The Dreamer's read of
/// a witnessed turn checks each of them (`turn_text::collect_with`).
pub(crate) const fn binds_turn_words(kind: EdgeKind) -> bool {
    matches!(
        kind,
        EdgeKind::PartOf | EdgeKind::BelongsTo | EdgeKind::AuthoredBy | EdgeKind::ChildOf
    )
}

/// One batch's writes and removals of edges that bind a TURN's words
/// ([`binds_turn_words`]), each with whether it was stored before the batch
/// applied, and the TURNs the batch births.
///
/// An edge rewire or a speaker rebinding changes what a TURN says with no
/// write to the TURN or to its MESSAGEs' text, so no publication door tells
/// the turn's listeners (ARCH-0026 #sieve-open). Read before the batch and
/// settled after it, in its transaction, each TURN whose binding an edge
/// changed is re-dirtied and marked as a publication of its text marks it.
pub(crate) struct RewiredTurnEdges {
    edges: Vec<(EntityId, EdgeKind, EntityId, bool)>,
    born: BTreeSet<EntityId>,
}

impl RewiredTurnEdges {
    /// Reads, in `txn` before the batch `ops` applies, whether each edge it
    /// writes or removes of a kind that binds a TURN's words is stored, and
    /// which TURNs it puts that no row holds yet. An edge out of a row the
    /// batch also puts counts like any other: a MESSAGE the batch births
    /// into a stored TURN (an archive restore) changes that turn's words.
    ///
    /// # Errors
    ///
    /// The edge and row reads.
    pub(crate) fn before(vault: &Vault, txn: &heed::RoTxn<'_>, ops: &[BatchOp]) -> Result<Self> {
        let candidates: Vec<_> = ops
            .iter()
            .filter_map(|op| match op {
                BatchOp::Edge { src, kind, tgt, .. }
                | BatchOp::PublicEdgeWithCreatedAt { src, kind, tgt, .. }
                | BatchOp::EdgeWithCreatedAt { src, kind, tgt, .. }
                | BatchOp::DeleteEdge { src, kind, tgt } => Some((*src, *kind, *tgt)),
                _ => None,
            })
            .filter(|(_, kind, _)| binds_turn_words(*kind))
            .collect();
        if candidates.is_empty() {
            return Ok(Self {
                edges: Vec::new(),
                born: BTreeSet::new(),
            });
        }
        let mut born = BTreeSet::new();
        for op in ops {
            if let BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_TURN,
                ..
            } = op
                && vault.store.port_entity_record(txn, id)?.is_none()
            {
                born.insert(*id);
            }
        }
        let mut edges = Vec::with_capacity(candidates.len());
        for (src, kind, tgt) in candidates {
            let stored = edge_stored_in_txn(&vault.store, txn, &src, kind, &tgt)?;
            edges.push((src, kind, tgt, stored));
        }
        Ok(Self { edges, born })
    }

    /// Admits, in the batch's transaction after it applied, each live TURN
    /// whose word binding one of the edges changed (the edge was stored
    /// before and is gone, or was not and is now) as a TURN whose words
    /// changed ([`admit_rewired_turn_in_txn`]). A TURN the batch births is
    /// new work on its own key already; a stored TURN the batch puts again
    /// is admitted like any other, since a put of its row says nothing of
    /// its new words to the tagger or the embedder.
    ///
    /// # Errors
    ///
    /// The reads, the carrier write and the marks.
    pub(crate) fn redirty_in_txn(self, vault: &Vault, txn: &mut heed::RwTxn<'_>) -> Result<()> {
        let mut turns = BTreeSet::new();
        for (src, kind, tgt, stored) in self.edges {
            if edge_stored_in_txn(&vault.store, txn, &src, kind, &tgt)? != stored {
                turns.extend(turns_bound_by_in_txn(&vault.store, txn, &src, kind, &tgt)?);
            }
        }
        for turn in turns.difference(&self.born) {
            if is_live(&vault.store, txn, turn)? {
                admit_rewired_turn_in_txn(vault, txn, turn)?;
            }
        }
        Ok(())
    }
}

/// A live TURN whose word binding an edge changed, in the edge's own
/// transaction: admitted as a TURN whose words changed
/// ([`admit_changed_words_in_txn`]), and marked by the tagger and the
/// embedder at its new words, as a publication of its text marks it.
fn admit_rewired_turn_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
) -> Result<()> {
    admit_changed_words_in_txn(&vault.store, txn, turn)?;
    crate::tagging::mark_on_publication_in_txn(vault, txn, turn, ENTITY_TYPE_TURN)?;
    crate::embed::mark_on_publication_in_txn(vault, txn, turn, ENTITY_TYPE_TURN)
}

/// A TURN whose words changed with no new temporal key of its own (an edge
/// rewire, a document edit or revision of its text, a lost source), in the
/// change's own transaction: re-dirtied when a round may have read it
/// ([`redirty_read_turn_in_txn`]). In any case the sieve and the projector
/// owe it a read and the redirty feed hears of it
/// ([`crate::dreamer_wake::words_changed_in_txn`]).
///
/// # Errors
///
/// [`Error::EntityNotFound`] when no row exists; the reads and the writes.
pub(crate) fn admit_changed_words_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
) -> Result<()> {
    redirty_read_turn_in_txn(store, txn, turn)?;
    crate::dreamer_wake::words_changed_in_txn(store, txn, turn)
}

/// The consolidation half of [`admit_changed_words_in_txn`]. A TURN whose
/// words changed that a round may have read (a scope's watermark passed it,
/// or a carrier keys it) takes a fresh carrier, pending for every scope, as
/// a TURN put behind a watermark does
/// ([`admit_turn_position_in_txn`](super::watermark::admit_turn_position_in_txn));
/// a TURN no round has passed is read at its new words on its own key. The
/// erase hook calls it alone for a TURN that keeps its row while one of its
/// MESSAGEs is erased: that hook settles the sieve and the projector itself
/// ([`crate::dreamer_wake::erase_in_txn`]).
///
/// # Errors
///
/// [`Error::EntityNotFound`] when no row exists; the reads and the carrier
/// write.
pub(crate) fn redirty_read_turn_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
) -> Result<()> {
    if REDIRTY.get(store, txn, turn)?.is_some()
        || super::watermark::turn_passed_in_txn(store, txn, turn)?
    {
        put_carrier_in_txn(store, txn, turn)?;
    }
    Ok(())
}

fn edge_stored_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    src: &EntityId,
    kind: EdgeKind,
    tgt: &EntityId,
) -> Result<bool> {
    store.port_edge_present(txn, src, EdgeDirection::Out, kind, tgt)
}

/// The TURNs whose words the edge `src -kind-> tgt` binds, read as the graph
/// stands: for an edge out of a MESSAGE, the TURN its `PartOf` names and every
/// TURN the MESSAGE is part of (its binding is checked in each); for a TURN's
/// `ChildOf`, that TURN.
fn turns_bound_by_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    src: &EntityId,
    kind: EdgeKind,
    tgt: &EntityId,
) -> Result<Vec<EntityId>> {
    let entity_type = |id: &EntityId| -> Result<Option<u8>> {
        Ok(store
            .port_entity_record(txn, id)?
            .map(|row| row.entity_type))
    };
    let mut turns = Vec::new();
    match entity_type(src)? {
        Some(ENTITY_TYPE_MESSAGE) => {
            if kind == EdgeKind::PartOf && entity_type(tgt)? == Some(ENTITY_TYPE_TURN) {
                turns.push(*tgt);
            }
            for peer in store.port_edge_peers(txn, src, EdgeDirection::Out, EdgeKind::PartOf)? {
                let peer = peer?;
                if entity_type(&peer)? == Some(ENTITY_TYPE_TURN) {
                    turns.push(peer);
                }
            }
        }
        Some(ENTITY_TYPE_TURN) if kind == EdgeKind::ChildOf => turns.push(*src),
        _ => {}
    }
    Ok(turns)
}

/// Whether `turn` holds a re-dirty carrier pending for every scope, and is
/// live (the test door `test_doors::turn_words`).
///
/// # Errors
///
/// The reads.
#[cfg(oneiron_test_support)]
pub(crate) fn pending_for_every_scope(vault: &Vault, turn: &EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    let Some(carrier) = REDIRTY.get(&vault.store, &txn, turn)? else {
        return Ok(false);
    };
    Ok(carrier.consumed == 0 && is_live(&vault.store, &txn, turn)?)
}

/// Settles every scope's watermark on `turn`'s key, as a round of each that
/// read it would (the test door `test_doors::turn_words`).
///
/// # Errors
///
/// The read and the watermark writes.
#[cfg(oneiron_test_support)]
pub(crate) fn settle_every_scope_on_turn(vault: &Vault, turn: &EntityId) -> Result<()> {
    super::watermark::settle_every_scope_on_turn(vault, turn)
}

/// Parks each TURN of `passed`, the temporal keys a cursor is settling past,
/// that has no conversation edge.
pub(super) fn park_edgeless_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    passed: impl IntoIterator<Item = EntityId>,
) -> Result<()> {
    for turn in passed {
        if conversation_in_txn(vault, txn, &turn)?.is_none() {
            park_turn_in_txn(vault, txn, &turn)?;
        }
    }
    Ok(())
}

pub(super) fn conversation_of(vault: &Vault, turn_id: &EntityId) -> Result<Option<EntityId>> {
    Ok(vault
        .edges_out(turn_id)?
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::ChildOf)
        .map(|edge| edge.target))
}

/// A TURN's structural conversation: the target of its `ChildOf` edge.
pub(crate) fn conversation_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<EntityId>> {
    Ok(vault
        .store
        .port_edges(txn, turn, EdgeDirection::Out, Some(EdgeKind::ChildOf), None)?
        .next()
        .transpose()?
        .map(|edge| edge.target))
}

fn put_carrier_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, turn: &EntityId) -> Result<()> {
    let row = store
        .port_entity_record(txn, turn)?
        .ok_or(Error::EntityNotFound)?;
    if row.entity_type != ENTITY_TYPE_TURN {
        return Err(Error::CorruptedIndex("re-dirtied row is not a TURN"));
    }
    if !is_live(store, txn, turn)? {
        return Ok(());
    }
    // Drawn before the clock read, which persists the id floor in this commit.
    let order = store.clock.entity_id()?;
    let position = crate::ports::recorded_at_in_txn(store, txn)?;
    let carrier = Carrier {
        position,
        order,
        consumed: 0,
        read_at: [0; 3],
    };
    REDIRTY.put(store, txn, turn, &carrier)
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
    Ok(is_live(&vault.store, txn, turn)?.then_some((carrier.position, carrier.order)))
}

fn is_live(store: &Store, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    let state = store.port_deletion_state(txn, id)?;
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
