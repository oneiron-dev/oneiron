//! Redirect projection row encoding, deletion maintenance and inbound traversal.

use std::collections::{BTreeMap, BTreeSet};

use crate::edge::EdgeKind;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::ports::EdgeStoreRead;
use crate::scan_check::{EngineScan, ScanCount};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::Store;

/// Only accepted row-version byte. A row is `[version][head_id(16)]*`, so
/// the zero-head split is exactly the one-byte row — distinguishable from
/// an absent row (live entity) by presence alone.
const REDIRECT_ROW_VERSION: u8 = 1;

/// The materialized redirect projection. Key: shell [`EntityId`].
pub(crate) const REDIRECT: SideTable<EntityId, RedirectRow, Raw> =
    SideTable::new(&side_table::IDENTITY_REDIRECT);

/// [`REDIRECT`]'s value: a shell's head set, wire-encoded by
/// [`encode_redirect_row`] / [`decode_redirect_row`] (those stay the codec).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RedirectRow(pub(crate) Vec<EntityId>);

impl RawValue for RedirectRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_redirect_row(&self.0))
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(Self(decode_redirect_row(bytes)?))
    }
}

const SHELL_EDGE_KINDS: [EdgeKind; 2] = [EdgeKind::MergedInto, EdgeKind::SplitInto];

/// Encodes a head set as a redirect row. The heads are written in the
/// caller's order, which every derivation normalizes to ascending id order,
/// so the same topology always encodes to the same bytes.
pub(crate) fn encode_redirect_row(heads: &[EntityId]) -> Vec<u8> {
    let mut row = Vec::with_capacity(1 + heads.len() * ENTITY_ID_LEN);
    row.push(REDIRECT_ROW_VERSION);
    for head in heads {
        row.extend_from_slice(head.as_bytes());
    }
    row
}

/// Decodes a redirect row back into its head set, fail-closed on any shape
/// the encoder cannot produce.
pub(crate) fn decode_redirect_row(row: &[u8]) -> Result<Vec<EntityId>> {
    let [version, heads @ ..] = row else {
        return Err(Error::CorruptedIndex("identity redirect row"));
    };
    if *version != REDIRECT_ROW_VERSION || heads.len() % ENTITY_ID_LEN != 0 {
        return Err(Error::CorruptedIndex("identity redirect row"));
    }
    heads
        .chunks_exact(ENTITY_ID_LEN)
        .map(|chunk| {
            let bytes: [u8; ENTITY_ID_LEN] = chunk
                .try_into()
                .map_err(|_| Error::CorruptedIndex("identity redirect row"))?;
            EntityId::from_bytes(bytes).map_err(|_| Error::CorruptedIndex("identity redirect row"))
        })
        .collect()
}

/// Drops a physically deleted `id` from the projection, before its shell
/// edges go: its own row, and its place in the head list of every shell
/// merged or split into it (H173). A shell left with no head loses its row,
/// as a rebuild from the remaining edges would.
pub(crate) fn forget_deleted_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    REDIRECT.delete(store, wtxn, id)?;
    let mut shells = BTreeSet::new();
    for kind in SHELL_EDGE_KINDS {
        for edge in store.port_edges(wtxn, id, crate::ports::EdgeDirection::In, Some(kind), None)? {
            shells.insert(edge?.target);
        }
    }
    for shell in shells {
        let Some(RedirectRow(mut heads)) = REDIRECT.get(store, wtxn, &shell)? else {
            continue;
        };
        let before = heads.len();
        heads.retain(|head| head != id);
        if heads.len() == before {
            continue;
        }
        if heads.is_empty() {
            REDIRECT.delete(store, wtxn, &shell)?;
        } else {
            REDIRECT.put(store, wtxn, &shell, &RedirectRow(heads))?;
        }
    }
    Ok(())
}

/// Whether `id` still holds a projection row: an erase scope of its own.
pub(crate) fn redirect_row_exists_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(REDIRECT.get(store, rtxn, id)?.is_some())
}

/// Reads one shell's row: `Ok(None)` when the entity is live (or the
/// projection has been dropped), `Ok(Some(heads))` for a shell.
pub(crate) fn redirect_row_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    shell: &EntityId,
) -> Result<Option<Vec<EntityId>>> {
    Ok(REDIRECT
        .get(store, rtxn, shell)?
        .map(|RedirectRow(heads)| heads))
}

/// The materialized table inverted: `head -> the shells whose row names it`.
///
/// One pass over the projection, so a walk that expands many heads pays for
/// the (shell-only, therefore small) table exactly once.
pub(crate) fn table_inbound_shells_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<EntityId, BTreeSet<EntityId>>> {
    let mut inbound: BTreeMap<EntityId, BTreeSet<EntityId>> = BTreeMap::new();
    for (shell, RedirectRow(heads)) in REDIRECT.scan(store, rtxn)? {
        for head in heads {
            inbound.entry(head).or_default().insert(shell);
        }
    }
    Ok(inbound)
}

/// Shells that point DIRECTLY at `head`, read through the CID-7 witnesses
/// and UNIONED.
///
/// - The canonical `merged_into` / `split_into` edges are engine-authored
///   truth, and the only witness left once the table has been dropped —
///   `edges_in` is keyed `[target | kind | source]`, so a reversed row for
///   `head` names the shell in its source slot.
/// - The materialized table additionally covers a row whose edge is already
///   gone, which is the shape a projector output can hold and the edges
///   cannot.
/// - `ledger_inbound` covers the shape NEITHER can hold: an erase that took
///   the edge AND the row with it. It is empty for every caller that reads
///   before a purge, where the two structural witnesses are already exact.
///
/// Either structural witness alone answers the ordinary case; the union is
/// what makes an ERASE walk fail-closed, because a shell missed here keeps a
/// readable payload of precisely what the erasure hid.
///
/// Every inbound edge is read, however many there are (FIX 8691): the count
/// only feeds the advisory [`EngineScan::EdgePeerRows`] check for this head,
/// kind and direction, which never refuses, caps or drops a shell.
pub(crate) fn direct_inbound_shells_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    head: &EntityId,
    table_inbound: &BTreeMap<EntityId, BTreeSet<EntityId>>,
    ledger_inbound: &BTreeMap<EntityId, BTreeSet<EntityId>>,
    shells: &mut BTreeSet<EntityId>,
) -> Result<()> {
    let direction = crate::ports::EdgeDirection::In;
    for kind in SHELL_EDGE_KINDS {
        let scope = [&[direction as u8][..], head.as_bytes(), &[kind as u8][..]].concat();
        let mut count = ScanCount::start(store, rtxn, EngineScan::EdgePeerRows, &scope)?;
        for entry in store.port_edges(rtxn, head, direction, Some(kind), None)? {
            count.row();
            shells.insert(entry?.target);
        }
        count.defer(store);
    }
    for witness in [table_inbound, ledger_inbound] {
        if let Some(witnessed) = witness.get(head) {
            shells.extend(witnessed.iter().copied());
        }
    }
    Ok(())
}

/// Every shell that resolves — directly or through a chain — to one of
/// `heads`. The inverse of [`resolve_into_in_txn`], and the walk ARCH-0055 §9
/// means by "HardErase walks redirects".
///
/// The frontier is walked to exhaustion, with no depth bound (FIX 8690): a
/// shell left past a cutoff would keep a readable payload of what the erase
/// hid. It still terminates and is cycle-safe for a stronger reason than a
/// path guard: a shell is expanded at most ONCE, so a forged cycle costs one
/// frontier step and ends rather than erroring — an erase walk must not be
/// stoppable by planting a cycle in the data it is about to erase.
///
/// `heads` themselves are never returned; the answer is the shells around
/// them.
pub(crate) fn inbound_redirect_shells_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    heads: &BTreeSet<EntityId>,
) -> Result<BTreeSet<EntityId>> {
    inbound_redirect_shells_with_ledger_in_txn(store, rtxn, heads, &BTreeMap::new())
}

/// [`inbound_redirect_shells_in_txn`] with the ledger witness of
/// [`ledger_inbound_shells_in_txn`] unioned into every frontier step.
///
/// Separate door rather than a widened one: the erase walk reads BEFORE the
/// purge, where the structural witnesses are exact and the ledger adds
/// nothing, so it keeps paying for neither the fold nor a cascade set derived
/// from anything but the edges it is about to tear.
pub(crate) fn inbound_redirect_shells_with_ledger_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    heads: &BTreeSet<EntityId>,
    ledger_inbound: &BTreeMap<EntityId, BTreeSet<EntityId>>,
) -> Result<BTreeSet<EntityId>> {
    let table_inbound = table_inbound_shells_in_txn(store, rtxn)?;
    let mut reached = heads.clone();
    let mut shells = BTreeSet::new();
    let mut frontier: Vec<EntityId> = heads.iter().copied().collect();
    while !frontier.is_empty() {
        let mut found = BTreeSet::new();
        for head in &frontier {
            direct_inbound_shells_in_txn(
                store,
                rtxn,
                head,
                &table_inbound,
                ledger_inbound,
                &mut found,
            )?;
        }
        frontier = Vec::new();
        for shell in found {
            if reached.insert(shell) {
                shells.insert(shell);
                frontier.push(shell);
            }
        }
    }
    Ok(shells)
}
