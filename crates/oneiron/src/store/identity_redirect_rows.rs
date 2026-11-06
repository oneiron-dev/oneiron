//! Redirect projection row encoding, deletion maintenance and inbound traversal.

use std::collections::{BTreeMap, BTreeSet};

use crate::edge::EdgeKind;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::ports::EdgeStoreRead;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::Store;

/// Only accepted row-version byte. A row is `[version][head_id(16)]*`, so
/// the zero-head split is exactly the one-byte row — distinguishable from
/// an absent row (live entity) by presence alone.
pub(crate) const REDIRECT_ROW_VERSION: u8 = 1;

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

pub(crate) const SHELL_EDGE_KINDS: [EdgeKind; 2] = [EdgeKind::MergedInto, EdgeKind::SplitInto];

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
