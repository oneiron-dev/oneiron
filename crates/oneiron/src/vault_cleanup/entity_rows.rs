//! Which cleanup listing rows name an id (FIX 7616): one index row per
//! (named id, listing, listing row), kept in step with every write and
//! delete of a proposal, digest or run in the writer's own transaction. An
//! erase, and restore's erase again of each hard-erased id, reads only the
//! rows that name what it erases, never a listing to its end.
//!
//! A row names an id where an erase would scrub it: the slot lists
//! [`super::erase::named_ids`] reads, by the same paths. An index row whose
//! listing row went, or no longer names its id, is dropped by the next erase
//! of that id and costs nothing else. A listing written before this index
//! has no index rows; no migration builds them (no backward compatibility).

use std::collections::BTreeSet;

use super::codec_receipts::{DIGEST, PROPOSAL};
use super::erase::named_ids;
use super::run_record::RUN;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

/// Key: the named id (16), the listing's tag (1), the listing row's key (16).
const ENTITY_ROWS: SideTable<([u8; 16], [u8; 1], [u8; 16]), (), Raw> =
    SideTable::new(&side_table::VAULT_CLEANUP_ENTITY_ROW);

/// One of cleanup's three listings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Listing {
    Proposal,
    Digest,
    Run,
}

impl Listing {
    const fn tag(self) -> [u8; 1] {
        match self {
            Self::Proposal => [b'p'],
            Self::Digest => [b'd'],
            Self::Run => [b'r'],
        }
    }

    const fn of(tag: [u8; 1]) -> Option<Self> {
        match tag {
            [b'p'] => Some(Self::Proposal),
            [b'd'] => Some(Self::Digest),
            [b'r'] => Some(Self::Run),
            _ => None,
        }
    }

    /// The listing row `key`, as stored.
    pub(super) fn get(
        self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        key: &[u8; 16],
    ) -> Result<Option<Vec<u8>>> {
        match self {
            Self::Proposal => PROPOSAL.get(store, txn, &EntityId::from_bytes_unchecked(*key)),
            Self::Digest => DIGEST.get(store, txn, &EntityId::from_bytes_unchecked(*key)),
            Self::Run => RUN.get(store, txn, key),
        }
    }

    /// Writes the listing row `key` as `encoded`, leaving the index as it
    /// is: for a rewrite that names no id it did not name before.
    pub(super) fn put_unindexed(
        self,
        store: &Store,
        txn: &mut heed::RwTxn<'_>,
        key: &[u8; 16],
        encoded: &[u8],
    ) -> Result<()> {
        let encoded = encoded.to_vec();
        match self {
            Self::Proposal => {
                PROPOSAL.put(store, txn, &EntityId::from_bytes_unchecked(*key), &encoded)
            }
            Self::Digest => DIGEST.put(store, txn, &EntityId::from_bytes_unchecked(*key), &encoded),
            Self::Run => RUN.put(store, txn, key, &encoded),
        }
    }

    /// Deletes the listing row `key`, leaving the index as it is: for a row
    /// that does not read, whose names no one can list.
    pub(super) fn delete_unindexed(
        self,
        store: &Store,
        txn: &mut heed::RwTxn<'_>,
        key: &[u8; 16],
    ) -> Result<bool> {
        match self {
            Self::Proposal => PROPOSAL.delete(store, txn, &EntityId::from_bytes_unchecked(*key)),
            Self::Digest => DIGEST.delete(store, txn, &EntityId::from_bytes_unchecked(*key)),
            Self::Run => RUN.delete(store, txn, key),
        }
    }
}

/// Keeps the index in step with the names the row held and now holds.
fn sync_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    listing: Listing,
    key: &[u8; 16],
    before: &BTreeSet<[u8; 16]>,
    after: &BTreeSet<[u8; 16]>,
) -> Result<()> {
    for gone in before.difference(after) {
        ENTITY_ROWS.delete(store, txn, &(*gone, listing.tag(), *key))?;
    }
    for added in after.difference(before) {
        ENTITY_ROWS.put(store, txn, &(*added, listing.tag(), *key), &())?;
    }
    Ok(())
}

/// Writes the listing row `key` as `encoded`, and the index rows of every id
/// it names, in the caller's transaction.
///
/// # Errors
///
/// Storage errors.
pub(super) fn put_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    listing: Listing,
    key: &[u8; 16],
    encoded: &[u8],
) -> Result<()> {
    let before = listing
        .get(store, txn, key)?
        .map_or_else(BTreeSet::new, |raw| named_ids(listing, &raw));
    sync_in_txn(
        store,
        txn,
        listing,
        key,
        &before,
        &named_ids(listing, encoded),
    )?;
    listing.put_unindexed(store, txn, key, encoded)
}

/// Deletes the listing row `key` and the index rows of every id it named, in
/// the caller's transaction. `true` when the row was there.
///
/// # Errors
///
/// Storage errors.
pub(super) fn delete_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    listing: Listing,
    key: &[u8; 16],
) -> Result<bool> {
    let Some(raw) = listing.get(store, txn, key)? else {
        return Ok(false);
    };
    sync_in_txn(
        store,
        txn,
        listing,
        key,
        &named_ids(listing, &raw),
        &BTreeSet::new(),
    )?;
    listing.delete_unindexed(store, txn, key)
}

/// Every listing row the index says names `id`.
///
/// # Errors
///
/// Storage errors.
pub(super) fn rows_naming(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &[u8; 16],
) -> Result<Vec<(Listing, [u8; 16])>> {
    Ok(ENTITY_ROWS
        .scan_keys(store, txn, id)?
        .into_iter()
        .filter_map(|(_, tag, key)| Listing::of(tag).map(|listing| (listing, key)))
        .collect())
}

/// Drops the index row that says `key` of `listing` names `id`.
///
/// # Errors
///
/// Storage errors.
pub(super) fn forget_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &[u8; 16],
    listing: Listing,
    key: &[u8; 16],
) -> Result<()> {
    ENTITY_ROWS
        .delete(store, txn, &(*id, listing.tag(), *key))
        .map(drop)
}
