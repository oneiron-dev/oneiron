//! Per-database accessor seam for the session write-overlay (ARCH-0052, D2).
//!
//! Every one of the 28 named LMDB databases is reached through an
//! [`OverlayDb`] (or [`OverlayStrDb`] for the `Str`-keyed `sync_state`)
//! accessor instead of a raw [`heed::Database`] handle. The canonical vault
//! instance is a pure passthrough: one enum branch per access, no overlay
//! logic. A session vault handle (ONE-1726/ONE-1727) composes an in-memory
//! `SessionOverlay` over the same base handles at exactly this seam, so every
//! reader that exists now or is ever added — entity gets, edge readers, tree
//! walks, BM25/HNSW/phonetic/temporal scans, PPR traversal, pipeline,
//! context-pack, facade, N-API — sees overlay ∪ base with zero per-reader
//! code.
//!
//! Two shapes are deliberately owned by this module rather than mirrored from
//! heed, because they cannot be mirrored transparently once an overlay merge
//! exists (ARCH-0052 §3/D2):
//!
//! * **Values are `Cow<'txn, [u8]>` from day one.** heed's `get` returns
//!   page-borrowed bytes; an overlay hit returns snapshot-owned bytes. Call
//!   sites are written once against the `Cow` shape so arming the overlay
//!   never re-touches them.
//! * **Iterators are owned enums.** heed's typestate cursor structs (for
//!   example the `move_between_keys` switch `bm25.rs` performs on a
//!   `prefix_iter` result) cannot carry a merged overlay variant. The enums
//!   here re-expose exactly the method subset a symbol-reference sweep of the
//!   crate found in use — nothing speculative.
//!
//! The accessor surface below is the census of actual crate usage (ONE-1725
//! sweep): `get`, `put`, `delete`, `delete_one_duplicate`, `clear`, `len`,
//! `is_empty`, `first`, `last`, `iter`, `rev_iter`, `prefix_iter`, `range`,
//! `rev_range`, `get_duplicates`, plus the `move_between_keys` iterator
//! switch. `sync_state` additionally needs only `get`/`put`/`delete`/
//! `iter`/`prefix_iter` on `str` keys. Any new heed method use MUST be added
//! here rather than taken from a raw handle — raw handles live behind
//! `StoreCore::raw` and are reserved for open-time machinery.

use std::borrow::Cow;
use std::ops::RangeBounds;

use heed::iteration_method::{MoveBetweenKeys, MoveOnCurrentKeyDuplicates};
use heed::types::{Bytes, Str};
use heed::{
    Database, DefaultComparator, RoIter, RoPrefix, RoRange, RoRevIter, RoRevRange, RoTxn, RwTxn,
};

use crate::error::{Error, Result};

/// One merged key/value row as yielded by the owned iterators and
/// `first`/`last`: both sides are Cow so a P2 overlay hit can return
/// snapshot-owned bytes through the same shape (ARCH-0052 D2).
pub(crate) type KvPair<'txn> = (Cow<'txn, [u8]>, Cow<'txn, [u8]>);

/// One merged key/value row for the `Str`-keyed `sync_state` database.
pub(crate) type StrKvPair<'txn> = (Cow<'txn, str>, Cow<'txn, [u8]>);

/// Accessor over one `Bytes`-keyed named database.
///
/// Canonical instance = passthrough to the base database. The session
/// variant (ONE-1726) adds an `Option<Arc<SessionOverlay>>` alongside the
/// base handle; the canonical accessor keeps `None` semantics and pays one
/// branch per access.
pub(crate) struct OverlayDb {
    base: Database<Bytes, Bytes>,
}

impl OverlayDb {
    /// Canonical (base-only) view over a raw database handle.
    pub(crate) fn canonical(base: Database<Bytes, Bytes>) -> Self {
        Self { base }
    }

    pub(crate) fn get<'txn>(
        &self,
        txn: &'txn RoTxn<'_>,
        key: &[u8],
    ) -> Result<Option<Cow<'txn, [u8]>>> {
        Ok(self.base.get(txn, key)?.map(Cow::Borrowed))
    }

    pub(crate) fn put(&self, txn: &mut RwTxn<'_>, key: &[u8], data: &[u8]) -> Result<()> {
        self.base.put(txn, key, data).map_err(Error::from)
    }

    pub(crate) fn delete(&self, txn: &mut RwTxn<'_>, key: &[u8]) -> Result<bool> {
        self.base.delete(txn, key).map_err(Error::from)
    }

    /// DUP_SORT only: deletes one exact `(key, data)` duplicate entry.
    pub(crate) fn delete_one_duplicate(
        &self,
        txn: &mut RwTxn<'_>,
        key: &[u8],
        data: &[u8],
    ) -> Result<bool> {
        self.base
            .delete_one_duplicate(txn, key, data)
            .map_err(Error::from)
    }

    pub(crate) fn clear(&self, txn: &mut RwTxn<'_>) -> Result<()> {
        self.base.clear(txn).map_err(Error::from)
    }

    pub(crate) fn len(&self, txn: &RoTxn<'_>) -> Result<u64> {
        self.base.len(txn).map_err(Error::from)
    }

    pub(crate) fn first<'txn>(&self, txn: &'txn RoTxn<'_>) -> Result<Option<KvPair<'txn>>> {
        Ok(self.base.first(txn)?.map(borrow_pair))
    }

    pub(crate) fn last<'txn>(&self, txn: &'txn RoTxn<'_>) -> Result<Option<KvPair<'txn>>> {
        Ok(self.base.last(txn)?.map(borrow_pair))
    }

    pub(crate) fn iter<'txn>(&self, txn: &'txn RoTxn<'_>) -> Result<OverlayIter<'txn>> {
        Ok(OverlayIter::Base(self.base.iter(txn)?))
    }

    pub(crate) fn rev_iter<'txn>(&self, txn: &'txn RoTxn<'_>) -> Result<OverlayRevIter<'txn>> {
        Ok(OverlayRevIter::Base(self.base.rev_iter(txn)?))
    }

    pub(crate) fn prefix_iter<'txn>(
        &self,
        txn: &'txn RoTxn<'_>,
        prefix: &[u8],
    ) -> Result<OverlayPrefix<'txn>> {
        Ok(OverlayPrefix::Base(self.base.prefix_iter(txn, prefix)?))
    }

    pub(crate) fn range<'txn, R>(
        &self,
        txn: &'txn RoTxn<'_>,
        range: &R,
    ) -> Result<OverlayRange<'txn>>
    where
        R: RangeBounds<[u8]>,
    {
        Ok(OverlayRange::Base(self.base.range(txn, range)?))
    }

    pub(crate) fn rev_range<'txn, R>(
        &self,
        txn: &'txn RoTxn<'_>,
        range: &R,
    ) -> Result<OverlayRevRange<'txn>>
    where
        R: RangeBounds<[u8]>,
    {
        Ok(OverlayRevRange::Base(self.base.rev_range(txn, range)?))
    }

    /// DUP_SORT only: iterator over the duplicate data items of `key`, or
    /// `None` when the key is absent.
    pub(crate) fn get_duplicates<'txn>(
        &self,
        txn: &'txn RoTxn<'_>,
        key: &[u8],
    ) -> Result<Option<OverlayDupValues<'txn>>> {
        Ok(self
            .base
            .get_duplicates(txn, key)?
            .map(OverlayDupValues::Base))
    }
}

/// Accessor over the one `Str`-keyed named database (`sync_state`).
pub(crate) struct OverlayStrDb {
    base: Database<Str, Bytes>,
}

impl OverlayStrDb {
    /// Canonical (base-only) view over a raw database handle.
    pub(crate) fn canonical(base: Database<Str, Bytes>) -> Self {
        Self { base }
    }

    pub(crate) fn get<'txn>(
        &self,
        txn: &'txn RoTxn<'_>,
        key: &str,
    ) -> Result<Option<Cow<'txn, [u8]>>> {
        Ok(self.base.get(txn, key)?.map(Cow::Borrowed))
    }

    pub(crate) fn put(&self, txn: &mut RwTxn<'_>, key: &str, data: &[u8]) -> Result<()> {
        self.base.put(txn, key, data).map_err(Error::from)
    }

    pub(crate) fn delete(&self, txn: &mut RwTxn<'_>, key: &str) -> Result<bool> {
        self.base.delete(txn, key).map_err(Error::from)
    }

    // Lib-target dead: today's callers are cfg(test) residue sweeps
    // (sweep/tests, convergence props, branch_store_oracle); ONE-1726's merge
    // variant arms the production caller. `allow` (not `expect`): the lint IS
    // fulfilled in test-cfg compilations.
    #[allow(dead_code)]
    pub(crate) fn iter<'txn>(&self, txn: &'txn RoTxn<'_>) -> Result<OverlayStrIter<'txn>> {
        Ok(OverlayStrIter::Base(self.base.iter(txn)?))
    }

    pub(crate) fn prefix_iter<'txn>(
        &self,
        txn: &'txn RoTxn<'_>,
        prefix: &str,
    ) -> Result<OverlayStrPrefix<'txn>> {
        Ok(OverlayStrPrefix::Base(self.base.prefix_iter(txn, prefix)?))
    }
}

fn borrow_pair<'txn>((k, v): (&'txn [u8], &'txn [u8])) -> KvPair<'txn> {
    (Cow::Borrowed(k), Cow::Borrowed(v))
}

fn convert_pair<'txn>(res: heed::Result<(&'txn [u8], &'txn [u8])>) -> Result<KvPair<'txn>> {
    res.map(borrow_pair).map_err(Error::from)
}

fn convert_str_pair<'txn>(res: heed::Result<(&'txn str, &'txn [u8])>) -> Result<StrKvPair<'txn>> {
    res.map(|(k, v)| (Cow::Borrowed(k), Cow::Borrowed(v)))
        .map_err(Error::from)
}

/// Owned iterator over all entries, in key order.
pub(crate) enum OverlayIter<'txn> {
    Base(RoIter<'txn, Bytes, Bytes>),
}

impl<'txn> Iterator for OverlayIter<'txn> {
    type Item = Result<KvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_pair),
        }
    }
}

/// Owned iterator over all entries, in reverse key order.
pub(crate) enum OverlayRevIter<'txn> {
    Base(RoRevIter<'txn, Bytes, Bytes>),
}

impl<'txn> Iterator for OverlayRevIter<'txn> {
    type Item = Result<KvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_pair),
        }
    }
}

/// Owned iterator over a key range.
pub(crate) enum OverlayRange<'txn> {
    Base(RoRange<'txn, Bytes, Bytes>),
}

impl<'txn> Iterator for OverlayRange<'txn> {
    type Item = Result<KvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_pair),
        }
    }
}

/// Owned iterator over a key range, in reverse order.
pub(crate) enum OverlayRevRange<'txn> {
    Base(RoRevRange<'txn, Bytes, Bytes>),
}

impl<'txn> Iterator for OverlayRevRange<'txn> {
    type Item = Result<KvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_pair),
        }
    }
}

/// Owned iterator over the entries sharing a key prefix.
///
/// On a DUP_SORT database the default mode visits every duplicate data item;
/// [`OverlayPrefix::move_between_keys`] switches to distinct-key iteration,
/// mirroring heed's typestate switch as a variant change.
pub(crate) enum OverlayPrefix<'txn> {
    Base(RoPrefix<'txn, Bytes, Bytes, DefaultComparator>),
    BaseBetweenKeys(RoPrefix<'txn, Bytes, Bytes, DefaultComparator, MoveBetweenKeys>),
}

impl OverlayPrefix<'_> {
    /// Iterate distinct keys only, skipping duplicate data items (DUP_SORT).
    pub(crate) fn move_between_keys(self) -> Self {
        match self {
            Self::Base(inner) => Self::BaseBetweenKeys(inner.move_between_keys()),
            Self::BaseBetweenKeys(inner) => Self::BaseBetweenKeys(inner),
        }
    }
}

impl<'txn> Iterator for OverlayPrefix<'txn> {
    type Item = Result<KvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_pair),
            Self::BaseBetweenKeys(inner) => inner.next().map(convert_pair),
        }
    }
}

/// Owned iterator over the duplicate data items of one DUP_SORT key.
pub(crate) enum OverlayDupValues<'txn> {
    Base(RoIter<'txn, Bytes, Bytes, MoveOnCurrentKeyDuplicates>),
}

impl<'txn> Iterator for OverlayDupValues<'txn> {
    type Item = Result<KvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_pair),
        }
    }
}

/// Owned iterator over all `sync_state` entries, in key order.
// Lib-target dead with `OverlayStrDb::iter` above — same rationale.
#[allow(dead_code)]
pub(crate) enum OverlayStrIter<'txn> {
    Base(RoIter<'txn, Str, Bytes>),
}

impl<'txn> Iterator for OverlayStrIter<'txn> {
    type Item = Result<StrKvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_str_pair),
        }
    }
}

/// Owned iterator over the `sync_state` entries sharing a key prefix.
pub(crate) enum OverlayStrPrefix<'txn> {
    Base(RoPrefix<'txn, Str, Bytes, DefaultComparator>),
}

impl<'txn> Iterator for OverlayStrPrefix<'txn> {
    type Item = Result<StrKvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_str_pair),
        }
    }
}
