//! ComposedOverlay snapshot holder plus OverlayDb/OverlayStrDb canonical-vs-composed read/write accessors.

use std::borrow::Cow;
use std::ops::RangeBounds;
use std::sync::Arc;

use heed::types::{Bytes, Str};
use heed::{Database, RoTxn, RwTxn};

use crate::session_overlay::{OverlayKeyspace, OverlaySnapshot, SessionOverlay, SnapshotLookup};
use oneiron_contracts::error::{Error, Result};

use super::iters::{
    OverlayDupValues, OverlayIter, OverlayPrefix, OverlayRange, OverlayRevRange, OverlayStrIter,
    OverlayStrPrefix,
};
use super::merge::{
    Direction, MergedPrefixRows, MergedRows, PrefetchedMergedRows, StrMergedRows, borrow_pair,
    key_in_range,
};

pub(super) type KvPair<'txn> = (Cow<'txn, [u8]>, Cow<'txn, [u8]>);

pub(super) type StrKvPair<'txn> = (Cow<'txn, str>, Cow<'txn, [u8]>);

struct ComposedOverlay {
    live: Arc<SessionOverlay>,
    snapshot: Arc<OverlaySnapshot>,
    keyspace: OverlayKeyspace,
}

impl ComposedOverlay {
    /// The view a read composes now (FIX 10004): a writer's own segment as
    /// it stands, when this accessor was captured inside it; else the
    /// captured snapshot ([`SessionOverlay::read_view`]).
    fn view(&self) -> Result<Arc<OverlaySnapshot>> {
        self.live.read_view(&self.snapshot)
    }

    /// [`Self::view`] for a question with no error to answer: the captured
    /// snapshot when the writer's view cannot be leased.
    fn view_or_captured(&self) -> Arc<OverlaySnapshot> {
        self.view().unwrap_or_else(|_| Arc::clone(&self.snapshot))
    }
}

pub struct OverlayDb {
    base: Database<Bytes, Bytes>,
    overlay: Option<ComposedOverlay>,
}

impl OverlayDb {
    pub fn canonical(base: Database<Bytes, Bytes>) -> Self {
        Self {
            base,
            overlay: None,
        }
    }

    pub fn composed(
        base: Database<Bytes, Bytes>,
        overlay: Arc<SessionOverlay>,
        snapshot: Arc<OverlaySnapshot>,
        keyspace: OverlayKeyspace,
    ) -> Self {
        Self {
            base,
            overlay: Some(ComposedOverlay {
                live: overlay,
                snapshot,
                keyspace,
            }),
        }
    }

    #[allow(
        dead_code,
        reason = "ONE-1726 single-accessor oracle helper; production sessions use Store::session_view"
    )]
    pub fn with_overlay(
        &self,
        overlay: Arc<SessionOverlay>,
        keyspace: OverlayKeyspace,
    ) -> Result<Self> {
        let snapshot = Arc::new(overlay.snapshot()?);
        Ok(Self::composed(self.base, overlay, snapshot, keyspace))
    }

    /// The room snapshot this accessor reads, shared by every accessor of
    /// its composed store view. Canonical accessors have no room snapshot.
    pub fn overlay_snapshot(&self) -> Option<&OverlaySnapshot> {
        self.overlay
            .as_ref()
            .map(|overlay| overlay.snapshot.as_ref())
    }

    /// What this accessor's room stages over base, from the snapshot its
    /// reads compose; `None` for the vault's own accessor.
    pub fn staged_rows(&self) -> Option<crate::session_overlay::StagedRows> {
        let overlay = self.overlay.as_ref()?;
        Some(overlay.view_or_captured().staged_rows(overlay.keyspace))
    }

    /// Whether this accessor's room stages a row of its own at `key` (not a
    /// deletion), in the snapshot its reads compose: an active segment's
    /// writes included.
    pub fn stages_row(&self, key: &[u8]) -> bool {
        self.overlay.as_ref().is_some_and(|overlay| {
            matches!(
                overlay
                    .view_or_captured()
                    .lookup_single(overlay.keyspace, key),
                SnapshotLookup::Present(_)
            )
        })
    }

    /// Whether this accessor's room hides base's row at `key` (see
    /// [`Self::hide_base_row`]), in the snapshot its reads compose.
    pub fn hides(&self, key: &[u8]) -> bool {
        self.overlay.as_ref().is_some_and(|overlay| {
            matches!(
                overlay
                    .view_or_captured()
                    .lookup_single(overlay.keyspace, key),
                SnapshotLookup::Tombstone
            )
        })
    }

    /// The keys of base's rows this accessor's room hides; none for the
    /// vault's own accessor, or for a room that cleared base.
    pub fn hidden_keys(&self, txn: &RoTxn<'_>) -> Result<Vec<Vec<u8>>> {
        let Some(staged) = self.staged_rows().filter(|staged| !staged.clear_base) else {
            return Ok(Vec::new());
        };
        let mut keys = Vec::new();
        for (key, value) in staged.rows {
            if value.is_none() && self.base.get(txn, &key)?.is_some() {
                keys.push(key);
            }
        }
        Ok(keys)
    }

    /// [`Self::get`], with base's row where this accessor's room hides it. A
    /// walk over a graph the room inherits from base reads this way: a row
    /// the room hides is still a node of that graph, and the walk passes
    /// through it, but it is never a result.
    pub fn get_unhidden<'txn>(
        &self,
        txn: &'txn RoTxn<'_>,
        key: &[u8],
    ) -> Result<Option<Cow<'txn, [u8]>>> {
        if self.hides(key) {
            return Ok(self.base.get(txn, key)?.map(Cow::Borrowed));
        }
        self.get(txn, key)
    }

    pub fn get<'txn>(&self, txn: &'txn RoTxn<'_>, key: &[u8]) -> Result<Option<Cow<'txn, [u8]>>> {
        let Some(overlay) = &self.overlay else {
            return Ok(self.base.get(txn, key)?.map(Cow::Borrowed));
        };
        if overlay.keyspace.is_dupsort() {
            let Some(mut values) = self.get_duplicates(txn, key)? else {
                return Ok(None);
            };
            return values
                .next()
                .transpose()
                .map(|row| row.map(|(_, value)| value));
        }
        match overlay.view()?.lookup_single(overlay.keyspace, key) {
            SnapshotLookup::Passthrough => Ok(self.base.get(txn, key)?.map(Cow::Borrowed)),
            SnapshotLookup::Tombstone => Ok(None),
            SnapshotLookup::Present(value) => Ok(Some(Cow::Owned(value))),
        }
    }

    pub fn put(&self, txn: &mut RwTxn<'_>, key: &[u8], data: &[u8]) -> Result<()> {
        match &self.overlay {
            Some(overlay) => overlay.live.put(overlay.keyspace, key, data),
            None => Ok(self.base.put(txn, key, data)?),
        }
    }

    pub fn delete(&self, txn: &mut RwTxn<'_>, key: &[u8]) -> Result<bool> {
        let Some(overlay) = &self.overlay else {
            return Ok(self.base.delete(txn, key)?);
        };
        let existed = self.get(txn, key)?.is_some();
        if existed {
            let base_backed = self.base.get(txn, key)?.is_some();
            overlay
                .live
                .delete_with_base_backing(overlay.keyspace, key, base_backed)?;
        }
        Ok(existed)
    }

    /// Hides base's row at `key` from this accessor's room: the row base
    /// holds now and any it writes there later, before the room's segment
    /// commits included. Base itself is not written. The vault's own
    /// accessor has no room to hide a row from.
    pub fn hide_base_row(&self, key: &[u8]) -> Result<()> {
        let overlay = self.overlay.as_ref().ok_or(Error::InvariantViolation(
            "only a room's accessor hides a base row",
        ))?;
        overlay
            .live
            .delete_with_base_backing(overlay.keyspace, key, true)
    }

    pub fn delete_one_duplicate(
        &self,
        txn: &mut RwTxn<'_>,
        key: &[u8],
        data: &[u8],
    ) -> Result<bool> {
        let Some(overlay) = &self.overlay else {
            return Ok(self.base.delete_one_duplicate(txn, key, data)?);
        };
        let mut exact_count = 0_usize;
        if let Some(values) = self.get_duplicates(txn, key)? {
            for row in values {
                let (_, value) = row?;
                if value.as_ref() == data {
                    exact_count += 1;
                }
            }
        }
        if exact_count != 0 {
            let mut base_backed = false;
            if let Some(values) = self.base.get_duplicates(txn, key)? {
                for row in values {
                    let (_, value) = row?;
                    if value == data {
                        base_backed = true;
                        break;
                    }
                }
            }
            overlay
                .live
                .delete_duplicate(overlay.keyspace, key, data, base_backed)?;
        }
        Ok(exact_count != 0)
    }

    pub fn clear(&self, txn: &mut RwTxn<'_>) -> Result<()> {
        match &self.overlay {
            Some(overlay) => overlay.live.clear(overlay.keyspace),
            None => Ok(self.base.clear(txn)?),
        }
    }

    pub fn len(&self, txn: &RoTxn<'_>) -> Result<u64> {
        if self.overlay.is_none() {
            return Ok(self.base.len(txn)?);
        }
        self.iter(txn)?.try_fold(0_u64, |count, row| {
            row?;
            count
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("overlay database row count"))
        })
    }

    #[allow(
        dead_code,
        reason = "completed composed accessor; first session caller lands with ONE-1728 retrieval"
    )]
    pub fn is_empty(&self, txn: &RoTxn<'_>) -> Result<bool> {
        if self.overlay.is_none() {
            return Ok(self.base.is_empty(txn)?);
        }
        Ok(self.iter(txn)?.next().transpose()?.is_none())
    }

    pub fn first<'txn>(&self, txn: &'txn RoTxn<'_>) -> Result<Option<KvPair<'txn>>> {
        if self.overlay.is_none() {
            return Ok(self.base.first(txn)?.map(borrow_pair));
        }
        self.iter(txn)?.next().transpose()
    }

    pub fn iter<'txn>(&self, txn: &'txn RoTxn<'_>) -> Result<OverlayIter<'txn>> {
        let Some(overlay) = &self.overlay else {
            return Ok(OverlayIter::Base(self.base.iter(txn)?));
        };
        let view = overlay.view()?;
        let plan = view.merge_plan(overlay.keyspace, |_| true);
        Ok(OverlayIter::Merged(Box::new(MergedRows::new(
            Some(self.base.iter(txn)?),
            plan,
            Direction::Forward,
            view,
        ))))
    }

    pub fn prefix_iter<'txn>(
        &self,
        txn: &'txn RoTxn<'_>,
        prefix: &[u8],
    ) -> Result<OverlayPrefix<'txn>> {
        let Some(overlay) = &self.overlay else {
            return Ok(OverlayPrefix::Base(self.base.prefix_iter(txn, prefix)?));
        };
        let view = overlay.view()?;
        let plan = view.merge_plan(overlay.keyspace, |key| key.starts_with(prefix));
        Ok(OverlayPrefix::Merged(Box::new(MergedPrefixRows::new(
            MergedRows::new(
                Some(self.base.prefix_iter(txn, prefix)?),
                plan,
                Direction::Forward,
                view,
            ),
        ))))
    }

    pub fn range<'txn, R>(&self, txn: &'txn RoTxn<'_>, range: &R) -> Result<OverlayRange<'txn>>
    where
        R: RangeBounds<[u8]>,
    {
        let Some(overlay) = &self.overlay else {
            return Ok(OverlayRange::Base(self.base.range(txn, range)?));
        };
        let view = overlay.view()?;
        let plan = view.merge_plan(overlay.keyspace, |key| key_in_range(key, range));
        Ok(OverlayRange::Merged(Box::new(MergedRows::new(
            Some(self.base.range(txn, range)?),
            plan,
            Direction::Forward,
            view,
        ))))
    }

    pub fn rev_range<'txn, R>(
        &self,
        txn: &'txn RoTxn<'_>,
        range: &R,
    ) -> Result<OverlayRevRange<'txn>>
    where
        R: RangeBounds<[u8]>,
    {
        let Some(overlay) = &self.overlay else {
            return Ok(OverlayRevRange::Base(self.base.rev_range(txn, range)?));
        };
        let view = overlay.view()?;
        let plan = view.merge_plan(overlay.keyspace, |key| key_in_range(key, range));
        Ok(OverlayRevRange::Merged(Box::new(MergedRows::new(
            Some(self.base.rev_range(txn, range)?),
            plan,
            Direction::Reverse,
            view,
        ))))
    }

    pub fn get_duplicates<'txn>(
        &self,
        txn: &'txn RoTxn<'_>,
        key: &[u8],
    ) -> Result<Option<OverlayDupValues<'txn>>> {
        let Some(overlay) = &self.overlay else {
            return Ok(self
                .base
                .get_duplicates(txn, key)?
                .map(OverlayDupValues::Base));
        };
        let view = overlay.view()?;
        let plan = view.merge_plan(overlay.keyspace, |candidate| candidate == key);
        let mut merged = MergedRows::new(
            self.base.get_duplicates(txn, key)?,
            plan,
            Direction::Forward,
            view,
        );
        let Some(first) = merged.next() else {
            return Ok(None);
        };
        let first = first?;
        Ok(Some(OverlayDupValues::Merged(Box::new(
            PrefetchedMergedRows {
                first: Some(first),
                inner: merged,
                last_duplicate_identity: None,
            },
        ))))
    }
}

pub struct OverlayStrDb {
    base: Database<Str, Bytes>,
    overlay: Option<ComposedOverlay>,
}

impl OverlayStrDb {
    pub fn canonical(base: Database<Str, Bytes>) -> Self {
        Self {
            base,
            overlay: None,
        }
    }

    #[allow(
        dead_code,
        reason = "constructed by the complete 28-accessor session view; first sync-state caller lands after ONE-1727"
    )]
    pub fn composed(
        base: Database<Str, Bytes>,
        overlay: Arc<SessionOverlay>,
        snapshot: Arc<OverlaySnapshot>,
        keyspace: OverlayKeyspace,
    ) -> Self {
        Self {
            base,
            overlay: Some(ComposedOverlay {
                live: overlay,
                snapshot,
                keyspace,
            }),
        }
    }

    pub fn get<'txn>(&self, txn: &'txn RoTxn<'_>, key: &str) -> Result<Option<Cow<'txn, [u8]>>> {
        let Some(overlay) = &self.overlay else {
            return Ok(self.base.get(txn, key)?.map(Cow::Borrowed));
        };
        match overlay
            .view()?
            .lookup_single(overlay.keyspace, key.as_bytes())
        {
            SnapshotLookup::Passthrough => Ok(self.base.get(txn, key)?.map(Cow::Borrowed)),
            SnapshotLookup::Tombstone => Ok(None),
            SnapshotLookup::Present(value) => Ok(Some(Cow::Owned(value))),
        }
    }

    pub fn put(&self, txn: &mut RwTxn<'_>, key: &str, data: &[u8]) -> Result<()> {
        match &self.overlay {
            Some(overlay) => overlay.live.put(overlay.keyspace, key.as_bytes(), data),
            None => Ok(self.base.put(txn, key, data)?),
        }
    }

    pub fn delete(&self, txn: &mut RwTxn<'_>, key: &str) -> Result<bool> {
        let Some(overlay) = &self.overlay else {
            return Ok(self.base.delete(txn, key)?);
        };
        let existed = self.get(txn, key)?.is_some();
        if existed {
            let base_backed = self.base.get(txn, key)?.is_some();
            overlay
                .live
                .delete_with_base_backing(overlay.keyspace, key.as_bytes(), base_backed)?;
        }
        Ok(existed)
    }

    #[allow(
        dead_code,
        reason = "completed composed accessor; first session sync-state scan lands after ONE-1727"
    )]
    pub fn iter<'txn>(&self, txn: &'txn RoTxn<'_>) -> Result<OverlayStrIter<'txn>> {
        let Some(overlay) = &self.overlay else {
            return Ok(OverlayStrIter::Base(self.base.iter(txn)?));
        };
        let view = overlay.view()?;
        let plan = view.merge_plan(overlay.keyspace, |_| true);
        Ok(OverlayStrIter::Merged(Box::new(StrMergedRows::new(
            self.base.iter(txn)?,
            plan,
            Direction::Forward,
            view,
        ))))
    }

    pub fn prefix_iter<'txn>(
        &self,
        txn: &'txn RoTxn<'_>,
        prefix: &str,
    ) -> Result<OverlayStrPrefix<'txn>> {
        let Some(overlay) = &self.overlay else {
            return Ok(OverlayStrPrefix::Base(self.base.prefix_iter(txn, prefix)?));
        };
        let view = overlay.view()?;
        let plan = view.merge_plan(overlay.keyspace, |key| key.starts_with(prefix.as_bytes()));
        Ok(OverlayStrPrefix::Merged(Box::new(StrMergedRows::new(
            self.base.prefix_iter(txn, prefix)?,
            plan,
            Direction::Forward,
            view,
        ))))
    }

    /// The rows whose keys, compared as bytes, fall in `range`, in key
    /// order: the seek past a cursor a prefix scan cannot make (FIX 5951).
    #[cfg(feature = "sync")]
    pub fn range_bytes<'txn, R>(
        &self,
        txn: &'txn RoTxn<'_>,
        range: &R,
    ) -> Result<OverlayRange<'txn>>
    where
        R: RangeBounds<[u8]>,
    {
        let base = self.base.remap_key_type::<Bytes>();
        let Some(overlay) = &self.overlay else {
            return Ok(OverlayRange::Base(base.range(txn, range)?));
        };
        let view = overlay.view()?;
        let plan = view.merge_plan(overlay.keyspace, |key| key_in_range(key, range));
        Ok(OverlayRange::Merged(Box::new(MergedRows::new(
            Some(base.range(txn, range)?),
            plan,
            Direction::Forward,
            view,
        ))))
    }
}
