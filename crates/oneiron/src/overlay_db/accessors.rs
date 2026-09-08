//! ComposedOverlay snapshot holder plus OverlayDb/OverlayStrDb canonical-vs-composed read/write accessors.

use std::borrow::Cow;
use std::ops::RangeBounds;
use std::sync::Arc;

use heed::types::{Bytes, Str};
use heed::{Database, RoTxn, RwTxn};

use crate::error::{Error, Result};
use crate::session_overlay::{OverlayKeyspace, OverlaySnapshot, SessionOverlay, SnapshotLookup};

use super::iters::{
    OverlayDupValues, OverlayIter, OverlayPrefix, OverlayRange, OverlayRevIter, OverlayRevRange,
    OverlayStrIter, OverlayStrPrefix,
};
use super::merge::{
    Direction, MergedPrefixRows, MergedRows, PrefetchedMergedRows, StrMergedRows, borrow_pair,
    key_in_range,
};

pub(crate) type KvPair<'txn> = (Cow<'txn, [u8]>, Cow<'txn, [u8]>);

pub(crate) type StrKvPair<'txn> = (Cow<'txn, str>, Cow<'txn, [u8]>);

struct ComposedOverlay {
    live: Arc<SessionOverlay>,
    snapshot: Arc<OverlaySnapshot>,
    keyspace: OverlayKeyspace,
}

pub(crate) struct OverlayDb {
    base: Database<Bytes, Bytes>,
    overlay: Option<ComposedOverlay>,
}

impl OverlayDb {
    pub(crate) fn canonical(base: Database<Bytes, Bytes>) -> Self {
        Self {
            base,
            overlay: None,
        }
    }

    pub(crate) fn composed(
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
    pub(crate) fn with_overlay(
        &self,
        overlay: Arc<SessionOverlay>,
        keyspace: OverlayKeyspace,
    ) -> Result<Self> {
        let snapshot = Arc::new(overlay.snapshot()?);
        Ok(Self::composed(self.base, overlay, snapshot, keyspace))
    }

    pub(crate) fn get<'txn>(
        &self,
        txn: &'txn RoTxn<'_>,
        key: &[u8],
    ) -> Result<Option<Cow<'txn, [u8]>>> {
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
        match overlay.snapshot.lookup_single(overlay.keyspace, key) {
            SnapshotLookup::Passthrough => Ok(self.base.get(txn, key)?.map(Cow::Borrowed)),
            SnapshotLookup::Tombstone => Ok(None),
            SnapshotLookup::Present(value) => Ok(Some(Cow::Owned(value))),
        }
    }

    pub(crate) fn put(&self, txn: &mut RwTxn<'_>, key: &[u8], data: &[u8]) -> Result<()> {
        match &self.overlay {
            Some(overlay) => overlay.live.put(overlay.keyspace, key, data),
            None => Ok(self.base.put(txn, key, data)?),
        }
    }

    pub(crate) fn delete(&self, txn: &mut RwTxn<'_>, key: &[u8]) -> Result<bool> {
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

    pub(crate) fn delete_one_duplicate(
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

    pub(crate) fn clear(&self, txn: &mut RwTxn<'_>) -> Result<()> {
        match &self.overlay {
            Some(overlay) => overlay.live.clear(overlay.keyspace),
            None => Ok(self.base.clear(txn)?),
        }
    }

    pub(crate) fn len(&self, txn: &RoTxn<'_>) -> Result<u64> {
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
    pub(crate) fn is_empty(&self, txn: &RoTxn<'_>) -> Result<bool> {
        if self.overlay.is_none() {
            return Ok(self.base.is_empty(txn)?);
        }
        Ok(self.iter(txn)?.next().transpose()?.is_none())
    }

    pub(crate) fn first<'txn>(&self, txn: &'txn RoTxn<'_>) -> Result<Option<KvPair<'txn>>> {
        if self.overlay.is_none() {
            return Ok(self.base.first(txn)?.map(borrow_pair));
        }
        self.iter(txn)?.next().transpose()
    }

    pub(crate) fn last<'txn>(&self, txn: &'txn RoTxn<'_>) -> Result<Option<KvPair<'txn>>> {
        if self.overlay.is_none() {
            return Ok(self.base.last(txn)?.map(borrow_pair));
        }
        self.rev_iter(txn)?.next().transpose()
    }

    pub(crate) fn iter<'txn>(&self, txn: &'txn RoTxn<'_>) -> Result<OverlayIter<'txn>> {
        let Some(overlay) = &self.overlay else {
            return Ok(OverlayIter::Base(self.base.iter(txn)?));
        };
        let plan = overlay.snapshot.merge_plan(overlay.keyspace, |_| true);
        Ok(OverlayIter::Merged(Box::new(MergedRows::new(
            Some(self.base.iter(txn)?),
            plan,
            Direction::Forward,
            overlay.snapshot.clone(),
        ))))
    }

    pub(crate) fn rev_iter<'txn>(&self, txn: &'txn RoTxn<'_>) -> Result<OverlayRevIter<'txn>> {
        let Some(overlay) = &self.overlay else {
            return Ok(OverlayRevIter::Base(self.base.rev_iter(txn)?));
        };
        let plan = overlay.snapshot.merge_plan(overlay.keyspace, |_| true);
        Ok(OverlayRevIter::Merged(Box::new(MergedRows::new(
            Some(self.base.rev_iter(txn)?),
            plan,
            Direction::Reverse,
            overlay.snapshot.clone(),
        ))))
    }

    pub(crate) fn prefix_iter<'txn>(
        &self,
        txn: &'txn RoTxn<'_>,
        prefix: &[u8],
    ) -> Result<OverlayPrefix<'txn>> {
        let Some(overlay) = &self.overlay else {
            return Ok(OverlayPrefix::Base(self.base.prefix_iter(txn, prefix)?));
        };
        let plan = overlay
            .snapshot
            .merge_plan(overlay.keyspace, |key| key.starts_with(prefix));
        Ok(OverlayPrefix::Merged(Box::new(MergedPrefixRows::new(
            MergedRows::new(
                Some(self.base.prefix_iter(txn, prefix)?),
                plan,
                Direction::Forward,
                overlay.snapshot.clone(),
            ),
        ))))
    }

    pub(crate) fn range<'txn, R>(
        &self,
        txn: &'txn RoTxn<'_>,
        range: &R,
    ) -> Result<OverlayRange<'txn>>
    where
        R: RangeBounds<[u8]>,
    {
        let Some(overlay) = &self.overlay else {
            return Ok(OverlayRange::Base(self.base.range(txn, range)?));
        };
        let plan = overlay
            .snapshot
            .merge_plan(overlay.keyspace, |key| key_in_range(key, range));
        Ok(OverlayRange::Merged(Box::new(MergedRows::new(
            Some(self.base.range(txn, range)?),
            plan,
            Direction::Forward,
            overlay.snapshot.clone(),
        ))))
    }

    pub(crate) fn rev_range<'txn, R>(
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
        let plan = overlay
            .snapshot
            .merge_plan(overlay.keyspace, |key| key_in_range(key, range));
        Ok(OverlayRevRange::Merged(Box::new(MergedRows::new(
            Some(self.base.rev_range(txn, range)?),
            plan,
            Direction::Reverse,
            overlay.snapshot.clone(),
        ))))
    }

    pub(crate) fn get_duplicates<'txn>(
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
        let plan = overlay
            .snapshot
            .merge_plan(overlay.keyspace, |candidate| candidate == key);
        let mut merged = MergedRows::new(
            self.base.get_duplicates(txn, key)?,
            plan,
            Direction::Forward,
            overlay.snapshot.clone(),
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

pub(crate) struct OverlayStrDb {
    base: Database<Str, Bytes>,
    overlay: Option<ComposedOverlay>,
}

impl OverlayStrDb {
    pub(crate) fn canonical(base: Database<Str, Bytes>) -> Self {
        Self {
            base,
            overlay: None,
        }
    }

    #[allow(
        dead_code,
        reason = "constructed by the complete 28-accessor session view; first sync-state caller lands after ONE-1727"
    )]
    pub(crate) fn composed(
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

    pub(crate) fn get<'txn>(
        &self,
        txn: &'txn RoTxn<'_>,
        key: &str,
    ) -> Result<Option<Cow<'txn, [u8]>>> {
        let Some(overlay) = &self.overlay else {
            return Ok(self.base.get(txn, key)?.map(Cow::Borrowed));
        };
        match overlay
            .snapshot
            .lookup_single(overlay.keyspace, key.as_bytes())
        {
            SnapshotLookup::Passthrough => Ok(self.base.get(txn, key)?.map(Cow::Borrowed)),
            SnapshotLookup::Tombstone => Ok(None),
            SnapshotLookup::Present(value) => Ok(Some(Cow::Owned(value))),
        }
    }

    pub(crate) fn put(&self, txn: &mut RwTxn<'_>, key: &str, data: &[u8]) -> Result<()> {
        match &self.overlay {
            Some(overlay) => overlay.live.put(overlay.keyspace, key.as_bytes(), data),
            None => Ok(self.base.put(txn, key, data)?),
        }
    }

    pub(crate) fn delete(&self, txn: &mut RwTxn<'_>, key: &str) -> Result<bool> {
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
    pub(crate) fn iter<'txn>(&self, txn: &'txn RoTxn<'_>) -> Result<OverlayStrIter<'txn>> {
        let Some(overlay) = &self.overlay else {
            return Ok(OverlayStrIter::Base(self.base.iter(txn)?));
        };
        let plan = overlay.snapshot.merge_plan(overlay.keyspace, |_| true);
        Ok(OverlayStrIter::Merged(Box::new(StrMergedRows::new(
            self.base.iter(txn)?,
            plan,
            Direction::Forward,
            overlay.snapshot.clone(),
        ))))
    }

    pub(crate) fn prefix_iter<'txn>(
        &self,
        txn: &'txn RoTxn<'_>,
        prefix: &str,
    ) -> Result<OverlayStrPrefix<'txn>> {
        let Some(overlay) = &self.overlay else {
            return Ok(OverlayStrPrefix::Base(self.base.prefix_iter(txn, prefix)?));
        };
        let plan = overlay
            .snapshot
            .merge_plan(overlay.keyspace, |key| key.starts_with(prefix.as_bytes()));
        Ok(OverlayStrPrefix::Merged(Box::new(StrMergedRows::new(
            self.base.prefix_iter(txn, prefix)?,
            plan,
            Direction::Forward,
            overlay.snapshot.clone(),
        ))))
    }
}
