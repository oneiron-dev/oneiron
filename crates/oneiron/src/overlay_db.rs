//! Per-database accessor seam for the session write-overlay (ARCH-0052, D2).
//!
//! Canonical accessors pass through to heed. A composed accessor keeps one
//! immutable overlay snapshot for its whole logical read while writes route to
//! the live transaction segment. Merged scans stream the base cursor and the
//! bounded overlay delta together, preserving page-borrowed base values.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::iter::Peekable;
use std::ops::{Bound, RangeBounds};
use std::sync::Arc;

use heed::iteration_method::{MoveBetweenKeys, MoveOnCurrentKeyDuplicates};
use heed::types::{Bytes, Str};
use heed::{
    Database, DefaultComparator, RoIter, RoPrefix, RoRange, RoRevIter, RoRevRange, RoTxn, RwTxn,
};

use crate::error::{Error, Result};
use crate::session_overlay::{
    OverlayKeyspace, OverlaySnapshot, SessionOverlay, SnapshotLookup, SnapshotMergePlan,
    SnapshotMergeRow,
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

#[derive(Clone, Copy)]
enum Direction {
    Forward,
    Reverse,
}

pub(crate) struct MergedRows<'txn, I>
where
    I: Iterator<Item = heed::Result<(&'txn [u8], &'txn [u8])>>,
{
    base: Option<I>,
    base_next: Option<heed::Result<(&'txn [u8], &'txn [u8])>>,
    base_done: bool,
    overlay: Peekable<std::vec::IntoIter<SnapshotMergeRow>>,
    deleted_keys: BTreeSet<Vec<u8>>,
    direction: Direction,
    _snapshot: Arc<OverlaySnapshot>,
}

impl<'txn, I> MergedRows<'txn, I>
where
    I: Iterator<Item = heed::Result<(&'txn [u8], &'txn [u8])>>,
{
    fn new(
        base: Option<I>,
        mut plan: SnapshotMergePlan,
        direction: Direction,
        snapshot: Arc<OverlaySnapshot>,
    ) -> Self {
        if matches!(direction, Direction::Reverse) {
            plan.rows.reverse();
        }
        Self {
            base: if plan.clear_base { None } else { base },
            base_next: None,
            base_done: plan.clear_base,
            overlay: plan.rows.into_iter().peekable(),
            deleted_keys: plan.deleted_keys,
            direction,
            _snapshot: snapshot,
        }
    }

    fn fill_base(&mut self) {
        if self.base_next.is_none() && !self.base_done {
            self.base_next = self.base.as_mut().and_then(Iterator::next);
            if self.base_next.is_none() {
                self.base_done = true;
            }
        }
    }

    fn base_precedes_overlay(
        direction: Direction,
        key: &[u8],
        value: &[u8],
        row: &SnapshotMergeRow,
    ) -> Ordering {
        let ordering = match row {
            SnapshotMergeRow::Single {
                key: overlay_key, ..
            } => key.cmp(overlay_key),
            SnapshotMergeRow::Duplicate {
                key: overlay_key,
                identity,
                ..
            } => {
                (key, duplicate_identity(value)).cmp(&(overlay_key.as_slice(), identity.as_slice()))
            }
        };
        match direction {
            Direction::Forward => ordering,
            Direction::Reverse => ordering.reverse(),
        }
    }

    fn base_key_is_deleted(deleted_keys: &BTreeSet<Vec<u8>>, key: &[u8]) -> bool {
        deleted_keys.contains(key)
    }

    fn take_base(&mut self) -> Option<Result<KvPair<'txn>>> {
        self.base_next.take().map(convert_pair)
    }

    fn take_overlay(&mut self) -> Option<KvPair<'txn>> {
        let row = self.overlay.next()?;
        match row {
            SnapshotMergeRow::Single {
                key,
                value: Some(value),
            }
            | SnapshotMergeRow::Duplicate {
                key,
                present: Some(value),
                ..
            } => Some((Cow::Owned(key), Cow::Owned(value))),
            SnapshotMergeRow::Single { value: None, .. }
            | SnapshotMergeRow::Duplicate { present: None, .. } => None,
        }
    }
}

impl<'txn, I> Iterator for MergedRows<'txn, I>
where
    I: Iterator<Item = heed::Result<(&'txn [u8], &'txn [u8])>>,
{
    type Item = Result<KvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            self.fill_base();
            if self
                .base_next
                .as_ref()
                .is_some_and(std::result::Result::is_err)
            {
                return self.take_base();
            }

            let base_row = self.base_next.as_ref().and_then(|row| row.as_ref().ok());
            let overlay_row = self.overlay.peek();
            match (base_row, overlay_row) {
                (None, None) => return None,
                (Some((key, _)), None) => {
                    if Self::base_key_is_deleted(&self.deleted_keys, key) {
                        self.base_next.take();
                        continue;
                    }
                    return self.take_base();
                }
                (None, Some(_)) => {
                    if let Some(row) = self.take_overlay() {
                        return Some(Ok(row));
                    }
                }
                (Some((key, value)), Some(overlay_row)) => {
                    match Self::base_precedes_overlay(self.direction, key, value, overlay_row) {
                        Ordering::Less => {
                            if Self::base_key_is_deleted(&self.deleted_keys, key) {
                                self.base_next.take();
                                continue;
                            }
                            return self.take_base();
                        }
                        Ordering::Greater => {
                            if let Some(row) = self.take_overlay() {
                                return Some(Ok(row));
                            }
                        }
                        Ordering::Equal => match overlay_row {
                            SnapshotMergeRow::Single { .. } => {
                                self.base_next.take();
                                if let Some(row) = self.take_overlay() {
                                    return Some(Ok(row));
                                }
                            }
                            SnapshotMergeRow::Duplicate {
                                deleted, present, ..
                            } => {
                                if Self::base_key_is_deleted(&self.deleted_keys, key)
                                    || present.is_some()
                                    || deleted.contains(*value)
                                {
                                    self.base_next.take();
                                    continue;
                                }
                                return self.take_base();
                            }
                        },
                    }
                }
            }
        }
    }
}

pub(crate) struct MergedPrefixRows<'txn> {
    rows: MergedRows<'txn, RoPrefix<'txn, Bytes, Bytes, DefaultComparator>>,
    previous_key: Option<Vec<u8>>,
    move_between_keys: bool,
}

impl<'txn> MergedPrefixRows<'txn> {
    fn new(rows: MergedRows<'txn, RoPrefix<'txn, Bytes, Bytes, DefaultComparator>>) -> Self {
        Self {
            rows,
            previous_key: None,
            move_between_keys: false,
        }
    }

    fn move_between_keys(mut self) -> Self {
        self.move_between_keys = true;
        self
    }
}

impl<'txn> Iterator for MergedPrefixRows<'txn> {
    type Item = Result<KvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let row = self.rows.next()?;
            let Ok((key, _)) = &row else {
                return Some(row);
            };
            if self.move_between_keys && self.previous_key.as_deref() == Some(key.as_ref()) {
                continue;
            }
            self.previous_key = Some(key.to_vec());
            return Some(row);
        }
    }
}

pub(crate) struct PrefetchedMergedRows<'txn, I>
where
    I: Iterator<Item = heed::Result<(&'txn [u8], &'txn [u8])>>,
{
    first: Option<KvPair<'txn>>,
    inner: MergedRows<'txn, I>,
    last_duplicate_identity: Option<Vec<u8>>,
}

impl<'txn, I> Iterator for PrefetchedMergedRows<'txn, I>
where
    I: Iterator<Item = heed::Result<(&'txn [u8], &'txn [u8])>>,
{
    type Item = Result<KvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        let row = self.first.take().map(Ok).or_else(|| self.inner.next())?;
        let Ok((_, value)) = &row else {
            return Some(row);
        };
        let identity = duplicate_identity(value);
        if self
            .last_duplicate_identity
            .as_deref()
            .is_some_and(|previous| identity <= previous)
        {
            return Some(Err(Error::CorruptedIndex(
                "duplicate posting entries for one entity",
            )));
        }
        self.last_duplicate_identity = Some(identity.to_vec());
        Some(row)
    }
}

pub(crate) struct StrBytes<I>(I);

impl<'txn, I> Iterator for StrBytes<I>
where
    I: Iterator<Item = heed::Result<(&'txn str, &'txn [u8])>>,
{
    type Item = heed::Result<(&'txn [u8], &'txn [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .next()
            .map(|row| row.map(|(key, value)| (key.as_bytes(), value)))
    }
}

pub(crate) struct StrMergedRows<'txn, I>
where
    I: Iterator<Item = heed::Result<(&'txn str, &'txn [u8])>>,
{
    inner: MergedRows<'txn, StrBytes<I>>,
}

impl<'txn, I> StrMergedRows<'txn, I>
where
    I: Iterator<Item = heed::Result<(&'txn str, &'txn [u8])>>,
{
    fn new(
        base: I,
        plan: SnapshotMergePlan,
        direction: Direction,
        snapshot: Arc<OverlaySnapshot>,
    ) -> Self {
        Self {
            inner: MergedRows::new(Some(StrBytes(base)), plan, direction, snapshot),
        }
    }
}

impl<'txn, I> Iterator for StrMergedRows<'txn, I>
where
    I: Iterator<Item = heed::Result<(&'txn str, &'txn [u8])>>,
{
    type Item = Result<StrKvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|row| {
            let (key, value) = row?;
            let key = match key {
                Cow::Borrowed(key) => {
                    Cow::Borrowed(std::str::from_utf8(key).map_err(|_| {
                        Error::InvariantViolation("non-UTF-8 base key in sync_state")
                    })?)
                }
                Cow::Owned(key) => Cow::Owned(String::from_utf8(key).map_err(|_| {
                    Error::InvariantViolation("non-UTF-8 key in sync_state overlay")
                })?),
            };
            Ok((key, value))
        })
    }
}

fn duplicate_identity(value: &[u8]) -> &[u8] {
    value.get(..16).unwrap_or(value)
}

fn key_in_range<R>(key: &[u8], range: &R) -> bool
where
    R: RangeBounds<[u8]>,
{
    let above_start = match range.start_bound() {
        Bound::Included(start) => key >= start,
        Bound::Excluded(start) => key > start,
        Bound::Unbounded => true,
    };
    let below_end = match range.end_bound() {
        Bound::Included(end) => key <= end,
        Bound::Excluded(end) => key < end,
        Bound::Unbounded => true,
    };
    above_start && below_end
}

fn borrow_pair<'txn>((key, value): (&'txn [u8], &'txn [u8])) -> KvPair<'txn> {
    (Cow::Borrowed(key), Cow::Borrowed(value))
}

fn convert_pair<'txn>(row: heed::Result<(&'txn [u8], &'txn [u8])>) -> Result<KvPair<'txn>> {
    Ok(row.map(borrow_pair)?)
}

fn convert_str_pair<'txn>(row: heed::Result<(&'txn str, &'txn [u8])>) -> Result<StrKvPair<'txn>> {
    Ok(row.map(|(key, value)| (Cow::Borrowed(key), Cow::Borrowed(value)))?)
}

pub(crate) enum OverlayIter<'txn> {
    Base(RoIter<'txn, Bytes, Bytes>),
    Merged(Box<MergedRows<'txn, RoIter<'txn, Bytes, Bytes>>>),
}

impl<'txn> Iterator for OverlayIter<'txn> {
    type Item = Result<KvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_pair),
            Self::Merged(inner) => inner.next(),
        }
    }
}

pub(crate) enum OverlayRevIter<'txn> {
    Base(RoRevIter<'txn, Bytes, Bytes>),
    Merged(Box<MergedRows<'txn, RoRevIter<'txn, Bytes, Bytes>>>),
}

impl<'txn> Iterator for OverlayRevIter<'txn> {
    type Item = Result<KvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_pair),
            Self::Merged(inner) => inner.next(),
        }
    }
}

pub(crate) enum OverlayRange<'txn> {
    Base(RoRange<'txn, Bytes, Bytes>),
    Merged(Box<MergedRows<'txn, RoRange<'txn, Bytes, Bytes>>>),
}

impl<'txn> Iterator for OverlayRange<'txn> {
    type Item = Result<KvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_pair),
            Self::Merged(inner) => inner.next(),
        }
    }
}

pub(crate) enum OverlayRevRange<'txn> {
    Base(RoRevRange<'txn, Bytes, Bytes>),
    Merged(Box<MergedRows<'txn, RoRevRange<'txn, Bytes, Bytes>>>),
}

impl<'txn> Iterator for OverlayRevRange<'txn> {
    type Item = Result<KvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_pair),
            Self::Merged(inner) => inner.next(),
        }
    }
}

pub(crate) enum OverlayPrefix<'txn> {
    Base(RoPrefix<'txn, Bytes, Bytes, DefaultComparator>),
    BaseBetweenKeys(RoPrefix<'txn, Bytes, Bytes, DefaultComparator, MoveBetweenKeys>),
    Merged(Box<MergedPrefixRows<'txn>>),
}

impl OverlayPrefix<'_> {
    pub(crate) fn move_between_keys(self) -> Self {
        match self {
            Self::Base(inner) => Self::BaseBetweenKeys(inner.move_between_keys()),
            Self::BaseBetweenKeys(inner) => Self::BaseBetweenKeys(inner),
            Self::Merged(inner) => Self::Merged(Box::new((*inner).move_between_keys())),
        }
    }
}

impl<'txn> Iterator for OverlayPrefix<'txn> {
    type Item = Result<KvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_pair),
            Self::BaseBetweenKeys(inner) => inner.next().map(convert_pair),
            Self::Merged(inner) => inner.next(),
        }
    }
}

pub(crate) enum OverlayDupValues<'txn> {
    Base(RoIter<'txn, Bytes, Bytes, MoveOnCurrentKeyDuplicates>),
    Merged(Box<PrefetchedMergedRows<'txn, RoIter<'txn, Bytes, Bytes, MoveOnCurrentKeyDuplicates>>>),
}

impl<'txn> Iterator for OverlayDupValues<'txn> {
    type Item = Result<KvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_pair),
            Self::Merged(inner) => inner.next(),
        }
    }
}

#[allow(
    dead_code,
    reason = "returned by the completed OverlayStrDb::iter accessor; first session sync-state scan lands after ONE-1727"
)]
pub(crate) enum OverlayStrIter<'txn> {
    Base(RoIter<'txn, Str, Bytes>),
    Merged(Box<StrMergedRows<'txn, RoIter<'txn, Str, Bytes>>>),
}

impl<'txn> Iterator for OverlayStrIter<'txn> {
    type Item = Result<StrKvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_str_pair),
            Self::Merged(inner) => inner.next(),
        }
    }
}

pub(crate) enum OverlayStrPrefix<'txn> {
    Base(RoPrefix<'txn, Str, Bytes, DefaultComparator>),
    Merged(Box<StrMergedRows<'txn, RoPrefix<'txn, Str, Bytes, DefaultComparator>>>),
}

impl<'txn> Iterator for OverlayStrPrefix<'txn> {
    type Item = Result<StrKvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_str_pair),
            Self::Merged(inner) => inner.next(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heed::{DatabaseFlags, Env, EnvOpenOptions};

    fn env_with_db(flags: DatabaseFlags) -> (tempfile::TempDir, Env, Database<Bytes, Bytes>) {
        let dir = tempfile::tempdir().expect("overlay db test temp dir");
        // SAFETY: `dir` is a freshly created, unique temp directory owned by
        // this test; no other `Env` maps the same path, this is the sole
        // opener, and the handle outlives the returned databases. heed's
        // `open` is unsafe only against concurrent/duplicate mappings of one
        // path, which cannot occur here.
        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(16 * 1024 * 1024)
                .max_dbs(1)
                .open(dir.path())
                .expect("open overlay db test env")
        };
        let mut wtxn = env.write_txn().expect("open setup write txn");
        let db = env
            .database_options()
            .types::<Bytes, Bytes>()
            .name("rows")
            .flags(flags)
            .create(&mut wtxn)
            .expect("create overlay db test database");
        wtxn.commit().expect("commit overlay db setup");
        (dir, env, db)
    }

    fn commit_put(
        overlay: &Arc<SessionOverlay>,
        keyspace: OverlayKeyspace,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        let segment = overlay.install_txn_segment()?;
        overlay.put(keyspace, key, value)?;
        segment.commit()
    }

    #[test]
    fn composed_view_reuses_one_snapshot_across_successive_gets() -> Result<()> {
        let (_dir, env, base) = env_with_db(DatabaseFlags::empty());
        let overlay = SessionOverlay::new(4096);
        commit_put(&overlay, OverlayKeyspace::Entities, b"a", b"old")?;
        let snapshot = Arc::new(overlay.snapshot()?);
        let view = OverlayDb::composed(base, overlay.clone(), snapshot, OverlayKeyspace::Entities);
        let rtxn = env.read_txn()?;

        assert_eq!(view.get(&rtxn, b"a")?.as_deref(), Some(&b"old"[..]));
        std::thread::scope(|scope| {
            scope
                .spawn(|| -> Result<()> {
                    let segment = overlay.install_txn_segment()?;
                    overlay.delete(OverlayKeyspace::Entities, b"a")?;
                    overlay.put(OverlayKeyspace::Entities, b"b", b"new")?;
                    segment.commit()
                })
                .join()
                .expect("overlay apply thread panicked")
        })?;
        assert_eq!(view.get(&rtxn, b"a")?.as_deref(), Some(&b"old"[..]));
        assert_eq!(view.get(&rtxn, b"b")?, None);
        Ok(())
    }

    #[test]
    fn composed_delete_only_stages_tombstones_for_visible_keys() -> Result<()> {
        let (_dir, env, base) = env_with_db(DatabaseFlags::empty());
        let mut setup_txn = env.write_txn()?;
        base.put(&mut setup_txn, b"base", b"present")?;
        setup_txn.commit()?;

        let overlay = SessionOverlay::new(4096);
        let snapshot = Arc::new(overlay.snapshot()?);
        let view = OverlayDb::composed(base, overlay.clone(), snapshot, OverlayKeyspace::Entities);
        let mut wtxn = env.write_txn()?;
        let segment = overlay.install_txn_segment()?;

        assert!(!view.delete(&mut wtxn, b"absent")?);
        let after_absent = overlay.snapshot()?;
        assert_eq!(
            after_absent
                .merge_plan(OverlayKeyspace::Entities, |_| true)
                .rows
                .len(),
            0
        );
        assert_eq!(after_absent.bytes_used(), 0);

        assert!(view.delete(&mut wtxn, b"base")?);
        let after_present = Arc::new(overlay.snapshot()?);
        assert_eq!(
            after_present
                .merge_plan(OverlayKeyspace::Entities, |_| true)
                .rows
                .len(),
            1
        );
        let staged_view =
            OverlayDb::composed(base, overlay, after_present, OverlayKeyspace::Entities);
        assert_eq!(staged_view.get(&wtxn, b"base")?, None);

        wtxn.commit()?;
        segment.commit()?;
        Ok(())
    }

    #[test]
    fn empty_overlay_streams_base_rows_as_borrowed() -> Result<()> {
        const ROW_COUNT: usize = 512;
        let (_dir, env, base) = env_with_db(DatabaseFlags::empty());
        let mut wtxn = env.write_txn()?;
        for index in 0..ROW_COUNT {
            let key = (index as u64).to_be_bytes();
            let value = vec![index as u8; 1024];
            base.put(&mut wtxn, &key, &value)?;
        }
        wtxn.commit()?;

        let overlay = SessionOverlay::new(4096);
        let snapshot = Arc::new(overlay.snapshot()?);
        let view = OverlayDb::composed(base, overlay, snapshot, OverlayKeyspace::Entities);
        let rtxn = env.read_txn()?;
        let mut borrowed_count = 0_usize;
        let mut owned_count = 0_usize;
        for row in view.iter(&rtxn)? {
            let (key, value) = row?;
            if matches!(key, Cow::Borrowed(_)) && matches!(value, Cow::Borrowed(_)) {
                borrowed_count += 1;
            } else {
                owned_count += 1;
            }
        }
        assert_eq!(borrowed_count, ROW_COUNT);
        assert_eq!(owned_count, 0);
        Ok(())
    }

    #[test]
    fn absent_exact_duplicate_delete_keeps_present_sibling() -> Result<()> {
        let (_dir, env, base) = env_with_db(DatabaseFlags::DUP_SORT);
        let key = b"term";
        let mut present = vec![0_u8; 16];
        present[15] = 7;
        present.extend_from_slice(b"fields-a");
        let mut absent = present[..16].to_vec();
        absent.extend_from_slice(b"fields-b");
        let mut wtxn = env.write_txn()?;
        base.put(&mut wtxn, key, &present)?;
        wtxn.commit()?;

        let overlay = SessionOverlay::new(4096);
        let snapshot = Arc::new(overlay.snapshot()?);
        let view = OverlayDb::composed(
            base,
            overlay.clone(),
            snapshot,
            OverlayKeyspace::TextPostings,
        );
        let mut wtxn = env.write_txn()?;
        let segment = overlay.install_txn_segment()?;
        assert!(!view.delete_one_duplicate(&mut wtxn, key, &absent)?);
        wtxn.commit()?;
        segment.commit()?;

        let fresh = OverlayDb::composed(
            base,
            overlay.clone(),
            Arc::new(overlay.snapshot()?),
            OverlayKeyspace::TextPostings,
        );
        let rtxn = env.read_txn()?;
        let values = fresh
            .get_duplicates(&rtxn, key)?
            .expect("present duplicate survives")
            .map(|row| row.map(|(_, value)| value.into_owned()))
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], present);
        Ok(())
    }

    #[test]
    fn merged_duplicate_stream_rejects_out_of_order_entity_ids() -> Result<()> {
        type EmptyBase = std::iter::Empty<heed::Result<(&'static [u8], &'static [u8])>>;

        let mut higher = vec![0_u8; 16];
        higher[15] = 2;
        higher.push(0);
        let mut lower = vec![0_u8; 16];
        lower[15] = 1;
        lower.push(0);
        let snapshot = Arc::new(SessionOverlay::new(4096).snapshot()?);
        let inner: MergedRows<'static, EmptyBase> = MergedRows::new(
            None,
            SnapshotMergePlan {
                clear_base: true,
                deleted_keys: BTreeSet::new(),
                rows: vec![SnapshotMergeRow::Duplicate {
                    key: b"term".to_vec(),
                    identity: duplicate_identity(&lower).to_vec(),
                    deleted: BTreeSet::new(),
                    present: Some(lower),
                }],
            },
            Direction::Forward,
            snapshot,
        );
        let merged = PrefetchedMergedRows {
            first: Some((Cow::Owned(b"term".to_vec()), Cow::Owned(higher))),
            inner,
            last_duplicate_identity: None,
        };

        let rows = merged.collect::<Vec<_>>();
        assert_eq!(rows.len(), 2);
        match &rows[0] {
            Ok((key, value)) => {
                assert_eq!(key.as_ref(), b"term");
                assert_eq!(value.len(), 17);
                assert_eq!(value[15], 2);
            }
            Err(other) => panic!("first duplicate unexpectedly failed: {other}"),
        }
        match &rows[1] {
            Err(Error::CorruptedIndex(message)) => {
                assert_eq!(*message, "duplicate posting entries for one entity");
            }
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("out-of-order duplicate unexpectedly emitted"),
        }
        Ok(())
    }
}
