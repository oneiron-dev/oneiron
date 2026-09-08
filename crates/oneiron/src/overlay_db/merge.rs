//! Base/overlay merge engine: MergedRows state machine, prefix/prefetch/str adapters, ordering and pair-conversion helpers.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::iter::Peekable;
use std::ops::{Bound, RangeBounds};
use std::sync::Arc;

use heed::types::Bytes;
use heed::{DefaultComparator, RoPrefix};

use crate::error::{Error, Result};
use crate::session_overlay::{OverlaySnapshot, SnapshotMergePlan, SnapshotMergeRow};

use super::accessors::{KvPair, StrKvPair};

#[derive(Clone, Copy)]
pub(super) enum Direction {
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
    pub(super) fn new(
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
    pub(super) fn new(
        rows: MergedRows<'txn, RoPrefix<'txn, Bytes, Bytes, DefaultComparator>>,
    ) -> Self {
        Self {
            rows,
            previous_key: None,
            move_between_keys: false,
        }
    }

    pub(super) fn move_between_keys(mut self) -> Self {
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
    pub(super) first: Option<KvPair<'txn>>,
    pub(super) inner: MergedRows<'txn, I>,
    pub(super) last_duplicate_identity: Option<Vec<u8>>,
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
    pub(super) inner: MergedRows<'txn, StrBytes<I>>,
}

impl<'txn, I> StrMergedRows<'txn, I>
where
    I: Iterator<Item = heed::Result<(&'txn str, &'txn [u8])>>,
{
    pub(super) fn new(
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

pub(super) fn duplicate_identity(value: &[u8]) -> &[u8] {
    value.get(..16).unwrap_or(value)
}

pub(super) fn key_in_range<R>(key: &[u8], range: &R) -> bool
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

pub(super) fn borrow_pair<'txn>((key, value): (&'txn [u8], &'txn [u8])) -> KvPair<'txn> {
    (Cow::Borrowed(key), Cow::Borrowed(value))
}

pub(super) fn convert_pair<'txn>(
    row: heed::Result<(&'txn [u8], &'txn [u8])>,
) -> Result<KvPair<'txn>> {
    Ok(row.map(borrow_pair)?)
}

pub(super) fn convert_str_pair<'txn>(
    row: heed::Result<(&'txn str, &'txn [u8])>,
) -> Result<StrKvPair<'txn>> {
    Ok(row.map(|(key, value)| (Cow::Borrowed(key), Cow::Borrowed(value)))?)
}
