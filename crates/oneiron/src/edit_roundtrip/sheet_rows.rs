//! Compact row selections for typed sheet asks and their unfinished suffix.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Selected row intervals, in ascending order without overlaps or adjacency.
/// A large rectangle stays one interval; absent rows are never enumerated
/// merely to describe work that has not run yet.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<(u32, u32)>", into = "Vec<(u32, u32)>")]
pub struct SheetRowSelection {
    ranges: BTreeMap<u32, u32>,
}

impl SheetRowSelection {
    /// One inclusive interval; invalid/empty bounds select nothing. The ask
    /// still validates its enclosing range independently.
    #[must_use]
    pub fn range(first: u32, last: u32) -> Self {
        let mut selected = Self::default();
        if first != 0 && first <= last {
            selected.ranges.insert(first, last);
        }
        selected
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    #[must_use]
    pub fn contains(&self, row: &u32) -> bool {
        self.ranges
            .range(..=*row)
            .next_back()
            .is_some_and(|(_, end)| row <= end)
    }

    /// Stream selected rows intersecting the caller's enclosing range.
    pub fn iter_within(&self, first: u32, last: u32) -> impl Iterator<Item = u32> + '_ {
        self.ranges
            .range(..=last)
            .filter_map(move |(start, end)| {
                let (start, end) = ((*start).max(first), (*end).min(last));
                (start <= end).then_some(start..=end)
            })
            .flatten()
    }

    pub fn insert(&mut self, row: u32) {
        if row != 0 {
            self.insert_range(row, row);
        }
    }

    fn insert_range(&mut self, mut first: u32, mut last: u32) {
        if let Some((&start, &end)) = self.ranges.range(..=first).next_back()
            && end.saturating_add(1) >= first
        {
            self.ranges.remove(&start);
            first = start;
            last = last.max(end);
        }
        while let Some((&start, &end)) = self.ranges.range(first..).next() {
            if start > last.saturating_add(1) {
                break;
            }
            self.ranges.remove(&start);
            last = last.max(end);
        }
        self.ranges.insert(first, last);
    }

    /// Union actual changed units with an unfinished selection without
    /// expanding either interval into individual rows.
    pub fn merge(&mut self, more: Self) {
        for (first, last) in more.ranges {
            self.insert_range(first, last);
        }
    }

    /// Intersect interval metadata with the enclosing original selection.
    pub fn intersect(&mut self, first: u32, last: u32) {
        self.trim_before(first);
        self.ranges.retain(|start, end| {
            *end = (*end).min(last);
            *start <= *end
        });
    }

    /// Consume the completed prefix by moving only interval metadata.
    pub fn trim_before(&mut self, next: u32) {
        let mut remaining = self.ranges.split_off(&next);
        if let Some((_, &last)) = self.ranges.iter().next_back()
            && last >= next
        {
            remaining.insert(next, last);
        }
        self.ranges = remaining;
    }
}

impl FromIterator<u32> for SheetRowSelection {
    fn from_iter<T: IntoIterator<Item = u32>>(rows: T) -> Self {
        let mut selected = Self::default();
        for row in rows {
            selected.insert(row);
        }
        selected
    }
}

impl TryFrom<Vec<(u32, u32)>> for SheetRowSelection {
    type Error = &'static str;

    fn try_from(ranges: Vec<(u32, u32)>) -> Result<Self, Self::Error> {
        let mut previous = None;
        for &(first, last) in &ranges {
            if first == 0
                || first > last
                || previous.is_some_and(|end: u32| end.saturating_add(1) >= first)
            {
                return Err("invalid sheet row selection");
            }
            previous = Some(last);
        }
        Ok(Self {
            ranges: ranges.into_iter().collect(),
        })
    }
}

impl From<SheetRowSelection> for Vec<(u32, u32)> {
    fn from(selection: SheetRowSelection) -> Self {
        selection.ranges.into_iter().collect()
    }
}
