//! The pending table vector keeps admission through its owning iterator.

use super::types::SplitStatus;
use crate::tendril::{ReserveError, StrTendril};
use std::mem::{replace, size_of};
use std::slice;
use std::vec;

#[derive(Default)]
pub(crate) struct PendingTableText {
    entries: Vec<(SplitStatus, StrTendril)>,
    reservation: Option<Box<dyn Send + Sync>>,
}

impl PendingTableText {
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(super) fn last_mut(&mut self) -> Option<&mut (SplitStatus, StrTendril)> {
        self.entries.last_mut()
    }

    pub(super) fn iter(&self) -> slice::Iter<'_, (SplitStatus, StrTendril)> {
        self.entries.iter()
    }

    pub(super) fn push(&mut self, entry: (SplitStatus, StrTendril)) {
        self.entries.push(entry);
    }

    pub(crate) fn try_reserve<R, E>(
        &mut self,
        additional: usize,
        reserve: impl FnOnce(usize) -> Result<R, E>,
        settle: impl FnOnce(&mut R, usize) -> Result<(), E>,
    ) -> Result<(), ReserveError<E>>
    where
        R: Send + Sync + 'static,
    {
        let required = self
            .entries
            .len()
            .checked_add(additional)
            .ok_or(ReserveError::CapacityOverflow)?;
        if required <= self.entries.capacity() {
            return Ok(());
        }
        let capacity = required.max(self.entries.capacity().saturating_mul(2));
        let bytes = capacity
            .checked_mul(size_of::<(SplitStatus, StrTendril)>())
            .ok_or(ReserveError::CapacityOverflow)?;
        let mut reservation = reserve(bytes).map_err(ReserveError::Refused)?;
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(capacity)
            .map_err(ReserveError::Allocation)?;
        let bytes = replacement
            .capacity()
            .checked_mul(size_of::<(SplitStatus, StrTendril)>())
            .ok_or(ReserveError::CapacityOverflow)?;
        settle(&mut reservation, bytes).map_err(ReserveError::Refused)?;
        let reservation: Box<dyn Send + Sync> = Box::new(reservation);
        replacement.append(&mut self.entries);
        let old_entries = replace(&mut self.entries, replacement);
        let old_reservation = replace(&mut self.reservation, Some(reservation));
        drop(old_entries);
        drop(old_reservation);
        Ok(())
    }
}

pub(crate) struct PendingTableTextIntoIter {
    entries: vec::IntoIter<(SplitStatus, StrTendril)>,
    _reservation: Option<Box<dyn Send + Sync>>,
}

impl IntoIterator for PendingTableText {
    type Item = (SplitStatus, StrTendril);
    type IntoIter = PendingTableTextIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        PendingTableTextIntoIter {
            entries: self.entries.into_iter(),
            _reservation: self.reservation,
        }
    }
}

impl Iterator for PendingTableTextIntoIter {
    type Item = (SplitStatus, StrTendril);

    fn next(&mut self) -> Option<Self::Item> {
        self.entries.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.entries.size_hint()
    }
}
