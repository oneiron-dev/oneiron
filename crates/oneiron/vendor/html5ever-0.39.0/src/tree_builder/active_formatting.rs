//! Private formatting-list storage retains admission until its allocation frees.

use super::types::FormatEntry;
use crate::tendril::ReserveError;
use std::mem::{replace, size_of};
use std::ops::{Deref, DerefMut};

pub(crate) struct ActiveFormatting<Handle> {
    entries: Vec<FormatEntry<Handle>>,
    reservation: Option<Box<dyn Send>>,
}

impl<Handle> Default for ActiveFormatting<Handle> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            reservation: None,
        }
    }
}

impl<Handle> ActiveFormatting<Handle> {
    pub(crate) fn try_reserve<R, E>(
        &mut self,
        additional: usize,
        reserve: impl FnOnce(usize) -> Result<R, E>,
        settle: impl FnOnce(&mut R, usize) -> Result<(), E>,
    ) -> Result<(), ReserveError<E>>
    where
        R: Send + 'static,
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
            .checked_mul(size_of::<FormatEntry<Handle>>())
            .ok_or(ReserveError::CapacityOverflow)?;
        let mut reservation = reserve(bytes).map_err(ReserveError::Refused)?;
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(capacity)
            .map_err(ReserveError::Allocation)?;
        let actual = replacement
            .capacity()
            .checked_mul(size_of::<FormatEntry<Handle>>())
            .ok_or(ReserveError::CapacityOverflow)?;
        settle(&mut reservation, actual).map_err(ReserveError::Refused)?;
        let reservation: Box<dyn Send> = Box::new(reservation);
        replacement.append(&mut self.entries);
        let old_entries = replace(&mut self.entries, replacement);
        let old_reservation = replace(&mut self.reservation, Some(reservation));
        drop(old_entries);
        drop(old_reservation);
        Ok(())
    }
}

impl<Handle> Deref for ActiveFormatting<Handle> {
    type Target = Vec<FormatEntry<Handle>>;
    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl<Handle> DerefMut for ActiveFormatting<Handle> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.entries
    }
}
