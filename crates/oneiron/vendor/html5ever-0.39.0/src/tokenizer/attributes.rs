//! Native attribute vectors retain admission across tokens and owning iterators.

use crate::tendril::ReserveError;
use crate::Attribute;
use std::fmt;
use std::mem::{replace, size_of};
use std::ops::{Deref, DerefMut};
use std::slice;
use std::sync::Arc;
use std::vec;

pub(crate) type TagAttributesReservation =
    Arc<dyn Fn(&mut TagAttributes, usize) -> bool + Send + Sync>;

/// An owned admission for one attribute-vector allocation.
pub struct TagAttributeGuard {
    _reservation: Box<dyn Send + Sync>,
}

/// Attribute storage whose admission follows the allocation, not the token.
#[derive(Default)]
pub struct TagAttributes {
    entries: Vec<Attribute>,
    reservation: Option<TagAttributeGuard>,
}

impl TagAttributes {
    /// Split storage for a sink that transfers the guard to its final owner.
    /// Free the vector allocation before dropping the returned guard.
    pub fn into_parts(self) -> (Vec<Attribute>, Option<TagAttributeGuard>) {
        (self.entries, self.reservation)
    }

    /// Return a plain vector only when it has no owned admission.
    pub fn into_unreserved(self) -> Result<Vec<Attribute>, Self> {
        if self.reservation.is_none() {
            Ok(self.entries)
        } else {
            Err(self)
        }
    }

    pub(crate) fn push(&mut self, attr: Attribute) {
        self.entries.push(attr);
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
            .checked_mul(size_of::<Attribute>())
            .ok_or(ReserveError::CapacityOverflow)?;
        let mut reservation = reserve(bytes).map_err(ReserveError::Refused)?;
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(capacity)
            .map_err(ReserveError::Allocation)?;
        let actual = replacement
            .capacity()
            .checked_mul(size_of::<Attribute>())
            .ok_or(ReserveError::CapacityOverflow)?;
        settle(&mut reservation, actual).map_err(ReserveError::Refused)?;
        let reservation = TagAttributeGuard {
            _reservation: Box::new(reservation),
        };
        replacement.append(&mut self.entries);
        let old_entries = replace(&mut self.entries, replacement);
        let old_reservation = replace(&mut self.reservation, Some(reservation));
        drop(old_entries);
        drop(old_reservation);
        Ok(())
    }

    pub(crate) fn try_clone(&self, reserve: &TagAttributesReservation) -> Option<Self> {
        let mut clone = Self::default();
        if !reserve(&mut clone, self.len()) {
            return None;
        }
        for attr in &self.entries {
            clone.entries.push(attr.clone());
        }
        Some(clone)
    }
}

impl From<Vec<Attribute>> for TagAttributes {
    fn from(entries: Vec<Attribute>) -> Self {
        Self {
            entries,
            reservation: None,
        }
    }
}

// Public clones allocate independent, unadmitted storage. Checked parser clones
// instead reserve their own destination through try_clone.
impl Clone for TagAttributes {
    fn clone(&self) -> Self {
        self.entries.clone().into()
    }
}

impl fmt::Debug for TagAttributes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.entries.fmt(formatter)
    }
}

impl PartialEq for TagAttributes {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}
impl Eq for TagAttributes {}

impl Deref for TagAttributes {
    type Target = [Attribute];
    fn deref(&self) -> &[Attribute] {
        &self.entries
    }
}
impl DerefMut for TagAttributes {
    fn deref_mut(&mut self) -> &mut [Attribute] {
        &mut self.entries
    }
}

impl<'a> IntoIterator for &'a TagAttributes {
    type Item = &'a Attribute;
    type IntoIter = slice::Iter<'a, Attribute>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}
impl<'a> IntoIterator for &'a mut TagAttributes {
    type Item = &'a mut Attribute;
    type IntoIter = slice::IterMut<'a, Attribute>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter_mut()
    }
}

/// The remaining attributes and allocation are freed before admission returns.
pub struct TagAttributesIntoIter {
    entries: vec::IntoIter<Attribute>,
    _reservation: Option<TagAttributeGuard>,
}
impl IntoIterator for TagAttributes {
    type Item = Attribute;
    type IntoIter = TagAttributesIntoIter;
    fn into_iter(self) -> Self::IntoIter {
        TagAttributesIntoIter {
            entries: self.entries.into_iter(),
            _reservation: self.reservation,
        }
    }
}
impl Iterator for TagAttributesIntoIter {
    type Item = Attribute;
    fn next(&mut self) -> Option<Attribute> {
        self.entries.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.entries.size_hint()
    }
}
