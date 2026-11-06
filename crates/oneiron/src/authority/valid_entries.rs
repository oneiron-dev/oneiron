//! An authority fold's valid entries (FIX 12330): an ordered set of entry
//! hashes that is persistent, so a fold resumed from a base copies the base's
//! set in O(1) and inserts only the tail's rows. It reads as the `BTreeSet`
//! it replaces: ascending hash order, set equality, the same `Debug` form and
//! the same serde form, a sequence of hashes.

use std::collections::BTreeSet;

use super::AuthorityEntryHash;

/// Valid entry hashes, in ascending order. A clone shares the set; an insert
/// or a removal copies one path of it.
#[derive(Clone, Default)]
pub struct ValidEntries(im::OrdSet<AuthorityEntryHash>);

/// A set of entry hashes that [`ValidEntries::difference`] takes away.
pub trait EntryHashSet {
    /// Whether `hash` is in the set.
    fn holds(&self, hash: &AuthorityEntryHash) -> bool;
}

impl EntryHashSet for ValidEntries {
    fn holds(&self, hash: &AuthorityEntryHash) -> bool {
        self.contains(hash)
    }
}

impl EntryHashSet for BTreeSet<AuthorityEntryHash> {
    fn holds(&self, hash: &AuthorityEntryHash) -> bool {
        self.contains(hash)
    }
}

impl ValidEntries {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains(&self, hash: &AuthorityEntryHash) -> bool {
        self.0.contains(hash)
    }

    /// Adds `hash`; whether it was not here yet.
    pub fn insert(&mut self, hash: AuthorityEntryHash) -> bool {
        self.0.insert(hash).is_none()
    }

    /// Takes `hash` out; whether it was here.
    pub fn remove(&mut self, hash: &AuthorityEntryHash) -> bool {
        self.0.remove(hash).is_some()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Each hash, ascending.
    pub fn iter(&self) -> im::ordset::Iter<'_, AuthorityEntryHash> {
        self.0.iter()
    }

    /// Each hash here that `other` does not hold, ascending.
    pub fn difference<'a>(
        &'a self,
        other: &'a impl EntryHashSet,
    ) -> impl Iterator<Item = &'a AuthorityEntryHash> + 'a {
        self.iter().filter(|hash| !other.holds(hash))
    }
}

impl PartialEq for ValidEntries {
    fn eq(&self, other: &Self) -> bool {
        self.0.ptr_eq(&other.0) || (self.len() == other.len() && self.iter().eq(other.iter()))
    }
}

impl Eq for ValidEntries {}

impl std::fmt::Debug for ValidEntries {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

impl FromIterator<AuthorityEntryHash> for ValidEntries {
    fn from_iter<I: IntoIterator<Item = AuthorityEntryHash>>(hashes: I) -> Self {
        Self(hashes.into_iter().collect())
    }
}

impl Extend<AuthorityEntryHash> for ValidEntries {
    fn extend<I: IntoIterator<Item = AuthorityEntryHash>>(&mut self, hashes: I) {
        self.0.extend(hashes);
    }
}

impl<'a> Extend<&'a AuthorityEntryHash> for ValidEntries {
    fn extend<I: IntoIterator<Item = &'a AuthorityEntryHash>>(&mut self, hashes: I) {
        self.0.extend(hashes.into_iter().copied());
    }
}

impl IntoIterator for ValidEntries {
    type Item = AuthorityEntryHash;
    type IntoIter = im::ordset::ConsumingIter<AuthorityEntryHash>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a ValidEntries {
    type Item = &'a AuthorityEntryHash;
    type IntoIter = im::ordset::Iter<'a, AuthorityEntryHash>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl serde::Serialize for ValidEntries {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.iter())
    }
}

impl<'de> serde::Deserialize<'de> for ValidEntries {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hashes: BTreeSet<AuthorityEntryHash> = serde::Deserialize::deserialize(deserializer)?;
        Ok(hashes.into_iter().collect())
    }
}
