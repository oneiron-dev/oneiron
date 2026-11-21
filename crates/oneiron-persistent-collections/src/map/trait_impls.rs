//! The conversion, comparison, formatting and serde trait impls of
//! [`PersistentMap`]: each gives the answer `BTreeMap`'s impl gives for the
//! same entries.

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Index;
use std::sync::Arc;

use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};

use super::{Form, IntoIter, Iter, IterMut, PersistentMap};

impl<K: Ord + Clone, V: Clone> IntoIterator for PersistentMap<K, V> {
    type Item = (K, V);
    type IntoIter = IntoIter<K, V>;

    fn into_iter(self) -> IntoIter<K, V> {
        let entries: Vec<(K, V)> = match self.form {
            Form::Empty => Vec::new(),
            Form::Small(map) => Arc::unwrap_or_clone(map)
                .into_iter()
                .map(|(key, value)| (key, Arc::unwrap_or_clone(value)))
                .collect(),
            Form::Large(map) => map
                .into_iter()
                .map(|(key, value)| (key, Arc::unwrap_or_clone(value)))
                .collect(),
        };
        entries.into_iter()
    }
}

impl<'a, K: Ord, V> IntoIterator for &'a PersistentMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = Iter<'a, K, V>;

    fn into_iter(self) -> Iter<'a, K, V> {
        self.iter()
    }
}

impl<'a, K: Ord + Clone, V: Clone> IntoIterator for &'a mut PersistentMap<K, V> {
    type Item = (&'a K, &'a mut V);
    type IntoIter = IterMut<'a, K, V>;

    fn into_iter(self) -> IterMut<'a, K, V> {
        self.iter_mut()
    }
}

impl<K: Ord + Clone, V> From<BTreeMap<K, V>> for PersistentMap<K, V> {
    fn from(entries: BTreeMap<K, V>) -> Self {
        let entries: BTreeMap<K, Arc<V>> = entries
            .into_iter()
            .map(|(key, value)| (key, Arc::new(value)))
            .collect();
        let mut map = Self {
            form: Form::Small(Arc::new(entries)),
        };
        map.fit_form();
        map
    }
}

impl<K: Ord + Clone, V: Clone, const N: usize> From<[(K, V); N]> for PersistentMap<K, V> {
    fn from(entries: [(K, V); N]) -> Self {
        Self::from(BTreeMap::from(entries))
    }
}

impl<K: Ord + Clone, V: Clone> FromIterator<(K, V)> for PersistentMap<K, V> {
    /// As `BTreeMap`'s: a repeated key keeps its last value.
    fn from_iter<I: IntoIterator<Item = (K, V)>>(entries: I) -> Self {
        Self::from(entries.into_iter().collect::<BTreeMap<K, V>>())
    }
}

impl<K: Ord + Clone, V: Clone + PartialEq> Extend<(K, V)> for PersistentMap<K, V> {
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, entries: I) {
        for (key, value) in entries {
            self.insert(key, value);
        }
    }
}

impl<'a, K: Ord + Copy, V: Copy + PartialEq> Extend<(&'a K, &'a V)> for PersistentMap<K, V> {
    fn extend<I: IntoIterator<Item = (&'a K, &'a V)>>(&mut self, entries: I) {
        self.extend(entries.into_iter().map(|(key, value)| (*key, *value)));
    }
}

impl<K: Ord + Borrow<Q>, Q: Ord + ?Sized, V> Index<&Q> for PersistentMap<K, V> {
    type Output = V;

    /// Panics if the map lacks `key`, as `BTreeMap`'s index does.
    fn index(&self, key: &Q) -> &V {
        self.get(key).expect("no entry found for key")
    }
}

impl<K: Ord, V: PartialEq> PartialEq for PersistentMap<K, V> {
    fn eq(&self, other: &Self) -> bool {
        match (&self.form, &other.form) {
            (Form::Large(left), Form::Large(right)) => left == right,
            _ => self.ptr_eq(other) || (self.len() == other.len() && self.iter().eq(other.iter())),
        }
    }
}

impl<K: Ord, V: Eq> Eq for PersistentMap<K, V> {}

impl<K: Ord, V: PartialOrd> PartialOrd for PersistentMap<K, V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.iter().partial_cmp(other.iter())
    }
}

impl<K: Ord, V: Ord> Ord for PersistentMap<K, V> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.iter().cmp(other.iter())
    }
}

impl<K: Ord + Hash, V: Hash> Hash for PersistentMap<K, V> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_usize(self.len());
        for entry in self {
            entry.hash(state);
        }
    }
}

impl<K: Ord + fmt::Debug, V: fmt::Debug> fmt::Debug for PersistentMap<K, V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_map().entries(self.iter()).finish()
    }
}

impl<K: Ord + Serialize, V: Serialize> Serialize for PersistentMap<K, V> {
    /// The call `BTreeMap`'s impl makes, with the same exact length hint.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self)
    }
}

impl<'de, K, V> Deserialize<'de> for PersistentMap<K, V>
where
    K: Ord + Clone + Deserialize<'de>,
    V: Deserialize<'de>,
{
    /// Through `BTreeMap`, so a repeated key keeps its last value.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        BTreeMap::<K, V>::deserialize(deserializer).map(Self::from)
    }
}
