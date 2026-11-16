//! [`PersistentMap`]: an ordered map whose clones share structure.

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::{BTreeMap, btree_map};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::iter::FusedIterator;
use std::ops::{Index, RangeBounds};
use std::sync::Arc;

use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};

use crate::{SHRINK_LIMIT, SMALL_LIMIT};

/// An ordered map with `BTreeMap`'s order, equality and serde bytes, whose
/// clones share structure (see the crate docs).
pub struct PersistentMap<K, V> {
    form: Form<K, V>,
}

enum Form<K, V> {
    Empty,
    Small(Arc<BTreeMap<K, Arc<V>>>),
    Large(im::OrdMap<K, Arc<V>>),
}

impl<K, V> PersistentMap<K, V> {
    /// An empty map. Allocates nothing.
    pub const fn new() -> Self {
        Self { form: Form::Empty }
    }
}

#[cfg(test)]
impl<K, V> PersistentMap<K, V> {
    /// The form's name, for the tests.
    pub(crate) fn form_name(&self) -> &'static str {
        match self.form {
            Form::Empty => "empty",
            Form::Small(_) => "small",
            Form::Large(_) => "large",
        }
    }
}

impl<K, V> Default for PersistentMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> Clone for PersistentMap<K, V> {
    /// O(1): the clone shares every entry until one side writes.
    fn clone(&self) -> Self {
        let form = match &self.form {
            Form::Empty => Form::Empty,
            Form::Small(map) => Form::Small(Arc::clone(map)),
            Form::Large(map) => Form::Large(map.clone()),
        };
        Self { form }
    }
}

impl<K: Ord, V> PersistentMap<K, V> {
    pub fn len(&self) -> usize {
        match &self.form {
            Form::Empty => 0,
            Form::Small(map) => map.len(),
            Form::Large(map) => map.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        match &self.form {
            Form::Empty => None,
            Form::Small(map) => map.get(key).map(|value| &**value),
            Form::Large(map) => map.get(key).map(|value| &**value),
        }
    }

    pub fn get_key_value<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        match &self.form {
            Form::Empty => None,
            Form::Small(map) => map.get_key_value(key).map(|(key, value)| (key, &**value)),
            Form::Large(map) => map.get_key_value(key).map(|(key, value)| (key, &**value)),
        }
    }

    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        match &self.form {
            Form::Empty => false,
            Form::Small(map) => map.contains_key(key),
            Form::Large(map) => map.contains_key(key),
        }
    }

    pub fn iter(&self) -> Iter<'_, K, V> {
        let remaining = self.len();
        let inner = match &self.form {
            Form::Empty => IterForm::Empty,
            Form::Small(map) => IterForm::Small(map.iter()),
            Form::Large(map) => IterForm::Large(map.iter()),
        };
        Iter { inner, remaining }
    }

    pub fn keys(&self) -> Keys<'_, K, V> {
        Keys { inner: self.iter() }
    }

    pub fn values(&self) -> Values<'_, K, V> {
        Values { inner: self.iter() }
    }

    pub fn range<Q, R>(&self, range: R) -> Range<'_, K, V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
        R: RangeBounds<Q>,
    {
        let inner = match &self.form {
            Form::Empty => RangeForm::Empty,
            Form::Small(map) => RangeForm::Small(map.range(range)),
            Form::Large(map) => RangeForm::Large(map.range(range)),
        };
        Range { inner }
    }

    pub fn first_key_value(&self) -> Option<(&K, &V)> {
        match &self.form {
            Form::Empty => None,
            Form::Small(map) => map.first_key_value().map(|(key, value)| (key, &**value)),
            Form::Large(map) => map.get_min().map(|(key, value)| (key, &**value)),
        }
    }

    pub fn last_key_value(&self) -> Option<(&K, &V)> {
        match &self.form {
            Form::Empty => None,
            Form::Small(map) => map.last_key_value().map(|(key, value)| (key, &**value)),
            Form::Large(map) => map.get_max().map(|(key, value)| (key, &**value)),
        }
    }

    /// Whether both maps share one root, so that they are equal without a
    /// walk. False says nothing.
    pub fn ptr_eq(&self, other: &Self) -> bool {
        match (&self.form, &other.form) {
            (Form::Empty, Form::Empty) => true,
            (Form::Small(left), Form::Small(right)) => Arc::ptr_eq(left, right),
            (Form::Large(left), Form::Large(right)) => left.ptr_eq(right),
            _ => false,
        }
    }
}

impl<K: Ord + Clone, V> PersistentMap<K, V> {
    /// Moves to the form the length asks for: empty at 0, large past
    /// `SMALL_LIMIT`, small again at `SHRINK_LIMIT` or fewer.
    fn fit_form(&mut self) {
        let len = self.len();
        let fitted = match &self.form {
            Form::Empty => return,
            _ if len == 0 => Form::Empty,
            Form::Small(map) if len > SMALL_LIMIT => Form::Large(
                map.iter()
                    .map(|(key, value)| (key.clone(), Arc::clone(value)))
                    .collect(),
            ),
            Form::Large(map) if len <= SHRINK_LIMIT => Form::Small(Arc::new(
                map.iter()
                    .map(|(key, value)| (key.clone(), Arc::clone(value)))
                    .collect(),
            )),
            Form::Small(_) | Form::Large(_) => return,
        };
        self.form = fitted;
    }
}

impl<K: Ord + Clone, V: Clone> PersistentMap<K, V> {
    /// The value at `key`, copied first if a clone shares it. A key the
    /// map lacks copies nothing.
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        if !self.contains_key(key) {
            return None;
        }
        let stored = match &mut self.form {
            Form::Empty => None,
            Form::Small(map) => Arc::make_mut(map).get_mut(key),
            Form::Large(map) => map.get_mut(key),
        };
        stored.map(Arc::make_mut)
    }

    /// As `BTreeMap::insert`, except that a value equal to the stored one is
    /// not written (it is handed back as the old value), so an unchanged
    /// entry copies nothing.
    pub fn insert(&mut self, key: K, value: V) -> Option<V>
    where
        V: PartialEq,
    {
        if self.get(&key) == Some(&value) {
            return Some(value);
        }
        self.store(key, value)
    }

    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.remove_entry(key).map(|(_, value)| value)
    }

    pub fn remove_entry<Q>(&mut self, key: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        if !self.contains_key(key) {
            return None;
        }
        let removed = match &mut self.form {
            Form::Empty => None,
            Form::Small(map) => Arc::make_mut(map).remove_entry(key),
            Form::Large(map) => map.remove_with_key(key),
        };
        self.fit_form();
        removed.map(|(key, value)| (key, Arc::unwrap_or_clone(value)))
    }

    pub fn entry(&mut self, key: K) -> Entry<'_, K, V> {
        if self.contains_key(&key) {
            Entry::Occupied(OccupiedEntry { map: self, key })
        } else {
            Entry::Vacant(VacantEntry { map: self, key })
        }
    }

    /// Keeps the entries `keep` accepts. Unlike `BTreeMap::retain`, `keep`
    /// reads the value (`&V`); [`Self::retain_mut`] hands out `&mut V`. Only
    /// a removal writes.
    pub fn retain<F>(&mut self, mut keep: F)
    where
        F: FnMut(&K, &V) -> bool,
    {
        let dropped: Vec<K> = self
            .iter()
            .filter(|&(key, value)| !keep(key, value))
            .map(|(key, _)| key.clone())
            .collect();
        if dropped.is_empty() {
            return;
        }
        match &mut self.form {
            Form::Empty => {}
            Form::Small(map) => {
                let map = Arc::make_mut(map);
                for key in &dropped {
                    map.remove(key);
                }
            }
            Form::Large(map) => {
                for key in &dropped {
                    map.remove(key);
                }
            }
        }
        self.fit_form();
    }

    /// As `BTreeMap::retain`: `keep` may change the values it keeps. Every
    /// value is copied first if a clone shares it, so prefer
    /// [`Self::retain`] when `keep` only reads.
    pub fn retain_mut<F>(&mut self, mut keep: F)
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        if let Some(map) = self.small_mut() {
            map.retain(|key, value| keep(key, Arc::make_mut(value)));
        }
        self.fit_form();
    }

    pub fn clear(&mut self) {
        self.form = Form::Empty;
    }

    /// Every entry with its value writable: each value is copied first if a
    /// clone shares it, and a large map moves to one `BTreeMap` (O(len), as
    /// the walk itself is).
    pub fn iter_mut(&mut self) -> IterMut<'_, K, V> {
        IterMut {
            inner: self.small_mut().map(|map| map.iter_mut()),
        }
    }

    /// As [`Self::iter_mut`], values only.
    pub fn values_mut(&mut self) -> ValuesMut<'_, K, V> {
        ValuesMut {
            inner: self.iter_mut(),
        }
    }

    pub fn pop_first(&mut self) -> Option<(K, V)> {
        let key = self.first_key_value()?.0.clone();
        self.remove_entry(&key)
    }

    pub fn pop_last(&mut self) -> Option<(K, V)> {
        let key = self.last_key_value()?.0.clone();
        self.remove_entry(&key)
    }

    /// The entries as a `BTreeMap` (each key and value cloned).
    pub fn to_btree_map(&self) -> BTreeMap<K, V> {
        self.iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }

    /// Writes `value` at `key` without comparing it to a stored value.
    fn store(&mut self, key: K, value: V) -> Option<V> {
        let value = Arc::new(value);
        if let Form::Empty = self.form {
            self.form = Form::Small(Arc::new(BTreeMap::from([(key, value)])));
            return None;
        }
        let replaced = match &mut self.form {
            Form::Empty => None,
            Form::Small(map) => Arc::make_mut(map).insert(key, value),
            Form::Large(map) => map.insert(key, value),
        };
        self.fit_form();
        replaced.map(Arc::unwrap_or_clone)
    }

    /// The entries as one uniquely held `BTreeMap`, for the walks that hand
    /// out `&mut V`. A large map moves to the small form first (O(len), as
    /// such a walk is); the next write moves it back once it is past
    /// `SMALL_LIMIT`. None for an empty map.
    fn small_mut(&mut self) -> Option<&mut BTreeMap<K, Arc<V>>> {
        if let Form::Large(map) = &self.form {
            let entries: BTreeMap<K, Arc<V>> = map
                .iter()
                .map(|(key, value)| (key.clone(), Arc::clone(value)))
                .collect();
            self.form = Form::Small(Arc::new(entries));
        }
        match &mut self.form {
            Form::Small(map) => Some(Arc::make_mut(map)),
            Form::Empty | Form::Large(_) => None,
        }
    }
}

/// A view into one key of a [`PersistentMap`], as `btree_map::Entry`.
pub enum Entry<'a, K, V> {
    Vacant(VacantEntry<'a, K, V>),
    Occupied(OccupiedEntry<'a, K, V>),
}

/// A key the map lacks.
pub struct VacantEntry<'a, K, V> {
    map: &'a mut PersistentMap<K, V>,
    key: K,
}

/// A key the map holds.
pub struct OccupiedEntry<'a, K, V> {
    map: &'a mut PersistentMap<K, V>,
    key: K,
}

impl<'a, K: Ord + Clone, V: Clone> Entry<'a, K, V> {
    pub fn key(&self) -> &K {
        match self {
            Entry::Vacant(entry) => entry.key(),
            Entry::Occupied(entry) => entry.key(),
        }
    }

    pub fn or_insert(self, default: V) -> &'a mut V {
        match self {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(default),
        }
    }

    pub fn or_insert_with<F: FnOnce() -> V>(self, default: F) -> &'a mut V {
        match self {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(default()),
        }
    }

    pub fn or_insert_with_key<F: FnOnce(&K) -> V>(self, default: F) -> &'a mut V {
        match self {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let value = default(entry.key());
                entry.insert(value)
            }
        }
    }

    pub fn or_default(self) -> &'a mut V
    where
        V: Default,
    {
        self.or_insert_with(V::default)
    }

    pub fn and_modify<F: FnOnce(&mut V)>(self, modify: F) -> Self {
        match self {
            Entry::Occupied(mut entry) => {
                modify(entry.get_mut());
                Entry::Occupied(entry)
            }
            Entry::Vacant(entry) => Entry::Vacant(entry),
        }
    }
}

impl<'a, K: Ord + Clone, V: Clone> VacantEntry<'a, K, V> {
    pub fn key(&self) -> &K {
        &self.key
    }

    pub fn into_key(self) -> K {
        self.key
    }

    pub fn insert(self, value: V) -> &'a mut V {
        let Self { map, key } = self;
        map.store(key.clone(), value);
        map.get_mut(&key)
            .expect("a vacant entry's key was just written")
    }
}

impl<'a, K: Ord + Clone, V: Clone> OccupiedEntry<'a, K, V> {
    pub fn key(&self) -> &K {
        &self.key
    }

    pub fn get(&self) -> &V {
        self.map
            .get(&self.key)
            .expect("an occupied entry's key is in the map")
    }

    /// The value, copied first if a clone shares it.
    pub fn get_mut(&mut self) -> &mut V {
        self.map
            .get_mut(&self.key)
            .expect("an occupied entry's key is in the map")
    }

    pub fn into_mut(self) -> &'a mut V {
        let Self { map, key } = self;
        map.get_mut(&key)
            .expect("an occupied entry's key is in the map")
    }

    /// Writes `value` and returns the old one.
    pub fn insert(&mut self, value: V) -> V {
        self.map
            .store(self.key.clone(), value)
            .expect("an occupied entry's key is in the map")
    }

    pub fn remove(self) -> V {
        self.remove_entry().1
    }

    pub fn remove_entry(self) -> (K, V) {
        let Self { map, key } = self;
        map.remove_entry(&key)
            .expect("an occupied entry's key is in the map")
    }
}

/// The entries of a [`PersistentMap`] in key order.
pub struct Iter<'a, K, V> {
    inner: IterForm<'a, K, V>,
    remaining: usize,
}

enum IterForm<'a, K, V> {
    Empty,
    Small(btree_map::Iter<'a, K, Arc<V>>),
    Large(im::ordmap::Iter<'a, K, Arc<V>>),
}

impl<'a, K: Ord, V> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let next = match &mut self.inner {
            IterForm::Empty => None,
            IterForm::Small(iter) => iter.next(),
            IterForm::Large(iter) => iter.next(),
        };
        let (key, value) = next?;
        self.remaining -= 1;
        Some((key, &**value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<K: Ord, V> DoubleEndedIterator for Iter<'_, K, V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let next = match &mut self.inner {
            IterForm::Empty => None,
            IterForm::Small(iter) => iter.next_back(),
            IterForm::Large(iter) => iter.next_back(),
        };
        let (key, value) = next?;
        self.remaining -= 1;
        Some((key, &**value))
    }
}

impl<K: Ord, V> ExactSizeIterator for Iter<'_, K, V> {}

impl<K: Ord, V> FusedIterator for Iter<'_, K, V> {}

/// The keys of a [`PersistentMap`] in order.
pub struct Keys<'a, K, V> {
    inner: Iter<'a, K, V>,
}

impl<'a, K: Ord, V> Iterator for Keys<'a, K, V> {
    type Item = &'a K;

    fn next(&mut self) -> Option<&'a K> {
        self.inner.next().map(|(key, _)| key)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<K: Ord, V> DoubleEndedIterator for Keys<'_, K, V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back().map(|(key, _)| key)
    }
}

impl<K: Ord, V> ExactSizeIterator for Keys<'_, K, V> {}

impl<K: Ord, V> FusedIterator for Keys<'_, K, V> {}

/// The values of a [`PersistentMap`] in key order.
pub struct Values<'a, K, V> {
    inner: Iter<'a, K, V>,
}

impl<'a, K: Ord, V> Iterator for Values<'a, K, V> {
    type Item = &'a V;

    fn next(&mut self) -> Option<&'a V> {
        self.inner.next().map(|(_, value)| value)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<K: Ord, V> DoubleEndedIterator for Values<'_, K, V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back().map(|(_, value)| value)
    }
}

impl<K: Ord, V> ExactSizeIterator for Values<'_, K, V> {}

impl<K: Ord, V> FusedIterator for Values<'_, K, V> {}

/// The entries of a [`PersistentMap`] in key order, values writable.
pub struct IterMut<'a, K, V> {
    inner: Option<btree_map::IterMut<'a, K, Arc<V>>>,
}

impl<'a, K: Clone, V: Clone> Iterator for IterMut<'a, K, V> {
    type Item = (&'a K, &'a mut V);

    fn next(&mut self) -> Option<Self::Item> {
        let (key, value) = self.inner.as_mut()?.next()?;
        Some((key, Arc::make_mut(value)))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner
            .as_ref()
            .map_or((0, Some(0)), Iterator::size_hint)
    }
}

impl<K: Clone, V: Clone> DoubleEndedIterator for IterMut<'_, K, V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let (key, value) = self.inner.as_mut()?.next_back()?;
        Some((key, Arc::make_mut(value)))
    }
}

impl<K: Clone, V: Clone> ExactSizeIterator for IterMut<'_, K, V> {}

impl<K: Clone, V: Clone> FusedIterator for IterMut<'_, K, V> {}

/// The values of a [`PersistentMap`] in key order, writable.
pub struct ValuesMut<'a, K, V> {
    inner: IterMut<'a, K, V>,
}

impl<'a, K: Clone, V: Clone> Iterator for ValuesMut<'a, K, V> {
    type Item = &'a mut V;

    fn next(&mut self) -> Option<&'a mut V> {
        self.inner.next().map(|(_, value)| value)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<K: Clone, V: Clone> DoubleEndedIterator for ValuesMut<'_, K, V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back().map(|(_, value)| value)
    }
}

impl<K: Clone, V: Clone> ExactSizeIterator for ValuesMut<'_, K, V> {}

impl<K: Clone, V: Clone> FusedIterator for ValuesMut<'_, K, V> {}

/// The entries of a [`PersistentMap`] within a key range, in order.
pub struct Range<'a, K, V> {
    inner: RangeForm<'a, K, V>,
}

enum RangeForm<'a, K, V> {
    Empty,
    Small(btree_map::Range<'a, K, Arc<V>>),
    Large(im::ordmap::Iter<'a, K, Arc<V>>),
}

impl<'a, K: Ord, V> Iterator for Range<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let next = match &mut self.inner {
            RangeForm::Empty => None,
            RangeForm::Small(range) => range.next(),
            RangeForm::Large(range) => range.next(),
        };
        next.map(|(key, value)| (key, &**value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // im's range iterator counts the whole map, so only the upper
        // bound holds.
        let upper = match &self.inner {
            RangeForm::Empty => Some(0),
            RangeForm::Small(range) => range.size_hint().1,
            RangeForm::Large(range) => range.size_hint().1,
        };
        (0, upper)
    }
}

impl<K: Ord, V> DoubleEndedIterator for Range<'_, K, V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let next = match &mut self.inner {
            RangeForm::Empty => None,
            RangeForm::Small(range) => range.next_back(),
            RangeForm::Large(range) => range.next_back(),
        };
        next.map(|(key, value)| (key, &**value))
    }
}

impl<K: Ord, V> FusedIterator for Range<'_, K, V> {}

/// The entries of a [`PersistentMap`] by value, in key order.
pub type IntoIter<K, V> = std::vec::IntoIter<(K, V)>;

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
