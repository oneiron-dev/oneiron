//! [`PersistentSet`]: an ordered set whose clones share structure.

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::{BTreeSet, btree_set};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::iter::{FusedIterator, Peekable};
use std::ops::{Bound, RangeBounds};
use std::sync::Arc;

use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};

use crate::{SHRINK_LIMIT, SMALL_LIMIT};

/// An ordered set with `BTreeSet`'s order, equality and serde bytes, whose
/// clones share structure (see the crate docs).
pub struct PersistentSet<T> {
    form: Form<T>,
}

enum Form<T> {
    Empty,
    Small(Arc<BTreeSet<T>>),
    Large(im::OrdSet<T>),
}

impl<T> PersistentSet<T> {
    /// An empty set. Allocates nothing.
    pub const fn new() -> Self {
        Self { form: Form::Empty }
    }
}

#[cfg(test)]
impl<T> PersistentSet<T> {
    /// The form's name, for the tests.
    pub(crate) fn form_name(&self) -> &'static str {
        match self.form {
            Form::Empty => "empty",
            Form::Small(_) => "small",
            Form::Large(_) => "large",
        }
    }
}

impl<T> Default for PersistentSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Clone for PersistentSet<T> {
    /// O(1): the clone shares every member until one side writes.
    fn clone(&self) -> Self {
        let form = match &self.form {
            Form::Empty => Form::Empty,
            Form::Small(set) => Form::Small(Arc::clone(set)),
            Form::Large(set) => Form::Large(set.clone()),
        };
        Self { form }
    }
}

impl<T: Ord + Clone> PersistentSet<T> {
    pub fn len(&self) -> usize {
        match &self.form {
            Form::Empty => 0,
            Form::Small(set) => set.len(),
            Form::Large(set) => set.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains<Q>(&self, value: &Q) -> bool
    where
        T: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        match &self.form {
            Form::Empty => false,
            Form::Small(set) => set.contains(value),
            Form::Large(set) => set.contains(value),
        }
    }

    pub fn get<Q>(&self, value: &Q) -> Option<&T>
    where
        T: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        match &self.form {
            Form::Empty => None,
            Form::Small(set) => set.get(value),
            Form::Large(set) => set
                .range::<_, Q>((Bound::Included(value), Bound::Included(value)))
                .next(),
        }
    }

    /// As `BTreeSet::insert`; a member already held is not written, so it
    /// copies nothing.
    pub fn insert(&mut self, value: T) -> bool {
        if self.contains(&value) {
            return false;
        }
        if let Form::Empty = self.form {
            self.form = Form::Small(Arc::new(BTreeSet::from([value])));
            return true;
        }
        match &mut self.form {
            Form::Empty => {}
            Form::Small(set) => {
                Arc::make_mut(set).insert(value);
            }
            Form::Large(set) => {
                set.insert(value);
            }
        }
        self.fit_form();
        true
    }

    pub fn remove<Q>(&mut self, value: &Q) -> bool
    where
        T: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.take(value).is_some()
    }

    pub fn take<Q>(&mut self, value: &Q) -> Option<T>
    where
        T: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        if !self.contains(value) {
            return None;
        }
        let taken = match &mut self.form {
            Form::Empty => None,
            Form::Small(set) => Arc::make_mut(set).take(value),
            Form::Large(set) => set.remove(value),
        };
        self.fit_form();
        taken
    }

    /// Keeps the members `keep` accepts. Only a removal writes.
    pub fn retain<F>(&mut self, mut keep: F)
    where
        F: FnMut(&T) -> bool,
    {
        let dropped: Vec<T> = self.iter().filter(|value| !keep(value)).cloned().collect();
        if dropped.is_empty() {
            return;
        }
        match &mut self.form {
            Form::Empty => {}
            Form::Small(set) => {
                let set = Arc::make_mut(set);
                for value in &dropped {
                    set.remove(value);
                }
            }
            Form::Large(set) => {
                for value in &dropped {
                    set.remove(value);
                }
            }
        }
        self.fit_form();
    }

    pub fn clear(&mut self) {
        self.form = Form::Empty;
    }

    pub fn iter(&self) -> SetIter<'_, T> {
        let remaining = self.len();
        let inner = match &self.form {
            Form::Empty => SetIterForm::Empty,
            Form::Small(set) => SetIterForm::Small(set.iter()),
            Form::Large(set) => SetIterForm::Large(set.iter()),
        };
        SetIter { inner, remaining }
    }

    pub fn range<Q, R>(&self, range: R) -> SetRange<'_, T>
    where
        T: Borrow<Q>,
        Q: Ord + ?Sized,
        R: RangeBounds<Q>,
    {
        let inner = match &self.form {
            Form::Empty => SetRangeForm::Empty,
            Form::Small(set) => SetRangeForm::Small(set.range(range)),
            Form::Large(set) => SetRangeForm::Large(set.range(range)),
        };
        SetRange { inner }
    }

    pub fn first(&self) -> Option<&T> {
        match &self.form {
            Form::Empty => None,
            Form::Small(set) => set.first(),
            Form::Large(set) => set.get_min(),
        }
    }

    pub fn last(&self) -> Option<&T> {
        match &self.form {
            Form::Empty => None,
            Form::Small(set) => set.last(),
            Form::Large(set) => set.get_max(),
        }
    }

    pub fn pop_first(&mut self) -> Option<T> {
        let value = self.first()?.clone();
        self.take(&value)
    }

    pub fn pop_last(&mut self) -> Option<T> {
        let value = self.last()?.clone();
        self.take(&value)
    }

    pub fn is_disjoint(&self, other: &Self) -> bool {
        let (fewer, more) = if self.len() <= other.len() {
            (self, other)
        } else {
            (other, self)
        };
        !fewer.iter().any(|value| more.contains(value))
    }

    pub fn is_subset(&self, other: &Self) -> bool {
        self.len() <= other.len() && self.iter().all(|value| other.contains(value))
    }

    pub fn is_superset(&self, other: &Self) -> bool {
        other.is_subset(self)
    }

    /// The members of either set, in order, each once.
    pub fn union<'a>(&'a self, other: &'a Self) -> impl Iterator<Item = &'a T> + 'a {
        SetUnion {
            left: self.iter().peekable(),
            right: other.iter().peekable(),
        }
    }

    /// The members of both sets, in order.
    pub fn intersection<'a>(&'a self, other: &'a Self) -> impl Iterator<Item = &'a T> + 'a {
        self.iter().filter(move |value| other.contains(*value))
    }

    /// The members of `self` that `other` lacks, in order.
    pub fn difference<'a>(&'a self, other: &'a Self) -> impl Iterator<Item = &'a T> + 'a {
        self.iter().filter(move |value| !other.contains(*value))
    }

    /// The members as a `BTreeSet` (each cloned).
    pub fn to_btree_set(&self) -> BTreeSet<T> {
        self.iter().cloned().collect()
    }

    /// Whether both sets share one root, so that they are equal without a
    /// walk. False says nothing.
    pub fn ptr_eq(&self, other: &Self) -> bool {
        match (&self.form, &other.form) {
            (Form::Empty, Form::Empty) => true,
            (Form::Small(left), Form::Small(right)) => Arc::ptr_eq(left, right),
            (Form::Large(left), Form::Large(right)) => left.ptr_eq(right),
            _ => false,
        }
    }

    /// Moves to the form the length asks for: empty at 0, large past
    /// `SMALL_LIMIT`, small again at `SHRINK_LIMIT` or fewer.
    fn fit_form(&mut self) {
        let len = self.len();
        let fitted = match &self.form {
            Form::Empty => return,
            _ if len == 0 => Form::Empty,
            Form::Small(set) if len > SMALL_LIMIT => {
                Form::Large(set.iter().cloned().collect::<im::OrdSet<T>>())
            }
            Form::Large(set) if len <= SHRINK_LIMIT => {
                Form::Small(Arc::new(set.iter().cloned().collect::<BTreeSet<T>>()))
            }
            Form::Small(_) | Form::Large(_) => return,
        };
        self.form = fitted;
    }
}

/// The members of a [`PersistentSet`] in order.
pub struct SetIter<'a, T> {
    inner: SetIterForm<'a, T>,
    remaining: usize,
}

enum SetIterForm<'a, T> {
    Empty,
    Small(btree_set::Iter<'a, T>),
    Large(im::ordset::Iter<'a, T>),
}

impl<'a, T: Ord + Clone> Iterator for SetIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        let next = match &mut self.inner {
            SetIterForm::Empty => None,
            SetIterForm::Small(iter) => iter.next(),
            SetIterForm::Large(iter) => iter.next(),
        }?;
        self.remaining -= 1;
        Some(next)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<T: Ord + Clone> DoubleEndedIterator for SetIter<'_, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let next = match &mut self.inner {
            SetIterForm::Empty => None,
            SetIterForm::Small(iter) => iter.next_back(),
            SetIterForm::Large(iter) => iter.next_back(),
        }?;
        self.remaining -= 1;
        Some(next)
    }
}

impl<T: Ord + Clone> ExactSizeIterator for SetIter<'_, T> {}

impl<T: Ord + Clone> FusedIterator for SetIter<'_, T> {}

/// The members of a [`PersistentSet`] within a range, in order.
pub struct SetRange<'a, T> {
    inner: SetRangeForm<'a, T>,
}

enum SetRangeForm<'a, T> {
    Empty,
    Small(btree_set::Range<'a, T>),
    Large(im::ordset::RangedIter<'a, T>),
}

impl<'a, T: Ord + Clone> Iterator for SetRange<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        match &mut self.inner {
            SetRangeForm::Empty => None,
            SetRangeForm::Small(range) => range.next(),
            SetRangeForm::Large(range) => range.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // im's range iterator does not count, so only the small form's
        // upper bound holds.
        let upper = match &self.inner {
            SetRangeForm::Empty => Some(0),
            SetRangeForm::Small(range) => range.size_hint().1,
            SetRangeForm::Large(_) => None,
        };
        (0, upper)
    }
}

impl<T: Ord + Clone> DoubleEndedIterator for SetRange<'_, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            SetRangeForm::Empty => None,
            SetRangeForm::Small(range) => range.next_back(),
            SetRangeForm::Large(range) => range.next_back(),
        }
    }
}

impl<T: Ord + Clone> FusedIterator for SetRange<'_, T> {}

/// A sorted merge of two sets' members, each once.
struct SetUnion<'a, T: Ord + Clone> {
    left: Peekable<SetIter<'a, T>>,
    right: Peekable<SetIter<'a, T>>,
}

impl<'a, T: Ord + Clone> Iterator for SetUnion<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        let order = match (self.left.peek(), self.right.peek()) {
            (Some(left), Some(right)) => left.cmp(right),
            (Some(_), None) => Ordering::Less,
            (None, _) => Ordering::Greater,
        };
        match order {
            Ordering::Less => self.left.next(),
            Ordering::Greater => self.right.next(),
            Ordering::Equal => {
                self.right.next();
                self.left.next()
            }
        }
    }
}

/// The members of a [`PersistentSet`] by value, in order.
pub type SetIntoIter<T> = std::vec::IntoIter<T>;

impl<T: Ord + Clone> IntoIterator for PersistentSet<T> {
    type Item = T;
    type IntoIter = SetIntoIter<T>;

    fn into_iter(self) -> SetIntoIter<T> {
        let members: Vec<T> = match self.form {
            Form::Empty => Vec::new(),
            Form::Small(set) => Arc::unwrap_or_clone(set).into_iter().collect(),
            Form::Large(set) => set.into_iter().collect(),
        };
        members.into_iter()
    }
}

impl<'a, T: Ord + Clone> IntoIterator for &'a PersistentSet<T> {
    type Item = &'a T;
    type IntoIter = SetIter<'a, T>;

    fn into_iter(self) -> SetIter<'a, T> {
        self.iter()
    }
}

impl<T: Ord + Clone> From<BTreeSet<T>> for PersistentSet<T> {
    fn from(members: BTreeSet<T>) -> Self {
        let mut set = Self {
            form: Form::Small(Arc::new(members)),
        };
        set.fit_form();
        set
    }
}

impl<T: Ord + Clone, const N: usize> From<[T; N]> for PersistentSet<T> {
    fn from(members: [T; N]) -> Self {
        Self::from(BTreeSet::from(members))
    }
}

impl<T: Ord + Clone> FromIterator<T> for PersistentSet<T> {
    fn from_iter<I: IntoIterator<Item = T>>(members: I) -> Self {
        Self::from(members.into_iter().collect::<BTreeSet<T>>())
    }
}

impl<T: Ord + Clone> Extend<T> for PersistentSet<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, members: I) {
        for value in members {
            self.insert(value);
        }
    }
}

impl<'a, T: Ord + Copy + 'a> Extend<&'a T> for PersistentSet<T> {
    fn extend<I: IntoIterator<Item = &'a T>>(&mut self, members: I) {
        self.extend(members.into_iter().copied());
    }
}

impl<T: Ord + Clone> PartialEq for PersistentSet<T> {
    fn eq(&self, other: &Self) -> bool {
        match (&self.form, &other.form) {
            (Form::Large(left), Form::Large(right)) => left == right,
            _ => self.ptr_eq(other) || (self.len() == other.len() && self.iter().eq(other.iter())),
        }
    }
}

impl<T: Ord + Clone> Eq for PersistentSet<T> {}

impl<T: Ord + Clone> PartialOrd for PersistentSet<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Ord + Clone> Ord for PersistentSet<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.iter().cmp(other.iter())
    }
}

impl<T: Ord + Clone + Hash> Hash for PersistentSet<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_usize(self.len());
        for value in self {
            value.hash(state);
        }
    }
}

impl<T: Ord + Clone + fmt::Debug> fmt::Debug for PersistentSet<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_set().entries(self.iter()).finish()
    }
}

impl<T: Ord + Clone + Serialize> Serialize for PersistentSet<T> {
    /// The call `BTreeSet`'s impl makes, with the same exact length hint.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self)
    }
}

impl<'de, T: Ord + Clone + Deserialize<'de>> Deserialize<'de> for PersistentSet<T> {
    /// Through `BTreeSet`, so a repeated member is held once.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        BTreeSet::<T>::deserialize(deserializer).map(Self::from)
    }
}
