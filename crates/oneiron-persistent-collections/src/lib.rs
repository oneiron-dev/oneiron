//! Ordered maps and sets whose clones share structure.
//!
//! A fold keeps one state per log row, and a row's state starts as a clone
//! of its parent's. With `BTreeMap` and `BTreeSet` every clone copies every
//! entry, so a chain of n rows holds n(n+1)/2 entries. [`PersistentMap`] and
//! [`PersistentSet`] clone in O(1) and copy only what a write touches.
//!
//! Each holds one of three forms, never visible through the API:
//! - empty: no allocation;
//! - small (at most [`SMALL_LIMIT`] entries after a write): an
//!   `Arc<BTreeMap>` / `Arc<BTreeSet>`, copied whole on the first write after
//!   a clone, about the size of one im leaf;
//! - large: an `im::OrdMap` / `im::OrdSet`, which copies only the nodes on a
//!   written key's path.
//!
//! What the API shows is the entries' alone: iteration is in key order, and
//! equality, ordering, hashing, `Debug` and serde are the ones `BTreeMap` and
//! `BTreeSet` give for the same entries. Serialize writes the same calls
//! (`serialize_map` / `serialize_seq` with the exact length, entries in key
//! order), so every encoder writes the same bytes; Deserialize reads through
//! `BTreeMap` / `BTreeSet`, so a repeated key keeps its last value, as there.
//!
//! A map holds each value behind an `Arc`, so a copied node copies pointers,
//! not values; `get_mut` and the entry API copy a shared value on write.
//! `insert` skips a write whose stored value is already equal, so re-inserting
//! an unchanged entry copies nothing; `PersistentMap::modify` and
//! `PersistentMap::modify_or_default` change a copy of a value and store it
//! the same way, for merges that leave most values as they were.

mod map;
mod set;

pub use map::{
    Entry, IntoIter, Iter, IterMut, Keys, OccupiedEntry, PersistentMap, Range, VacantEntry, Values,
    ValuesMut,
};
pub use set::{PersistentSet, SetIntoIter, SetIter, SetRange};

/// The most entries a small form holds after a write; one more moves the
/// collection to its large form.
pub const SMALL_LIMIT: usize = 64;

/// A large form that shrinks to this many entries moves back to the small
/// form, so a collection that hovers at the limit does not switch forms on
/// every write.
const SHRINK_LIMIT: usize = SMALL_LIMIT / 2;

#[cfg(test)]
mod tests;
