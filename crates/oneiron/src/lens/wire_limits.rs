//! Generic serde plumbing shared by every lens wire type: bounded-collection
//! deserialization against the [`MAX_LENS_COLLECTION_ITEMS`] budget, and the
//! externally-tagged map serializer the hand-rolled `Serialize` impls use.

use std::{cell::Cell, convert::Infallible, fmt, marker::PhantomData};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer, de, de::DeserializeSeed, ser::SerializeMap,
};

use super::wire_ids::MAX_LENS_COLLECTION_ITEMS;

pub(super) struct LimitedVecSeed<T> {
    pub(super) _marker: PhantomData<T>,
}

impl<'de, T> de::DeserializeSeed<'de> for LimitedVecSeed<T>
where
    T: Deserialize<'de>,
{
    type Value = Vec<T>;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(LimitedVecVisitor::<T> {
            _marker: PhantomData,
        })
    }
}

struct LimitedVecVisitor<T> {
    _marker: PhantomData<T>,
}

impl<'de, T> de::Visitor<'de> for LimitedVecVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded lens collection")
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        next_bounded_lens_entries(seq, || PhantomData::<T>)
    }
}

thread_local! {
    /// Collection entries the lens tree being decoded on this thread may still admit;
    /// `None` outside a tree decode.
    static LENS_TREE_ENTRIES_LEFT: Cell<Option<usize>> = const { Cell::new(None) };
}

/// Runs a lens tree decode under one shared entry budget: every child, binding and
/// atom collection entry of the tree is charged against the
/// [`MAX_LENS_COLLECTION_ITEMS`] total that `validate_lens_tree` checks once the tree
/// is built, so an over-budget tree is refused at its first excess entry instead.
/// A decode nested in a tree keeps charging the outer tree's budget.
pub(super) fn with_lens_tree_budget<T>(decode: impl FnOnce() -> T) -> T {
    struct EndTree;
    impl Drop for EndTree {
        fn drop(&mut self) {
            LENS_TREE_ENTRIES_LEFT.with(|left| left.set(None));
        }
    }

    let nested = LENS_TREE_ENTRIES_LEFT.with(|left| {
        let nested = left.get().is_some();
        if !nested {
            left.set(Some(MAX_LENS_COLLECTION_ITEMS));
        }
        nested
    });
    if nested {
        return decode();
    }
    let _end = EndTree;
    decode()
}

fn take_lens_tree_entry() -> bool {
    LENS_TREE_ENTRIES_LEFT.with(|left| match left.get() {
        None => true,
        Some(0) => false,
        Some(remaining) => {
            left.set(Some(remaining - 1));
            true
        }
    })
}

fn return_lens_tree_entry() {
    LENS_TREE_ENTRIES_LEFT.with(|left| {
        if let Some(remaining) = left.get() {
            left.set(Some(remaining + 1));
        }
    });
}

/// Pulls one bounded lens collection: at most [`MAX_LENS_COLLECTION_ITEMS`] entries,
/// each charged to the active tree budget before it is decoded. Past either bound the
/// next entry meets a seed that refuses it unread, so an excess entry (for children,
/// a whole subtree) is never built.
pub(super) fn next_bounded_lens_entries<'de, A, S>(
    mut seq: A,
    mut seed: impl FnMut() -> S,
) -> std::result::Result<Vec<S::Value>, A::Error>
where
    A: de::SeqAccess<'de>,
    S: DeserializeSeed<'de>,
{
    reject_lens_sequence_hint(seq.size_hint())?;
    let mut values = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(16));
    loop {
        let refusal = if values.len() >= MAX_LENS_COLLECTION_ITEMS {
            Some(RefuseLensEntry { tree_budget: false })
        } else if !take_lens_tree_entry() {
            Some(RefuseLensEntry { tree_budget: true })
        } else {
            None
        };
        if let Some(refusal) = refusal {
            return match seq.next_element_seed(refusal)? {
                None => Ok(values),
                Some(never) => match never {},
            };
        }
        match seq.next_element_seed(seed())? {
            Some(value) => values.push(value),
            None => {
                return_lens_tree_entry();
                return Ok(values);
            }
        }
    }
}

struct RefuseLensEntry {
    tree_budget: bool,
}

impl<'de> DeserializeSeed<'de> for RefuseLensEntry {
    type Value = Infallible;

    fn deserialize<D>(self, _deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.tree_budget {
            return Err(de::Error::custom(format!(
                "generated lens collections must contain at most {MAX_LENS_COLLECTION_ITEMS} total items"
            )));
        }
        Err(max_lens_collection_items_error())
    }
}

pub(super) fn deserialize_limited_vec<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    LimitedVecSeed::<T> {
        _marker: PhantomData,
    }
    .deserialize(deserializer)
}

fn reject_lens_sequence_hint<E>(size_hint: Option<usize>) -> std::result::Result<(), E>
where
    E: de::Error,
{
    if size_hint.is_some_and(|len| len > MAX_LENS_COLLECTION_ITEMS) {
        return Err(max_lens_collection_items_error());
    }
    Ok(())
}

fn max_lens_collection_items_error<E>() -> E
where
    E: de::Error,
{
    de::Error::custom(format!(
        "lens collection must contain at most {MAX_LENS_COLLECTION_ITEMS} items"
    ))
}

pub(super) fn serialize_tagged<S, T>(
    serializer: S,
    tag_field: &'static str,
    tag: &'static str,
    content_field: &'static str,
    content: &T,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize + ?Sized,
{
    let mut map = serializer.serialize_map(Some(2))?;
    map.serialize_entry(tag_field, tag)?;
    map.serialize_entry(content_field, content)?;
    map.end()
}
