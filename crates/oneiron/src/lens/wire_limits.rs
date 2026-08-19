//! Generic serde plumbing shared by every lens wire type: bounded-collection
//! deserialization against the [`MAX_LENS_COLLECTION_ITEMS`] budget, and the
//! externally-tagged map serializer the hand-rolled `Serialize` impls use.

use std::{fmt, marker::PhantomData};

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
        reject_lens_sequence_hint(seq.size_hint())?;
        let mut values = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(16));
        while let Some(value) = seq.next_element::<T>()? {
            if values.len() >= MAX_LENS_COLLECTION_ITEMS {
                return Err(max_lens_collection_items_error());
            }
            values.push(value);
        }
        Ok(values)
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

pub(super) fn reject_lens_sequence_hint<E>(size_hint: Option<usize>) -> std::result::Result<(), E>
where
    E: de::Error,
{
    if size_hint.is_some_and(|len| len > MAX_LENS_COLLECTION_ITEMS) {
        return Err(max_lens_collection_items_error());
    }
    Ok(())
}

pub(super) fn max_lens_collection_items_error<E>() -> E
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
