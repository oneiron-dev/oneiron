//! Generic serde plumbing shared by the hand-rolled lens wire types: the
//! externally-tagged map serializer their `Serialize` impls use. Lens
//! collections decode whole, at any length (FIX 9900).

use serde::{Serialize, Serializer, ser::SerializeMap};

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
