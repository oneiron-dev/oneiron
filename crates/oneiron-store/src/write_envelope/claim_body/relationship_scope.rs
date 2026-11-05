//! CLAIM relationship scope sets (ARCH-0022): the relationship key holds
//! everything (`all`), a set of RELATIONSHIP ids, or nothing (the empty set).
//! Each is an act the writer performed, so the three stay distinct in
//! storage, reads, consolidation identity and signed transcripts.

use rmpv::Value;

use super::scope_stamp;
use oneiron_contracts::entity_id::{ENTITY_ID_LEN, EntityId};
use oneiron_contracts::error::{Error, Result};

/// A finite relationship scope in canonical EntityId order.
///
/// Every constructor and deserializer sorts and de-duplicates the private
/// backing storage. Read-only access cannot change canonical identity.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelationshipSet {
    ids: Vec<EntityId>,
}

impl RelationshipSet {
    fn canonicalize(mut ids: Vec<EntityId>) -> Self {
        ids.sort_unstable();
        ids.dedup();
        Self { ids }
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, EntityId> {
        self.ids.iter()
    }

    pub fn contains(&self, id: &EntityId) -> bool {
        self.ids.binary_search(id).is_ok()
    }

    pub fn intersection<'a>(&'a self, other: &'a Self) -> impl Iterator<Item = &'a EntityId> {
        self.iter().filter(move |id| other.contains(id))
    }
}

impl FromIterator<EntityId> for RelationshipSet {
    fn from_iter<T: IntoIterator<Item = EntityId>>(iter: T) -> Self {
        Self::canonicalize(iter.into_iter().collect())
    }
}

impl<const N: usize> From<[EntityId; N]> for RelationshipSet {
    fn from(ids: [EntityId; N]) -> Self {
        Self::canonicalize(Vec::from(ids))
    }
}

impl IntoIterator for RelationshipSet {
    type Item = EntityId;
    type IntoIter = std::vec::IntoIter<EntityId>;

    fn into_iter(self) -> Self::IntoIter {
        self.ids.into_iter()
    }
}

impl<'a> IntoIterator for &'a RelationshipSet {
    type Item = &'a EntityId;
    type IntoIter = std::slice::Iter<'a, EntityId>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl serde::Serialize for RelationshipSet {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&self.ids, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for RelationshipSet {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let ids = <Vec<EntityId> as serde::Deserialize>::deserialize(deserializer)?;
        Ok(Self::canonicalize(ids))
    }
}

/// A claim's relationship key. `None` is the stamped `all`; `Some(empty)` is
/// the explicit empty set; `Some(ids)` is the ordered, de-duplicated set.
pub type RelationshipScope = Option<RelationshipSet>;

/// The singleton scope for one relationship id; `None` stays `all`.
#[must_use]
pub fn relationship_scope_of(id: Option<EntityId>) -> RelationshipScope {
    id.map(|id| RelationshipSet::from([id]))
}

/// Whether a claim keyed to `rel` is in scope for the active relationship:
/// the key is `all`, or the set holds the relationship. The empty set holds
/// no relationship.
#[must_use]
pub fn relationship_scope_includes(rel: Option<&RelationshipSet>, active: EntityId) -> bool {
    rel.is_none_or(|ids| ids.contains(&active))
}

/// The meet of two exposure scopes: `all` is the identity and finite sets
/// intersect, so the result never reaches a relationship either side lacks.
#[must_use]
pub fn meet_relationship_scopes(
    left: Option<&RelationshipSet>,
    right: Option<&RelationshipSet>,
) -> RelationshipScope {
    match (left, right) {
        (None, None) => None,
        (Some(ids), None) | (None, Some(ids)) => Some(ids.clone()),
        (Some(left), Some(right)) => Some(left.intersection(right).copied().collect()),
    }
}

/// Unambiguous identity bytes for hashes and signed transcripts: tag `0` for
/// `all`, or tag `1`, the member count as a big-endian u64, then each id's 16
/// raw bytes in set order. The count is a structural length, not a cap.
#[must_use]
pub fn relationship_scope_transcript(rel: Option<&RelationshipSet>) -> Vec<u8> {
    let Some(ids) = rel else {
        return vec![0];
    };
    let mut out = Vec::with_capacity(1 + 8 + ids.len() * ENTITY_ID_LEN);
    out.push(1);
    out.extend_from_slice(&(ids.len() as u64).to_be_bytes());
    for id in ids {
        out.extend_from_slice(id.as_bytes());
    }
    out
}

/// The on-disk `scopeRelationshipId` value: `all`, or an array of every id
/// in set order (`[]` for the empty set).
pub fn encode_relationship_scope(rel: Option<&RelationshipSet>) -> Value {
    rel.map_or_else(
        || Value::from("all"),
        |ids| Value::Array(ids.iter().map(|id| scope_stamp::id_value(*id)).collect()),
    )
}

/// Decode `scopeRelationshipId`: `all`, or an array of 16-byte ids of any
/// length, `[]` included.
pub fn decode_relationship_scope(value: &Value) -> Result<RelationshipScope> {
    if value.as_str() == Some("all") {
        return Ok(None);
    }
    let Value::Array(ids) = value else {
        return Err(Error::InvalidClaimBody("invalid relationship scope"));
    };
    ids.iter()
        .map(scope_stamp::scope_id)
        .collect::<Result<RelationshipSet>>()
        .map(Some)
}
