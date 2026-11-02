//! CLAIM relationship scope sets (ARCH-0022): the relationship key holds
//! everything (`all`), a set of RELATIONSHIP ids, or nothing (the empty set).
//! Each is an act the writer performed, so the three stay distinct in
//! storage, reads, consolidation identity and signed transcripts.

use std::collections::BTreeSet;

use rmpv::Value;

use crate::claim::scope_stamp;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};

/// A claim's relationship key. `None` is the stamped `all`; `Some(empty)` is
/// the explicit empty set; `Some(ids)` is the ordered, de-duplicated set.
pub type RelationshipScope = Option<BTreeSet<EntityId>>;

/// The singleton scope for one relationship id; `None` stays `all`.
#[must_use]
pub fn relationship_scope_of(id: Option<EntityId>) -> RelationshipScope {
    id.map(|id| BTreeSet::from([id]))
}

/// Whether a claim keyed to `rel` is in scope for the active relationship:
/// the key is `all`, or the set holds the relationship. The empty set holds
/// no relationship.
#[must_use]
pub fn relationship_scope_includes(rel: Option<&BTreeSet<EntityId>>, active: EntityId) -> bool {
    rel.is_none_or(|ids| ids.contains(&active))
}

/// The meet of two exposure scopes: `all` is the identity and finite sets
/// intersect, so the result never reaches a relationship either side lacks.
#[must_use]
pub fn meet_relationship_scopes(
    left: Option<&BTreeSet<EntityId>>,
    right: Option<&BTreeSet<EntityId>>,
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
pub fn relationship_scope_transcript(rel: Option<&BTreeSet<EntityId>>) -> Vec<u8> {
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
pub(crate) fn encode_relationship_scope(rel: Option<&BTreeSet<EntityId>>) -> Value {
    rel.map_or_else(
        || Value::from("all"),
        |ids| Value::Array(ids.iter().map(|id| scope_stamp::id_value(*id)).collect()),
    )
}

/// Decode `scopeRelationshipId`: `all`, or an array of 16-byte ids of any
/// length, `[]` included.
pub(crate) fn decode_relationship_scope(value: &Value) -> Result<RelationshipScope> {
    if value.as_str() == Some("all") {
        return Ok(None);
    }
    let Value::Array(ids) = value else {
        return Err(Error::InvalidClaimBody("invalid relationship scope"));
    };
    ids.iter()
        .map(scope_stamp::scope_id)
        .collect::<Result<BTreeSet<_>>>()
        .map(Some)
}
