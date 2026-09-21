//! Reserved board claim shape shared by admission and history reconstruction.

use super::types::BoardSelection;
use crate::EntityId;
use crate::claim::{ClaimBody, ClaimSubject};
use crate::error::{Error, Result};
use crate::vault::RevisionRef;
use rmpv::Value;
use std::collections::BTreeSet;

pub(super) const PREDICATES: [&str; 5] = [
    "world_access.allowed",
    "world_access.default_on",
    "world_access.active",
    "activated.pinned",
    "activated.top_snippet",
];

pub(super) fn sets(selection: &BoardSelection) -> [&BTreeSet<EntityId>; 5] {
    [
        &selection.allowed,
        &selection.default_on,
        &selection.active,
        &selection.pinned,
        &selection.top_snippet,
    ]
}

pub(super) fn value(items: &BTreeSet<EntityId>, anchor: RevisionRef) -> Value {
    Value::Map(vec![
        (
            Value::from("items"),
            Value::Array(
                items
                    .iter()
                    .map(|id| Value::Binary(id.as_bytes().to_vec()))
                    .collect(),
            ),
        ),
        (
            Value::from("source_revision_ref"),
            Value::Binary(anchor.0.to_vec()),
        ),
    ])
}

pub(super) fn decode_value(value: &Value) -> Result<(BTreeSet<EntityId>, RevisionRef)> {
    let Value::Map(fields) = value else {
        return Err(Error::InvalidClaimBody("board claim value must be a map"));
    };
    if fields.len() != 2 {
        return Err(Error::InvalidClaimBody("board claim field count"));
    }
    let mut items = None;
    let mut anchor = None;
    for (key, value) in fields {
        match (key.as_str(), value) {
            (Some("items"), Value::Array(values)) if items.is_none() => {
                let mut set = BTreeSet::new();
                for value in values {
                    let Value::Binary(bytes) = value else {
                        return Err(Error::InvalidClaimBody(
                            "board item must be an entity reference",
                        ));
                    };
                    let bytes = bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::InvalidClaimBody("board item reference length"))?;
                    let id = EntityId::from_bytes(bytes)
                        .map_err(|_| Error::InvalidClaimBody("board item reference"))?;
                    if !set.insert(id) {
                        return Err(Error::InvalidClaimBody("duplicate board item"));
                    }
                }
                items = Some(set);
            }
            (Some("source_revision_ref"), Value::Binary(bytes)) if anchor.is_none() => {
                anchor = Some(RevisionRef(bytes.as_slice().try_into().map_err(|_| {
                    Error::InvalidClaimBody("board frontier reference length")
                })?));
            }
            _ => return Err(Error::InvalidClaimBody("invalid board claim field")),
        }
    }
    Ok((
        items.ok_or(Error::InvalidClaimBody("board items missing"))?,
        anchor.ok_or(Error::InvalidClaimBody("board frontier missing"))?,
    ))
}

pub(crate) fn validate_board_claim(body: &ClaimBody) -> Result<()> {
    if !PREDICATES.contains(&body.predicate.as_str()) {
        return Err(Error::InvalidClaimBody("unknown board predicate"));
    }
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(Error::InvalidClaimBody("board subject must be an entity"));
    }
    let from = body
        .valid_from
        .ok_or(Error::InvalidClaimBody("board valid_from missing"))?;
    if body.valid_to.is_some_and(|to| to < from) {
        return Err(Error::InvalidClaimBody("board validity is inverted"));
    }
    decode_value(&body.value)?;
    Ok(())
}
