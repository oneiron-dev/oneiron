//! Frozen source data for an explicitly born, scoped touch; not write authority.

use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;

use super::{CommError, CommResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedTouchSource {
    pub world: EntityId,
    pub facet: EntityId,
    pub project: EntityId,
    pub sensitivity: u8,
    pub origin_digest: [u8; 32],
}

pub(super) fn encode_source_position(source: Option<&ScopedTouchSource>) -> Value {
    source.map_or(Value::Nil, |source| {
        Value::Array(vec![
            Value::from(source.world.to_hex()),
            Value::from(source.facet.to_hex()),
            Value::from(source.project.to_hex()),
            Value::from(source.sensitivity),
            Value::Binary(source.origin_digest.to_vec()),
        ])
    })
}

pub(super) fn decode_source_position(value: &Value) -> CommResult<Option<ScopedTouchSource>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    let Value::Array(fields) = value else {
        return Err(CommError::InvalidRecord);
    };
    let [world, facet, project, sensitivity, digest] = fields.as_slice() else {
        return Err(CommError::InvalidRecord);
    };
    let id = |value: &Value| {
        value
            .as_str()
            .and_then(|text| EntityId::from_hex(text).ok())
            .ok_or(CommError::InvalidRecord)
    };
    let sensitivity = sensitivity
        .as_u64()
        .filter(|band| *band <= 3)
        .ok_or(CommError::InvalidRecord)? as u8;
    let Value::Binary(digest) = digest else {
        return Err(CommError::InvalidRecord);
    };
    let origin_digest = digest
        .as_slice()
        .try_into()
        .map_err(|_| CommError::InvalidRecord)?;
    Ok(Some(ScopedTouchSource {
        world: id(world)?,
        facet: id(facet)?,
        project: id(project)?,
        sensitivity,
        origin_digest,
    }))
}
