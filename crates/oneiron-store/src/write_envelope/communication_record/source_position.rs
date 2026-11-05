//! Frozen source data for an explicitly born, scoped touch; not write authority.

use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;

use super::{CommError, CommResult};

/// The exact native scope shape frozen for a born touch comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ScopedTouchScopeForm {
    Numeric = 0,
    Public = 1,
    Private = 2,
    Internal = 3,
    Sensitive = 4,
    Restricted = 5,
    Unstamped = 6,
    Empty = 7,
}

impl ScopedTouchScopeForm {
    pub fn from_scope(scope: Option<&Value>) -> Option<Self> {
        let Some(scope) = scope else {
            return Some(Self::Unstamped);
        };
        let Value::Map(entries) = scope else {
            return None;
        };
        let [(key, value)] = entries.as_slice() else {
            return entries.is_empty().then_some(Self::Empty);
        };
        if key.as_str() != Some("sensitivity") {
            return None;
        }
        if value.as_u64().is_some() {
            return Some(Self::Numeric);
        }
        match value.as_str()? {
            "public" => Some(Self::Public),
            "private" => Some(Self::Private),
            "internal" => Some(Self::Internal),
            "sensitive" => Some(Self::Sensitive),
            "restricted" => Some(Self::Restricted),
            _ => None,
        }
    }

    pub fn scope(self, sensitivity: u8) -> CommResult<Option<Value>> {
        if sensitivity > 3 {
            return Err(CommError::InvalidRecord);
        }
        let value = match self {
            Self::Numeric => Value::from(u64::from(sensitivity)),
            Self::Public => Value::from("public"),
            Self::Private => Value::from("private"),
            Self::Internal => Value::from("internal"),
            Self::Sensitive => Value::from("sensitive"),
            Self::Restricted => Value::from("restricted"),
            Self::Unstamped | Self::Empty => {
                if sensitivity != super::super::claim_body::UNSTAMPED_CLAIM_SENSITIVITY_BAND {
                    return Err(CommError::InvalidRecord);
                }
                return Ok(if self == Self::Unstamped {
                    None
                } else {
                    Some(Value::Map(Vec::new()))
                });
            }
        };
        if super::super::claim_body::sensitivity_band_from_value(&value) != Some(sensitivity) {
            return Err(CommError::InvalidRecord);
        }
        Ok(Some(Value::Map(vec![(Value::from("sensitivity"), value)])))
    }

    fn from_wire(value: &Value) -> CommResult<Self> {
        match value.as_u64() {
            Some(0) => Ok(Self::Numeric),
            Some(1) => Ok(Self::Public),
            Some(2) => Ok(Self::Private),
            Some(3) => Ok(Self::Internal),
            Some(4) => Ok(Self::Sensitive),
            Some(5) => Ok(Self::Restricted),
            Some(6) => Ok(Self::Unstamped),
            Some(7) => Ok(Self::Empty),
            _ => Err(CommError::InvalidRecord),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedTouchSource {
    pub world: EntityId,
    pub facet: EntityId,
    pub project: EntityId,
    pub sensitivity: u8,
    pub scope_form: ScopedTouchScopeForm,
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
            Value::from(source.scope_form as u8),
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
    let [world, facet, project, sensitivity, digest, scope_form] = fields.as_slice() else {
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
    let scope_form = ScopedTouchScopeForm::from_wire(scope_form)?;
    scope_form.scope(sensitivity)?;
    Ok(Some(ScopedTouchSource {
        world: id(world)?,
        facet: id(facet)?,
        project: id(project)?,
        sensitivity,
        scope_form,
        origin_digest,
    }))
}
