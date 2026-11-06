//! Frozen source data for an explicitly born, scoped touch; not write authority.

use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;

use super::super::claim_body::{
    RelationshipScope, decode_relationship_scope, encode_relationship_scope,
};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopedTouchPrincipal {
    pub id: EntityId,
    pub index: u8,
}

impl ScopedTouchScopeForm {
    pub fn from_scope(scope: Option<&Value>) -> Option<(Self, Option<ScopedTouchPrincipal>)> {
        let Some(scope) = scope else {
            return Some((Self::Unstamped, None));
        };
        let Value::Map(entries) = scope else {
            return None;
        };
        let mut sensitivity = None;
        let mut principal = None;
        for (index, (key, value)) in entries.iter().enumerate() {
            match key.as_str()? {
                "sensitivity" if sensitivity.is_none() => sensitivity = Some(value),
                "principal" if principal.is_none() => {
                    let Value::Binary(bytes) = value else {
                        return None;
                    };
                    principal = Some(ScopedTouchPrincipal {
                        id: EntityId::from_bytes(bytes.as_slice().try_into().ok()?).ok()?,
                        index: index.try_into().ok()?,
                    });
                }
                _ => return None,
            }
        }
        let Some(value) = sensitivity else {
            return Some((Self::Empty, principal));
        };
        let form = if value.as_u64().is_some() {
            Self::Numeric
        } else {
            match value.as_str()? {
                "public" => Self::Public,
                "private" => Self::Private,
                "internal" => Self::Internal,
                "sensitive" => Self::Sensitive,
                "restricted" => Self::Restricted,
                _ => return None,
            }
        };
        Some((form, principal))
    }

    pub fn scope(
        self,
        sensitivity: u8,
        principal: Option<&ScopedTouchPrincipal>,
    ) -> CommResult<Option<Value>> {
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
            Self::Unstamped | Self::Empty => Value::Nil,
        };
        let mut scope = if matches!(self, Self::Unstamped | Self::Empty) {
            if sensitivity != super::super::claim_body::UNSTAMPED_CLAIM_SENSITIVITY_BAND {
                return Err(CommError::InvalidRecord);
            }
            if self == Self::Unstamped {
                None
            } else {
                Some(Value::Map(Vec::new()))
            }
        } else {
            if super::super::claim_body::sensitivity_band_from_value(&value) != Some(sensitivity) {
                return Err(CommError::InvalidRecord);
            }
            Some(Value::Map(vec![(Value::from("sensitivity"), value)]))
        };
        if let Some(principal) = principal {
            let Some(Value::Map(entries)) = &mut scope else {
                return Err(CommError::InvalidRecord);
            };
            let index = usize::from(principal.index);
            if index > entries.len() {
                return Err(CommError::InvalidRecord);
            }
            entries.insert(
                index,
                (
                    Value::from("principal"),
                    Value::Binary(principal.id.as_bytes().to_vec()),
                ),
            );
        }
        Ok(scope)
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
    pub rel: RelationshipScope,
    pub session_tag: Option<String>,
    pub principal: Option<ScopedTouchPrincipal>,
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
            encode_relationship_scope(source.rel.as_ref()),
            source
                .session_tag
                .as_deref()
                .map_or(Value::Nil, Value::from),
            source.principal.as_ref().map_or(Value::Nil, |principal| {
                Value::Array(vec![
                    Value::from(principal.index),
                    Value::Binary(principal.id.as_bytes().to_vec()),
                ])
            }),
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
    let [
        world,
        facet,
        project,
        sensitivity,
        digest,
        scope_form,
        rel,
        session_tag,
        principal,
    ] = fields.as_slice()
    else {
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
    let principal = match principal {
        Value::Nil => None,
        Value::Array(fields) => {
            let [index, Value::Binary(bytes)] = fields.as_slice() else {
                return Err(CommError::InvalidRecord);
            };
            let index = index
                .as_u64()
                .filter(|index| *index <= 1)
                .ok_or(CommError::InvalidRecord)? as u8;
            let id = EntityId::from_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| CommError::InvalidRecord)?,
            )
            .map_err(|_| CommError::InvalidRecord)?;
            Some(ScopedTouchPrincipal { id, index })
        }
        _ => return Err(CommError::InvalidRecord),
    };
    let _ = scope_form.scope(sensitivity, principal.as_ref())?;
    let rel = decode_relationship_scope(rel).map_err(|_| CommError::InvalidRecord)?;
    let session_tag = match session_tag {
        Value::Nil => None,
        value => {
            let tag = value.as_str().ok_or(CommError::InvalidRecord)?;
            super::super::claim_predicate::validate_session_tag(tag)
                .map_err(|_| CommError::InvalidRecord)?;
            Some(tag.to_owned())
        }
    };
    Ok(Some(ScopedTouchSource {
        world: id(world)?,
        facet: id(facet)?,
        project: id(project)?,
        sensitivity,
        scope_form,
        rel,
        session_tag,
        principal,
        origin_digest,
    }))
}
