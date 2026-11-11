//! Typed access to the manifest's existing scoped-grant rows.
use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::Result;
use crate::gate::value_encoding::write_value;

/// A configured row, not a substitute for the owner's write credential.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyScopedGrantRow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_ref: Option<String>,
    pub effector: String,
    pub scope: crate::federation::Scope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selectors: Option<PolicyGrantValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<PolicyGrantValue>,
    pub receipt_required: bool,
}

/// A lossless JSON representation of a MessagePack value. Integer text avoids
/// SDK number rounding; float bytes preserve their width and exact bits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum PolicyGrantValue {
    Nil,
    Boolean(bool),
    Integer(String),
    Float32([u8; 4]),
    Float64([u8; 8]),
    String(String),
    /// A complete encoded MessagePack string, including its string header,
    /// for a native string that is not valid UTF-8.
    RawString(Vec<u8>),
    Binary(Vec<u8>),
    Array(Vec<PolicyGrantValue>),
    /// Entries retain order, duplicate keys and non-string keys.
    Map(Vec<PolicyGrantMapEntry>),
    Extension(PolicyGrantExtension),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyGrantMapEntry {
    pub key: PolicyGrantValue,
    pub value: PolicyGrantValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyGrantExtension {
    pub tag: i8,
    pub data: Vec<u8>,
}

impl PolicyGrantValue {
    fn from_value(value: &Value) -> Result<Self> {
        Ok(match value {
            Value::Nil => Self::Nil,
            Value::Boolean(value) => Self::Boolean(*value),
            Value::Integer(value) => Self::Integer(value.to_string()),
            Value::F32(value) => Self::Float32(value.to_bits().to_be_bytes()),
            Value::F64(value) => Self::Float64(value.to_bits().to_be_bytes()),
            Value::String(value) => match value.as_str() {
                Some(value) => Self::String(value.to_owned()),
                None => {
                    let mut encoded = Vec::new();
                    write_value(&mut encoded, &Value::String(value.clone()))?;
                    Self::RawString(encoded)
                }
            },
            Value::Binary(value) => Self::Binary(value.clone()),
            Value::Array(values) => {
                Self::Array(values.iter().map(Self::from_value).collect::<Result<_>>()?)
            }
            Value::Map(entries) => Self::Map(
                entries
                    .iter()
                    .map(|(key, value)| {
                        Ok(PolicyGrantMapEntry {
                            key: Self::from_value(key)?,
                            value: Self::from_value(value)?,
                        })
                    })
                    .collect::<Result<_>>()?,
            ),
            Value::Ext(tag, data) => Self::Extension(PolicyGrantExtension {
                tag: *tag,
                data: data.clone(),
            }),
        })
    }

    fn to_value(&self) -> Result<Value> {
        Ok(match self {
            Self::Nil => Value::Nil,
            Self::Boolean(value) => Value::Boolean(*value),
            Self::Integer(value) => value
                .parse::<i64>()
                .map(Value::from)
                .or_else(|_| value.parse::<u64>().map(Value::from))
                .map_err(|_| {
                    super::invalid("scoped grant integer is outside MessagePack's range")
                })?,
            Self::Float32(bits) => Value::F32(f32::from_bits(u32::from_be_bytes(*bits))),
            Self::Float64(bits) => Value::F64(f64::from_bits(u64::from_be_bytes(*bits))),
            Self::String(value) => Value::from(value.as_str()),
            Self::RawString(encoded) => {
                let mut cursor = std::io::Cursor::new(encoded.as_slice());
                let value = rmpv::decode::read_value(&mut cursor)
                    .map_err(|_| super::invalid("scoped grant raw string does not decode"))?;
                if cursor.position() != encoded.len() as u64 || !matches!(&value, Value::String(_))
                {
                    return Err(super::invalid(
                        "scoped grant raw string is not exactly one string",
                    ));
                }
                value
            }
            Self::Binary(value) => Value::Binary(value.clone()),
            Self::Array(values) => {
                Value::Array(values.iter().map(Self::to_value).collect::<Result<_>>()?)
            }
            Self::Map(entries) => Value::Map(
                entries
                    .iter()
                    .map(|entry| Ok((entry.key.to_value()?, entry.value.to_value()?)))
                    .collect::<Result<_>>()?,
            ),
            Self::Extension(value) => Value::Ext(value.tag, value.data.clone()),
        })
    }
}

impl PolicyScopedGrantRow {
    /// The typed view of one scoped grant row as the policy fold decoded it.
    pub(crate) fn of_decoded(row: &crate::gate::grants::PolicyScopedGrant) -> Result<Self> {
        Ok(Self {
            actor_class: row.actor_class.clone(),
            actor_ref: row.actor_ref.clone(),
            effector: row.effector.clone(),
            scope: row.authority_scope.clone(),
            selectors: row
                .scope
                .as_ref()
                .map(PolicyGrantValue::from_value)
                .transpose()?,
            budget: row
                .budget
                .as_ref()
                .map(PolicyGrantValue::from_value)
                .transpose()?,
            receipt_required: row.receipt_required,
        })
    }
}

pub(super) fn decode_table(value: &Value) -> Result<Vec<PolicyScopedGrantRow>> {
    crate::gate::decode::decode_scoped_grant_table(value)
        .ok_or_else(|| super::invalid("malformed scoped grants"))?
        .iter()
        .map(PolicyScopedGrantRow::of_decoded)
        .collect()
}

pub(super) fn replace_table(
    fields: &mut Vec<(Value, Value)>,
    rows: &[PolicyScopedGrantRow],
) -> Result<()> {
    use crate::gate::constants::{
        ACTOR_CLASS_KEY, ACTOR_REF_KEY, GRANT_BUDGET_KEY, GRANT_EFFECTOR_KEY,
        GRANT_RECEIPT_REQUIRED_KEY, GRANT_SCOPE_KEY, GRANT_SELECTORS_KEY, POLICY_SCOPED_GRANTS_KEY,
    };
    let value = Value::Array(
        rows.iter()
            .map(|row| {
                let mut fields = vec![
                    (
                        Value::from(GRANT_EFFECTOR_KEY),
                        Value::from(row.effector.as_str()),
                    ),
                    (
                        Value::from(GRANT_SCOPE_KEY),
                        crate::federation::scope_codec::encode_scope_value(&row.scope)
                            .map_err(|_| super::invalid("scoped grant scope encoding"))?,
                    ),
                    (
                        Value::from(GRANT_RECEIPT_REQUIRED_KEY),
                        Value::Boolean(row.receipt_required),
                    ),
                ];
                for (key, value) in [
                    (ACTOR_CLASS_KEY, row.actor_class.as_deref()),
                    (ACTOR_REF_KEY, row.actor_ref.as_deref()),
                ] {
                    if let Some(value) = value {
                        fields.push((Value::from(key), Value::from(value)));
                    }
                }
                for (key, value) in [
                    (GRANT_SELECTORS_KEY, row.selectors.as_ref()),
                    (GRANT_BUDGET_KEY, row.budget.as_ref()),
                ] {
                    if let Some(value) = value {
                        fields.push((Value::from(key), value.to_value()?));
                    }
                }
                Ok(Value::Map(fields))
            })
            .collect::<Result<_>>()?,
    );
    fields.retain(|(key, _)| key.as_str() != Some(POLICY_SCOPED_GRANTS_KEY));
    fields.push((Value::from(POLICY_SCOPED_GRANTS_KEY), value));
    Ok(())
}
