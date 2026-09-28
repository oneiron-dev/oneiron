//! Skill roles and the bounded executable call contract.

use crate::error::{ArtifactError, Error, Result};
use rmpv::Value;
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillRole {
    Knowledge,
    Workflow,
    Callable,
}

impl SkillRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Knowledge => "knowledge",
            Self::Workflow => "workflow",
            Self::Callable => "callable",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "knowledge" => Some(Self::Knowledge),
            "workflow" => Some(Self::Workflow),
            "callable" => Some(Self::Callable),
            _ => None,
        }
    }
}

/// `reference` is a file in the exact admitted skill tree, never a host path.
/// `arguments` and `returns` are JSON-shaped contracts supplied by the author.
#[derive(Debug, Clone, PartialEq)]
pub struct SkillCallContract {
    pub reference: String,
    pub arguments: JsonValue,
    pub returns: JsonValue,
}

fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(reason))
}

fn valid_shape(shape: &JsonValue, depth: usize) -> bool {
    if depth > 8 {
        return false;
    }
    match shape {
        JsonValue::String(kind) => matches!(
            kind.as_str(),
            "string" | "number" | "integer" | "boolean" | "object" | "array" | "null"
        ),
        JsonValue::Object(fields) => {
            !fields.is_empty()
                && fields.len() <= 64
                && fields.iter().all(|(key, value)| {
                    !key.is_empty() && key.len() <= 128 && valid_shape(value, depth + 1)
                })
        }
        JsonValue::Array(items) => items.len() == 1 && valid_shape(&items[0], depth + 1),
        _ => false,
    }
}

impl SkillCallContract {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.reference.is_empty()
            || self.reference.len() > 512
            || self.reference.starts_with('/')
            || self
                .reference
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || self.reference.contains('\\')
        {
            return Err(invalid(
                "call reference must be a bounded relative skill-tree path",
            ));
        }
        for shape in [&self.arguments, &self.returns] {
            if !valid_shape(shape, 0)
                || serde_json::to_vec(shape).map_or(true, |encoded| encoded.len() > 16_384)
            {
                return Err(invalid(
                    "call arguments and returns must be bounded non-null JSON contracts",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Value> {
        self.validate()?;
        Ok(Value::Map(vec![
            (
                Value::from("reference"),
                Value::from(self.reference.as_str()),
            ),
            (
                Value::from("arguments"),
                rmpv::ext::to_value(&self.arguments)
                    .map_err(|_| invalid("call arguments cannot be encoded"))?,
            ),
            (
                Value::from("returns"),
                rmpv::ext::to_value(&self.returns)
                    .map_err(|_| invalid("call returns cannot be encoded"))?,
            ),
        ]))
    }

    pub(crate) fn decode(value: &Value) -> Result<Self> {
        let Value::Map(entries) = value else {
            return Err(invalid("call must be a map"));
        };
        if entries.len() != 3 {
            return Err(invalid(
                "call must contain reference, arguments and returns exactly once",
            ));
        }
        let mut reference = None;
        let mut arguments = None;
        let mut returns = None;
        for (key, value) in entries {
            match key.as_str() {
                Some("reference") if reference.is_none() => {
                    reference = value.as_str().map(str::to_owned);
                }
                Some("arguments") if arguments.is_none() => {
                    arguments = Some(
                        rmpv::ext::from_value::<JsonValue>(value.clone())
                            .map_err(|_| invalid("invalid call arguments"))?,
                    );
                }
                Some("returns") if returns.is_none() => {
                    returns = Some(
                        rmpv::ext::from_value::<JsonValue>(value.clone())
                            .map_err(|_| invalid("invalid call returns"))?,
                    );
                }
                _ => return Err(invalid("unknown, duplicate or malformed call field")),
            }
        }
        let call = Self {
            reference: reference.ok_or(invalid("call reference must be a string"))?,
            arguments: arguments.ok_or(invalid("missing call arguments"))?,
            returns: returns.ok_or(invalid("missing call returns"))?,
        };
        call.validate()?;
        Ok(call)
    }
}
