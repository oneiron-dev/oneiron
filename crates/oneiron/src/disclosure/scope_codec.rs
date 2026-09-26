//! Contact clearance envelope and canonical six-axis Scope codec.

use std::io::Cursor;

use rmpv::Value;

use crate::error::{Error, GateError, Result};
use crate::federation::{
    Scope,
    scope_codec::{decode_scope_value, encode_scope_value},
};

/// Current contact clearance body schema version (prerelease wire format).
pub const DISCLOSURE_SCOPE_SCHEMA_VERSION: u64 = 1;

/// Pinned on-disk MessagePack key set for contact clearance bodies.
pub const DISCLOSURE_SCOPE_BODY_KEYS: [&str; 6] = [
    "schema_version",
    "scope",
    "purpose",
    "status",
    "created_at",
    "updated_at",
];
const MAX_PURPOSE_BYTES: usize = 512;
pub(super) const MAX_DISCLOSURE_SCOPE_TOPIC_BYTES: usize = 128;

/// Lifecycle of a contact's clearance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DisclosureScopeStatus {
    Active,
    Revoked,
}
impl DisclosureScopeStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// Owner-visible metadata around a contact's six-axis Scope clearance.
/// The clearance itself is `scope`, not this envelope or an entity allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosureScope {
    pub scope: Scope,
    /// Human-readable purpose of the grant, 1..=512 bytes.
    pub purpose: String,
    pub status: DisclosureScopeStatus,
    pub created_at: u64,
    pub updated_at: u64,
}
impl DisclosureScope {
    pub fn new(scope: Scope, purpose: impl Into<String>, created_at: u64) -> Result<Self> {
        let value = Self {
            scope,
            purpose: purpose.into(),
            status: DisclosureScopeStatus::Active,
            created_at,
            updated_at: created_at,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<()> {
        if self.purpose.trim().is_empty()
            || self.purpose.trim() != self.purpose
            || self.purpose.len() > MAX_PURPOSE_BYTES
        {
            return Err(Error::Gate(GateError::InvalidDisclosureScope(
                "clearance purpose must be trimmed, non-empty, and at most 512 bytes",
            )));
        }
        if self.updated_at < self.created_at {
            return Err(Error::Gate(GateError::InvalidDisclosureScope(
                "clearance updated_at must not precede created_at",
            )));
        }
        // Reject noncanonical in-memory axes (Some(empty) must be Bottom).
        let wire = encode_scope_value(&self.scope).map_err(|_| invalid_scope())?;
        if decode_scope_value(&wire).map_err(|_| invalid_scope())? != self.scope {
            return Err(invalid_scope());
        }
        Ok(())
    }

    /// Revoked clearance is bottom; never re-use its stored scope for admission.
    #[must_use]
    pub(super) fn effective_scope(&self) -> Scope {
        if self.status == DisclosureScopeStatus::Active {
            self.scope.clone()
        } else {
            Scope::default()
        }
    }
}

pub(super) fn disclosure_scope_body_value(clearance: &DisclosureScope) -> Result<Value> {
    Ok(Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(DISCLOSURE_SCOPE_SCHEMA_VERSION),
        ),
        (
            Value::from("scope"),
            encode_scope_value(&clearance.scope).map_err(|_| invalid_scope())?,
        ),
        (
            Value::from("purpose"),
            Value::from(clearance.purpose.as_str()),
        ),
        (
            Value::from("status"),
            Value::from(clearance.status.as_str()),
        ),
        (Value::from("created_at"), Value::from(clearance.created_at)),
        (Value::from("updated_at"), Value::from(clearance.updated_at)),
    ]))
}

/// Encodes the contact clearance with a canonical six-axis Scope payload.
pub fn encode_disclosure_scope_body(clearance: &DisclosureScope) -> Result<Vec<u8>> {
    clearance.validate()?;
    let value = disclosure_scope_body_value(clearance)?;
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value).map_err(|_| {
        Error::InvariantViolation("disclosure scope body MessagePack encode failed")
    })?;
    Ok(out)
}

/// Strict decode: no trailing bytes, unknown/duplicate/missing envelope or Scope keys.
pub fn decode_disclosure_scope_body(bytes: &[u8]) -> Result<DisclosureScope> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_scope())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_scope());
    }
    decode_disclosure_scope_value(&value)
}
pub(super) fn decode_disclosure_scope_value(value: &Value) -> Result<DisclosureScope> {
    let Value::Map(entries) = value else {
        return Err(invalid_scope());
    };
    validate_keys(entries, &DISCLOSURE_SCOPE_BODY_KEYS)?;
    if required_value(entries, "schema_version")?.as_u64() != Some(DISCLOSURE_SCOPE_SCHEMA_VERSION)
    {
        return Err(invalid_scope());
    }
    let scope_value = required_value(entries, "scope")?;
    let scope = decode_scope_value(scope_value).map_err(|_| invalid_scope())?;
    // In-memory and wire axes must use the same normalized, canonical shape.
    if encode_scope_value(&scope).map_err(|_| invalid_scope())? != *scope_value {
        return Err(invalid_scope());
    }
    let purpose = required_value(entries, "purpose")?
        .as_str()
        .ok_or_else(invalid_scope)?
        .to_owned();
    let status = required_value(entries, "status")?
        .as_str()
        .and_then(DisclosureScopeStatus::parse)
        .ok_or_else(invalid_scope)?;
    let created_at = required_value(entries, "created_at")?
        .as_u64()
        .ok_or_else(invalid_scope)?;
    let updated_at = required_value(entries, "updated_at")?
        .as_u64()
        .ok_or_else(invalid_scope)?;
    let clearance = DisclosureScope {
        scope,
        purpose,
        status,
        created_at,
        updated_at,
    };
    clearance.validate()?;
    Ok(clearance)
}

pub(super) fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_scope)?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(invalid_scope());
        };
        if seen[index] {
            return Err(invalid_scope());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid_scope())
    }
}

pub(super) fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(invalid_scope)
}

pub(super) fn invalid_scope() -> Error {
    Error::Gate(GateError::InvalidDisclosureScope("body failed validation"))
}
