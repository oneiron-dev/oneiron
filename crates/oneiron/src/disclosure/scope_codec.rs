//! DisclosureScope type with canonical msgpack codec and key validation.

use std::io::Cursor;

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Current DisclosureScope body schema version.
pub const DISCLOSURE_SCOPE_SCHEMA_VERSION: u64 = 1;

/// Pinned on-disk MessagePack key set for DisclosureScope bodies.
pub const DISCLOSURE_SCOPE_BODY_KEYS: [&str; 7] = [
    "schema_version",
    "entities",
    "topics",
    "purpose",
    "status",
    "created_at",
    "updated_at",
];

const KEY_SCHEMA_VERSION: &str = DISCLOSURE_SCOPE_BODY_KEYS[0];

const KEY_ENTITIES: &str = DISCLOSURE_SCOPE_BODY_KEYS[1];

const KEY_TOPICS: &str = DISCLOSURE_SCOPE_BODY_KEYS[2];

const KEY_PURPOSE: &str = DISCLOSURE_SCOPE_BODY_KEYS[3];

const KEY_STATUS: &str = DISCLOSURE_SCOPE_BODY_KEYS[4];

const KEY_CREATED_AT: &str = DISCLOSURE_SCOPE_BODY_KEYS[5];

const KEY_UPDATED_AT: &str = DISCLOSURE_SCOPE_BODY_KEYS[6];

/// Maximum explicit allowlist entries one scope may carry.
pub const MAX_DISCLOSURE_SCOPE_ENTITIES: usize = 256;

/// Maximum reserved topic tags one scope may carry.
pub const MAX_DISCLOSURE_SCOPE_TOPICS: usize = 32;

pub(super) const MAX_DISCLOSURE_SCOPE_TOPIC_BYTES: usize = 128;

const MAX_DISCLOSURE_SCOPE_PURPOSE_BYTES: usize = 512;

/// OF-153 grant-grammar lifecycle for a disclosure scope.
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

/// Per-contact disclosure scope: WHAT a known contact may hear about
/// (explicit entity allowlist; topics are schema-reserved, stored and
/// intersected but NOT a v1 admission path — design §8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosureScope {
    /// Explicit allowlist, sorted and deduped; at most
    /// [`MAX_DISCLOSURE_SCOPE_ENTITIES`].
    pub entities: Vec<EntityId>,
    /// Reserved topic tags (v1 stores + intersects; never admits).
    pub topics: Vec<String>,
    /// Human-readable task purpose from the introduction; 1..=512 bytes.
    pub purpose: String,
    pub status: DisclosureScopeStatus,
    pub created_at: u64,
    pub updated_at: u64,
}

impl DisclosureScope {
    /// The auto-scope constructor introductions call: sorts and dedupes the
    /// entity allowlist, starts Active with no topics.
    pub fn task_scoped(
        purpose: impl Into<String>,
        mut entities: Vec<EntityId>,
        created_at: u64,
    ) -> Result<Self> {
        entities.sort_unstable();
        entities.dedup();
        let scope = Self {
            entities,
            topics: Vec::new(),
            purpose: purpose.into(),
            status: DisclosureScopeStatus::Active,
            created_at,
            updated_at: created_at,
        };
        scope.validate()?;
        Ok(scope)
    }

    /// The pinned EMPTY scope — the fail-closed default an unknown party,
    /// revoked scope, or missing row contributes to the DEC-0005
    /// intersection. An all-empty struct literal is invalid by construction
    /// because `purpose` has a 1..=512-byte floor.
    #[must_use]
    pub fn deny_all(now: u64) -> Self {
        Self {
            entities: Vec::new(),
            topics: Vec::new(),
            purpose: "deny_all".to_owned(),
            status: DisclosureScopeStatus::Active,
            created_at: now,
            updated_at: now,
        }
    }

    /// Validates the pinned scope invariants.
    pub fn validate(&self) -> Result<()> {
        if self.entities.len() > MAX_DISCLOSURE_SCOPE_ENTITIES {
            return Err(Error::InvalidDisclosureScope(
                "scope entities exceed the 256-entry allowlist cap",
            ));
        }
        if !self
            .entities
            .windows(2)
            .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
        {
            return Err(Error::InvalidDisclosureScope(
                "scope entities must be sorted and deduped",
            ));
        }
        if self.topics.len() > MAX_DISCLOSURE_SCOPE_TOPICS {
            return Err(Error::InvalidDisclosureScope(
                "scope topics exceed the 32-entry cap",
            ));
        }
        for topic in &self.topics {
            if topic.trim().is_empty()
                || topic.trim() != topic
                || topic.len() > MAX_DISCLOSURE_SCOPE_TOPIC_BYTES
            {
                return Err(Error::InvalidDisclosureScope(
                    "scope topic must be trimmed, non-empty, and at most 128 bytes",
                ));
            }
        }
        if self.purpose.trim().is_empty()
            || self.purpose.trim() != self.purpose
            || self.purpose.len() > MAX_DISCLOSURE_SCOPE_PURPOSE_BYTES
        {
            return Err(Error::InvalidDisclosureScope(
                "scope purpose must be trimmed, non-empty, and at most 512 bytes",
            ));
        }
        if self.updated_at < self.created_at {
            return Err(Error::InvalidDisclosureScope(
                "scope updated_at must not precede created_at",
            ));
        }
        Ok(())
    }

    /// DEC-0005 most-restrictive-wins intersection: entity/topic
    /// set-intersection, earliest `created_at`, latest `updated_at`,
    /// Revoked-propagating status. The empty scope is the absorbing element.
    #[must_use]
    pub fn intersect(&self, other: &Self) -> Self {
        let entities = self
            .entities
            .iter()
            .filter(|id| other.entities.binary_search(id).is_ok())
            .copied()
            .collect();
        let topics = self
            .topics
            .iter()
            .filter(|topic| other.topics.contains(topic))
            .cloned()
            .collect();
        let purpose = truncate_at_char_boundary(
            format!("{} ∩ {}", self.purpose, other.purpose),
            MAX_DISCLOSURE_SCOPE_PURPOSE_BYTES,
        );
        let status = if self.status == DisclosureScopeStatus::Active
            && other.status == DisclosureScopeStatus::Active
        {
            DisclosureScopeStatus::Active
        } else {
            DisclosureScopeStatus::Revoked
        };
        Self {
            entities,
            topics,
            purpose,
            status,
            created_at: self.created_at.min(other.created_at),
            updated_at: self.updated_at.max(other.updated_at),
        }
    }

    pub(super) fn allows_entity(&self, id: &EntityId) -> bool {
        self.entities.binary_search(id).is_ok()
    }
}

fn truncate_at_char_boundary(mut value: String, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    let mut cut = max_bytes;
    while cut > 0 && !value.is_char_boundary(cut) {
        cut -= 1;
    }
    value.truncate(cut);
    value
}

pub(super) fn disclosure_scope_body_value(scope: &DisclosureScope) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DISCLOSURE_SCOPE_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_ENTITIES),
            Value::Array(
                scope
                    .entities
                    .iter()
                    .map(|id| Value::from(id.to_hex()))
                    .collect(),
            ),
        ),
        (
            Value::from(KEY_TOPICS),
            Value::Array(
                scope
                    .topics
                    .iter()
                    .map(|topic| Value::from(topic.as_str()))
                    .collect(),
            ),
        ),
        (
            Value::from(KEY_PURPOSE),
            Value::from(scope.purpose.as_str()),
        ),
        (Value::from(KEY_STATUS), Value::from(scope.status.as_str())),
        (Value::from(KEY_CREATED_AT), Value::from(scope.created_at)),
        (Value::from(KEY_UPDATED_AT), Value::from(scope.updated_at)),
    ])
}

/// Encodes a DisclosureScope body in canonical MessagePack key order.
pub fn encode_disclosure_scope_body(scope: &DisclosureScope) -> Result<Vec<u8>> {
    scope.validate()?;
    let value = disclosure_scope_body_value(scope);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value).map_err(|_| {
        Error::InvariantViolation("disclosure scope body MessagePack encode failed")
    })?;
    Ok(out)
}

/// Decodes and validates a DisclosureScope body (strict key set, no
/// duplicates, no trailing bytes).
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

    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64()
        != Some(DISCLOSURE_SCOPE_SCHEMA_VERSION)
    {
        return Err(invalid_scope());
    }
    let Value::Array(raw_entities) = required_value(entries, KEY_ENTITIES)? else {
        return Err(invalid_scope());
    };
    let entities = raw_entities
        .iter()
        .map(|value| {
            value
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or_else(invalid_scope)
        })
        .collect::<Result<Vec<_>>>()?;
    let Value::Array(raw_topics) = required_value(entries, KEY_TOPICS)? else {
        return Err(invalid_scope());
    };
    let topics = raw_topics
        .iter()
        .map(|value| value.as_str().map(str::to_owned).ok_or_else(invalid_scope))
        .collect::<Result<Vec<_>>>()?;
    let purpose = required_value(entries, KEY_PURPOSE)?
        .as_str()
        .ok_or_else(invalid_scope)?
        .to_owned();
    let status = required_value(entries, KEY_STATUS)?
        .as_str()
        .and_then(DisclosureScopeStatus::parse)
        .ok_or_else(invalid_scope)?;
    let created_at = required_value(entries, KEY_CREATED_AT)?
        .as_u64()
        .ok_or_else(invalid_scope)?;
    let updated_at = required_value(entries, KEY_UPDATED_AT)?
        .as_u64()
        .ok_or_else(invalid_scope)?;

    let scope = DisclosureScope {
        entities,
        topics,
        purpose,
        status,
        created_at,
        updated_at,
    };
    scope.validate()?;
    Ok(scope)
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
    Error::InvalidDisclosureScope("body failed validation")
}
