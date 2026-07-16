//! AccessGrant control-plane record substrate.
//!
//! Access grants are engine-authored maintenance records that authorize a
//! principal for a narrowly scoped control-plane capability. Bodies are pinned
//! MessagePack maps and decode fail-closed: unknown keys, duplicate keys,
//! unsupported scope/capability/status strings, malformed entity references,
//! and inconsistent revocation state are rejected.

use std::io::Cursor;

use rmpv::Value;

use crate::Vault;
use crate::batch::BatchOp;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::batch::EntityMetadataHeader;
use crate::batch::apply_ops;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_ACCESS_GRANT;
use crate::temporal::TimeRange;

/// Current AccessGrant body schema version.
pub const ACCESS_GRANT_SCHEMA_VERSION: u64 = 1;

/// Pinned on-disk MessagePack key set for AccessGrant bodies.
pub const ACCESS_GRANT_BODY_KEYS: [&str; 7] = [
    "schema_version",
    "principal_ref",
    "scope",
    "capability",
    "status",
    "created_at",
    "revoked_at",
];

pub(crate) const ACCESS_GRANT_FIELDS_MINIMAL: &[&str] = &["scope", "capability", "status"];
pub(crate) const ACCESS_GRANT_FIELDS_STANDARD: &[&str] =
    &["principal_ref", "scope", "capability", "status"];
pub(crate) const ACCESS_GRANT_FIELDS_FULL: &[&str] = &ACCESS_GRANT_BODY_KEYS;

const KEY_SCHEMA_VERSION: &str = ACCESS_GRANT_BODY_KEYS[0];
const KEY_PRINCIPAL_REF: &str = ACCESS_GRANT_BODY_KEYS[1];
const KEY_SCOPE: &str = ACCESS_GRANT_BODY_KEYS[2];
const KEY_CAPABILITY: &str = ACCESS_GRANT_BODY_KEYS[3];
const KEY_STATUS: &str = ACCESS_GRANT_BODY_KEYS[4];
const KEY_CREATED_AT: &str = ACCESS_GRANT_BODY_KEYS[5];
const KEY_REVOKED_AT: &str = ACCESS_GRANT_BODY_KEYS[6];

const SCOPE_KEYS: [&str; 3] = ["kind", "person_ref", "persona_ref"];
const SCOPE_KIND_COMPANION_PROFILE: &str = "companion_profile";

/// Scope addressed by an AccessGrant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AccessGrantScope {
    /// Access to one companion persona profile in one person scope.
    CompanionProfile {
        /// Person scope the companion profile belongs to.
        person_ref: EntityId,
        /// Persona/profile record being addressed.
        persona_ref: EntityId,
    },
}

impl AccessGrantScope {
    /// Constructs a companion profile scope.
    #[must_use]
    pub const fn companion_profile(person_ref: EntityId, persona_ref: EntityId) -> Self {
        Self::CompanionProfile {
            person_ref,
            persona_ref,
        }
    }

    /// Returns whether this scope exactly names the supplied companion profile.
    #[must_use]
    pub fn matches_companion_profile(self, person_ref: &EntityId, persona_ref: &EntityId) -> bool {
        match self {
            Self::CompanionProfile {
                person_ref: grant_person_ref,
                persona_ref: grant_persona_ref,
            } => {
                grant_person_ref.as_bytes() == person_ref.as_bytes()
                    && grant_persona_ref.as_bytes() == persona_ref.as_bytes()
            }
        }
    }

    /// Returns companion profile refs when this scope uses that shape.
    #[must_use]
    pub const fn companion_profile_refs(self) -> Option<(EntityId, EntityId)> {
        match self {
            Self::CompanionProfile {
                person_ref,
                persona_ref,
            } => Some((person_ref, persona_ref)),
        }
    }
}

/// Capability authorized by an AccessGrant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AccessGrantCapability {
    /// Read one companion profile.
    CompanionProfileRead,
}

impl AccessGrantCapability {
    /// Returns the pinned on-disk string for this capability.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompanionProfileRead => "companion_profile.read",
        }
    }

    /// Parses a pinned on-disk capability string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "companion_profile.read" => Some(Self::CompanionProfileRead),
            _ => None,
        }
    }
}

/// AccessGrant lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AccessGrantStatus {
    /// Grant is live and can authorize a matching access.
    Active,
    /// Grant has been revoked and must fail closed.
    Revoked,
}

impl AccessGrantStatus {
    /// Returns the pinned on-disk string for this status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    /// Parses a pinned on-disk status string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// Vault-resident access grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccessGrant {
    /// Principal receiving access.
    pub principal_ref: EntityId,
    /// Exact resource scope.
    pub scope: AccessGrantScope,
    /// Authorized capability.
    pub capability: AccessGrantCapability,
    /// Grant lifecycle status.
    pub status: AccessGrantStatus,
    /// Creation time in Unix seconds.
    pub created_at: u64,
    /// Revocation time in Unix seconds.
    pub revoked_at: Option<u64>,
}

impl AccessGrant {
    /// Constructs an active companion-profile read grant.
    #[must_use]
    pub const fn companion_profile_read(
        principal_ref: EntityId,
        person_ref: EntityId,
        persona_ref: EntityId,
        created_at: u64,
    ) -> Self {
        Self {
            principal_ref,
            scope: AccessGrantScope::companion_profile(person_ref, persona_ref),
            capability: AccessGrantCapability::CompanionProfileRead,
            status: AccessGrantStatus::Active,
            created_at,
            revoked_at: None,
        }
    }

    /// Returns a revoked version of this grant.
    pub fn revoked(self, revoked_at: u64) -> Result<Self> {
        let grant = Self {
            status: AccessGrantStatus::Revoked,
            revoked_at: Some(revoked_at),
            ..self
        };
        grant.validate()?;
        Ok(grant)
    }

    /// Validates revocation invariants.
    pub fn validate(&self) -> Result<()> {
        match (self.status, self.revoked_at) {
            (AccessGrantStatus::Active, None) => Ok(()),
            (AccessGrantStatus::Active, Some(_)) => Err(invalid_grant()),
            (AccessGrantStatus::Revoked, Some(revoked_at)) if revoked_at >= self.created_at => {
                Ok(())
            }
            (AccessGrantStatus::Revoked, Some(_)) | (AccessGrantStatus::Revoked, None) => {
                Err(invalid_grant())
            }
        }
    }

    /// Returns whether this grant authorizes the supplied companion profile.
    #[must_use]
    pub fn allows_companion_profile_read(
        &self,
        principal_ref: &EntityId,
        person_ref: &EntityId,
        persona_ref: &EntityId,
    ) -> bool {
        self.status == AccessGrantStatus::Active
            && self.capability == AccessGrantCapability::CompanionProfileRead
            && self.principal_ref.as_bytes() == principal_ref.as_bytes()
            && self
                .scope
                .matches_companion_profile(person_ref, persona_ref)
    }
}

/// Encodes an AccessGrant body in canonical MessagePack field order.
pub fn encode_access_grant_body(grant: &AccessGrant) -> Result<Vec<u8>> {
    grant.validate()?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(ACCESS_GRANT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_PRINCIPAL_REF),
            Value::from(grant.principal_ref.to_hex()),
        ),
        (Value::from(KEY_SCOPE), encode_scope(grant.scope)),
        (
            Value::from(KEY_CAPABILITY),
            Value::from(grant.capability.as_str()),
        ),
        (Value::from(KEY_STATUS), Value::from(grant.status.as_str())),
        (Value::from(KEY_CREATED_AT), Value::from(grant.created_at)),
        (
            Value::from(KEY_REVOKED_AT),
            grant.revoked_at.map_or(Value::Nil, Value::from),
        ),
    ]);

    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("access grant body MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes and validates an AccessGrant body.
pub fn decode_access_grant_body(bytes: &[u8]) -> Result<AccessGrant> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_grant())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_grant());
    }

    decode_access_grant_value(&value)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_access_grant_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_access_grant_body(bytes).map(|_| ())
}

fn decode_access_grant_value(value: &Value) -> Result<AccessGrant> {
    let Value::Map(entries) = value else {
        return Err(invalid_grant());
    };
    validate_keys(entries, &ACCESS_GRANT_BODY_KEYS)?;

    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64() != Some(ACCESS_GRANT_SCHEMA_VERSION) {
        return Err(invalid_grant());
    }

    let principal_ref = decode_entity_ref(required_value(entries, KEY_PRINCIPAL_REF)?)?;
    let scope = decode_scope(required_value(entries, KEY_SCOPE)?)?;
    let capability = required_value(entries, KEY_CAPABILITY)?
        .as_str()
        .and_then(AccessGrantCapability::parse)
        .ok_or_else(invalid_grant)?;
    let status = required_value(entries, KEY_STATUS)?
        .as_str()
        .and_then(AccessGrantStatus::parse)
        .ok_or_else(invalid_grant)?;
    let created_at = required_value(entries, KEY_CREATED_AT)?
        .as_u64()
        .ok_or_else(invalid_grant)?;
    let revoked_value = required_value(entries, KEY_REVOKED_AT)?;
    let revoked_at = if matches!(revoked_value, Value::Nil) {
        None
    } else {
        Some(revoked_value.as_u64().ok_or_else(invalid_grant)?)
    };

    let grant = AccessGrant {
        principal_ref,
        scope,
        capability,
        status,
        created_at,
        revoked_at,
    };
    grant.validate()?;
    Ok(grant)
}

fn encode_scope(scope: AccessGrantScope) -> Value {
    match scope {
        AccessGrantScope::CompanionProfile {
            person_ref,
            persona_ref,
        } => Value::Map(vec![
            (
                Value::from(SCOPE_KEYS[0]),
                Value::from(SCOPE_KIND_COMPANION_PROFILE),
            ),
            (Value::from(SCOPE_KEYS[1]), Value::from(person_ref.to_hex())),
            (
                Value::from(SCOPE_KEYS[2]),
                Value::from(persona_ref.to_hex()),
            ),
        ]),
    }
}

fn decode_scope(value: &Value) -> Result<AccessGrantScope> {
    let Value::Map(entries) = value else {
        return Err(invalid_grant());
    };
    validate_keys(entries, &SCOPE_KEYS)?;

    let kind = required_value(entries, SCOPE_KEYS[0])?
        .as_str()
        .ok_or_else(invalid_grant)?;
    if kind != SCOPE_KIND_COMPANION_PROFILE {
        return Err(invalid_grant());
    }

    Ok(AccessGrantScope::CompanionProfile {
        person_ref: decode_entity_ref(required_value(entries, SCOPE_KEYS[1])?)?,
        persona_ref: decode_entity_ref(required_value(entries, SCOPE_KEYS[2])?)?,
    })
}

fn decode_entity_ref(value: &Value) -> Result<EntityId> {
    let hex = value.as_str().ok_or_else(invalid_grant)?;
    EntityId::from_hex(hex).map_err(|_| invalid_grant())
}

fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_grant)?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(invalid_grant());
        };
        if seen[index] {
            return Err(invalid_grant());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid_grant())
    }
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(invalid_grant)
}

fn invalid_grant() -> Error {
    Error::InvalidAccessGrantBody("body failed validation")
}

impl Vault {
    /// Engine-authored write door for AccessGrant control-plane records.
    ///
    /// Public generic entity puts for `ENTITY_TYPE_ACCESS_GRANT` remain
    /// rejected with `MaintenanceKindNotWritable`; this method validates the
    /// pinned AccessGrant body before using the maintenance write path.
    pub fn put_access_grant(&self, id: &EntityId, grant: &AccessGrant) -> Result<()> {
        let data = encode_access_grant_body(grant)?;
        self.write_access_grant_body(id, grant.created_at, &data)
    }

    /// Creates an AccessGrant only when no entity already exists at `id`.
    pub fn create_access_grant(&self, id: &EntityId, grant: &AccessGrant) -> Result<()> {
        let data = encode_access_grant_body(grant)?;
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_some() {
            return Err(Error::AccessGrantAlreadyExists);
        }
        self.apply_access_grant_body(&mut wtxn, id, grant.created_at, data)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Revokes an AccessGrant by rewriting the same record as revoked.
    pub fn revoke_access_grant(&self, id: &EntityId, revoked_at: u64) -> Result<AccessGrant> {
        let mut wtxn = self.store.env.write_txn()?;
        let raw = self
            .store
            .entities
            .get(&wtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_ACCESS_GRANT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        let grant = decode_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let revoked = grant.revoked(revoked_at)?;
        let data = encode_access_grant_body(&revoked)?;
        self.apply_access_grant_body(&mut wtxn, id, revoked_at, data)?;
        wtxn.commit()?;
        Ok(revoked)
    }

    /// Reads and decodes an AccessGrant record.
    pub fn get_access_grant(&self, id: &EntityId) -> Result<Option<AccessGrant>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_ACCESS_GRANT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    fn write_access_grant_body(&self, id: &EntityId, learned_at: u64, data: &[u8]) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        self.apply_access_grant_body(&mut wtxn, id, learned_at, data.to_vec())?;
        wtxn.commit()?;
        Ok(())
    }

    fn apply_access_grant_body(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        learned_at: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_ACCESS_GRANT,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    }
}

#[cfg(test)]
mod tests;
