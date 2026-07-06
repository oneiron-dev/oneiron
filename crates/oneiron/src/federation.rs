//! Federation grant record substrate.
//!
//! A federation grant is a vault-resident membership record for a shared
//! vault. The body is a pinned MessagePack map with fail-closed decoding:
//! unknown keys, duplicate keys, unknown role/preset strings, unsupported
//! scope kinds, and preset/role mismatches are rejected.

use std::io::Cursor;

use rmpv::Value;

use crate::error::{Error, Result};
use crate::types::EntityId;

/// Current FederationGrant body schema version.
pub const FEDERATION_GRANT_SCHEMA_VERSION: u64 = 1;

/// Pinned ON-DISK MessagePack key set for FEDERATION_GRANT bodies.
pub const FEDERATION_GRANT_BODY_KEYS: [&str; 5] =
    ["schema_version", "scope", "member_ref", "role", "preset"];

pub(crate) const FEDERATION_GRANT_FIELDS_MINIMAL: &[&str] = &["scope", "role", "preset"];
pub(crate) const FEDERATION_GRANT_FIELDS_STANDARD: &[&str] =
    &["scope", "member_ref", "role", "preset"];
pub(crate) const FEDERATION_GRANT_FIELDS_FULL: &[&str] = &FEDERATION_GRANT_BODY_KEYS;

const KEY_SCHEMA_VERSION: &str = FEDERATION_GRANT_BODY_KEYS[0];
const KEY_SCOPE: &str = FEDERATION_GRANT_BODY_KEYS[1];
// Stored as EntityId hex so generic context-pack hydration preserves the principal.
const KEY_MEMBER_REF: &str = FEDERATION_GRANT_BODY_KEYS[2];
const KEY_ROLE: &str = FEDERATION_GRANT_BODY_KEYS[3];
const KEY_PRESET: &str = FEDERATION_GRANT_BODY_KEYS[4];

const FEDERATION_GRANT_SCOPE_KEYS: [&str; 2] = ["kind", "vault_id"];
const SCOPE_KIND_VAULT: &str = "vault";

/// Current guest-share envelope body schema version.
pub const GUEST_SHARE_ENVELOPE_SCHEMA_VERSION: u64 = 1;

/// Pinned MessagePack key set for guest-share envelope bodies.
pub const GUEST_SHARE_ENVELOPE_BODY_KEYS: [&str; 6] = [
    "schema_version",
    "scope",
    "member_ref",
    "selector",
    "window_key",
    "update",
];

/// Pinned MessagePack key set for signed guest-share envelopes.
pub const GUEST_SHARE_ENVELOPE_KEYS: [&str; 2] = ["body", "signature"];

const KEY_GUEST_SCHEMA_VERSION: &str = GUEST_SHARE_ENVELOPE_BODY_KEYS[0];
const KEY_GUEST_SCOPE: &str = GUEST_SHARE_ENVELOPE_BODY_KEYS[1];
const KEY_GUEST_MEMBER_REF: &str = GUEST_SHARE_ENVELOPE_BODY_KEYS[2];
const KEY_GUEST_SELECTOR: &str = GUEST_SHARE_ENVELOPE_BODY_KEYS[3];
const KEY_GUEST_WINDOW_KEY: &str = GUEST_SHARE_ENVELOPE_BODY_KEYS[4];
const KEY_GUEST_UPDATE: &str = GUEST_SHARE_ENVELOPE_BODY_KEYS[5];

const KEY_GUEST_BODY: &str = GUEST_SHARE_ENVELOPE_KEYS[0];
const KEY_GUEST_SIGNATURE: &str = GUEST_SHARE_ENVELOPE_KEYS[1];

/// Scope addressed by a federation grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FederationGrantScope {
    /// Membership in a shared vault.
    Vault { vault_id: u64 },
}

impl FederationGrantScope {
    /// Constructs a shared-vault scope.
    #[must_use]
    pub const fn vault(vault_id: u64) -> Self {
        Self::Vault { vault_id }
    }

    fn validate(self) -> Result<()> {
        match self {
            Self::Vault { vault_id: 0 } => Err(invalid_grant()),
            Self::Vault { .. } => Ok(()),
        }
    }
}

/// Role assigned by a federation grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FederationGrantRole {
    /// Full owner privileges for the shared vault.
    Owner,
    /// Administrative privileges without owner transfer semantics.
    Admin,
    /// Read/write member privileges.
    Member,
    /// Read-only member privileges.
    Viewer,
    /// Audit-only read privileges.
    Auditor,
}

impl FederationGrantRole {
    /// Returns the pinned on-disk string for this role.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
            Self::Viewer => "viewer",
            Self::Auditor => "auditor",
        }
    }

    /// Parses a pinned on-disk role string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "member" => Some(Self::Member),
            "viewer" => Some(Self::Viewer),
            "auditor" => Some(Self::Auditor),
            _ => None,
        }
    }

    /// Returns whether this role can administer membership or policy.
    #[must_use]
    pub const fn is_admin(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }
}

/// Capability preset bounding a federation grant role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FederationGrantPreset {
    /// Owner-grade capability envelope.
    Owner,
    /// Admin-grade capability envelope.
    Admin,
    /// Read/write member capability envelope.
    Member,
    /// Read-only capability envelope.
    ReadOnly,
    /// Audit-only capability envelope.
    Audit,
}

impl FederationGrantPreset {
    /// Returns the pinned on-disk string for this preset.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
            Self::ReadOnly => "read_only",
            Self::Audit => "audit",
        }
    }

    /// Parses a pinned on-disk preset string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "member" => Some(Self::Member),
            "read_only" => Some(Self::ReadOnly),
            "audit" => Some(Self::Audit),
            _ => None,
        }
    }

    /// Returns whether this preset can carry `role`.
    #[must_use]
    pub const fn permits_role(self, role: FederationGrantRole) -> bool {
        match self {
            Self::Owner => true,
            Self::Admin => !matches!(role, FederationGrantRole::Owner),
            Self::Member => matches!(
                role,
                FederationGrantRole::Member
                    | FederationGrantRole::Viewer
                    | FederationGrantRole::Auditor
            ),
            Self::ReadOnly => matches!(
                role,
                FederationGrantRole::Viewer | FederationGrantRole::Auditor
            ),
            Self::Audit => matches!(role, FederationGrantRole::Auditor),
        }
    }
}

/// Shared-vault membership record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FederationGrant {
    /// Shared-vault scope for this membership record.
    pub scope: FederationGrantScope,
    /// Entity representing the member/principal receiving access.
    pub member_ref: EntityId,
    /// Assigned membership role.
    pub role: FederationGrantRole,
    /// Capability preset bounding the assigned role.
    pub preset: FederationGrantPreset,
}

impl FederationGrant {
    /// Constructs a federation grant.
    #[must_use]
    pub const fn new(
        scope: FederationGrantScope,
        member_ref: EntityId,
        role: FederationGrantRole,
        preset: FederationGrantPreset,
    ) -> Self {
        Self {
            scope,
            member_ref,
            role,
            preset,
        }
    }

    /// Validates scope and role/preset policy.
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        if self.preset.permits_role(self.role) {
            Ok(())
        } else {
            Err(invalid_grant())
        }
    }

    /// Returns whether this grant carries an administrative role.
    #[must_use]
    pub const fn is_admin(&self) -> bool {
        self.role.is_admin()
    }
}

/// Canonical, pre-sign guest-share envelope body.
///
/// Membership lists, authority rosters, topology summaries, and counts are not
/// representable in this body. Callers must place only selector-filtered,
/// redacted update bytes in `update`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestShareEnvelopeBody {
    /// Shared-vault scope for the guest share.
    pub scope: FederationGrantScope,
    /// Recipient principal for this share.
    pub member_ref: EntityId,
    /// Canonical encoded [`crate::sync::SyncSelector`] bytes.
    pub selector: Vec<u8>,
    /// Window key addressed by `update`.
    pub window_key: String,
    /// Selector-filtered, metadata-stripped Loro update bytes.
    pub update: Vec<u8>,
}

impl GuestShareEnvelopeBody {
    /// Constructs a canonical guest-share envelope body.
    #[must_use]
    pub fn new(
        scope: FederationGrantScope,
        member_ref: EntityId,
        selector: Vec<u8>,
        window_key: impl Into<String>,
        update: Vec<u8>,
    ) -> Self {
        Self {
            scope,
            member_ref,
            selector,
            window_key: window_key.into(),
            update,
        }
    }
}

/// Signed guest-share envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestShareEnvelope {
    /// Body that was signed.
    pub body: GuestShareEnvelopeBody,
    /// Caller-provided signature over `encode_guest_share_envelope_body(body)`.
    pub signature: Vec<u8>,
}

/// Encodes a guest-share envelope body in canonical MessagePack field order.
pub fn encode_guest_share_envelope_body(body: &GuestShareEnvelopeBody) -> Result<Vec<u8>> {
    body.scope.validate()?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_GUEST_SCHEMA_VERSION),
            Value::from(GUEST_SHARE_ENVELOPE_SCHEMA_VERSION),
        ),
        (Value::from(KEY_GUEST_SCOPE), encode_scope(body.scope)),
        (
            Value::from(KEY_GUEST_MEMBER_REF),
            Value::from(body.member_ref.to_hex()),
        ),
        (
            Value::from(KEY_GUEST_SELECTOR),
            Value::Binary(body.selector.clone()),
        ),
        (
            Value::from(KEY_GUEST_WINDOW_KEY),
            Value::from(body.window_key.as_str()),
        ),
        (
            Value::from(KEY_GUEST_UPDATE),
            Value::Binary(body.update.clone()),
        ),
    ]);

    encode_msgpack_value(
        &value,
        "guest-share envelope body MessagePack encode failed",
    )
}

/// Signs a guest-share envelope body after canonical stripping has completed.
pub fn sign_guest_share_envelope<S>(
    body: GuestShareEnvelopeBody,
    signer: S,
) -> Result<GuestShareEnvelope>
where
    S: FnOnce(&[u8]) -> Result<Vec<u8>>,
{
    let body_bytes = encode_guest_share_envelope_body(&body)?;
    let signature = signer(&body_bytes)?;
    Ok(GuestShareEnvelope { body, signature })
}

/// Encodes a signed guest-share envelope in canonical MessagePack field order.
pub fn encode_guest_share_envelope(envelope: &GuestShareEnvelope) -> Result<Vec<u8>> {
    let body = encode_guest_share_envelope_body(&envelope.body)?;
    let value = Value::Map(vec![
        (Value::from(KEY_GUEST_BODY), Value::Binary(body)),
        (
            Value::from(KEY_GUEST_SIGNATURE),
            Value::Binary(envelope.signature.clone()),
        ),
    ]);

    encode_msgpack_value(&value, "guest-share envelope MessagePack encode failed")
}

/// Encodes a FederationGrant body in canonical MessagePack field order.
pub fn encode_federation_grant_body(grant: &FederationGrant) -> Result<Vec<u8>> {
    grant.validate()?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(FEDERATION_GRANT_SCHEMA_VERSION),
        ),
        (Value::from(KEY_SCOPE), encode_scope(grant.scope)),
        (
            Value::from(KEY_MEMBER_REF),
            Value::from(grant.member_ref.to_hex()),
        ),
        (Value::from(KEY_ROLE), Value::from(grant.role.as_str())),
        (Value::from(KEY_PRESET), Value::from(grant.preset.as_str())),
    ]);

    encode_msgpack_value(&value, "federation grant body MessagePack encode failed")
}

/// Decodes and validates a FederationGrant body.
pub fn decode_federation_grant_body(bytes: &[u8]) -> Result<FederationGrant> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_grant())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_grant());
    }

    decode_federation_grant_value(&value)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_federation_grant_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_federation_grant_body(bytes).map(|_| ())
}

fn decode_federation_grant_value(value: &Value) -> Result<FederationGrant> {
    let Value::Map(entries) = value else {
        return Err(invalid_grant());
    };
    validate_body_keys(entries)?;

    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64()
        != Some(FEDERATION_GRANT_SCHEMA_VERSION)
    {
        return Err(invalid_grant());
    }

    let scope = decode_scope(required_value(entries, KEY_SCOPE)?)?;
    let member_ref = decode_entity_ref(required_value(entries, KEY_MEMBER_REF)?)?;
    let role = required_value(entries, KEY_ROLE)?
        .as_str()
        .and_then(FederationGrantRole::parse)
        .ok_or_else(invalid_grant)?;
    let preset = required_value(entries, KEY_PRESET)?
        .as_str()
        .and_then(FederationGrantPreset::parse)
        .ok_or_else(invalid_grant)?;

    let grant = FederationGrant {
        scope,
        member_ref,
        role,
        preset,
    };
    grant.validate()?;
    Ok(grant)
}

fn encode_scope(scope: FederationGrantScope) -> Value {
    match scope {
        FederationGrantScope::Vault { vault_id } => Value::Map(vec![
            (
                Value::from(FEDERATION_GRANT_SCOPE_KEYS[0]),
                Value::from(SCOPE_KIND_VAULT),
            ),
            (
                Value::from(FEDERATION_GRANT_SCOPE_KEYS[1]),
                Value::from(vault_id),
            ),
        ]),
    }
}

fn decode_scope(value: &Value) -> Result<FederationGrantScope> {
    let Value::Map(entries) = value else {
        return Err(invalid_grant());
    };
    validate_scope_keys(entries)?;

    let kind = required_value(entries, FEDERATION_GRANT_SCOPE_KEYS[0])?
        .as_str()
        .ok_or_else(invalid_grant)?;
    if kind != SCOPE_KIND_VAULT {
        return Err(invalid_grant());
    }

    let vault_id = required_value(entries, FEDERATION_GRANT_SCOPE_KEYS[1])?
        .as_u64()
        .ok_or_else(invalid_grant)?;
    let scope = FederationGrantScope::Vault { vault_id };
    scope.validate()?;
    Ok(scope)
}

fn decode_entity_ref(value: &Value) -> Result<EntityId> {
    let hex = value.as_str().ok_or_else(invalid_grant)?;
    EntityId::from_hex(hex).map_err(|_| invalid_grant())
}

fn validate_body_keys(entries: &[(Value, Value)]) -> Result<()> {
    let mut seen = [false; FEDERATION_GRANT_BODY_KEYS.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_grant)?;
        let Some(index) = FEDERATION_GRANT_BODY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
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

fn validate_scope_keys(entries: &[(Value, Value)]) -> Result<()> {
    let mut seen = [false; FEDERATION_GRANT_SCOPE_KEYS.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_grant)?;
        let Some(index) = FEDERATION_GRANT_SCOPE_KEYS
            .iter()
            .position(|known| *known == key)
        else {
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

fn encode_msgpack_value(value: &Value, context: &'static str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).map_err(|_| Error::InvariantViolation(context))?;
    Ok(out)
}

fn invalid_grant() -> Error {
    Error::InvalidFederationGrantBody("body failed validation")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use crate::types::{
        ENTITY_TYPE_FEDERATION_GRANT, EntityClassification, TypeByteBand,
        entity_type_registry_entry,
    };

    fn member_ref() -> EntityId {
        EntityId::from_bytes([0x42; 16]).expect("valid member id")
    }

    fn test_grant() -> FederationGrant {
        FederationGrant::new(
            FederationGrantScope::vault(7),
            member_ref(),
            FederationGrantRole::Admin,
            FederationGrantPreset::Admin,
        )
    }

    fn encode_value(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, value).expect("encode msgpack");
        out
    }

    fn valid_entries() -> Vec<(Value, Value)> {
        vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(FEDERATION_GRANT_SCHEMA_VERSION),
            ),
            (
                Value::from(KEY_SCOPE),
                Value::Map(vec![
                    (
                        Value::from(FEDERATION_GRANT_SCOPE_KEYS[0]),
                        Value::from(SCOPE_KIND_VAULT),
                    ),
                    (
                        Value::from(FEDERATION_GRANT_SCOPE_KEYS[1]),
                        Value::from(7_u64),
                    ),
                ]),
            ),
            (
                Value::from(KEY_MEMBER_REF),
                Value::from(member_ref().to_hex()),
            ),
            (Value::from(KEY_ROLE), Value::from("admin")),
            (Value::from(KEY_PRESET), Value::from("admin")),
        ]
    }

    fn grant_map(entries: Vec<(Value, Value)>) -> Vec<u8> {
        encode_value(&Value::Map(entries))
    }

    #[test]
    fn federation_grant_codec_round_trips_scope_role_and_preset() -> Result<()> {
        let grant = test_grant();

        let encoded = encode_federation_grant_body(&grant)?;
        validate_federation_grant_body_bytes(&encoded)?;
        let decoded = decode_federation_grant_body(&encoded)?;

        assert_eq!(decoded, grant);
        assert!(decoded.is_admin());
        Ok(())
    }

    #[test]
    fn federation_grant_body_encodes_member_ref_as_hex_string() -> Result<()> {
        let encoded = encode_federation_grant_body(&test_grant())?;
        let mut cursor = Cursor::new(&encoded);
        let value = rmpv::decode::read_value(&mut cursor).expect("decode grant body");
        let Value::Map(entries) = value else {
            panic!("grant body must encode as a map");
        };

        let expected = member_ref().to_hex();
        let member = required_value(&entries, KEY_MEMBER_REF)?;
        assert_eq!(member.as_str(), Some(expected.as_str()));
        Ok(())
    }

    #[test]
    fn federation_grant_decode_fails_closed_for_malformed_bodies() {
        let mut trailing = grant_map(valid_entries());
        trailing.push(0xc0);

        let mut missing_preset = valid_entries();
        missing_preset.retain(|(key, _)| key.as_str() != Some(KEY_PRESET));

        let mut duplicate_role = valid_entries();
        duplicate_role.push((Value::from(KEY_ROLE), Value::from("viewer")));

        let mut unknown_key = valid_entries();
        unknown_key.push((Value::from("future"), Value::from("permit")));

        let mut bad_role = valid_entries();
        for (key, value) in &mut bad_role {
            if key.as_str() == Some(KEY_ROLE) {
                *value = Value::from("super_admin");
            }
        }

        let mut bad_scope_kind = valid_entries();
        for (key, value) in &mut bad_scope_kind {
            if key.as_str() == Some(KEY_SCOPE) {
                *value = Value::Map(vec![
                    (
                        Value::from(FEDERATION_GRANT_SCOPE_KEYS[0]),
                        Value::from("selector"),
                    ),
                    (
                        Value::from(FEDERATION_GRANT_SCOPE_KEYS[1]),
                        Value::from(7_u64),
                    ),
                ]);
            }
        }

        let mut zero_vault = valid_entries();
        for (key, value) in &mut zero_vault {
            if key.as_str() == Some(KEY_SCOPE) {
                *value = Value::Map(vec![
                    (
                        Value::from(FEDERATION_GRANT_SCOPE_KEYS[0]),
                        Value::from(SCOPE_KIND_VAULT),
                    ),
                    (
                        Value::from(FEDERATION_GRANT_SCOPE_KEYS[1]),
                        Value::from(0_u64),
                    ),
                ]);
            }
        }

        let mut bad_member = valid_entries();
        for (key, value) in &mut bad_member {
            if key.as_str() == Some(KEY_MEMBER_REF) {
                *value = Value::from("not-a-32-char-hex-entity-id");
            }
        }

        let mut binary_member = valid_entries();
        for (key, value) in &mut binary_member {
            if key.as_str() == Some(KEY_MEMBER_REF) {
                *value = Value::Binary(member_ref().as_bytes().to_vec());
            }
        }

        for (case, bytes) in [
            ("not msgpack", b"not-msgpack".to_vec()),
            ("not map", encode_value(&Value::from("grant"))),
            ("trailing bytes", trailing),
            ("missing preset", grant_map(missing_preset)),
            ("duplicate role", grant_map(duplicate_role)),
            ("unknown key", grant_map(unknown_key)),
            ("bad role", grant_map(bad_role)),
            ("bad scope kind", grant_map(bad_scope_kind)),
            ("zero vault", grant_map(zero_vault)),
            ("bad member", grant_map(bad_member)),
            ("binary member", grant_map(binary_member)),
        ] {
            let err = match decode_federation_grant_body(&bytes) {
                Ok(decoded) => panic!("{case}: malformed grant decoded as {decoded:?}"),
                Err(err) => err,
            };
            assert_eq!(
                err.kind(),
                ErrorKind::InvalidFederationGrantBody,
                "{case}: wrong error"
            );
        }
    }

    #[test]
    fn federation_grant_policy_rejects_admin_role_under_non_admin_preset() {
        let grant = FederationGrant::new(
            FederationGrantScope::vault(7),
            member_ref(),
            FederationGrantRole::Admin,
            FederationGrantPreset::ReadOnly,
        );

        let err = grant
            .validate()
            .expect_err("read-only preset must not carry admin role");

        assert_eq!(err.kind(), ErrorKind::InvalidFederationGrantBody);
    }

    #[test]
    fn federation_grant_type_registration_is_stable() {
        let entry = entity_type_registry_entry(ENTITY_TYPE_FEDERATION_GRANT)
            .expect("FEDERATION_GRANT registry row");

        assert_eq!(ENTITY_TYPE_FEDERATION_GRANT, 124);
        assert_eq!(entry.kind, "FEDERATION_GRANT");
        assert_eq!(entry.short_id_prefix, None);
        assert_eq!(entry.classification, EntityClassification::Maintenance);
        assert_eq!(entry.band, TypeByteBand::InducedDynamicMaintenance);
    }
}
