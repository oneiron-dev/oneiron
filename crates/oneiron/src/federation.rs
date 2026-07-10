//! Federation grant record substrate.
//!
//! A federation grant is a vault-resident membership record for a shared
//! vault. The body is a pinned MessagePack map with fail-closed decoding:
//! unknown keys, duplicate keys, unknown role/preset strings, unsupported
//! scope kinds, and preset/role mismatches are rejected.

use std::io::Cursor;

use rmpv::Value;

use crate::entity_id::{EntityId, is_foreign_world_id_range};
use crate::error::{Error, Result};
use crate::registry::TypeByteBand;

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

/// Current FederationPactScope canonical encoding schema version.
pub const FEDERATION_PACT_SCOPE_SCHEMA_VERSION: u64 = 1;

const FEDERATION_PACT_SCOPE_KEYS: [&str; 3] = ["schema_version", "lo_to_hi", "hi_to_lo"];
const KEY_PACT_SCOPE_SCHEMA_VERSION: &str = FEDERATION_PACT_SCOPE_KEYS[0];
const KEY_PACT_SCOPE_LO_TO_HI: &str = FEDERATION_PACT_SCOPE_KEYS[1];
const KEY_PACT_SCOPE_HI_TO_LO: &str = FEDERATION_PACT_SCOPE_KEYS[2];

const FEDERATION_DIRECTION_SCOPE_KEYS: [&str; 3] = ["worlds", "facets", "bands"];
const KEY_DIRECTION_WORLDS: &str = FEDERATION_DIRECTION_SCOPE_KEYS[0];
const KEY_DIRECTION_FACETS: &str = FEDERATION_DIRECTION_SCOPE_KEYS[1];
const KEY_DIRECTION_BANDS: &str = FEDERATION_DIRECTION_SCOPE_KEYS[2];

const FEDERATION_SCOPE_AXIS_KEYS: [&str; 2] = ["kind", "ids"];
const KEY_SCOPE_AXIS_KIND: &str = FEDERATION_SCOPE_AXIS_KEYS[0];
const KEY_SCOPE_AXIS_IDS: &str = FEDERATION_SCOPE_AXIS_KEYS[1];

const SCOPE_WORLDS_KIND_ALL: &str = "all";
const SCOPE_WORLDS_KIND_BASE: &str = "base";
const SCOPE_WORLDS_KIND_WORLDS: &str = "worlds";

const SCOPE_AXIS_KIND_ALL: &str = "all";
const SCOPE_AXIS_KIND_SOME: &str = "some";
const SCOPE_AXIS_KIND_BOTTOM: &str = "bottom";

/// Normalized band order shared with `SyncSelector::new`.
const FEDERATION_SCOPE_BAND_ORDER: [TypeByteBand; 6] = [
    TypeByteBand::Semantic,
    TypeByteBand::Core,
    TypeByteBand::Companion,
    TypeByteBand::Productivity,
    TypeByteBand::Crm,
    TypeByteBand::InducedDynamicMaintenance,
];

/// World axis of a federation pact direction scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationScopeWorlds {
    /// Base reality plus every world.
    All,
    /// Base reality only.
    Base,
    /// Base reality plus the named worlds (sorted, deduplicated, non-empty,
    /// local-range only — foreign-range world ids fail closed).
    Worlds(Vec<EntityId>),
}

/// Facet axis of a federation pact direction scope.
///
/// The bottom is a distinct wire value: an empty id set is NEVER decoded as
/// "all facets". Per ARCH-0022, a fail-open widen here would break the type-13
/// minting invariant (profiles never merge across masks), so the meet of
/// disjoint facet sets confers nothing on this axis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationScopeFacets {
    /// Every facet (⊤).
    All,
    /// Exactly the named facets (sorted, deduplicated, non-empty).
    Some(Vec<EntityId>),
    /// No facet-scoped content at all (⊥).
    Bottom,
}

/// Band axis of a federation pact direction scope.
///
/// Kind-tagged like [`FederationScopeFacets`]: ⊤ and ⊥ are distinct wire
/// values and the disjoint meet is ⊥, never an accidental all-bands widen
/// (ARCH-0022).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationScopeBands {
    /// Every band (⊤).
    All,
    /// Exactly the named bands (normalized `SyncSelector::new` order,
    /// deduplicated, non-empty).
    Some(Vec<TypeByteBand>),
    /// No band passes (⊥).
    Bottom,
}

/// One direction of a federation pact scope pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationDirectionScope {
    /// World filter for shared claims.
    pub worlds: FederationScopeWorlds,
    /// Facet filter for shared content.
    pub facets: FederationScopeFacets,
    /// Type-byte band filter for shared content.
    pub bands: FederationScopeBands,
}

/// Dual-signed federation pact scope pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationPactScope {
    /// Direction: vault_lo shares → vault_hi.
    pub lo_to_hi: FederationDirectionScope,
    /// Direction: vault_hi shares → vault_lo.
    pub hi_to_lo: FederationDirectionScope,
}

impl FederationScopeWorlds {
    fn validate(&self) -> Result<()> {
        match self {
            Self::All | Self::Base => Ok(()),
            Self::Worlds(ids) => {
                validate_strictly_ascending_ids(ids)?;
                if ids.iter().any(|id| is_foreign_world_id_range(*id)) {
                    return Err(invalid_pact_scope());
                }
                Ok(())
            }
        }
    }

    fn is_narrowing_of(&self, ceiling: &Self) -> bool {
        match (self, ceiling) {
            (_, Self::All) => true,
            (Self::All, _) => false,
            (Self::Base, _) => true,
            (Self::Worlds(_), Self::Base) => false,
            (Self::Worlds(narrow), Self::Worlds(wide)) => {
                narrow.iter().all(|id| wide.contains(id))
            }
        }
    }

    fn intersect(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::All, x) | (x, Self::All) => x.clone(),
            (Self::Base, _) | (_, Self::Base) => Self::Base,
            (Self::Worlds(left), Self::Worlds(right)) => {
                let both: Vec<EntityId> = left
                    .iter()
                    .filter(|id| right.contains(id))
                    .copied()
                    .collect();
                if both.is_empty() {
                    Self::Base
                } else {
                    Self::Worlds(both)
                }
            }
        }
    }
}

impl FederationScopeFacets {
    fn validate(&self) -> Result<()> {
        match self {
            Self::All | Self::Bottom => Ok(()),
            Self::Some(ids) => validate_strictly_ascending_ids(ids),
        }
    }

    fn is_narrowing_of(&self, ceiling: &Self) -> bool {
        match (self, ceiling) {
            (_, Self::All) => true,
            (Self::Bottom, _) => true,
            (Self::All, _) => false,
            (Self::Some(_), Self::Bottom) => false,
            (Self::Some(narrow), Self::Some(wide)) => narrow.iter().all(|id| wide.contains(id)),
        }
    }

    fn intersect(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::All, x) | (x, Self::All) => x.clone(),
            (Self::Some(left), Self::Some(right)) => {
                let both: Vec<EntityId> = left
                    .iter()
                    .filter(|id| right.contains(id))
                    .copied()
                    .collect();
                if both.is_empty() {
                    Self::Bottom
                } else {
                    Self::Some(both)
                }
            }
        }
    }
}

impl FederationScopeBands {
    fn validate(&self) -> Result<()> {
        match self {
            Self::All | Self::Bottom => Ok(()),
            Self::Some(bands) => {
                if bands.is_empty() {
                    return Err(invalid_pact_scope());
                }
                let ascending = bands
                    .windows(2)
                    .all(|pair| band_order_index(pair[0]) < band_order_index(pair[1]));
                if ascending { Ok(()) } else { Err(invalid_pact_scope()) }
            }
        }
    }

    fn is_narrowing_of(&self, ceiling: &Self) -> bool {
        match (self, ceiling) {
            (_, Self::All) => true,
            (Self::Bottom, _) => true,
            (Self::All, _) => false,
            (Self::Some(_), Self::Bottom) => false,
            (Self::Some(narrow), Self::Some(wide)) => {
                narrow.iter().all(|band| wide.contains(band))
            }
        }
    }

    fn intersect(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::All, x) | (x, Self::All) => x.clone(),
            (Self::Some(left), Self::Some(right)) => {
                let both: Vec<TypeByteBand> = left
                    .iter()
                    .filter(|band| right.contains(band))
                    .copied()
                    .collect();
                if both.is_empty() {
                    Self::Bottom
                } else {
                    Self::Some(both)
                }
            }
        }
    }
}

impl FederationDirectionScope {
    /// Validates every axis of this direction scope.
    pub fn validate(&self) -> Result<()> {
        self.worlds.validate()?;
        self.facets.validate()?;
        self.bands.validate()
    }

    /// Axis-wise partial order: `self ⊑ ceiling`.
    #[must_use]
    pub fn is_narrowing_of(&self, ceiling: &Self) -> bool {
        self.worlds.is_narrowing_of(&ceiling.worlds)
            && self.facets.is_narrowing_of(&ceiling.facets)
            && self.bands.is_narrowing_of(&ceiling.bands)
    }

    /// Axis-wise meet; disjoint facet/band sets meet at their kind-tagged ⊥.
    #[must_use]
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            worlds: self.worlds.intersect(&other.worlds),
            facets: self.facets.intersect(&other.facets),
            bands: self.bands.intersect(&other.bands),
        }
    }
}

impl FederationPactScope {
    /// Validates both direction scopes.
    pub fn validate(&self) -> Result<()> {
        self.lo_to_hi.validate()?;
        self.hi_to_lo.validate()
    }
}

/// Encodes a FederationPactScope in canonical MessagePack field order.
pub fn encode_federation_pact_scope(scope: &FederationPactScope) -> Result<Vec<u8>> {
    scope.validate()?;
    encode_msgpack_value(
        &federation_pact_scope_value(scope),
        "federation pact scope MessagePack encode failed",
    )
}

/// Decodes and validates a canonical FederationPactScope.
pub fn decode_federation_pact_scope(bytes: &[u8]) -> Result<FederationPactScope> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_pact_scope())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_pact_scope());
    }
    decode_federation_pact_scope_value(&value)
}

/// Canonical MessagePack value for a pact scope (authority-log op payloads).
pub(crate) fn federation_pact_scope_value(scope: &FederationPactScope) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_PACT_SCOPE_SCHEMA_VERSION),
            Value::from(FEDERATION_PACT_SCOPE_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_PACT_SCOPE_LO_TO_HI),
            federation_direction_scope_value(&scope.lo_to_hi),
        ),
        (
            Value::from(KEY_PACT_SCOPE_HI_TO_LO),
            federation_direction_scope_value(&scope.hi_to_lo),
        ),
    ])
}

/// Fail-closed value-level pact scope decoder (authority-log op payloads).
pub(crate) fn decode_federation_pact_scope_value(value: &Value) -> Result<FederationPactScope> {
    let Value::Map(entries) = value else {
        return Err(invalid_pact_scope());
    };
    validate_exact_keys(entries, &FEDERATION_PACT_SCOPE_KEYS)?;
    if pact_scope_value(entries, KEY_PACT_SCOPE_SCHEMA_VERSION)?.as_u64()
        != Some(FEDERATION_PACT_SCOPE_SCHEMA_VERSION)
    {
        return Err(invalid_pact_scope());
    }
    let scope = FederationPactScope {
        lo_to_hi: decode_direction_scope_value(pact_scope_value(
            entries,
            KEY_PACT_SCOPE_LO_TO_HI,
        )?)?,
        hi_to_lo: decode_direction_scope_value(pact_scope_value(
            entries,
            KEY_PACT_SCOPE_HI_TO_LO,
        )?)?,
    };
    scope.validate()?;
    Ok(scope)
}

/// Canonical MessagePack value for one direction scope (Rescope-narrow payloads).
pub(crate) fn federation_direction_scope_value(scope: &FederationDirectionScope) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_DIRECTION_WORLDS),
            worlds_axis_value(&scope.worlds),
        ),
        (
            Value::from(KEY_DIRECTION_FACETS),
            facets_axis_value(&scope.facets),
        ),
        (
            Value::from(KEY_DIRECTION_BANDS),
            bands_axis_value(&scope.bands),
        ),
    ])
}

/// Fail-closed value-level direction scope decoder (Rescope-narrow payloads).
pub(crate) fn decode_federation_direction_scope_value(
    value: &Value,
) -> Result<FederationDirectionScope> {
    decode_direction_scope_value(value)
}

fn decode_direction_scope_value(value: &Value) -> Result<FederationDirectionScope> {
    let Value::Map(entries) = value else {
        return Err(invalid_pact_scope());
    };
    validate_exact_keys(entries, &FEDERATION_DIRECTION_SCOPE_KEYS)?;
    let scope = FederationDirectionScope {
        worlds: decode_worlds_axis(pact_scope_value(entries, KEY_DIRECTION_WORLDS)?)?,
        facets: decode_facets_axis(pact_scope_value(entries, KEY_DIRECTION_FACETS)?)?,
        bands: decode_bands_axis(pact_scope_value(entries, KEY_DIRECTION_BANDS)?)?,
    };
    scope.validate()?;
    Ok(scope)
}

fn worlds_axis_value(worlds: &FederationScopeWorlds) -> Value {
    match worlds {
        FederationScopeWorlds::All => axis_kind_value(SCOPE_WORLDS_KIND_ALL),
        FederationScopeWorlds::Base => axis_kind_value(SCOPE_WORLDS_KIND_BASE),
        FederationScopeWorlds::Worlds(ids) => Value::Map(vec![
            (
                Value::from(KEY_SCOPE_AXIS_KIND),
                Value::from(SCOPE_WORLDS_KIND_WORLDS),
            ),
            (
                Value::from(KEY_SCOPE_AXIS_IDS),
                Value::Array(ids.iter().map(|id| Value::from(id.to_hex())).collect()),
            ),
        ]),
    }
}

fn facets_axis_value(facets: &FederationScopeFacets) -> Value {
    match facets {
        FederationScopeFacets::All => axis_kind_value(SCOPE_AXIS_KIND_ALL),
        FederationScopeFacets::Bottom => axis_kind_value(SCOPE_AXIS_KIND_BOTTOM),
        FederationScopeFacets::Some(ids) => Value::Map(vec![
            (
                Value::from(KEY_SCOPE_AXIS_KIND),
                Value::from(SCOPE_AXIS_KIND_SOME),
            ),
            (
                Value::from(KEY_SCOPE_AXIS_IDS),
                Value::Array(ids.iter().map(|id| Value::from(id.to_hex())).collect()),
            ),
        ]),
    }
}

fn bands_axis_value(bands: &FederationScopeBands) -> Value {
    match bands {
        FederationScopeBands::All => axis_kind_value(SCOPE_AXIS_KIND_ALL),
        FederationScopeBands::Bottom => axis_kind_value(SCOPE_AXIS_KIND_BOTTOM),
        FederationScopeBands::Some(bands) => Value::Map(vec![
            (
                Value::from(KEY_SCOPE_AXIS_KIND),
                Value::from(SCOPE_AXIS_KIND_SOME),
            ),
            (
                Value::from(KEY_SCOPE_AXIS_IDS),
                Value::Array(
                    bands
                        .iter()
                        .map(|band| Value::from(federation_band_wire(*band)))
                        .collect(),
                ),
            ),
        ]),
    }
}

fn axis_kind_value(kind: &str) -> Value {
    Value::Map(vec![(
        Value::from(KEY_SCOPE_AXIS_KIND),
        Value::from(kind),
    )])
}

fn decode_worlds_axis(value: &Value) -> Result<FederationScopeWorlds> {
    let (kind, ids) = decode_axis_map(value)?;
    match (kind, ids) {
        (SCOPE_WORLDS_KIND_ALL, None) => Ok(FederationScopeWorlds::All),
        (SCOPE_WORLDS_KIND_BASE, None) => Ok(FederationScopeWorlds::Base),
        (SCOPE_WORLDS_KIND_WORLDS, Some(ids)) => {
            Ok(FederationScopeWorlds::Worlds(decode_hex_id_array(ids)?))
        }
        _ => Err(invalid_pact_scope()),
    }
}

fn decode_facets_axis(value: &Value) -> Result<FederationScopeFacets> {
    let (kind, ids) = decode_axis_map(value)?;
    match (kind, ids) {
        (SCOPE_AXIS_KIND_ALL, None) => Ok(FederationScopeFacets::All),
        (SCOPE_AXIS_KIND_BOTTOM, None) => Ok(FederationScopeFacets::Bottom),
        (SCOPE_AXIS_KIND_SOME, Some(ids)) => {
            Ok(FederationScopeFacets::Some(decode_hex_id_array(ids)?))
        }
        _ => Err(invalid_pact_scope()),
    }
}

fn decode_bands_axis(value: &Value) -> Result<FederationScopeBands> {
    let (kind, ids) = decode_axis_map(value)?;
    match (kind, ids) {
        (SCOPE_AXIS_KIND_ALL, None) => Ok(FederationScopeBands::All),
        (SCOPE_AXIS_KIND_BOTTOM, None) => Ok(FederationScopeBands::Bottom),
        (SCOPE_AXIS_KIND_SOME, Some(values)) => {
            let bands = values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .and_then(parse_federation_band_wire)
                        .ok_or_else(invalid_pact_scope)
                })
                .collect::<Result<Vec<TypeByteBand>>>()?;
            Ok(FederationScopeBands::Some(bands))
        }
        _ => Err(invalid_pact_scope()),
    }
}

fn decode_axis_map(value: &Value) -> Result<(&str, Option<&[Value]>)> {
    let Value::Map(entries) = value else {
        return Err(invalid_pact_scope());
    };
    let mut seen = [false; FEDERATION_SCOPE_AXIS_KEYS.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_pact_scope)?;
        let Some(index) = FEDERATION_SCOPE_AXIS_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(invalid_pact_scope());
        };
        if seen[index] {
            return Err(invalid_pact_scope());
        }
        seen[index] = true;
    }
    if !seen[0] {
        return Err(invalid_pact_scope());
    }
    let kind = required_value(entries, KEY_SCOPE_AXIS_KIND)
        .map_err(|_| invalid_pact_scope())?
        .as_str()
        .ok_or_else(invalid_pact_scope)?;
    let ids = if seen[1] {
        let Value::Array(values) = required_value(entries, KEY_SCOPE_AXIS_IDS)
            .map_err(|_| invalid_pact_scope())?
        else {
            return Err(invalid_pact_scope());
        };
        Some(values.as_slice())
    } else {
        None
    };
    Ok((kind, ids))
}

fn decode_hex_id_array(values: &[Value]) -> Result<Vec<EntityId>> {
    values
        .iter()
        .map(|value| {
            let hex = value.as_str().ok_or_else(invalid_pact_scope)?;
            let id = EntityId::from_hex(hex).map_err(|_| invalid_pact_scope())?;
            if id.to_hex() != hex {
                return Err(invalid_pact_scope());
            }
            Ok(id)
        })
        .collect()
}

fn validate_strictly_ascending_ids(ids: &[EntityId]) -> Result<()> {
    if ids.is_empty() {
        return Err(invalid_pact_scope());
    }
    if ids.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        Err(invalid_pact_scope())
    }
}

fn band_order_index(band: TypeByteBand) -> usize {
    FEDERATION_SCOPE_BAND_ORDER
        .iter()
        .position(|known| *known == band)
        .unwrap_or(FEDERATION_SCOPE_BAND_ORDER.len())
}

fn federation_band_wire(band: TypeByteBand) -> &'static str {
    match band {
        TypeByteBand::Semantic => "semantic",
        TypeByteBand::Core => "core",
        TypeByteBand::Companion => "companion",
        TypeByteBand::Productivity => "productivity",
        TypeByteBand::Crm => "crm",
        TypeByteBand::InducedDynamicMaintenance => "maintenance",
    }
}

fn parse_federation_band_wire(value: &str) -> Option<TypeByteBand> {
    match value {
        "semantic" => Some(TypeByteBand::Semantic),
        "core" => Some(TypeByteBand::Core),
        "companion" => Some(TypeByteBand::Companion),
        "productivity" => Some(TypeByteBand::Productivity),
        "crm" => Some(TypeByteBand::Crm),
        "maintenance" => Some(TypeByteBand::InducedDynamicMaintenance),
        _ => None,
    }
}

fn validate_exact_keys(entries: &[(Value, Value)], expected: &[&str]) -> Result<()> {
    let mut seen = vec![false; expected.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_pact_scope)?;
        let Some(index) = expected.iter().position(|known| *known == key) else {
            return Err(invalid_pact_scope());
        };
        if seen[index] {
            return Err(invalid_pact_scope());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid_pact_scope())
    }
}

fn pact_scope_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    required_value(entries, key).map_err(|_| invalid_pact_scope())
}

fn invalid_pact_scope() -> Error {
    Error::InvalidFederationGrantBody("pact scope failed validation")
}

#[cfg(test)]
mod tests;
