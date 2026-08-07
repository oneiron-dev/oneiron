//! Federation grant record substrate.
//!
//! A federation grant is a vault-resident membership record for a shared
//! vault. The body is a pinned MessagePack map with fail-closed decoding:
//! unknown keys, duplicate keys, unknown role/preset strings, unsupported
//! scope kinds, and preset/role mismatches are rejected.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use rmpv::Value;

use crate::authority::{
    AuthorityFold, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthorityVaultId,
    authority_entry_hash, decode_authority_log_entry_body, fold_peer_authority_log,
    folded_peer_device_is_consent_root, genesis_vault_id,
};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::entity_id::{EntityId, bytes_to_hex_lower, is_foreign_world_id_range};
use crate::error::{Error, Result};
use crate::registry::TypeByteBand;
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// Current FederationGrant body schema version.
///
/// Stays 1 across the Delegate tier: the body grew two ROLE-CONDITIONAL keys
/// that only a Delegate carries, so every pre-Delegate body is still exactly a
/// valid current body. A reader on the old five-key set fails CLOSED on a
/// seven-key Delegate body (its key allowlist rejects `expires_at`), which is
/// the desired direction — an old peer never silently reads a delegate grant as
/// a non-expiring one.
pub const FEDERATION_GRANT_SCHEMA_VERSION: u64 = 1;

/// Maximum delegate time-to-live: 90 days.
pub const MAX_DELEGATE_TTL_SECS: u64 = 7_776_000;

/// Pinned ON-DISK MessagePack key set for FEDERATION_GRANT bodies.
///
/// The first [`FEDERATION_GRANT_REQUIRED_KEYS`] entries are required on every
/// body; `expires_at` and `delegated_by` are role-conditional — required for
/// [`FederationGrantRole::Delegate`], forbidden for every other role.
pub const FEDERATION_GRANT_BODY_KEYS: [&str; 7] = [
    "schema_version",
    "scope",
    "member_ref",
    "role",
    "preset",
    "expires_at",
    "delegated_by",
];

/// Count of unconditionally required keys at the head of
/// [`FEDERATION_GRANT_BODY_KEYS`].
const FEDERATION_GRANT_REQUIRED_KEYS: usize = 5;

pub(crate) const FEDERATION_GRANT_FIELDS_MINIMAL: &[&str] = &["scope", "role", "preset"];
pub(crate) const FEDERATION_GRANT_FIELDS_STANDARD: &[&str] =
    &["scope", "member_ref", "role", "preset"];
// Explicit, NOT an alias of the on-disk key set: the body grew to seven keys,
// context-pack hydration deliberately did not. Delegate expiry and parentage
// are authorization facts read at the selector door, not pack content.
pub(crate) const FEDERATION_GRANT_FIELDS_FULL: &[&str] =
    &["schema_version", "scope", "member_ref", "role", "preset"];

const KEY_SCHEMA_VERSION: &str = FEDERATION_GRANT_BODY_KEYS[0];
const KEY_SCOPE: &str = FEDERATION_GRANT_BODY_KEYS[1];
// Stored as EntityId hex so generic context-pack hydration preserves the principal.
const KEY_MEMBER_REF: &str = FEDERATION_GRANT_BODY_KEYS[2];
const KEY_ROLE: &str = FEDERATION_GRANT_BODY_KEYS[3];
const KEY_PRESET: &str = FEDERATION_GRANT_BODY_KEYS[4];
const KEY_EXPIRES_AT: &str = FEDERATION_GRANT_BODY_KEYS[5];
const KEY_DELEGATED_BY: &str = FEDERATION_GRANT_BODY_KEYS[6];

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
    /// One-hop, expiring read privileges attenuated from an admin parent.
    ///
    /// A delegate is never administrative and can never itself delegate, so
    /// the tier cannot self-widen: the only minting path is
    /// [`FederationGrant::attenuated_delegate`] from an [`Self::is_admin`]
    /// parent.
    Delegate,
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
            Self::Delegate => "delegate",
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
            "delegate" => Some(Self::Delegate),
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
    /// Attenuated one-hop delegate envelope.
    Delegate,
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
            Self::Delegate => "delegate",
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
            "delegate" => Some(Self::Delegate),
            _ => None,
        }
    }

    /// Returns whether this preset can carry `role`.
    ///
    /// Delegate is a 1:1 pair, in both directions: the Delegate preset carries
    /// only the Delegate role, and the Delegate role rides only the Delegate
    /// preset — including under Owner, which is otherwise universal. Letting
    /// the Owner envelope carry a Delegate role would hand a delegate the owner
    /// capability set while it still reads as attenuated.
    #[must_use]
    pub const fn permits_role(self, role: FederationGrantRole) -> bool {
        match self {
            Self::Owner => !matches!(role, FederationGrantRole::Delegate),
            Self::Admin => !matches!(
                role,
                FederationGrantRole::Owner | FederationGrantRole::Delegate
            ),
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
            Self::Delegate => matches!(role, FederationGrantRole::Delegate),
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
    /// Unix-seconds instant at which a Delegate grant stops conferring.
    ///
    /// Required for [`FederationGrantRole::Delegate`], forbidden for every
    /// other role.
    pub expires_at: Option<u64>,
    /// `member_ref` of the parent grant this Delegate was attenuated from.
    ///
    /// The PARENT'S PRINCIPAL, not the parent grant's entity id: the delegate
    /// names who delegated, and a grant record can be re-minted while the
    /// principal stays the same. Required for
    /// [`FederationGrantRole::Delegate`], forbidden for every other role.
    pub delegated_by: Option<EntityId>,
}

impl FederationGrant {
    /// Constructs a non-delegate federation grant.
    ///
    /// Both role-conditional fields are `None`, so a `Delegate` role built
    /// through this door fails [`Self::validate`]. Delegates mint only through
    /// [`Self::attenuated_delegate`].
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
            expires_at: None,
            delegated_by: None,
        }
    }

    /// Mints a one-hop delegate attenuated from an administrative `parent`.
    ///
    /// The delegate inherits the parent's scope, names the parent's principal
    /// in `delegated_by`, and expires no later than
    /// [`MAX_DELEGATE_TTL_SECS`] past `now_secs`. Only an
    /// [`FederationGrantRole::is_admin`] parent may delegate, so the chain is
    /// exactly one hop deep and no role can widen itself.
    pub fn attenuated_delegate(
        parent: &FederationGrant,
        member_ref: EntityId,
        now_secs: u64,
        expires_at_secs: u64,
    ) -> Result<Self> {
        parent.validate()?;
        if !parent.role.is_admin() {
            return Err(invalid_grant());
        }
        let ceiling = now_secs
            .checked_add(MAX_DELEGATE_TTL_SECS)
            .ok_or_else(invalid_grant)?;
        if expires_at_secs <= now_secs || expires_at_secs > ceiling {
            return Err(invalid_grant());
        }

        // No re-validation of the freshly built delegate: every `validate`
        // clause holds by construction here (validated parent's scope, the 1:1
        // Delegate role/preset pair, both role-conditional fields `Some`, and
        // `expires_at_secs > now_secs >= 0` rules out zero), and the struct's
        // `pub` fields make any construction-time invariant unenforceable
        // anyway. Encode and decode remain the validating doors.
        Ok(Self {
            scope: parent.scope,
            member_ref,
            role: FederationGrantRole::Delegate,
            preset: FederationGrantPreset::Delegate,
            expires_at: Some(expires_at_secs),
            delegated_by: Some(parent.member_ref),
        })
    }

    /// Validates scope, role/preset policy, and role-conditional field shape.
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        if !self.preset.permits_role(self.role) {
            return Err(invalid_grant());
        }
        let expects_delegation = matches!(self.role, FederationGrantRole::Delegate);
        if expects_delegation != self.expires_at.is_some()
            || expects_delegation != self.delegated_by.is_some()
        {
            return Err(invalid_grant());
        }
        if self.expires_at == Some(0) {
            return Err(invalid_grant());
        }
        Ok(())
    }

    /// Returns whether this grant confers at `now_secs`.
    ///
    /// The expiry second itself DENIES. Grants without an expiry — every
    /// non-delegate role — confer regardless of age.
    #[must_use]
    pub const fn confers_at(&self, now_secs: u64) -> bool {
        match self.expires_at {
            None => true,
            Some(expires_at) => now_secs < expires_at,
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
///
/// A non-delegate emits exactly the five pre-Delegate keys, byte-for-byte as
/// before; a delegate appends `expires_at` and `delegated_by` in
/// [`FEDERATION_GRANT_BODY_KEYS`] order.
pub fn encode_federation_grant_body(grant: &FederationGrant) -> Result<Vec<u8>> {
    grant.validate()?;
    let mut entries = vec![
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
    ];
    if let Some(expires_at) = grant.expires_at {
        entries.push((Value::from(KEY_EXPIRES_AT), Value::from(expires_at)));
    }
    if let Some(delegated_by) = grant.delegated_by {
        entries.push((
            Value::from(KEY_DELEGATED_BY),
            Value::from(delegated_by.to_hex()),
        ));
    }

    encode_msgpack_value(
        &Value::Map(entries),
        "federation grant body MessagePack encode failed",
    )
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

    let expires_at = optional_value(entries, KEY_EXPIRES_AT)
        .map(|value| value.as_u64().ok_or_else(invalid_grant))
        .transpose()?;
    let delegated_by = optional_value(entries, KEY_DELEGATED_BY)
        .map(decode_canonical_entity_ref)
        .transpose()?;

    let grant = FederationGrant {
        scope,
        member_ref,
        role,
        preset,
        expires_at,
        delegated_by,
    };
    // Role-conditional presence is enforced here: a five-key Delegate body and
    // a seven-key Owner body both die at `validate`, not at the key allowlist.
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

/// [`decode_entity_ref`] restricted to the canonical lowercase hex spelling.
///
/// `EntityId::from_hex` is case-insensitive, so an uppercase spelling would
/// re-encode to different bytes than it arrived as. `delegated_by` is a fresh
/// key with no shipped bodies behind it, so it is pinned canonical from the
/// start and the grant body stays byte-stable across a decode/encode round.
fn decode_canonical_entity_ref(value: &Value) -> Result<EntityId> {
    let hex = value.as_str().ok_or_else(invalid_grant)?;
    let id = EntityId::from_hex(hex).map_err(|_| invalid_grant())?;
    if id.to_hex() == hex {
        Ok(id)
    } else {
        Err(invalid_grant())
    }
}

/// Rejects unknown and duplicate keys, and any missing REQUIRED key.
///
/// Presence of the two role-conditional tail keys is not decided here — that
/// is [`FederationGrant::validate`]'s job, because it depends on the role.
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
    if seen[..FEDERATION_GRANT_REQUIRED_KEYS].iter().all(|v| *v) {
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

fn optional_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    optional_value(entries, key).ok_or_else(invalid_grant)
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
            (Self::Worlds(narrow), Self::Worlds(wide)) => narrow.iter().all(|id| wide.contains(id)),
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
                if ascending {
                    Ok(())
                } else {
                    Err(invalid_pact_scope())
                }
            }
        }
    }

    fn is_narrowing_of(&self, ceiling: &Self) -> bool {
        match (self, ceiling) {
            (_, Self::All) => true,
            (Self::Bottom, _) => true,
            (Self::All, _) => false,
            (Self::Some(_), Self::Bottom) => false,
            (Self::Some(narrow), Self::Some(wide)) => narrow.iter().all(|band| wide.contains(band)),
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
    Value::Map(vec![(Value::from(KEY_SCOPE_AXIS_KIND), Value::from(kind))])
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
        let Value::Array(values) =
            required_value(entries, KEY_SCOPE_AXIS_IDS).map_err(|_| invalid_pact_scope())?
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

/// CLAIM predicate binding a grant's `member_ref` to a PERSON entity.
///
/// Deliberately NOT in `CLAIM_PREDICATE_REGISTRY`: the registry is the
/// crate-owned STRUCTURAL schema list, and the generic claim door already
/// accepts a well-formed non-structural predicate. Registering these two would
/// claim a validator seat neither of them needs.
pub const PREDICATE_RELATIONSHIP_PERSON_REF: &str = "core.relationship.person_ref";

/// CLAIM predicate labelling a PERSON entity with a relationship word.
pub const PREDICATE_RELATIONSHIP_LABEL: &str = "core.relationship.label";

/// Maximum byte length of a relationship label.
///
/// The label grammar is ASCII-only, so this bounds the character count too.
pub const MAX_RELATIONSHIP_LABEL_BYTES: usize = 64;

/// Trust class a relationship label resolves to.
///
/// The word lists are FIXED: there is no Unicode folding and no synonym model,
/// so an unrecognized but well-formed label lands on [`Self::Unlabeled`] rather
/// than being guessed into a class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelationshipTrustClass {
    /// Partner-grade closeness.
    Intimate,
    /// Blood or household family.
    Family,
    /// Chosen personal closeness.
    Friend,
    /// Work relationships inside one's own org.
    Professional,
    /// Commercial counterparties.
    Client,
    /// Bound to a person, but with no label in the fixed table.
    Unlabeled,
}

/// Resolved label context for a member bound to a PERSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRelationshipContext {
    /// PERSON entity the member is bound to.
    pub person: EntityId,
    /// Winning label, stored verbatim.
    pub label: String,
    /// CLAIM entity the winning label came from.
    pub label_claim: EntityId,
    /// Trust class [`relationship_trust_class`] maps `label` to.
    pub trust_class: RelationshipTrustClass,
}

/// Relationship state of a federation grant's `member_ref`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberRelationship {
    /// Bound to a person carrying a valid label.
    Labeled(MemberRelationshipContext),
    /// Bound to a person with no valid label claim.
    Unlabeled {
        /// PERSON entity the member is bound to.
        person: EntityId,
    },
    /// No valid person binding.
    Unbound,
}

/// Resolves the relationship a grant's `member_ref` carries.
///
/// Deterministic and agent-independent by construction: the signature takes no
/// actor, so two agent contexts reading the same vault state get the same
/// answer. Person binding wins by (learned_at, claim id) descending; the label
/// on the bound person then prefers Approved over Auto REGARDLESS OF AGE,
/// falling back to (learned_at, claim id) descending. Proposed, Rejected,
/// non-Active, and malformed claims never enter either contest.
///
/// This reads only `member_ref`, so it is total over every
/// [`FederationGrantRole`] — a Delegate resolves exactly like an Owner.
pub fn resolve_member_relationship(
    vault: &Vault,
    member_ref: EntityId,
) -> Result<MemberRelationship> {
    let person = relationship_claims(
        vault,
        member_ref,
        PREDICATE_RELATIONSHIP_PERSON_REF,
        |value| decode_canonical_entity_ref(value).ok(),
    )?
    .into_iter()
    .max_by_key(|claim| (claim.learned_at, claim.claim))
    .map(|claim| claim.payload);

    let Some(person) = person else {
        return Ok(MemberRelationship::Unbound);
    };

    let label = relationship_claims(vault, person, PREDICATE_RELATIONSHIP_LABEL, |value| {
        let label = value.as_str()?;
        is_relationship_label(label).then(|| label.to_owned())
    })?
    .into_iter()
    .max_by_key(|claim| (claim.approved, claim.learned_at, claim.claim));

    let Some(label) = label else {
        return Ok(MemberRelationship::Unlabeled { person });
    };

    let trust_class = relationship_trust_class(&label.payload);
    Ok(MemberRelationship::Labeled(MemberRelationshipContext {
        person,
        label: label.payload,
        label_claim: label.claim,
        trust_class,
    }))
}

/// Maps a relationship label to its trust class.
///
/// The word lists are the pinned table; anything else is
/// [`RelationshipTrustClass::Unlabeled`].
#[must_use]
pub fn relationship_trust_class(label: &str) -> RelationshipTrustClass {
    match label {
        "girlfriend" | "boyfriend" | "partner" | "wife" | "husband" | "spouse" => {
            RelationshipTrustClass::Intimate
        }
        "mother" | "father" | "mom" | "dad" | "parent" | "brother" | "sister" | "sibling"
        | "son" | "daughter" | "family" => RelationshipTrustClass::Family,
        "friend" | "roommate" => RelationshipTrustClass::Friend,
        "coworker" | "colleague" | "manager" | "report" | "boss" | "teammate" => {
            RelationshipTrustClass::Professional
        }
        "client" | "customer" | "vendor" | "contractor" => RelationshipTrustClass::Client,
        _ => RelationshipTrustClass::Unlabeled,
    }
}

/// Default trust tier for a class. Callers may narrow, never widen.
#[must_use]
pub const fn default_trust_tier(class: RelationshipTrustClass) -> u8 {
    match class {
        RelationshipTrustClass::Intimate | RelationshipTrustClass::Family => 3,
        RelationshipTrustClass::Friend => 2,
        RelationshipTrustClass::Professional | RelationshipTrustClass::Client => 1,
        RelationshipTrustClass::Unlabeled => 0,
    }
}

/// Default retrieval bands for a class. Callers may narrow, never widen.
///
/// Client and Professional share a tier but NOT a band set: a client sees Crm,
/// a coworker sees Core.
#[must_use]
pub fn default_retrieval_bands(class: RelationshipTrustClass) -> Vec<TypeByteBand> {
    match class {
        RelationshipTrustClass::Intimate | RelationshipTrustClass::Family => vec![
            TypeByteBand::Semantic,
            TypeByteBand::Core,
            TypeByteBand::Companion,
        ],
        RelationshipTrustClass::Friend => vec![TypeByteBand::Semantic, TypeByteBand::Core],
        RelationshipTrustClass::Professional => vec![
            TypeByteBand::Semantic,
            TypeByteBand::Core,
            TypeByteBand::Productivity,
        ],
        RelationshipTrustClass::Client => vec![
            TypeByteBand::Semantic,
            TypeByteBand::Crm,
            TypeByteBand::Productivity,
        ],
        RelationshipTrustClass::Unlabeled => vec![TypeByteBand::Semantic],
    }
}

/// Writes an Approved person-ref claim binding `member_ref` to `person`.
///
/// `person` is the claim VALUE, not its subject, so the claim door's own
/// subject-existence check never sees it: existence is confirmed HERE, before
/// anything is written. Self-binding (`person == member_ref`) is legal.
pub fn bind_member_person(
    vault: &Vault,
    member_ref: EntityId,
    person: EntityId,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<EntityId> {
    if !vault.entity_exists(&person)? {
        return Err(Error::EntityNotFound);
    }
    put_relationship_claim(
        vault,
        RelationshipClaim {
            predicate: PREDICATE_RELATIONSHIP_PERSON_REF,
            subject: member_ref,
            value: Value::from(person.to_hex()),
            approval: ClaimApprovalStatus::Approved,
        },
        occurred,
        learned_at,
    )
}

/// Writes a relationship label claim on `person`.
///
/// Only Auto and Approved are accepted — a Proposed or Rejected label would be
/// ignored by [`resolve_member_relationship`] anyway, so writing one is a
/// caller error, not a stored no-op.
pub fn put_member_relationship_label(
    vault: &Vault,
    person: EntityId,
    label: &str,
    approval: ClaimApprovalStatus,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<EntityId> {
    if !matches!(
        approval,
        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
    ) || !is_relationship_label(label)
    {
        return Err(invalid_relationship_claim());
    }
    put_relationship_claim(
        vault,
        RelationshipClaim {
            predicate: PREDICATE_RELATIONSHIP_LABEL,
            subject: person,
            value: Value::from(label),
            approval,
        },
        occurred,
        learned_at,
    )
}

/// One valid relationship claim reduced to its precedence key and payload.
struct RelationshipClaimCandidate<T> {
    payload: T,
    claim: EntityId,
    /// Approved outranks Auto on the LABEL axis only; the person-ref contest
    /// ignores this field and orders purely by recency.
    approved: bool,
    learned_at: u64,
}

/// The writable half of a relationship claim, so the two writer doors share one
/// mint-and-put path without a long positional argument list.
struct RelationshipClaim {
    predicate: &'static str,
    subject: EntityId,
    value: Value,
    approval: ClaimApprovalStatus,
}

/// Collects every valid `predicate` claim on `subject`, dropping any whose
/// approval, lifecycle, or value shape disqualifies it.
fn relationship_claims<T>(
    vault: &Vault,
    subject: EntityId,
    predicate: &str,
    parse: impl Fn(&Value) -> Option<T>,
) -> Result<Vec<RelationshipClaimCandidate<T>>> {
    let mut candidates = Vec::new();
    for claim in vault.claims_for_subject(&subject)? {
        let Some(body) = vault.get_claim(&claim)? else {
            continue;
        };
        if body.predicate != predicate || body.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        let approved = match body.approval {
            ClaimApprovalStatus::Approved => true,
            ClaimApprovalStatus::Auto => false,
            ClaimApprovalStatus::Proposed | ClaimApprovalStatus::Rejected => continue,
        };
        let Some(payload) = parse(&body.value) else {
            continue;
        };
        candidates.push(RelationshipClaimCandidate {
            payload,
            claim,
            approved,
            learned_at: vault.get_learned_at(&claim)?,
        });
    }
    Ok(candidates)
}

fn put_relationship_claim(
    vault: &Vault,
    claim: RelationshipClaim,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<EntityId> {
    let id = EntityId::now();
    vault.put_claim(
        &id,
        &ClaimBody::new(
            claim.predicate,
            ClaimSubject::Entity(claim.subject),
            claim.value,
            1.0,
            claim.approval,
            ClaimLifecycleStatus::Active,
        ),
        occurred,
        learned_at,
    )?;
    Ok(id)
}

/// `[a-z_]{1,64}` — the pinned label grammar.
fn is_relationship_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_RELATIONSHIP_LABEL_BYTES
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

fn invalid_relationship_claim() -> Error {
    Error::InvalidClaimBody("relationship claim failed validation")
}

// ---------------------------------------------------------------------------
// Peer authority-log admission (FED-03).
//
// The transport relays canonical AUTHORITY_LOG entry BYTES and nothing else.
// There is no API here that takes a roster, an owner list, or a boolean owner
// assertion: a peer roster is always RECOMPUTED locally by the pure authority
// fold over the bytes we hold. That is the whole trust boundary — a cached
// roster row would be a server-influenceable projection carrying authority
// semantics, so none is kept.
// ---------------------------------------------------------------------------

/// LMDB `sync_state` key prefix for admitted peer authority-log entry bytes.
pub const PEER_AUTHORITY_KEY_PREFIX: &str = "peerauth:";

/// Ceiling on DISTINCT admitted entry hashes per peer vault.
///
/// Distinct HASHES, not admission calls: re-offering a stored entry is
/// idempotent at any size, including at the ceiling.
pub const MAX_PEER_AUTHORITY_ENTRIES_PER_PEER: usize = 4096;

/// `peerauth:{peer_vault_id_hex}:{entry_hash_hex}`.
#[must_use]
pub fn peer_authority_entry_key(peer_vault_id: &[u8; 32], entry_hash: &[u8; 32]) -> String {
    let mut key = peer_authority_prefix(peer_vault_id);
    key.push_str(&bytes_to_hex_lower(entry_hash));
    key
}

/// `peerauth:{peer_vault_id_hex}:` — the scan prefix for ONE peer.
fn peer_authority_prefix(peer_vault_id: &AuthorityVaultId) -> String {
    let mut prefix = String::with_capacity(PEER_AUTHORITY_KEY_PREFIX.len() + 66);
    prefix.push_str(PEER_AUTHORITY_KEY_PREFIX);
    prefix.push_str(&bytes_to_hex_lower(peer_vault_id));
    prefix.push(':');
    prefix
}

/// Admits one canonical peer AUTHORITY_LOG entry body under `peer_vault_id`.
///
/// The order is fixed and every step fails closed: validate the canonical body
/// bytes and decode (one act — the decoder re-encodes, compares, and verifies
/// the embedded origin signature before yielding an entry), derive the entry's
/// OWN vault id and require it to equal the claimed peer, hash the canonical
/// bytes, check the per-peer ceiling, store idempotently.
///
/// Admitted bytes live in `sync_state` only. They never enter type-122 entity
/// storage and never touch the local roster.
pub fn admit_peer_authority_log_entry(
    vault: &Vault,
    peer_vault_id: &AuthorityVaultId,
    bytes: &[u8],
) -> Result<()> {
    let entry = decode_authority_log_entry_body(bytes)?;
    let entry_vault_id = match entry.op {
        // Genesis carries no `vault_id` field — its id IS its content hash.
        AuthorityOp::Genesis { .. } => genesis_vault_id(&entry)?,
        // `validate_shape` (which the decode above ran) already refuses a
        // non-genesis entry without a vault id, so this arm's `None` is
        // structurally unreachable; it resolves to the same refusal rather than
        // to a panic.
        _ => entry.vault_id.ok_or_else(peer_authority_vault_mismatch)?,
    };
    if entry_vault_id != *peer_vault_id {
        return Err(peer_authority_vault_mismatch());
    }
    let key = peer_authority_entry_key(peer_vault_id, &authority_entry_hash(&entry)?);
    let prefix = peer_authority_prefix(peer_vault_id);
    vault.with_write_txn(|wtxn| {
        if vault.store.sync_state.get(wtxn, &key)?.is_some() {
            return Ok(());
        }
        let mut distinct = 0usize;
        for row in vault.store.sync_state.prefix_iter(wtxn, &prefix)? {
            row?;
            distinct += 1;
        }
        if distinct >= MAX_PEER_AUTHORITY_ENTRIES_PER_PEER {
            return Err(Error::InvalidAuthorityLogBody("peer authority log flood"));
        }
        vault.store.sync_state.put(wtxn, &key, bytes)?;
        Ok(())
    })
}

/// Recomputes `peer_vault_id`'s roster from the entries admitted for it.
///
/// The fold must root at the peer we filed the rows under; anything else is a
/// log we cannot attribute, and it is refused rather than reported as a roster.
pub fn peer_authority_roster(
    vault: &Vault,
    peer_vault_id: &AuthorityVaultId,
) -> Result<AuthorityFold> {
    let rtxn = vault.store.env.read_txn()?;
    let fold = fold_peer_authority_log(&peer_authority_entries_in_txn(
        vault,
        &rtxn,
        &peer_authority_prefix(peer_vault_id),
    )?);
    if fold.vault_id != Some(*peer_vault_id) {
        return Err(Error::InvalidAuthorityLogBody(
            "peer authority fold root mismatch",
        ));
    }
    Ok(fold)
}

/// Consent roots of an ADMITTED PEER roster — host key included (host-root).
///
/// Callers: the FED-01 gesture check only. Never feed this back into the local
/// fold; these keys hold no local authority of any kind.
#[must_use]
pub fn peer_consent_roots(fold: &AuthorityFold) -> BTreeSet<AuthorityKey> {
    fold.roster
        .iter()
        .filter(|(_, device)| folded_peer_device_is_consent_root(device))
        .map(|(key, _)| key.clone())
        .collect()
}

/// Every admitted peer's consent-root set, for one local authority fold.
///
/// Discovers the distinct `peerauth:` peers in `sync_state` and refolds each
/// one. A peer whose rows do not fold back to the vault id they were filed
/// under contributes NOTHING — that is the pinned-key-only FED-01 baseline, not
/// a refusal. Which bytes arrive is the relay's choice, and a withheld genesis
/// must never be able to fail the LOCAL fold.
pub(crate) fn admitted_peer_consent_roots_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>> {
    let mut by_peer: BTreeMap<String, Vec<AuthorityLogEntry>> = BTreeMap::new();
    for row in vault
        .store
        .sync_state
        .prefix_iter(txn, PEER_AUTHORITY_KEY_PREFIX)?
    {
        let (key, raw) = row?;
        by_peer
            .entry(peer_authority_row_prefix(&key)?)
            .or_default()
            .push(decode_peer_authority_row(&raw)?);
    }
    let mut roots = BTreeMap::new();
    for (prefix, entries) in by_peer {
        let fold = fold_peer_authority_log(&entries);
        if let Some(vault_id) = fold.vault_id
            && peer_authority_prefix(&vault_id) == prefix
        {
            roots.insert(vault_id, peer_consent_roots(&fold));
        }
    }
    Ok(roots)
}

fn peer_authority_entries_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    prefix: &str,
) -> Result<Vec<AuthorityLogEntry>> {
    let mut entries = Vec::new();
    for row in vault.store.sync_state.prefix_iter(txn, prefix)? {
        let (_key, raw) = row?;
        entries.push(decode_peer_authority_row(&raw)?);
    }
    Ok(entries)
}

/// Decodes one STORED peer row.
///
/// These bytes already passed admission, so a decode failure here is local
/// storage corruption, not a bad peer body — and it propagates. Skipping the
/// row would silently hand back a roster folded over a subset of what we hold,
/// which is exactly the shape an attacker with write access would want.
fn decode_peer_authority_row(raw: &[u8]) -> Result<AuthorityLogEntry> {
    decode_authority_log_entry_body(raw)
        .map_err(|_| Error::CorruptedIndex("peer authority log row"))
}

/// `peerauth:{peer}:` — the grouping prefix of one stored row's key.
///
/// Derived by position rather than by parsing hex: the id itself comes back
/// from the fold, and re-deriving the prefix from THAT is what proves the rows
/// were filed under the vault they actually root at.
fn peer_authority_row_prefix(key: &str) -> Result<String> {
    let end = key
        .match_indices(':')
        .nth(1)
        .map(|(index, _)| index + 1)
        .ok_or(Error::CorruptedIndex("peer authority log row key"))?;
    Ok(key[..end].to_owned())
}

fn peer_authority_vault_mismatch() -> Error {
    Error::InvalidAuthorityLogBody("peer authority log vault id")
}

#[cfg(test)]
mod tests;
