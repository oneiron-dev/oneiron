//! Federation grant record, role/preset policy, and grant body MessagePack codec.

use std::collections::BTreeSet;
use std::io::Cursor;

use rmpv::Value;

use super::codec::{
    decode_canonical_entity_ref, decode_entity_ref, encode_msgpack_value, optional_value,
    required_value,
};

use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};

/// Current FederationGrant body schema version.
///
/// Version 3 adds a role-conditional guest payload. The existing schema-1
/// decoder remains; no new pre-release schema-2 compatibility path is added.
pub const FEDERATION_GRANT_SCHEMA_VERSION: u64 = 3;

const FEDERATION_GRANT_LEGACY_SCHEMA_VERSION: u64 = 1;

/// Maximum delegate time-to-live: 90 days.
pub const MAX_DELEGATE_TTL_SECS: u64 = 7_776_000;

/// Pinned ON-DISK MessagePack key set for FEDERATION_GRANT bodies.
///
/// The first `FEDERATION_GRANT_REQUIRED_KEYS` entries are required on every
/// body; `expires_at` and `delegated_by` are role-conditional — required for
/// [`FederationGrantRole::Delegate`], forbidden for every other role. `guest`
/// is required only for [`FederationGrantRole::Guest`].
pub const FEDERATION_GRANT_BODY_KEYS: [&str; 9] = [
    "schema_version",
    "scope",
    "member_ref",
    "role",
    "preset",
    "expires_at",
    "delegated_by",
    "authority_scope",
    "guest",
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

pub(super) const KEY_SCHEMA_VERSION: &str = FEDERATION_GRANT_BODY_KEYS[0];

pub(super) const KEY_SCOPE: &str = FEDERATION_GRANT_BODY_KEYS[1];

// Stored as EntityId hex so generic context-pack hydration preserves the principal.
pub(super) const KEY_MEMBER_REF: &str = FEDERATION_GRANT_BODY_KEYS[2];

pub(super) const KEY_ROLE: &str = FEDERATION_GRANT_BODY_KEYS[3];

pub(super) const KEY_PRESET: &str = FEDERATION_GRANT_BODY_KEYS[4];

pub(super) const KEY_EXPIRES_AT: &str = FEDERATION_GRANT_BODY_KEYS[5];

pub(super) const KEY_DELEGATED_BY: &str = FEDERATION_GRANT_BODY_KEYS[6];

pub(super) const KEY_GUEST: &str = FEDERATION_GRANT_BODY_KEYS[8];

pub(super) const FEDERATION_GRANT_SCOPE_KEYS: [&str; 2] = ["kind", "vault_id"];

const FEDERATION_GRANT_ASK_SCOPE_KEYS: [&str; 2] = ["kind", "ask_ref"];

pub(super) const SCOPE_KIND_VAULT: &str = "vault";

const SCOPE_KIND_ASK: &str = "ask";

/// Wire/resource-safety maximum for one guest grant body, not a policy grant.
/// Ask-class disclosure limits can narrow this bound but never widen it.
pub const MAX_GUEST_DISCLOSED_REFS: usize = 64;

const GUEST_SCOPE_KEYS: [&str; 3] = ["person_ref", "asker_ref", "disclosed_refs"];

/// Scope addressed by a federation grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FederationGrantScope {
    /// Membership in a shared vault.
    Vault { vault_id: u64 },
    /// Access to facts explicitly disclosed for one ask.
    Ask { ask_ref: EntityId },
}

impl FederationGrantScope {
    /// Constructs a shared-vault scope.
    #[must_use]
    pub const fn vault(vault_id: u64) -> Self {
        Self::Vault { vault_id }
    }

    /// Constructs a scope bound to exactly one ask.
    #[must_use]
    pub const fn ask(ask_ref: EntityId) -> Self {
        Self::Ask { ask_ref }
    }

    pub(super) fn validate(self) -> Result<()> {
        match self {
            Self::Vault { vault_id: 0 } => Err(invalid_grant()),
            Self::Vault { .. } | Self::Ask { .. } => Ok(()),
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
    /// Read/propose-only access to explicitly disclosed facts for one ask.
    Guest,
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
            Self::Guest => "guest",
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
            "guest" => Some(Self::Guest),
            _ => None,
        }
    }

    /// Returns whether this role can administer membership or policy.
    #[must_use]
    pub const fn is_admin(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    /// Returns whether this role is the isolated ask-scoped guest role.
    #[must_use]
    pub const fn is_guest(self) -> bool {
        matches!(self, Self::Guest)
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
    /// Ask-scoped read/propose-only guest envelope.
    Guest,
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
            Self::Guest => "guest",
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
            "guest" => Some(Self::Guest),
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
            Self::Owner => !matches!(
                role,
                FederationGrantRole::Delegate | FederationGrantRole::Guest
            ),
            Self::Admin => !matches!(
                role,
                FederationGrantRole::Owner
                    | FederationGrantRole::Delegate
                    | FederationGrantRole::Guest
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
            Self::Guest => matches!(role, FederationGrantRole::Guest),
        }
    }
}

/// Bounded identity and fact allowlist carried only by ask-scoped guest grants.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FederationGrantGuestPayload {
    /// Person whose facts are disclosed for the ask.
    pub person_ref: EntityId,
    /// Actor who asked for the disclosed facts.
    pub asker_ref: EntityId,
    /// Exact fact entities disclosed to this guest.
    pub disclosed_refs: BTreeSet<EntityId>,
}

impl FederationGrantGuestPayload {
    fn validate(&self) -> Result<()> {
        if self.disclosed_refs.is_empty() || self.disclosed_refs.len() > MAX_GUEST_DISCLOSED_REFS {
            return Err(invalid_grant());
        }
        Ok(())
    }
}

/// Federation grant record. Member grants address a shared vault; guest grants
/// carry a separate, ask-scoped payload and cannot act as shared membership.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FederationGrant {
    /// Canonical grant authority. Resource fields below are narrowing presets.
    pub authority_scope: crate::federation::Scope,
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
    /// Ask guest bindings and explicit fact allowlist; absent on every member grant.
    pub guest: Option<FederationGrantGuestPayload>,
}

impl FederationGrant {
    /// Constructs a non-delegate federation grant.
    ///
    /// Both role-conditional fields are `None`, so a `Delegate` role built
    /// through this door fails [`Self::validate`]. Delegates mint only through
    /// [`Self::attenuated_delegate`].
    #[must_use]
    pub fn new(
        scope: FederationGrantScope,
        member_ref: EntityId,
        role: FederationGrantRole,
        preset: FederationGrantPreset,
    ) -> Self {
        Self {
            authority_scope: super::grant_scope::membership_preset(role),
            scope,
            member_ref,
            role,
            preset,
            expires_at: None,
            delegated_by: None,
            guest: None,
        }
    }

    /// Mints a guest grant restricted to one ask and a non-empty bounded fact set.
    pub fn ask_guest(
        group_ref: EntityId,
        companion_ref: EntityId,
        person_ref: EntityId,
        asker_ref: EntityId,
        disclosed_refs: BTreeSet<EntityId>,
    ) -> Result<Self> {
        let grant = Self {
            authority_scope: guest_authority_scope(),
            scope: FederationGrantScope::Ask { ask_ref: group_ref },
            member_ref: companion_ref,
            role: FederationGrantRole::Guest,
            preset: FederationGrantPreset::Guest,
            expires_at: None,
            delegated_by: None,
            guest: Some(FederationGrantGuestPayload {
                person_ref,
                asker_ref,
                disclosed_refs,
            }),
        };
        grant.validate()?;
        Ok(grant)
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
            authority_scope: parent.authority_scope.clone(),
            scope: parent.scope,
            member_ref,
            role: FederationGrantRole::Delegate,
            preset: FederationGrantPreset::Delegate,
            expires_at: Some(expires_at_secs),
            delegated_by: Some(parent.member_ref),
            guest: None,
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
        let is_guest = self.role.is_guest();
        if is_guest != self.guest.is_some() {
            return Err(invalid_grant());
        }
        if self.role.is_guest() {
            let (FederationGrantScope::Ask { .. }, Some(guest)) = (self.scope, self.guest.as_ref())
            else {
                return Err(invalid_grant());
            };
            guest.validate()?;
            if self.authority_scope != guest_authority_scope() {
                return Err(invalid_grant());
            }
        } else if matches!(self.scope, FederationGrantScope::Ask { .. }) {
            return Err(invalid_grant());
        }
        Ok(())
    }

    /// Returns whether this grant confers at `now_secs`.
    ///
    /// The expiry second itself DENIES. Grants without an expiry — every
    /// non-delegate role — confer regardless of age.
    #[must_use]
    pub fn confers_at(&self, now_secs: u64) -> bool {
        if !self.authority_scope.verbs.contains(&"read".to_owned())
            || self.authority_scope.worlds.is_bottom()
            || self.authority_scope.bands.is_bottom()
            || self.authority_scope.audience.is_bottom()
            || self.authority_scope.sensitivity == super::SensitivityCeiling::Bottom
        {
            return false;
        }
        match self.expires_at {
            None => true,
            Some(expires_at) => now_secs < expires_at,
        }
    }

    /// Returns whether this grant carries an administrative role.
    #[must_use]
    pub fn is_admin(&self) -> bool {
        super::grant_scope::admits_preset(&self.authority_scope, "admin") && self.role.is_admin()
    }

    /// Returns whether this valid guest grant names `fact` for the exact ask,
    /// guest actor, person, and asker tuple. The disclosed set is not transitive.
    #[must_use]
    pub fn allows_ask_fact(
        &self,
        group_ref: EntityId,
        companion_ref: EntityId,
        person_ref: EntityId,
        asker_ref: EntityId,
        fact: EntityId,
    ) -> bool {
        self.validate().is_ok()
            && self.role.is_guest()
            && self.scope == FederationGrantScope::Ask { ask_ref: group_ref }
            && self.member_ref == companion_ref
            && self.guest.as_ref().is_some_and(|guest| {
                guest.person_ref == person_ref
                    && guest.asker_ref == asker_ref
                    && guest.disclosed_refs.contains(&fact)
            })
    }
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
            "authority_scope".into(),
            super::scope_codec::encode_scope_value(&grant.authority_scope)?,
        ),
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
    if let Some(guest) = &grant.guest {
        entries.push((Value::from(KEY_GUEST), encode_guest_payload(guest)));
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

    let schema_version = required_value(entries, KEY_SCHEMA_VERSION)?
        .as_u64()
        .ok_or_else(invalid_grant)?;
    if !matches!(
        schema_version,
        FEDERATION_GRANT_LEGACY_SCHEMA_VERSION | FEDERATION_GRANT_SCHEMA_VERSION
    ) {
        return Err(invalid_grant());
    }
    let legacy = schema_version == FEDERATION_GRANT_LEGACY_SCHEMA_VERSION;
    validate_body_keys(entries, schema_version)?;
    if !legacy && optional_value(entries, "authority_scope").is_none() {
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
    let guest = optional_value(entries, KEY_GUEST)
        .map(decode_guest_payload)
        .transpose()?;

    let grant = FederationGrant {
        authority_scope: if legacy {
            super::grant_scope::membership_preset(role)
        } else {
            super::scope_codec::decode_scope_value(required_value(entries, "authority_scope")?)
                .map_err(|_| invalid_grant())?
        },
        scope,
        member_ref,
        role,
        preset,
        expires_at,
        delegated_by,
        guest,
    };
    // Role-conditional presence is enforced here: a five-key Delegate body and
    // a seven-key Owner body both die at `validate`, not at the key allowlist.
    grant.validate()?;
    Ok(grant)
}

pub(crate) fn encode_scope(scope: FederationGrantScope) -> Value {
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
        FederationGrantScope::Ask { ask_ref } => Value::Map(vec![
            (
                Value::from(FEDERATION_GRANT_ASK_SCOPE_KEYS[0]),
                Value::from(SCOPE_KIND_ASK),
            ),
            (
                Value::from(FEDERATION_GRANT_ASK_SCOPE_KEYS[1]),
                Value::from(ask_ref.to_hex()),
            ),
        ]),
    }
}

fn decode_scope(value: &Value) -> Result<FederationGrantScope> {
    let Value::Map(entries) = value else {
        return Err(invalid_grant());
    };
    let kind = required_value(entries, "kind")?
        .as_str()
        .ok_or_else(invalid_grant)?;
    match kind {
        SCOPE_KIND_VAULT => {
            validate_scope_keys(entries, &FEDERATION_GRANT_SCOPE_KEYS)?;
            let vault_id = required_value(entries, "vault_id")?
                .as_u64()
                .ok_or_else(invalid_grant)?;
            let scope = FederationGrantScope::Vault { vault_id };
            scope.validate()?;
            Ok(scope)
        }
        SCOPE_KIND_ASK => {
            validate_scope_keys(entries, &FEDERATION_GRANT_ASK_SCOPE_KEYS)?;
            Ok(FederationGrantScope::Ask {
                ask_ref: decode_canonical_entity_ref(required_value(entries, "ask_ref")?)?,
            })
        }
        _ => Err(invalid_grant()),
    }
}

fn encode_guest_payload(guest: &FederationGrantGuestPayload) -> Value {
    Value::Map(vec![
        (
            Value::from(GUEST_SCOPE_KEYS[0]),
            Value::from(guest.person_ref.to_hex()),
        ),
        (
            Value::from(GUEST_SCOPE_KEYS[1]),
            Value::from(guest.asker_ref.to_hex()),
        ),
        (
            Value::from(GUEST_SCOPE_KEYS[2]),
            Value::Array(
                guest
                    .disclosed_refs
                    .iter()
                    .map(|id| Value::from(id.to_hex()))
                    .collect(),
            ),
        ),
    ])
}

fn decode_guest_payload(value: &Value) -> Result<FederationGrantGuestPayload> {
    let Value::Map(entries) = value else {
        return Err(invalid_grant());
    };
    validate_scope_keys(entries, &GUEST_SCOPE_KEYS)?;
    let person_ref = decode_canonical_entity_ref(required_value(entries, GUEST_SCOPE_KEYS[0])?)?;
    let asker_ref = decode_canonical_entity_ref(required_value(entries, GUEST_SCOPE_KEYS[1])?)?;
    let Value::Array(disclosed) = required_value(entries, GUEST_SCOPE_KEYS[2])? else {
        return Err(invalid_grant());
    };
    if disclosed.is_empty() || disclosed.len() > MAX_GUEST_DISCLOSED_REFS {
        return Err(invalid_grant());
    }
    let mut disclosed_refs = BTreeSet::new();
    for value in disclosed {
        if !disclosed_refs.insert(decode_canonical_entity_ref(value)?) {
            return Err(invalid_grant());
        }
    }
    Ok(FederationGrantGuestPayload {
        person_ref,
        asker_ref,
        disclosed_refs,
    })
}

fn validate_scope_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
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

/// Rejects unknown and duplicate keys, and any missing REQUIRED key.
///
/// Presence of the two role-conditional tail keys is not decided here — that
/// is [`FederationGrant::validate`]'s job, because it depends on the role.
/// A schema-1 body must not carry `authority_scope`: legacy decodes to the
/// role's membership preset, so accepting a carried value would silently
/// widen a narrowed scope.
fn validate_body_keys(entries: &[(Value, Value)], schema_version: u64) -> Result<()> {
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
        // Schema 1 is the original five-key shape; only the current schema
        // can carry the guest payload.
        if schema_version == FEDERATION_GRANT_LEGACY_SCHEMA_VERSION && index >= 7 {
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

fn guest_authority_scope() -> super::Scope {
    let mut scope = super::Scope::top();
    scope.verbs = super::ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "propose".to_owned()]));
    scope
}

pub(super) fn invalid_grant() -> Error {
    Error::Record(RecordError::InvalidFederationGrantBody(
        "body failed validation",
    ))
}
