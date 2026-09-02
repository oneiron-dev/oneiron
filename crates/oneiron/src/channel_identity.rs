//! ChannelIdentity record substrate (OF-347 CID-1).
//!
//! A ChannelIdentity is a vault-resident engine record plus a typed
//! `channel_identity.*` claim family. Provisioning verbs, provider adapters,
//! reputation scoring, and manifest contents are intentionally outside this
//! module; CID-1 pins the primitive shape and lifecycle invariants only.

use std::io::Cursor;

use rmpv::Value;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Vault;
use crate::batch::BatchOp;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::batch::EntityMetadataHeader;
use crate::batch::apply_ops;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, MAX_PREDICATE_BYTES,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY;
use crate::temporal::TimeRange;
use crate::vault::entity_id_from_type_index_key;

/// Current ChannelIdentity body schema version for the three self-held shapes.
///
/// This stays `1` on purpose. A `delegated_grant` row carries two extra keys
/// and encodes at [`CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION`]; every
/// self-held row keeps encoding the exact head bytes, so every body written
/// before INB-00 decodes unchanged.
pub const CHANNEL_IDENTITY_SCHEMA_VERSION: u64 = 1;

/// ChannelIdentity body schema version for `delegated_grant` rows (INB-00).
///
/// Only the fourth shape uses it. The version is what selects the pinned key
/// set at decode, so the two shapes' key sets can never be mixed.
pub const CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION: u64 = 2;

/// Minimum self-hold window for a quarantined released identity (90 days).
pub const CHANNEL_IDENTITY_MIN_QUARANTINE_SECS: u64 = 90 * 24 * 60 * 60;

/// Pinned on-disk MessagePack key set for ChannelIdentity bodies.
pub const CHANNEL_IDENTITY_BODY_KEYS: [&str; 12] = [
    "schema_version",
    "channel",
    "address_or_handle",
    "shape",
    "binding_scope",
    "binding_target",
    "state",
    "pending_fulfillment",
    "state_changed_at",
    "quarantine_until",
    "reputation_ref",
    "manifest_ref",
];

/// Pinned on-disk MessagePack key set for `delegated_grant` bodies.
///
/// The twelve self-held keys in the same order, then the two custody keys.
/// `delegated_grant_ref` is a custody record NAME; no token bytes are ever
/// written here.
pub const CHANNEL_IDENTITY_DELEGATED_BODY_KEYS: [&str; 14] = [
    CHANNEL_IDENTITY_BODY_KEYS[0],
    CHANNEL_IDENTITY_BODY_KEYS[1],
    CHANNEL_IDENTITY_BODY_KEYS[2],
    CHANNEL_IDENTITY_BODY_KEYS[3],
    CHANNEL_IDENTITY_BODY_KEYS[4],
    CHANNEL_IDENTITY_BODY_KEYS[5],
    CHANNEL_IDENTITY_BODY_KEYS[6],
    CHANNEL_IDENTITY_BODY_KEYS[7],
    CHANNEL_IDENTITY_BODY_KEYS[8],
    CHANNEL_IDENTITY_BODY_KEYS[9],
    CHANNEL_IDENTITY_BODY_KEYS[10],
    CHANNEL_IDENTITY_BODY_KEYS[11],
    "delegated_grant_ref",
    "grant_scopes",
];

const KEY_SCHEMA_VERSION: &str = CHANNEL_IDENTITY_BODY_KEYS[0];
const KEY_CHANNEL: &str = CHANNEL_IDENTITY_BODY_KEYS[1];
const KEY_ADDRESS_OR_HANDLE: &str = CHANNEL_IDENTITY_BODY_KEYS[2];
const KEY_SHAPE: &str = CHANNEL_IDENTITY_BODY_KEYS[3];
const KEY_BINDING_SCOPE: &str = CHANNEL_IDENTITY_BODY_KEYS[4];
const KEY_BINDING_TARGET: &str = CHANNEL_IDENTITY_BODY_KEYS[5];
const KEY_STATE: &str = CHANNEL_IDENTITY_BODY_KEYS[6];
const KEY_PENDING_FULFILLMENT: &str = CHANNEL_IDENTITY_BODY_KEYS[7];
const KEY_STATE_CHANGED_AT: &str = CHANNEL_IDENTITY_BODY_KEYS[8];
const KEY_QUARANTINE_UNTIL: &str = CHANNEL_IDENTITY_BODY_KEYS[9];
const KEY_REPUTATION_REF: &str = CHANNEL_IDENTITY_BODY_KEYS[10];
const KEY_MANIFEST_REF: &str = CHANNEL_IDENTITY_BODY_KEYS[11];
const KEY_DELEGATED_GRANT_REF: &str = CHANNEL_IDENTITY_DELEGATED_BODY_KEYS[12];
const KEY_GRANT_SCOPES: &str = CHANNEL_IDENTITY_DELEGATED_BODY_KEYS[13];

/// Pinned `channel_identity.*` claim predicates for the CID-1 record fields.
pub const CHANNEL_IDENTITY_CLAIM_PREDICATES: [&str; 11] = [
    PREDICATE_CHANNEL_IDENTITY_CHANNEL,
    PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE,
    PREDICATE_CHANNEL_IDENTITY_SHAPE,
    PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE,
    PREDICATE_CHANNEL_IDENTITY_BINDING_TARGET,
    PREDICATE_CHANNEL_IDENTITY_STATE,
    PREDICATE_CHANNEL_IDENTITY_PENDING_FULFILLMENT,
    PREDICATE_CHANNEL_IDENTITY_STATE_CHANGED_AT,
    PREDICATE_CHANNEL_IDENTITY_QUARANTINE_UNTIL,
    PREDICATE_CHANNEL_IDENTITY_REPUTATION_REF,
    PREDICATE_CHANNEL_IDENTITY_MANIFEST_REF,
];

pub const PREDICATE_CHANNEL_IDENTITY_CHANNEL: &str = "channel_identity.channel";
pub const PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE: &str = "channel_identity.address_or_handle";
pub const PREDICATE_CHANNEL_IDENTITY_SHAPE: &str = "channel_identity.shape";
pub const PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE: &str = "channel_identity.binding_scope";
pub const PREDICATE_CHANNEL_IDENTITY_BINDING_TARGET: &str = "channel_identity.binding_target";
pub const PREDICATE_CHANNEL_IDENTITY_STATE: &str = "channel_identity.state";
pub const PREDICATE_CHANNEL_IDENTITY_PENDING_FULFILLMENT: &str =
    "channel_identity.pending_fulfillment";
pub const PREDICATE_CHANNEL_IDENTITY_STATE_CHANGED_AT: &str = "channel_identity.state_changed_at";
pub const PREDICATE_CHANNEL_IDENTITY_QUARANTINE_UNTIL: &str = "channel_identity.quarantine_until";
pub const PREDICATE_CHANNEL_IDENTITY_REPUTATION_REF: &str = "channel_identity.reputation_ref";
pub const PREDICATE_CHANNEL_IDENTITY_MANIFEST_REF: &str = "channel_identity.manifest_ref";

const MAX_CHANNEL_BYTES: usize = 64;
const MAX_ADDRESS_OR_HANDLE_BYTES: usize = 512;
const MAX_DELEGATED_GRANT_REF_BYTES: usize = 256;
const MAX_DELEGATED_GRANT_SCOPES: usize = 8;

/// ChannelIdentity addressability shape (OF-347 R1, ARCH-0063 R2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ChannelIdentityShape {
    DedicatedAddress,
    DedicatedHandle,
    SharedPresence,
    /// A member/owner mailbox held under a scoped-read OAuth grant.
    ///
    /// The product never mints, owns, rotates, or quarantines the underlying
    /// account: it holds a custody record ref and reads. Routing, receipts,
    /// health claims, and manifests never special-case this shape.
    DelegatedGrant,
}

impl ChannelIdentityShape {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DedicatedAddress => "dedicated_address",
            Self::DedicatedHandle => "dedicated_handle",
            Self::SharedPresence => "shared_presence",
            Self::DelegatedGrant => "delegated_grant",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "dedicated_address" => Some(Self::DedicatedAddress),
            "dedicated_handle" => Some(Self::DedicatedHandle),
            "shared_presence" => Some(Self::SharedPresence),
            "delegated_grant" => Some(Self::DelegatedGrant),
            _ => None,
        }
    }

    /// Whether the product itself holds the underlying account.
    ///
    /// False only for [`Self::DelegatedGrant`], where the member's provider
    /// owns creation, rotation, and revocation.
    #[must_use]
    pub const fn is_self_held(self) -> bool {
        !matches!(self, Self::DelegatedGrant)
    }
}

/// Read-only OAuth scope classes a `delegated_grant` row may carry.
///
/// There is deliberately no send, reply, delete, or modify variant. Scoped-read
/// is not a policy setting that a caller could widen: the absence of the variant
/// is what makes a delegated row structurally incapable of naming a write scope,
/// including through a decoded body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DelegatedGrantScope {
    /// Read message bodies in the granted mailbox.
    MailRead,
    /// Read message headers/metadata only.
    MailMetadata,
}

impl DelegatedGrantScope {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MailRead => "mail.read",
            Self::MailMetadata => "mail.metadata",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "mail.read" => Some(Self::MailRead),
            "mail.metadata" => Some(Self::MailMetadata),
            _ => None,
        }
    }
}

/// The custody handle a `delegated_grant` row carries.
///
/// This is a custody record NAME plus the read scopes the grant covers. The
/// OAuth access/refresh token bytes live in the custody record and are reachable
/// only through the SECRET-02 door/lease API under an effector binding; they
/// never land on this struct, on the encoded body, or on any claim derived
/// from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedGrant {
    /// Custody record name (`Vault::resolve_secret_ref` key), never a token.
    pub custody_record_ref: String,
    /// Read scopes the grant covers; non-empty, deduplicated.
    pub scopes: Vec<DelegatedGrantScope>,
}

impl DelegatedGrant {
    /// Builds a delegated grant handle from a custody record name and scopes.
    #[must_use]
    pub fn new(custody_record_ref: impl Into<String>, scopes: Vec<DelegatedGrantScope>) -> Self {
        Self {
            custody_record_ref: custody_record_ref.into(),
            scopes,
        }
    }

    fn validate(&self) -> Result<()> {
        validate_non_empty_bounded(
            &self.custody_record_ref,
            MAX_DELEGATED_GRANT_REF_BYTES,
            "delegated_grant_ref must be a non-empty custody record name of at most 256 bytes",
        )?;
        if self.scopes.is_empty() || self.scopes.len() > MAX_DELEGATED_GRANT_SCOPES {
            return Err(Error::InvalidChannelIdentityBody(
                "delegated grant must declare 1..=8 read scopes",
            ));
        }
        for (index, scope) in self.scopes.iter().enumerate() {
            if self.scopes[..index].contains(scope) {
                return Err(Error::InvalidChannelIdentityBody(
                    "delegated grant scopes must not repeat",
                ));
            }
        }
        Ok(())
    }
}

impl Serialize for ChannelIdentityShape {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ChannelIdentityShape {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).ok_or_else(|| {
            serde::de::Error::custom(format!("unknown channel identity shape {value:?}"))
        })
    }
}

/// Scope at which an identity is bound (OF-347 R2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChannelIdentityBinding {
    Agent { agent_ref: EntityId },
    Vault { vault_id: u64 },
}

impl ChannelIdentityBinding {
    #[must_use]
    pub const fn agent(agent_ref: EntityId) -> Self {
        Self::Agent { agent_ref }
    }

    #[must_use]
    pub const fn vault(vault_id: u64) -> Self {
        Self::Vault { vault_id }
    }

    #[must_use]
    pub const fn scope_str(self) -> &'static str {
        match self {
            Self::Agent { .. } => "agent",
            Self::Vault { .. } => "vault",
        }
    }

    fn validate(self) -> Result<()> {
        match self {
            Self::Agent { .. } => Ok(()),
            Self::Vault { vault_id: 0 } => Err(invalid_identity()),
            Self::Vault { .. } => Ok(()),
        }
    }
}

/// Async fulfillment lane for PENDING_FULFILLMENT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChannelIdentityFulfillment {
    Api,
    Manual,
    Review,
}

impl ChannelIdentityFulfillment {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Manual => "manual",
            Self::Review => "review",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "api" => Some(Self::Api),
            "manual" => Some(Self::Manual),
            "review" => Some(Self::Review),
            _ => None,
        }
    }
}

/// ChannelIdentity lifecycle state (OF-347 R3/R5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChannelIdentityState {
    Requested,
    PendingFulfillment,
    Active,
    Rotating,
    Released,
    Quarantine,
    Tombstone,
}

impl ChannelIdentityState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::PendingFulfillment => "pending_fulfillment",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Released => "released",
            Self::Quarantine => "quarantine",
            Self::Tombstone => "tombstone",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "requested" => Some(Self::Requested),
            "pending_fulfillment" => Some(Self::PendingFulfillment),
            "active" => Some(Self::Active),
            "rotating" => Some(Self::Rotating),
            "released" => Some(Self::Released),
            "quarantine" => Some(Self::Quarantine),
            "tombstone" => Some(Self::Tombstone),
            _ => None,
        }
    }

    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Requested, Self::PendingFulfillment)
                | (Self::PendingFulfillment, Self::Active)
                | (Self::Active, Self::Rotating)
                | (Self::Rotating, Self::Active)
                | (Self::Active, Self::Released)
                | (Self::Rotating, Self::Released)
                | (Self::Released, Self::Quarantine)
                | (Self::Quarantine, Self::Tombstone)
        )
    }
}

/// Vault-resident ChannelIdentity record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentity {
    pub channel: String,
    pub address_or_handle: String,
    pub shape: ChannelIdentityShape,
    pub binding: ChannelIdentityBinding,
    pub state: ChannelIdentityState,
    pub pending_fulfillment: Option<ChannelIdentityFulfillment>,
    pub state_changed_at: u64,
    pub quarantine_until: Option<u64>,
    pub reputation_ref: Option<EntityId>,
    pub manifest_ref: Option<EntityId>,
    /// Present exactly when `shape` is [`ChannelIdentityShape::DelegatedGrant`].
    ///
    /// The one-to-one tie is enforced by [`ChannelIdentity::validate`], so a
    /// delegated row without custody, or a self-held row carrying custody,
    /// cannot be built, encoded, or decoded.
    pub delegated_grant: Option<DelegatedGrant>,
}

impl ChannelIdentity {
    /// Constructs a requested identity row before provider fulfillment starts.
    #[must_use]
    pub fn requested(
        channel: impl Into<String>,
        address_or_handle: impl Into<String>,
        shape: ChannelIdentityShape,
        binding: ChannelIdentityBinding,
        requested_at: u64,
    ) -> Self {
        Self {
            channel: channel.into(),
            address_or_handle: address_or_handle.into(),
            shape,
            binding,
            state: ChannelIdentityState::Requested,
            pending_fulfillment: None,
            state_changed_at: requested_at,
            quarantine_until: None,
            reputation_ref: None,
            manifest_ref: None,
            delegated_grant: None,
        }
    }

    /// Constructs a requested `delegated_grant` row over a member-held mailbox.
    ///
    /// `grant` names an already-granted custody record; this constructor does
    /// not mint, rotate, or read it. The caller proves the record exists with a
    /// covering binding before provisioning (see the Gmail adapter).
    #[must_use]
    pub fn requested_delegated(
        channel: impl Into<String>,
        address_or_handle: impl Into<String>,
        binding: ChannelIdentityBinding,
        grant: DelegatedGrant,
        requested_at: u64,
    ) -> Self {
        Self {
            delegated_grant: Some(grant),
            ..Self::requested(
                channel,
                address_or_handle,
                ChannelIdentityShape::DelegatedGrant,
                binding,
                requested_at,
            )
        }
    }

    /// Constructs the pre-provisioned own-app home-channel identity for an agent.
    #[must_use]
    pub fn own_app_home(agent_ref: EntityId, created_at: u64) -> Self {
        Self {
            channel: "own_app".to_owned(),
            address_or_handle: format!("own_app:{}", agent_ref.to_hex()),
            shape: ChannelIdentityShape::DedicatedHandle,
            binding: ChannelIdentityBinding::agent(agent_ref),
            state: ChannelIdentityState::Active,
            pending_fulfillment: None,
            state_changed_at: created_at,
            quarantine_until: None,
            reputation_ref: None,
            manifest_ref: None,
            delegated_grant: None,
        }
    }

    /// Returns the uniqueness key used for never-recycle enforcement.
    #[must_use]
    pub fn assignment_key(&self) -> (&str, &str) {
        (&self.channel, &self.address_or_handle)
    }

    /// Whether this row is a member-held mailbox under a scoped-read grant.
    #[must_use]
    pub const fn is_delegated(&self) -> bool {
        matches!(self.shape, ChannelIdentityShape::DelegatedGrant)
    }

    /// Validates CID-1 record invariants.
    pub fn validate(&self) -> Result<()> {
        validate_non_empty_bounded(
            &self.channel,
            MAX_CHANNEL_BYTES,
            "channel must be non-empty and at most 64 bytes",
        )?;
        validate_non_empty_bounded(
            &self.address_or_handle,
            MAX_ADDRESS_OR_HANDLE_BYTES,
            "address_or_handle must be non-empty and at most 512 bytes",
        )?;
        self.binding.validate()?;
        self.validate_custody()?;
        match self.state {
            ChannelIdentityState::PendingFulfillment => {
                if self.pending_fulfillment.is_none() {
                    return Err(invalid_identity());
                }
                if self.quarantine_until.is_some() {
                    return Err(invalid_identity());
                }
            }
            ChannelIdentityState::Quarantine => {
                if self.pending_fulfillment.is_some() {
                    return Err(invalid_identity());
                }
                let quarantine_until = self.quarantine_until.ok_or_else(invalid_identity)?;
                let min_until = self
                    .state_changed_at
                    .checked_add(CHANNEL_IDENTITY_MIN_QUARANTINE_SECS)
                    .ok_or(Error::ArithmeticOverflow(
                        "channel identity quarantine window",
                    ))?;
                if quarantine_until < min_until {
                    return Err(invalid_identity());
                }
            }
            _ => {
                if self.pending_fulfillment.is_some() || self.quarantine_until.is_some() {
                    return Err(invalid_identity());
                }
            }
        }
        Ok(())
    }

    /// Enforces the shape/custody tie and the delegated quarantine ban.
    ///
    /// A `delegated_grant` row holds a member's mailbox, so the two states that
    /// assert product custody of the underlying account — `ROTATING` (we are
    /// re-minting it) and `QUARANTINE` (we are holding it back from reuse) —
    /// are structurally unreachable. Every writer, including
    /// [`Vault::transition_channel_identity`] and the body decoder, funnels
    /// through here, so there is no path that parks a delegated row in either.
    fn validate_custody(&self) -> Result<()> {
        match (&self.delegated_grant, self.is_delegated()) {
            (Some(grant), true) => grant.validate()?,
            (None, false) => return Ok(()),
            (Some(_), false) => {
                return Err(Error::InvalidChannelIdentityBody(
                    "only a delegated_grant identity may carry a delegated grant ref",
                ));
            }
            (None, true) => {
                return Err(Error::InvalidChannelIdentityBody(
                    "delegated_grant identity requires a delegated grant ref",
                ));
            }
        }
        if matches!(
            self.state,
            ChannelIdentityState::Rotating | ChannelIdentityState::Quarantine
        ) || self.quarantine_until.is_some()
        {
            return Err(Error::InvalidChannelIdentityBody(
                "delegated_grant identity admits no rotation or quarantine state",
            ));
        }
        Ok(())
    }

    /// Returns a copy with a checked lifecycle transition applied.
    pub fn transition(
        &self,
        next: ChannelIdentityState,
        pending_fulfillment: Option<ChannelIdentityFulfillment>,
        state_changed_at: u64,
        quarantine_until: Option<u64>,
    ) -> Result<Self> {
        if !self.state.can_transition_to(next) {
            return Err(invalid_identity());
        }
        if state_changed_at < self.state_changed_at {
            return Err(invalid_identity());
        }
        let next_identity = Self {
            state: next,
            pending_fulfillment,
            state_changed_at,
            quarantine_until,
            ..self.clone()
        };
        next_identity.validate()?;
        Ok(next_identity)
    }

    /// Builds typed `channel_identity.*` claim bodies for this record.
    #[must_use]
    pub fn claim_bodies(&self, identity_id: EntityId) -> Vec<ClaimBody> {
        CHANNEL_IDENTITY_CLAIM_PREDICATES
            .iter()
            .map(|predicate| {
                ClaimBody::new(
                    *predicate,
                    ClaimSubject::Entity(identity_id),
                    self.claim_value(predicate)
                        .expect("predicate drawn from channel identity family"),
                    1.0,
                    ClaimApprovalStatus::Auto,
                    ClaimLifecycleStatus::Active,
                )
            })
            .collect()
    }

    fn claim_value(&self, predicate: &str) -> Option<Value> {
        match predicate {
            PREDICATE_CHANNEL_IDENTITY_CHANNEL => Some(Value::from(self.channel.as_str())),
            PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE => {
                Some(Value::from(self.address_or_handle.as_str()))
            }
            PREDICATE_CHANNEL_IDENTITY_SHAPE => Some(Value::from(self.shape.as_str())),
            PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE => Some(Value::from(self.binding.scope_str())),
            PREDICATE_CHANNEL_IDENTITY_BINDING_TARGET => Some(encode_binding_target(self.binding)),
            PREDICATE_CHANNEL_IDENTITY_STATE => Some(Value::from(self.state.as_str())),
            PREDICATE_CHANNEL_IDENTITY_PENDING_FULFILLMENT => Some(
                self.pending_fulfillment
                    .map_or(Value::Nil, |fulfillment| Value::from(fulfillment.as_str())),
            ),
            PREDICATE_CHANNEL_IDENTITY_STATE_CHANGED_AT => Some(Value::from(self.state_changed_at)),
            PREDICATE_CHANNEL_IDENTITY_QUARANTINE_UNTIL => {
                Some(self.quarantine_until.map_or(Value::Nil, Value::from))
            }
            PREDICATE_CHANNEL_IDENTITY_REPUTATION_REF => {
                Some(encode_optional_entity_ref(self.reputation_ref))
            }
            PREDICATE_CHANNEL_IDENTITY_MANIFEST_REF => {
                Some(encode_optional_entity_ref(self.manifest_ref))
            }
            _ => None,
        }
    }
}

/// Encodes a ChannelIdentity body in canonical MessagePack field order.
///
/// A self-held row encodes the twelve pinned keys at
/// [`CHANNEL_IDENTITY_SCHEMA_VERSION`] — byte-for-byte what head wrote. Only a
/// `delegated_grant` row appends the two custody keys and stamps
/// [`CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION`].
pub fn encode_channel_identity_body(identity: &ChannelIdentity) -> Result<Vec<u8>> {
    identity.validate()?;
    let mut entries = vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(body_schema_version(identity)),
        ),
        (
            Value::from(KEY_CHANNEL),
            Value::from(identity.channel.as_str()),
        ),
        (
            Value::from(KEY_ADDRESS_OR_HANDLE),
            Value::from(identity.address_or_handle.as_str()),
        ),
        (Value::from(KEY_SHAPE), Value::from(identity.shape.as_str())),
        (
            Value::from(KEY_BINDING_SCOPE),
            Value::from(identity.binding.scope_str()),
        ),
        (
            Value::from(KEY_BINDING_TARGET),
            encode_binding_target(identity.binding),
        ),
        (Value::from(KEY_STATE), Value::from(identity.state.as_str())),
        (
            Value::from(KEY_PENDING_FULFILLMENT),
            identity
                .pending_fulfillment
                .map_or(Value::Nil, |fulfillment| Value::from(fulfillment.as_str())),
        ),
        (
            Value::from(KEY_STATE_CHANGED_AT),
            Value::from(identity.state_changed_at),
        ),
        (
            Value::from(KEY_QUARANTINE_UNTIL),
            identity.quarantine_until.map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_REPUTATION_REF),
            encode_optional_entity_ref(identity.reputation_ref),
        ),
        (
            Value::from(KEY_MANIFEST_REF),
            encode_optional_entity_ref(identity.manifest_ref),
        ),
    ];

    if let Some(grant) = &identity.delegated_grant {
        entries.push((
            Value::from(KEY_DELEGATED_GRANT_REF),
            Value::from(grant.custody_record_ref.as_str()),
        ));
        entries.push((
            Value::from(KEY_GRANT_SCOPES),
            Value::Array(
                grant
                    .scopes
                    .iter()
                    .map(|scope| Value::from(scope.as_str()))
                    .collect(),
            ),
        ));
    }

    encode_msgpack_value(
        &Value::Map(entries),
        "channel identity body MessagePack encode failed",
    )
}

const fn body_schema_version(identity: &ChannelIdentity) -> u64 {
    if identity.delegated_grant.is_some() {
        CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION
    } else {
        CHANNEL_IDENTITY_SCHEMA_VERSION
    }
}

/// Decodes and validates a ChannelIdentity body.
pub fn decode_channel_identity_body(bytes: &[u8]) -> Result<ChannelIdentity> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_identity())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_identity());
    }
    decode_channel_identity_value(&value)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_channel_identity_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_channel_identity_body(bytes).map(|_| ())
}

/// Returns whether `predicate` belongs to the ChannelIdentity claim family.
#[must_use]
pub fn is_channel_identity_claim_predicate(predicate: &str) -> bool {
    CHANNEL_IDENTITY_CLAIM_PREDICATES.contains(&predicate)
}

/// Validates one `channel_identity.*` claim body.
pub(crate) fn validate_channel_identity_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(Error::InvalidClaimBody(
            "channel_identity claim subject must be an entity",
        ));
    }
    if !is_channel_identity_claim_predicate(&body.predicate) {
        return Err(Error::InvalidClaimBody(
            "unknown channel_identity claim predicate",
        ));
    }
    if body.predicate.len() > MAX_PREDICATE_BYTES {
        return Err(Error::InvalidClaimBody(
            "channel_identity predicate exceeds max predicate bytes",
        ));
    }

    match body.predicate.as_str() {
        PREDICATE_CHANNEL_IDENTITY_CHANNEL => validate_claim_string(
            &body.value,
            MAX_CHANNEL_BYTES,
            "channel_identity.channel value must be non-empty string",
        ),
        PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE => validate_claim_string(
            &body.value,
            MAX_ADDRESS_OR_HANDLE_BYTES,
            "channel_identity.address_or_handle value must be non-empty string",
        ),
        PREDICATE_CHANNEL_IDENTITY_SHAPE => body
            .value
            .as_str()
            .and_then(ChannelIdentityShape::parse)
            .map(|_| ())
            .ok_or(Error::InvalidClaimBody(
                "channel_identity.shape value must be a pinned shape",
            )),
        PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE => match body.value.as_str() {
            Some("agent" | "vault") => Ok(()),
            _ => Err(Error::InvalidClaimBody(
                "channel_identity.binding_scope value must be agent|vault",
            )),
        },
        PREDICATE_CHANNEL_IDENTITY_BINDING_TARGET => validate_claim_binding_target(&body.value),
        PREDICATE_CHANNEL_IDENTITY_STATE => body
            .value
            .as_str()
            .and_then(ChannelIdentityState::parse)
            .map(|_| ())
            .ok_or(Error::InvalidClaimBody(
                "channel_identity.state value must be a pinned state",
            )),
        PREDICATE_CHANNEL_IDENTITY_PENDING_FULFILLMENT => {
            if matches!(body.value, Value::Nil)
                || body
                    .value
                    .as_str()
                    .and_then(ChannelIdentityFulfillment::parse)
                    .is_some()
            {
                Ok(())
            } else {
                Err(Error::InvalidClaimBody(
                    "channel_identity.pending_fulfillment value must be nil|api|manual|review",
                ))
            }
        }
        PREDICATE_CHANNEL_IDENTITY_STATE_CHANGED_AT => {
            body.value
                .as_u64()
                .map(|_| ())
                .ok_or(Error::InvalidClaimBody(
                    "channel_identity.state_changed_at value must be u64",
                ))
        }
        PREDICATE_CHANNEL_IDENTITY_QUARANTINE_UNTIL => {
            if matches!(body.value, Value::Nil) || body.value.as_u64().is_some() {
                Ok(())
            } else {
                Err(Error::InvalidClaimBody(
                    "channel_identity.quarantine_until value must be nil or u64",
                ))
            }
        }
        PREDICATE_CHANNEL_IDENTITY_REPUTATION_REF | PREDICATE_CHANNEL_IDENTITY_MANIFEST_REF => {
            if matches!(body.value, Value::Nil) || decode_entity_ref(&body.value).is_ok() {
                Ok(())
            } else {
                Err(Error::InvalidClaimBody(
                    "channel_identity ref claim value must be nil or entity hex",
                ))
            }
        }
        _ => unreachable!("predicate membership checked above"),
    }
}

fn decode_channel_identity_value(value: &Value) -> Result<ChannelIdentity> {
    let Value::Map(entries) = value else {
        return Err(invalid_identity());
    };
    // The version selects the pinned key set, so the two key sets can never be
    // mixed: an unknown version, a self-held body carrying custody keys, and a
    // delegated body missing them all fail closed before any field is read.
    let delegated_grant = match required_value(entries, KEY_SCHEMA_VERSION)?.as_u64() {
        Some(CHANNEL_IDENTITY_SCHEMA_VERSION) => {
            validate_keys(entries, &CHANNEL_IDENTITY_BODY_KEYS)?;
            None
        }
        Some(CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION) => {
            validate_keys(entries, &CHANNEL_IDENTITY_DELEGATED_BODY_KEYS)?;
            Some(decode_delegated_grant(entries)?)
        }
        _ => return Err(invalid_identity()),
    };

    let channel = required_string(entries, KEY_CHANNEL)?.to_owned();
    let address_or_handle = required_string(entries, KEY_ADDRESS_OR_HANDLE)?.to_owned();
    let shape = ChannelIdentityShape::parse(required_string(entries, KEY_SHAPE)?)
        .ok_or_else(invalid_identity)?;
    let binding_scope = required_string(entries, KEY_BINDING_SCOPE)?;
    let binding = decode_binding(binding_scope, required_value(entries, KEY_BINDING_TARGET)?)?;
    let state = ChannelIdentityState::parse(required_string(entries, KEY_STATE)?)
        .ok_or_else(invalid_identity)?;
    let pending_fulfillment_value = required_value(entries, KEY_PENDING_FULFILLMENT)?;
    let pending_fulfillment = if matches!(pending_fulfillment_value, Value::Nil) {
        None
    } else {
        Some(
            pending_fulfillment_value
                .as_str()
                .and_then(ChannelIdentityFulfillment::parse)
                .ok_or_else(invalid_identity)?,
        )
    };
    let state_changed_at = required_value(entries, KEY_STATE_CHANGED_AT)?
        .as_u64()
        .ok_or_else(invalid_identity)?;
    let quarantine_until_value = required_value(entries, KEY_QUARANTINE_UNTIL)?;
    let quarantine_until = if matches!(quarantine_until_value, Value::Nil) {
        None
    } else {
        Some(
            quarantine_until_value
                .as_u64()
                .ok_or_else(invalid_identity)?,
        )
    };
    let reputation_ref = decode_optional_entity_ref(required_value(entries, KEY_REPUTATION_REF)?)?;
    let manifest_ref = decode_optional_entity_ref(required_value(entries, KEY_MANIFEST_REF)?)?;

    let identity = ChannelIdentity {
        channel,
        address_or_handle,
        shape,
        binding,
        state,
        pending_fulfillment,
        state_changed_at,
        quarantine_until,
        reputation_ref,
        manifest_ref,
        delegated_grant,
    };
    identity.validate()?;
    Ok(identity)
}

fn decode_delegated_grant(entries: &[(Value, Value)]) -> Result<DelegatedGrant> {
    let custody_record_ref = required_string(entries, KEY_DELEGATED_GRANT_REF)?.to_owned();
    let Value::Array(scopes) = required_value(entries, KEY_GRANT_SCOPES)? else {
        return Err(invalid_identity());
    };
    let scopes = scopes
        .iter()
        .map(|scope| {
            scope
                .as_str()
                .and_then(DelegatedGrantScope::parse)
                .ok_or_else(invalid_identity)
        })
        .collect::<Result<Vec<_>>>()?;
    let grant = DelegatedGrant {
        custody_record_ref,
        scopes,
    };
    grant.validate()?;
    Ok(grant)
}

fn encode_binding_target(binding: ChannelIdentityBinding) -> Value {
    match binding {
        ChannelIdentityBinding::Agent { agent_ref } => Value::from(agent_ref.to_hex()),
        ChannelIdentityBinding::Vault { vault_id } => Value::from(vault_id),
    }
}

fn decode_binding(scope: &str, target: &Value) -> Result<ChannelIdentityBinding> {
    match scope {
        "agent" => decode_entity_ref(target).map(ChannelIdentityBinding::agent),
        "vault" => target
            .as_u64()
            .map(ChannelIdentityBinding::vault)
            .ok_or_else(invalid_identity),
        _ => Err(invalid_identity()),
    }
}

fn validate_claim_binding_target(value: &Value) -> Result<()> {
    if decode_entity_ref(value).is_ok() {
        return Ok(());
    }
    match value.as_u64() {
        Some(0) => Err(Error::InvalidClaimBody(
            "channel_identity.binding_target vault id must be non-zero",
        )),
        Some(_) => Ok(()),
        None => Err(Error::InvalidClaimBody(
            "channel_identity.binding_target value must be entity hex or non-zero vault id",
        )),
    }
}

fn encode_optional_entity_ref(id: Option<EntityId>) -> Value {
    id.map_or(Value::Nil, |id| Value::from(id.to_hex()))
}

fn decode_optional_entity_ref(value: &Value) -> Result<Option<EntityId>> {
    if matches!(value, Value::Nil) {
        Ok(None)
    } else {
        decode_entity_ref(value).map(Some)
    }
}

fn decode_entity_ref(value: &Value) -> Result<EntityId> {
    let hex = value.as_str().ok_or_else(invalid_identity)?;
    EntityId::from_hex(hex).map_err(|_| invalid_identity())
}

fn required_string<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    required_value(entries, key)?
        .as_str()
        .ok_or_else(invalid_identity)
}

fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_identity)?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(invalid_identity());
        };
        if seen[index] {
            return Err(invalid_identity());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid_identity())
    }
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(invalid_identity)
}

fn validate_non_empty_bounded(value: &str, max: usize, reason: &'static str) -> Result<()> {
    if value.trim().is_empty() || value.len() > max {
        Err(Error::InvalidChannelIdentityBody(reason))
    } else {
        Ok(())
    }
}

fn validate_claim_string(value: &Value, max: usize, reason: &'static str) -> Result<()> {
    let Some(value) = value.as_str() else {
        return Err(Error::InvalidClaimBody(reason));
    };
    if value.trim().is_empty() || value.len() > max {
        Err(Error::InvalidClaimBody(reason))
    } else {
        Ok(())
    }
}

fn encode_msgpack_value(value: &Value, context: &'static str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).map_err(|_| Error::InvariantViolation(context))?;
    Ok(out)
}

fn invalid_identity() -> Error {
    Error::InvalidChannelIdentityBody("body failed validation")
}

impl Vault {
    /// Creates a ChannelIdentity record through the engine maintenance door.
    ///
    /// Generic public entity puts for `ENTITY_TYPE_CHANNEL_IDENTITY` remain
    /// rejected with `MaintenanceKindNotWritable`; this method validates the
    /// CID-1 body and enforces the assignment-key uniqueness invariant before
    /// writing.
    pub fn create_channel_identity(&self, id: &EntityId, identity: &ChannelIdentity) -> Result<()> {
        let data = encode_channel_identity_body(identity)?;
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_some()
            || self.channel_identity_assignment_conflict_in_txn(&wtxn, id, identity)?
        {
            return Err(Error::ChannelIdentityAlreadyExists);
        }
        self.apply_channel_identity_body(&mut wtxn, id, identity.state_changed_at, data)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Creates the pre-provisioned own-app home-channel identity for an agent.
    pub fn create_own_app_channel_identity(
        &self,
        id: &EntityId,
        agent_ref: EntityId,
        created_at: u64,
    ) -> Result<ChannelIdentity> {
        let identity = ChannelIdentity::own_app_home(agent_ref, created_at);
        self.create_channel_identity(id, &identity)?;
        Ok(identity)
    }

    /// Applies a checked ChannelIdentity lifecycle transition in place.
    pub fn transition_channel_identity(
        &self,
        id: &EntityId,
        next_state: ChannelIdentityState,
        pending_fulfillment: Option<ChannelIdentityFulfillment>,
        state_changed_at: u64,
        quarantine_until: Option<u64>,
    ) -> Result<ChannelIdentity> {
        let mut wtxn = self.store.env.write_txn()?;
        let raw = self
            .store
            .entities
            .get(&wtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        let current = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let next = current.transition(
            next_state,
            pending_fulfillment,
            state_changed_at,
            quarantine_until,
        )?;
        if self.channel_identity_assignment_conflict_in_txn(&wtxn, id, &next)? {
            return Err(Error::ChannelIdentityAlreadyExists);
        }
        let data = encode_channel_identity_body(&next)?;
        self.apply_channel_identity_body(&mut wtxn, id, state_changed_at, data)?;
        wtxn.commit()?;
        Ok(next)
    }

    /// Reads and decodes a ChannelIdentity record.
    pub fn get_channel_identity(&self, id: &EntityId) -> Result<Option<ChannelIdentity>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    /// Reads the ChannelIdentity bound to an exact `(channel, address)` key.
    pub fn channel_identity_by_assignment(
        &self,
        channel: &str,
        address_or_handle: &str,
    ) -> Result<Option<(EntityId, ChannelIdentity)>> {
        let rtxn = self.store.env.read_txn()?;
        for entry in self
            .store
            .type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_CHANNEL_IDENTITY])?
        {
            let (key, _) = entry?;
            let id = entity_id_from_type_index_key(&key)?;
            let raw = self
                .store
                .entities
                .get(&rtxn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("type index row without entity"))?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
                return Err(Error::CorruptedIndex("type index row kind mismatch"));
            }
            let identity = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if identity.assignment_key() == (channel, address_or_handle) {
                return Ok(Some((id, identity)));
            }
        }
        Ok(None)
    }

    pub(crate) fn channel_identity_assignment_conflict_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        id: &EntityId,
        identity: &ChannelIdentity,
    ) -> Result<bool> {
        for entry in self
            .store
            .type_index
            .prefix_iter(txn, &[ENTITY_TYPE_CHANNEL_IDENTITY])?
        {
            let (key, _) = entry?;
            let existing_id = entity_id_from_type_index_key(&key)?;
            if existing_id == *id {
                continue;
            }
            let raw = self
                .store
                .entities
                .get(txn, existing_id.as_bytes())?
                .ok_or(Error::CorruptedIndex("type index row without entity"))?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
                return Err(Error::CorruptedIndex("type index row kind mismatch"));
            }
            let stored = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if stored.assignment_key() == identity.assignment_key() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn apply_channel_identity_body(
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
                entity_type: ENTITY_TYPE_CHANNEL_IDENTITY,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
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
