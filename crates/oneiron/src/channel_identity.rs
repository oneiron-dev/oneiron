//! ChannelIdentity record substrate (OF-347 CID-1).
//!
//! A ChannelIdentity is a vault-resident engine record plus a typed
//! `channel_identity.*` claim family. Provisioning verbs, provider adapters,
//! reputation scoring, and manifest contents are intentionally outside this
//! module; CID-1 pins the primitive shape and lifecycle invariants only.

use std::io::Cursor;

use rmpv::Value;

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, MAX_PREDICATE_BYTES,
};
use crate::error::{Error, Result};
use crate::types::EntityId;

/// Current ChannelIdentity body schema version.
pub const CHANNEL_IDENTITY_SCHEMA_VERSION: u64 = 1;

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

/// ChannelIdentity addressability shape (OF-347 R1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChannelIdentityShape {
    DedicatedAddress,
    DedicatedHandle,
    SharedPresence,
}

impl ChannelIdentityShape {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DedicatedAddress => "dedicated_address",
            Self::DedicatedHandle => "dedicated_handle",
            Self::SharedPresence => "shared_presence",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "dedicated_address" => Some(Self::DedicatedAddress),
            "dedicated_handle" => Some(Self::DedicatedHandle),
            "shared_presence" => Some(Self::SharedPresence),
            _ => None,
        }
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
        }
    }

    /// Returns the uniqueness key used for never-recycle enforcement.
    #[must_use]
    pub fn assignment_key(&self) -> (&str, &str) {
        (&self.channel, &self.address_or_handle)
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
pub fn encode_channel_identity_body(identity: &ChannelIdentity) -> Result<Vec<u8>> {
    identity.validate()?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(CHANNEL_IDENTITY_SCHEMA_VERSION),
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
    ]);

    encode_msgpack_value(&value, "channel identity body MessagePack encode failed")
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
    validate_keys(entries, &CHANNEL_IDENTITY_BODY_KEYS)?;

    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64()
        != Some(CHANNEL_IDENTITY_SCHEMA_VERSION)
    {
        return Err(invalid_identity());
    }

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
    };
    identity.validate()?;
    Ok(identity)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Vault;
    use crate::error::ErrorKind;
    use crate::test_util::open_test_vault_with;
    use crate::types::{
        ENTITY_TYPE_CHANNEL_IDENTITY, EntityClassification, TimeRange, TypeByteBand, VaultConfig,
        entity_type_registry_entry,
    };

    fn entity(seed: u8) -> EntityId {
        EntityId::from_bytes([seed; 16]).expect("valid entity id")
    }

    fn sample_identity() -> ChannelIdentity {
        let mut identity = ChannelIdentity::requested(
            "email",
            "agent@example.com",
            ChannelIdentityShape::DedicatedAddress,
            ChannelIdentityBinding::agent(entity(0xA1)),
            1_800_000_000,
        );
        identity.reputation_ref = Some(entity(0xB1));
        identity.manifest_ref = Some(entity(0xC1));
        identity
    }

    fn test_vault() -> (tempfile::TempDir, Vault) {
        let mut cfg = VaultConfig::device();
        cfg.map_size = 16 * 1024 * 1024;
        cfg.dimensions = 4;
        cfg.embedding_model = None;
        open_test_vault_with(cfg)
    }

    #[test]
    fn channel_identity_codec_and_claim_family_round_trip() -> Result<()> {
        let identity = sample_identity().transition(
            ChannelIdentityState::PendingFulfillment,
            Some(ChannelIdentityFulfillment::Manual),
            1_800_000_010,
            None,
        )?;

        let encoded = encode_channel_identity_body(&identity)?;
        validate_channel_identity_body_bytes(&encoded)?;
        assert_eq!(decode_channel_identity_body(&encoded)?, identity);

        let claims = identity.claim_bodies(entity(0xD1));
        assert_eq!(claims.len(), CHANNEL_IDENTITY_CLAIM_PREDICATES.len());
        for claim in &claims {
            validate_channel_identity_claim_structure(claim)?;
        }
        assert!(claims.iter().any(|claim| {
            claim.predicate == PREDICATE_CHANNEL_IDENTITY_SHAPE
                && claim.value.as_str() == Some("dedicated_address")
        }));
        assert!(claims.iter().any(|claim| {
            claim.predicate == PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE
                && claim.value.as_str() == Some("agent")
        }));
        assert!(claims.iter().any(|claim| {
            claim.predicate == PREDICATE_CHANNEL_IDENTITY_PENDING_FULFILLMENT
                && claim.value.as_str() == Some("manual")
        }));
        Ok(())
    }

    #[test]
    fn state_machine_rejects_skips_and_pins_quarantine_window() -> Result<()> {
        let requested = sample_identity();
        assert!(
            requested
                .transition(ChannelIdentityState::Active, None, 1_800_000_010, None)
                .is_err()
        );

        let pending = requested.transition(
            ChannelIdentityState::PendingFulfillment,
            Some(ChannelIdentityFulfillment::Api),
            1_800_000_010,
            None,
        )?;
        let active = pending.transition(ChannelIdentityState::Active, None, 1_800_000_020, None)?;
        assert!(
            active
                .transition(ChannelIdentityState::Tombstone, None, 1_800_000_030, None)
                .is_err()
        );

        let released =
            active.transition(ChannelIdentityState::Released, None, 1_800_000_030, None)?;
        assert!(
            released
                .transition(
                    ChannelIdentityState::Quarantine,
                    None,
                    1_800_000_020,
                    Some(1_800_000_020 + CHANNEL_IDENTITY_MIN_QUARANTINE_SECS),
                )
                .is_err()
        );
        assert!(
            released
                .transition(
                    ChannelIdentityState::Quarantine,
                    None,
                    1_800_000_040,
                    Some(1_800_000_040 + CHANNEL_IDENTITY_MIN_QUARANTINE_SECS - 1),
                )
                .is_err()
        );
        let quarantine = released.transition(
            ChannelIdentityState::Quarantine,
            None,
            1_800_000_040,
            Some(1_800_000_040 + CHANNEL_IDENTITY_MIN_QUARANTINE_SECS),
        )?;
        quarantine.transition(ChannelIdentityState::Tombstone, None, 1_900_000_000, None)?;
        Ok(())
    }

    #[test]
    fn channel_identity_claim_binding_target_rejects_invalid_values() {
        let subject = ClaimSubject::Entity(entity(0xD2));
        let claim = |value| {
            ClaimBody::new(
                PREDICATE_CHANNEL_IDENTITY_BINDING_TARGET,
                subject,
                value,
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            )
        };

        validate_channel_identity_claim_structure(&claim(Value::from(entity(0xA1).to_hex())))
            .expect("agent entity target accepted");
        validate_channel_identity_claim_structure(&claim(Value::from(7_u64)))
            .expect("non-zero vault target accepted");

        let zero_err = validate_channel_identity_claim_structure(&claim(Value::from(0_u64)))
            .expect_err("zero vault id must be rejected");
        assert_eq!(zero_err.kind(), ErrorKind::InvalidClaimBody);

        let bogus_err = validate_channel_identity_claim_structure(&claim(Value::from("not-hex")))
            .expect_err("malformed target must be rejected");
        assert_eq!(bogus_err.kind(), ErrorKind::InvalidClaimBody);
    }

    #[test]
    fn own_app_home_identity_is_constructible_active_agent_binding() -> Result<()> {
        let agent = entity(0xE1);
        let identity = ChannelIdentity::own_app_home(agent, 7);
        identity.validate()?;
        assert_eq!(identity.channel, "own_app");
        assert_eq!(identity.shape, ChannelIdentityShape::DedicatedHandle);
        assert_eq!(identity.binding, ChannelIdentityBinding::agent(agent));
        assert_eq!(identity.state, ChannelIdentityState::Active);
        Ok(())
    }

    #[test]
    fn vault_create_transition_and_never_recycle_invariant() -> Result<()> {
        let (_dir, vault) = test_vault();
        let id = entity(0x11);
        let identity = sample_identity();

        let data = encode_channel_identity_body(&identity)?;
        let err = vault
            .put_entity(
                &id,
                ENTITY_TYPE_CHANNEL_IDENTITY,
                TimeRange {
                    start: identity.state_changed_at,
                    end: identity.state_changed_at,
                },
                identity.state_changed_at,
                &data,
            )
            .expect_err("generic public put must reject maintenance CID records");
        assert_eq!(err.kind(), ErrorKind::MaintenanceKindNotWritable);

        vault.create_channel_identity(&id, &identity)?;
        assert_eq!(vault.get_channel_identity(&id)?, Some(identity));

        vault.transition_channel_identity(
            &id,
            ChannelIdentityState::PendingFulfillment,
            Some(ChannelIdentityFulfillment::Api),
            1_800_000_010,
            None,
        )?;
        vault.transition_channel_identity(
            &id,
            ChannelIdentityState::Active,
            None,
            1_800_000_020,
            None,
        )?;
        vault.transition_channel_identity(
            &id,
            ChannelIdentityState::Released,
            None,
            1_800_000_030,
            None,
        )?;
        vault.transition_channel_identity(
            &id,
            ChannelIdentityState::Quarantine,
            None,
            1_800_000_040,
            Some(1_800_000_040 + CHANNEL_IDENTITY_MIN_QUARANTINE_SECS),
        )?;
        let tombstone = vault.transition_channel_identity(
            &id,
            ChannelIdentityState::Tombstone,
            None,
            1_900_000_000,
            None,
        )?;
        assert_eq!(tombstone.state, ChannelIdentityState::Tombstone);

        let duplicate = ChannelIdentity::requested(
            "email",
            "agent@example.com",
            ChannelIdentityShape::DedicatedAddress,
            ChannelIdentityBinding::agent(entity(0xA2)),
            1_900_000_010,
        );
        let err = vault
            .create_channel_identity(&entity(0x12), &duplicate)
            .expect_err("released/tombstoned identities must never be reassigned");
        assert_eq!(err.kind(), ErrorKind::ChannelIdentityAlreadyExists);
        Ok(())
    }

    #[test]
    fn malformed_channel_identity_bodies_fail_closed() {
        let mut encoded = encode_channel_identity_body(&sample_identity()).unwrap();
        encoded.push(0xc0);
        let err = decode_channel_identity_body(&encoded).expect_err("trailing bytes rejected");
        assert_eq!(err.kind(), ErrorKind::InvalidChannelIdentityBody);

        let mut blank = sample_identity();
        blank.address_or_handle = " ".to_owned();
        let err = encode_channel_identity_body(&blank).expect_err("blank address rejected");
        assert_eq!(err.kind(), ErrorKind::InvalidChannelIdentityBody);
    }

    #[test]
    fn channel_identity_type_registration_is_stable() {
        let entry = entity_type_registry_entry(ENTITY_TYPE_CHANNEL_IDENTITY)
            .expect("CHANNEL_IDENTITY registry row");

        assert_eq!(ENTITY_TYPE_CHANNEL_IDENTITY, 131);
        assert_eq!(entry.kind, "CHANNEL_IDENTITY");
        assert_eq!(entry.short_id_prefix, None);
        assert_eq!(entry.classification, EntityClassification::Maintenance);
        assert_eq!(entry.band, TypeByteBand::InducedDynamicMaintenance);
    }
}
