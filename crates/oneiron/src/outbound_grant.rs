//! Standing outbound-grant records for OF-367 RS6.2/RS6.5.
//!
//! These are engine-authored, vault-resident grant claims minted from OF-336
//! consent escalators or bundle approvals. They intentionally have no expiry
//! field: policy-floor staleness and explicit revocation are the invalidation
//! paths.

use std::io::Cursor;

use rmpv::Value;

use crate::Vault;
use crate::batch::BatchOp;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::batch::EntityMetadataHeader;
use crate::batch::apply_ops;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::genui::{GrantMintIntent, GrantMintIntentScope};
use crate::outbound_consent::{DataClass, ScopedMcpGrantRef};
use crate::registry::ENTITY_TYPE_OUTBOUND_GRANT;
use crate::store::Store;
use crate::temporal::TimeRange;

/// Current StandingOutboundGrant body schema version.
pub const OUTBOUND_GRANT_SCHEMA_VERSION: u64 = 1;

pub(crate) fn standing_outbound_grant_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<StandingOutboundGrant>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_OUTBOUND_GRANT {
        return Err(Error::InvalidEntityType(header.entity_type));
    }
    decode_standing_outbound_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
}

/// Pinned recursive MessagePack key vocabulary for StandingOutboundGrant
/// bodies. Existing top-level positions remain stable; scoped-tool keys are
/// appended and encoded inside the `scope` map.
pub const OUTBOUND_GRANT_BODY_KEYS: [&str; 16] = [
    "schema_version",
    "principal_ref",
    "origin_component_id",
    "origin_action_id",
    "origin_receipt_ref",
    "scope",
    "status",
    "created_at",
    "revoked_at",
    "last_used_at",
    "binding_diff_handle",
    "read_frontier_hash",
    "server",
    "tool",
    "data_class_ceiling",
    "endpoint_allowlist",
];

const OUTBOUND_GRANT_TOP_LEVEL_KEYS: [&str; 12] = [
    OUTBOUND_GRANT_BODY_KEYS[0],
    OUTBOUND_GRANT_BODY_KEYS[1],
    OUTBOUND_GRANT_BODY_KEYS[2],
    OUTBOUND_GRANT_BODY_KEYS[3],
    OUTBOUND_GRANT_BODY_KEYS[4],
    OUTBOUND_GRANT_BODY_KEYS[5],
    OUTBOUND_GRANT_BODY_KEYS[6],
    OUTBOUND_GRANT_BODY_KEYS[7],
    OUTBOUND_GRANT_BODY_KEYS[8],
    OUTBOUND_GRANT_BODY_KEYS[9],
    OUTBOUND_GRANT_BODY_KEYS[10],
    OUTBOUND_GRANT_BODY_KEYS[11],
];

pub(crate) const OUTBOUND_GRANT_FIELDS_MINIMAL: &[&str] = &["scope", "status", "last_used_at"];
pub(crate) const OUTBOUND_GRANT_FIELDS_STANDARD: &[&str] = &[
    "principal_ref",
    "origin_component_id",
    "origin_action_id",
    "scope",
    "status",
    "last_used_at",
];
pub(crate) const OUTBOUND_GRANT_FIELDS_FULL: &[&str] = &OUTBOUND_GRANT_TOP_LEVEL_KEYS;

const KEY_SCHEMA_VERSION: &str = OUTBOUND_GRANT_BODY_KEYS[0];
const KEY_PRINCIPAL_REF: &str = OUTBOUND_GRANT_BODY_KEYS[1];
const KEY_ORIGIN_COMPONENT_ID: &str = OUTBOUND_GRANT_BODY_KEYS[2];
const KEY_ORIGIN_ACTION_ID: &str = OUTBOUND_GRANT_BODY_KEYS[3];
const KEY_ORIGIN_RECEIPT_REF: &str = OUTBOUND_GRANT_BODY_KEYS[4];
const KEY_SCOPE: &str = OUTBOUND_GRANT_BODY_KEYS[5];
const KEY_STATUS: &str = OUTBOUND_GRANT_BODY_KEYS[6];
const KEY_CREATED_AT: &str = OUTBOUND_GRANT_BODY_KEYS[7];
const KEY_REVOKED_AT: &str = OUTBOUND_GRANT_BODY_KEYS[8];
const KEY_LAST_USED_AT: &str = OUTBOUND_GRANT_BODY_KEYS[9];
const KEY_BINDING_DIFF_HANDLE: &str = OUTBOUND_GRANT_BODY_KEYS[10];
const KEY_READ_FRONTIER_HASH: &str = OUTBOUND_GRANT_BODY_KEYS[11];

const SCOPE_KEYS: [&str; 9] = [
    "kind",
    "contact_ref",
    "verb_class",
    "channel",
    "brief_ref",
    "server",
    "tool",
    "data_class_ceiling",
    "endpoint_allowlist",
];

const SCOPE_KIND_CONTACT: &str = "contact";
const SCOPE_KIND_VERB_CLASS: &str = "verb_class";
const SCOPE_KIND_CHANNEL: &str = "channel";
const SCOPE_KIND_BRIEF_VERB_CLASS: &str = "brief_verb_class";
const SCOPE_KIND_SCOPED_MCP: &str = "scoped_mcp";
const PRINCIPAL_INDEX_PREFIX: &[u8] = b"outbound_grant/principal/v1\0";
const SEND_VERB_CLASS: &str = "send";

/// Scope dial selected by the owner when minting a standing outbound grant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StandingOutboundGrantScope {
    /// Always allow matching sends to one contact/counterparty.
    Contact { contact_ref: String },
    /// Always allow matching sends for one outbound verb class.
    VerbClass { verb_class: String },
    /// Always allow matching sends on one channel.
    Channel { channel: String },
    /// Bundle approval for one brief and verb class.
    BriefVerbClass {
        brief_ref: String,
        verb_class: String,
    },
    /// Payload-aware standing authority for one external tool.
    ScopedMcp {
        server: String,
        tool: String,
        data_class_ceiling: DataClass,
        endpoint_allowlist: Vec<String>,
    },
}

/// Authenticated grant-time input for one payload-aware external tool scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ScopedMcpGrantMintIntent {
    pub principal_ref: String,
    pub origin_component_id: String,
    pub origin_action_id: String,
    pub origin_receipt_ref: Option<String>,
    pub server: String,
    pub tool: String,
    pub data_class_ceiling: DataClass,
    pub endpoint_allowlist: Vec<String>,
}

impl StandingOutboundGrantScope {
    /// Builds a storage scope from the RCPT-3 grant mint intent scope.
    pub fn from_grant_mint_scope(scope: &GrantMintIntentScope) -> Result<Self> {
        match scope {
            GrantMintIntentScope::JustOnce { .. } => Err(invalid_grant()),
            GrantMintIntentScope::Contact { contact_ref } => Ok(Self::Contact {
                contact_ref: non_empty_string(contact_ref)?,
            }),
            GrantMintIntentScope::VerbClass { verb_class } => Ok(Self::VerbClass {
                verb_class: non_empty_string(verb_class)?,
            }),
            GrantMintIntentScope::Channel { channel } => Ok(Self::Channel {
                channel: non_empty_string(channel)?,
            }),
            GrantMintIntentScope::BundleExactSends { .. } => Err(invalid_grant()),
            GrantMintIntentScope::BriefVerbClass {
                brief_ref,
                verb_class,
            } => Ok(Self::BriefVerbClass {
                brief_ref: non_empty_string(brief_ref)?,
                verb_class: non_empty_string(verb_class)?,
            }),
            // A calendar disclosure grant authorizes a READ at a rung. It must
            // never become a standing permission to send.
            GrantMintIntentScope::Calendar { .. } => Err(invalid_grant()),
        }
    }

    /// Stable dial label for grants-lens rows.
    #[must_use]
    pub const fn dial_label(&self) -> &'static str {
        match self {
            Self::Contact { .. } => "always_this_contact",
            Self::VerbClass { .. } => "always_this_verb_class",
            Self::Channel { .. } => "always_this_channel",
            Self::BriefVerbClass { .. } => "brief_verb_class",
            Self::ScopedMcp { .. } => "scoped_mcp",
        }
    }

    /// Returns the payload-aware axes when this is a scoped external-tool
    /// grant. Blind grant kinds intentionally return `None`.
    #[must_use]
    pub fn scoped_mcp_grant(&self) -> Option<ScopedMcpGrantRef<'_>> {
        match self {
            Self::ScopedMcp {
                server,
                tool,
                data_class_ceiling,
                endpoint_allowlist,
            } => Some(ScopedMcpGrantRef {
                server,
                tool,
                data_class_ceiling: *data_class_ceiling,
                endpoint_allowlist,
            }),
            _ => None,
        }
    }

    /// Returns whether this grant scope covers a candidate outbound effect.
    #[must_use]
    pub fn matches_effect(
        &self,
        verb: &str,
        channel: &str,
        counterparty: Option<&str>,
        brief_ref: Option<&str>,
    ) -> bool {
        // MCP calls require the payload-aware path. No argument-blind dial is
        // allowed to authorize one, even if its channel string matches.
        if is_mcp_channel(channel) {
            return false;
        }
        match self {
            Self::Contact { contact_ref } => {
                counterparty.is_some_and(|counterparty| refs_match(contact_ref, counterparty))
            }
            Self::VerbClass { verb_class } => verb_class.trim() == verb.trim(),
            Self::Channel {
                channel: grant_channel,
            } => grant_channel.trim() == channel.trim() && is_send_class_verb(verb),
            Self::BriefVerbClass {
                brief_ref: grant_brief,
                verb_class,
            } => {
                verb_class.trim() == verb.trim()
                    && brief_ref.is_some_and(|brief_ref| refs_match(grant_brief, brief_ref))
            }
            Self::ScopedMcp { .. } => false,
        }
    }
}

/// StandingOutboundGrant lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StandingOutboundGrantStatus {
    /// Grant is live and can authorize a matching outbound effect.
    Active,
    /// Grant has been revoked and must fail closed immediately.
    Revoked,
}

impl StandingOutboundGrantStatus {
    /// Returns the pinned on-disk status string.
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

/// Vault-resident standing outbound-grant claim.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StandingOutboundGrant {
    /// Principal that authenticated the consent action.
    pub principal_ref: String,
    /// OF-336 component that originated the grant.
    pub origin_component_id: String,
    /// OF-336 typed action that originated the grant.
    pub origin_action_id: String,
    /// Optional origin ask/gate receipt reference.
    pub origin_receipt_ref: Option<String>,
    /// Owner-selected grant scope dial.
    pub scope: StandingOutboundGrantScope,
    /// Grant lifecycle status.
    pub status: StandingOutboundGrantStatus,
    /// Creation time in Unix seconds.
    pub created_at: u64,
    /// Revocation time in Unix seconds.
    pub revoked_at: Option<u64>,
    /// Last successful gate use in Unix seconds.
    pub last_used_at: Option<u64>,
    /// Content address for the originating consent binding.
    pub binding_diff_handle: Vec<u8>,
    /// Policy-floor hash in effect when the grant was minted.
    pub read_frontier_hash: [u8; 32],
}

impl StandingOutboundGrant {
    /// Constructs an active grant from an OF-336 grant mint intent.
    pub fn from_grant_mint_intent(
        intent: &GrantMintIntent,
        created_at: u64,
        binding_diff_handle: Vec<u8>,
        read_frontier_hash: [u8; 32],
    ) -> Result<Self> {
        let grant = Self {
            principal_ref: non_empty_string(&intent.principal_ref)?,
            origin_component_id: non_empty_string(&intent.origin_component_id)?,
            origin_action_id: non_empty_string(&intent.origin_action_id)?,
            origin_receipt_ref: non_empty_optional(intent.origin_receipt_ref.as_deref())?,
            scope: StandingOutboundGrantScope::from_grant_mint_scope(&intent.scope)?,
            status: StandingOutboundGrantStatus::Active,
            created_at,
            revoked_at: None,
            last_used_at: None,
            binding_diff_handle,
            read_frontier_hash,
        };
        grant.validate()?;
        Ok(grant)
    }

    /// Constructs an active payload-aware grant from authenticated grant-time
    /// input whose resolved endpoints were shown to the consenting principal.
    pub fn from_scoped_mcp_grant_mint_intent(
        intent: &ScopedMcpGrantMintIntent,
        created_at: u64,
        binding_diff_handle: Vec<u8>,
        read_frontier_hash: [u8; 32],
    ) -> Result<Self> {
        let grant = Self {
            principal_ref: non_empty_string(&intent.principal_ref)?,
            origin_component_id: non_empty_string(&intent.origin_component_id)?,
            origin_action_id: non_empty_string(&intent.origin_action_id)?,
            origin_receipt_ref: non_empty_optional(intent.origin_receipt_ref.as_deref())?,
            scope: StandingOutboundGrantScope::ScopedMcp {
                server: intent.server.clone(),
                tool: intent.tool.clone(),
                data_class_ceiling: intent.data_class_ceiling,
                endpoint_allowlist: intent.endpoint_allowlist.clone(),
            },
            status: StandingOutboundGrantStatus::Active,
            created_at,
            revoked_at: None,
            last_used_at: None,
            binding_diff_handle,
            read_frontier_hash,
        };
        grant.validate()?;
        Ok(grant)
    }

    /// Returns a revoked version of this grant.
    pub fn revoked(self, revoked_at: u64) -> Result<Self> {
        let grant = Self {
            status: StandingOutboundGrantStatus::Revoked,
            revoked_at: Some(revoked_at),
            ..self
        };
        grant.validate()?;
        Ok(grant)
    }

    /// Returns a last-used version of this grant.
    pub fn touched(self, used_at: u64) -> Result<Self> {
        if self.status != StandingOutboundGrantStatus::Active {
            return Err(invalid_grant());
        }
        let grant = Self {
            last_used_at: Some(used_at),
            ..self
        };
        grant.validate()?;
        Ok(grant)
    }

    /// Returns whether this active grant can still be evaluated under the
    /// supplied current policy-floor hash.
    #[must_use]
    pub fn is_active_under_policy(&self, read_frontier_hash: &[u8; 32]) -> bool {
        self.status == StandingOutboundGrantStatus::Active
            && self.revoked_at.is_none()
            && &self.read_frontier_hash == read_frontier_hash
    }

    /// Validates revocation, timestamp, and binding invariants.
    pub fn validate(&self) -> Result<()> {
        non_empty_str(&self.principal_ref)?;
        non_empty_str(&self.origin_component_id)?;
        non_empty_str(&self.origin_action_id)?;
        if let Some(origin_receipt_ref) = self.origin_receipt_ref.as_deref() {
            non_empty_str(origin_receipt_ref)?;
        }
        validate_scope(&self.scope)?;
        if self.binding_diff_handle.is_empty() {
            return Err(invalid_grant());
        }
        match (self.status, self.revoked_at) {
            (StandingOutboundGrantStatus::Active, None) => {}
            (StandingOutboundGrantStatus::Active, Some(_)) => return Err(invalid_grant()),
            (StandingOutboundGrantStatus::Revoked, Some(revoked_at))
                if revoked_at >= self.created_at => {}
            (StandingOutboundGrantStatus::Revoked, Some(_))
            | (StandingOutboundGrantStatus::Revoked, None) => return Err(invalid_grant()),
        }
        if let Some(last_used_at) = self.last_used_at
            && last_used_at < self.created_at
        {
            return Err(invalid_grant());
        }
        Ok(())
    }
}

/// Encodes a StandingOutboundGrant body in canonical MessagePack field order.
pub fn encode_standing_outbound_grant_body(grant: &StandingOutboundGrant) -> Result<Vec<u8>> {
    grant.validate()?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(OUTBOUND_GRANT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_PRINCIPAL_REF),
            Value::from(grant.principal_ref.clone()),
        ),
        (
            Value::from(KEY_ORIGIN_COMPONENT_ID),
            Value::from(grant.origin_component_id.clone()),
        ),
        (
            Value::from(KEY_ORIGIN_ACTION_ID),
            Value::from(grant.origin_action_id.clone()),
        ),
        (
            Value::from(KEY_ORIGIN_RECEIPT_REF),
            option_string_value(grant.origin_receipt_ref.as_deref()),
        ),
        (Value::from(KEY_SCOPE), encode_scope(&grant.scope)),
        (Value::from(KEY_STATUS), Value::from(grant.status.as_str())),
        (Value::from(KEY_CREATED_AT), Value::from(grant.created_at)),
        (
            Value::from(KEY_REVOKED_AT),
            grant.revoked_at.map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_LAST_USED_AT),
            grant.last_used_at.map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_BINDING_DIFF_HANDLE),
            Value::Binary(grant.binding_diff_handle.clone()),
        ),
        (
            Value::from(KEY_READ_FRONTIER_HASH),
            Value::Binary(grant.read_frontier_hash.to_vec()),
        ),
    ]);

    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value).map_err(|_| {
        Error::InvariantViolation("standing outbound grant body MessagePack encode failed")
    })?;
    Ok(out)
}

/// Decodes a StandingOutboundGrant body after fail-closed structural validation.
pub fn decode_standing_outbound_grant_body(bytes: &[u8]) -> Result<StandingOutboundGrant> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_grant())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_grant());
    }
    decode_standing_outbound_grant_value(&value)
}

pub(crate) fn validate_standing_outbound_grant_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_standing_outbound_grant_body(bytes).map(|_| ())
}

fn decode_standing_outbound_grant_value(value: &Value) -> Result<StandingOutboundGrant> {
    let Value::Map(entries) = value else {
        return Err(invalid_grant());
    };
    validate_keys(entries, &OUTBOUND_GRANT_TOP_LEVEL_KEYS)?;

    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64() != Some(OUTBOUND_GRANT_SCHEMA_VERSION)
    {
        return Err(invalid_grant());
    }

    let revoked_at = decode_optional_u64(required_value(entries, KEY_REVOKED_AT)?)?;
    let last_used_at = decode_optional_u64(required_value(entries, KEY_LAST_USED_AT)?)?;
    let grant = StandingOutboundGrant {
        principal_ref: decode_non_empty_string(required_value(entries, KEY_PRINCIPAL_REF)?)?,
        origin_component_id: decode_non_empty_string(required_value(
            entries,
            KEY_ORIGIN_COMPONENT_ID,
        )?)?,
        origin_action_id: decode_non_empty_string(required_value(entries, KEY_ORIGIN_ACTION_ID)?)?,
        origin_receipt_ref: decode_optional_string(required_value(
            entries,
            KEY_ORIGIN_RECEIPT_REF,
        )?)?,
        scope: decode_scope(required_value(entries, KEY_SCOPE)?)?,
        status: required_value(entries, KEY_STATUS)?
            .as_str()
            .and_then(StandingOutboundGrantStatus::parse)
            .ok_or_else(invalid_grant)?,
        created_at: required_value(entries, KEY_CREATED_AT)?
            .as_u64()
            .ok_or_else(invalid_grant)?,
        revoked_at,
        last_used_at,
        binding_diff_handle: decode_non_empty_binary(required_value(
            entries,
            KEY_BINDING_DIFF_HANDLE,
        )?)?,
        read_frontier_hash: decode_hash32(required_value(entries, KEY_READ_FRONTIER_HASH)?)?,
    };
    grant.validate()?;
    Ok(grant)
}

fn encode_scope(scope: &StandingOutboundGrantScope) -> Value {
    let mut contact_ref = Value::Nil;
    let mut verb_class = Value::Nil;
    let mut channel = Value::Nil;
    let mut brief_ref = Value::Nil;
    let mut server = Value::Nil;
    let mut tool = Value::Nil;
    let mut data_class_ceiling = Value::Nil;
    let mut endpoint_allowlist = Value::Nil;
    let kind = match scope {
        StandingOutboundGrantScope::Contact {
            contact_ref: grant_contact_ref,
        } => {
            contact_ref = Value::from(grant_contact_ref.clone());
            SCOPE_KIND_CONTACT
        }
        StandingOutboundGrantScope::VerbClass {
            verb_class: grant_verb_class,
        } => {
            verb_class = Value::from(grant_verb_class.clone());
            SCOPE_KIND_VERB_CLASS
        }
        StandingOutboundGrantScope::Channel {
            channel: grant_channel,
        } => {
            channel = Value::from(grant_channel.clone());
            SCOPE_KIND_CHANNEL
        }
        StandingOutboundGrantScope::BriefVerbClass {
            brief_ref: grant_brief_ref,
            verb_class: grant_verb_class,
        } => {
            brief_ref = Value::from(grant_brief_ref.clone());
            verb_class = Value::from(grant_verb_class.clone());
            SCOPE_KIND_BRIEF_VERB_CLASS
        }
        StandingOutboundGrantScope::ScopedMcp {
            server: grant_server,
            tool: grant_tool,
            data_class_ceiling: grant_ceiling,
            endpoint_allowlist: grant_endpoints,
        } => {
            server = Value::from(grant_server.clone());
            tool = Value::from(grant_tool.clone());
            data_class_ceiling = Value::from(grant_ceiling.as_str());
            endpoint_allowlist =
                Value::Array(grant_endpoints.iter().cloned().map(Value::from).collect());
            SCOPE_KIND_SCOPED_MCP
        }
    };

    Value::Map(vec![
        (Value::from(SCOPE_KEYS[0]), Value::from(kind)),
        (Value::from(SCOPE_KEYS[1]), contact_ref),
        (Value::from(SCOPE_KEYS[2]), verb_class),
        (Value::from(SCOPE_KEYS[3]), channel),
        (Value::from(SCOPE_KEYS[4]), brief_ref),
        (Value::from(SCOPE_KEYS[5]), server),
        (Value::from(SCOPE_KEYS[6]), tool),
        (Value::from(SCOPE_KEYS[7]), data_class_ceiling),
        (Value::from(SCOPE_KEYS[8]), endpoint_allowlist),
    ])
}

fn decode_scope(value: &Value) -> Result<StandingOutboundGrantScope> {
    let Value::Map(entries) = value else {
        return Err(invalid_grant());
    };
    validate_keys_with_optional(entries, &SCOPE_KEYS[..5], &SCOPE_KEYS[5..])?;

    let kind = required_value(entries, SCOPE_KEYS[0])?
        .as_str()
        .ok_or_else(invalid_grant)?;
    let has_non_applicable_field = if kind == SCOPE_KIND_SCOPED_MCP {
        SCOPE_KEYS[1..5].iter().any(|scope_key| {
            entries.iter().any(|(key, value)| {
                key.as_str() == Some(*scope_key) && !matches!(value, Value::Nil)
            })
        })
    } else {
        SCOPE_KEYS[5..].iter().any(|scope_key| {
            entries.iter().any(|(key, value)| {
                key.as_str() == Some(*scope_key) && !matches!(value, Value::Nil)
            })
        })
    };
    if has_non_applicable_field {
        return Err(invalid_grant());
    }
    match kind {
        SCOPE_KIND_CONTACT => Ok(StandingOutboundGrantScope::Contact {
            contact_ref: decode_non_empty_string(required_value(entries, SCOPE_KEYS[1])?)?,
        }),
        SCOPE_KIND_VERB_CLASS => Ok(StandingOutboundGrantScope::VerbClass {
            verb_class: decode_non_empty_string(required_value(entries, SCOPE_KEYS[2])?)?,
        }),
        SCOPE_KIND_CHANNEL => Ok(StandingOutboundGrantScope::Channel {
            channel: decode_non_empty_string(required_value(entries, SCOPE_KEYS[3])?)?,
        }),
        SCOPE_KIND_BRIEF_VERB_CLASS => Ok(StandingOutboundGrantScope::BriefVerbClass {
            brief_ref: decode_non_empty_string(required_value(entries, SCOPE_KEYS[4])?)?,
            verb_class: decode_non_empty_string(required_value(entries, SCOPE_KEYS[2])?)?,
        }),
        SCOPE_KIND_SCOPED_MCP => {
            let data_class_ceiling = DataClass::parse(
                required_value(entries, SCOPE_KEYS[7])?
                    .as_str()
                    .ok_or_else(invalid_grant)?,
            );
            if !data_class_ceiling.is_grantable() {
                return Err(invalid_grant());
            }
            Ok(StandingOutboundGrantScope::ScopedMcp {
                server: decode_canonical_non_empty_string(required_value(entries, SCOPE_KEYS[5])?)?,
                tool: decode_canonical_non_empty_string(required_value(entries, SCOPE_KEYS[6])?)?,
                data_class_ceiling,
                endpoint_allowlist: decode_canonical_non_empty_string_array(required_value(
                    entries,
                    SCOPE_KEYS[8],
                )?)?,
            })
        }
        _ => Err(invalid_grant()),
    }
}

fn validate_scope(scope: &StandingOutboundGrantScope) -> Result<()> {
    match scope {
        StandingOutboundGrantScope::Contact { contact_ref } => non_empty_str(contact_ref)?,
        StandingOutboundGrantScope::VerbClass { verb_class } => non_empty_str(verb_class)?,
        StandingOutboundGrantScope::Channel { channel } => non_empty_str(channel)?,
        StandingOutboundGrantScope::BriefVerbClass {
            brief_ref,
            verb_class,
        } => {
            non_empty_str(brief_ref)?;
            non_empty_str(verb_class)?;
        }
        StandingOutboundGrantScope::ScopedMcp {
            server,
            tool,
            data_class_ceiling,
            endpoint_allowlist,
        } => {
            canonical_non_empty_str(server)?;
            canonical_non_empty_str(tool)?;
            if !data_class_ceiling.is_grantable() || endpoint_allowlist.is_empty() {
                return Err(invalid_grant());
            }
            for endpoint in endpoint_allowlist {
                canonical_non_empty_str(endpoint)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn standing_outbound_grant_principal_index_prefix(
    principal_ref: &str,
) -> Result<Vec<u8>> {
    let principal_ref = non_empty_string(principal_ref)?;
    let principal_len = u16::try_from(principal_ref.len()).map_err(|_| invalid_grant())?;
    let mut key = Vec::with_capacity(PRINCIPAL_INDEX_PREFIX.len() + 2 + principal_ref.len());
    key.extend_from_slice(PRINCIPAL_INDEX_PREFIX);
    key.extend_from_slice(&principal_len.to_be_bytes());
    key.extend_from_slice(principal_ref.as_bytes());
    Ok(key)
}

pub(crate) fn standing_outbound_grant_principal_index_key(
    principal_ref: &str,
    id: &EntityId,
) -> Result<Vec<u8>> {
    let mut key = standing_outbound_grant_principal_index_prefix(principal_ref)?;
    key.extend_from_slice(id.as_bytes());
    Ok(key)
}

pub(crate) fn standing_outbound_grant_principal_index_entity_id(
    key: &[u8],
    principal_ref: &str,
) -> Result<EntityId> {
    let prefix = standing_outbound_grant_principal_index_prefix(principal_ref)?;
    if key.len() != prefix.len() + ENTITY_ID_LEN || !key.starts_with(&prefix) {
        return Err(Error::CorruptedIndex("outbound grant principal index key"));
    }
    let mut raw_id = [0; ENTITY_ID_LEN];
    raw_id.copy_from_slice(&key[prefix.len()..]);
    EntityId::from_bytes(raw_id)
        .map_err(|_| Error::CorruptedIndex("outbound grant principal index key"))
}

fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    validate_keys_with_optional(entries, keys, &[])
}

fn validate_keys_with_optional(
    entries: &[(Value, Value)],
    required_keys: &[&str],
    optional_keys: &[&str],
) -> Result<()> {
    let mut required_seen = vec![false; required_keys.len()];
    let mut optional_seen = vec![false; optional_keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_grant)?;
        if let Some(index) = required_keys.iter().position(|known| *known == key) {
            if required_seen[index] {
                return Err(invalid_grant());
            }
            required_seen[index] = true;
        } else if let Some(index) = optional_keys.iter().position(|known| *known == key) {
            if optional_seen[index] {
                return Err(invalid_grant());
            }
            optional_seen[index] = true;
        } else {
            return Err(invalid_grant());
        }
    }
    if required_seen.into_iter().all(|value| value) {
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

fn decode_non_empty_string(value: &Value) -> Result<String> {
    let value = value.as_str().ok_or_else(invalid_grant)?;
    non_empty_string(value)
}

fn decode_canonical_non_empty_string(value: &Value) -> Result<String> {
    let value = value.as_str().ok_or_else(invalid_grant)?;
    canonical_non_empty_str(value)?;
    Ok(value.to_owned())
}

fn decode_optional_string(value: &Value) -> Result<Option<String>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    decode_non_empty_string(value).map(Some)
}

fn decode_optional_u64(value: &Value) -> Result<Option<u64>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    value.as_u64().ok_or_else(invalid_grant).map(Some)
}

fn decode_non_empty_binary(value: &Value) -> Result<Vec<u8>> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_grant());
    };
    if bytes.is_empty() {
        return Err(invalid_grant());
    }
    Ok(bytes.clone())
}

fn decode_canonical_non_empty_string_array(value: &Value) -> Result<Vec<String>> {
    let Value::Array(values) = value else {
        return Err(invalid_grant());
    };
    if values.is_empty() {
        return Err(invalid_grant());
    }
    values
        .iter()
        .map(decode_canonical_non_empty_string)
        .collect()
}

fn decode_hash32(value: &Value) -> Result<[u8; 32]> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_grant());
    };
    bytes.as_slice().try_into().map_err(|_| invalid_grant())
}

fn option_string_value(value: Option<&str>) -> Value {
    value.map_or(Value::Nil, Value::from)
}

fn non_empty_optional(value: Option<&str>) -> Result<Option<String>> {
    value.map(non_empty_string).transpose()
}

fn non_empty_string(value: &str) -> Result<String> {
    non_empty_str(value)?;
    Ok(value.trim().to_owned())
}

fn non_empty_str(value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(invalid_grant());
    }
    Ok(())
}

fn canonical_non_empty_str(value: &str) -> Result<()> {
    non_empty_str(value)?;
    if value != value.trim() {
        return Err(invalid_grant());
    }
    Ok(())
}

fn refs_match(candidate: &str, target: &str) -> bool {
    candidate.trim() == target.trim()
}

fn is_send_class_verb(verb: &str) -> bool {
    verb.trim() == SEND_VERB_CLASS
}

fn is_mcp_channel(channel: &str) -> bool {
    channel
        .trim()
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("mcp:"))
}

fn invalid_grant() -> Error {
    Error::InvalidOutboundGrantBody("body failed validation")
}

impl Vault {
    /// Mints a standing outbound grant from an authenticated OF-336 grant intent.
    pub fn mint_standing_outbound_grant(
        &self,
        id: &EntityId,
        intent: &crate::genui::GrantMintIntent,
        created_at: u64,
    ) -> Result<StandingOutboundGrant> {
        let policy = {
            let rtxn = self.store.env.read_txn()?;
            crate::gate::resolve_policy_manifest(&self.store, &rtxn)?
        };
        let (binding_diff_handle, read_frontier_hash) =
            crate::gate::standing_outbound_grant_binding_parts(intent, &policy)?;
        let grant = StandingOutboundGrant::from_grant_mint_intent(
            intent,
            created_at,
            binding_diff_handle,
            read_frontier_hash,
        )?;
        let data = encode_standing_outbound_grant_body(&grant)?;
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_some() {
            return Err(Error::OutboundGrantAlreadyExists);
        }
        self.apply_standing_outbound_grant_body(&mut wtxn, id, created_at, data)?;
        wtxn.commit()?;
        Ok(grant)
    }

    /// Mints a payload-aware standing grant from an authenticated grant-time
    /// decision and binds it to the current policy floor.
    pub fn mint_scoped_mcp_outbound_grant(
        &self,
        id: &EntityId,
        intent: &ScopedMcpGrantMintIntent,
        created_at: u64,
    ) -> Result<StandingOutboundGrant> {
        let policy = {
            let rtxn = self.store.env.read_txn()?;
            crate::gate::resolve_policy_manifest(&self.store, &rtxn)?
        };
        let binding_diff_handle = scoped_mcp_grant_binding_handle(intent);
        let grant = StandingOutboundGrant::from_scoped_mcp_grant_mint_intent(
            intent,
            created_at,
            binding_diff_handle,
            policy.read_frontier_hash()?,
        )?;
        let data = encode_standing_outbound_grant_body(&grant)?;
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_some() {
            return Err(Error::OutboundGrantAlreadyExists);
        }
        self.apply_standing_outbound_grant_body(&mut wtxn, id, created_at, data)?;
        wtxn.commit()?;
        Ok(grant)
    }

    /// Revokes a standing outbound grant by rewriting the same record as revoked.
    pub fn revoke_standing_outbound_grant(
        &self,
        id: &EntityId,
        revoked_at: u64,
    ) -> Result<StandingOutboundGrant> {
        let mut wtxn = self.store.env.write_txn()?;
        let raw = self
            .store
            .entities
            .get(&wtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_OUTBOUND_GRANT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        let grant = decode_standing_outbound_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let revoked = grant.revoked(revoked_at)?;
        let data = encode_standing_outbound_grant_body(&revoked)?;
        self.apply_standing_outbound_grant_body(&mut wtxn, id, revoked_at, data)?;
        wtxn.commit()?;
        Ok(revoked)
    }

    /// Reads and decodes a standing outbound grant record.
    pub fn get_standing_outbound_grant(
        &self,
        id: &EntityId,
    ) -> Result<Option<StandingOutboundGrant>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_OUTBOUND_GRANT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_standing_outbound_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    fn apply_standing_outbound_grant_body(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        learned_at: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        let new_grant = decode_standing_outbound_grant_body(&data)?;
        let new_index_key =
            standing_outbound_grant_principal_index_key(&new_grant.principal_ref, id)?;
        let old_index_key = if let Some(raw) = self.store.entities.get(&*wtxn, id.as_bytes())? {
            let Some(header) = EntityMetadataHeader::parse(&raw) else {
                return Err(Error::CorruptedIndex("outbound grant entity header"));
            };
            if header.entity_type != ENTITY_TYPE_OUTBOUND_GRANT {
                return Err(Error::CorruptedIndex("outbound grant entity type"));
            }
            let old_grant = decode_standing_outbound_grant_body(
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            )?;
            Some(standing_outbound_grant_principal_index_key(
                &old_grant.principal_ref,
                id,
            )?)
        } else {
            None
        };
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_OUTBOUND_GRANT,
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
        )?;
        if let Some(old_index_key) = old_index_key.as_ref()
            && old_index_key != &new_index_key
        {
            self.store.vault_meta.delete(wtxn, old_index_key)?;
        }
        self.store.vault_meta.put(wtxn, &new_index_key, &[])?;
        Ok(())
    }
}

fn scoped_mcp_grant_binding_handle(intent: &ScopedMcpGrantMintIntent) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    scoped_mcp_binding_hash_bytes(
        &mut hasher,
        b"oneiron.gate.standing_outbound_grant.scoped_mcp.v1",
    );
    scoped_mcp_binding_hash_str(&mut hasher, &intent.principal_ref);
    scoped_mcp_binding_hash_str(&mut hasher, &intent.origin_component_id);
    scoped_mcp_binding_hash_str(&mut hasher, &intent.origin_action_id);
    if let Some(origin_receipt_ref) = intent.origin_receipt_ref.as_deref() {
        scoped_mcp_binding_hash_str(&mut hasher, origin_receipt_ref);
    }
    scoped_mcp_binding_hash_str(&mut hasher, &intent.server);
    scoped_mcp_binding_hash_str(&mut hasher, &intent.tool);
    scoped_mcp_binding_hash_str(&mut hasher, intent.data_class_ceiling.as_str());
    for endpoint in &intent.endpoint_allowlist {
        scoped_mcp_binding_hash_str(&mut hasher, endpoint);
    }
    hasher.finalize().as_bytes().to_vec()
}

fn scoped_mcp_binding_hash_str(hasher: &mut blake3::Hasher, value: &str) {
    scoped_mcp_binding_hash_bytes(hasher, value.as_bytes());
}

fn scoped_mcp_binding_hash_bytes(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests;
