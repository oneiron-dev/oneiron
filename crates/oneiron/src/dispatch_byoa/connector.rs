//! Connector shapes, wire enums, attempt-payload codec, and serde adapters.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::checkout::CheckoutId;
use crate::code_sandbox::{SandboxBoundaryContract, SandboxCredentialHandle, SandboxGuestTier};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::llm::ModelId;

use super::error::{
    ByoaError, ByoaResult, ERR_ATTACH_KIND, ERR_ENDPOINT_PROTOCOL, ERR_PAYLOAD_DECODE,
    ERR_PAYLOAD_ENCODE, ERR_PAYLOAD_SCHEMA, ERR_UNKNOWN_MODEL_SLUG,
};
use super::validate::validate_connector;
/// Wire version of every connector payload this module encodes.
pub const BYOA_CONNECTOR_SCHEMA_VERSION: u8 = 1;

/// Attempt `kind` every foreign-agent dispatch lands under.
pub const BYOA_ATTEMPT_KIND: &str = "agent.dispatch.byoa";

/// Media type of the single canonical exhaust artifact.
pub const BYOA_EXHAUST_MEDIA_TYPE: &str = "application/vnd.oneiron.byoa-exhaust+msgpack";

/// Scheme prefix every BYOA result reference carries.
pub const BYOA_RESULT_REF_PREFIX: &str = "blob-artifact:";

/// Domain separator for the per-attempt exhaust artifact id.
pub(super) const BYOA_EXHAUST_ARTIFACT_ID_DOMAIN: &[u8] = b"oneiron:byoa-exhaust-artifact:v1";

/// Domain separator for the stable host-runtime write actor.
pub(super) const BYOA_RUNTIME_ACTOR_DOMAIN: &[u8] = b"oneiron:byoa-runtime-actor:v1";

/// Maximum bytes in each binary exhaust stream.
pub const BYOA_MAX_EXHAUST_STREAM_BYTES: usize = 4 * 1024 * 1024;

/// Maximum total stream and checkpoint text bytes in one capture.
pub const BYOA_MAX_EXHAUST_TOTAL_BYTES: usize = 8 * 1024 * 1024;

pub(super) const MAX_EXHAUST_ENCODED_BYTES: usize = 2 * BYOA_MAX_EXHAUST_TOTAL_BYTES + 64 * 1024;

pub(super) const MAX_BASE_URL_LEN: usize = 2048;

pub(super) const MAX_MODEL_SLUG_LEN: usize = 128;

pub(super) const MAX_MODEL_SLUG_ENTRIES: usize = 512;

pub(super) const MAX_SERVER_REF_LEN: usize = 512;

pub(super) const MAX_PROGRAM_LEN: usize = 512;

pub(super) const MAX_ARGV_ENTRIES: usize = 256;

pub(super) const MAX_ARGV_ENTRY_LEN: usize = 4096;

pub(super) const MAX_EGRESS_PROFILE_REF_LEN: usize = 256;

pub(super) const MAX_CREDENTIAL_HANDLES: usize = 32;

pub(super) const MAX_ALLOWED_HOSTS: usize = 256;

pub(super) const MAX_CHECKPOINT_FRONTIER_ENTRIES: usize = 1024;

pub(super) const MAX_CHECKPOINT_FRONTIER_ENTRY_LEN: usize = 1024;

pub(super) const MAX_STOP_REASON_LEN: usize = 2048;

/// Bytes a shell would interpret. An argv-only door refuses them in `program`
/// so a caller cannot smuggle a shell fragment through the one field that
/// names an executable.
pub(super) const SHELL_METACHARACTERS: &[char] = &[
    '|', '&', ';', '<', '>', '(', ')', '$', '`', '\\', '"', '\'', '*', '?', '[', ']', '{', '}',
    '~', '!', '#', '\n', '\r',
];

/// Which of the three v1 connector shapes an attempt row carries.
///
/// The discriminants are the pinned wire values. This type is deliberately NOT
/// serialized: the durable payload carries the connector VARIANT itself, so a
/// row cannot end up with a kind tag that disagrees with the spec beside it.
/// [`Self::wire_value`] is the outward-facing number for configuration and
/// diagnostic surfaces.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ByoaConnectorKind {
    Endpoint = 1,
    ProtocolAttach = 2,
    CliSandbox = 3,
}

impl ByoaConnectorKind {
    /// Stable wire label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Endpoint => "endpoint",
            Self::ProtocolAttach => "protocol_attach",
            Self::CliSandbox => "cli_sandbox",
        }
    }

    /// The pinned numeric wire value.
    #[must_use]
    pub const fn wire_value(self) -> u8 {
        self as u8
    }
}

/// Which host-owned codec an endpoint connector selects.
///
/// This names a PROTOCOL, not a vendor: several providers speak the
/// OpenAI-compatible shape, and the endpoint config stays provider-neutral so
/// the host factory — not this module — decides which concrete backend and
/// custody-backed transport realizes it.
///
/// Encoded as its LABEL, not its declaration index, so a durable payload stays
/// readable if the variant order ever changes.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum ByoEndpointProtocol {
    OpenAiCompat = 1,
    AnthropicMessages = 2,
}

impl ByoEndpointProtocol {
    /// Stable wire label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAiCompat => "openai_compat",
            Self::AnthropicMessages => "anthropic_messages",
        }
    }

    /// The pinned numeric wire value.
    #[must_use]
    pub const fn wire_value(self) -> u8 {
        self as u8
    }
}

impl From<ByoEndpointProtocol> for String {
    fn from(protocol: ByoEndpointProtocol) -> Self {
        protocol.as_str().to_owned()
    }
}

impl TryFrom<String> for ByoEndpointProtocol {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "openai_compat" => Ok(Self::OpenAiCompat),
            "anthropic_messages" => Ok(Self::AnthropicMessages),
            _ => Err(Error::InvalidAgentDispatchInput(ERR_ENDPOINT_PROTOCOL)),
        }
    }
}

/// A bring-your-own endpoint: where to reach it, which custody handle opens
/// it, which protocol it speaks, and which models it exposes.
///
/// `credential_ref` is an opaque custody handle. No field of this type can
/// hold an API key, so no encoding, rendering, or receipt derived from it can
/// leak one.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByoEndpointSpec {
    pub base_url: String,
    #[serde(with = "credential_handle_wire")]
    pub credential_ref: SandboxCredentialHandle,
    pub protocol: ByoEndpointProtocol,
    /// Caller-facing slug to canonical model id. A `BTreeMap` because the
    /// lookup must be deterministic and the encoding must be byte-stable: a
    /// hash-ordered map would make the same configuration encode differently
    /// on different runs and defeat artifact dedupe.
    pub model_slug_map: BTreeMap<String, ModelId>,
}

impl std::fmt::Debug for ByoEndpointSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Public config can be constructed before validation. Never echo a
        // rejected user-info URL (or a query token) through diagnostic output.
        f.debug_struct("ByoEndpointSpec")
            .field("base_url", &"<endpoint URL>")
            .field("credential_ref", &self.credential_ref)
            .field("protocol", &self.protocol)
            .field("model_slug_map", &self.model_slug_map)
            .finish()
    }
}

impl ByoEndpointSpec {
    /// Resolves one caller-facing slug to the model it names.
    ///
    /// # Errors
    ///
    /// Returns [`ByoaError::Backend`] for a slug this endpoint does not bind.
    /// An unknown slug is a REFUSAL, never a pass-through: forwarding it would
    /// let a caller address any model the far side happens to host, which is
    /// exactly the exposure the map exists to bound.
    pub fn model_for_slug(&self, slug: &str) -> ByoaResult<&ModelId> {
        self.model_slug_map
            .get(slug)
            .ok_or_else(|| ByoaError::Backend(ERR_UNKNOWN_MODEL_SLUG.to_owned()))
    }
}

/// The one v1 protocol-attach kind.
///
/// A2A is deliberately absent. It is a watch item, and giving it a variant
/// now — or a catch-all `Other(String)` — would mean an unimplemented protocol
/// could be configured and silently do nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum ProtocolAttachKind {
    Mcp,
}

impl ProtocolAttachKind {
    /// Stable wire label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mcp => "mcp",
        }
    }
}

impl From<ProtocolAttachKind> for String {
    fn from(kind: ProtocolAttachKind) -> Self {
        kind.as_str().to_owned()
    }
}

impl TryFrom<String> for ProtocolAttachKind {
    type Error = Error;

    /// Refuses every label but `mcp`.
    ///
    /// This is where an A2A attach dies on the READ path, matching the
    /// type-level refusal on the write path: a row hand-written with
    /// `"a2a"` decodes as an error, never as a permissive default.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "mcp" => Ok(Self::Mcp),
            _ => Err(Error::InvalidAgentDispatchInput(ERR_ATTACH_KIND)),
        }
    }
}

/// An attach to a protocol server the runtime already knows how to speak.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolAttachSpec {
    pub protocol: ProtocolAttachKind,
    pub server_ref: String,
    /// Optional because an attach may reach a server that needs no credential
    /// at all; when one is needed it is still only a handle.
    #[serde(with = "optional_credential_handle_wire")]
    pub credential_ref: Option<SandboxCredentialHandle>,
}

/// An argv-only foreign command run against a real checkout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliSandboxSpec {
    /// The executable. Never a command line: shell metacharacters are refused
    /// at the door.
    pub program: String,
    /// Arguments as a vector, exactly as they will be passed. There is no
    /// string form of this anywhere in the module, so there is nothing for a
    /// shell to re-parse.
    pub argv: Vec<String>,
    /// The real CHECKOUT this guest runs against.
    #[serde(with = "checkout_id_wire")]
    pub checkout_id: CheckoutId,
    /// Names the egress profile an injected [`ByoaEgressPort`] must honour.
    /// It is a REFERENCE to a host-side policy, not the policy itself: a guest
    /// config cannot widen its own network reach.
    pub egress_profile_ref: String,
    #[serde(with = "credential_handle_vec_wire")]
    pub credential_handles: Vec<SandboxCredentialHandle>,
}

impl CliSandboxSpec {
    /// The sandbox boundary every CLI guest runs under.
    ///
    /// Fixed at [`SandboxGuestTier::Foreign`] and not configurable: a foreign
    /// program does not get to name its own trust tier.
    #[must_use]
    pub const fn boundary_contract() -> SandboxBoundaryContract {
        SandboxBoundaryContract::for_tier(SandboxGuestTier::Foreign)
    }
}

/// One of the three v1 connector shapes.
///
/// Append-only: the encoding is externally tagged by DECLARATION INDEX, so a
/// fourth shape may only ever be added after these three. Reordering would
/// silently re-read every already-written row as the wrong connector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ByoaConnectorSpec {
    Endpoint(ByoEndpointSpec),
    ProtocolAttach(ProtocolAttachSpec),
    CliSandbox(CliSandboxSpec),
}

impl ByoaConnectorSpec {
    /// Which shape this is.
    #[must_use]
    pub const fn kind(&self) -> ByoaConnectorKind {
        match self {
            Self::Endpoint(_) => ByoaConnectorKind::Endpoint,
            Self::ProtocolAttach(_) => ByoaConnectorKind::ProtocolAttach,
            Self::CliSandbox(_) => ByoaConnectorKind::CliSandbox,
        }
    }

    /// Every custody handle this connector references, in a deterministic
    /// order. Handles only — this is the complete inventory of secret-adjacent
    /// material a connector can carry, and it is all references.
    #[must_use]
    pub fn credential_handles(&self) -> Vec<&SandboxCredentialHandle> {
        match self {
            Self::Endpoint(spec) => vec![&spec.credential_ref],
            Self::ProtocolAttach(spec) => spec.credential_ref.iter().collect(),
            Self::CliSandbox(spec) => spec.credential_handles.iter().collect(),
        }
    }
}

/// A request to dispatch one foreign agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchByoa {
    pub connector: ByoaConnectorSpec,
    pub task_ref: Option<EntityId>,
    pub parent_attempt_id: Option<AttemptId>,
    pub run_id: Option<String>,
    pub dedupe_key: Option<String>,
    pub now: u64,
}

/// The attempt row a dispatch produced, with its connector shape resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByoaDispatchStatus {
    pub attempt: AttemptRecord,
    pub connector_kind: ByoaConnectorKind,
}

/// Typed dispatch outcome. `Existing` is the advisory-dedupe hit, exactly as
/// on the underlying queue door.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ByoaDispatchOutcome {
    Dispatched(ByoaDispatchStatus),
    Existing(ByoaDispatchStatus),
}

impl ByoaDispatchOutcome {
    /// The dispatch status either arm carries.
    #[must_use]
    pub const fn status(&self) -> &ByoaDispatchStatus {
        match self {
            Self::Dispatched(status) | Self::Existing(status) => status,
        }
    }
}

/// The durable payload a BYOA attempt row carries.
///
/// The connector config and the spawn lineage ride the payload rather than new
/// queue columns: the attempt queue stays a generic mechanical store and gains
/// no BYOA-shaped fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByoaAttemptPayload {
    pub schema_version: u8,
    pub connector: ByoaConnectorSpec,
    /// The attempt that asked for this one, when there was one.
    #[serde(default)]
    pub parent_attempt: Option<[u8; 16]>,
}

/// Encodes a connector payload in its canonical form.
///
/// # Errors
///
/// Returns [`ByoaError::Store`] when the payload cannot be encoded.
pub fn encode_byoa_attempt_payload(payload: &ByoaAttemptPayload) -> ByoaResult<Vec<u8>> {
    validate_connector(&payload.connector)?;
    rmp_serde::to_vec_named(payload)
        .map_err(|_| ByoaError::Store(Error::InvalidAgentDispatchInput(ERR_PAYLOAD_ENCODE)))
}

/// Decodes a connector payload written by [`encode_byoa_attempt_payload`].
///
/// # Errors
///
/// Returns [`ByoaError::Store`] when the bytes are not a payload of a schema
/// version this build understands, or when the decoded connector would not
/// pass the dispatch door.
pub fn decode_byoa_attempt_payload(bytes: &[u8]) -> ByoaResult<ByoaAttemptPayload> {
    let payload: ByoaAttemptPayload = rmp_serde::from_slice(bytes)
        .map_err(|_| ByoaError::Store(Error::InvalidAgentDispatchInput(ERR_PAYLOAD_DECODE)))?;
    if payload.schema_version != BYOA_CONNECTOR_SCHEMA_VERSION {
        return Err(ByoaError::Store(Error::InvalidAgentDispatchInput(
            ERR_PAYLOAD_SCHEMA,
        )));
    }
    // The same door the writer passed, applied on read: a row hand-written
    // around this module cannot present a connector the dispatcher would have
    // refused.
    validate_connector(&payload.connector)?;
    Ok(payload)
}

// ---------------------------------------------------------------------------
// Serde adapters for host types that own no serde impl
// ---------------------------------------------------------------------------
//
// The custody handle and the checkout id are host-owned types this module only
// REFERENCES. Rather than widen their definitions, each is carried on the wire
// as its own public spelling and rebuilt through its own validating
// constructor on the way back, so a decoded connector is exactly as
// well-formed as one that was constructed in process.

mod credential_handle_wire {
    use super::SandboxCredentialHandle;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        handle: &SandboxCredentialHandle,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(handle.as_str())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<SandboxCredentialHandle, D::Error> {
        let raw = String::deserialize(deserializer)?;
        SandboxCredentialHandle::new(raw).map_err(serde::de::Error::custom)
    }
}

mod optional_credential_handle_wire {
    use super::SandboxCredentialHandle;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        handle: &Option<SandboxCredentialHandle>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match handle {
            Some(handle) => serializer.serialize_some(handle.as_str()),
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<SandboxCredentialHandle>, D::Error> {
        let raw = Option::<String>::deserialize(deserializer)?;
        raw.map(SandboxCredentialHandle::new)
            .transpose()
            .map_err(serde::de::Error::custom)
    }
}

mod credential_handle_vec_wire {
    use super::SandboxCredentialHandle;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(
        handles: &[SandboxCredentialHandle],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        handles
            .iter()
            .map(SandboxCredentialHandle::as_str)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<SandboxCredentialHandle>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(SandboxCredentialHandle::new)
            .collect::<crate::error::Result<Vec<_>>>()
            .map_err(serde::de::Error::custom)
    }
}

mod checkout_id_wire {
    use super::CheckoutId;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(
        id: &CheckoutId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        id.as_bytes().serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<CheckoutId, D::Error> {
        let bytes = <[u8; 16]>::deserialize(deserializer)?;
        CheckoutId::from_bytes(bytes).map_err(|e| serde::de::Error::custom(format!("{e:?}")))
    }
}
