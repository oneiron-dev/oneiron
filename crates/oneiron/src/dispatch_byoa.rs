//! Foreign-agent dispatch: the connector shapes, the egress seam, and the
//! terminal exhaust capture for agents this runtime does not host.
//!
//! This organ sits BESIDE [`crate::agent_dispatch`] rather than inside it.
//! Native in-process agents keep their spawn semantics untouched; a foreign
//! agent is not spawned at all, it is CONNECTED TO, and the two concerns share
//! nothing but the attempt row they both land on. Widening the native dispatch
//! input to carry connector configuration would have mixed "how do I start
//! this" with "how do I reach that".
//!
//! Exactly three v1 connector shapes exist, and the enum is closed on purpose:
//!
//! 1. [`ByoaConnectorSpec::Endpoint`] — a provider-neutral endpoint config that
//!    a host factory resolves into an existing [`LlmBackend`]. The provider
//!    codecs stay host-owned; this module never speaks a wire protocol.
//! 2. [`ByoaConnectorSpec::ProtocolAttach`] — MCP, and only MCP. A2A gets no
//!    variant here, so an A2A attach is a compile error rather than a runtime
//!    refusal that a later change could soften into a permissive default.
//! 3. [`ByoaConnectorSpec::CliSandbox`] — an argv-only command run as a
//!    foreign sandbox guest against a real checkout. There is no shell string
//!    anywhere in this module, and no direct socket: network access exists
//!    only through an injected [`ByoaEgressPort`].
//!
//! Credentials cross this seam as [`SandboxCredentialHandle`] references and
//! never as bytes. That is the whole redaction story: there is no secret in
//! any type here to leak into an attempt payload, a `Debug` rendering, or a
//! terminal receipt, because none of them ever holds one.
//!
//! A foreign agent owes this runtime no completion protocol. What it owes is
//! EXHAUST — transcript, stdout, stderr, diff bundle, checkpoint frontier —
//! and [`ByoaDispatcher::capture_terminal_exhaust`] folds that into exactly
//! one BLOB_ARTIFACT version whose `artifact@version` string becomes the
//! attempt row's result reference. An executor that stops without completing
//! is [`crate::attempt_queue::AttemptState::Abandoned`], not failed, and still
//! points at the last exhaust it produced.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{
    AbandonAttempt, AbandonOutcome, AttemptId, AttemptQueue, AttemptRecord, AttemptResultRef,
    EnqueueAttempt, EnqueueOutcome, SetAttemptResult,
};
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::checkout::CheckoutId;
use crate::code_sandbox::{SandboxBoundaryContract, SandboxCredentialHandle, SandboxGuestTier};
use crate::codebase::entity_id_from_hash_material;
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;
use crate::git_wire::{GitRefName, GitWire, GitWireRepo};
use crate::llm::{LlmBackend, ModelId};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

#[cfg(test)]
mod tests;

/// Wire version of every connector payload this module encodes.
pub const BYOA_CONNECTOR_SCHEMA_VERSION: u8 = 1;
/// Attempt `kind` every foreign-agent dispatch lands under.
pub const BYOA_ATTEMPT_KIND: &str = "agent.dispatch.byoa";
/// Media type of the single canonical exhaust artifact.
pub const BYOA_EXHAUST_MEDIA_TYPE: &str = "application/vnd.oneiron.byoa-exhaust+msgpack";
/// Scheme prefix every BYOA result reference carries.
pub const BYOA_RESULT_REF_PREFIX: &str = "blob-artifact:";

/// Domain separator for the per-attempt exhaust artifact id.
const BYOA_EXHAUST_ARTIFACT_ID_DOMAIN: &[u8] = b"oneiron:byoa-exhaust-artifact:v1";
/// Domain separator for the stable host-runtime write actor.
const BYOA_RUNTIME_ACTOR_DOMAIN: &[u8] = b"oneiron:byoa-runtime-actor:v1";

const MAX_BASE_URL_LEN: usize = 2048;
const MAX_MODEL_SLUG_LEN: usize = 128;
const MAX_MODEL_SLUG_ENTRIES: usize = 512;
const MAX_SERVER_REF_LEN: usize = 512;
const MAX_PROGRAM_LEN: usize = 512;
const MAX_ARGV_ENTRIES: usize = 256;
const MAX_ARGV_ENTRY_LEN: usize = 4096;
const MAX_EGRESS_PROFILE_REF_LEN: usize = 256;
const MAX_CREDENTIAL_HANDLES: usize = 32;
const MAX_ALLOWED_HOSTS: usize = 256;
const MAX_CHECKPOINT_FRONTIER_ENTRIES: usize = 1024;
const MAX_CHECKPOINT_FRONTIER_ENTRY_LEN: usize = 1024;

/// Bytes a shell would interpret. An argv-only door refuses them in `program`
/// so a caller cannot smuggle a shell fragment through the one field that
/// names an executable.
const SHELL_METACHARACTERS: &[char] = &[
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Resolves an endpoint config into a concrete host-owned backend.
///
/// The factory is the host's, not this module's: provider transports, custody
/// wiring, and retry policy all stay on the host side of this seam.
pub trait ByoEndpointBackendFactory {
    /// Resolves `spec` into the backend that serves it.
    ///
    /// # Errors
    ///
    /// Returns [`ByoaError::Backend`] when no backend can serve the config, or
    /// [`ByoaError::CredentialUnavailable`] when the custody handle cannot be
    /// opened.
    fn resolve_backend(&self, spec: &ByoEndpointSpec) -> ByoaResult<Arc<dyn LlmBackend>>;
}

/// Result alias for every door in this module.
pub type ByoaResult<T> = Result<T, ByoaError>;

const ERR_UNKNOWN_MODEL_SLUG: &str = "model slug is not bound by this endpoint connector";
const ERR_ENDPOINT_PROTOCOL: &str = "endpoint protocol label is not a v1 protocol";
const ERR_ATTACH_KIND: &str = "protocol attach kind is not implemented in v1";
const ERR_DISPOSITION: &str = "byoa terminal disposition label is not recognized";
const ERR_PAYLOAD_ENCODE: &str = "byoa connector payload failed to encode";
const ERR_PAYLOAD_DECODE: &str = "byoa connector payload failed to decode";
const ERR_PAYLOAD_SCHEMA: &str = "byoa connector payload schema version is not supported";
const ERR_BASE_URL: &str = "endpoint base_url must be a bare http(s) URL";
const ERR_SLUG_MAP_EMPTY: &str = "endpoint must bind at least one model slug";
const ERR_SLUG_MAP_TOO_LARGE: &str = "endpoint binds too many model slugs";
const ERR_MODEL_SLUG: &str = "model slug must be non-empty, bounded, and printable";
const ERR_SERVER_REF: &str = "protocol attach server_ref must be non-empty and bounded";
const ERR_PROGRAM: &str = "cli sandbox program must be a bare executable, not a command line";
const ERR_ARGV_ENTRY: &str = "cli sandbox argv entry must be bounded and printable";
const ERR_ARGV_TOO_LONG: &str = "cli sandbox argv has too many entries";
const ERR_EGRESS_PROFILE_REF: &str = "cli sandbox egress_profile_ref must be non-empty and bounded";
const ERR_CREDENTIAL_HANDLES: &str = "cli sandbox references too many credential handles";
const ERR_EXHAUST_ENCODE: &str = "byoa exhaust failed to encode";
const ERR_EXHAUST_EMPTY: &str = "byoa exhaust must carry at least one stream";
const ERR_CHECKPOINT_FRONTIER: &str = "byoa checkpoint frontier entry is unbounded or unprintable";
const ERR_ATTEMPT_MISSING: &str = "missing";
const ERR_RESULT_REF_SHAPE: &str = "byoa result reference is not artifact@version shaped";
const ERR_LEASE_PROFILE_MISMATCH: &str = "egress lease names a different profile";
const ERR_LEASE_EXPIRED: &str = "egress lease is already expired";
const ERR_LEASE_UNBOUNDED: &str = "egress lease grants no bounded host scope";
const ERR_LEASE_HOST_DENIED: &str = "egress lease does not admit the requested host";
const ERR_LEASE_ID_ZERO: &str = "egress lease carries no lease id";

/// Every way a foreign-agent door can refuse.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ByoaError {
    /// Network was attempted without a lease that admits it. This is the
    /// refusal a direct-socket attempt lands on: there is no other door.
    #[error("byoa egress denied for profile {profile_ref}: {reason}")]
    EgressDenied { profile_ref: String, reason: String },
    /// A custody handle could not be opened. Carries the HANDLE, which is a
    /// reference; it can never carry the material behind it.
    #[error("byoa credential unavailable: {}", .0.as_str())]
    CredentialUnavailable(SandboxCredentialHandle),
    /// The host-owned backend seam refused.
    #[error("byoa backend refused: {0}")]
    Backend(String),
    /// Any crate-level refusal raised beneath this module — a queue door, a
    /// vault write, or a connector validator.
    #[error(transparent)]
    Store(#[from] Error),
}

/// The proof that one network reach crossed the injected egress port.
///
/// Scope, expiry, and audit reference all live on the lease so the guarantee
/// stays inspectable after the fact: a reviewer can tell what was reachable,
/// until when, and which audit row authorized it, without re-deriving any of
/// it from policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByoaEgressLease {
    pub lease_id: [u8; 16],
    pub profile_ref: String,
    /// Host suffixes this lease admits. Matching is label-boundary aware, so
    /// `example.com` never admits `notexample.com`.
    pub allowed_hosts: Vec<String>,
    pub expires_at: u64,
    pub audit_ref: EntityId,
}

impl ByoaEgressLease {
    /// True when this lease is still live at `now` and admits `host`.
    #[must_use]
    pub fn permits_host(&self, host: &str, now: u64) -> bool {
        if now >= self.expires_at {
            return false;
        }
        let host = host.trim().trim_matches('.').to_lowercase();
        if host.is_empty() {
            return false;
        }
        self.allowed_hosts.iter().any(|allowed| {
            let allowed = allowed.trim().trim_matches('.').to_lowercase();
            !allowed.is_empty()
                && (host == allowed
                    || host
                        .strip_suffix(&allowed)
                        .is_some_and(|head| head.ends_with('.')))
        })
    }
}

/// The injected door every foreign network reach must cross.
///
/// This is an adapter seam over the host's credential-egress boundary
/// (allowlist enforcement plus resolve-and-inject). It is a TRAIT because the
/// dispatcher must be unable to reach the network on its own: with no port
/// injected there is no code path here that opens a socket.
pub trait ByoaEgressPort {
    /// Opens a lease for `profile_ref` on behalf of `intent_ref`.
    ///
    /// # Errors
    ///
    /// Returns [`ByoaError::EgressDenied`] when the profile grants nothing for
    /// this intent.
    fn open(&mut self, profile_ref: &str, intent_ref: &str) -> ByoaResult<ByoaEgressLease>;
}

/// The transcript and side-channel output one foreign agent left behind.
///
/// Every field is optional-or-empty because a foreign agent cooperates only as
/// much as it chooses to; what is NOT optional is that SOMETHING durable was
/// captured — an entirely empty exhaust is refused at the capture door, because
/// an abandonment pointing at nothing is not auditable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByoaExhaust {
    #[serde(default)]
    pub transcript: Option<Vec<u8>>,
    #[serde(default)]
    pub stdout: Vec<u8>,
    #[serde(default)]
    pub stderr: Vec<u8>,
    #[serde(default)]
    pub diff_bundle: Option<Vec<u8>>,
    /// Checkpoint refs as `name@oid`, read through the git seam.
    #[serde(default)]
    pub checkpoint_frontier: Vec<String>,
}

impl ByoaExhaust {
    /// True when nothing durable was captured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.transcript.as_ref().is_none_or(Vec::is_empty)
            && self.stdout.is_empty()
            && self.stderr.is_empty()
            && self.diff_bundle.as_ref().is_none_or(Vec::is_empty)
            && self.checkpoint_frontier.is_empty()
    }
}

/// How a foreign executor stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum ByoaTerminalDisposition {
    Completed,
    Failed,
    Cancelled,
    /// Stopped carrying the work without delivering, and without anyone
    /// stopping it.
    Abandoned,
}

impl ByoaTerminalDisposition {
    /// Stable wire label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Abandoned => "abandoned",
        }
    }
}

impl From<ByoaTerminalDisposition> for String {
    fn from(disposition: ByoaTerminalDisposition) -> Self {
        disposition.as_str().to_owned()
    }
}

impl TryFrom<String> for ByoaTerminalDisposition {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "abandoned" => Ok(Self::Abandoned),
            _ => Err(Error::InvalidAgentDispatchInput(ERR_DISPOSITION)),
        }
    }
}

/// A request to fold one terminated executor's exhaust into its artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureByoaExhaust {
    pub attempt_id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub disposition: ByoaTerminalDisposition,
    pub exhaust: ByoaExhaust,
    /// Why the executor stopped. Required for
    /// [`ByoaTerminalDisposition::Abandoned`], which cannot be recorded
    /// without one; advisory for the others.
    pub reason: Option<String>,
    pub now: u64,
}

/// What one capture produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByoaTerminalReceipt {
    pub attempt: AttemptRecord,
    pub artifact_id: EntityId,
    pub artifact_version: u64,
    pub result_ref: AttemptResultRef,
}

/// The canonical body one exhaust artifact version holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ByoaExhaustEnvelope {
    schema_version: u8,
    attempt_id: [u8; 16],
    disposition: ByoaTerminalDisposition,
    exhaust: ByoaExhaust,
}

/// The foreign-agent dispatch organ.
///
/// It owns no transport of its own. The endpoint factory and the egress port
/// are both INJECTED, which is what makes "network only through the egress
/// door" a structural property rather than a convention: there is no field
/// here that could reach a socket without one.
pub struct ByoaDispatcher<'a, B, E> {
    vault: &'a Vault,
    endpoint_factory: B,
    egress: E,
}

impl<'a, B, E> ByoaDispatcher<'a, B, E>
where
    B: ByoEndpointBackendFactory,
    E: ByoaEgressPort,
{
    /// Opens a dispatcher over an already-open vault.
    #[must_use]
    pub fn new(vault: &'a Vault, endpoint_factory: B, egress: E) -> Self {
        Self {
            vault,
            endpoint_factory,
            egress,
        }
    }

    /// Validates a foreign connector and lands it on a durable attempt row.
    ///
    /// Nothing is reached out to here. Dispatch records the INTENT; the
    /// endpoint backend and the egress lease are both acquired later, at the
    /// moment work actually runs, because an expiring lease taken at dispatch
    /// time would be dead before the executor used it.
    ///
    /// # Errors
    ///
    /// Returns [`ByoaError::Store`] when the connector fails the door or the
    /// queue refuses the row.
    pub fn dispatch(&mut self, request: DispatchByoa) -> ByoaResult<ByoaDispatchOutcome> {
        validate_connector(&request.connector)?;
        let connector_kind = request.connector.kind();
        let payload = encode_byoa_attempt_payload(&ByoaAttemptPayload {
            schema_version: BYOA_CONNECTOR_SCHEMA_VERSION,
            connector: request.connector,
            parent_attempt: request.parent_attempt_id.map(|id| *id.as_bytes()),
        })?;

        let queue = AttemptQueue::new(self.vault);
        let outcome = queue.enqueue_with_task_ref(
            EnqueueAttempt {
                kind: BYOA_ATTEMPT_KIND.to_owned(),
                payload,
                dedupe_key: request.dedupe_key,
                run_id: request.run_id,
                now: request.now,
            },
            request.task_ref.map(|task_ref| task_ref.to_hex()),
        )?;

        let status = |attempt| ByoaDispatchStatus {
            attempt,
            connector_kind,
        };
        Ok(match outcome {
            EnqueueOutcome::Enqueued(attempt) => ByoaDispatchOutcome::Dispatched(status(attempt)),
            EnqueueOutcome::Existing(attempt) => ByoaDispatchOutcome::Existing(status(attempt)),
        })
    }

    /// Resolves an endpoint connector into the host backend that serves it.
    ///
    /// # Errors
    ///
    /// Returns [`ByoaError::Store`] when the config fails the door, or the
    /// factory's own refusal.
    pub fn endpoint_backend(&self, spec: &ByoEndpointSpec) -> ByoaResult<Arc<dyn LlmBackend>> {
        validate_endpoint(spec)?;
        self.endpoint_factory.resolve_backend(spec)
    }

    /// Authorizes ONE outbound host for a CLI-sandbox guest.
    ///
    /// This is the only network door in the module. A guest that tries to
    /// reach the network any other way has no lease, and no lease means no
    /// reach: there is nothing else here to grant it.
    ///
    /// The lease the port hands back is re-checked rather than trusted: a port
    /// that returned a lease for the wrong profile, an already-expired one, an
    /// unbounded one, or one that does not admit the requested host is a
    /// denial, not a grant.
    ///
    /// # Errors
    ///
    /// Returns [`ByoaError::EgressDenied`] when the port refuses or the lease
    /// does not actually authorize `host`.
    pub fn authorize_cli_egress(
        &mut self,
        spec: &CliSandboxSpec,
        host: &str,
        intent_ref: &str,
        now: u64,
    ) -> ByoaResult<ByoaEgressLease> {
        validate_cli_sandbox(spec)?;
        let lease = self.egress.open(&spec.egress_profile_ref, intent_ref)?;
        let denied = |reason: &str| ByoaError::EgressDenied {
            profile_ref: spec.egress_profile_ref.clone(),
            reason: reason.to_owned(),
        };
        if lease.profile_ref != spec.egress_profile_ref {
            return Err(denied(ERR_LEASE_PROFILE_MISMATCH));
        }
        if lease.lease_id == [0_u8; 16] {
            return Err(denied(ERR_LEASE_ID_ZERO));
        }
        if lease.allowed_hosts.is_empty() || lease.allowed_hosts.len() > MAX_ALLOWED_HOSTS {
            return Err(denied(ERR_LEASE_UNBOUNDED));
        }
        if now >= lease.expires_at {
            return Err(denied(ERR_LEASE_EXPIRED));
        }
        if !lease.permits_host(host, now) {
            return Err(denied(ERR_LEASE_HOST_DENIED));
        }
        Ok(lease)
    }

    /// Folds a terminated executor's exhaust into ONE canonical artifact
    /// version and settles the attempt row against it.
    ///
    /// Idempotent at both layers. The artifact append de-duplicates identical
    /// bytes onto the existing head version, and the queue doors are
    /// idempotent for a reference already attached, so a capture retried after
    /// a crash converges on the SAME `artifact@version` instead of minting a
    /// second version of the same evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ByoaError::Store`] when the attempt is unknown, the exhaust
    /// is empty, the artifact write fails, or the queue refuses the terminal
    /// transition.
    pub fn capture_terminal_exhaust(
        &mut self,
        request: CaptureByoaExhaust,
    ) -> ByoaResult<ByoaTerminalReceipt> {
        validate_exhaust(&request.exhaust)?;
        let queue = AttemptQueue::new(self.vault);
        let record = queue.get(request.attempt_id)?.ok_or_else(|| {
            ByoaError::Store(Error::InvalidAttemptQueueTransition {
                action: "capture_byoa_exhaust",
                state: ERR_ATTEMPT_MISSING,
            })
        })?;

        let artifact_id = byoa_exhaust_artifact_id(request.attempt_id)?;
        let bytes = encode_exhaust_envelope(&ByoaExhaustEnvelope {
            schema_version: BYOA_CONNECTOR_SCHEMA_VERSION,
            attempt_id: *request.attempt_id.as_bytes(),
            disposition: request.disposition,
            exhaust: request.exhaust,
        })?;

        let occurred = TimeRange {
            start: request.now,
            end: request.now,
        };
        if self.vault.get_blob_artifact(&artifact_id)?.is_none() {
            self.vault.put_blob_artifact(
                &artifact_id,
                &BlobArtifactBody::new(
                    byoa_exhaust_artifact_name(request.attempt_id),
                    BYOA_EXHAUST_MEDIA_TYPE,
                ),
                occurred,
                request.now,
            )?;
        }
        // The run this exhaust belongs to, falling back to the attempt itself
        // for a row dispatched outside any named run.
        let run_ref = record
            .run_id
            .unwrap_or_else(|| bytes_to_hex_lower(request.attempt_id.as_bytes()));
        let version = self.vault.append_blob_artifact_version(
            &artifact_id,
            &bytes,
            &BlobVersionProvenance::AgentRun { run_ref },
            ensure_byoa_runtime_actor(self.vault, occurred, request.now)?,
            occurred,
            request.now,
        )?;

        let appended_ref = byoa_result_ref(&artifact_id, version.version)?;
        let (attempt, result_ref) = match request.disposition {
            ByoaTerminalDisposition::Abandoned => {
                let outcome = queue.abandon(AbandonAttempt {
                    id: request.attempt_id,
                    lease_owner: request.lease_owner,
                    attempt_count: request.attempt_count,
                    result_ref: appended_ref.clone(),
                    reason: request
                        .reason
                        .unwrap_or_else(|| BYOA_DEFAULT_ABANDON_REASON.to_owned()),
                    now: request.now,
                })?;
                let attempt = match outcome {
                    AbandonOutcome::Abandoned(attempt)
                    | AbandonOutcome::AlreadyAbandoned(attempt) => attempt,
                };
                // The receipt names what the ROW owns, not what this call just
                // appended. An abandonment is terminal and its reference is
                // write-once: the fresh path validates the rebind and stores
                // exactly the reference above, while a re-capture whose exhaust
                // bytes differ takes `AlreadyAbandoned` and keeps the FIRST
                // reference. Reporting the new version there would advertise an
                // artifact the attempt does not name, so the extra version stays
                // durable evidence only and repeated capture returns the same
                // `result_ref`. (An abandoned row always carries one; the append
                // is the fallback purely to stay total.)
                let settled_ref = attempt
                    .result_ref
                    .clone()
                    .unwrap_or_else(|| appended_ref.clone());
                (attempt, settled_ref)
            }
            // The row is still live and its worker settles it; capture only
            // names what it produced. Attaching the artifact and settling are
            // deliberately separate so the evidence is durable even if the
            // settle never happens. A divergent re-capture is refused outright
            // by `set_result`'s write-once door, so the reference the receipt
            // carries here is always the one just attached.
            ByoaTerminalDisposition::Completed
            | ByoaTerminalDisposition::Failed
            | ByoaTerminalDisposition::Cancelled => (
                queue.set_result(SetAttemptResult {
                    id: request.attempt_id,
                    lease_owner: request.lease_owner,
                    attempt_count: request.attempt_count,
                    result_ref: appended_ref.clone(),
                    now: request.now,
                })?,
                appended_ref,
            ),
        };
        // The version the receipt reports is read back OUT of the reference it
        // carries, so the two can never disagree.
        let artifact_version = parse_byoa_result_ref(&result_ref)?.1;

        Ok(ByoaTerminalReceipt {
            attempt,
            artifact_id,
            artifact_version,
            result_ref,
        })
    }
}

/// Stamped on an abandonment whose caller supplied no reason.
pub const BYOA_DEFAULT_ABANDON_REASON: &str = "foreign executor stopped without delivering";

/// The one artifact every capture for this attempt appends to.
///
/// Derived from the attempt id rather than minted per capture: that is what
/// makes "one canonical artifact per terminal attempt" a property of the
/// address, not of caller discipline.
///
/// # Errors
///
/// Returns [`ByoaError::Store`] when no non-reserved id can be derived.
pub fn byoa_exhaust_artifact_id(attempt_id: AttemptId) -> ByoaResult<EntityId> {
    Ok(entity_id_from_hash_material(
        BYOA_EXHAUST_ARTIFACT_ID_DOMAIN,
        &[attempt_id.as_bytes()],
    )?)
}

/// Builds the `blob-artifact:<id>@<version>` reference for one artifact
/// version.
///
/// # Errors
///
/// Returns [`ByoaError::Store`] when the reference fails the attempt-queue
/// result-reference door.
pub fn byoa_result_ref(artifact_id: &EntityId, version: u64) -> ByoaResult<AttemptResultRef> {
    Ok(AttemptResultRef::new(format!(
        "{BYOA_RESULT_REF_PREFIX}{}@{version}",
        artifact_id.to_hex()
    ))?)
}

/// Splits a BYOA result reference back into the artifact and version it names.
///
/// # Errors
///
/// Returns [`ByoaError::Store`] when the reference is not this module's shape.
pub fn parse_byoa_result_ref(result_ref: &AttemptResultRef) -> ByoaResult<(EntityId, u64)> {
    let shape = || ByoaError::Store(Error::InvalidAgentDispatchInput(ERR_RESULT_REF_SHAPE));
    let body = result_ref
        .as_str()
        .strip_prefix(BYOA_RESULT_REF_PREFIX)
        .ok_or_else(shape)?;
    // Split from the RIGHT: the version is the tail, and an artifact id is
    // fixed-width hex that can never contain the delimiter.
    let (id_hex, version) = body.rsplit_once('@').ok_or_else(shape)?;
    let artifact_id = EntityId::from_hex(id_hex).map_err(|_| shape())?;
    let version: u64 = version.parse().map_err(|_| shape())?;
    Ok((artifact_id, version))
}

/// Reads a checkpoint frontier for one checkout through the typed git seam.
///
/// READ-ONLY by construction: it calls only the wire's read constructors, and
/// a ref whose tip object is not actually present is omitted rather than
/// reported, so a frontier never names an object a reader could not resolve.
///
/// # Errors
///
/// Returns [`ByoaError::Store`] on any git-seam refusal.
pub fn read_checkpoint_frontier(
    wire: &GitWire<'_>,
    repo: &GitWireRepo,
    names: &[GitRefName],
) -> ByoaResult<Vec<String>> {
    let mut frontier = Vec::new();
    for observed in wire.read_refs(repo, names)? {
        let Some(oid) = observed.oid else {
            continue;
        };
        if !wire.object_exists(repo, &oid)? {
            continue;
        }
        frontier.push(format!("{}@{}", observed.name.as_str(), oid.as_str()));
    }
    Ok(frontier)
}

/// The stable host-runtime identity that authors exhaust artifact writes.
///
/// Content-free and derived, not minted: the WRITE is performed by this
/// runtime on a foreign agent's behalf, and stamping a fresh actor per capture
/// would scatter one durable responsibility across unrelated ids.
fn byoa_runtime_actor() -> ByoaResult<WriteActor> {
    Ok(WriteActor::new(
        entity_id_from_hash_material(BYOA_RUNTIME_ACTOR_DOMAIN, &[])?,
        EdgeActorClass::Agent,
    ))
}

/// Materializes the stable actor before the blob-version claim references it.
/// PERSON admits the existing Agent class. Check and create share a transaction
/// so concurrent first captures cannot overwrite an existing identity.
fn ensure_byoa_runtime_actor(
    vault: &Vault,
    occurred: TimeRange,
    learned_at: u64,
) -> ByoaResult<WriteActor> {
    let actor = byoa_runtime_actor()?;
    vault.with_write_txn(|wtxn| {
        if let Some(entity_type) = vault.get_entity_type_in_txn(wtxn, &actor.entity_ref())? {
            crate::provenance::validate_actor_class(entity_type, actor.actor_class())?;
        } else {
            vault
                .batch_in()
                .put(
                    &actor.entity_ref(),
                    crate::registry::ENTITY_TYPE_PERSON,
                    occurred,
                    learned_at,
                    BYOA_RUNTIME_ACTOR_DOMAIN,
                )
                .apply(wtxn)?;
        }
        Ok(())
    })?;
    Ok(actor)
}

fn byoa_exhaust_artifact_name(attempt_id: AttemptId) -> String {
    format!(
        "{BYOA_ATTEMPT_KIND}/{}",
        bytes_to_hex_lower(attempt_id.as_bytes())
    )
}

fn encode_exhaust_envelope(envelope: &ByoaExhaustEnvelope) -> ByoaResult<Vec<u8>> {
    rmp_serde::to_vec_named(envelope)
        .map_err(|_| ByoaError::Store(Error::InvalidAgentDispatchInput(ERR_EXHAUST_ENCODE)))
}

/// Decodes one exhaust artifact version body.
///
/// # Errors
///
/// Returns [`ByoaError::Store`] when the bytes are not an exhaust envelope of
/// a schema version this build understands.
pub fn decode_byoa_exhaust(
    bytes: &[u8],
) -> ByoaResult<(AttemptId, ByoaTerminalDisposition, ByoaExhaust)> {
    let envelope: ByoaExhaustEnvelope = rmp_serde::from_slice(bytes)
        .map_err(|_| ByoaError::Store(Error::InvalidAgentDispatchInput(ERR_EXHAUST_ENCODE)))?;
    if envelope.schema_version != BYOA_CONNECTOR_SCHEMA_VERSION {
        return Err(ByoaError::Store(Error::InvalidAgentDispatchInput(
            ERR_PAYLOAD_SCHEMA,
        )));
    }
    let attempt_id = AttemptId::from_bytes(&envelope.attempt_id)?;
    Ok((attempt_id, envelope.disposition, envelope.exhaust))
}

// ---------------------------------------------------------------------------
// Door validators
// ---------------------------------------------------------------------------

fn invalid(message: &'static str) -> ByoaError {
    ByoaError::Store(Error::InvalidAgentDispatchInput(message))
}

fn is_bounded_printable(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len && !value.chars().any(char::is_control)
}

/// Refuses a connector no executor could honestly run.
///
/// # Errors
///
/// Returns [`ByoaError::Store`] naming the field that failed.
pub fn validate_connector(connector: &ByoaConnectorSpec) -> ByoaResult<()> {
    match connector {
        ByoaConnectorSpec::Endpoint(spec) => validate_endpoint(spec),
        ByoaConnectorSpec::ProtocolAttach(spec) => validate_protocol_attach(spec),
        ByoaConnectorSpec::CliSandbox(spec) => validate_cli_sandbox(spec),
    }
}

fn validate_endpoint(spec: &ByoEndpointSpec) -> ByoaResult<()> {
    let base_url = spec.base_url.as_str();
    if !is_bounded_printable(base_url, MAX_BASE_URL_LEN)
        || base_url.chars().any(char::is_whitespace)
        || !(base_url.starts_with("https://") || base_url.starts_with("http://"))
    {
        return Err(invalid(ERR_BASE_URL));
    }
    if spec.model_slug_map.is_empty() {
        return Err(invalid(ERR_SLUG_MAP_EMPTY));
    }
    if spec.model_slug_map.len() > MAX_MODEL_SLUG_ENTRIES {
        return Err(invalid(ERR_SLUG_MAP_TOO_LARGE));
    }
    for slug in spec.model_slug_map.keys() {
        if !is_bounded_printable(slug, MAX_MODEL_SLUG_LEN) {
            return Err(invalid(ERR_MODEL_SLUG));
        }
    }
    Ok(())
}

fn validate_protocol_attach(spec: &ProtocolAttachSpec) -> ByoaResult<()> {
    if !is_bounded_printable(&spec.server_ref, MAX_SERVER_REF_LEN) {
        return Err(invalid(ERR_SERVER_REF));
    }
    Ok(())
}

fn validate_cli_sandbox(spec: &CliSandboxSpec) -> ByoaResult<()> {
    let program = spec.program.as_str();
    if !is_bounded_printable(program, MAX_PROGRAM_LEN)
        || program.chars().any(char::is_whitespace)
        || program.chars().any(|c| SHELL_METACHARACTERS.contains(&c))
    {
        return Err(invalid(ERR_PROGRAM));
    }
    if spec.argv.len() > MAX_ARGV_ENTRIES {
        return Err(invalid(ERR_ARGV_TOO_LONG));
    }
    for arg in &spec.argv {
        // An argument MAY be empty — an empty argv slot is meaningful to many
        // programs — but it may not be unbounded or carry control bytes.
        if arg.len() > MAX_ARGV_ENTRY_LEN || arg.chars().any(char::is_control) {
            return Err(invalid(ERR_ARGV_ENTRY));
        }
    }
    if !is_bounded_printable(&spec.egress_profile_ref, MAX_EGRESS_PROFILE_REF_LEN) {
        return Err(invalid(ERR_EGRESS_PROFILE_REF));
    }
    if spec.credential_handles.len() > MAX_CREDENTIAL_HANDLES {
        return Err(invalid(ERR_CREDENTIAL_HANDLES));
    }
    Ok(())
}

fn validate_exhaust(exhaust: &ByoaExhaust) -> ByoaResult<()> {
    if exhaust.is_empty() {
        return Err(invalid(ERR_EXHAUST_EMPTY));
    }
    if exhaust.checkpoint_frontier.len() > MAX_CHECKPOINT_FRONTIER_ENTRIES {
        return Err(invalid(ERR_CHECKPOINT_FRONTIER));
    }
    for entry in &exhaust.checkpoint_frontier {
        if !is_bounded_printable(entry, MAX_CHECKPOINT_FRONTIER_ENTRY_LEN) {
            return Err(invalid(ERR_CHECKPOINT_FRONTIER));
        }
    }
    Ok(())
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
