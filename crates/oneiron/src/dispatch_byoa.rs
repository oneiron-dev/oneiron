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
    AttemptState, CompleteAttempt, CompleteOutcome, EnqueueAttempt, EnqueueOutcome, FailAttempt,
    FailOutcome, FinishAttemptLanding, FinishLandingOutcome, SetAttemptResult,
};
use crate::blob_artifact::{
    BlobArtifactBody, BlobVersionProvenance, encode_blob_artifact_body,
    read_blob_artifact_head_in_txn,
};
use crate::checkout::{
    CheckoutFactSink, CheckoutId, CheckoutLeaseAct, CheckoutLeaseService, CheckoutLeaseState,
    CheckoutLiveness,
};
use crate::code_sandbox::microvm::ExecutionBudget;
use crate::code_sandbox::{SandboxBoundaryContract, SandboxCredentialHandle, SandboxGuestTier};
use crate::codebase::entity_id_from_hash_material;
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;
use crate::git_wire::{GitRefName, GitWire, GitWireRepo};
use crate::llm::{BudgetLease, LlmBackend, LlmRequest, ModelId};
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

/// Maximum bytes in each binary exhaust stream.
pub const BYOA_MAX_EXHAUST_STREAM_BYTES: usize = 4 * 1024 * 1024;
/// Maximum total stream and checkpoint text bytes in one capture.
pub const BYOA_MAX_EXHAUST_TOTAL_BYTES: usize = 8 * 1024 * 1024;
// Vec<u8> is encoded as a MessagePack sequence: a byte can take two bytes.
const MAX_EXHAUST_ENCODED_BYTES: usize = 2 * BYOA_MAX_EXHAUST_TOTAL_BYTES + 64 * 1024;

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
// Keep terminal retries within attempt_queue::validate's failure-reason bound.
const MAX_STOP_REASON_LEN: usize = 2048;

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

/// The claimed attempt a host is about to execute. Connector truth is loaded
/// from this row, never supplied again by the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByoaExecutionFence {
    pub attempt_id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
}

/// Host-owned MCP client. Implementations attach to the configured server,
/// perform the bounded call, close the session, and return its exhaust.
/// Credential resolution and MCP wire details stay outside the engine.
pub trait ByoaMcpExecutor {
    /// Must enforce the supplied runtime budget and exhaust byte limits while
    /// collecting output, not after reading an unbounded transport response.
    ///
    /// # Errors
    /// Returns a refusal if attachment or execution fails.
    fn attach_and_run(
        &mut self,
        spec: &ProtocolAttachSpec,
        input: &[u8],
        budget: ExecutionBudget,
    ) -> ByoaResult<ByoaExhaust>;
}

/// Host-owned foreign sandbox runner. There is no process/shell fallback.
/// The host resolves the live checkout into its real worktree, enforces the
/// supplied foreign boundary and budget, and routes every guest network reach
/// through `authorize`. A returned lease is not permission for direct sockets.
pub trait ByoaCliExecutor {
    /// Run the exact argv against the named checkout and collect bounded exhaust.
    ///
    /// # Errors
    /// Refuses unavailable checkouts, confinement, egress, or runtime failures.
    fn run(
        &mut self,
        spec: &CliSandboxSpec,
        checkout: &CheckoutLeaseAct,
        boundary: SandboxBoundaryContract,
        budget: ExecutionBudget,
        authorize: &mut dyn FnMut(&str, u64) -> ByoaResult<ByoaEgressLease>,
    ) -> ByoaResult<ByoaExhaust>;
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
const ERR_EXHAUST_TOO_LARGE: &str = "byoa exhaust exceeds its byte budget";
const ERR_ATTEMPT_KIND: &str = "operation requires a valid BYOA attempt";
const ERR_EXECUTION_SHAPE: &str = "execution does not match the persisted connector";
const ERR_EXECUTION_BUDGET: &str = "byoa execution requires a bounded budget";
const ERR_EXECUTION_CHECKOUT: &str = "byoa execution requires a live matching checkout";
const ERR_ARTIFACT_COLLISION: &str = "byoa exhaust artifact is not owned by this capture";
const ERR_RUNTIME_ACTOR_COLLISION: &str = "byoa runtime actor is not the canonical identity";
const ERR_CAPTURE_CONFLICT: &str = "byoa capture conflicts with the canonical result";
const ERR_STOP_REASON_EMPTY: &str = "failure reason must not be empty";
const ERR_STOP_REASON_TOO_LONG: &str = "failure reason exceeds 2048 bytes";
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
    /// Why the executor stopped. Failed and abandoned captures use a default
    /// when omitted; a supplied reason must satisfy the queue's reason bounds.
    /// Retries must match the stored reason after applying that default.
    /// Advisory for the other dispositions.
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
    // Retained after settlement clears the row's live owner. Terminal retries
    // must present the same fence rather than borrowing generic no-op semantics.
    // Old exhaust remains readable, but missing fence evidence cannot authorize a retry.
    #[serde(default)]
    lease_owner: String,
    #[serde(default)]
    attempt_count: u32,
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

        let status = |attempt: AttemptRecord| -> ByoaResult<ByoaDispatchStatus> {
            let connector_kind = decode_byoa_record(&attempt)?.connector.kind();
            Ok(ByoaDispatchStatus {
                attempt,
                connector_kind,
            })
        };
        Ok(match outcome {
            EnqueueOutcome::Enqueued(attempt) => ByoaDispatchOutcome::Dispatched(status(attempt)?),
            EnqueueOutcome::Existing(attempt) => ByoaDispatchOutcome::Existing(status(attempt)?),
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

    fn execution_record(&self, fence: &ByoaExecutionFence) -> ByoaResult<AttemptRecord> {
        let record = AttemptQueue::new(self.vault)
            .get(fence.attempt_id)?
            .ok_or_else(|| invalid(ERR_ATTEMPT_MISSING))?;
        decode_byoa_record(&record)?;
        AttemptQueue::check_result_lease(
            &record,
            &fence.lease_owner,
            fence.attempt_count,
            "execute_byoa",
        )?;
        if record.result_ref.is_some() {
            return Err(invalid(ERR_CAPTURE_CONFLICT));
        }
        Ok(record)
    }

    /// Invokes the persisted endpoint through its host backend and budget lease.
    /// The returned transcript can be passed to `capture_terminal_exhaust`.
    /// The backend owns transport timeouts and enforces its budget lease.
    ///
    /// # Errors
    /// Refuses stale fences, unbound/mismatched models, oversized input/output,
    /// and backend failures. Provider error text is not copied into custody.
    pub async fn execute_endpoint(
        &self,
        fence: &ByoaExecutionFence,
        slug: &str,
        request: LlmRequest,
        lease: &BudgetLease,
    ) -> ByoaResult<ByoaExhaust> {
        let record = self.execution_record(fence)?;
        let ByoaConnectorSpec::Endpoint(spec) = decode_byoa_record(&record)?.connector else {
            return Err(invalid(ERR_EXECUTION_SHAPE));
        };
        if spec.model_for_slug(slug)? != &request.model {
            return Err(invalid(ERR_EXECUTION_SHAPE));
        }
        encode_execution_transcript(&request)?;
        let backend = self.endpoint_backend(&spec)?;
        let response = backend
            .generate(request, lease)
            .await
            .map_err(|_| ByoaError::Backend("endpoint execution failed".to_owned()))?;
        Ok(ByoaExhaust {
            transcript: Some(encode_execution_transcript(&response)?),
            ..ByoaExhaust::default()
        })
    }

    /// Attaches and executes MCP using the host client, not just its config.
    ///
    /// # Errors
    /// Refuses an invalid fence, connector, budget, or oversized input/output,
    /// and propagates the host client's refusal.
    pub fn execute_mcp<M: ByoaMcpExecutor>(
        &self,
        fence: &ByoaExecutionFence,
        input: &[u8],
        budget: ExecutionBudget,
        executor: &mut M,
    ) -> ByoaResult<ByoaExhaust> {
        validate_execution_budget(budget)?;
        if input.len() > BYOA_MAX_EXHAUST_STREAM_BYTES {
            return Err(invalid(ERR_EXHAUST_TOO_LARGE));
        }
        let record = self.execution_record(fence)?;
        let ByoaConnectorSpec::ProtocolAttach(spec) = decode_byoa_record(&record)?.connector else {
            return Err(invalid(ERR_EXECUTION_SHAPE));
        };
        let exhaust = executor.attach_and_run(&spec, input, budget)?;
        validate_exhaust(&exhaust)?;
        Ok(exhaust)
    }

    /// Invokes a host sandbox against a live checkout through the foreign
    /// boundary. Lease validation occurs again at terminal capture; no LMDB
    /// write lock is held while host code executes.
    ///
    /// # Errors
    /// Refuses stale leases, missing/expired checkouts, invalid budgets, and
    /// unbounded output, or propagates the sandbox's refusal.
    pub fn execute_cli<C: ByoaCliExecutor, F: CheckoutFactSink, L: CheckoutLiveness>(
        &mut self,
        fence: &ByoaExecutionFence,
        budget: ExecutionBudget,
        checkouts: &CheckoutLeaseService<'_, F, L>,
        executor: &mut C,
        now: u64,
    ) -> ByoaResult<ByoaExhaust> {
        validate_execution_budget(budget)?;
        let record = self.execution_record(fence)?;
        let ByoaConnectorSpec::CliSandbox(spec) = decode_byoa_record(&record)?.connector else {
            return Err(invalid(ERR_EXECUTION_SHAPE));
        };
        let checkout = checkouts
            .get(spec.checkout_id)
            .map_err(|_| invalid(ERR_EXECUTION_CHECKOUT))?
            .ok_or_else(|| invalid(ERR_EXECUTION_CHECKOUT))?;
        if checkout.state != CheckoutLeaseState::Active
            || now < checkout.updated_at
            || checkout
                .lease_expires_at
                .is_some_and(|expiry| now >= expiry)
            || record
                .task_ref
                .as_ref()
                .is_some_and(|task| *task != checkout.task_ref.to_hex())
        {
            return Err(invalid(ERR_EXECUTION_CHECKOUT));
        }
        let intent = bytes_to_hex_lower(fence.attempt_id.as_bytes());
        let mut authorize = |host: &str, at: u64| {
            if at < now {
                return Err(invalid(ERR_LEASE_EXPIRED));
            }
            self.authorize_cli_egress(&spec, host, &intent, at)
        };
        let exhaust = executor.run(
            &spec,
            &checkout,
            CliSandboxSpec::boundary_contract(),
            budget,
            &mut authorize,
        )?;
        validate_exhaust(&exhaust)?;
        Ok(exhaust)
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

    /// Folds a terminated executor's exhaust into one canonical artifact.
    ///
    /// Artifact, actor, result reference, and terminal settlement commit in one
    /// write transaction. Completed and failed captures require a leased row;
    /// cancelled captures finish an accepted landing without force authority or
    /// handoff. Retries never append another version. An abandoned retry returns
    /// the first result, even if the new exhaust differs.
    ///
    /// # Errors
    ///
    /// Refuses invalid BYOA rows, stale leases, conflicting results, artifact
    /// collisions, and invalid or oversized exhaust without durable writes.
    pub fn capture_terminal_exhaust(
        &mut self,
        request: CaptureByoaExhaust,
    ) -> ByoaResult<ByoaTerminalReceipt> {
        self.vault
            .try_with_write_txn(|wtxn| self.capture_terminal_exhaust_in_txn(wtxn, request))
    }

    fn capture_terminal_exhaust_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        request: CaptureByoaExhaust,
    ) -> ByoaResult<ByoaTerminalReceipt> {
        validate_exhaust(&request.exhaust)?;
        let reason = normalize_capture_reason(request.disposition, request.reason)?;
        if request.lease_owner.is_empty() || request.lease_owner.len() > 128 {
            return Err(invalid(ERR_CAPTURE_CONFLICT));
        }
        let artifact_id = byoa_exhaust_artifact_id(request.attempt_id)?;
        let result_ref = byoa_result_ref(&artifact_id, 1)?;
        let envelope = ByoaExhaustEnvelope {
            schema_version: BYOA_CONNECTOR_SCHEMA_VERSION,
            attempt_id: *request.attempt_id.as_bytes(),
            lease_owner: request.lease_owner,
            attempt_count: request.attempt_count,
            disposition: request.disposition,
            exhaust: request.exhaust,
        };
        let bytes = encode_exhaust_envelope(&envelope)?;
        let body = BlobArtifactBody::new(
            byoa_exhaust_artifact_name(request.attempt_id),
            BYOA_EXHAUST_MEDIA_TYPE,
        );
        let occurred = TimeRange {
            start: request.now,
            end: request.now,
        };
        let action = match request.disposition {
            ByoaTerminalDisposition::Completed => "complete",
            ByoaTerminalDisposition::Failed => "fail",
            ByoaTerminalDisposition::Cancelled => "finish_landing",
            ByoaTerminalDisposition::Abandoned => "abandon",
        };
        let queue = AttemptQueue::new(self.vault);
        let record = queue
            .get_in_write_txn(wtxn, request.attempt_id)?
            .ok_or(ByoaError::Store(Error::InvalidAttemptQueueTransition {
                action: "capture_byoa_exhaust",
                state: ERR_ATTEMPT_MISSING,
            }))?;
        decode_byoa_record(&record)?;
        if record.state.is_running() {
            AttemptQueue::check_result_lease(
                &record,
                &envelope.lease_owner,
                envelope.attempt_count,
                action,
            )?;
        } else if record.result_ref.is_none()
            || record.attempt_count != envelope.attempt_count
            || !disposition_matches_state(envelope.disposition, record.state)
        {
            return Err(ByoaError::Store(Error::InvalidAttemptQueueTransition {
                action,
                state: record.state.as_str(),
            }));
        }
        let provenance = BlobVersionProvenance::AgentRun {
            run_ref: record
                .run_id
                .clone()
                .unwrap_or_else(|| bytes_to_hex_lower(request.attempt_id.as_bytes())),
        };
        if let Some(existing_ref) = record.result_ref.as_ref() {
            // This build never commits a canonical capture on a running row.
            // A generic result attachment cannot stand in for terminal custody.
            if !record.state.is_terminal() || existing_ref != &result_ref {
                return Err(invalid(ERR_CAPTURE_CONFLICT));
            }
            if matches!(
                envelope.disposition,
                ByoaTerminalDisposition::Failed | ByoaTerminalDisposition::Abandoned
            ) && record.last_error.as_deref() != Some(reason.as_str())
            {
                return Err(invalid(ERR_CAPTURE_CONFLICT));
            }
            validate_canonical_capture(
                self.vault,
                wtxn,
                &artifact_id,
                &body,
                &provenance,
                &envelope,
            )?;
            return Ok(ByoaTerminalReceipt {
                attempt: record,
                artifact_id,
                artifact_version: 1,
                result_ref,
            });
        }
        // An unattached artifact can never be a partial successful capture:
        // all custody writes now share this transaction. Refuse collisions,
        // including empty chains with perfectly matching caller-made metadata.
        if self
            .vault
            .get_entity_type_in_txn(wtxn, &artifact_id)?
            .is_some()
            || read_blob_artifact_head_in_txn(&self.vault.store, wtxn, &artifact_id)?.is_some()
        {
            return Err(invalid(ERR_ARTIFACT_COLLISION));
        }
        // Attach and settle through the queue's existing fenced doors. No
        // writer can interleave a different disposition, and any later failure
        // rolls back the row, dedupe release, receipts, and artifact together.
        queue.set_result_in_txn(
            wtxn,
            SetAttemptResult {
                id: request.attempt_id,
                lease_owner: envelope.lease_owner.clone(),
                attempt_count: envelope.attempt_count,
                result_ref: result_ref.clone(),
                now: request.now,
            },
        )?;
        let attempt = match envelope.disposition {
            ByoaTerminalDisposition::Completed => match queue.complete_in_txn(
                wtxn,
                CompleteAttempt {
                    id: request.attempt_id,
                    lease_owner: envelope.lease_owner.clone(),
                    attempt_count: envelope.attempt_count,
                    now: request.now,
                },
            )? {
                CompleteOutcome::Completed(attempt)
                | CompleteOutcome::AlreadyCompleted(attempt) => attempt,
            },
            ByoaTerminalDisposition::Failed => match queue.fail_in_txn(
                wtxn,
                FailAttempt {
                    id: request.attempt_id,
                    lease_owner: envelope.lease_owner.clone(),
                    attempt_count: envelope.attempt_count,
                    reason,
                    now: request.now,
                },
            )? {
                FailOutcome::Failed(attempt) | FailOutcome::AlreadyFailed(attempt) => attempt,
            },
            ByoaTerminalDisposition::Cancelled => match queue.finish_landing_in_txn(
                wtxn,
                FinishAttemptLanding {
                    id: request.attempt_id,
                    lease_owner: envelope.lease_owner.clone(),
                    attempt_count: envelope.attempt_count,
                    hand_off: false,
                    scheduled_at: None,
                    now: request.now,
                },
            )? {
                FinishLandingOutcome::Landed(attempt) => attempt,
                FinishLandingOutcome::HandedOff { .. } => {
                    return Err(invalid(ERR_CAPTURE_CONFLICT));
                }
            },
            ByoaTerminalDisposition::Abandoned => match queue.abandon_in_txn(
                wtxn,
                AbandonAttempt {
                    id: request.attempt_id,
                    lease_owner: envelope.lease_owner.clone(),
                    attempt_count: envelope.attempt_count,
                    result_ref: result_ref.clone(),
                    reason,
                    now: request.now,
                },
            )? {
                AbandonOutcome::Abandoned(attempt) | AbandonOutcome::AlreadyAbandoned(attempt) => {
                    attempt
                }
            },
        };
        let actor = ensure_byoa_runtime_actor(self.vault, wtxn, occurred, request.now)?;
        self.vault
            .batch_in()
            .put(
                &artifact_id,
                crate::registry::ENTITY_TYPE_BLOB_ARTIFACT,
                occurred,
                request.now,
                &encode_blob_artifact_body(&body)?,
            )
            .apply(wtxn)?;
        let version = self.vault.append_blob_artifact_version_in_txn(
            wtxn,
            &artifact_id,
            &bytes,
            &provenance,
            actor,
            occurred,
            request.now,
        )?;
        if version.version != 1 {
            return Err(invalid(ERR_ARTIFACT_COLLISION));
        }
        Ok(ByoaTerminalReceipt {
            attempt,
            artifact_id,
            artifact_version: version.version,
            result_ref,
        })
    }
}

/// Stamped on a failure whose caller supplied no reason.
pub const BYOA_DEFAULT_FAILURE_REASON: &str = "foreign executor failed";

/// Stamped on an abandonment whose caller supplied no reason.
pub const BYOA_DEFAULT_ABANDON_REASON: &str = "foreign executor stopped without delivering";

fn normalize_capture_reason(
    disposition: ByoaTerminalDisposition,
    reason: Option<String>,
) -> ByoaResult<String> {
    let reason = match disposition {
        ByoaTerminalDisposition::Failed => {
            reason.unwrap_or_else(|| BYOA_DEFAULT_FAILURE_REASON.to_owned())
        }
        ByoaTerminalDisposition::Abandoned => {
            reason.unwrap_or_else(|| BYOA_DEFAULT_ABANDON_REASON.to_owned())
        }
        ByoaTerminalDisposition::Completed | ByoaTerminalDisposition::Cancelled => {
            return Ok(String::new());
        }
    };
    // Match queue admission on every request, including read-only retries.
    if reason.is_empty() {
        return Err(ByoaError::Store(Error::InvalidAttemptQueueRecord(
            ERR_STOP_REASON_EMPTY,
        )));
    }
    if reason.len() > MAX_STOP_REASON_LEN {
        return Err(ByoaError::Store(Error::InvalidAttemptQueueRecord(
            ERR_STOP_REASON_TOO_LONG,
        )));
    }
    Ok(reason)
}

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
/// Only the canonical PERSON body may own this id; admitting the Agent class
/// alone does not establish runtime identity. Check and create share a transaction.
fn ensure_byoa_runtime_actor(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    occurred: TimeRange,
    learned_at: u64,
) -> ByoaResult<WriteActor> {
    let actor = byoa_runtime_actor()?;
    if let Some(entity_type) = vault.get_entity_type_in_txn(wtxn, &actor.entity_ref())? {
        crate::provenance::validate_actor_class(entity_type, actor.actor_class())?;
        let raw = vault
            .get_raw_in(wtxn, &actor.entity_ref())?
            .ok_or_else(|| invalid(ERR_RUNTIME_ACTOR_COLLISION))?;
        if entity_type != crate::registry::ENTITY_TYPE_PERSON
            || raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
                != Some(BYOA_RUNTIME_ACTOR_DOMAIN)
        {
            return Err(invalid(ERR_RUNTIME_ACTOR_COLLISION));
        }
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
    Ok(actor)
}

fn decode_byoa_record(record: &AttemptRecord) -> ByoaResult<ByoaAttemptPayload> {
    if record.kind != BYOA_ATTEMPT_KIND {
        return Err(invalid(ERR_ATTEMPT_KIND));
    }
    decode_byoa_attempt_payload(&record.payload)
}

fn disposition_matches_state(disposition: ByoaTerminalDisposition, state: AttemptState) -> bool {
    matches!(
        (disposition, state),
        (ByoaTerminalDisposition::Completed, AttemptState::Completed)
            | (ByoaTerminalDisposition::Failed, AttemptState::Failed)
            | (ByoaTerminalDisposition::Cancelled, AttemptState::Cancelled)
            | (ByoaTerminalDisposition::Abandoned, AttemptState::Abandoned)
    )
}

fn validate_canonical_capture(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    artifact_id: &EntityId,
    body: &BlobArtifactBody,
    provenance: &BlobVersionProvenance,
    requested: &ByoaExhaustEnvelope,
) -> ByoaResult<()> {
    if vault.get_blob_artifact_in_txn(wtxn, artifact_id)?.as_ref() != Some(body) {
        return Err(invalid(ERR_ARTIFACT_COLLISION));
    }
    let head = read_blob_artifact_head_in_txn(&vault.store, wtxn, artifact_id)?
        .ok_or_else(|| invalid(ERR_ARTIFACT_COLLISION))?;
    if head.version != 1 || &head.provenance != provenance {
        return Err(invalid(ERR_ARTIFACT_COLLISION));
    }
    let bytes = vault
        .read_blob_artifact_version_in_txn(wtxn, artifact_id, 1)?
        .ok_or_else(|| invalid(ERR_ARTIFACT_COLLISION))?;
    if blake3::hash(&bytes).as_bytes() != &head.content_hash {
        return Err(invalid(ERR_ARTIFACT_COLLISION));
    }
    let stored = decode_exhaust_envelope(&bytes)?;
    if stored.attempt_id != requested.attempt_id
        || stored.lease_owner != requested.lease_owner
        || stored.attempt_count != requested.attempt_count
        || stored.disposition != requested.disposition
        || (stored.disposition != ByoaTerminalDisposition::Abandoned
            && stored.exhaust != requested.exhaust)
    {
        return Err(invalid(ERR_CAPTURE_CONFLICT));
    }
    Ok(())
}

fn byoa_exhaust_artifact_name(attempt_id: AttemptId) -> String {
    format!(
        "{BYOA_ATTEMPT_KIND}/{}",
        bytes_to_hex_lower(attempt_id.as_bytes())
    )
}

fn encode_exhaust_envelope(envelope: &ByoaExhaustEnvelope) -> ByoaResult<Vec<u8>> {
    validate_exhaust(&envelope.exhaust)?;
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
    let envelope = decode_exhaust_envelope(bytes)?;
    let attempt_id = AttemptId::from_bytes(&envelope.attempt_id)?;
    Ok((attempt_id, envelope.disposition, envelope.exhaust))
}

fn decode_exhaust_envelope(bytes: &[u8]) -> ByoaResult<ByoaExhaustEnvelope> {
    if bytes.len() > MAX_EXHAUST_ENCODED_BYTES {
        return Err(invalid(ERR_EXHAUST_TOO_LARGE));
    }
    let envelope: ByoaExhaustEnvelope = rmp_serde::from_slice(bytes)
        .map_err(|_| ByoaError::Store(Error::InvalidAgentDispatchInput(ERR_EXHAUST_ENCODE)))?;
    if envelope.schema_version != BYOA_CONNECTOR_SCHEMA_VERSION {
        return Err(ByoaError::Store(Error::InvalidAgentDispatchInput(
            ERR_PAYLOAD_SCHEMA,
        )));
    }
    validate_exhaust(&envelope.exhaust)?;
    Ok(envelope)
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
        || base_url.contains('\\')
    {
        return Err(invalid(ERR_BASE_URL));
    }
    // URL parsers normalize hostless forms and backslashes. Refuse those
    // spellings, all user-info (even empty), and query/fragment credentials
    // before passing the structurally parsed endpoint to a host transport.
    let authority = base_url
        .strip_prefix("https://")
        .or_else(|| base_url.strip_prefix("http://"))
        .ok_or_else(|| invalid(ERR_BASE_URL))?
        .split(['/', '?', '#'])
        .next()
        .filter(|authority| !authority.is_empty() && !authority.contains('@'))
        .ok_or_else(|| invalid(ERR_BASE_URL))?;
    let url = reqwest::Url::parse(base_url).map_err(|_| invalid(ERR_BASE_URL))?;
    if url.host_str().is_none_or(str::is_empty)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || authority.ends_with(':')
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

fn validate_execution_budget(budget: ExecutionBudget) -> ByoaResult<()> {
    if !budget.is_bounded()
        || budget.wall_clock_secs > 3600
        || budget.mem_mib > 4096
        || budget.pids > 128
    {
        return Err(invalid(ERR_EXECUTION_BUDGET));
    }
    Ok(())
}

// Bound serialization itself rather than allocating an arbitrary request or
// response before checking its size. Host transports must bound collection too.
fn encode_execution_transcript(value: &impl Serialize) -> ByoaResult<Vec<u8>> {
    struct BoundedBytes(Vec<u8>);
    impl std::io::Write for BoundedBytes {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > BYOA_MAX_EXHAUST_STREAM_BYTES - self.0.len() {
                return Err(std::io::Error::other(ERR_EXHAUST_TOO_LARGE));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut bytes = BoundedBytes(Vec::new());
    serde_json::to_writer(&mut bytes, value).map_err(|_| invalid(ERR_EXHAUST_TOO_LARGE))?;
    Ok(bytes.0)
}

fn validate_exhaust(exhaust: &ByoaExhaust) -> ByoaResult<()> {
    if exhaust.is_empty() {
        return Err(invalid(ERR_EXHAUST_EMPTY));
    }
    let mut total = 0_usize;
    for stream in [
        exhaust.transcript.as_deref().unwrap_or_default(),
        exhaust.stdout.as_slice(),
        exhaust.stderr.as_slice(),
        exhaust.diff_bundle.as_deref().unwrap_or_default(),
    ] {
        if stream.len() > BYOA_MAX_EXHAUST_STREAM_BYTES {
            return Err(invalid(ERR_EXHAUST_TOO_LARGE));
        }
        total = total
            .checked_add(stream.len())
            .ok_or_else(|| invalid(ERR_EXHAUST_TOO_LARGE))?;
    }
    if exhaust.checkpoint_frontier.len() > MAX_CHECKPOINT_FRONTIER_ENTRIES {
        return Err(invalid(ERR_CHECKPOINT_FRONTIER));
    }
    for entry in &exhaust.checkpoint_frontier {
        if !is_bounded_printable(entry, MAX_CHECKPOINT_FRONTIER_ENTRY_LEN) {
            return Err(invalid(ERR_CHECKPOINT_FRONTIER));
        }
        total = total
            .checked_add(entry.len())
            .ok_or_else(|| invalid(ERR_EXHAUST_TOO_LARGE))?;
    }
    if total > BYOA_MAX_EXHAUST_TOTAL_BYTES {
        return Err(invalid(ERR_EXHAUST_TOO_LARGE));
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
