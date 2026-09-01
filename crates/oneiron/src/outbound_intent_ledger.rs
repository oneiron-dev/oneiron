//! Device-local durable intent ledger for effectful outbound calls.
//!
//! Effectful calls persist frozen bytes as `Pending` before transport. Replay
//! and recovery reuse the persisted deterministic key; these private
//! `vault_meta` rows never enter replication.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Cursor;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

use rmpv::Value;
use serde::Serialize;
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::connector_key::ScopedCapabilityProvenance;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;

/// Current schema version for device-local outbound intent rows.
///
/// v3 adds the required `capability_provenance` field (ONE-1885). These rows are
/// device-local and pre-release, so v3 is read exclusively: there is no
/// old-schema reader.
pub const INTENT_LEDGER_SCHEMA_VERSION: u64 = 3;
/// Binding format emitted and accepted by this greenfield ledger.
pub const OUTBOUND_BINDING_VERSION: u64 = 2;
/// Pinned MessagePack key set for device-local outbound intent rows.
pub const INTENT_LEDGER_VALUE_KEYS: [&str; 20] = [
    "schema_version",
    "id",
    "attempt_id",
    "call_seq",
    "server",
    "tool",
    "payload_hash",
    "payload",
    "idempotency_key",
    "idempotency_supported",
    "authorization_binding",
    "binding_version",
    "resolved_endpoint",
    "capability_provenance",
    "budget_accounting",
    "recorded_outcome",
    "state",
    "created_ms",
    "updated_ms",
    "content_digest",
];

const INTENT_LEDGER_PRIVATE_PREFIX: &[u8] = b"outbound:intent_ledger:v2:"; // + id(32)
const BUDGET_ACCOUNTING_KEYS: [&str; 5] = [
    "key_ref",
    "budget_class",
    "matched_rows",
    "sends_debit",
    "accounted_at_ms",
];
const RECORDED_OUTCOME_KEYS: [&str; 2] = ["kind", "reason"];
/// Pinned nested key set for the typed scoped capability provenance.
const CAPABILITY_PROVENANCE_KEYS: [&str; 3] = ["grant_id", "server", "connector"];

#[cfg(test)]
static FORCE_SYNC_CALLS: AtomicUsize = AtomicUsize::new(0);

const KEY_SCHEMA_VERSION: &str = INTENT_LEDGER_VALUE_KEYS[0];
const KEY_ID: &str = INTENT_LEDGER_VALUE_KEYS[1];
const KEY_ATTEMPT_ID: &str = INTENT_LEDGER_VALUE_KEYS[2];
const KEY_CALL_SEQ: &str = INTENT_LEDGER_VALUE_KEYS[3];
const KEY_SERVER: &str = INTENT_LEDGER_VALUE_KEYS[4];
const KEY_TOOL: &str = INTENT_LEDGER_VALUE_KEYS[5];
const KEY_PAYLOAD_HASH: &str = INTENT_LEDGER_VALUE_KEYS[6];
const KEY_PAYLOAD: &str = INTENT_LEDGER_VALUE_KEYS[7];
const KEY_IDEMPOTENCY_KEY: &str = INTENT_LEDGER_VALUE_KEYS[8];
const KEY_IDEMPOTENCY_SUPPORTED: &str = INTENT_LEDGER_VALUE_KEYS[9];
const KEY_AUTHORIZATION_BINDING: &str = INTENT_LEDGER_VALUE_KEYS[10];
const KEY_BINDING_VERSION: &str = INTENT_LEDGER_VALUE_KEYS[11];
const KEY_RESOLVED_ENDPOINT: &str = INTENT_LEDGER_VALUE_KEYS[12];
const KEY_CAPABILITY_PROVENANCE: &str = INTENT_LEDGER_VALUE_KEYS[13];
const KEY_BUDGET_ACCOUNTING: &str = INTENT_LEDGER_VALUE_KEYS[14];
const KEY_RECORDED_OUTCOME: &str = INTENT_LEDGER_VALUE_KEYS[15];
const KEY_STATE: &str = INTENT_LEDGER_VALUE_KEYS[16];
const KEY_CREATED_MS: &str = INTENT_LEDGER_VALUE_KEYS[17];
const KEY_UPDATED_MS: &str = INTENT_LEDGER_VALUE_KEYS[18];
const KEY_CONTENT_DIGEST: &str = INTENT_LEDGER_VALUE_KEYS[19];

pub type IntentLedgerResult<T> = std::result::Result<T, IntentLedgerError>;
pub type IntentId = [u8; 32];

/// Typed failure surface for durable outbound intent operations.
#[derive(Debug, thiserror::Error)]
pub enum IntentLedgerError {
    #[error(transparent)]
    Engine(#[from] Error),
    #[error("outbound intent canonicalization failed: {0}")]
    Canonical(#[from] serde_json::Error),
    #[error("invalid outbound intent input: {0}")]
    InvalidInput(&'static str),
    #[error("the verified outbound actor is no longer valid")]
    InvalidBoundActor,
    #[error("invalid outbound intent ledger record: {0}")]
    InvalidRecord(&'static str),
    #[error("invalid outbound intent transition: {from:?} -> {to:?}")]
    InvalidTransition { from: IntentState, to: IntentState },
}

/// Durable state of one effectful outbound intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntentState {
    Pending,
    Done,
    Abandoned,
}

impl IntentState {
    /// Stable on-disk state spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Done => "done",
            Self::Abandoned => "abandoned",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "done" => Some(Self::Done),
            "abandoned" => Some(Self::Abandoned),
            _ => None,
        }
    }

    const fn may_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Pending, Self::Done) | (Self::Pending, Self::Abandoned)
        )
    }
}

/// MCP-style tool annotation hints consumed by the fail-closed classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboundToolDescriptor {
    pub read_only_hint: Option<bool>,
    pub idempotency_supported_hint: Option<bool>,
}

impl OutboundToolDescriptor {
    #[must_use]
    pub const fn idempotency_supported(self) -> bool {
        matches!(self.idempotency_supported_hint, Some(true))
    }
}

/// Replay-safety class for one outbound tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutboundCallClass {
    ReadOnly,
    Effectful,
}

/// Classifies unknown tools as effectful. Only an explicit read-only hint is
/// allowed to bypass durable intent machinery.
#[must_use]
pub const fn classify_outbound_tool(descriptor: OutboundToolDescriptor) -> OutboundCallClass {
    if matches!(descriptor.read_only_hint, Some(true)) {
        OutboundCallClass::ReadOnly
    } else {
        OutboundCallClass::Effectful
    }
}

/// Opaque binding to the authorization decision made before ledger entry.
///
/// The chokepoint mints and verifies this carrier around the durable row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutboundAuthorizationBinding([u8; 32]);

impl OutboundAuthorizationBinding {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Semantic accounting class. It is persisted so recovery never re-derives
/// whether this intent consumed the sends dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BudgetClass {
    Send,
    Operation,
}

impl BudgetClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Operation => "operation",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "send" => Some(Self::Send),
            "operation" => Some(Self::Operation),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_send(self) -> bool {
        matches!(self, Self::Send)
    }
}

/// Durable proof that accounting and `Pending` were committed together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetChargeMarker {
    pub key_ref: Option<EntityId>,
    pub budget_class: BudgetClass,
    pub matched_rows: Vec<u16>,
    pub sends_debit: u64,
    pub accounted_at_ms: u64,
}

/// Machine-readable reason that requires caller escalation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntentEscalationReason {
    NonIdempotentAmbiguous,
    NonIdempotentPending,
    ConnectorRevoked,
    BindingInvalid,
    PreviouslyAbandoned,
    CorruptLedgerRow,
}

impl IntentEscalationReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NonIdempotentAmbiguous => "non_idempotent_ambiguous",
            Self::NonIdempotentPending => "non_idempotent_pending",
            Self::ConnectorRevoked => "connector_revoked",
            Self::BindingInvalid => "binding_invalid",
            Self::PreviouslyAbandoned => "previously_abandoned",
            Self::CorruptLedgerRow => "corrupt_ledger_row",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "non_idempotent_ambiguous" => Some(Self::NonIdempotentAmbiguous),
            "non_idempotent_pending" => Some(Self::NonIdempotentPending),
            "connector_revoked" => Some(Self::ConnectorRevoked),
            "binding_invalid" => Some(Self::BindingInvalid),
            "previously_abandoned" => Some(Self::PreviouslyAbandoned),
            "corrupt_ledger_row" => Some(Self::CorruptLedgerRow),
            _ => None,
        }
    }
}

/// Typed scrubbed outcome persisted for replay decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordedOutboundOutcome {
    /// The last transport attempt certainly did not deliver. This is a
    /// non-terminal retry permit, not a completion.
    DefiniteNonDelivery,
    Acked,
    Abandoned(IntentEscalationReason),
}

/// Caller-owned identity and once-serialized payload for one outbound call.
///
/// `call_seq` must come from the caller's durable execution context; clocks
/// and process-local counters are not replay-stable substitutes.
#[derive(Clone, PartialEq, Eq)]
pub struct OutboundCallRequest {
    pub attempt_id: AttemptId,
    pub call_seq: u64,
    pub server: String,
    pub tool: String,
    pub payload: Vec<u8>,
    pub authorization_binding: Option<OutboundAuthorizationBinding>,
    pub resolved_endpoint: Option<String>,
    /// Typed per-grant capability identity this call was admitted under, minted
    /// only by the verified scoped-MCP admission path (ONE-1885). Ordinary
    /// connector calls carry `None` and can never gain one from their text.
    capability_provenance: Option<ScopedCapabilityProvenance>,
    pub now_ms: u64,
}

impl OutboundCallRequest {
    #[must_use]
    pub fn new(
        attempt_id: AttemptId,
        call_seq: u64,
        server: impl Into<String>,
        tool: impl Into<String>,
        payload: Vec<u8>,
        now_ms: u64,
    ) -> Self {
        Self {
            attempt_id,
            call_seq,
            server: server.into(),
            tool: tool.into(),
            payload,
            authorization_binding: None,
            resolved_endpoint: None,
            capability_provenance: None,
            now_ms,
        }
    }

    #[must_use]
    pub fn with_authorization_binding(mut self, binding: OutboundAuthorizationBinding) -> Self {
        self.authorization_binding = Some(binding);
        self
    }

    /// Attaches the typed capability identity the scoped admission path minted.
    #[must_use]
    pub(crate) fn with_capability_provenance(
        mut self,
        capability: ScopedCapabilityProvenance,
    ) -> Self {
        self.capability_provenance = Some(capability);
        self
    }

    #[must_use]
    pub fn with_resolved_endpoint(mut self, resolved_endpoint: impl Into<String>) -> Self {
        self.resolved_endpoint = Some(resolved_endpoint.into());
        self
    }
}

/// Immutable transport input. The payload is serialized once by the caller;
/// senders can only read the exact bytes whose BLAKE3 hash is exposed here.
#[derive(Clone, PartialEq, Eq)]
pub struct FrozenOutboundCall {
    server: String,
    tool: String,
    payload: Box<[u8]>,
    payload_hash: [u8; 32],
    intent_id: Option<[u8; 32]>,
    idempotency_key: Option<String>,
    idempotency_supported: bool,
    authorization_binding: Option<OutboundAuthorizationBinding>,
    binding_version: u64,
    resolved_endpoint: Option<String>,
    capability_provenance: Option<ScopedCapabilityProvenance>,
}

impl FrozenOutboundCall {
    #[must_use]
    pub fn server(&self) -> &str {
        &self.server
    }

    #[must_use]
    pub fn tool(&self) -> &str {
        &self.tool
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    #[must_use]
    pub const fn payload_hash(&self) -> &[u8; 32] {
        &self.payload_hash
    }

    #[must_use]
    pub const fn intent_id(&self) -> Option<&[u8; 32]> {
        self.intent_id.as_ref()
    }

    #[must_use]
    pub fn idempotency_key(&self) -> Option<&str> {
        self.idempotency_key.as_deref()
    }

    #[must_use]
    pub const fn idempotency_supported(&self) -> bool {
        self.idempotency_supported
    }

    #[must_use]
    pub const fn authorization_binding(&self) -> Option<&OutboundAuthorizationBinding> {
        self.authorization_binding.as_ref()
    }

    #[must_use]
    pub const fn binding_version(&self) -> u64 {
        self.binding_version
    }

    #[must_use]
    pub fn resolved_endpoint(&self) -> Option<&str> {
        self.resolved_endpoint.as_deref()
    }

    /// The typed per-grant capability identity this call was authorized under,
    /// carried unchanged from admission through the durable row (ONE-1885).
    #[must_use]
    pub(crate) const fn capability_provenance(&self) -> Option<&ScopedCapabilityProvenance> {
        self.capability_provenance.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn read_only(request: OutboundCallRequest, payload_hash: [u8; 32]) -> Self {
        Self {
            server: request.server,
            tool: request.tool,
            payload: request.payload.into_boxed_slice(),
            payload_hash,
            intent_id: None,
            idempotency_key: None,
            idempotency_supported: false,
            authorization_binding: request.authorization_binding,
            binding_version: OUTBOUND_BINDING_VERSION,
            resolved_endpoint: request.resolved_endpoint,
            capability_provenance: request.capability_provenance,
        }
    }

    #[cfg(test)]
    fn effectful(
        request: OutboundCallRequest,
        payload_hash: [u8; 32],
        intent_id: [u8; 32],
        idempotency_supported: bool,
    ) -> Self {
        Self {
            server: request.server,
            tool: request.tool,
            payload: request.payload.into_boxed_slice(),
            payload_hash,
            intent_id: Some(intent_id),
            idempotency_key: Some(bytes_to_hex_lower(&intent_id)),
            idempotency_supported,
            authorization_binding: request.authorization_binding,
            binding_version: OUTBOUND_BINDING_VERSION,
            resolved_endpoint: request.resolved_endpoint,
            capability_provenance: request.capability_provenance,
        }
    }

    pub(crate) fn from_record(record: &IntentLedgerRecord) -> Self {
        Self {
            server: record.server.clone(),
            tool: record.tool.clone(),
            payload: record.payload().to_vec().into_boxed_slice(),
            payload_hash: record.payload_hash,
            intent_id: Some(record.id),
            idempotency_key: Some(record.idempotency_key.clone()),
            idempotency_supported: record.idempotency_supported,
            authorization_binding: record.authorization_binding,
            binding_version: record.binding_version,
            resolved_endpoint: record.resolved_endpoint.clone(),
            capability_provenance: record.capability_provenance.clone(),
        }
    }
}

/// Structured definite non-delivery category. Transport integrations scrub
/// wire details before selecting one of these values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OutboundFailureKind {
    Rejected,
    InvalidRequest,
    TransportNotStarted,
}

/// Definite non-delivery result with no raw body, URL, or provider text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutboundSendFailure {
    pub kind: OutboundFailureKind,
    pub code: Option<u16>,
}

/// Transport result for a frozen outbound call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutboundSendOutcome {
    /// The transport confirmed delivery.
    Acked,
    /// Delivery may have occurred; retry safety depends on idempotency support.
    Ambiguous,
    /// Certain non-delivery. An unsure transport must return [`Self::Ambiguous`].
    Failed(OutboundSendFailure),
}

/// Test-only transport seam for exercising ledger encoding primitives.
#[cfg(test)]
pub(crate) trait OutboundSender {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundSendOutcome;
}

/// Device-local durable record and audit receipt for one effectful call.
#[derive(Clone, PartialEq, Eq)]
pub struct IntentLedgerRecord {
    pub id: [u8; 32],
    pub attempt_id: AttemptId,
    pub call_seq: u64,
    pub server: String,
    pub tool: String,
    pub payload_hash: [u8; 32],
    payload: Vec<u8>,
    pub idempotency_key: String,
    pub idempotency_supported: bool,
    pub authorization_binding: Option<OutboundAuthorizationBinding>,
    pub binding_version: u64,
    pub resolved_endpoint: Option<String>,
    /// Typed per-grant capability identity, or `None` for every ordinary
    /// connector row. This durable value — never the row's connector text — is
    /// what recovery reads to decide a capability-only prohibition (ONE-1885).
    capability_provenance: Option<ScopedCapabilityProvenance>,
    pub budget_accounting: BudgetChargeMarker,
    pub recorded_outcome: Option<RecordedOutboundOutcome>,
    pub state: IntentState,
    pub created_ms: u64,
    pub updated_ms: u64,
}

impl IntentLedgerRecord {
    /// Exact persisted bytes used for recovery sends.
    #[must_use]
    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The durable typed capability identity, if this intent was admitted as a
    /// scoped per-grant capability call (ONE-1885).
    #[must_use]
    pub(crate) const fn capability_provenance(&self) -> Option<&ScopedCapabilityProvenance> {
        self.capability_provenance.as_ref()
    }

    pub(crate) fn pending(
        request: OutboundCallRequest,
        idempotency_supported: bool,
        budget_accounting: BudgetChargeMarker,
    ) -> IntentLedgerResult<Self> {
        validate_request(&request)?;
        let payload_hash = hash_frozen_payload(&request.payload);
        let id = derive_intent_id(
            request.attempt_id,
            request.call_seq,
            &request.server,
            &request.tool,
            &payload_hash,
        )?;
        Ok(Self {
            id,
            attempt_id: request.attempt_id,
            call_seq: request.call_seq,
            server: request.server,
            tool: request.tool,
            payload_hash,
            payload: request.payload,
            idempotency_key: bytes_to_hex_lower(&id),
            idempotency_supported,
            authorization_binding: request.authorization_binding,
            binding_version: OUTBOUND_BINDING_VERSION,
            resolved_endpoint: request.resolved_endpoint,
            capability_provenance: request.capability_provenance,
            budget_accounting,
            recorded_outcome: None,
            state: IntentState::Pending,
            created_ms: request.now_ms,
            updated_ms: request.now_ms,
        })
    }
}

// Manual Debug impls redact the raw outbound `payload` from every diagnostic
// surface (`{:?}` in logs/errors/test failures). Only the byte length is shown;
// the safe content-addressed surface is `payload_hash`. A derived Debug would
// leak charge/message/secret bodies, defeating the pub(crate) payload accessor.
impl fmt::Debug for OutboundCallRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundCallRequest")
            .field("attempt_id", &self.attempt_id)
            .field("call_seq", &self.call_seq)
            .field("server", &self.server)
            .field("tool", &self.tool)
            .field(
                "payload",
                &format_args!("[{} bytes redacted]", self.payload.len()),
            )
            .field("authorization_binding", &self.authorization_binding)
            .field("resolved_endpoint", &self.resolved_endpoint)
            .field("capability_provenance", &self.capability_provenance)
            .field("now_ms", &self.now_ms)
            .finish()
    }
}

impl fmt::Debug for FrozenOutboundCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrozenOutboundCall")
            .field("server", &self.server)
            .field("tool", &self.tool)
            .field(
                "payload",
                &format_args!("[{} bytes redacted]", self.payload.len()),
            )
            .field("payload_hash", &self.payload_hash)
            .field("intent_id", &self.intent_id)
            .field("idempotency_key", &self.idempotency_key)
            .field("idempotency_supported", &self.idempotency_supported)
            .field("authorization_binding", &self.authorization_binding)
            .field("binding_version", &self.binding_version)
            .field("resolved_endpoint", &self.resolved_endpoint)
            .field("capability_provenance", &self.capability_provenance)
            .finish()
    }
}

impl fmt::Debug for IntentLedgerRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntentLedgerRecord")
            .field("id", &self.id)
            .field("attempt_id", &self.attempt_id)
            .field("call_seq", &self.call_seq)
            .field("server", &self.server)
            .field("tool", &self.tool)
            .field("payload_hash", &self.payload_hash)
            .field(
                "payload",
                &format_args!("[{} bytes redacted]", self.payload.len()),
            )
            .field("idempotency_key", &self.idempotency_key)
            .field("idempotency_supported", &self.idempotency_supported)
            .field("authorization_binding", &self.authorization_binding)
            .field("binding_version", &self.binding_version)
            .field("resolved_endpoint", &self.resolved_endpoint)
            .field("capability_provenance", &self.capability_provenance)
            .field("budget_accounting", &self.budget_accounting)
            .field("recorded_outcome", &self.recorded_outcome)
            .field("state", &self.state)
            .field("created_ms", &self.created_ms)
            .field("updated_ms", &self.updated_ms)
            .finish()
    }
}

/// One intent requiring external review; corrupt keys may not contain an id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IntentEscalation {
    pub intent_id: Option<[u8; 32]>,
    pub reason: IntentEscalationReason,
}

/// Result of dispatching one read-only or effectful outbound call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentDispatchResult {
    pub class: OutboundCallClass,
    pub intent_id: Option<[u8; 32]>,
    pub state: Option<IntentState>,
    pub send_outcome: Option<OutboundSendOutcome>,
    pub replayed: bool,
    pub escalation: Option<IntentEscalation>,
}

/// One definite non-delivery observed during recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IntentRecoveryFailure {
    pub intent_id: [u8; 32],
    pub failure: OutboundSendFailure,
}

/// Counted crash-recovery result.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IntentRecoveryReport {
    pub scanned: usize,
    pub resent: usize,
    pub completed: usize,
    pub pending: usize,
    pub skipped_done: usize,
    pub skipped_abandoned: usize,
    pub escalations: Vec<IntentEscalation>,
    pub failures: Vec<IntentRecoveryFailure>,
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum IntentRecoveryEntry {
    Valid(IntentLedgerRecord),
    Corrupt(Option<IntentId>),
}

pub(crate) fn intent_recovery_entries(
    vault: &Vault,
) -> IntentLedgerResult<Vec<IntentRecoveryEntry>> {
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    let mut entries = Vec::new();
    for row in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, INTENT_LEDGER_PRIVATE_PREFIX)?
    {
        let (key, value) = row?;
        entries.push(match decode_record(&key, &value) {
            Ok(record) => IntentRecoveryEntry::Valid(record),
            Err(_) => IntentRecoveryEntry::Corrupt(id_from_ledger_key(&key)),
        });
    }
    Ok(entries)
}

/// Derives the replay-stable BLAKE3 identity from canonical call identity.
pub fn derive_intent_id(
    attempt_id: AttemptId,
    call_seq: u64,
    server: &str,
    tool: &str,
    payload_hash: &[u8; 32],
) -> IntentLedgerResult<[u8; 32]> {
    #[derive(Serialize)]
    struct IntentIdentity<'a> {
        attempt_id: &'a [u8; 16],
        call_seq: u64,
        server: &'a str,
        tool: &'a str,
        payload_hash: &'a [u8; 32],
    }

    canonical_hash(&IntentIdentity {
        attempt_id: attempt_id.as_bytes(),
        call_seq,
        server,
        tool,
        payload_hash,
    })
}

/// Test-only ledger primitive fixture. Production effects enter through
/// `outbound_chokepoint::execute_outbound_effect`.
#[cfg(test)]
pub(crate) fn execute_outbound_call<S: OutboundSender + ?Sized>(
    vault: &Vault,
    descriptor: OutboundToolDescriptor,
    request: OutboundCallRequest,
    sender: &mut S,
) -> IntentLedgerResult<IntentDispatchResult> {
    validate_request(&request)?;
    let payload_hash = hash_frozen_payload(&request.payload);
    let intent_id = derive_intent_id(
        request.attempt_id,
        request.call_seq,
        &request.server,
        &request.tool,
        &payload_hash,
    )?;
    if let Some(record) = read_intent_record(vault, &intent_id)? {
        validate_replay_matches_request(&record, &request, &payload_hash)?;
        // Mirror insert_pending_or_read's existing-row fence before replay/resend.
        force_sync(vault)?;
        return replay_dispatch(vault, record, sender, request.now_ms);
    }

    let class = classify_outbound_tool(descriptor);
    if class == OutboundCallClass::ReadOnly {
        let call = FrozenOutboundCall::read_only(request, payload_hash);
        let outcome = sender.send(&call);
        return Ok(IntentDispatchResult {
            class,
            intent_id: None,
            state: None,
            send_outcome: Some(outcome),
            replayed: false,
            escalation: None,
        });
    }

    let authorization_binding =
        request
            .authorization_binding
            .ok_or(IntentLedgerError::InvalidInput(
                "effectful call requires an authorization binding",
            ))?;
    let attempt_id = request.attempt_id;
    let call_seq = request.call_seq;
    let now_ms = request.now_ms;
    let idempotency_supported = descriptor.idempotency_supported();
    let call =
        FrozenOutboundCall::effectful(request, payload_hash, intent_id, idempotency_supported);
    let idempotency_key = call
        .idempotency_key
        .clone()
        .ok_or(IntentLedgerError::InvalidRecord(
            "effectful frozen call is missing idempotency key",
        ))?;
    let new_record = IntentLedgerRecord {
        id: intent_id,
        attempt_id,
        call_seq,
        server: call.server.clone(),
        tool: call.tool.clone(),
        payload_hash: call.payload_hash,
        payload: call.payload.to_vec(),
        idempotency_key,
        idempotency_supported,
        authorization_binding: Some(authorization_binding),
        binding_version: OUTBOUND_BINDING_VERSION,
        resolved_endpoint: call.resolved_endpoint.clone(),
        capability_provenance: call.capability_provenance.clone(),
        budget_accounting: BudgetChargeMarker {
            key_ref: None,
            budget_class: BudgetClass::Send,
            matched_rows: Vec::new(),
            sends_debit: 0,
            accounted_at_ms: now_ms,
        },
        recorded_outcome: None,
        state: IntentState::Pending,
        created_ms: now_ms,
        updated_ms: now_ms,
    };

    let (record, replayed) = insert_pending_or_read(vault, &new_record)?;
    if replayed {
        validate_replay_matches(&record, &call)?;
        return replay_dispatch(vault, record, sender, now_ms);
    }

    let persisted_call = FrozenOutboundCall::from_record(&record);
    let send_outcome = sender.send(&persisted_call);
    finish_send(vault, record, send_outcome, now_ms, false)
}

/// Reads all valid device-local intent receipts. Any malformed row fails the
/// read closed; recovery uses its separate escalation path.
pub fn intent_ledger_records(vault: &Vault) -> IntentLedgerResult<Vec<IntentLedgerRecord>> {
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    let mut records = Vec::new();
    for row in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, INTENT_LEDGER_PRIVATE_PREFIX)?
    {
        let (key, value) = row?;
        records.push(decode_record(&key, &value)?);
    }
    Ok(records)
}

/// Walks device-local intent rows after a crash. Resends use only persisted
/// frozen bytes and the persisted key/authorization binding.
///
/// This is a quiescent startup sweep and must not run concurrently with live
/// dispatch of the same intent. ONE-1690/the driver owns lease-based concurrency.
#[cfg(test)]
pub(crate) fn recover_outbound_intents<S: OutboundSender + ?Sized>(
    vault: &Vault,
    sender: &mut S,
    now_ms: u64,
) -> IntentLedgerResult<IntentRecoveryReport> {
    enum RecoveryRow {
        Valid(Box<IntentLedgerRecord>),
        Corrupt(Option<[u8; 32]>),
    }

    let rows = {
        let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
        let mut rows = Vec::new();
        for row in vault
            .store
            .vault_meta
            .prefix_iter(&rtxn, INTENT_LEDGER_PRIVATE_PREFIX)?
        {
            let (key, value) = row?;
            match decode_record(&key, &value) {
                Ok(record) => rows.push(RecoveryRow::Valid(Box::new(record))),
                Err(_) => rows.push(RecoveryRow::Corrupt(id_from_ledger_key(&key))),
            }
        }
        rows
    };
    // A prior caller may have observed a force-sync error after LMDB commit.
    // Re-establish durability before any recovery send can leave this node.
    force_sync(vault)?;

    let mut report = IntentRecoveryReport {
        scanned: rows.len(),
        ..IntentRecoveryReport::default()
    };
    for row in rows {
        let record = match row {
            RecoveryRow::Valid(record) => record,
            RecoveryRow::Corrupt(intent_id) => {
                report.escalations.push(IntentEscalation {
                    intent_id,
                    reason: IntentEscalationReason::CorruptLedgerRow,
                });
                continue;
            }
        };

        match record.state {
            IntentState::Done => report.skipped_done += 1,
            IntentState::Abandoned => {
                report.skipped_abandoned += 1;
                // Durable Abandoned state re-derives the signal after a crash.
                report.escalations.push(IntentEscalation {
                    intent_id: Some(record.id),
                    reason: IntentEscalationReason::PreviouslyAbandoned,
                });
            }
            IntentState::Pending if !record.idempotency_supported => {
                let abandoned = abandon_record(
                    vault,
                    record.id,
                    IntentEscalationReason::NonIdempotentPending,
                    now_ms,
                )?;
                debug_assert_eq!(abandoned.state, IntentState::Abandoned);
                report.escalations.push(IntentEscalation {
                    intent_id: Some(record.id),
                    reason: IntentEscalationReason::NonIdempotentPending,
                });
            }
            IntentState::Pending => {
                report.resent += 1;
                let call = FrozenOutboundCall::from_record(&record);
                match sender.send(&call) {
                    OutboundSendOutcome::Acked => {
                        complete_record(vault, record.id, now_ms)?;
                        report.completed += 1;
                    }
                    OutboundSendOutcome::Ambiguous => report.pending += 1,
                    OutboundSendOutcome::Failed(failure) => {
                        // Recovery reaches this arm only for idempotent Pending rows.
                        report.pending += 1;
                        report.failures.push(IntentRecoveryFailure {
                            intent_id: record.id,
                            failure,
                        });
                    }
                }
            }
        }
    }
    Ok(report)
}

fn validate_request(request: &OutboundCallRequest) -> IntentLedgerResult<()> {
    if request.server.trim().is_empty() {
        return Err(IntentLedgerError::InvalidInput("server must not be empty"));
    }
    if request.tool.trim().is_empty() {
        return Err(IntentLedgerError::InvalidInput("tool must not be empty"));
    }
    Ok(())
}

#[cfg(test)]
fn validate_replay_matches(
    record: &IntentLedgerRecord,
    call: &FrozenOutboundCall,
) -> IntentLedgerResult<()> {
    if record.server != call.server
        || record.tool != call.tool
        || record.payload_hash != call.payload_hash
        || record.payload() != call.payload()
        || Some(&record.id) != call.intent_id()
    {
        return Err(IntentLedgerError::InvalidRecord(
            "replay input does not match persisted intent",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn validate_replay_matches_request(
    record: &IntentLedgerRecord,
    request: &OutboundCallRequest,
    payload_hash: &[u8; 32],
) -> IntentLedgerResult<()> {
    let intent_id = derive_intent_id(
        request.attempt_id,
        request.call_seq,
        &request.server,
        &request.tool,
        payload_hash,
    )?;
    if record.server != request.server
        || record.tool != request.tool
        || record.payload_hash != *payload_hash
        || record.payload() != request.payload.as_slice()
        || record.id != intent_id
    {
        return Err(IntentLedgerError::InvalidRecord(
            "replay input does not match persisted intent",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn replay_dispatch<S: OutboundSender + ?Sized>(
    vault: &Vault,
    record: IntentLedgerRecord,
    sender: &mut S,
    now_ms: u64,
) -> IntentLedgerResult<IntentDispatchResult> {
    match record.state {
        IntentState::Done => Ok(dispatch_without_send(&record, true, None)),
        IntentState::Abandoned => Ok(dispatch_without_send(
            &record,
            true,
            Some(IntentEscalationReason::PreviouslyAbandoned),
        )),
        IntentState::Pending if !record.idempotency_supported => {
            let abandoned = abandon_record(
                vault,
                record.id,
                IntentEscalationReason::NonIdempotentPending,
                now_ms,
            )?;
            Ok(dispatch_without_send(
                &abandoned,
                true,
                Some(IntentEscalationReason::NonIdempotentPending),
            ))
        }
        IntentState::Pending => {
            let call = FrozenOutboundCall::from_record(&record);
            let outcome = sender.send(&call);
            finish_send(vault, record, outcome, now_ms, true)
        }
    }
}

#[cfg(test)]
fn dispatch_without_send(
    record: &IntentLedgerRecord,
    replayed: bool,
    escalation_reason: Option<IntentEscalationReason>,
) -> IntentDispatchResult {
    IntentDispatchResult {
        class: OutboundCallClass::Effectful,
        intent_id: Some(record.id),
        state: Some(record.state),
        send_outcome: None,
        replayed,
        escalation: escalation_reason.map(|reason| IntentEscalation {
            intent_id: Some(record.id),
            reason,
        }),
    }
}

#[cfg(test)]
fn finish_send(
    vault: &Vault,
    record: IntentLedgerRecord,
    outcome: OutboundSendOutcome,
    now_ms: u64,
    replayed: bool,
) -> IntentLedgerResult<IntentDispatchResult> {
    let (state, escalation) = match outcome {
        OutboundSendOutcome::Acked => {
            let done = complete_record(vault, record.id, now_ms)?;
            (Some(done.state), None)
        }
        OutboundSendOutcome::Ambiguous if record.idempotency_supported => {
            (Some(IntentState::Pending), None)
        }
        OutboundSendOutcome::Ambiguous => {
            let abandoned = abandon_record(
                vault,
                record.id,
                IntentEscalationReason::NonIdempotentAmbiguous,
                now_ms,
            )?;
            (
                Some(abandoned.state),
                Some(IntentEscalation {
                    intent_id: Some(record.id),
                    reason: IntentEscalationReason::NonIdempotentAmbiguous,
                }),
            )
        }
        OutboundSendOutcome::Failed(_) => (Some(IntentState::Pending), None),
    };
    Ok(IntentDispatchResult {
        class: OutboundCallClass::Effectful,
        intent_id: Some(record.id),
        state,
        send_outcome: Some(outcome),
        replayed,
        escalation,
    })
}

#[cfg(test)]
pub(crate) fn read_intent_record(
    vault: &Vault,
    id: &[u8; 32],
) -> IntentLedgerResult<Option<IntentLedgerRecord>> {
    let key = intent_ledger_key(id);
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, &key)? else {
        return Ok(None);
    };
    Ok(Some(decode_record(&key, &raw)?))
}

pub(crate) fn read_intent_record_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    id: &[u8; 32],
) -> IntentLedgerResult<Option<IntentLedgerRecord>> {
    let key = intent_ledger_key(id);
    let Some(raw) = vault.store.vault_meta.get(txn, &key)? else {
        return Ok(None);
    };
    Ok(Some(decode_record(&key, &raw)?))
}

#[cfg(test)]
fn insert_pending_or_read(
    vault: &Vault,
    pending: &IntentLedgerRecord,
) -> IntentLedgerResult<(IntentLedgerRecord, bool)> {
    let key = intent_ledger_key(&pending.id);
    let mut wtxn = vault.store.env.write_txn().map_err(Error::from)?;
    if let Some(raw) = vault.store.vault_meta.get(&wtxn, &key)? {
        let existing = decode_record(&key, &raw)?;
        drop(wtxn);
        // A prior commit may be visible even if its force-sync reported an
        // error. Replay cannot send until the existing intent is durable.
        force_sync(vault)?;
        return Ok((existing, true));
    }

    validate_record(&key, pending)?;
    let encoded = encode_record(pending)?;
    vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
    wtxn.commit().map_err(Error::from)?;
    force_sync(vault)?;
    Ok((pending.clone(), false))
}

pub(crate) fn insert_pending_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    pending: &IntentLedgerRecord,
) -> IntentLedgerResult<()> {
    if pending.state != IntentState::Pending || pending.recorded_outcome.is_some() {
        return Err(IntentLedgerError::InvalidRecord(
            "only outcome-free Pending may be inserted",
        ));
    }
    let key = intent_ledger_key(&pending.id);
    if vault.store.vault_meta.get(&*wtxn, &key)?.is_some() {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent insert target already exists",
        ));
    }
    validate_record(&key, pending)?;
    let encoded = encode_record(pending)?;
    vault.store.vault_meta.put(wtxn, &key, &encoded)?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn transition_record(
    vault: &Vault,
    id: [u8; 32],
    next: IntentState,
    now_ms: u64,
) -> IntentLedgerResult<IntentLedgerRecord> {
    let outcome = match next {
        IntentState::Done => RecordedOutboundOutcome::Acked,
        IntentState::Abandoned => {
            RecordedOutboundOutcome::Abandoned(IntentEscalationReason::PreviouslyAbandoned)
        }
        IntentState::Pending => {
            let record = read_intent_record(vault, &id)?.ok_or(
                IntentLedgerError::InvalidRecord("transition target is missing"),
            )?;
            return Err(IntentLedgerError::InvalidTransition {
                from: record.state,
                to: IntentState::Pending,
            });
        }
    };
    transition_record_with_outcome(vault, id, next, outcome, now_ms)
}

pub(crate) fn complete_record(
    vault: &Vault,
    id: [u8; 32],
    now_ms: u64,
) -> IntentLedgerResult<IntentLedgerRecord> {
    transition_record_with_outcome(
        vault,
        id,
        IntentState::Done,
        RecordedOutboundOutcome::Acked,
        now_ms,
    )
}

pub(crate) fn abandon_record(
    vault: &Vault,
    id: [u8; 32],
    reason: IntentEscalationReason,
    now_ms: u64,
) -> IntentLedgerResult<IntentLedgerRecord> {
    transition_record_with_outcome(
        vault,
        id,
        IntentState::Abandoned,
        RecordedOutboundOutcome::Abandoned(reason),
        now_ms,
    )
}

pub(crate) fn record_definite_non_delivery(
    vault: &Vault,
    id: [u8; 32],
    now_ms: u64,
) -> IntentLedgerResult<IntentLedgerRecord> {
    update_pending_recorded_outcome(
        vault,
        id,
        None,
        Some(RecordedOutboundOutcome::DefiniteNonDelivery),
        now_ms,
    )
}

pub(crate) fn begin_definite_non_delivery_retry(
    vault: &Vault,
    id: [u8; 32],
    now_ms: u64,
) -> IntentLedgerResult<IntentLedgerRecord> {
    update_pending_recorded_outcome(
        vault,
        id,
        Some(RecordedOutboundOutcome::DefiniteNonDelivery),
        None,
        now_ms,
    )
}

fn update_pending_recorded_outcome(
    vault: &Vault,
    id: [u8; 32],
    expected: Option<RecordedOutboundOutcome>,
    next: Option<RecordedOutboundOutcome>,
    now_ms: u64,
) -> IntentLedgerResult<IntentLedgerRecord> {
    let key = intent_ledger_key(&id);
    let mut wtxn = vault.store.env.write_txn().map_err(Error::from)?;
    let raw = vault
        .store
        .vault_meta
        .get(&wtxn, &key)?
        .ok_or(IntentLedgerError::InvalidRecord(
            "pending outcome target is missing",
        ))?;
    let mut record = decode_record(&key, &raw)?;
    if record.state != IntentState::Pending || record.recorded_outcome != expected {
        return Err(IntentLedgerError::InvalidRecord(
            "pending outcome transition is invalid",
        ));
    }
    record.recorded_outcome = next;
    record.updated_ms = now_ms.max(record.created_ms);
    let encoded = encode_record(&record)?;
    vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
    wtxn.commit().map_err(Error::from)?;
    force_sync(vault)?;
    Ok(record)
}

fn transition_record_with_outcome(
    vault: &Vault,
    id: [u8; 32],
    next: IntentState,
    outcome: RecordedOutboundOutcome,
    now_ms: u64,
) -> IntentLedgerResult<IntentLedgerRecord> {
    let key = intent_ledger_key(&id);
    let mut wtxn = vault.store.env.write_txn().map_err(Error::from)?;
    let raw = vault
        .store
        .vault_meta
        .get(&wtxn, &key)?
        .ok_or(IntentLedgerError::InvalidRecord(
            "transition target is missing",
        ))?;
    let mut record = decode_record(&key, &raw)?;
    if record.state == next {
        drop(wtxn);
        if record.recorded_outcome != Some(outcome) {
            return Err(IntentLedgerError::InvalidRecord(
                "terminal replay outcome does not match persisted outcome",
            ));
        }
        return Ok(record);
    }
    if !record.state.may_transition_to(next) {
        return Err(IntentLedgerError::InvalidTransition {
            from: record.state,
            to: next,
        });
    }
    record.state = next;
    record.recorded_outcome = Some(outcome);
    record.updated_ms = now_ms.max(record.created_ms);
    let encoded = encode_record(&record)?;
    vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
    wtxn.commit().map_err(Error::from)?;
    force_sync(vault)?;
    Ok(record)
}

pub(crate) fn force_sync(vault: &Vault) -> IntentLedgerResult<()> {
    #[cfg(test)]
    FORCE_SYNC_CALLS.fetch_add(1, AtomicOrdering::SeqCst);
    vault.store.env.force_sync().map_err(Error::from)?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn replace_intent_record_for_test(
    vault: &Vault,
    record: &IntentLedgerRecord,
) -> IntentLedgerResult<()> {
    let key = intent_ledger_key(&record.id);
    validate_record(&key, record)?;
    let encoded = encode_record(record)?;
    let mut wtxn = vault.store.env.write_txn().map_err(Error::from)?;
    if vault.store.vault_meta.get(&wtxn, &key)?.is_none() {
        return Err(IntentLedgerError::InvalidRecord(
            "test replacement target is missing",
        ));
    }
    vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
    wtxn.commit().map_err(Error::from)?;
    force_sync(vault)
}

pub(crate) fn hash_frozen_payload(payload: &[u8]) -> [u8; 32] {
    *blake3::hash(payload).as_bytes()
}

fn canonical_hash<T: Serialize>(value: &T) -> IntentLedgerResult<[u8; 32]> {
    let value = serde_json::to_value(value)?;
    let bytes = serde_json::to_vec(&canonicalize_json(value))?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn record_content_digest(record: &IntentLedgerRecord) -> IntentLedgerResult<[u8; 32]> {
    #[derive(Serialize)]
    struct RecordContent<'a> {
        schema_version: u64,
        id: &'a [u8; 32],
        attempt_id: &'a [u8; 16],
        call_seq: u64,
        server: &'a str,
        tool: &'a str,
        // payload_hash cryptographically binds the payload; hashing the raw
        // bytes again here is redundant and O(payload) on every encode/decode.
        payload_hash: &'a [u8; 32],
        idempotency_key: &'a str,
        idempotency_supported: bool,
        authorization_binding: Option<&'a [u8; 32]>,
        binding_version: u64,
        resolved_endpoint: Option<&'a str>,
        // The typed capability identity is digest-bound like every other
        // authority-bearing field: a swapped, added, or stripped provenance
        // fails the content digest at decode (ONE-1885).
        capability_grant_id: Option<&'a [u8; 16]>,
        capability_server: Option<&'a str>,
        capability_connector: Option<&'a str>,
        budget_key_ref: Option<&'a [u8; 16]>,
        budget_class: &'a str,
        budget_matched_rows: &'a [u16],
        budget_sends_debit: u64,
        budget_accounted_at_ms: u64,
        recorded_outcome: Option<&'a str>,
        recorded_outcome_reason: Option<&'a str>,
        state: &'a str,
        created_ms: u64,
        updated_ms: u64,
    }

    let capability_grant_id = record
        .capability_provenance
        .as_ref()
        .map(ScopedCapabilityProvenance::grant_id);
    canonical_hash(&RecordContent {
        schema_version: INTENT_LEDGER_SCHEMA_VERSION,
        id: &record.id,
        attempt_id: record.attempt_id.as_bytes(),
        call_seq: record.call_seq,
        server: &record.server,
        tool: &record.tool,
        payload_hash: &record.payload_hash,
        idempotency_key: &record.idempotency_key,
        idempotency_supported: record.idempotency_supported,
        authorization_binding: record
            .authorization_binding
            .as_ref()
            .map(OutboundAuthorizationBinding::as_bytes),
        binding_version: record.binding_version,
        resolved_endpoint: record.resolved_endpoint.as_deref(),
        capability_grant_id: capability_grant_id.as_ref().map(EntityId::as_bytes),
        capability_server: record
            .capability_provenance
            .as_ref()
            .map(ScopedCapabilityProvenance::server),
        capability_connector: record
            .capability_provenance
            .as_ref()
            .map(ScopedCapabilityProvenance::connector),
        budget_key_ref: record
            .budget_accounting
            .key_ref
            .as_ref()
            .map(EntityId::as_bytes),
        budget_class: record.budget_accounting.budget_class.as_str(),
        budget_matched_rows: &record.budget_accounting.matched_rows,
        budget_sends_debit: record.budget_accounting.sends_debit,
        budget_accounted_at_ms: record.budget_accounting.accounted_at_ms,
        recorded_outcome: record.recorded_outcome.map(|outcome| match outcome {
            RecordedOutboundOutcome::DefiniteNonDelivery => "definite_non_delivery",
            RecordedOutboundOutcome::Acked => "acked",
            RecordedOutboundOutcome::Abandoned(_) => "abandoned",
        }),
        recorded_outcome_reason: record.recorded_outcome.and_then(|outcome| match outcome {
            RecordedOutboundOutcome::DefiniteNonDelivery => None,
            RecordedOutboundOutcome::Acked => None,
            RecordedOutboundOutcome::Abandoned(reason) => Some(reason.as_str()),
        }),
        state: record.state.as_str(),
        created_ms: record.created_ms,
        updated_ms: record.updated_ms,
    })
}

fn canonicalize_json(value: JsonValue) -> JsonValue {
    match value {
        JsonValue::Array(values) => {
            JsonValue::Array(values.into_iter().map(canonicalize_json).collect())
        }
        JsonValue::Object(entries) => {
            let mut sorted = BTreeMap::new();
            for (key, value) in entries {
                sorted.insert(key, canonicalize_json(value));
            }
            let mut canonical = JsonMap::new();
            for (key, value) in sorted {
                canonical.insert(key, value);
            }
            JsonValue::Object(canonical)
        }
        scalar => scalar,
    }
}

fn intent_ledger_key(id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(INTENT_LEDGER_PRIVATE_PREFIX.len() + id.len());
    key.extend_from_slice(INTENT_LEDGER_PRIVATE_PREFIX);
    key.extend_from_slice(id);
    key
}

fn id_from_ledger_key(key: &[u8]) -> Option<[u8; 32]> {
    if key.len() != INTENT_LEDGER_PRIVATE_PREFIX.len() + 32
        || !key.starts_with(INTENT_LEDGER_PRIVATE_PREFIX)
    {
        return None;
    }
    key[INTENT_LEDGER_PRIVATE_PREFIX.len()..].try_into().ok()
}

fn encode_record(record: &IntentLedgerRecord) -> IntentLedgerResult<Vec<u8>> {
    let content_digest = record_content_digest(record)?;
    let budget_accounting = Value::Map(vec![
        (
            Value::from(BUDGET_ACCOUNTING_KEYS[0]),
            record
                .budget_accounting
                .key_ref
                .as_ref()
                .map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec())),
        ),
        (
            Value::from(BUDGET_ACCOUNTING_KEYS[1]),
            Value::from(record.budget_accounting.budget_class.as_str()),
        ),
        (
            Value::from(BUDGET_ACCOUNTING_KEYS[2]),
            Value::Array(
                record
                    .budget_accounting
                    .matched_rows
                    .iter()
                    .map(|row| Value::from(u64::from(*row)))
                    .collect(),
            ),
        ),
        (
            Value::from(BUDGET_ACCOUNTING_KEYS[3]),
            Value::from(record.budget_accounting.sends_debit),
        ),
        (
            Value::from(BUDGET_ACCOUNTING_KEYS[4]),
            Value::from(record.budget_accounting.accounted_at_ms),
        ),
    ]);
    let capability_provenance =
        record
            .capability_provenance
            .as_ref()
            .map_or(Value::Nil, |capability| {
                Value::Map(vec![
                    (
                        Value::from(CAPABILITY_PROVENANCE_KEYS[0]),
                        Value::Binary(capability.grant_id().as_bytes().to_vec()),
                    ),
                    (
                        Value::from(CAPABILITY_PROVENANCE_KEYS[1]),
                        Value::from(capability.server()),
                    ),
                    (
                        Value::from(CAPABILITY_PROVENANCE_KEYS[2]),
                        Value::from(capability.connector()),
                    ),
                ])
            });
    let recorded_outcome = record.recorded_outcome.map_or(Value::Nil, |outcome| {
        let (kind, reason) = match outcome {
            RecordedOutboundOutcome::DefiniteNonDelivery => ("definite_non_delivery", Value::Nil),
            RecordedOutboundOutcome::Acked => ("acked", Value::Nil),
            RecordedOutboundOutcome::Abandoned(reason) => {
                ("abandoned", Value::from(reason.as_str()))
            }
        };
        Value::Map(vec![
            (Value::from(RECORDED_OUTCOME_KEYS[0]), Value::from(kind)),
            (Value::from(RECORDED_OUTCOME_KEYS[1]), reason),
        ])
    });
    let entries = vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(INTENT_LEDGER_SCHEMA_VERSION),
        ),
        (Value::from(KEY_ID), Value::Binary(record.id.to_vec())),
        (
            Value::from(KEY_ATTEMPT_ID),
            Value::Binary(record.attempt_id.as_bytes().to_vec()),
        ),
        (Value::from(KEY_CALL_SEQ), Value::from(record.call_seq)),
        (Value::from(KEY_SERVER), Value::from(record.server.as_str())),
        (Value::from(KEY_TOOL), Value::from(record.tool.as_str())),
        (
            Value::from(KEY_PAYLOAD_HASH),
            Value::Binary(record.payload_hash.to_vec()),
        ),
        (
            Value::from(KEY_PAYLOAD),
            Value::Binary(record.payload.clone()),
        ),
        (
            Value::from(KEY_IDEMPOTENCY_KEY),
            Value::from(record.idempotency_key.as_str()),
        ),
        (
            Value::from(KEY_IDEMPOTENCY_SUPPORTED),
            Value::Boolean(record.idempotency_supported),
        ),
        (
            Value::from(KEY_AUTHORIZATION_BINDING),
            record
                .authorization_binding
                .as_ref()
                .map_or(Value::Nil, |binding| {
                    Value::Binary(binding.as_bytes().to_vec())
                }),
        ),
        (
            Value::from(KEY_BINDING_VERSION),
            Value::from(record.binding_version),
        ),
        (
            Value::from(KEY_RESOLVED_ENDPOINT),
            record
                .resolved_endpoint
                .as_deref()
                .map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_CAPABILITY_PROVENANCE),
            capability_provenance,
        ),
        (Value::from(KEY_BUDGET_ACCOUNTING), budget_accounting),
        (Value::from(KEY_RECORDED_OUTCOME), recorded_outcome),
        (Value::from(KEY_STATE), Value::from(record.state.as_str())),
        (Value::from(KEY_CREATED_MS), Value::from(record.created_ms)),
        (Value::from(KEY_UPDATED_MS), Value::from(record.updated_ms)),
        (
            Value::from(KEY_CONTENT_DIGEST),
            Value::Binary(content_digest.to_vec()),
        ),
    ];
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &Value::Map(entries)).map_err(|_| {
        IntentLedgerError::InvalidRecord("outbound intent MessagePack encode failed")
    })?;
    Ok(encoded)
}

fn decode_record(key: &[u8], raw: &[u8]) -> IntentLedgerResult<IntentLedgerRecord> {
    let mut cursor = Cursor::new(raw);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        IntentLedgerError::InvalidRecord("outbound intent MessagePack decode failed")
    })?;
    if cursor.position() != raw.len() as u64 {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent row has trailing bytes",
        ));
    }
    let Value::Map(entries) = value else {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent row must be a MessagePack map",
        ));
    };

    let mut schema_version = None;
    let mut id = None;
    let mut attempt_id = None;
    let mut call_seq = None;
    let mut server = None;
    let mut tool = None;
    let mut payload_hash = None;
    let mut payload = None;
    let mut idempotency_key = None;
    let mut idempotency_supported = None;
    let mut authorization_binding = None;
    let mut binding_version = None;
    let mut resolved_endpoint = None;
    let mut capability_provenance = None;
    let mut budget_accounting = None;
    let mut recorded_outcome = None;
    let mut state = None;
    let mut created_ms = None;
    let mut updated_ms = None;
    let mut content_digest = None;
    let mut seen = [false; INTENT_LEDGER_VALUE_KEYS.len()];

    for (entry_key, value) in entries {
        let entry_key = entry_key.as_str().ok_or(IntentLedgerError::InvalidRecord(
            "outbound intent keys must be strings",
        ))?;
        let index = INTENT_LEDGER_VALUE_KEYS
            .iter()
            .position(|candidate| *candidate == entry_key)
            .ok_or(IntentLedgerError::InvalidRecord(
                "outbound intent key is not pinned",
            ))?;
        if seen[index] {
            return Err(IntentLedgerError::InvalidRecord(
                "duplicate outbound intent key",
            ));
        }
        seen[index] = true;

        match INTENT_LEDGER_VALUE_KEYS[index] {
            KEY_SCHEMA_VERSION => schema_version = Some(expect_u64(&value)?),
            KEY_ID => id = Some(expect_binary_array::<32>(&value)?),
            KEY_ATTEMPT_ID => {
                let bytes = expect_binary_array::<16>(&value)?;
                attempt_id = Some(AttemptId::from_bytes(&bytes)?);
            }
            KEY_CALL_SEQ => call_seq = Some(expect_u64(&value)?),
            KEY_SERVER => server = Some(expect_string(&value)?),
            KEY_TOOL => tool = Some(expect_string(&value)?),
            KEY_PAYLOAD_HASH => payload_hash = Some(expect_binary_array::<32>(&value)?),
            KEY_PAYLOAD => payload = Some(expect_binary(&value)?),
            KEY_IDEMPOTENCY_KEY => idempotency_key = Some(expect_string(&value)?),
            KEY_IDEMPOTENCY_SUPPORTED => {
                idempotency_supported =
                    Some(value.as_bool().ok_or(IntentLedgerError::InvalidRecord(
                        "outbound intent idempotency_supported must be boolean",
                    ))?);
            }
            KEY_AUTHORIZATION_BINDING => {
                authorization_binding = Some(if matches!(value, Value::Nil) {
                    None
                } else {
                    Some(OutboundAuthorizationBinding::new(
                        expect_binary_array::<32>(&value)?,
                    ))
                });
            }
            KEY_BINDING_VERSION => binding_version = Some(expect_u64(&value)?),
            KEY_RESOLVED_ENDPOINT => {
                resolved_endpoint = Some(if matches!(value, Value::Nil) {
                    None
                } else {
                    Some(expect_string(&value)?)
                });
            }
            KEY_CAPABILITY_PROVENANCE => {
                capability_provenance = Some(decode_capability_provenance(&value)?);
            }
            KEY_BUDGET_ACCOUNTING => budget_accounting = Some(decode_budget_accounting(&value)?),
            KEY_RECORDED_OUTCOME => {
                recorded_outcome = Some(decode_recorded_outcome(&value)?);
            }
            KEY_STATE => {
                state = Some(
                    IntentState::parse(value.as_str().ok_or(IntentLedgerError::InvalidRecord(
                        "outbound intent state must be a string",
                    ))?)
                    .ok_or(IntentLedgerError::InvalidRecord(
                        "unknown outbound intent state",
                    ))?,
                );
            }
            KEY_CREATED_MS => created_ms = Some(expect_u64(&value)?),
            KEY_UPDATED_MS => updated_ms = Some(expect_u64(&value)?),
            KEY_CONTENT_DIGEST => content_digest = Some(expect_binary_array::<32>(&value)?),
            _ => {
                return Err(IntentLedgerError::InvalidRecord(
                    "outbound intent pinned key has no decoder",
                ));
            }
        }
    }

    let schema_version = required(schema_version, "missing outbound intent schema_version")?;
    if schema_version != INTENT_LEDGER_SCHEMA_VERSION {
        return Err(IntentLedgerError::InvalidRecord(
            "unsupported outbound intent schema_version",
        ));
    }
    let record = IntentLedgerRecord {
        id: required(id, "missing outbound intent id")?,
        attempt_id: required(attempt_id, "missing outbound intent attempt_id")?,
        call_seq: required(call_seq, "missing outbound intent call_seq")?,
        server: required(server, "missing outbound intent server")?,
        tool: required(tool, "missing outbound intent tool")?,
        payload_hash: required(payload_hash, "missing outbound intent payload_hash")?,
        payload: required(payload, "missing outbound intent payload")?,
        idempotency_key: required(idempotency_key, "missing outbound intent idempotency_key")?,
        idempotency_supported: required(
            idempotency_supported,
            "missing outbound intent idempotency_supported",
        )?,
        authorization_binding: required(
            authorization_binding,
            "missing outbound intent authorization_binding",
        )?,
        binding_version: required(binding_version, "missing outbound intent binding_version")?,
        resolved_endpoint: required(
            resolved_endpoint,
            "missing outbound intent resolved_endpoint",
        )?,
        capability_provenance: required(
            capability_provenance,
            "missing outbound intent capability_provenance",
        )?,
        budget_accounting: required(
            budget_accounting,
            "missing outbound intent budget_accounting",
        )?,
        recorded_outcome: required(recorded_outcome, "missing outbound intent recorded_outcome")?,
        state: required(state, "missing outbound intent state")?,
        created_ms: required(created_ms, "missing outbound intent created_ms")?,
        updated_ms: required(updated_ms, "missing outbound intent updated_ms")?,
    };
    let content_digest = required(content_digest, "missing outbound intent content_digest")?;
    if record_content_digest(&record)? != content_digest {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent content digest mismatch",
        ));
    }
    validate_record(key, &record)?;
    Ok(record)
}

fn decode_budget_accounting(value: &Value) -> IntentLedgerResult<BudgetChargeMarker> {
    let Value::Map(entries) = value else {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent budget_accounting must be a map",
        ));
    };
    validate_nested_keys(entries, &BUDGET_ACCOUNTING_KEYS)?;
    let key_ref = match nested_value(entries, BUDGET_ACCOUNTING_KEYS[0])? {
        Value::Nil => None,
        value => Some(
            EntityId::from_bytes(expect_binary_array::<16>(value)?).map_err(|_| {
                IntentLedgerError::InvalidRecord("outbound intent budget key_ref is invalid")
            })?,
        ),
    };
    let budget_class = nested_value(entries, BUDGET_ACCOUNTING_KEYS[1])?
        .as_str()
        .and_then(BudgetClass::parse)
        .ok_or(IntentLedgerError::InvalidRecord(
            "outbound intent budget_class is invalid",
        ))?;
    let Value::Array(row_values) = nested_value(entries, BUDGET_ACCOUNTING_KEYS[2])? else {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent matched_rows must be an array",
        ));
    };
    let mut matched_rows = Vec::with_capacity(row_values.len());
    for value in row_values {
        let row = expect_u64(value)?;
        matched_rows.push(u16::try_from(row).map_err(|_| {
            IntentLedgerError::InvalidRecord("outbound intent matched row is invalid")
        })?);
    }
    Ok(BudgetChargeMarker {
        key_ref,
        budget_class,
        matched_rows,
        sends_debit: expect_u64(nested_value(entries, BUDGET_ACCOUNTING_KEYS[3])?)?,
        accounted_at_ms: expect_u64(nested_value(entries, BUDGET_ACCOUNTING_KEYS[4])?)?,
    })
}

/// Decodes the typed scoped capability provenance fail-closed: unknown or
/// duplicate nested keys, a malformed grant id, an unsafe/non-canonical server,
/// or a connector that is not EXACTLY the identity that (server, grant) mints
/// are all rejected, so no durable row can carry a forged capability (ONE-1885).
fn decode_capability_provenance(
    value: &Value,
) -> IntentLedgerResult<Option<ScopedCapabilityProvenance>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    let Value::Map(entries) = value else {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent capability_provenance must be a map",
        ));
    };
    validate_nested_keys(entries, &CAPABILITY_PROVENANCE_KEYS)?;
    let grant_id = EntityId::from_bytes(expect_binary_array::<16>(nested_value(
        entries,
        CAPABILITY_PROVENANCE_KEYS[0],
    )?)?)
    .map_err(|_| {
        IntentLedgerError::InvalidRecord("outbound intent capability grant_id is invalid")
    })?;
    let server = expect_string(nested_value(entries, CAPABILITY_PROVENANCE_KEYS[1])?)?;
    let connector = expect_string(nested_value(entries, CAPABILITY_PROVENANCE_KEYS[2])?)?;
    ScopedCapabilityProvenance::from_persisted_parts(&grant_id, &server, &connector)
        .map(Some)
        .ok_or(IntentLedgerError::InvalidRecord(
            "outbound intent capability_provenance is inconsistent",
        ))
}

fn decode_recorded_outcome(value: &Value) -> IntentLedgerResult<Option<RecordedOutboundOutcome>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    let Value::Map(entries) = value else {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent recorded_outcome must be a map",
        ));
    };
    validate_nested_keys(entries, &RECORDED_OUTCOME_KEYS)?;
    let kind = nested_value(entries, RECORDED_OUTCOME_KEYS[0])?
        .as_str()
        .ok_or(IntentLedgerError::InvalidRecord(
            "outbound intent outcome kind is invalid",
        ))?;
    let reason = nested_value(entries, RECORDED_OUTCOME_KEYS[1])?;
    match (kind, reason) {
        ("definite_non_delivery", Value::Nil) => {
            Ok(Some(RecordedOutboundOutcome::DefiniteNonDelivery))
        }
        ("acked", Value::Nil) => Ok(Some(RecordedOutboundOutcome::Acked)),
        ("abandoned", value) => {
            let reason = value
                .as_str()
                .and_then(IntentEscalationReason::parse)
                .ok_or(IntentLedgerError::InvalidRecord(
                    "outbound intent abandonment reason is invalid",
                ))?;
            Ok(Some(RecordedOutboundOutcome::Abandoned(reason)))
        }
        _ => Err(IntentLedgerError::InvalidRecord(
            "outbound intent recorded_outcome is inconsistent",
        )),
    }
}

fn validate_nested_keys(entries: &[(Value, Value)], keys: &[&str]) -> IntentLedgerResult<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or(IntentLedgerError::InvalidRecord(
            "outbound intent nested keys must be strings",
        ))?;
        let index = keys.iter().position(|candidate| *candidate == key).ok_or(
            IntentLedgerError::InvalidRecord("outbound intent nested key is not pinned"),
        )?;
        if seen[index] {
            return Err(IntentLedgerError::InvalidRecord(
                "duplicate outbound intent nested key",
            ));
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(IntentLedgerError::InvalidRecord(
            "outbound intent nested field is missing",
        ))
    }
}

fn nested_value<'a>(entries: &'a [(Value, Value)], key: &str) -> IntentLedgerResult<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or(IntentLedgerError::InvalidRecord(
            "outbound intent nested field is missing",
        ))
}

fn validate_record(key: &[u8], record: &IntentLedgerRecord) -> IntentLedgerResult<()> {
    if id_from_ledger_key(key) != Some(record.id) {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent key does not match id",
        ));
    }
    if record.server.trim().is_empty() || record.tool.trim().is_empty() {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent endpoint is empty",
        ));
    }
    if record.updated_ms < record.created_ms {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent updated_ms predates created_ms",
        ));
    }
    if record.binding_version != OUTBOUND_BINDING_VERSION {
        return Err(IntentLedgerError::InvalidRecord(
            "unsupported outbound intent binding_version",
        ));
    }
    if record
        .resolved_endpoint
        .as_deref()
        .is_some_and(|endpoint| endpoint.trim().is_empty() || endpoint != endpoint.trim())
    {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent resolved_endpoint is invalid",
        ));
    }
    if record.resolved_endpoint.is_some() && record.authorization_binding.is_none() {
        return Err(IntentLedgerError::InvalidRecord(
            "endpoint-bound intent is missing authorization binding",
        ));
    }
    // A capability identity only ever exists on the verified scoped path, which
    // always mints an authorization binding in the same admission step; a row
    // carrying one without the other is not a row this engine wrote.
    if record.capability_provenance.is_some() && record.authorization_binding.is_none() {
        return Err(IntentLedgerError::InvalidRecord(
            "capability-bound intent is missing authorization binding",
        ));
    }
    if record.budget_accounting.key_ref.is_none()
        && (!record.budget_accounting.matched_rows.is_empty()
            || record.budget_accounting.sends_debit != 0)
    {
        return Err(IntentLedgerError::InvalidRecord(
            "unkeyed budget marker contains a debit",
        ));
    }
    if record.budget_accounting.sends_debit > 1
        || (!record.budget_accounting.budget_class.is_send()
            && record.budget_accounting.sends_debit != 0)
    {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent sends debit is invalid",
        ));
    }
    if record
        .budget_accounting
        .matched_rows
        .windows(2)
        .any(|rows| rows[0] >= rows[1])
    {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent matched rows are not canonical",
        ));
    }
    let outcome_matches_state = matches!(
        (record.state, record.recorded_outcome),
        (IntentState::Pending, None)
            | (
                IntentState::Pending,
                Some(RecordedOutboundOutcome::DefiniteNonDelivery)
            )
            | (IntentState::Done, Some(RecordedOutboundOutcome::Acked))
            | (
                IntentState::Abandoned,
                Some(RecordedOutboundOutcome::Abandoned(_))
            )
    );
    if !outcome_matches_state {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent state and recorded_outcome disagree",
        ));
    }
    if hash_frozen_payload(record.payload()) != record.payload_hash {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent payload hash mismatch",
        ));
    }
    if bytes_to_hex_lower(&record.id) != record.idempotency_key {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent idempotency key mismatch",
        ));
    }
    let derived = derive_intent_id(
        record.attempt_id,
        record.call_seq,
        &record.server,
        &record.tool,
        &record.payload_hash,
    )?;
    if derived != record.id {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent identity hash mismatch",
        ));
    }
    Ok(())
}

fn expect_u64(value: &Value) -> IntentLedgerResult<u64> {
    value.as_u64().ok_or(IntentLedgerError::InvalidRecord(
        "outbound intent integer field is invalid",
    ))
}

fn expect_string(value: &Value) -> IntentLedgerResult<String> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or(IntentLedgerError::InvalidRecord(
            "outbound intent string field is invalid",
        ))
}

fn expect_binary(value: &Value) -> IntentLedgerResult<Vec<u8>> {
    let Value::Binary(bytes) = value else {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent binary field is invalid",
        ));
    };
    Ok(bytes.clone())
}

fn expect_binary_array<const N: usize>(value: &Value) -> IntentLedgerResult<[u8; N]> {
    expect_binary(value)?
        .try_into()
        .map_err(|_| IntentLedgerError::InvalidRecord("outbound intent binary length is invalid"))
}

fn required<T>(value: Option<T>, reason: &'static str) -> IntentLedgerResult<T> {
    value.ok_or(IntentLedgerError::InvalidRecord(reason))
}

#[cfg(test)]
mod tests;
