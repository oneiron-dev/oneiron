//! Version consts, domain types, record impls, and listing/escalation/report types.

use std::fmt;

use super::dispatch::{derive_intent_id, validate_request};
use super::store::hash_frozen_payload;
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

pub type IntentLedgerResult<T> = std::result::Result<T, IntentLedgerError>;

pub type IntentId = [u8; 32];

/// Typed failure surface for durable outbound intent operations.
#[derive(Debug, thiserror::Error)]
pub enum IntentLedgerError {
    #[error(transparent)]
    Engine(#[from] Error),
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

    pub(super) fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "done" => Some(Self::Done),
            "abandoned" => Some(Self::Abandoned),
            _ => None,
        }
    }

    pub(super) const fn may_transition_to(self, next: Self) -> bool {
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

    pub(super) fn parse(value: &str) -> Option<Self> {
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
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::NonIdempotentAmbiguous => "non_idempotent_ambiguous",
            Self::NonIdempotentPending => "non_idempotent_pending",
            Self::ConnectorRevoked => "connector_revoked",
            Self::BindingInvalid => "binding_invalid",
            Self::PreviouslyAbandoned => "previously_abandoned",
            Self::CorruptLedgerRow => "corrupt_ledger_row",
        }
    }

    pub(super) fn parse(value: &str) -> Option<Self> {
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
    pub(super) server: String,
    pub(super) tool: String,
    pub(super) payload: Box<[u8]>,
    pub(super) payload_hash: [u8; 32],
    pub(super) intent_id: Option<[u8; 32]>,
    pub(super) idempotency_key: Option<String>,
    idempotency_supported: bool,
    authorization_binding: Option<OutboundAuthorizationBinding>,
    binding_version: u64,
    pub(super) resolved_endpoint: Option<String>,
    pub(super) capability_provenance: Option<ScopedCapabilityProvenance>,
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
    pub(super) fn effectful(
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
    pub(super) payload: Vec<u8>,
    pub idempotency_key: String,
    pub idempotency_supported: bool,
    pub authorization_binding: Option<OutboundAuthorizationBinding>,
    pub binding_version: u64,
    pub resolved_endpoint: Option<String>,
    /// Typed per-grant capability identity, or `None` for every ordinary
    /// connector row. This durable value — never the row's connector text — is
    /// what recovery reads to decide a capability-only prohibition (ONE-1885).
    pub(super) capability_provenance: Option<ScopedCapabilityProvenance>,
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

/// One ledger row that failed to decode, kept with the evidence an auditor
/// needs. The raw row itself is left untouched in storage: this type reports
/// damage, it never repairs, quarantines, or deletes it.
#[derive(Debug)]
pub struct IntentLedgerCorruptRow {
    /// Full `vault_meta` key bytes; enough to identify even a malformed-key row.
    pub key: Box<[u8]>,
    pub error: IntentLedgerError,
}

/// One audit walk over the device-local intent ledger.
///
/// Damage is per row: one unreadable row cannot darken every other receipt in
/// the audit, and no corrupt row is ever presented as a valid record.
#[derive(Debug, Default)]
pub struct IntentLedgerListing {
    pub records: Vec<IntentLedgerRecord>,
    pub corrupt: Vec<IntentLedgerCorruptRow>,
}

/// Yields valid rows only; corrupt rows stay in `corrupt`.
///
/// `.len()` therefore counts valid rows — audit code that must fail on
/// corruption inspects `corrupt` rather than reading a count as completeness.
impl std::ops::Deref for IntentLedgerListing {
    type Target = [IntentLedgerRecord];

    fn deref(&self) -> &Self::Target {
        &self.records
    }
}

/// Consuming iteration yields valid rows only and drops `corrupt` — audit code
/// that must fail on corruption inspects `corrupt` before consuming the listing.
impl IntoIterator for IntentLedgerListing {
    type Item = IntentLedgerRecord;
    type IntoIter = std::vec::IntoIter<IntentLedgerRecord>;

    fn into_iter(self) -> Self::IntoIter {
        self.records.into_iter()
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
