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
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Error;

/// Current schema version for device-local outbound intent rows.
pub const INTENT_LEDGER_SCHEMA_VERSION: u64 = 1;
/// Pinned MessagePack key set for device-local outbound intent rows.
pub const INTENT_LEDGER_VALUE_KEYS: [&str; 15] = [
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
    "state",
    "created_ms",
    "updated_ms",
    "content_digest",
];

const INTENT_LEDGER_PRIVATE_PREFIX: &[u8] = b"outbound:intent_ledger:v1:"; // + id(32)

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
const KEY_STATE: &str = INTENT_LEDGER_VALUE_KEYS[11];
const KEY_CREATED_MS: &str = INTENT_LEDGER_VALUE_KEYS[12];
const KEY_UPDATED_MS: &str = INTENT_LEDGER_VALUE_KEYS[13];
const KEY_CONTENT_DIGEST: &str = INTENT_LEDGER_VALUE_KEYS[14];

pub type IntentLedgerResult<T> = std::result::Result<T, IntentLedgerError>;

/// Typed failure surface for durable outbound intent operations.
#[derive(Debug, thiserror::Error)]
pub enum IntentLedgerError {
    #[error(transparent)]
    Engine(#[from] Error),
    #[error("outbound intent canonicalization failed: {0}")]
    Canonical(#[from] serde_json::Error),
    #[error("invalid outbound intent input: {0}")]
    InvalidInput(&'static str),
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
/// The transport integration (ONE-1690) supplies this carrier from its verified
/// gate decision. This ledger enforces presence only; ONE-1690 owns authenticity
/// and revocation-aware re-validation during recovery.
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
            now_ms,
        }
    }

    #[must_use]
    pub fn with_authorization_binding(mut self, binding: OutboundAuthorizationBinding) -> Self {
        self.authorization_binding = Some(binding);
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

    fn read_only(request: OutboundCallRequest, payload_hash: [u8; 32]) -> Self {
        Self {
            server: request.server,
            tool: request.tool,
            payload: request.payload.into_boxed_slice(),
            payload_hash,
            intent_id: None,
            idempotency_key: None,
            idempotency_supported: false,
            authorization_binding: request.authorization_binding,
        }
    }

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
        }
    }

    fn from_record(record: &IntentLedgerRecord) -> Self {
        Self {
            server: record.server.clone(),
            tool: record.tool.clone(),
            payload: record.payload().to_vec().into_boxed_slice(),
            payload_hash: record.payload_hash,
            intent_id: Some(record.id),
            idempotency_key: Some(record.idempotency_key.clone()),
            idempotency_supported: record.idempotency_supported,
            authorization_binding: Some(record.authorization_binding),
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

/// Connector-agnostic outbound transport seam.
pub trait OutboundSender {
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
    pub authorization_binding: OutboundAuthorizationBinding,
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
            .field("state", &self.state)
            .field("created_ms", &self.created_ms)
            .field("updated_ms", &self.updated_ms)
            .finish()
    }
}

/// Machine-readable reason that requires caller escalation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntentEscalationReason {
    NonIdempotentAmbiguous,
    NonIdempotentPending,
    PreviouslyAbandoned,
    CorruptLedgerRow,
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

/// Executes one outbound call through the read-only fast path or the durable
/// effectful state machine.
pub fn execute_outbound_call<S: OutboundSender + ?Sized>(
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
        authorization_binding,
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
pub fn recover_outbound_intents<S: OutboundSender + ?Sized>(
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
                let abandoned =
                    transition_record(vault, record.id, IntentState::Abandoned, now_ms)?;
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
                        transition_record(vault, record.id, IntentState::Done, now_ms)?;
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
            let abandoned = transition_record(vault, record.id, IntentState::Abandoned, now_ms)?;
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

fn finish_send(
    vault: &Vault,
    record: IntentLedgerRecord,
    outcome: OutboundSendOutcome,
    now_ms: u64,
    replayed: bool,
) -> IntentLedgerResult<IntentDispatchResult> {
    let (state, escalation) = match outcome {
        OutboundSendOutcome::Acked => {
            let done = transition_record(vault, record.id, IntentState::Done, now_ms)?;
            (Some(done.state), None)
        }
        OutboundSendOutcome::Ambiguous if record.idempotency_supported => {
            (Some(IntentState::Pending), None)
        }
        OutboundSendOutcome::Ambiguous => {
            let abandoned = transition_record(vault, record.id, IntentState::Abandoned, now_ms)?;
            (
                Some(abandoned.state),
                Some(IntentEscalation {
                    intent_id: Some(record.id),
                    reason: IntentEscalationReason::NonIdempotentAmbiguous,
                }),
            )
        }
        OutboundSendOutcome::Failed(_) if !replayed => {
            delete_pending_record(vault, record.id)?;
            (None, None)
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

fn read_intent_record(
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

fn delete_pending_record(vault: &Vault, id: [u8; 32]) -> IntentLedgerResult<()> {
    let key = intent_ledger_key(&id);
    let mut wtxn = vault.store.env.write_txn().map_err(Error::from)?;
    let raw = vault
        .store
        .vault_meta
        .get(&wtxn, &key)?
        .ok_or(IntentLedgerError::InvalidRecord("delete target is missing"))?;
    let record = decode_record(&key, &raw)?;
    if record.state != IntentState::Pending {
        return Err(IntentLedgerError::InvalidRecord(
            "definite failure target is not pending",
        ));
    }
    let deleted = vault.store.vault_meta.delete(&mut wtxn, &key)?;
    if !deleted {
        return Err(IntentLedgerError::InvalidRecord("delete target is missing"));
    }
    wtxn.commit().map_err(Error::from)?;
    force_sync(vault)
}

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

    let encoded = encode_record(pending)?;
    vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
    wtxn.commit().map_err(Error::from)?;
    force_sync(vault)?;
    Ok((pending.clone(), false))
}

fn transition_record(
    vault: &Vault,
    id: [u8; 32],
    next: IntentState,
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
        return Ok(record);
    }
    if !record.state.may_transition_to(next) {
        return Err(IntentLedgerError::InvalidTransition {
            from: record.state,
            to: next,
        });
    }
    record.state = next;
    record.updated_ms = now_ms.max(record.created_ms);
    let encoded = encode_record(&record)?;
    vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
    wtxn.commit().map_err(Error::from)?;
    force_sync(vault)?;
    Ok(record)
}

fn force_sync(vault: &Vault) -> IntentLedgerResult<()> {
    #[cfg(test)]
    FORCE_SYNC_CALLS.fetch_add(1, AtomicOrdering::SeqCst);
    vault.store.env.force_sync().map_err(Error::from)?;
    Ok(())
}

fn hash_frozen_payload(payload: &[u8]) -> [u8; 32] {
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
        authorization_binding: &'a [u8; 32],
        state: &'a str,
        created_ms: u64,
        updated_ms: u64,
    }

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
        authorization_binding: record.authorization_binding.as_bytes(),
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
            Value::Binary(record.authorization_binding.as_bytes().to_vec()),
        ),
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
                authorization_binding = Some(OutboundAuthorizationBinding::new(
                    expect_binary_array::<32>(&value)?,
                ));
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
