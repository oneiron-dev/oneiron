//! Closed diagnostic event vocabulary: classes, sources, criticality, event and working-set types, bounds.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{Error, RecordError};

/// Schema version stamped into, and required by, every DIAGNOSTIC body.
pub const DIAGNOSTIC_SCHEMA_VERSION: u64 = 1;

/// The pinned, ordered DIAGNOSTIC body key set.
///
/// The order here IS the canonical encode order, and the set is CLOSED: decode
/// rejects an unknown key, a missing key, a duplicate key, or reordered keys.
/// This pre-release schema changes in place; no legacy body grammar is admitted.
pub const DIAGNOSTIC_BODY_KEYS: [&str; 17] = [
    "schema_version",
    "detector_id",
    "event_class",
    "actor_class",
    "actor_ref",
    "source",
    "criticality",
    "expected",
    "actual",
    "delta",
    "replay_content_hash",
    "replay_run_ref",
    "replay_checkpoint_ref",
    "evidence_refs",
    "untrusted_detail",
    "valid_from",
    "valid_to",
];

/// The closed `actor_class` vocabulary, which is the Gate's actor-class
/// vocabulary rather than a second one invented here.
///
/// Sorted so the membership test reads as a set. `self_heal::tests` pins these
/// spellings against [`crate::edge::EdgeActorClass::gate_actor_class`] so the
/// two cannot drift apart silently.
pub(super) const DIAGNOSTIC_ACTOR_CLASSES: [&str; 3] = ["agent", "human", "system"];

/// Domain separator for the stable `(detector_id, canonical body)` event id.
pub(super) const DIAGNOSTIC_EVENT_ID_DOMAIN: &[u8] = b"oneiron.self_heal.diagnostic_event.v1";

/// Longest accepted `run_ref` / `checkpoint_ref` / `scope_ref`.
pub(super) const MAX_REF_LEN: usize = 256;

/// Longest accepted canonical untrusted-detail leaf, AFTER escaping.
pub(super) const MAX_UNTRUSTED_DETAIL_LEN: usize = 4096;

/// Most evidence refs one event may cite.
pub(super) const MAX_EVIDENCE_REFS: usize = 64;

/// Longest accepted detector id / observation kind token.
pub(super) const MAX_TOKEN_LEN: usize = 64;

/// Longest accepted string leaf inside `expected` / `actual` / `delta`.
pub(super) const MAX_INVARIANT_STRING_LEN: usize = 1024;

/// Deepest accepted nesting inside `expected` / `actual` / `delta`.
pub(super) const MAX_INVARIANT_DEPTH: usize = 8;

/// Most nodes one `expected` / `actual` / `delta` value may contain.
pub(super) const MAX_INVARIANT_NODES: usize = 256;

/// Widest accepted array / map inside `expected` / `actual` / `delta`.
pub(super) const MAX_INVARIANT_WIDTH: usize = 64;

/// Most events one detector run may persist.
///
/// A detector that trips this is malfunctioning, and a malfunctioning detector
/// must not be able to fill the vault with its own noise.
pub(super) const MAX_EVENTS_PER_RUN: usize = 1024;

/// The closed self-healing event vocabulary.
///
/// The first four name failures of the engine's own build/test loop; the rest
/// name failures of a live vault. `SuspiciousWake` is a CLASS here and
/// deliberately not an entity kind of its own — canon byte 72 stays reserved
/// and unregistered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum DiagnosticEventClass {
    /// A test that should pass did not.
    TestFailure,
    /// A beam-eval score moved the wrong way against its pinned baseline.
    BeamEvalRegression,
    /// A build that should succeed did not.
    BuildFailure,
    /// A schema migration did not reach its declared end state.
    SchemaMigrationFailure,
    /// A dreamer run produced a degenerate result.
    DreamerRunDegenerate,
    /// A wake fired without a defensible cause.
    SuspiciousWake,
    /// An MCP action was rejected at the boundary.
    McpActionRejected,
    /// A consent gate denied a write or a disclosure.
    ConsentDenied,
    /// A retrieval that should have returned a known entity did not.
    RetrievalMiss,
    /// Consolidation failed to fold what it was given.
    ConsolidationError,
    /// A chain or fold verification did not reproduce its expected head.
    ChainVerifyFailure,
    /// Sync replay diverged from the peer's committed order.
    SyncReplayDivergence,
    /// A conversation degraded without raising any error of its own.
    SilentConversationDegradation,
}

impl DiagnosticEventClass {
    /// Canonical wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TestFailure => "test_failure",
            Self::BeamEvalRegression => "beam_eval_regression",
            Self::BuildFailure => "build_failure",
            Self::SchemaMigrationFailure => "schema_migration_failure",
            Self::DreamerRunDegenerate => "dreamer_run_degenerate",
            Self::SuspiciousWake => "suspicious_wake",
            Self::McpActionRejected => "mcp_action_rejected",
            Self::ConsentDenied => "consent_denied",
            Self::RetrievalMiss => "retrieval_miss",
            Self::ConsolidationError => "consolidation_error",
            Self::ChainVerifyFailure => "chain_verify_failure",
            Self::SyncReplayDivergence => "sync_replay_divergence",
            Self::SilentConversationDegradation => "silent_conversation_degradation",
        }
    }

    /// Parses a wire spelling, rejecting anything outside the closed set.
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        let parsed = match raw {
            "test_failure" => Self::TestFailure,
            "beam_eval_regression" => Self::BeamEvalRegression,
            "build_failure" => Self::BuildFailure,
            "schema_migration_failure" => Self::SchemaMigrationFailure,
            "dreamer_run_degenerate" => Self::DreamerRunDegenerate,
            "suspicious_wake" => Self::SuspiciousWake,
            "mcp_action_rejected" => Self::McpActionRejected,
            "consent_denied" => Self::ConsentDenied,
            "retrieval_miss" => Self::RetrievalMiss,
            "consolidation_error" => Self::ConsolidationError,
            "chain_verify_failure" => Self::ChainVerifyFailure,
            "sync_replay_divergence" => Self::SyncReplayDivergence,
            "silent_conversation_degradation" => Self::SilentConversationDegradation,
            _ => return None,
        };
        Some(parsed)
    }

    /// Every class, in declaration order. Census helper for tests and callers
    /// that need to iterate the closed vocabulary.
    #[must_use]
    pub const fn all() -> [Self; 13] {
        [
            Self::TestFailure,
            Self::BeamEvalRegression,
            Self::BuildFailure,
            Self::SchemaMigrationFailure,
            Self::DreamerRunDegenerate,
            Self::SuspiciousWake,
            Self::McpActionRejected,
            Self::ConsentDenied,
            Self::RetrievalMiss,
            Self::ConsolidationError,
            Self::ChainVerifyFailure,
            Self::SyncReplayDivergence,
            Self::SilentConversationDegradation,
        ]
    }
}

/// Which read-only substrate the observation was drawn from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum DiagnosticSourceKind {
    /// A receipt row.
    Receipt,
    /// A retrieval telemetry row.
    RetrievalTelemetry,
    /// A dreamer event-DAG node.
    DreamerEventDag,
    /// The engine reporting on itself, with no external substrate.
    SelfReport,
}

impl DiagnosticSourceKind {
    /// Canonical wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Receipt => "receipt",
            Self::RetrievalTelemetry => "retrieval_telemetry",
            Self::DreamerEventDag => "dreamer_event_dag",
            Self::SelfReport => "self_report",
        }
    }

    /// Parses a wire spelling, rejecting anything outside the closed set.
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "receipt" => Some(Self::Receipt),
            "retrieval_telemetry" => Some(Self::RetrievalTelemetry),
            "dreamer_event_dag" => Some(Self::DreamerEventDag),
            "self_report" => Some(Self::SelfReport),
            _ => None,
        }
    }
}

/// How loudly the event asks to be looked at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum DiagnosticCriticality {
    /// Worth recording; nothing is on fire.
    Normal,
    /// Worth interrupting for.
    Critical,
}

impl DiagnosticCriticality {
    /// Canonical wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Critical => "critical",
        }
    }

    /// Parses a wire spelling, rejecting anything outside the closed set.
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "normal" => Some(Self::Normal),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

/// Where to stand to see the failure again.
///
/// `content_hash` is the load-bearing field: it addresses the exact bytes the
/// verdict was computed over, so a later healer can RE-DERIVE the finding
/// instead of trusting this record's prose. `run_ref` and `checkpoint_ref` are
/// optional coordinates into the run that produced them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticReplayCoordinate {
    /// Content address of the bytes the verdict was computed over.
    pub content_hash: [u8; 32],
    /// Optional run coordinate.
    pub run_ref: Option<String>,
    /// Optional checkpoint coordinate inside the run.
    pub checkpoint_ref: Option<String>,
}

/// One typed self-healing finding.
///
/// Every field except the optional coordinates is required: an event that
/// cannot say who, from what, how bad, what was expected, what happened, how
/// they differ, where to look again, and when it was true is not a diagnostic —
/// it is a rumour, and encode rejects it.
#[derive(Debug, Clone, PartialEq)]
pub struct DiagnosticEvent {
    /// Stable detector token, persisted so every admission door can reproduce
    /// the content-addressed id. Must match the emitting detector's identity.
    pub detector_id: String,
    /// Closed event class.
    pub event_class: DiagnosticEventClass,
    /// Actor class that owns the failure, in the Gate vocabulary.
    pub actor_class: String,
    /// Optional concrete actor.
    pub actor_ref: Option<EntityId>,
    /// Read-only substrate the observation came from.
    pub source: DiagnosticSourceKind,
    /// How loudly the event asks to be looked at.
    pub criticality: DiagnosticCriticality,
    /// Invariant input: what should have been true.
    pub expected: Value,
    /// Invariant input: what was true instead.
    pub actual: Value,
    /// Invariant input: how the two differ.
    pub delta: Value,
    /// Content-addressed replay coordinate.
    pub replay: DiagnosticReplayCoordinate,
    /// Entities this finding is evidenced by. Canonicalized on encode to
    /// strictly ascending order with duplicates removed.
    pub evidence_refs: Vec<EntityId>,
    /// The ONE leaf untrusted text may enter through. Escaped on encode and
    /// re-validated on decode, so control data can never ride in on it.
    pub untrusted_detail: Option<String>,
    /// Bitemporal validity start (unix seconds).
    pub valid_from: u64,
    /// Bitemporal validity end (unix seconds), strictly after `valid_from`.
    pub valid_to: Option<u64>,
}

/// One observed input fact a detector may consult.
///
/// The sole element type of the working set, so its shape and ordering are what
/// "same ordered input yields identical events" MEANS. `payload_digest` is a
/// digest of the canonical source bytes and never the bytes themselves: the
/// working set is an index into evidence, not a second copy of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagnosticObservation {
    /// The entity/receipt/row the fact came from.
    pub source_ref: EntityId,
    /// Closed per-detector vocabulary token, e.g. `"receipt"`, `"retr_run"`.
    pub kind: &'static str,
    /// Digest of the canonical source bytes.
    pub payload_digest: [u8; 32],
    /// When the fact was observed (unix seconds).
    pub observed_at: u64,
}

impl DiagnosticObservation {
    /// The PINNED ordering key: `(observed_at, source_ref, payload_digest)`.
    pub(super) fn order_key(&self) -> (u64, EntityId, [u8; 32]) {
        (self.observed_at, self.source_ref, self.payload_digest)
    }
}

/// A bounded, scoped, pinned-order slice of observations.
///
/// The caller builds it from a scoped read; this layer never widens it.
#[derive(Debug, Clone, Copy)]
pub struct DiagnosticWorkingSet<'a> {
    /// Opaque label for the scope the caller read under.
    pub scope_ref: &'a str,
    /// Observations in strictly ascending
    /// `(observed_at, source_ref, payload_digest)` order.
    pub observations: &'a [DiagnosticObservation],
}

/// A pure, deterministic detector over a working set.
///
/// `detect` MUST be a function of the ordered working set alone: no clock, no
/// randomness, no ambient reads, no re-sorting of `input.observations`. It
/// returns drafts and nothing else — it CANNOT repair, propose, authorize or
/// mutate anything, because it is handed no vault and no transaction.
pub trait DeterministicDetector: Send + Sync {
    /// Stable identity, folded into every derived event id.
    fn detector_id(&self) -> &'static str;
    /// Draft events for this working set. Each draft's `detector_id` must
    /// equal this detector's identity; the runner rejects a mismatch.
    fn detect(&self, input: &DiagnosticWorkingSet<'_>) -> Vec<DiagnosticEvent>;
}

pub(super) fn invalid_diagnostic(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidDiagnosticBody(reason))
}
