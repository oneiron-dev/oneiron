//! GATE-14 layer 1 (ONE-1394): deterministic detectors and the typed
//! `DiagnosticEvent` maintenance entity.
//!
//! A failure this engine notices about itself is NOT a log line. It is a
//! `DiagnosticEvent`: a closed, canonical MessagePack record at entity byte 69
//! (`DIAGNOSTIC`, Maintenance/System) carrying engine-authored actor / source /
//! criticality metadata, the invariant inputs the verdict was computed from
//! (`expected`, `actual`, `delta`), a content-addressed replay coordinate,
//! evidence refs, bitemporal validity, and exactly ONE explicitly typed escaped
//! leaf for untrusted detail. That is what makes a failure addressable,
//! provenance-carrying and re-derivable by the later healer, instead of a
//! string somebody has to parse back into meaning.
//!
//! # Determinism is the contract
//!
//! [`run_deterministic_detectors`] takes a bounded [`DiagnosticWorkingSet`]
//! whose order is PINNED at `(observed_at, source_ref, payload_digest)`
//! ascending. Detectors read that slice and return drafts; they never re-sort
//! it, and a working set presented out of order is REJECTED rather than quietly
//! sorted — sorting here would hide a non-deterministic scoped read behind a
//! deterministic-looking result, which is the exact failure this layer exists
//! to make visible. Drafts are canonicalized, encoded, keyed by a stable id
//! derived from `(detector_id, canonical body)`, sorted by that id, and
//! deduplicated. The same ordered input and detector set therefore produces
//! byte-identical bodies, identical ids, identical ordering, and identical
//! dedup on every run.
//!
//! # Scope
//!
//! T1 ONLY. Detection has no repair type, no healer callback, no gate mutation
//! and no apply path; the sole write is a DIAGNOSTIC entity through
//! [`DiagnosticEvent`]'s maintenance-band door. T2 classifiers, T3 judges,
//! healer proposals and automatic repair are deliberately absent (ONE-1395 and
//! beyond). The narrow BM25 deindex self-heal is a different, untouched thing:
//! receipts and retrieval telemetry are READ-ONLY detector inputs here, and no
//! parallel log stack is introduced.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::atomic::Ordering;

use rmpv::{Integer, Value};

use crate::Vault;
use crate::batch::{BatchOp, apply_ops};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::temporal::TimeRange;

pub use crate::registry::ENTITY_TYPE_DIAGNOSTIC;

mod consent_detector;
pub use consent_detector::ConsentDeniedDetector;

/// Schema version stamped into, and required by, every DIAGNOSTIC body.
pub const DIAGNOSTIC_SCHEMA_VERSION: u64 = 1;

/// The pinned, ordered DIAGNOSTIC body key set.
///
/// The order here IS the canonical encode order, and the set is CLOSED: decode
/// rejects an unknown key, a missing key, or a duplicate key. Growing this
/// array is a schema change and needs [`DIAGNOSTIC_SCHEMA_VERSION`] to move
/// with it.
pub const DIAGNOSTIC_BODY_KEYS: [&str; 16] = [
    "schema_version",
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
const DIAGNOSTIC_ACTOR_CLASSES: [&str; 3] = ["agent", "human", "system"];

/// Domain separator for the stable `(detector_id, canonical body)` event id.
const DIAGNOSTIC_EVENT_ID_DOMAIN: &[u8] = b"oneiron.self_heal.diagnostic_event.v1";

/// Longest accepted `run_ref` / `checkpoint_ref` / `scope_ref`.
const MAX_REF_LEN: usize = 256;
/// Longest accepted canonical untrusted-detail leaf, AFTER escaping.
const MAX_UNTRUSTED_DETAIL_LEN: usize = 4096;
/// Most evidence refs one event may cite.
const MAX_EVIDENCE_REFS: usize = 64;
/// Longest accepted detector id / observation kind token.
const MAX_TOKEN_LEN: usize = 64;
/// Longest accepted string leaf inside `expected` / `actual` / `delta`.
const MAX_INVARIANT_STRING_LEN: usize = 1024;
/// Deepest accepted nesting inside `expected` / `actual` / `delta`.
const MAX_INVARIANT_DEPTH: usize = 8;
/// Most nodes one `expected` / `actual` / `delta` value may contain.
const MAX_INVARIANT_NODES: usize = 256;
/// Widest accepted array / map inside `expected` / `actual` / `delta`.
const MAX_INVARIANT_WIDTH: usize = 64;
/// Most events one detector run may persist.
///
/// A detector that trips this is malfunctioning, and a malfunctioning detector
/// must not be able to fill the vault with its own noise.
const MAX_EVENTS_PER_RUN: usize = 1024;

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
    fn order_key(&self) -> (u64, EntityId, [u8; 32]) {
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
    /// Draft events for this working set.
    fn detect(&self, input: &DiagnosticWorkingSet<'_>) -> Vec<DiagnosticEvent>;
}

/// Runs `detectors` over `input` and persists the resulting events.
///
/// Canonicalizes every draft, derives a stable id from
/// `(detector_id, canonical body)`, sorts by that id, deduplicates identical
/// events, and writes each one through `Vault::emit_diagnostic_event` — the
/// single maintenance-band door. Returns the persisted ids in that sorted
/// order.
///
/// Fails closed BEFORE any write when the working set is not in pinned order,
/// when a detector id or a draft is malformed, or when a run exceeds the event
/// ceiling. Persistence is then per-event: every id in the returned vector was
/// written, and a mid-run storage failure leaves the already-written events in
/// place rather than discarding observations that really were made.
pub fn run_deterministic_detectors(
    vault: &Vault,
    input: &DiagnosticWorkingSet<'_>,
    detectors: &[&dyn DeterministicDetector],
) -> Result<Vec<EntityId>> {
    validate_working_set(input)?;

    let mut staged: Vec<(EntityId, Vec<u8>, DiagnosticEvent)> = Vec::new();
    for detector in detectors {
        let detector_id = detector.detector_id();
        validate_token(detector_id, "detector id is not a bounded token")?;
        for event in detector.detect(input) {
            let body = encode_diagnostic_event_body(&event)?;
            let id = diagnostic_event_id(detector_id, &body);
            staged.push((id, body, event));
            if staged.len() > MAX_EVENTS_PER_RUN {
                return Err(Error::InvariantViolation("diagnostic event ceiling"));
            }
        }
    }

    staged.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    staged.dedup_by(|left, right| left.0 == right.0 && left.1 == right.1);
    // Anything still adjacent-equal by id now carries DIFFERENT bytes under one
    // id. That is a broken addressing story rather than a duplicate, so it
    // fails instead of silently dropping one of the two findings.
    if staged.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(Error::InvariantViolation("diagnostic event id collision"));
    }

    let mut ids = Vec::with_capacity(staged.len());
    for (id, _, event) in &staged {
        vault.emit_diagnostic_event(id, event)?;
        ids.push(*id);
    }
    Ok(ids)
}

/// Derives the stable event id for `(detector_id, canonical_body)`.
///
/// 16 raw domain-separated BLAKE3 bytes, so the id is reproducible from the
/// detector identity and the canonical body alone. The detector id is
/// length-prefixed so no two `(id, body)` pairs can concatenate to the same
/// transcript. A prefix landing on a reserved sentinel (~2^-120) is perturbed
/// rather than randomized, which keeps the derivation total without making it
/// unreproducible.
#[must_use]
pub fn diagnostic_event_id(detector_id: &str, canonical_body: &[u8]) -> EntityId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DIAGNOSTIC_EVENT_ID_DOMAIN);
    hasher.update(&(detector_id.len() as u64).to_be_bytes());
    hasher.update(detector_id.as_bytes());
    hasher.update(canonical_body);
    let mut raw = [0_u8; 16];
    raw.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    EntityId::from_bytes(raw).unwrap_or_else(|_| {
        raw[0] ^= 0x01;
        raw[15] ^= 0x01;
        EntityId::from_bytes(raw).expect("perturbed diagnostic id is non-reserved")
    })
}

/// Canonicalizes and encodes one DIAGNOSTIC body from a RAW draft.
///
/// Canonicalization is what makes determinism a property of the DATA rather
/// than of detector discipline: invariant values are rebuilt into one normal
/// form, evidence refs are sorted and deduplicated, and the untrusted leaf is
/// escaped. Two detectors that mean the same thing therefore emit the same
/// bytes and the same id.
///
/// `event.untrusted_detail` is read as RAW author text here, so this door must
/// only ever see a draft. Re-encoding an event that came back out of
/// [`decode_diagnostic_event_body`] belongs to the engine-internal stored-body
/// door instead: its leaf is already the stored canonical one, and escaping it
/// a second time would change the body.
pub fn encode_diagnostic_event_body(event: &DiagnosticEvent) -> Result<Vec<u8>> {
    let untrusted_detail = match event.untrusted_detail.as_deref() {
        Some(raw) => Value::from(canonical_untrusted_detail(raw)?),
        None => Value::Nil,
    };
    encode_body_with_detail(event, untrusted_detail)
}

/// Re-encodes an event whose untrusted leaf is ALREADY the stored canonical
/// one, i.e. one that came out of [`decode_diagnostic_event_body`].
///
/// The leaf is re-validated rather than re-escaped, which is what makes the
/// canonical form a fixed point of decode + re-encode even though
/// [`canonical_untrusted_detail`] is deliberately not idempotent.
fn encode_stored_diagnostic_event_body(event: &DiagnosticEvent) -> Result<Vec<u8>> {
    let untrusted_detail = match event.untrusted_detail.as_deref() {
        Some(stored) => {
            validate_untrusted_detail(stored)?;
            Value::from(stored)
        }
        None => Value::Nil,
    };
    encode_body_with_detail(event, untrusted_detail)
}

/// Builds and writes the pinned 16-key body around an already-decided
/// `untrusted_detail` leaf, so the raw door and the stored door cannot drift
/// apart in any other field.
fn encode_body_with_detail(event: &DiagnosticEvent, untrusted_detail: Value) -> Result<Vec<u8>> {
    validate_actor_class(&event.actor_class)?;
    validate_validity(event.valid_from, event.valid_to)?;
    let run_ref = canonical_optional_ref(event.replay.run_ref.as_deref())?;
    let checkpoint_ref = canonical_optional_ref(event.replay.checkpoint_ref.as_deref())?;

    let mut evidence_refs = event.evidence_refs.clone();
    evidence_refs.sort_unstable();
    evidence_refs.dedup();
    if evidence_refs.len() > MAX_EVIDENCE_REFS {
        return Err(invalid_diagnostic("too many evidence refs"));
    }
    let evidence: Vec<Value> = evidence_refs.iter().map(entity_ref_value).collect();

    let values = [
        Value::from(DIAGNOSTIC_SCHEMA_VERSION),
        Value::from(event.event_class.as_str()),
        Value::from(event.actor_class.as_str()),
        event
            .actor_ref
            .as_ref()
            .map_or(Value::Nil, entity_ref_value),
        Value::from(event.source.as_str()),
        Value::from(event.criticality.as_str()),
        canonical_invariant_value(&event.expected)?,
        canonical_invariant_value(&event.actual)?,
        canonical_invariant_value(&event.delta)?,
        Value::from(bytes_to_hex_lower(&event.replay.content_hash)),
        run_ref,
        checkpoint_ref,
        Value::Array(evidence),
        untrusted_detail,
        Value::from(event.valid_from),
        event.valid_to.map_or(Value::Nil, Value::from),
    ];

    let map = Value::Map(
        DIAGNOSTIC_BODY_KEYS
            .iter()
            .zip(values)
            .map(|(key, value)| (Value::from(*key), value))
            .collect(),
    );
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &map)
        .map_err(|_| Error::InvariantViolation("diagnostic body encode failed"))?;
    Ok(out)
}

/// Decodes and fully validates one DIAGNOSTIC body.
///
/// Fails closed on an unknown, missing or duplicate key, trailing bytes, an
/// invalid enum string, a malformed ref or content hash, non-monotonic
/// validity, a non-canonical invariant value or evidence-ref order, and control
/// data hidden in the untrusted leaf.
pub fn decode_diagnostic_event_body(bytes: &[u8]) -> Result<DiagnosticEvent> {
    let mut cursor = Cursor::new(bytes);
    let Ok(value) = rmpv::decode::read_value(&mut cursor) else {
        return Err(invalid_diagnostic("body is not MessagePack"));
    };
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_diagnostic("trailing bytes after body map"));
    }
    let Value::Map(entries) = &value else {
        return Err(invalid_diagnostic("body must be a MessagePack map"));
    };
    validate_keys(entries)?;

    if required(entries, "schema_version")?.as_u64() != Some(DIAGNOSTIC_SCHEMA_VERSION) {
        return Err(invalid_diagnostic("unsupported schema version"));
    }

    let event_class = DiagnosticEventClass::from_wire(required_str(entries, "event_class")?)
        .ok_or_else(|| invalid_diagnostic("unknown event class"))?;
    let source = DiagnosticSourceKind::from_wire(required_str(entries, "source")?)
        .ok_or_else(|| invalid_diagnostic("unknown source kind"))?;
    let criticality = DiagnosticCriticality::from_wire(required_str(entries, "criticality")?)
        .ok_or_else(|| invalid_diagnostic("unknown criticality"))?;

    let actor_class = required_str(entries, "actor_class")?.to_owned();
    validate_actor_class(&actor_class)?;

    let from_value = required(entries, "valid_from")?;
    let valid_from = decode_u64(from_value, "valid_from must be an integer")?;
    let valid_to = match required(entries, "valid_to")? {
        Value::Nil => None,
        other => Some(decode_u64(other, "valid_to must be an integer")?),
    };
    validate_validity(valid_from, valid_to)?;

    let untrusted_detail = match required(entries, "untrusted_detail")? {
        Value::Nil => None,
        other => {
            let text = decode_str(other, "untrusted_detail must be a string")?;
            validate_untrusted_detail(text)?;
            Some(text.to_owned())
        }
    };

    Ok(DiagnosticEvent {
        event_class,
        actor_class,
        actor_ref: decode_optional_entity_ref(required(entries, "actor_ref")?)?,
        source,
        criticality,
        expected: canonical_invariant_field(required(entries, "expected")?)?,
        actual: canonical_invariant_field(required(entries, "actual")?)?,
        delta: canonical_invariant_field(required(entries, "delta")?)?,
        replay: DiagnosticReplayCoordinate {
            content_hash: decode_content_hash(required(entries, "replay_content_hash")?)?,
            run_ref: decode_optional_ref(required(entries, "replay_run_ref")?)?,
            checkpoint_ref: decode_optional_ref(required(entries, "replay_checkpoint_ref")?)?,
        },
        evidence_refs: decode_evidence_refs(required(entries, "evidence_refs")?)?,
        untrusted_detail,
        valid_from,
        valid_to,
    })
}

/// Fail-closed body validation for the DIAGNOSTIC write door.
///
/// Decoding is necessary but NOT sufficient: the grammar above constrains the
/// VALUES, while a content-addressed body has to be pinned down to its exact
/// BYTES. So the decoded event is re-encoded and the result must equal the
/// input byte for byte. That closes the whole class of spellings that mean the
/// same thing on the wire — an alternate MessagePack marker for a value that
/// has a shorter one, or any residual re-arrangement — because such a body
/// would decode fine and then re-encode to different bytes than it arrived as.
///
/// Failing closed here is what keeps `(detector_id, canonical body)` a real
/// address: no writer, local or replicated, can store two byte strings that
/// carry one event, and no stored byte string can be one an honest re-encode
/// would not have produced.
pub(crate) fn validate_diagnostic_event_body_bytes(bytes: &[u8]) -> Result<()> {
    let event = decode_diagnostic_event_body(bytes)?;
    if encode_stored_diagnostic_event_body(&event)?.as_slice() != bytes {
        return Err(invalid_diagnostic("body is not canonically encoded"));
    }
    Ok(())
}

impl Vault {
    /// The ONE engine-authored write door for DIAGNOSTIC entities.
    ///
    /// Generic and public puts of byte 69 stay rejected with
    /// `MaintenanceKindNotWritable`: the kind is Maintenance-classified, so the
    /// public entity-type gate refuses it without needing a special case. This
    /// door is the only path that opens the maintenance band for byte 69, and
    /// it canonicalizes and validates the body before it does.
    pub(crate) fn emit_diagnostic_event(
        &self,
        id: &EntityId,
        event: &DiagnosticEvent,
    ) -> Result<()> {
        let data = encode_diagnostic_event_body(event)?;
        let learned_at = crate::unix_seconds_now();
        // An absent `valid_to` means STILL VALID, not "valid for an instant".
        // Collapsing it to a point would index the event as a closed interval
        // that ended the moment it began, so a temporal read anchored after
        // `valid_from` — which is every read of a still-open failure — would
        // miss it. `u64::MAX` is the repo's open-interval end (see the
        // open-ended CLAIM writes in `affect`), and it is what puts the event
        // in the long-interval index a spanning query looks at.
        let occurred = TimeRange {
            start: event.valid_from,
            end: event.valid_to.unwrap_or(u64::MAX),
        };
        self.with_write_txn(|wtxn| {
            apply_ops(
                &self.store,
                &self.config,
                &self.analyzer,
                wtxn,
                vec![BatchOp::Put {
                    id: *id,
                    entity_type: ENTITY_TYPE_DIAGNOSTIC,
                    occurred,
                    learned_at,
                    data,
                    allow_maintenance: true,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                }],
                self.text_index_trusted.load(Ordering::Acquire),
                false,
                true,
            )
        })
    }
}

// ── working-set validation ──────────────────────────────────────────────────

fn validate_working_set(input: &DiagnosticWorkingSet<'_>) -> Result<()> {
    if input.scope_ref.is_empty() || input.scope_ref.len() > MAX_REF_LEN {
        return Err(Error::InvariantViolation("scope_ref is empty or too long"));
    }
    if input.scope_ref.chars().any(is_forbidden_text_scalar) {
        return Err(Error::InvariantViolation("scope_ref carries control data"));
    }
    for observation in input.observations {
        validate_token(observation.kind, "observation kind is not a token")?;
    }
    // PINNED order is CHECKED, never imposed.
    if !is_pinned_order(input.observations) {
        return Err(Error::InvariantViolation("working set order is not pinned"));
    }
    Ok(())
}

fn is_pinned_order(observations: &[DiagnosticObservation]) -> bool {
    observations
        .windows(2)
        .all(|pair| pair[0].order_key() < pair[1].order_key())
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'.'
}

fn validate_token(token: &str, reason: &'static str) -> Result<()> {
    if token.is_empty() || token.len() > MAX_TOKEN_LEN {
        return Err(Error::InvariantViolation(reason));
    }
    if !token.bytes().all(is_token_byte) {
        return Err(Error::InvariantViolation(reason));
    }
    Ok(())
}

// ── body-field validation ───────────────────────────────────────────────────

fn validate_actor_class(actor_class: &str) -> Result<()> {
    if DIAGNOSTIC_ACTOR_CLASSES.contains(&actor_class) {
        Ok(())
    } else {
        Err(invalid_diagnostic("actor_class outside Gate vocabulary"))
    }
}

fn validate_validity(valid_from: u64, valid_to: Option<u64>) -> Result<()> {
    if valid_to.is_some_and(|end| end <= valid_from) {
        return Err(invalid_diagnostic("valid_to must follow valid_from"));
    }
    Ok(())
}

fn validate_keys(entries: &[(Value, Value)]) -> Result<()> {
    let mut seen = [false; DIAGNOSTIC_BODY_KEYS.len()];
    for (position, (key, _)) in entries.iter().enumerate() {
        let key = decode_str(key, "body keys must be strings")?;
        let Some(index) = DIAGNOSTIC_BODY_KEYS.iter().position(|known| *known == key) else {
            return Err(invalid_diagnostic("unknown body key"));
        };
        if seen[index] {
            return Err(invalid_diagnostic("duplicate body key"));
        }
        // Key ORDER is part of the body, not a rendering of it: the pinned
        // array IS the encode order, so a map carrying the same 16 pairs in
        // any other order is a DIFFERENT byte string and must not decode as
        // this event. Checked here rather than repaired, for the same reason
        // invariant values are checked rather than normalized.
        if index != position {
            return Err(invalid_diagnostic("body keys are out of canonical order"));
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|present| present) {
        Ok(())
    } else {
        Err(invalid_diagnostic("missing required body key"))
    }
}

fn required<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(entry_key, value)| (entry_key.as_str() == Some(key)).then_some(value))
        .ok_or_else(|| invalid_diagnostic("missing required body key"))
}

fn required_str<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    decode_str(required(entries, key)?, "body field must be a string")
}

fn decode_str<'a>(value: &'a Value, reason: &'static str) -> Result<&'a str> {
    value.as_str().ok_or_else(|| invalid_diagnostic(reason))
}

fn decode_u64(value: &Value, reason: &'static str) -> Result<u64> {
    value.as_u64().ok_or_else(|| invalid_diagnostic(reason))
}

fn entity_ref_value(entity: &EntityId) -> Value {
    Value::from(entity.to_hex())
}

fn decode_entity_ref(value: &Value) -> Result<EntityId> {
    let hex = decode_str(value, "entity ref must be a hex string")?;
    // Lowercase-only, matching `hex_nibble` above and `EntityId::to_hex`, so
    // one id has exactly one spelling on the wire. `EntityId::from_hex` is
    // case-INSENSITIVE by design, which would otherwise let 2^32 spellings of
    // one ref decode to one event under different bytes and different ids.
    if hex.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(invalid_diagnostic("entity ref must be lowercase hex"));
    }
    EntityId::from_hex(hex).map_err(|_| invalid_diagnostic("malformed entity ref"))
}

fn decode_optional_entity_ref(value: &Value) -> Result<Option<EntityId>> {
    match value {
        Value::Nil => Ok(None),
        other => decode_entity_ref(other).map(Some),
    }
}

fn decode_content_hash(value: &Value) -> Result<[u8; 32]> {
    let hex = decode_str(value, "content hash must be a hex string")?;
    if hex.len() != 64 {
        return Err(invalid_diagnostic("content hash must be 32 bytes"));
    }
    let mut out = [0_u8; 32];
    let bytes = hex.as_bytes();
    for (index, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(bytes[index * 2]);
        let lo = hex_nibble(bytes[index * 2 + 1]);
        let (Some(hi), Some(lo)) = (hi, lo) else {
            return Err(invalid_diagnostic("malformed content hash"));
        };
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

/// Lowercase-only, so one hash has exactly one spelling on the wire.
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn decode_optional_ref(value: &Value) -> Result<Option<String>> {
    match value {
        Value::Nil => Ok(None),
        other => {
            let text = decode_str(other, "replay ref must be a string")?;
            validate_ref(text)?;
            Ok(Some(text.to_owned()))
        }
    }
}

fn decode_evidence_refs(value: &Value) -> Result<Vec<EntityId>> {
    let Value::Array(items) = value else {
        return Err(invalid_diagnostic("evidence_refs must be an array"));
    };
    if items.len() > MAX_EVIDENCE_REFS {
        return Err(invalid_diagnostic("too many evidence refs"));
    }
    let mut refs: Vec<EntityId> = Vec::with_capacity(items.len());
    for item in items {
        let entity = decode_entity_ref(item)?;
        // Canonical order is PART of the body, so a re-ordered or duplicated
        // list is a different body that must not decode as this one.
        if refs.last().is_some_and(|previous| *previous >= entity) {
            return Err(invalid_diagnostic("evidence_refs must ascend"));
        }
        refs.push(entity);
    }
    Ok(refs)
}

fn canonical_optional_ref(value: Option<&str>) -> Result<Value> {
    match value {
        None => Ok(Value::Nil),
        Some(text) => {
            validate_ref(text)?;
            Ok(Value::from(text))
        }
    }
}

fn validate_ref(text: &str) -> Result<()> {
    if text.is_empty() || text.len() > MAX_REF_LEN {
        return Err(invalid_diagnostic("replay ref is empty or too long"));
    }
    if text.chars().any(is_forbidden_text_scalar) {
        return Err(invalid_diagnostic("replay ref carries control data"));
    }
    Ok(())
}

// ── invariant-value canonicalization ────────────────────────────────────────

/// Node and depth budget for one `expected` / `actual` / `delta` value.
#[derive(Default)]
struct InvariantBudget {
    depth: usize,
    nodes: usize,
}

/// Canonicalizes an invariant input AND requires it to have arrived canonical.
///
/// Decode uses this rather than plain canonicalization: silently normalizing a
/// stored body would let two different byte strings decode to one event, which
/// breaks the content addressing the replay coordinate rests on.
fn canonical_invariant_field(value: &Value) -> Result<Value> {
    let canonical = canonical_invariant_value(value)?;
    if &canonical != value {
        return Err(invalid_diagnostic("invariant value is not canonical"));
    }
    Ok(canonical)
}

/// Rebuilds one invariant input into its single canonical spelling.
///
/// The grammar is deliberately narrow. Floats collapse to `f64` and must be
/// finite; integers are normalized; map keys must be unique strings and are
/// sorted; binary and extension leaves are refused outright (a hash belongs
/// here as hex). Strings must be ENGINE-AUTHORED: control data is refused so
/// [`DiagnosticEvent::untrusted_detail`] stays the ONLY door untrusted text
/// enters through, rather than one of four.
fn canonical_invariant_value(value: &Value) -> Result<Value> {
    let mut budget = InvariantBudget::default();
    canonical_invariant_node(value, &mut budget)
}

fn canonical_invariant_node(value: &Value, budget: &mut InvariantBudget) -> Result<Value> {
    budget.nodes += 1;
    if budget.nodes > MAX_INVARIANT_NODES {
        return Err(invalid_diagnostic("invariant value has too many nodes"));
    }
    if budget.depth > MAX_INVARIANT_DEPTH {
        return Err(invalid_diagnostic("invariant value nests too deeply"));
    }
    match value {
        Value::Nil => Ok(Value::Nil),
        Value::Boolean(flag) => Ok(Value::Boolean(*flag)),
        Value::Integer(number) => canonical_invariant_integer(*number),
        Value::F32(number) => canonical_invariant_float(f64::from(*number)),
        Value::F64(number) => canonical_invariant_float(*number),
        Value::String(_) => canonical_invariant_string(value),
        Value::Array(items) => canonical_invariant_array(items, budget),
        Value::Map(entries) => canonical_invariant_map(entries, budget),
        Value::Binary(_) | Value::Ext(_, _) => Err(invalid_diagnostic("invariant raw byte leaf")),
    }
}

fn canonical_invariant_string(value: &Value) -> Result<Value> {
    let text = decode_str(value, "invariant string must be valid UTF-8")?;
    canonical_invariant_text(text).map(Value::from)
}

fn canonical_invariant_text(text: &str) -> Result<&str> {
    if text.len() > MAX_INVARIANT_STRING_LEN {
        return Err(invalid_diagnostic("invariant string is too long"));
    }
    if text.chars().any(is_forbidden_text_scalar) {
        return Err(invalid_diagnostic("invariant string carries controls"));
    }
    Ok(text)
}

fn canonical_invariant_integer(number: Integer) -> Result<Value> {
    if let Some(unsigned) = number.as_u64() {
        return Ok(Value::Integer(Integer::from(unsigned)));
    }
    if let Some(signed) = number.as_i64() {
        return Ok(Value::Integer(Integer::from(signed)));
    }
    Err(invalid_diagnostic("invariant integer is out of range"))
}

fn canonical_invariant_float(number: f64) -> Result<Value> {
    if number.is_finite() {
        Ok(Value::F64(number))
    } else {
        Err(invalid_diagnostic("invariant float must be finite"))
    }
}

fn canonical_invariant_array(items: &[Value], budget: &mut InvariantBudget) -> Result<Value> {
    if items.len() > MAX_INVARIANT_WIDTH {
        return Err(invalid_diagnostic("invariant array is too wide"));
    }
    budget.depth += 1;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        out.push(canonical_invariant_node(item, budget)?);
    }
    budget.depth -= 1;
    Ok(Value::Array(out))
}

fn canonical_invariant_map(
    entries: &[(Value, Value)],
    budget: &mut InvariantBudget,
) -> Result<Value> {
    if entries.len() > MAX_INVARIANT_WIDTH {
        return Err(invalid_diagnostic("invariant map is too wide"));
    }
    budget.depth += 1;
    // A `BTreeMap` IS the canonicalization: it sorts by key and it refuses a
    // second value for a key that already has one, in one structure.
    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    for (key, value) in entries {
        let key = decode_str(key, "invariant map keys must be strings")?;
        if key.is_empty() {
            return Err(invalid_diagnostic("invariant map key is empty"));
        }
        canonical_invariant_text(key)?;
        let value = canonical_invariant_node(value, budget)?;
        if out.insert(key.to_owned(), value).is_some() {
            return Err(invalid_diagnostic("duplicate invariant map key"));
        }
    }
    budget.depth -= 1;
    let mut sorted = Vec::with_capacity(out.len());
    for (key, value) in out {
        sorted.push((Value::from(key), value));
    }
    Ok(Value::Map(sorted))
}

// ── untrusted detail ────────────────────────────────────────────────────────

/// Inclusive scalar ranges that must never reach a reader raw, beyond the C0
/// and C1 control classes `char::is_control` already covers.
///
/// These are the INVISIBLE ones: soft hyphen, the Arabic letter mark, the
/// Mongolian vowel separator, the zero-width space/joiner family, the line and
/// paragraph separators, the bidirectional embedding/override/isolate controls,
/// the deprecated format characters, the byte-order mark, the interlinear
/// annotation marks, and Unicode tag controls. Each is a way to make one string RENDER as a different
/// string, which is exactly the trick an untrusted detail leaf would be used
/// for if it were allowed to carry them.
const FORBIDDEN_TEXT_RANGES: [(char, char); 11] = [
    ('\u{00AD}', '\u{00AD}'),
    ('\u{061C}', '\u{061C}'),
    ('\u{180E}', '\u{180E}'),
    ('\u{200B}', '\u{200F}'),
    ('\u{2028}', '\u{2029}'),
    ('\u{202A}', '\u{202E}'),
    ('\u{2060}', '\u{206F}'),
    ('\u{FEFF}', '\u{FEFF}'),
    ('\u{FFF9}', '\u{FFFB}'),
    ('\u{E0001}', '\u{E0001}'),
    ('\u{E0020}', '\u{E007F}'),
];

/// Whether `scalar` is control or invisible-format data.
fn is_forbidden_text_scalar(scalar: char) -> bool {
    if scalar.is_control() {
        return true;
    }
    for (start, end) in FORBIDDEN_TEXT_RANGES {
        if (start..=end).contains(&scalar) {
            return true;
        }
    }
    false
}

/// Renders `raw` as a control-free canonical leaf.
///
/// Every forbidden scalar becomes a VISIBLE `\u{XXXX}` escape and a literal
/// backslash becomes `\\`, so the escaping is unambiguous to read. The mapping
/// is TOTAL — it runs over every input, including one that already LOOKS
/// escaped — which is what makes it injective: a raw tab and the literal
/// eight-character text `\u{0009}` land on the two different leafs `\u{0009}`
/// and `\\u{0009}`, and therefore on two different event ids, instead of
/// colliding on one.
fn escape_untrusted_detail(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for scalar in raw.chars() {
        if scalar == '\\' {
            out.push_str("\\\\");
        } else if is_forbidden_text_scalar(scalar) {
            let code = scalar as u32;
            out.push_str(&format!("\\u{{{code:04X}}}"));
        } else {
            out.push(scalar);
        }
    }
    out
}

/// Whether `text` is already an escaped canonical leaf.
fn is_canonical_untrusted_detail(text: &str) -> bool {
    if text.chars().any(is_forbidden_text_scalar) {
        return false;
    }
    // Byte scanning is safe here: `\`, `u`, `{`, `}` and the hex digits are all
    // ASCII, and UTF-8 never encodes an ASCII byte inside a multi-byte
    // sequence.
    let bytes = text.as_bytes();
    let mut index = 0_usize;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            index += 1;
            continue;
        }
        match bytes.get(index + 1) {
            Some(b'\\') => index += 2,
            Some(b'u') => match escape_end(bytes, index) {
                Some(next) => index = next,
                None => return false,
            },
            _ => return false,
        }
    }
    true
}

/// End offset only for the writer's exact rendering of a forbidden scalar.
fn escape_end(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start + 2) != Some(&b'{') {
        return None;
    }
    let mut cursor = start + 3;
    while bytes.get(cursor).is_some_and(u8::is_ascii_hexdigit) {
        cursor += 1;
    }
    let digits = cursor - (start + 3);
    if !(4..=6).contains(&digits) || bytes.get(cursor) != Some(&b'}') {
        return None;
    }
    let hex = std::str::from_utf8(&bytes[start + 3..cursor]).ok()?;
    let code = u32::from_str_radix(hex, 16).ok()?;
    let scalar = char::from_u32(code)?;
    if !is_forbidden_text_scalar(scalar) || hex != format!("{code:04X}") {
        return None;
    }
    Some(cursor + 1)
}

/// Escapes ONE raw, author-supplied detail into its stored canonical leaf.
///
/// There is deliberately NO already-canonical passthrough. A passthrough makes
/// the raw → stored map non-injective: a raw tab and the literal
/// eight-character text `\u{0009}` would both store `\u{0009}`, so two
/// different findings would share one body and one content-addressed id, and
/// the text a reader sees would not say which of the two it came from.
///
/// Applying this twice is therefore NOT the identity, and must never happen. A
/// stored leaf is TERMINAL: decode hands it back escaped and never unescapes
/// it, so the only door back onto the wire for an already-canonical leaf is
/// [`encode_stored_diagnostic_event_body`], which validates it instead of
/// escaping it again. This function's one caller is the raw author door.
fn canonical_untrusted_detail(raw: &str) -> Result<String> {
    let canonical = escape_untrusted_detail(raw);
    validate_untrusted_detail(&canonical)?;
    Ok(canonical)
}

fn validate_untrusted_detail(text: &str) -> Result<()> {
    if text.is_empty() {
        return Err(invalid_diagnostic("untrusted_detail must not be empty"));
    }
    if text.len() > MAX_UNTRUSTED_DETAIL_LEN {
        return Err(invalid_diagnostic("untrusted_detail is too long"));
    }
    if text.chars().any(is_forbidden_text_scalar) {
        return Err(invalid_diagnostic("untrusted_detail hides control data"));
    }
    if !is_canonical_untrusted_detail(text) {
        return Err(invalid_diagnostic("untrusted_detail is not escaped"));
    }
    Ok(())
}

fn invalid_diagnostic(reason: &'static str) -> Error {
    Error::InvalidDiagnosticBody(reason)
}

#[cfg(test)]
mod production_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod text_tests;
