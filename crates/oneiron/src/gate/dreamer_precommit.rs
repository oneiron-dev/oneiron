//! GATE-12 pre-commit validation for Dreamer-authored claim writes.
//!
//! Every claim a Dreamer run attempts through the LOCAL write door clears
//! these checks BEFORE the policy evaluator runs and before any decision is
//! applied, so an invalid candidate is a stable gate DENIAL rather than a
//! Proposed row, a pending consent, or a supersession. The checks are
//! deterministic and model-free: no clock, no randomness, no network, and no
//! I/O beyond the injected existence resolver.
//!
//! The replicated replay path never reaches this module — replay stays
//! trust-blind.

use rmpv::Value;

use crate::claim::{MAX_PREDICATE_BYTES, RESERVED_PREDICATE_NAMESPACE};
use crate::dreamer_consolidation::decode_consolidation_evidence;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY;

use super::decision::GateReasonCode;

/// Lowercase prefixes of narration a Dreamer sometimes emits in place of a
/// claim value. Matched case-insensitively against the trimmed value.
pub(crate) const DREAMER_DEGENERATE_VALUE_PREFIXES: [&str; 8] = [
    "i will",
    "i'll",
    "working on",
    "in progress",
    "todo",
    "tbd",
    "placeholder",
    "as an ai",
];

/// Predicates whose claims ARE the Dreamer's own runtime record, so they
/// cannot be asked to cite evidence for themselves. Composed from the
/// existing predicate constants rather than re-literalized, so a rename
/// cannot silently desync this exemption table from the writers.
pub(crate) const DREAMER_RUNTIME_RECORD_PREDICATES: [&str; 3] = [
    crate::dreamer_runner::DREAMER_MILESTONE_PREDICATE,
    crate::llm::DREAMER_STEP_PREDICATE,
    crate::llm::DREAMER_TRAP_PREDICATE,
];

/// The claim-shaped axes the pre-commit checks read. Borrowed from the
/// candidate body at the door; nothing here is owned or mutated.
pub(crate) struct DreamerPrecommitInput<'a> {
    pub(crate) predicate: &'a str,
    pub(crate) value: &'a Value,
    pub(crate) confidence: f32,
    pub(crate) subject_present: bool,
    /// The claim body's evidence map, as written by the envelope door.
    pub(crate) evidence: Option<&'a Value>,
}

/// Validates one Dreamer-authored claim candidate.
///
/// The check ORDER is load-bearing and first failure wins: degeneracy, then
/// structural shape, then the evidence floor. `resolves` answers "does this
/// entity exist and read back" for one evidence ref; it is injected so the
/// validator stays deterministic and unit-testable while the door supplies
/// its own transaction.
pub(crate) fn validate_dreamer_precommit(
    input: &DreamerPrecommitInput<'_>,
    resolves: &dyn Fn(&EntityId) -> Result<bool>,
) -> std::result::Result<(), GateReasonCode> {
    if degenerate_narration(input.value) {
        return Err(GateReasonCode::DenyDreamerDegenerateOutput);
    }
    if malformed_shape(input) {
        return Err(GateReasonCode::DenyDreamerMalformed);
    }
    // A runtime record is its own evidence; every other claim must cite at
    // least one ref that still resolves.
    if DREAMER_RUNTIME_RECORD_PREDICATES.contains(&input.predicate) {
        return Ok(());
    }
    if evidence_floor_satisfied(input, resolves) {
        return Ok(());
    }
    Err(GateReasonCode::DenyDreamerNoEvidence)
}

/// Check 1. Only string values can be degenerate narration; every other
/// value shape skips this check and is judged structurally.
fn degenerate_narration(value: &Value) -> bool {
    let Value::String(text) = value else {
        return false;
    };
    let Some(text) = text.as_str() else {
        // Not readable as narration at all; the structural check refuses it.
        return false;
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return true;
    }
    let lowered = trimmed.to_lowercase();
    DREAMER_DEGENERATE_VALUE_PREFIXES
        .iter()
        .any(|prefix| lowered.starts_with(prefix))
}

/// Check 2. Predicate, confidence, subject and value-shape floors. These
/// restate bounds the claim codec also enforces: the codec owns the stored
/// shape, this door owns the Dreamer's authorship contract, and a candidate
/// that slips past one must still not pass the other.
fn malformed_shape(input: &DreamerPrecommitInput<'_>) -> bool {
    let reserved_namespace = input
        .predicate
        .split('.')
        .next()
        .is_some_and(|namespace| namespace == RESERVED_PREDICATE_NAMESPACE);
    // A string payload whose bytes are not UTF-8 is a malformed value, not
    // narration: check 1 cannot read it, so it is refused here.
    let non_utf8_value = matches!(input.value, Value::String(text) if text.as_str().is_none());

    input.predicate.is_empty()
        || input.predicate.len() > MAX_PREDICATE_BYTES
        || reserved_namespace
        || input.confidence.is_nan()
        || !(0.0..=1.0).contains(&input.confidence)
        || !input.subject_present
        || matches!(input.value, Value::Nil)
        || non_utf8_value
}

/// Check 3. At least one `candidate_evidence` ref must resolve to an
/// existing, non-erased entity.
fn evidence_floor_satisfied(
    input: &DreamerPrecommitInput<'_>,
    resolves: &dyn Fn(&EntityId) -> Result<bool>,
) -> bool {
    let Some(Value::Map(entries)) = input.evidence else {
        return false;
    };
    let Some(candidate_evidence) = entries.iter().find_map(|(key, value)| {
        (key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY)).then_some(value)
    }) else {
        return false;
    };
    // A legacy payload shape (`Ok(None)`) and a structurally broken envelope
    // — including a malformed or reserved-sentinel ref — both count as no
    // admissible evidence rather than aborting the write with a decode
    // error. A resolver error is likewise fail-closed: unresolved, so the
    // floor is not met.
    let Ok(Some(envelope)) = decode_consolidation_evidence(candidate_evidence) else {
        return false;
    };
    envelope
        .refs
        .iter()
        .any(|entity_ref| resolves(entity_ref).unwrap_or(false))
}
