//! Deterministic detector execution: working-set validation, run loop, event ids, Vault entry points.

use std::sync::atomic::Ordering;

use super::diagnostic_codec::{encode_diagnostic_event_body, validate_token};
use super::event::{
    DIAGNOSTIC_EVENT_ID_DOMAIN, DeterministicDetector, DiagnosticEvent, DiagnosticObservation,
    DiagnosticWorkingSet, MAX_EVENTS_PER_RUN, MAX_REF_LEN, invalid_diagnostic,
};
use super::untrusted_text::is_forbidden_text_scalar;
use crate::Vault;
use crate::batch::{BatchOp, apply_ops};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_DIAGNOSTIC;
use crate::temporal::TimeRange;

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
            if event.detector_id != detector_id {
                return Err(invalid_diagnostic("draft detector identity mismatch"));
            }
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
/// Admission requires `detector_id` to equal the identity persisted in the
/// canonical body. Every local and replicated put checks this binding.
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

pub(super) fn validate_working_set(input: &DiagnosticWorkingSet<'_>) -> Result<()> {
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
