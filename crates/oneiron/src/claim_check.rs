//! Claim auto-check candidates and normalized verdict values.

use crate::Result;
use crate::claim::ClaimSource;
use crate::claim::VerdictBasis;
use crate::model_binding::{CalibratedVerdict, VerdictBinding, VerdictMode};
use crate::write_envelope::SourceLineage;
use oneiron_model::llm::NormalizedBurstInputs;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Auto-check seam (ONE-1296).
//
// The engine owns exactly two things here: the typed allow-or-hold decision
// a host's ladder answers, and the bounded wrapper that keeps that answer from
// becoming an engine liveness problem. It owns no model choice, no prompt
// tuning and no verdict policy — the write gate reads only Allow / Hold /
// Unavailable.
// ---------------------------------------------------------------------------

/// Wall-clock bound one auto-check consult may take before the write gate
/// stops waiting for it, and the wait for a turn at the checker of a direct
/// call that brings no deadline of its own.
///
/// A checker that has not answered by then is [`AutoCheckOutcome::Unavailable`]
/// and the write falls to Proposed. The bound is the engine's, not the host's:
/// a claim write must not be able to block on a host process at all. A call
/// with its own deadline ([`BoundedAutoChecker::with_deadline`]) spends that
/// deadline instead, and a consult inside a write never waits past this bound.
pub const AUTO_CHECKER_DEADLINE_MS: u64 = 1_500;

/// Longest claim-value prefix an auto-check candidate carries.
///
/// The checker is shown a PREVIEW, never the whole value: this seam is a
/// second opinion on a candidate, not a disclosure channel.
pub const AUTO_CHECK_VALUE_PREVIEW_BYTES: usize = 512;

/// Most `Hold` reasons one verdict may put on the receipt.
pub(crate) const AUTO_CHECK_MAX_HOLD_REASONS: usize = 8;

/// Longest single `Hold` reason one verdict may put on the receipt.
pub(crate) const AUTO_CHECK_HOLD_REASON_MAX_BYTES: usize = 256;

/// Soft auto-verdict inputs computed from committed/same-transaction receipts.
/// They are observations, not a durable trip or an authority ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AutoCheckSignals {
    pub recent_writes: u64,
    pub window_secs: u64,
    pub failure_streak: u64,
}

/// One candidate write presented to a host checker, borrowed from the write
/// door's own state.
#[derive(Debug, Clone, PartialEq)]
pub struct AutoCheckCandidate<'a> {
    pub predicate: &'a str,
    pub value_preview: &'a str,
    /// The claim's declared source, independent of its history.
    pub source: ClaimSource,
    /// Source classes in the write's history, or `None` without an envelope.
    /// Restricted members can trigger this consult even for a benign declaration.
    pub lineage: Option<&'a SourceLineage>,
    pub actor_class: &'a str,
    pub sensitivity_band: Option<u8>,
    /// Native peer-relative observations, absent at doors with no write history.
    /// These are verdict inputs and never an engine-side clamp.
    pub burst: Option<NormalizedBurstInputs>,
    pub signals: AutoCheckSignals,
}

/// [`AutoCheckCandidate`] with every borrow resolved.
///
/// [`BoundedAutoChecker`] hands this — not the borrowed form — to its worker,
/// so the host's answer can outlive the gate's deadline without the gate having
/// to keep anything alive for it.
#[derive(Debug, Clone, PartialEq)]
pub struct AutoCheckCandidateOwned {
    pub predicate: String,
    pub value_preview: String,
    /// The claim's declared source, independent of its history.
    pub source: ClaimSource,
    /// Source classes in the write's history, or `None` without an envelope.
    pub lineage: Option<SourceLineage>,
    pub actor_class: String,
    pub sensitivity_band: Option<u8>,
    /// Native peer-relative observations, absent at doors with no write history.
    /// These are verdict inputs and never an engine-side clamp.
    pub burst: Option<NormalizedBurstInputs>,
    pub signals: AutoCheckSignals,
}

impl AutoCheckCandidateOwned {
    /// Borrows this candidate back into the shape the decisions take.
    #[must_use]
    pub fn borrowed(&self) -> AutoCheckCandidate<'_> {
        AutoCheckCandidate {
            predicate: &self.predicate,
            value_preview: &self.value_preview,
            source: self.source,
            lineage: self.lineage.as_ref(),
            actor_class: &self.actor_class,
            sensitivity_band: self.sensitivity_band,
            burst: self.burst,
            signals: self.signals,
        }
    }
}

impl From<&AutoCheckCandidate<'_>> for AutoCheckCandidateOwned {
    fn from(candidate: &AutoCheckCandidate<'_>) -> Self {
        Self {
            predicate: candidate.predicate.to_owned(),
            value_preview: candidate.value_preview.to_owned(),
            source: candidate.source,
            lineage: candidate.lineage.cloned(),
            actor_class: candidate.actor_class.to_owned(),
            sensitivity_band: candidate.sensitivity_band,
            burst: candidate.burst,
            signals: candidate.signals,
        }
    }
}

/// The auto check's verdict on one candidate.
///
/// There is no error arm on purpose: a failed or abstained decision — budget
/// denial, fatal model error, no rung left — is [`Self::Unavailable`], and the
/// gate treats that exactly like a hold that could not name its reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoCheckOutcome {
    Verdict(CalibratedVerdict),
    Allow,
    Hold { reasons: Vec<String> },
    Unavailable,
}

impl AutoCheckOutcome {
    /// Fail-closed normalization every consumer of a host verdict applies.
    ///
    /// A `Hold` that names no surviving reason is a MALFORMED verdict, not a
    /// quiet hold: the receipt would carry a refusal nothing could explain, so
    /// it becomes [`Self::Unavailable`]. Reasons are trimmed, blank-dropped,
    /// truncated to `AUTO_CHECK_HOLD_REASON_MAX_BYTES` and capped at
    /// `AUTO_CHECK_MAX_HOLD_REASONS`, so a host cannot write an unbounded
    /// gate-decision receipt.
    #[must_use]
    pub fn normalized(self) -> Self {
        let Self::Hold { reasons } = self else {
            return self;
        };
        let reasons: Vec<String> = reasons
            .iter()
            .filter_map(|reason| {
                let trimmed = reason.trim();
                (!trimmed.is_empty()).then(|| {
                    truncate_on_char_boundary(trimmed, AUTO_CHECK_HOLD_REASON_MAX_BYTES).to_owned()
                })
            })
            .take(AUTO_CHECK_MAX_HOLD_REASONS)
            .collect();
        if reasons.is_empty() {
            Self::Unavailable
        } else {
            Self::Hold { reasons }
        }
    }
}

/// Generation beside a decided hold: the reasons the gate's receipt keeps, from
/// the host's own model transport. The hold is already decided; reasons cannot
/// turn it into an allow. A hold with no surviving reason is
/// [`AutoCheckOutcome::Unavailable`]. `due` is when the gate stops waiting: a
/// reason written past it would lose the hold, so a host writes none that
/// late (FIX 654).
pub trait AutoCheckNotes: Send + Sync {
    fn hold_reasons(&self, candidate: &AutoCheckCandidate<'_>, due: Instant)
    -> Result<Vec<String>>;
}

/// Truncates `value` to at most `max_bytes`, never splitting a character.
pub(crate) fn truncate_on_char_boundary(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// A calibrated check can only hold. Shadow emits a receipt reason without holding.
pub(crate) fn apply_verdict_floor(
    binding: Option<&VerdictBinding>,
    outcome: AutoCheckOutcome,
) -> (AutoCheckOutcome, Option<&'static str>) {
    let Some(binding) = binding else {
        return (
            if matches!(outcome, AutoCheckOutcome::Verdict(_)) {
                AutoCheckOutcome::Unavailable
            } else {
                outcome
            },
            None,
        );
    };
    // A floor evaluates calibrated verdicts only; legacy checker refusals survive.
    if matches!(
        &outcome,
        AutoCheckOutcome::Hold { .. } | AutoCheckOutcome::Unavailable
    ) {
        return (outcome, None);
    }
    let pass = matches!(&outcome, AutoCheckOutcome::Verdict(v) if v.validate().is_ok() && v.model == binding.model && v.allow && v.band >= binding.floor && v.basis == VerdictBasis::CalibratedModel);
    if pass {
        return (AutoCheckOutcome::Allow, Some("verdict_pass"));
    }
    match binding.mode {
        VerdictMode::Shadow => (AutoCheckOutcome::Allow, Some("verdict_shadow_hold")),
        VerdictMode::Enforce => (
            AutoCheckOutcome::Hold {
                reasons: vec!["verdict_floor".into()],
            },
            Some("verdict_enforce_hold"),
        ),
    }
}
