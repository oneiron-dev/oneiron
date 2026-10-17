//! Auto-check seam: candidate types, fail-closed verdicts and the bounded host wrapper.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::{Value as JsonValue, json};

use super::ModelId;
use super::NormalizedBurstInputs;
use super::decision::catalogue::AUTO_CHECK;
use super::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionDial, HeldLadder, Reversibility,
};
use super::manifest::{CalibratedVerdict, ConfidenceBand, VerdictBasis};
use crate::claim::ClaimSource;
use crate::retrieval_depth::RetrievalDeadline;
use crate::write_envelope::SourceLineage;
use crate::{EntityId, Result};

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
/// stops waiting for it.
///
/// A checker that has not answered by then is [`AutoCheckOutcome::Unavailable`]
/// and the write falls to Proposed. The bound is the engine's, not the host's:
/// a claim write must not be able to block on a host process at all.
pub const AUTO_CHECKER_DEADLINE_MS: u64 = 1_500;

/// Longest claim-value prefix an auto-check candidate carries.
///
/// The checker is shown a PREVIEW, never the whole value: this seam is a
/// second opinion on a candidate, not a disclosure channel.
pub const AUTO_CHECK_VALUE_PREVIEW_BYTES: usize = 512;

/// Most `Hold` reasons one verdict may put on the receipt.
pub(super) const AUTO_CHECK_MAX_HOLD_REASONS: usize = 8;

/// Longest single `Hold` reason one verdict may put on the receipt.
pub(super) const AUTO_CHECK_HOLD_REASON_MAX_BYTES: usize = 256;

/// The tier an auto check asks for by PURPOSE default: the cheap one. The
/// per-call and vault-policy slots stay empty so a vault that pins its own
/// tier still wins through [`crate::llm::TierPrecedence::resolved`].
#[cfg(test)]
pub(super) const AUTO_CHECK_PURPOSE_DEFAULT_TIER: &str = "cheap";

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
    Verdict(super::manifest::CalibratedVerdict),
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

/// The answer that lets a candidate self-approve.
const ALLOW: &str = "allow";
/// The answer that holds it.
const HOLD: &str = "hold";

/// Generation beside a decided hold: the reasons the gate's receipt keeps, from
/// the host's own model transport. The hold is already decided; reasons cannot
/// turn it into an allow. A hold with no surviving reason is
/// [`AutoCheckOutcome::Unavailable`].
pub trait AutoCheckNotes: Send + Sync {
    fn hold_reasons(&self, candidate: &AutoCheckCandidate<'_>) -> Result<Vec<String>>;
}

/// The host's auto check as one typed decision through its ladder: allow or
/// hold, over the candidate as the call's bounded state, under the gate's own
/// clock ([`AUTO_CHECKER_DEADLINE_MS`]). The check is a self-approval, so a
/// cut abstains rather than take an unfinished answer.
///
/// Synchronous by design: the write gate runs inside an LMDB write
/// transaction, which is not a place to hold an async runtime open. Bound it
/// with [`BoundedAutoChecker`] before injecting it.
pub struct AutoCheckDecisions {
    pub ladder: HeldLadder,
    pub principal: EntityId,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    pub wording: String,
    pub notes: Arc<dyn AutoCheckNotes>,
    /// The model a vault's verdict binding names, when the host's ladder
    /// answers as that calibrated model: the answer then reaches the gate as
    /// its calibrated verdict, the decision's probability as the confidence,
    /// and the floor decides. `None` answers Allow or Hold.
    pub calibrated: Option<ModelId>,
}

impl AutoCheckDecisions {
    /// An error, an abstention or a hold with no reasons is
    /// [`AutoCheckOutcome::Unavailable`], never a third label.
    fn check(&self, candidate: &AutoCheckCandidate<'_>) -> AutoCheckOutcome {
        self.decide(candidate)
            .unwrap_or(AutoCheckOutcome::Unavailable)
    }

    fn decide(&self, candidate: &AutoCheckCandidate<'_>) -> Result<AutoCheckOutcome> {
        let question = AUTO_CHECK.question(
            &[],
            self.wording.clone(),
            AnswerContract::Choice {
                options: vec![ALLOW.to_owned(), HOLD.to_owned()],
            },
        )?;
        let decision = self.ladder.ladder().run(
            &question,
            self.principal,
            &[],
            &candidate_state(candidate),
            self.dial,
            &self.bands,
            Reversibility::OutboundEffect,
            &RetrievalDeadline::hard(
                Instant::now(),
                Duration::from_millis(AUTO_CHECKER_DEADLINE_MS),
            ),
        )?;
        let (DecisionAnswer::Choice(label), Some(probability)) =
            (&decision.answer, decision.probability)
        else {
            return Ok(AutoCheckOutcome::Unavailable);
        };
        let allow = label == ALLOW;
        if let Some(model) = &self.calibrated {
            return Ok(calibrated(model, allow, probability));
        }
        Ok(if allow {
            AutoCheckOutcome::Allow
        } else {
            AutoCheckOutcome::Hold {
                reasons: self.notes.hold_reasons(candidate)?,
            }
        })
    }
}

/// The answer as `model`'s calibrated verdict, in the band its confidence
/// falls in.
fn calibrated(model: &ModelId, allow: bool, probability: f64) -> AutoCheckOutcome {
    let confidence_millionths = millionths(probability);
    [
        ConfidenceBand::Low,
        ConfidenceBand::Medium,
        ConfidenceBand::High,
        ConfidenceBand::Certain,
    ]
    .into_iter()
    .map(|band| CalibratedVerdict {
        model: model.clone(),
        allow,
        confidence_millionths,
        band,
        basis: VerdictBasis::CalibratedModel,
    })
    .find(|verdict| verdict.validate().is_ok())
    .map_or(AutoCheckOutcome::Unavailable, AutoCheckOutcome::Verdict)
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "a unit-interval probability as millionths fits a u32"
)]
fn millionths(probability: f64) -> u32 {
    (probability.clamp(0.0, 1.0) * 1_000_000.0).round() as u32
}

/// The candidate as the call's state. The value is the gate's bounded preview,
/// never the whole value.
fn candidate_state(candidate: &AutoCheckCandidate<'_>) -> JsonValue {
    json!({
        "predicate": candidate.predicate,
        "value_preview": candidate.value_preview,
        "source": candidate.source.as_str(),
        "lineage": candidate
            .lineage
            .map(|lineage| lineage.iter().map(ClaimSource::as_str).collect::<Vec<_>>()),
        "actor_class": candidate.actor_class,
        "sensitivity_band": candidate.sensitivity_band,
        "burst": candidate
            .burst
            .map(|burst| json!({"rate_ratio": burst.rate_ratio, "streak": burst.streak})),
        "signals": {
            "recent_writes": candidate.signals.recent_writes,
            "window_secs": candidate.signals.window_secs,
            "failure_streak": candidate.signals.failure_streak,
        },
    })
}

/// The wrapper that makes the host's auto-check decisions safe to call from
/// the write gate.
///
/// Each wrapper owns one worker and admits only one outstanding consult.
/// Clones share that worker and its capacity. A timeout stops the caller's wait,
/// but capacity stays occupied until the host call actually ends. Further
/// consults fail closed immediately while occupied; blocked hosts are never
/// joined and cannot cause this wrapper to accumulate workers or queued calls.
///
/// Candidates are owned off the gate's stack. Timeout, panic, spawn failure,
/// occupied capacity, and malformed verdicts become [`AutoCheckOutcome::Unavailable`].
#[derive(Clone)]
pub struct BoundedAutoChecker {
    sender: Option<mpsc::SyncSender<AutoCheckJob>>,
    pub(super) occupied: Arc<AtomicBool>,
}

struct AutoCheckJob {
    candidate: AutoCheckCandidateOwned,
    reply: mpsc::SyncSender<AutoCheckOutcome>,
}

impl BoundedAutoChecker {
    #[must_use]
    pub fn new(decisions: AutoCheckDecisions) -> Self {
        let (sender, receiver) = mpsc::sync_channel::<AutoCheckJob>(1);
        let occupied = Arc::new(AtomicBool::new(false));
        let worker_occupied = Arc::clone(&occupied);
        // One persistent worker, not one detached thread per consult. Dropping
        // the last wrapper closes the channel; an idle worker then exits. A
        // blocked host keeps only this worker, without delaying wrapper drop.
        let worker = std::thread::Builder::new()
            .name("oneiron-auto-check".to_owned())
            .spawn(move || {
                while let Ok(job) = receiver.recv() {
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        decisions.check(&job.candidate.borrowed()).normalized()
                    }))
                    .unwrap_or(AutoCheckOutcome::Unavailable);
                    drop(job.candidate);
                    // Only the worker releases an admitted call's capacity,
                    // after the host has returned or unwound, never on timeout.
                    worker_occupied.store(false, Ordering::Release);
                    // Capacity one; never wait for a caller that has timed out.
                    let _ = job.reply.try_send(outcome);
                }
            });
        Self {
            sender: worker.ok().map(|_| sender),
            occupied,
        }
    }
}

impl fmt::Debug for BoundedAutoChecker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedAutoChecker").finish_non_exhaustive()
    }
}

impl BoundedAutoChecker {
    pub fn check(&self, candidate: &AutoCheckCandidate<'_>) -> AutoCheckOutcome {
        let Some(sender) = &self.sender else {
            return AutoCheckOutcome::Unavailable;
        };
        if self
            .occupied
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return AutoCheckOutcome::Unavailable;
        }
        let (reply, receiver) = mpsc::sync_channel(1);
        let job = AutoCheckJob {
            candidate: AutoCheckCandidateOwned::from(candidate),
            reply,
        };
        if sender.try_send(job).is_err() {
            // No worker accepted this call, so there is no live host to await.
            self.occupied.store(false, Ordering::Release);
            return AutoCheckOutcome::Unavailable;
        }
        receiver
            .recv_timeout(Duration::from_millis(AUTO_CHECKER_DEADLINE_MS))
            .unwrap_or(AutoCheckOutcome::Unavailable)
    }
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
