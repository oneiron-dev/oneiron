//! What the gate ruled, and the durable row that says so.

use super::*;

// ---------------------------------------------------------------------------
// Verdicts
// ---------------------------------------------------------------------------

/// What the gate ruled, and why.
///
/// Every arm is durable and queryable — an automated editor whose rejections
/// are invisible is an editor nobody can audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SkillEditDisposition {
    /// Strict improvement, unprotected tier, within cap.
    Accepted,
    /// `after <= before`. Ties live here: there is no epsilon.
    Rejected,
    /// Improving, but this cycle already spent its accepts. The proposal stays
    /// OPEN — a later cycle may admit it. The ONLY durable open disposition.
    DeferredCycleCap,
    /// Identity- or alignment-tier at accept time, on the TARGET or on the
    /// PROPOSAL itself — protected, ambiguous, or moved since the basis was
    /// taken. One arm carries every tier answer, and as a refusal it closes the
    /// proposal atomically.
    RefusedProtectedTier,
    /// The target moved (superseded, re-versioned, no longer active) between
    /// drafting and the verdict.
    RefusedStaleTarget,
    /// A cited `source_messages` id no longer resolves in the active store.
    RefusedSourceLoss,
    /// A `source_messages` linkage is present but not an array of entity ids.
    RefusedSourceMalformed,
    /// At admission, the candidate body, the predecessor body or the reserved
    /// evidence was no longer the one the standing acceptance was ruled over.
    ///
    /// The binding arm: an acceptance is about a specific pair of bodies judged
    /// over a specific set of receipts, and admitting anything else would
    /// activate content the gate never scored.
    RefusedBindingMismatch,
}

impl SkillEditDisposition {
    /// The pinned on-disk / on-receipt string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::DeferredCycleCap => "deferred_cycle_cap",
            Self::RefusedProtectedTier => "refused_protected_tier",
            Self::RefusedStaleTarget => "refused_stale_target",
            Self::RefusedSourceLoss => "refused_source_loss",
            Self::RefusedSourceMalformed => "refused_source_malformed",
            Self::RefusedBindingMismatch => "refused_binding_mismatch",
        }
    }

    pub(super) fn parse(value: &str) -> Option<Self> {
        match value {
            "accepted" => Some(Self::Accepted),
            "rejected" => Some(Self::Rejected),
            "deferred_cycle_cap" => Some(Self::DeferredCycleCap),
            // "deferred_evidence_changed" is deliberately ABSENT: the evidence
            // race is a retryable abort that commits nothing, so a row
            // spelling it is a row from a build whose contract no longer
            // holds. It decodes as `CorruptedIndex`, like every other v1/v2
            // row — prerelease, no shim.
            //
            // "refused_no_held_out_evidence" is absent for exactly that
            // reason, one repair later: an empty reserve says nothing about
            // the proposal, so it too became a retryable abort that writes no
            // row (`decision::rule_on_proposal`), and a stored row spelling it
            // is a durable answer this contract no longer gives.
            "refused_protected_tier" => Some(Self::RefusedProtectedTier),
            "refused_stale_target" => Some(Self::RefusedStaleTarget),
            "refused_source_loss" => Some(Self::RefusedSourceLoss),
            "refused_source_malformed" => Some(Self::RefusedSourceMalformed),
            "refused_binding_mismatch" => Some(Self::RefusedBindingMismatch),
            _ => None,
        }
    }

    /// Whether this verdict makes the proposal eligible for admission.
    #[must_use]
    pub const fn admits(self) -> bool {
        matches!(self, Self::Accepted)
    }

    /// Whether the proposal remains an open question a later cycle may answer.
    ///
    /// Exactly ONE ruling leaves it open, and it is the cap deferral: a ruling
    /// that says nothing about the proposal except that this wake's budget was
    /// already spent. A rejection and a refusal are both ANSWERS — the evidence
    /// said no — and re-asking them next wake would be the nagging ONE-1448's
    /// open-question rule already refuses.
    ///
    /// A raced snapshot is NOT on this list, because it is not a ruling at all:
    /// it commits nothing and returns [`Error::SkillEditGateRetry`], leaving
    /// the proposal in its pre-call state. A second durable open class would
    /// have grown one more row on every raced retry and made "open" mean two
    /// different things.
    ///
    /// The complement is [`Self::closes_proposal`], and every answer that is
    /// not this deferral closes: a terminal ruling that left the record
    /// `candidate + proposed` would wedge the skill forever, because the
    /// drafting job skips a skill with an open proposed revision.
    #[must_use]
    pub const fn leaves_proposal_open(self) -> bool {
        matches!(self, Self::DeferredCycleCap)
    }

    /// Whether this ruling ANSWERS the proposal, and so must close it.
    ///
    /// An acceptance is not an answer of this kind: it arms the admission door,
    /// and the proposal stays open until that door (or a later refusal at it)
    /// moves the record.
    #[must_use]
    pub const fn closes_proposal(self) -> bool {
        !self.leaves_proposal_open() && !self.admits()
    }

    /// Whether the caller is told by an `Err` as well as by the ledger.
    ///
    /// Reject and defer are ordinary answers a loop keeps running after, so
    /// they return `Ok`. A refusal says the proposal should never have reached
    /// the gate in this shape, so it is also a typed error.
    pub(super) const fn is_refusal(self) -> bool {
        matches!(
            self,
            Self::RefusedProtectedTier
                | Self::RefusedStaleTarget
                | Self::RefusedSourceLoss
                | Self::RefusedSourceMalformed
                | Self::RefusedBindingMismatch
        )
    }

    pub(super) const fn refusal_error(self) -> Error {
        match self {
            Self::RefusedBindingMismatch => invalid(
                "the candidate, its target or the reserved evidence moved after the accepted verdict",
            ),
            Self::RefusedProtectedTier => invalid(
                "identity/alignment-tier skills are never admitted by the automated edit loop",
            ),
            Self::RefusedStaleTarget => {
                invalid("optimization target moved before the gate could rule")
            }
            Self::RefusedSourceLoss => {
                invalid("a cited source message no longer resolves; the candidate is ungrounded")
            }
            Self::RefusedSourceMalformed => {
                invalid("source_messages must be an array of 32-char entity id hex strings")
            }
            _ => invalid("skill edit gate refusal"),
        }
    }
}

/// One durable gate ruling.
///
/// The three blueprint fields (`before`, `after`, `accepted`) are the headline;
/// the rest is what makes the ruling auditable without a second lookup — which
/// proposal, against which skill, on which reserved evidence, in which cycle.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct HeldOutVerdict {
    /// Score of the CURRENT instructions over the reserved evidence.
    pub before: f32,
    /// Score of the PROPOSED instructions over the same reserved evidence.
    pub after: f32,
    /// `after > before`, and nothing refused or deferred it.
    pub accepted: bool,
    /// Ledger row id; the receipt's id is derived from it.
    pub id: EntityId,
    /// The gated proposal this ruling is about.
    pub proposal: EntityId,
    /// The ACTIVE skill the proposal revises.
    pub skill: EntityId,
    pub disposition: SkillEditDisposition,
    pub cycle: String,
    /// The reserved receipts the scores were computed over — a bounded DISPLAY
    /// list, newest [`SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE`] first-dropped-last.
    ///
    /// [`Self::held_out_truncated`] says when it is a window rather than the
    /// whole basis; [`Self::held_out_count`] and [`Self::held_out_digest`] are
    /// the basis itself and are what every comparison in this module actually
    /// uses. A row that showed 64 of 300 receipts with no count and no digest
    /// was claiming an evidence basis it did not have.
    pub held_out_receipts: Vec<String>,
    /// How many reserved receipts the scores were ACTUALLY computed over.
    pub held_out_count: u64,
    /// Canonical digest of the exact scored evidence set, in scored order
    /// ([`held_out_receipt_set_digest`]).
    pub held_out_digest: String,
    /// Whether [`Self::held_out_receipts`] is a bounded window on the basis.
    pub held_out_truncated: bool,
    /// Canonical content digest of the candidate body that was scored.
    pub proposal_digest: String,
    /// Canonical content digest of the predecessor body it was scored against.
    pub target_digest: String,
    /// The PROPOSAL's effective governance tier at the moment this ruling was
    /// based ([`ScoredBasis::proposal_tier`]).
    ///
    /// `None` on a pre-score refusal, which has no basis at all, and on a
    /// ruling whose proposal resolved AMBIGUOUS — neither can be admitted.
    /// The admission door re-resolves the tier in its own snapshot and refuses
    /// when it is protected, ambiguous, or simply no longer this one: an
    /// owner's identity mark landed on the PROPOSAL after acceptance is the
    /// newer fact, and it must not ride the old acceptance into canon.
    pub proposal_tier: Option<SkillGovernanceTier>,
    /// The accepted verdict this row answers, on a post-score refusal.
    ///
    /// `None` on every ruling the gate itself made. `Some` exactly when
    /// admission was reached THROUGH a standing acceptance and then refused, so
    /// a reader can follow the refusal back to the scores it supersedes rather
    /// than reading a zero pair as an unscored tie.
    pub accepted_verdict: Option<EntityId>,
    /// Cited source ids that failed to resolve, on a source refusal.
    pub missing_sources: Vec<EntityId>,
    pub at: u64,
}

impl HeldOutVerdict {
    /// The improvement the pair records. Negative on a regression.
    #[must_use]
    pub fn improvement(&self) -> f32 {
        self.after - self.before
    }

    /// This ruling, restated as a post-score refusal at the admission door.
    ///
    /// A NEW row (its own id, its own timestamp, its own disposition) that
    /// keeps everything the acceptance established: the real score pair, the
    /// evidence basis, both body digests, the pair of entities and the cycle.
    /// Only the answer changes, and the row names the acceptance it answers.
    pub(super) fn refused_at_admission(&self, disposition: SkillEditDisposition, at: u64) -> Self {
        Self {
            id: EntityId::now(),
            disposition,
            accepted: disposition.admits(),
            accepted_verdict: Some(self.id),
            missing_sources: Vec::new(),
            at,
            ..self.clone()
        }
    }
}
