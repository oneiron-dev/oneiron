//! Confidence-gated forward commitments, separate from belief consolidation and the commitment ledger.
//!
//! The four kinds are the stable vocabulary; this module's predicates and
//! string payload are deliberately small implementation choices, not canon ABI.

use rmpv::Value;

use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};

/// Minimum confidence for an automatic forward claim (an engine policy choice).
pub const FORWARD_CONFIDENCE_FLOOR: f32 = 0.7;
/// Care check-ins require stronger evidence than ordinary forward claims.
pub const CARE_CONFIDENCE_FLOOR: f32 = 0.9;

/// The pinned four kinds of carry-forward claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarryForwardKind {
    /// A future event worth checking after it happens.
    EventCheckIn,
    /// A deadline requiring a follow-up.
    DeadlineCheck,
    /// A care-sensitive check-in, not an inferred wellbeing diagnosis.
    CareCheckIn,
    /// An unfinished thread to revisit.
    OpenLoop,
}

impl CarryForwardKind {
    /// The current claim predicate for this kind.
    #[must_use]
    pub const fn predicate(self) -> &'static str {
        match self {
            Self::EventCheckIn => "core.carry_forward.event_check_in",
            Self::DeadlineCheck => "core.carry_forward.deadline_check",
            Self::CareCheckIn => "core.carry_forward.care_check_in",
            Self::OpenLoop => "core.carry_forward.open_loop",
        }
    }

    /// Identify a carry-forward claim without accepting unknown sub-types.
    #[must_use]
    pub fn from_predicate(predicate: &str) -> Option<Self> {
        match predicate {
            "core.carry_forward.event_check_in" => Some(Self::EventCheckIn),
            "core.carry_forward.deadline_check" => Some(Self::DeadlineCheck),
            "core.carry_forward.care_check_in" => Some(Self::CareCheckIn),
            "core.carry_forward.open_loop" => Some(Self::OpenLoop),
            _ => None,
        }
    }

    /// The minimum confidence before an automatic write can be attempted.
    #[must_use]
    pub const fn auto_floor(self) -> f32 {
        match self {
            Self::CareCheckIn => CARE_CONFIDENCE_FLOOR,
            _ => FORWARD_CONFIDENCE_FLOOR,
        }
    }
}

/// One forward-looking claim, authored through the ordinary Write Envelope.
#[derive(Debug, Clone, PartialEq)]
pub struct CarryForwardClaim {
    /// What to follow up on.
    pub kind: CarryForwardKind,
    /// The entity this forward claim concerns.
    pub subject: EntityId,
    /// The concrete event, deadline, check-in or open loop, without style or cadence policy.
    pub detail: String,
    /// Evidence confidence in [0, 1].
    pub confidence: f32,
}

impl CarryForwardClaim {
    /// Build a claim with the correct predicate and value.
    ///
    /// # Errors
    /// Invalid detail or confidence is rejected before a write starts.
    pub fn into_candidate(self) -> Result<ClaimCandidate> {
        if self.detail.trim().is_empty()
            || !self.confidence.is_finite()
            || !(0.0..=1.0).contains(&self.confidence)
        {
            return Err(Error::InvalidClaimBody(
                "invalid carry-forward detail or confidence",
            ));
        }
        Ok(ClaimCandidate::new(
            self.kind.predicate(),
            ClaimSubject::Entity(self.subject),
            Value::from(self.detail),
            self.confidence,
        ))
    }
}

/// Shared structural validation, including replay and generic batch writes.
pub(crate) fn validate_claim(body: &ClaimBody) -> Result<()> {
    if !body.predicate.starts_with("core.carry_forward.") {
        return Ok(());
    }
    let kind = CarryForwardKind::from_predicate(&body.predicate)
        .ok_or(Error::InvalidClaimBody("unknown carry-forward kind"))?;
    if !matches!(body.subject, ClaimSubject::Entity(_))
        || body
            .value
            .as_str()
            .is_none_or(|detail| detail.trim().is_empty())
    {
        return Err(Error::InvalidClaimBody("invalid carry-forward claim shape"));
    }
    // A low-confidence claim is a proposal even on replicated replay. A local
    // Auto attempt through the generic batch door cannot bypass this check.
    if body.confidence < kind.auto_floor() && body.approval != ClaimApprovalStatus::Proposed {
        return Err(Error::InvalidClaimBody(
            "carry-forward confidence requires Proposed",
        ));
    }
    Ok(())
}

impl Vault {
    /// Write one typed forward claim through the standard envelope and Gate.
    /// Low-confidence writes are forced to Proposed; policy can still hold a
    /// high-confidence Auto request, never promote a Proposed request itself.
    ///
    /// # Errors
    /// Returns a validation, authority or Gate error on an invalid write.
    pub fn put_carry_forward_claim(
        &self,
        id: &EntityId,
        claim: CarryForwardClaim,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let held = claim.confidence < claim.kind.auto_floor();
        let candidate = claim.into_candidate()?;
        let envelope = if held {
            envelope
                .clone()
                .with_approval(ClaimApprovalStatus::Proposed)
        } else {
            envelope.clone()
        };
        self.batch()
            .claim_candidate(id, candidate, &envelope, occurred, learned_at)
            .commit()
    }
}
