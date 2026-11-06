//! Confidence-gated forward commitments, separate from belief consolidation and the commitment ledger.
//!
//! The four kinds are the stable vocabulary; this module's predicates and
//! string payload are deliberately small implementation choices, not canon ABI.

use rmpv::Value;

use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::claim_body::{ClaimBody, ClaimSubject};
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::error::{Error, Result};

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
pub fn validate_claim(body: &ClaimBody) -> Result<()> {
    if !body.predicate.starts_with("core.carry_forward.") {
        return Ok(());
    }
    CarryForwardKind::from_predicate(&body.predicate)
        .ok_or(Error::InvalidClaimBody("unknown carry-forward kind"))?;
    if !matches!(body.subject, ClaimSubject::Entity(_))
        || body
            .value
            .as_str()
            .is_none_or(|detail| detail.trim().is_empty())
    {
        return Err(Error::InvalidClaimBody("invalid carry-forward claim shape"));
    }
    // Confidence is an ADMISSION floor, not a storage shape: later owner
    // resolution and monotonic demotion may change approval or confidence.
    Ok(())
}

/// The actor a stored claim's evidence names, when it names one.
pub fn actor_from_evidence(evidence: &Value) -> Option<EntityId> {
    let Value::Map(entries) = evidence else {
        return None;
    };
    let Value::Binary(bytes) = entries
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some("actor_entity_ref")).then_some(value))?
    else {
        return None;
    };
    EntityId::from_bytes(bytes.as_slice().try_into().ok()?).ok()
}
