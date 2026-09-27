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
pub(crate) fn validate_claim(body: &ClaimBody) -> Result<()> {
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

/// Enforce the floor on local put admission. Replay validates the claim shape,
/// but receives final CRDT heads without their local transition history. A
/// locally authored below-floor Auto head must follow a monotonic demotion or
/// an exact lifecycle closure; new generic/raw Auto claims are refused.
pub(crate) fn validate_admission(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    envelope: Option<&WriteEnvelope>,
) -> Result<()> {
    let Some(kind) = CarryForwardKind::from_predicate(&body.predicate) else {
        return Ok(());
    };
    let prior = prior_claim(store, txn, id)?;
    let actor = envelope
        .map(|envelope| envelope.actor().entity_ref())
        .or_else(|| {
            prior
                .as_ref()
                .and_then(|prior| prior.evidence.as_ref())
                .and_then(actor_from_evidence)
        });
    let policy = crate::gate::resolve_policy_manifest(store, txn)?;
    if body.confidence >= policy.carry_forward_floor(kind, actor)
        || body.approval == ClaimApprovalStatus::Proposed
    {
        return Ok(());
    }
    let valid = match body.approval {
        ClaimApprovalStatus::Auto => prior
            .as_ref()
            .is_some_and(|prior| valid_auto_transition(prior, body)),
        ClaimApprovalStatus::Approved => prior.as_ref().is_some_and(|prior| {
            matches!(
                prior.approval,
                ClaimApprovalStatus::Proposed | ClaimApprovalStatus::Approved
            ) && prior.predicate == body.predicate
                && prior.subject == body.subject
        }),
        ClaimApprovalStatus::Rejected => prior.as_ref().is_some_and(|prior| {
            matches!(
                prior.approval,
                ClaimApprovalStatus::Proposed | ClaimApprovalStatus::Rejected
            ) && prior.predicate == body.predicate
                && prior.subject == body.subject
                && body.lifecycle == crate::claim::ClaimLifecycleStatus::Retracted
        }),
        ClaimApprovalStatus::Proposed => true,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidClaimBody(
            "carry-forward confidence requires a proposal or bound lifecycle transition",
        ))
    }
}

/// The Gate can preserve a prior Auto head for exact confidence weakening or
/// lifecycle closure, without treating either as a new automatic admission.
pub(crate) fn allows_auto_demotion(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
) -> Result<bool> {
    Ok(prior_claim(store, txn, id)?
        .as_ref()
        .is_some_and(|prior| valid_auto_transition(prior, body)))
}

fn actor_from_evidence(evidence: &Value) -> Option<EntityId> {
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

fn prior_claim(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<ClaimBody>> {
    use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("carry-forward prior header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true).map(Some)
}

/// Match canonical demotion deltas or the exact terminal lifecycle closure.
/// A raw caller cannot create a new low-confidence Auto head by stamping a rung.
fn valid_auto_transition(prior: &ClaimBody, next: &ClaimBody) -> bool {
    use crate::claim::{CLAIM_SCOPE_DEMOTION_RUNG_KEY, ClaimDemotionRung, claim_demotion_rung};
    if prior.approval != ClaimApprovalStatus::Auto
        || prior.lifecycle != crate::claim::ClaimLifecycleStatus::Active
        || next.confidence > prior.confidence
    {
        return false;
    }
    if matches!(
        next.lifecycle,
        crate::claim::ClaimLifecycleStatus::Retracted
            | crate::claim::ClaimLifecycleStatus::Superseded
    ) && let Some(valid_to) = next.valid_to
    {
        let mut expected = prior.clone();
        expected.lifecycle = next.lifecycle;
        expected.valid_to = Some(valid_to);
        return expected == *next;
    }
    let Ok(before) = claim_demotion_rung(prior) else {
        return false;
    };
    let Ok(after) = claim_demotion_rung(next) else {
        return false;
    };
    let mut expected = prior.clone();
    let rung = match (before, after) {
        (
            Some(ClaimDemotionRung::Decayed | ClaimDemotionRung::Weakened),
            Some(ClaimDemotionRung::Weakened),
        ) => {
            expected.confidence = next.confidence;
            "weakened"
        }
        (Some(ClaimDemotionRung::Weakened), Some(ClaimDemotionRung::Stale)) => {
            expected.stale = true;
            "stale"
        }
        _ => return prior == next, // idempotent same-body replay only
    };
    let mut scope = match expected.scope.take() {
        Some(Value::Map(entries)) => entries,
        _ => return false,
    };
    scope.retain(|(key, _)| key.as_str() != Some(CLAIM_SCOPE_DEMOTION_RUNG_KEY));
    scope.push((
        Value::from(CLAIM_SCOPE_DEMOTION_RUNG_KEY),
        Value::from(rung),
    ));
    expected.scope = Some(Value::Map(scope));
    expected == *next
}

impl Vault {
    /// Write one typed forward claim through the standard envelope and Gate.
    /// Low-confidence Auto requests are forced to Proposed. An explicit
    /// approval or rejection is not silently rewritten; the existing claim
    /// lifecycle and its authenticated consent door must authorize it.
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
        if !matches!(
            envelope.approval(),
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Proposed
        ) {
            return Err(Error::InvalidClaimBody(
                "carry-forward consent must use the authenticated resolution door",
            ));
        }
        let candidate = claim.clone().into_candidate()?;
        self.with_write_txn(|txn| {
            let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
            let held = claim.confidence
                < policy.carry_forward_floor(claim.kind, Some(envelope.actor().entity_ref()));
            let envelope = if held && envelope.approval() == ClaimApprovalStatus::Auto {
                envelope
                    .clone()
                    .with_approval(ClaimApprovalStatus::Proposed)
            } else {
                envelope.clone()
            };
            self.batch_in()
                .claim_candidate(id, candidate, &envelope, occurred, learned_at)
                .apply_recording_gate_decisions(txn)
        })
    }
}
