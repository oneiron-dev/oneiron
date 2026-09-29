//! Deterministic causal fold. No wall clock, LWW ordering, or mutable birth body.

use std::collections::{BTreeMap, BTreeSet};

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimDemotionRung, ClaimLifecycleStatus, ClaimSubject,
};
use crate::entity_id::EntityId;

use super::event::{
    ClaimTransitionKind, SignedClaimTransitionEvent, TransitionDelta, TransitionEventHash,
    machine_claim_transition_event_hash, verify_machine_claim_transition_event,
};

const MAX_EVENTS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransitionFoldError {
    InvalidBirth,
    InvalidEvent,
    Unauthorized,
    MissingHistory,
    FrontierMismatch,
    IncompatibleFork,
    Rollback,
}

/// Born content and provenance remain intact; the other fields are an effective
/// restrictive view of the closed transition history. The original `scope` is
/// never edited: `scope_band_floor` is an additional read-time restriction.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ClaimTransitionProjection {
    pub birth: ClaimBody,
    pub approval: ClaimApprovalStatus,
    pub lifecycle: ClaimLifecycleStatus,
    pub confidence: f32,
    pub claim_of_weight: Option<f32>,
    pub demotion_rung: Option<ClaimDemotionRung>,
    pub valid_to: Option<u64>,
    pub stale: bool,
    pub scope_band_floor: Option<u8>,
    /// The actor whose signed `SupersedeClose` ended the history.
    pub superseded_by: Option<EntityId>,
    pub frontier: Vec<TransitionEventHash>,
}

impl ClaimTransitionProjection {
    fn initial(
        body: &ClaimBody,
        initial_claim_of_weight: Option<f32>,
    ) -> Result<Self, TransitionFoldError> {
        if initial_claim_of_weight
            .is_some_and(|weight| !weight.is_finite() || !(0.0..=1.0).contains(&weight))
            || (initial_claim_of_weight.is_some()
                && !matches!(body.subject, ClaimSubject::Entity(_)))
            || !body.confidence.is_finite()
            || !(0.0..=1.0).contains(&body.confidence)
            || body
                .valid_from
                .zip(body.valid_to)
                .is_some_and(|(start, end)| start > end)
            || body.stale
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.approval == ClaimApprovalStatus::Rejected
        {
            return Err(TransitionFoldError::InvalidBirth);
        }
        Ok(Self {
            birth: body.clone(),
            approval: body.approval,
            lifecycle: body.lifecycle,
            confidence: body.confidence,
            claim_of_weight: initial_claim_of_weight,
            demotion_rung: None,
            valid_to: body.valid_to,
            stale: false,
            scope_band_floor: None,
            superseded_by: None,
            frontier: Vec::new(),
        })
    }

    /// Whether the signed history has ended, so no further transition applies.
    pub(crate) fn is_closed(&self) -> bool {
        self.lifecycle != ClaimLifecycleStatus::Active
            || self.approval == ClaimApprovalStatus::Rejected
    }

    /// Whether a same-id successor row by `author` owns the live claim: its
    /// author ended this history with a signed `SupersedeClose`. A retracted
    /// or rejected history never becomes an ordinary claim.
    pub(crate) fn admits_successor_by(&self, author: Option<EntityId>) -> bool {
        self.lifecycle == ClaimLifecycleStatus::Superseded
            && author.is_some()
            && self.superseded_by == author
    }

    fn join(&mut self, other: &Self) -> Result<(), TransitionFoldError> {
        if self.birth != other.birth {
            return Err(TransitionFoldError::IncompatibleFork);
        }
        self.approval = match (self.approval, other.approval) {
            (a, b) if a == b => a,
            (ClaimApprovalStatus::Proposed, b) => b,
            (a, ClaimApprovalStatus::Proposed) => a,
            // Reject and approve on separate branches cannot be resolved by
            // incidental order, even when rejection would hide more content.
            _ => return Err(TransitionFoldError::IncompatibleFork),
        };
        self.lifecycle = match (self.lifecycle, other.lifecycle) {
            (a, b) if a == b => a,
            (ClaimLifecycleStatus::Active, b) => b,
            (a, ClaimLifecycleStatus::Active) => a,
            _ => return Err(TransitionFoldError::IncompatibleFork),
        };
        self.confidence = self.confidence.min(other.confidence);
        self.claim_of_weight = match (self.claim_of_weight, other.claim_of_weight) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (None, None) => None,
            _ => return Err(TransitionFoldError::IncompatibleFork),
        };
        self.demotion_rung = self.demotion_rung.max(other.demotion_rung);
        self.valid_to = match (self.valid_to, other.valid_to) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a @ Some(_), None) | (None, a @ Some(_)) => a,
            (None, None) => None,
        };
        self.stale |= other.stale;
        self.scope_band_floor = self.scope_band_floor.max(other.scope_band_floor);
        // Concurrent closes by two actors settle on one, independent of order.
        self.superseded_by = match (self.superseded_by, other.superseded_by) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        Ok(())
    }

    fn apply(&mut self, event: &SignedClaimTransitionEvent) -> Result<(), TransitionFoldError> {
        use ClaimApprovalStatus::{Approved, Auto, Proposed, Rejected};
        use ClaimLifecycleStatus::{Active, Retracted, Superseded};
        if self.lifecycle != Active || self.approval == Rejected {
            return Err(TransitionFoldError::Rollback);
        }
        match (event.kind, event.delta) {
            (ClaimTransitionKind::Approve, TransitionDelta::None) if self.approval == Proposed => {
                // The MACHINE author's own Approve is the Gate's deferred Auto
                // grant of its proposal; any other actor's is an approval.
                let own_grant = event.actor_class == crate::edge::EdgeActorClass::System
                    && crate::memory::claim_author(&self.birth) == Some(event.actor);
                self.approval = if own_grant { Auto } else { Approved };
            }
            (ClaimTransitionKind::Reject, TransitionDelta::None)
                if matches!(self.approval, Proposed | Approved | Auto) =>
            {
                self.approval = Rejected;
            }
            (ClaimTransitionKind::Retract, TransitionDelta::ValidTo(end))
            | (ClaimTransitionKind::SupersedeClose, TransitionDelta::ValidTo(end)) => {
                // A Proposed claim closes like any other: ARCH-0040 defers a
                // destructive supersede on the superseding write's approval,
                // which the deferred-closure grant settles before staging.
                if self.birth.valid_from.is_some_and(|start| end < start)
                    || self.valid_to.is_some_and(|old| end > old)
                {
                    return Err(TransitionFoldError::Rollback);
                }
                self.valid_to = Some(end);
                self.lifecycle = if event.kind == ClaimTransitionKind::Retract {
                    Retracted
                } else {
                    self.superseded_by = Some(event.actor);
                    Superseded
                };
            }
            (ClaimTransitionKind::Decay, TransitionDelta::ClaimOfWeight(weight)) => {
                if !weight.is_finite()
                    || !(0.0..=1.0).contains(&weight)
                    || self.demotion_rung.is_some()
                    || self.claim_of_weight.is_none_or(|old| weight >= old)
                {
                    return Err(TransitionFoldError::Rollback);
                }
                self.claim_of_weight = Some(weight);
                self.demotion_rung = Some(ClaimDemotionRung::Decayed);
            }
            (ClaimTransitionKind::Weaken, TransitionDelta::Confidence(confidence)) => {
                if !matches!(
                    self.demotion_rung,
                    Some(ClaimDemotionRung::Decayed | ClaimDemotionRung::Weakened)
                ) || !confidence.is_finite()
                    || !(0.0..=1.0).contains(&confidence)
                    || confidence >= self.confidence
                {
                    return Err(TransitionFoldError::Rollback);
                }
                self.confidence = confidence;
                self.demotion_rung = Some(ClaimDemotionRung::Weakened);
            }
            (ClaimTransitionKind::Stale, TransitionDelta::None)
                if !self.stale && self.demotion_rung == Some(ClaimDemotionRung::Weakened) =>
            {
                self.stale = true;
                self.demotion_rung = Some(ClaimDemotionRung::Stale);
            }
            (ClaimTransitionKind::Stale, TransitionDelta::ScopeBand(band))
                if !self.stale && self.demotion_rung == Some(ClaimDemotionRung::Weakened) =>
            {
                // The source scope stays unchanged. The read surface applies
                // max(original band, effective floor) and must fail closed on
                // malformed or ambiguous original bands.
                let original = crate::claim::claim_sensitivity_band(&self.birth)
                    .ok_or(TransitionFoldError::InvalidBirth)?;
                if band > 3
                    || band < original
                    || self.scope_band_floor.is_some_and(|floor| band < floor)
                {
                    return Err(TransitionFoldError::Rollback);
                }
                self.scope_band_floor = Some(band);
                self.stale = true;
                self.demotion_rung = Some(ClaimDemotionRung::Stale);
            }
            _ => return Err(TransitionFoldError::Rollback),
        }
        Ok(())
    }
}

/// Folds an exact pinned closure of transition events. The caller must bind
/// `birth_digest` to a verified birth, supply the COMPLETE expected tip hashes
/// from its trusted closure/handoff pin, and check historical host enrollment,
/// actor binding/class and permission at EACH event's `authority_head` in
/// `authorized`. No current-roster or timestamp shortcut is allowed.
///
/// Input order has no meaning. Missing parents and omitted tips fail closed.
/// An authorized signature alone does not grant a transition kind.
#[expect(
    clippy::too_many_arguments,
    reason = "pure fold needs birth, pinned identity/closure, and historical authority callback as separate axes"
)]
pub(crate) fn fold_machine_claim_transitions(
    birth: &ClaimBody,
    vault_id: &[u8; 32],
    target: EntityId,
    birth_digest: &[u8; 32],
    initial_claim_of_weight: Option<f32>,
    events: &[SignedClaimTransitionEvent],
    pinned_frontier: &[TransitionEventHash],
    mut authorized: impl FnMut(&SignedClaimTransitionEvent) -> bool,
) -> Result<ClaimTransitionProjection, TransitionFoldError> {
    let base = ClaimTransitionProjection::initial(birth, initial_claim_of_weight)?;
    if events.len() > MAX_EVENTS
        || *vault_id == [0; 32]
        || *birth_digest == [0; 32]
        || pinned_frontier.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(TransitionFoldError::InvalidEvent);
    }
    let mut pending = BTreeMap::new();
    for event in events {
        if event.vault_id != *vault_id
            || event.target != target
            || event.birth_digest != *birth_digest
        {
            return Err(TransitionFoldError::InvalidEvent);
        }
        verify_machine_claim_transition_event(event)
            .map_err(|_| TransitionFoldError::InvalidEvent)?;
        if !authorized(event) {
            return Err(TransitionFoldError::Unauthorized);
        }
        let hash = machine_claim_transition_event_hash(event)
            .map_err(|_| TransitionFoldError::InvalidEvent)?;
        if pending.insert(hash, event).is_some() {
            return Err(TransitionFoldError::InvalidEvent);
        }
    }
    let mut tips: BTreeSet<TransitionEventHash> = pending.keys().copied().collect();
    for event in pending.values() {
        for parent in &event.predecessors {
            if !pending.contains_key(parent) {
                return Err(TransitionFoldError::MissingHistory);
            }
            tips.remove(parent);
        }
    }
    if tips.iter().copied().collect::<Vec<_>>() != pinned_frontier {
        return Err(TransitionFoldError::FrontierMismatch);
    }
    let mut states: BTreeMap<TransitionEventHash, ClaimTransitionProjection> = BTreeMap::new();
    while !pending.is_empty() {
        let Some(hash) = pending
            .iter()
            .find(|(_, event)| {
                event
                    .predecessors
                    .iter()
                    .all(|parent| states.contains_key(parent))
            })
            .map(|(hash, _)| *hash)
        else {
            return Err(TransitionFoldError::MissingHistory);
        };
        let event = pending
            .remove(&hash)
            .ok_or(TransitionFoldError::MissingHistory)?;
        let mut state = base.clone();
        for parent in &event.predecessors {
            state.join(&states[parent])?;
        }
        state.apply(event)?;
        states.insert(hash, state);
    }
    let mut result = base;
    for tip in &tips {
        result.join(&states[tip])?;
    }
    result.frontier = tips.into_iter().collect();
    Ok(result)
}
