//! The (state, op) transition table and the deterministic rejection taxonomy
//! it speaks, plus the proposal ruling/outcome/scope vocabulary the resolution
//! door rules with.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

use super::lifecycle_state::EntityLifecycleState;
use super::op_vocabulary::IdentityTopologyOp;
use super::reassignment_map::{ReassignmentTarget, encode_reassignment_item};

/// The ruling a decider applies to a parked `Proposed` identity-topology
/// event (ARCH-0055 r7 outcome vocabulary).
///
/// `AmendThenApprove` carries the amended op body as encoded bytes — the
/// form the decider actually approved, which is what gets applied and what
/// the outcome receipt preserves verbatim. The amendment NARROWS what the
/// owner reviewed: it can never become a different op kind nor reach an
/// entity the proposal did not name
/// ([`SyncError::IdentityProposalAmendmentOutOfScope`](crate::error::SyncError::IdentityProposalAmendmentOutOfScope)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalRuling<'a> {
    /// Apply exactly as proposed.
    Approve,
    /// Apply the amended body instead of the proposed one.
    AmendThenApprove(&'a [u8]),
    /// Retire the park with zero topology effects.
    Reject,
}

/// Resolved-proposal outcome — exactly three states (r7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProposalOutcome {
    /// Approved as proposed; the proposed op applied unchanged.
    ApprovedUntouched,
    /// Approved after amendment; the AMENDED op applied.
    ApprovedAmended,
    /// Rejected; nothing applied, the park retired.
    Rejected,
}

impl ProposalOutcome {
    /// The pinned wire/receipt string for this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApprovedUntouched => "approved_untouched",
            Self::ApprovedAmended => "approved_amended",
            Self::Rejected => "rejected",
        }
    }

    /// Parses a pinned outcome string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "approved_untouched" => Some(Self::ApprovedUntouched),
            "approved_amended" => Some(Self::ApprovedAmended),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }

    /// Whether the ruling applied an op (either form).
    #[must_use]
    pub const fn is_approved(self) -> bool {
        matches!(self, Self::ApprovedUntouched | Self::ApprovedAmended)
    }
}

/// The DEC-0006 consent-ramp scope tuple stamped on a proposal-outcome
/// receipt: (op kind × target class × actor).
///
/// Stamped from the RESOLVED proposal at resolution time, not dereferenced
/// later: MS-06 (ONE-1748) rebuilds per-scope ramp statistics from receipts
/// ALONE, so a receipt that required a ledger join to name its own scope
/// could not satisfy that contract. Stamping also records the scope AS
/// RULED — a later topology change cannot retroactively re-key history.
///
/// `actor` is the PROPOSING actor (whose autonomy the ramp measures), which
/// is a different question from who ruled — the decider lands on the
/// resolution event's own actor field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalScope {
    /// The proposed op's wire kind (`merge` / `split`).
    pub op_kind: &'static str,
    /// Registry kind name of the op's primary target entity (the merge
    /// survivor / the split original), e.g. `"PERSON"`.
    pub target_class: String,
    /// The proposing actor's entity ref in hex, or
    /// [`PROPOSAL_SCOPE_ACTOR_UNATTRIBUTED`](super::PROPOSAL_SCOPE_ACTOR_UNATTRIBUTED) when the proposal bound none.
    pub actor: String,
}

// ─── Transition table ───────────────────────────────────────────────────────

pub use oneiron_contracts::identity_topology::IdentityTopologyRejection;

/// Full (state, op) transition table over entity lifecycle × op role,
/// evaluated against the caller's folded states (absent entity = `Active`).
/// Returns the state assignments the op performs; participants it validates
/// but does not move (merge survivor, split heads, facet base,
/// assert_distinct pair) are absent from the result.
///
/// Check order is pinned: op shape (empty / self / duplicate), then
/// per-role state cells, then reassignment-map item uniqueness and targets.
pub fn evaluate_transition(
    states: &BTreeMap<EntityId, EntityLifecycleState>,
    op: &IdentityTopologyOp,
) -> std::result::Result<Vec<(EntityId, EntityLifecycleState)>, IdentityTopologyRejection> {
    let state_of = |entity: &EntityId| {
        states
            .get(entity)
            .copied()
            .unwrap_or(EntityLifecycleState::Active)
    };
    let require_active = |entity: &EntityId| match state_of(entity) {
        EntityLifecycleState::Active => Ok(()),
        state => Err(IdentityTopologyRejection::NotActive {
            entity: *entity,
            state,
        }),
    };

    match op {
        IdentityTopologyOp::Merge(merge) => {
            if merge.sources.is_empty() {
                return Err(IdentityTopologyRejection::EmptySources);
            }
            let mut seen = BTreeSet::new();
            for source in &merge.sources {
                if !seen.insert(*source) {
                    return Err(IdentityTopologyRejection::DuplicateParticipant {
                        entity: *source,
                    });
                }
            }
            if seen.contains(&merge.survivor) {
                return Err(IdentityTopologyRejection::SelfReference {
                    entity: merge.survivor,
                });
            }
            require_active(&merge.survivor)?;
            let mut transitions = Vec::with_capacity(merge.sources.len());
            for source in &merge.sources {
                require_active(source)?;
                transitions.push((*source, EntityLifecycleState::Merged));
            }
            Ok(transitions)
        }
        IdentityTopologyOp::Split(split) => {
            // ONE-1744 lifted the zero-head guard: `heads: []` is the r2
            // "gone" form — a deliberate retire-without-successor. It shells
            // the original like any split, writes NO `split_into` edge (there
            // is no head to point at), and resolves to the empty set through
            // the redirect projection.
            let mut seen = BTreeSet::new();
            for head in &split.heads {
                if !seen.insert(*head) {
                    return Err(IdentityTopologyRejection::DuplicateParticipant { entity: *head });
                }
            }
            if seen.contains(&split.entity) {
                return Err(IdentityTopologyRejection::SelfReference {
                    entity: split.entity,
                });
            }
            require_active(&split.entity)?;
            for head in &split.heads {
                require_active(head)?;
            }
            let mut seen_items = BTreeSet::new();
            for entry in &split.reassignment.entries {
                if !seen_items.insert(encode_reassignment_item(&entry.item)) {
                    return Err(IdentityTopologyRejection::DuplicateReassignmentItem);
                }
                match entry.target {
                    ReassignmentTarget::Head(head) => {
                        if !split.heads.contains(&head) {
                            return Err(IdentityTopologyRejection::UnknownHead { head });
                        }
                    }
                    ReassignmentTarget::Facet { .. } => {
                        return Err(IdentityTopologyRejection::InvalidReassignmentTarget);
                    }
                    ReassignmentTarget::Residue => {}
                }
            }
            Ok(vec![(split.entity, EntityLifecycleState::Split)])
        }
        IdentityTopologyOp::Facet(facet) => {
            if facet.facets.is_empty() {
                return Err(IdentityTopologyRejection::EmptyFacets);
            }
            require_active(&facet.entity)?;
            let facet_count = facet.facets.len() as u32;
            let mut seen_items = BTreeSet::new();
            for entry in &facet.reassignment.entries {
                if !seen_items.insert(encode_reassignment_item(&entry.item)) {
                    return Err(IdentityTopologyRejection::DuplicateReassignmentItem);
                }
                match entry.target {
                    ReassignmentTarget::Facet { index } => {
                        if index >= facet_count {
                            return Err(IdentityTopologyRejection::UnknownFacet { index });
                        }
                    }
                    ReassignmentTarget::Head(_) => {
                        return Err(IdentityTopologyRejection::InvalidReassignmentTarget);
                    }
                    ReassignmentTarget::Residue => {}
                }
            }
            // Facet ops touch no entity ids (r6): the base stays Active.
            Ok(Vec::new())
        }
        IdentityTopologyOp::AssertDistinct(distinct) => {
            if distinct.a == distinct.b {
                return Err(IdentityTopologyRejection::SelfReference { entity: distinct.a });
            }
            require_active(&distinct.a)?;
            require_active(&distinct.b)?;
            Ok(Vec::new())
        }
    }
}
