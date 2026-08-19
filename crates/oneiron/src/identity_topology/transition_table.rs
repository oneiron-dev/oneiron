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
/// ([`Error::IdentityProposalAmendmentOutOfScope`](crate::error::Error::IdentityProposalAmendmentOutOfScope)).
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

/// Deterministic per-op rejection reason — the
/// `FederationLifecycleRejection` analogue for this family. Shape and
/// state cells come from [`evaluate_transition`]; the storage cells
/// (`FacetMerge`, `NotStructural`) from the vault apply door; the ledger
/// cells (`NotCurrent`, `NotUndoable`) from undo evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityTopologyRejection {
    /// merge names zero sources.
    EmptySources,
    /// facet names zero facet specs.
    EmptyFacets,
    /// An op names one entity on both sides (survivor among sources, the
    /// split original among its heads, `assert_distinct(a, a)`).
    SelfReference {
        /// The self-referenced entity.
        entity: EntityId,
    },
    /// An op names the same participant twice in one role.
    DuplicateParticipant {
        /// The duplicated entity.
        entity: EntityId,
    },
    /// The (state, op) cell requires an `Active` participant. This is also
    /// the merge-a-shell answer: following the redirect silently would
    /// record an op the caller never stated — resolution through the
    /// redirect projection is a read-time concern (r6), the ledger stays
    /// explicit.
    NotActive {
        /// The shell participant.
        entity: EntityId,
        /// Its current lifecycle state.
        state: EntityLifecycleState,
    },
    /// A reassignment row targets a head the split op does not name.
    UnknownHead {
        /// The foreign head.
        head: EntityId,
    },
    /// A reassignment row targets a facet index out of the op's range.
    UnknownFacet {
        /// The out-of-range index.
        index: u32,
    },
    /// A reassignment row uses a target kind foreign to the op (a facet
    /// target on a split, a head target on a facet).
    InvalidReassignmentTarget,
    /// A reassignment map names the same item twice. The map is
    /// single-valued per item (r2): recording two assignments for one
    /// claim would force ONE-1745's replay to duplicate the claim or pick
    /// a winner the decision never stated.
    DuplicateReassignmentItem,
    /// A merge participant is a FACET mask: facets partition within one
    /// entity and behavioral profiles never blend across masks
    /// (ARCH-0022 no-merge canon; ARCH-0055 §5 catches this by construction).
    FacetMerge {
        /// The FACET-typed participant.
        entity: EntityId,
    },
    /// A participant's type byte is not a StructuralKind: claims have their
    /// own supersession lifecycle (D11) and maintenance records their own
    /// substrate doors — identity topology operates on entities.
    NotStructural {
        /// The non-structural participant.
        entity: EntityId,
    },
    /// A PROPOSED merge names a pair an effective `entity.distinct_from`
    /// claim already covers (ARCH-0055 §6, ONE-1746). Rejections route, they
    /// do not dead-end into re-asks: the claim suppresses agent re-proposal
    /// only — an `Auto`/`Approved` merge the owner ruled on is never blocked,
    /// and superseding or retracting the claim lifts the suppression.
    DistinctPairSuppressed {
        /// Lexicographically-first side of the covered pair.
        a: EntityId,
        /// Lexicographically-last side of the covered pair.
        b: EntityId,
    },
    /// undo names an event that is not the current topology writer for its
    /// entities (already undone, superseded by a later re-apply, parked, or
    /// never applied).
    NotCurrent {
        /// The named event.
        event: EntityId,
    },
    /// undo names an event kind that cannot be undone (a counter-event, a
    /// proposal resolution, or an op family whose apply path is not armed
    /// yet).
    NotUndoable {
        /// The named event.
        event: EntityId,
    },
    /// A ruling names an event that is not a parked `Proposed` op (r7): an
    /// already-effective event, a counter-event, or another resolution.
    /// Only a park can be resolved.
    NotProposed {
        /// The named event.
        event: EntityId,
    },
    /// A ruling names a proposal a resolution event already retired (r7).
    /// The park retires exactly once — a second ruling would record two
    /// contradictory decisions about one review.
    ProposalAlreadyResolved {
        /// The already-resolved proposal.
        proposal: EntityId,
    },
    /// A ruling was submitted under a non-effective consent axis
    /// (`Proposed` / `Rejected`). A ruling IS the act of deciding: parking
    /// it would leave the proposal open behind a row claiming to resolve
    /// it, and the consent no-op has no outcome to report.
    ProposalRulingNotEffective,
    /// An amended body left the reviewed proposal's scope: a different op
    /// kind, or a subject the proposal never named. An amendment NARROWS
    /// what the owner reviewed — it is never an op-substitution capability.
    AmendmentOutOfScope {
        /// Which scope bound the amendment broke.
        reason: &'static str,
    },
    /// A resolution event lies about what it rules: the park it retires is
    /// not `Proposed`, or its stamped ramp scope is not the tuple the
    /// proposal's own row derives. Local rulings can never produce either
    /// (the door derives both at ruling time); they are how a MALFORMED
    /// replicated resolution row reads.
    ResolutionRuleMismatch {
        /// Which rule the row broke.
        reason: &'static str,
    },
}

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
