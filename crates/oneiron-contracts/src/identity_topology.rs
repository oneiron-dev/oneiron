//! Identity-topology lifecycle states and per-op rejections: the values the topology
//! ledger, the sync replay door and `Error` share. `oneiron::identity_topology`
//! re-exports both next to the ledger and transition table.

use crate::entity_id::EntityId;

/// Entity lifecycle state derived from the identity-topology op log.
///
/// `Merged` / `Split` are REDIRECT-SHELL states, not tombstones: the entity
/// body stays fully readable forever and no `TombstoneReason` exists for
/// them (merge-away is not deletion — ARCH-0055 §10 vs ARCH-0038).
///
/// The derive order is the pinned CRDT join precedence
/// (`Active < Merged < Split`); see `oneiron::identity_topology::merge_lifecycle_states`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntityLifecycleState {
    /// Live identity — the default; every op may target it.
    Active,
    /// Redirect shell left behind by a merge (r1): resolves to exactly one
    /// surviving head through the `merged_into` edge.
    Merged,
    /// Redirect shell left behind by a split (r2): resolves to its head SET
    /// through `split_into` edges (Senzing 0/1/N stable-id semantics).
    Split,
}

impl EntityLifecycleState {
    /// The pinned on-disk / wire string for this state.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Merged => "merged",
            Self::Split => "split",
        }
    }

    /// Parses the pinned wire string back into a state.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "merged" => Some(Self::Merged),
            "split" => Some(Self::Split),
            _ => None,
        }
    }

    /// `true` for the redirect-shell states (`Merged` / `Split`).
    #[must_use]
    pub const fn is_redirect_shell(self) -> bool {
        matches!(self, Self::Merged | Self::Split)
    }

    /// Legal DIRECT transitions (the `ChannelIdentityState` house shape):
    /// `Active → Merged` (merge source), `Active → Split` (split original),
    /// and each shell back to `Active` (undo counter-event). Shells never
    /// transition into each other without passing through `Active` — an
    /// undo-then-reapply, both on the ledger. `evaluate_transition` and
    /// the fold's undo arm produce exactly these moves.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Active, Self::Merged)
                | (Self::Active, Self::Split)
                | (Self::Merged, Self::Active)
                | (Self::Split, Self::Active)
        )
    }
}

/// Deterministic per-op rejection reason — the
/// `FederationLifecycleRejection` analogue for this family. Shape and
/// state cells come from `evaluate_transition`; the storage cells
/// (`FacetMerge`, `NotStructural`) from the vault apply door; the ledger
/// cells (`NotCurrent`, `NotUndoable`) from undo evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityTopologyRejection {
    /// Deletion of a current merge source or survivor requires undo first.
    ActiveMergeParticipantDeletion {
        /// The protected participant.
        entity: EntityId,
    },
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
