//! The typed identity-topology op vocabulary (ARCH-0055 §2): merge, split,
//! facet and assert_distinct, plus the evidence and survivorship shapes their
//! callers mint.

use crate::claim::ClaimSubject;
use crate::entity_id::EntityId;

use super::reassignment_map::ReassignmentMap;
use super::wire_keys::{
    EVENT_KIND_ASSERT_DISTINCT, EVENT_KIND_FACET, EVENT_KIND_MERGE, EVENT_KIND_PROPOSAL_RESOLUTION,
    EVENT_KIND_SPLIT, EVENT_KIND_UNDO,
};

/// Evidence carried by an identity-topology op: entity refs backing the
/// decision plus the agent's stated rationale. Stored on the ledger event
/// record — receipts explain, they never gate (r3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityOpEvidence {
    /// Entities (claims, turns, mentions, …) the decision points back to.
    pub refs: Vec<EntityId>,
    /// Free-form rationale from the deciding agent or user.
    pub rationale: String,
}

/// Merge survivorship posture. Nothing is overwritten by a merge — both
/// sides' claims remain, subjects intact, read through the canonical head
/// (r1/§3) — so the only ratified plan is read-through; post-merge scalar
/// conflicts land in the existing dreamer consolidation machinery.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum SurvivorshipPlan {
    /// Keep every claim where it is; canonicalize at read time.
    #[default]
    ReadThrough,
}

/// Spec for one FACET entity a facet op mints (type-13, ARCH-0022). Minting
/// arms in ONE-1745; the vocabulary is declared here so producers and the
/// forward oracle share one shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FacetSpec {
    /// Caller-supplied facet label (runtime data, e.g. a register name).
    pub label: String,
}

/// merge(sources[], survivor, evidence, survivorship_plan) — N → 1.
#[derive(Debug, Clone, PartialEq)]
pub struct MergeOp {
    /// Losing entities; each becomes a `Merged` redirect shell.
    pub sources: Vec<EntityId>,
    /// Surviving canonical head; stays `Active`.
    pub survivor: EntityId,
    /// Decision evidence + rationale for the ledger event.
    pub evidence: IdentityOpEvidence,
    /// Survivorship posture (read-through is the only ratified plan).
    pub survivorship_plan: SurvivorshipPlan,
}

/// split(entity, heads[], reassignment_map, evidence) — 1 → N.
#[derive(Debug, Clone, PartialEq)]
pub struct SplitOp {
    /// The conflated original; becomes a `Split` redirect-to-set shell.
    pub entity: EntityId,
    /// Head entities the original resolves to. EMPTY is legal (ONE-1744
    /// lifted the MS-01 `EmptyHeads` guard): the r2 zero-head ("gone") form
    /// is a deliberate retire-without-successor, shelling the original with
    /// no successor to redirect to. It writes no `split_into` edge, so the
    /// type-76 ledger is its only witness, and it resolves to the EMPTY set
    /// through [`Vault::resolve_entity`](crate::Vault::resolve_entity).
    pub heads: Vec<EntityId>,
    /// Evidence-guided item map; recorded canonically on the event,
    /// application arms in ONE-1745.
    pub reassignment: ReassignmentMap,
    /// Decision evidence + rationale for the ledger event.
    pub evidence: IdentityOpEvidence,
}

/// facet(entity, facets[], reassignment_map, evidence) — 1 → 1×n. Touches
/// no entity ids beyond the FACET entities it mints (r6); apply path arms
/// in ONE-1745.
#[derive(Debug, Clone, PartialEq)]
pub struct FacetOp {
    /// The entity whose masks are being partitioned; stays `Active`.
    pub entity: EntityId,
    /// Specs of the FACET entities to mint.
    pub facets: Vec<FacetSpec>,
    /// Scoping map for behavioral claims; application arms in ONE-1745.
    pub reassignment: ReassignmentMap,
    /// Decision evidence + rationale for the ledger event.
    pub evidence: IdentityOpEvidence,
}

/// assert_distinct(a, b, reason) — the anti-merge claim. Conflict set is
/// the normalized symmetric pair (§9 G.1 row); claim storage and merge
/// re-proposal suppression arm in ONE-1746.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertDistinctOp {
    /// One side of the distinct pair.
    pub a: EntityId,
    /// Other side of the distinct pair.
    pub b: EntityId,
    /// Why the two are distinct (runtime data).
    pub reason: String,
}

/// Typed identity-topology op vocabulary (ARCH-0055 §2, the trio + the
/// anti-merge claim), mirroring the `AuthorityOp` house shape.
#[derive(Debug, Clone, PartialEq)]
pub enum IdentityTopologyOp {
    /// Different records, same referent.
    Merge(MergeOp),
    /// One record, different referents.
    Split(SplitOp),
    /// Same referent, different masks — the "soft split".
    Facet(FacetOp),
    /// Suppresses future merge proposals for the pair; trains the matcher.
    AssertDistinct(AssertDistinctOp),
}

impl IdentityTopologyOp {
    /// Every pre-existing entity the op names, in role order. Facet specs
    /// are not entities yet (minting is the op's own effect), so a facet op
    /// names only its base entity.
    #[must_use]
    pub fn participants(&self) -> Vec<EntityId> {
        match self {
            Self::Merge(op) => {
                let mut ids = op.sources.clone();
                ids.push(op.survivor);
                ids
            }
            Self::Split(op) => {
                let mut ids = vec![op.entity];
                ids.extend(op.heads.iter().copied());
                ids
            }
            Self::Facet(op) => vec![op.entity],
            Self::AssertDistinct(op) => vec![op.a, op.b],
        }
    }

    /// Ids that are NOT participants but whose later materialization changes
    /// what a reconcile replay of this op records (ONE-1745).
    ///
    /// A reassignment row records only when this vault already holds the
    /// CLAIM it names — that is deliberate (r2 lets a decision name an item
    /// a peer does not have), which is exactly why a mapped claim can arrive
    /// AFTER the event that maps it. Split rows are re-derived from the fold
    /// at the reconcile door, so the arriving claim has to wake that door or
    /// the projection diverges by delivery order alone: claim-before-event
    /// records the row, event-before-claim never does.
    ///
    /// Split only. A facet assignment's witness is its canonical `facet_of`
    /// edge, which replicates as an ordinary edge and is derived by no
    /// reconcile pass — there is nothing here for a trigger to re-run.
    /// A map item is never a participant: participants must exist and be
    /// `Active` at the door, and a map item must not.
    pub(crate) fn deferred_reassignment_items(&self) -> Vec<EntityId> {
        match self {
            Self::Split(op) => op
                .reassignment
                .entries
                .iter()
                .filter_map(|entry| match entry.item {
                    ClaimSubject::Entity(item) => Some(item),
                    ClaimSubject::Edge { .. } => None,
                })
                .collect(),
            Self::Merge(_) | Self::Facet(_) | Self::AssertDistinct(_) => Vec::new(),
        }
    }
}

/// Whether `op_kind` names an event kind of THIS family.
///
/// The one place the family's wire vocabulary is enumerated for outside
/// consumers. ONE-1748's consent-graduation ramp asks it to answer the r7 §5
/// boundary: identity-topology ops carry their own per-write consent axis and
/// are auto day one, so they never sit on the propose→auto ramp. Keeping the
/// enumeration here means adding an op kind cannot silently make it
/// graduatable.
pub(crate) fn is_identity_topology_op_kind(op_kind: &str) -> bool {
    matches!(
        op_kind,
        EVENT_KIND_MERGE
            | EVENT_KIND_SPLIT
            | EVENT_KIND_FACET
            | EVENT_KIND_ASSERT_DISTINCT
            | EVENT_KIND_UNDO
            | EVENT_KIND_PROPOSAL_RESOLUTION
    )
}
