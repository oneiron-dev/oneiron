//! ARCH-0055 identity-topology op family: merge / split / facet /
//! assert_distinct as typed ops over an append-only event ledger.
//!
//! The shape mirrors the ONE-1408 authority-op house style: a typed op enum
//! ([`IdentityTopologyOp`]), a full (state, op) transition table evaluated as
//! a deterministic fold over the op log ([`evaluate_transition`] /
//! [`fold_identity_topology_log`]), and a fixed CRDT precedence for
//! concurrent state joins ([`merge_lifecycle_states`]).
//!
//! Structural truth follows the D11 supersedes law: `merged_into` /
//! `split_into` edges are canonical and carry no body-field twin, and their
//! writes are RESERVED to this module's apply/undo door (public edge
//! builders — creation, deletion, AND the operational weight/VAD setters —
//! reject them typed; sync edge doors admit a 21/22 row only when the
//! local validated ledger mandates it). The ledger events are
//! engine-authored type-76
//! [`crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT`] maintenance
//! records: public puts AND deletes are rejected like every protected
//! engine record (D5/MODEL pattern — undo is a counter-event, never a row
//! deletion), sync ingest rides the fail-closed single-writer-leased
//! stream class (ARCH-0023b) through ONE shared door that validates,
//! quota-bounds, joins `seq = max(local, incoming)`, and reconciles the
//! shell edges from the fold; the fold, the receipt projection, and any
//! rebuild all read from this one record family. Causality is the
//! engine-stamped monotonic `seq` — the caller's `at` is stored as data
//! and never orders the fold, so a backdated counter-event cannot rewrite
//! history.
//!
//! Consent (ARCH-0055 r3): `Auto` is the family default and applies
//! immediately; `Approved` applies; `Proposed` PARKS — the event is
//! recorded for legibility but carries zero topology effects until
//! approved; `Rejected` is the consent no-op. The propose lane is an
//! explicit caller choice, never an engine-imposed gate. Undo is a
//! counter-event over the ledger, never a rewrite (r1); claim subjects are
//! never eagerly rewritten (r6) — read-time canonicalization through the
//! redirect projection is ONE-1744. Reassignment-map application and FACET
//! minting arm in ONE-1745; `entity.distinct_from` claim storage arms in
//! ONE-1746.

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, is_structural_kind};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

#[cfg(test)]
pub(crate) mod test_hooks {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static FULL_RECONCILIATIONS: AtomicUsize = AtomicUsize::new(0);

    pub(crate) fn reset_full_reconciliations() {
        FULL_RECONCILIATIONS.store(0, Ordering::SeqCst);
    }

    pub(crate) fn full_reconciliations() -> usize {
        FULL_RECONCILIATIONS.load(Ordering::SeqCst)
    }

    pub(super) fn note_full_reconciliation() {
        FULL_RECONCILIATIONS.fetch_add(1, Ordering::SeqCst);
    }
}

/// Predicate of the anti-merge claim (ARCH-0055 §9 G.1 row): symmetric
/// `entity.distinct_from` pair, conflict-set keyed by [`distinct_pair_key`].
/// Declared here as the family's contract; the write path — a
/// `CLAIM_PREDICATE_REGISTRY` entry plus the literal-dispatch match arm in
/// `claim.rs` — arms in ONE-1746 together with re-proposal suppression.
/// Unlike the op events (engine-authored type-76 records), distinct_from
/// stays a public CLAIM: it is a statement about the world, not an action.
pub const PREDICATE_ENTITY_DISTINCT_FROM: &str = "entity.distinct_from";

/// vault_meta key of the engine-stamped monotonic event sequence — the
/// family's causality clock. Allocated inside the apply/undo write txn, so
/// a rolled-back op never burns a visible gap into committed history.
pub(crate) const IDENTITY_TOPOLOGY_SEQ_KEY: &[u8] = b"m:identity_topology_seq";

/// First sequence value the local allocator may not enter. The final 1,024
/// `u64` values remain the terminal band shared by local and replicated
/// records.
pub(crate) const IDENTITY_TOPOLOGY_REPLICATED_SEQ_CEILING: u64 = u64::MAX - 1_023;

/// Minimum allocator capacity a replicated record must leave below the
/// terminal band for locally-authored apply/undo counter-events.
pub(crate) const IDENTITY_TOPOLOGY_LOCAL_SEQ_HEADROOM: u64 = 1_024;

/// First sequence value rejected from replicated input. A peer may advance
/// the local clock only while all [`IDENTITY_TOPOLOGY_LOCAL_SEQ_HEADROOM`]
/// slots remain available to the local allocator below the terminal band.
const IDENTITY_TOPOLOGY_REPLICATED_SEQ_LIMIT: u64 =
    IDENTITY_TOPOLOGY_REPLICATED_SEQ_CEILING - IDENTITY_TOPOLOGY_LOCAL_SEQ_HEADROOM;

/// Hard per-record limits for the append-only replicated family. The body
/// limit bounds decode/allocation work before MessagePack parsing; the
/// participant limit bounds per-event fold and reconciliation fan-out.
pub(crate) const MAX_IDENTITY_TOPOLOGY_EVENT_BODY_BYTES: usize = 64 * 1024;
pub(crate) const MAX_IDENTITY_TOPOLOGY_EVENT_PARTICIPANTS: usize = 256;

const BODY_KEY_KIND: &str = "kind";
const BODY_KEY_SEQ: &str = "seq";
const BODY_KEY_AT: &str = "at";
const BODY_KEY_ACTOR: &str = "actor";
const BODY_KEY_ACTOR_CLASS: &str = "actor_class";
const BODY_KEY_SOURCE: &str = "src";
const BODY_KEY_APPROVAL: &str = "appr";
const BODY_KEY_CONFIDENCE: &str = "conf";
const BODY_KEY_EVIDENCE: &str = "evid";
const BODY_KEY_SOURCES: &str = "sources";
const BODY_KEY_SURVIVOR: &str = "survivor";
const BODY_KEY_PLAN: &str = "plan";
const BODY_KEY_ENTITY: &str = "entity";
const BODY_KEY_HEADS: &str = "heads";
const BODY_KEY_MAP: &str = "map";
const BODY_KEY_TARGET: &str = "target";

const MAP_KEY_ITEM: &str = "item";
const MAP_KEY_HEAD: &str = "head";
const MAP_KEY_FACET: &str = "facet";

const EVENT_KIND_MERGE: &str = "merge";
const EVENT_KIND_SPLIT: &str = "split";
const EVENT_KIND_UNDO: &str = "undo";

const PLAN_READ_THROUGH: &str = "read_through";

const EVIDENCE_KEY_REFS: &str = "refs";
const EVIDENCE_KEY_RATIONALE: &str = "rationale";

// ─── Lifecycle state ────────────────────────────────────────────────────────

/// Entity lifecycle state derived from the identity-topology op log.
///
/// `Merged` / `Split` are REDIRECT-SHELL states, not tombstones: the entity
/// body stays fully readable forever and no `TombstoneReason` exists for
/// them (merge-away is not deletion — ARCH-0055 §10 vs ARCH-0038).
///
/// The derive order is the pinned CRDT join precedence
/// (`Active < Merged < Split`); see [`merge_lifecycle_states`].
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
    /// undo-then-reapply, both on the ledger. [`evaluate_transition`] and
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

/// Commutative, associative, idempotent join of two concurrently folded
/// lifecycle states (the `merge_pact_states` analogue for this family).
///
/// Fixed precedence `Split > Merged > Active`: a shell state observed on
/// either replica is never lost to a concurrent `Active` (the op happened;
/// its ledger event survives the join), and between concurrent shells the
/// split wins because it preserves the finer topology — residue stays
/// readable through all heads, while carrying the merge instead would
/// conflate referents, the one failure the family's precision bias exists
/// to avoid ("false merges are poison", research-0904 via ARCH-0055 §1).
/// The discarded op's event stays on the ledger and can be re-applied after
/// an undo. `max` over a total order is commutative, associative, and
/// idempotent by construction.
#[must_use]
pub fn merge_lifecycle_states(
    left: EntityLifecycleState,
    right: EntityLifecycleState,
) -> EntityLifecycleState {
    left.max(right)
}

// ─── Op vocabulary ──────────────────────────────────────────────────────────

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

/// One reassignment-map row: where an item of the split/facet entity goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReassignmentEntry {
    /// The claim (entity ref) or edge being reassigned.
    pub item: ClaimSubject,
    /// Destination head / facet, or explicit residue.
    pub target: ReassignmentTarget,
}

/// Destination of one reassignment-map row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReassignmentTarget {
    /// Assign to a split head (must be one of the op's `heads`).
    Head(EntityId),
    /// Assign to the facet minted from the op's `facets[index]` spec.
    Facet {
        /// Index into the facet op's `facets` list.
        index: u32,
    },
    /// Unattributable residue: stays on the original entity, marked
    /// ambiguous — never force-assigned (r2).
    Residue,
}

/// Evidence-guided reassignment map shared by split and facet (r2/r5).
///
/// The map is encoded CANONICALLY into the split event record (entries
/// normalized by item bytes) so ONE-1745 replays exactly what the decision
/// stated; MS-01 validates targets and records — application arms there.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReassignmentMap {
    /// Per-item assignments; items absent from the map are residue.
    pub entries: Vec<ReassignmentEntry>,
}

impl ReassignmentMap {
    /// r2 stats over the map: rows assigned to a head/facet vs rows left
    /// as explicit ambiguous residue.
    #[must_use]
    pub fn assigned_and_residue_counts(&self) -> (u64, u64) {
        let assigned = self
            .entries
            .iter()
            .filter(|entry| !matches!(entry.target, ReassignmentTarget::Residue))
            .count() as u64;
        let residue = self.entries.len() as u64 - assigned;
        (assigned, residue)
    }

    /// The canonical entry order the wire codec pins: sorted by encoded
    /// item bytes, then target shape — deterministic for any caller order.
    #[must_use]
    pub fn canonicalized(&self) -> Self {
        let mut entries = self.entries.clone();
        entries.sort_by_key(|entry| {
            (
                encode_reassignment_item(&entry.item),
                reassignment_target_rank(&entry.target),
            )
        });
        Self { entries }
    }
}

fn reassignment_target_rank(target: &ReassignmentTarget) -> (u8, Vec<u8>) {
    match target {
        ReassignmentTarget::Head(head) => (0, head.as_bytes().to_vec()),
        ReassignmentTarget::Facet { index } => (1, index.to_be_bytes().to_vec()),
        ReassignmentTarget::Residue => (2, Vec::new()),
    }
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
    /// Head entities the original resolves to. MS-01 requires ≥1 head —
    /// the r2 zero-head ("gone") form has no readable witness until the
    /// redirect projection lands (ONE-1744 lifts
    /// [`IdentityTopologyRejection::EmptyHeads`]).
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
}

/// Normalized symmetric key for a distinct pair: `(min(a, b), max(a, b))`
/// (§9 G.1 `valueKeyFn`), so `assert_distinct(a, b)` and
/// `assert_distinct(b, a)` key to the same claim.
#[must_use]
pub fn distinct_pair_key(a: EntityId, b: EntityId) -> (EntityId, EntityId) {
    if a <= b { (a, b) } else { (b, a) }
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
    /// split names zero heads. MS-01 only: the r2 zero-head ("gone") form
    /// arms with the redirect projection (ONE-1744), the only surface able
    /// to express an empty resolution set.
    EmptyHeads,
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
    /// undo names an event that is not the current topology writer for its
    /// entities (already undone, superseded by a later re-apply, parked, or
    /// never applied).
    NotCurrent {
        /// The named event.
        event: EntityId,
    },
    /// undo names an event kind that cannot be undone (a counter-event, or
    /// an op family whose apply path is not armed yet).
    NotUndoable {
        /// The named event.
        event: EntityId,
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
            if split.heads.is_empty() {
                return Err(IdentityTopologyRejection::EmptyHeads);
            }
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

// ─── Ledger fold ────────────────────────────────────────────────────────────

/// One ledger action: apply an op, or undo a previously applied event.
#[derive(Debug, Clone, PartialEq)]
pub enum IdentityTopologyAction {
    /// Apply the op through the transition table.
    Apply(IdentityTopologyOp),
    /// Counter-event reverting a previously applied event (r1: undo is an
    /// append, never a rewrite).
    Undo {
        /// The ledger event being reverted.
        target: EntityId,
    },
}

/// One identity-topology ledger event, ready for folding.
#[derive(Debug, Clone, PartialEq)]
pub struct IdentityTopologyEvent {
    /// The event's type-76 record entity id (unique per event).
    pub event_id: EntityId,
    /// Engine-stamped monotonic sequence — the causality axis the fold
    /// orders by. Caller wall time is data, never ordering.
    pub seq: u64,
    /// Consent axis the event was recorded under. The fold evaluates
    /// EFFECTIVE events only (`Auto` / `Approved`); a `Proposed` event is
    /// parked legibility with zero topology effects.
    pub approval: ClaimApprovalStatus,
    /// The action the event records.
    pub action: IdentityTopologyAction,
}

/// Deterministic fold result over an identity-topology op log.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IdentityTopologyFold {
    /// Folded lifecycle state per touched entity (absent = `Active`).
    pub states: BTreeMap<EntityId, EntityLifecycleState>,
    /// For each entity in a shell state, the event that put it there — the
    /// undo-currency witness.
    pub current_event: BTreeMap<EntityId, EntityId>,
    /// Per-event rejections, in fold order.
    pub rejections: Vec<(EntityId, IdentityTopologyRejection)>,
}

/// Folds identity-topology events into lifecycle states — the
/// `fold_authority_log` analogue. Events are ordered by `(seq, event_id)`
/// so the fold is independent of input order AND of caller-supplied wall
/// time (a backdated counter-event cannot reorder history); non-effective
/// events (`Proposed` parks, `Rejected` is never recorded) change nothing.
#[must_use]
pub fn fold_identity_topology_log(events: &[IdentityTopologyEvent]) -> IdentityTopologyFold {
    let mut ordered: Vec<&IdentityTopologyEvent> = events.iter().collect();
    ordered.sort_by_key(|event| (event.seq, event.event_id));

    let mut fold = IdentityTopologyFold::default();
    let mut applied: BTreeMap<EntityId, &IdentityTopologyOp> = BTreeMap::new();
    let mut undo_events: BTreeSet<EntityId> = BTreeSet::new();

    for event in ordered {
        if !matches!(
            event.approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        ) {
            continue;
        }
        match &event.action {
            IdentityTopologyAction::Apply(op) => match evaluate_transition(&fold.states, op) {
                Ok(transitions) => {
                    for (entity, state) in transitions {
                        fold.states.insert(entity, state);
                        if state == EntityLifecycleState::Active {
                            fold.current_event.remove(&entity);
                        } else {
                            fold.current_event.insert(entity, event.event_id);
                        }
                    }
                    applied.insert(event.event_id, op);
                }
                Err(rejection) => fold.rejections.push((event.event_id, rejection)),
            },
            IdentityTopologyAction::Undo { target } => {
                match evaluate_fold_undo(&fold.current_event, &applied, &undo_events, target) {
                    Ok(reverted) => {
                        for entity in reverted {
                            fold.states.insert(entity, EntityLifecycleState::Active);
                            fold.current_event.remove(&entity);
                        }
                        undo_events.insert(event.event_id);
                    }
                    Err(rejection) => {
                        fold.rejections.push((event.event_id, rejection));
                        undo_events.insert(event.event_id);
                    }
                }
            }
        }
    }
    fold
}

/// Undo legality against the fold state: the target must be an applied
/// merge/split whose shell entities all still name it as their current
/// topology writer.
fn evaluate_fold_undo(
    current_event: &BTreeMap<EntityId, EntityId>,
    applied: &BTreeMap<EntityId, &IdentityTopologyOp>,
    undo_events: &BTreeSet<EntityId>,
    target: &EntityId,
) -> std::result::Result<Vec<EntityId>, IdentityTopologyRejection> {
    if undo_events.contains(target) {
        return Err(IdentityTopologyRejection::NotUndoable { event: *target });
    }
    let Some(op) = applied.get(target) else {
        return Err(IdentityTopologyRejection::NotCurrent { event: *target });
    };
    let shelled = match op {
        IdentityTopologyOp::Merge(merge) => merge.sources.clone(),
        IdentityTopologyOp::Split(split) => vec![split.entity],
        // Facet / assert_distinct applies move no lifecycle state; their
        // undo semantics arm with their apply paths (ONE-1745 / ONE-1746).
        IdentityTopologyOp::Facet(_) | IdentityTopologyOp::AssertDistinct(_) => {
            return Err(IdentityTopologyRejection::NotUndoable { event: *target });
        }
    };
    for entity in &shelled {
        if current_event.get(entity) != Some(target) {
            return Err(IdentityTopologyRejection::NotCurrent { event: *target });
        }
    }
    Ok(shelled)
}

// ─── Event records (type-76 wire) ───────────────────────────────────────────

/// Action payload of one stored ledger event. The split map is carried
/// CANONICALLY (never discarded) so ONE-1745 replays exactly what the
/// decision stated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredIdentityOpAction {
    /// A merge event.
    Merge {
        /// Losing entities.
        sources: Vec<EntityId>,
        /// Surviving canonical head.
        survivor: EntityId,
    },
    /// A split event carrying its full reassignment map.
    Split {
        /// The split original.
        entity: EntityId,
        /// Head entities.
        heads: Vec<EntityId>,
        /// Canonically ordered reassignment map.
        reassignment: ReassignmentMap,
    },
    /// A counter-event reverting `target`.
    Undo {
        /// The reverted ledger event.
        target: EntityId,
    },
}

impl StoredIdentityOpAction {
    /// The pinned wire/receipt kind string for this action.
    #[must_use]
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::Merge { .. } => EVENT_KIND_MERGE,
            Self::Split { .. } => EVENT_KIND_SPLIT,
            Self::Undo { .. } => EVENT_KIND_UNDO,
        }
    }

    /// Reconstructs the fold-grade action. Evidence and survivorship plan
    /// do not participate in transition evaluation; the split map rides
    /// along verbatim.
    #[must_use]
    pub fn to_fold_action(&self) -> IdentityTopologyAction {
        match self {
            Self::Merge { sources, survivor } => {
                IdentityTopologyAction::Apply(IdentityTopologyOp::Merge(MergeOp {
                    sources: sources.clone(),
                    survivor: *survivor,
                    evidence: IdentityOpEvidence::default(),
                    survivorship_plan: SurvivorshipPlan::ReadThrough,
                }))
            }
            Self::Split {
                entity,
                heads,
                reassignment,
            } => IdentityTopologyAction::Apply(IdentityTopologyOp::Split(SplitOp {
                entity: *entity,
                heads: heads.clone(),
                reassignment: reassignment.clone(),
                evidence: IdentityOpEvidence::default(),
            })),
            Self::Undo { target } => IdentityTopologyAction::Undo { target: *target },
        }
    }
}

/// One identity-topology ledger event as stored in a type-76 maintenance
/// record body (engine-pinned MessagePack map).
///
/// Engine-authored ONLY: public puts of the type byte are rejected
/// (`MaintenanceKindNotWritable`), so every stored record passed this
/// module's door — the fold and the receipt projection therefore read the
/// family fail-closed (a malformed body is corruption, never skipped).
#[derive(Debug, Clone, PartialEq)]
pub struct StoredIdentityOpEvent {
    /// Engine-stamped monotonic causality sequence.
    pub seq: u64,
    /// Caller-supplied event time (Unix seconds) — data, never ordering.
    pub at: u64,
    /// Deciding actor, validated at the door when bound (r1).
    pub actor: Option<WriteActor>,
    /// Provenance source of the decision.
    pub source: ClaimSource,
    /// Consent axis the event was recorded under.
    pub approval: ClaimApprovalStatus,
    /// Decision confidence, finite in `[0, 1]`.
    pub confidence: f32,
    /// Decision evidence; absent on undo counter-events.
    pub evidence: Option<IdentityOpEvidence>,
    /// The recorded action.
    pub action: StoredIdentityOpAction,
}

impl StoredIdentityOpEvent {
    /// Encodes the record into its pinned MessagePack map value. Split
    /// reassignment entries are canonicalized (sorted by item bytes).
    #[must_use]
    pub fn encode_value(&self) -> Value {
        let mut entries = Vec::new();
        entries.push((
            Value::from(BODY_KEY_KIND),
            Value::from(self.action.kind_str()),
        ));
        entries.push((Value::from(BODY_KEY_SEQ), Value::from(self.seq)));
        entries.push((Value::from(BODY_KEY_AT), Value::from(self.at)));
        if let Some(actor) = self.actor {
            entries.push((Value::from(BODY_KEY_ACTOR), id_value(&actor.entity_ref())));
            entries.push((
                Value::from(BODY_KEY_ACTOR_CLASS),
                Value::from(actor.actor_class().gate_actor_class()),
            ));
        }
        entries.push((
            Value::from(BODY_KEY_SOURCE),
            Value::from(self.source.as_str()),
        ));
        entries.push((
            Value::from(BODY_KEY_APPROVAL),
            Value::from(self.approval.as_str()),
        ));
        entries.push((
            Value::from(BODY_KEY_CONFIDENCE),
            Value::F32(self.confidence),
        ));
        if let Some(evidence) = &self.evidence {
            entries.push((
                Value::from(BODY_KEY_EVIDENCE),
                Value::Map(vec![
                    (Value::from(EVIDENCE_KEY_REFS), ids_value(&evidence.refs)),
                    (
                        Value::from(EVIDENCE_KEY_RATIONALE),
                        Value::from(evidence.rationale.as_str()),
                    ),
                ]),
            ));
        }
        match &self.action {
            StoredIdentityOpAction::Merge { sources, survivor } => {
                entries.push((Value::from(BODY_KEY_SOURCES), ids_value(sources)));
                entries.push((Value::from(BODY_KEY_SURVIVOR), id_value(survivor)));
                entries.push((Value::from(BODY_KEY_PLAN), Value::from(PLAN_READ_THROUGH)));
            }
            StoredIdentityOpAction::Split {
                entity,
                heads,
                reassignment,
            } => {
                entries.push((Value::from(BODY_KEY_ENTITY), id_value(entity)));
                entries.push((Value::from(BODY_KEY_HEADS), ids_value(heads)));
                entries.push((
                    Value::from(BODY_KEY_MAP),
                    encode_reassignment_map(reassignment),
                ));
            }
            StoredIdentityOpAction::Undo { target } => {
                entries.push((Value::from(BODY_KEY_TARGET), id_value(target)));
            }
        }
        Value::Map(entries)
    }

    /// Decodes a stored record value, fail-closed on any malformed field.
    pub fn decode_value(value: &Value) -> Result<Self> {
        let map = value
            .as_map()
            .ok_or(Error::InvalidIdentityTopologyEventBody(
                "identity topology event must be a map",
            ))?;
        let kind = decode_str_field(map, BODY_KEY_KIND, "identity topology event kind")?;
        let seq = decode_u64_field(map, BODY_KEY_SEQ, "identity topology event seq")?;
        let at = decode_u64_field(map, BODY_KEY_AT, "identity topology event at")?;
        let actor = decode_actor(map)?;
        let source = map_field(map, BODY_KEY_SOURCE)
            .and_then(Value::as_str)
            .and_then(ClaimSource::parse)
            .ok_or(Error::InvalidIdentityTopologyEventBody(
                "identity topology event source",
            ))?;
        let approval = map_field(map, BODY_KEY_APPROVAL)
            .and_then(Value::as_str)
            .and_then(ClaimApprovalStatus::parse)
            .ok_or(Error::InvalidIdentityTopologyEventBody(
                "identity topology event approval",
            ))?;
        let confidence = map_field(map, BODY_KEY_CONFIDENCE)
            .and_then(Value::as_f64)
            .ok_or(Error::InvalidIdentityTopologyEventBody(
                "identity topology event confidence",
            ))? as f32;
        if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
            return Err(Error::InvalidIdentityTopologyEventBody(
                "identity topology event confidence",
            ));
        }
        let evidence = match map_field(map, BODY_KEY_EVIDENCE) {
            None => None,
            Some(value) => Some(decode_evidence(value)?),
        };
        let action = match kind {
            EVENT_KIND_MERGE => {
                let plan = decode_str_field(map, BODY_KEY_PLAN, "identity topology event plan")?;
                if plan != PLAN_READ_THROUGH {
                    return Err(Error::InvalidIdentityTopologyEventBody(
                        "identity topology event plan is unknown",
                    ));
                }
                StoredIdentityOpAction::Merge {
                    sources: decode_ids_field(
                        map,
                        BODY_KEY_SOURCES,
                        "identity topology event sources",
                    )?,
                    survivor: decode_id_field(
                        map,
                        BODY_KEY_SURVIVOR,
                        "identity topology event survivor",
                    )?,
                }
            }
            EVENT_KIND_SPLIT => StoredIdentityOpAction::Split {
                entity: decode_id_field(map, BODY_KEY_ENTITY, "identity topology event entity")?,
                heads: decode_ids_field(map, BODY_KEY_HEADS, "identity topology event heads")?,
                reassignment: decode_reassignment_map(map_field(map, BODY_KEY_MAP).ok_or(
                    Error::InvalidIdentityTopologyEventBody("identity topology event map"),
                )?)?,
            },
            EVENT_KIND_UNDO => StoredIdentityOpAction::Undo {
                target: decode_id_field(map, BODY_KEY_TARGET, "identity topology event target")?,
            },
            _ => {
                return Err(Error::InvalidIdentityTopologyEventBody(
                    "identity topology event kind is unknown",
                ));
            }
        };
        Ok(Self {
            seq,
            at,
            actor,
            source,
            approval,
            confidence,
            evidence,
            action,
        })
    }
}

/// Encodes a type-76 record body to its pinned MessagePack bytes.
pub(crate) fn encode_identity_topology_event_body(
    record: &StoredIdentityOpEvent,
) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &record.encode_value()).map_err(|_| {
        Error::InvalidIdentityTopologyEventBody("identity topology event encode failed")
    })?;
    Ok(data)
}

/// Decodes a type-76 record body from its pinned MessagePack bytes,
/// fail-closed on trailing bytes or any malformed field.
pub(crate) fn decode_identity_topology_event_body(data: &[u8]) -> Result<StoredIdentityOpEvent> {
    if data.len() > MAX_IDENTITY_TOPOLOGY_EVENT_BODY_BYTES {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology event body exceeds the size limit",
        ));
    }
    let mut cursor = data;
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        Error::InvalidIdentityTopologyEventBody("identity topology event bytes are malformed")
    })?;
    if !cursor.is_empty() {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology event carries trailing bytes",
        ));
    }
    let record = StoredIdentityOpEvent::decode_value(&value)?;
    if encode_identity_topology_event_body(&record)? != data {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology event body is not canonical",
        ));
    }
    validate_identity_topology_event_stateless(&record)?;
    Ok(record)
}

/// Timeless replicated-record admission checks. These are exactly the
/// invariants a local door can enforce without consulting lifecycle state:
/// sequence/consent legality, bounded fan-out, and operation shape. They run
/// during body decode, before quota, storage, clock join, or reconciliation.
fn validate_identity_topology_event_stateless(record: &StoredIdentityOpEvent) -> Result<()> {
    if record.seq == 0 {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology event seq must be nonzero",
        ));
    }
    if record.seq >= IDENTITY_TOPOLOGY_REPLICATED_SEQ_CEILING {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology event seq is in the reserved terminal range",
        ));
    }
    if record.approval == ClaimApprovalStatus::Rejected {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "rejected identity topology decisions are not stored",
        ));
    }

    let IdentityTopologyAction::Apply(op) = record.action.to_fold_action() else {
        return Ok(());
    };
    if op.participants().len() > MAX_IDENTITY_TOPOLOGY_EVENT_PARTICIPANTS {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology event has too many participants",
        ));
    }
    evaluate_transition(&BTreeMap::new(), &op).map_err(|_| {
        Error::InvalidIdentityTopologyEventBody(
            "identity topology event operation shape is invalid",
        )
    })?;
    Ok(())
}

fn validate_replicated_identity_topology_seq(seq: u64) -> Result<()> {
    if seq >= IDENTITY_TOPOLOGY_REPLICATED_SEQ_LIMIT {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology event seq is in the reserved terminal range",
        ));
    }
    Ok(())
}

/// D18 body validator for the type-76 maintenance kind, run at the shared
/// write chokepoint on every path that can admit the byte (engine door and
/// sync replay alike).
pub(crate) fn validate_identity_topology_event_body_bytes(data: &[u8]) -> Result<()> {
    decode_identity_topology_event_body(data).map(|_| ())
}

/// Decodes the deterministic body predicate shared by every replicated
/// type-76 ingress decision. Local authoring may consume the retained
/// headroom; replicated bodies must additionally leave it intact.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) fn decode_replicated_identity_topology_event_body(
    data: &[u8],
) -> Result<StoredIdentityOpEvent> {
    let record = decode_identity_topology_event_body(data)?;
    validate_replicated_identity_topology_seq(record.seq)?;
    Ok(record)
}

fn id_value(id: &EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

fn ids_value(ids: &[EntityId]) -> Value {
    Value::Array(ids.iter().map(id_value).collect())
}

fn encode_reassignment_item(item: &ClaimSubject) -> Vec<u8> {
    match item {
        ClaimSubject::Entity(id) => id.as_bytes().to_vec(),
        ClaimSubject::Edge {
            source,
            kind,
            target,
        } => {
            let mut bytes = Vec::with_capacity(ENTITY_ID_LEN * 2 + 1);
            bytes.extend_from_slice(source.as_bytes());
            bytes.push(*kind as u8);
            bytes.extend_from_slice(target.as_bytes());
            bytes
        }
    }
}

fn decode_reassignment_item(bytes: &[u8]) -> Result<ClaimSubject> {
    const ITEM_CONTEXT: &str = "identity topology event map item";
    match bytes.len() {
        ENTITY_ID_LEN => {
            let arr: [u8; ENTITY_ID_LEN] = bytes
                .try_into()
                .map_err(|_| Error::InvalidIdentityTopologyEventBody(ITEM_CONTEXT))?;
            EntityId::from_bytes(arr)
                .map(ClaimSubject::Entity)
                .map_err(|_| Error::InvalidIdentityTopologyEventBody(ITEM_CONTEXT))
        }
        len if len == ENTITY_ID_LEN * 2 + 1 => {
            let source = decode_id_bytes(&bytes[..ENTITY_ID_LEN], ITEM_CONTEXT)?;
            let kind = EdgeKind::try_from_u8(bytes[ENTITY_ID_LEN])
                .ok_or(Error::InvalidIdentityTopologyEventBody(ITEM_CONTEXT))?;
            let target = decode_id_bytes(&bytes[ENTITY_ID_LEN + 1..], ITEM_CONTEXT)?;
            Ok(ClaimSubject::Edge {
                source,
                kind,
                target,
            })
        }
        _ => Err(Error::InvalidIdentityTopologyEventBody(ITEM_CONTEXT)),
    }
}

fn encode_reassignment_map(map: &ReassignmentMap) -> Value {
    let canonical = map.canonicalized();
    Value::Array(
        canonical
            .entries
            .iter()
            .map(|entry| {
                let mut fields = vec![(
                    Value::from(MAP_KEY_ITEM),
                    Value::Binary(encode_reassignment_item(&entry.item)),
                )];
                match entry.target {
                    ReassignmentTarget::Head(head) => {
                        fields.push((Value::from(MAP_KEY_HEAD), id_value(&head)));
                    }
                    ReassignmentTarget::Facet { index } => {
                        fields.push((Value::from(MAP_KEY_FACET), Value::from(index)));
                    }
                    ReassignmentTarget::Residue => {}
                }
                Value::Map(fields)
            })
            .collect(),
    )
}

fn decode_reassignment_map(value: &Value) -> Result<ReassignmentMap> {
    const MAP_CONTEXT: &str = "identity topology event map";
    let Value::Array(rows) = value else {
        return Err(Error::InvalidIdentityTopologyEventBody(MAP_CONTEXT));
    };
    let mut entries = Vec::with_capacity(rows.len());
    let mut previous_item: Option<&[u8]> = None;
    for row in rows {
        let fields = row
            .as_map()
            .ok_or(Error::InvalidIdentityTopologyEventBody(MAP_CONTEXT))?;
        let item_bytes = map_field(fields, MAP_KEY_ITEM)
            .and_then(Value::as_slice)
            .ok_or(Error::InvalidIdentityTopologyEventBody(MAP_CONTEXT))?;
        // The pinned wire order is STRICTLY ascending encoded item bytes
        // (the `canonicalized()` sort key): equal items are the duplicate-
        // assignment shape (one claim must not carry two assignments), and
        // out-of-order rows would re-serialize to different bytes than
        // stored — breaking the on-disk == re-encoded identity the sync
        // divergence checks rely on. Fail closed on both.
        if previous_item.is_some_and(|previous| previous >= item_bytes) {
            return Err(Error::InvalidIdentityTopologyEventBody(MAP_CONTEXT));
        }
        previous_item = Some(item_bytes);
        let item = decode_reassignment_item(item_bytes)?;
        let head = map_field(fields, MAP_KEY_HEAD);
        let facet = map_field(fields, MAP_KEY_FACET);
        let target = match (head, facet) {
            (None, None) => ReassignmentTarget::Residue,
            (Some(head), None) => ReassignmentTarget::Head(decode_id_value(head, MAP_CONTEXT)?),
            (None, Some(index)) => ReassignmentTarget::Facet {
                index: index
                    .as_u64()
                    .and_then(|index| u32::try_from(index).ok())
                    .ok_or(Error::InvalidIdentityTopologyEventBody(MAP_CONTEXT))?,
            },
            (Some(_), Some(_)) => {
                return Err(Error::InvalidIdentityTopologyEventBody(MAP_CONTEXT));
            }
        };
        entries.push(ReassignmentEntry { item, target });
    }
    Ok(ReassignmentMap { entries })
}

fn decode_evidence(value: &Value) -> Result<IdentityOpEvidence> {
    const EVIDENCE_CONTEXT: &str = "identity topology event evidence";
    let map = value
        .as_map()
        .ok_or(Error::InvalidIdentityTopologyEventBody(EVIDENCE_CONTEXT))?;
    let refs = decode_ids_field(map, EVIDENCE_KEY_REFS, EVIDENCE_CONTEXT)?;
    let rationale = decode_str_field(map, EVIDENCE_KEY_RATIONALE, EVIDENCE_CONTEXT)?.to_owned();
    Ok(IdentityOpEvidence { refs, rationale })
}

fn map_field<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(entry_key, _)| entry_key.as_str() == Some(key))
        .map(|(_, entry_value)| entry_value)
}

fn decode_str_field<'a>(
    map: &'a [(Value, Value)],
    key: &str,
    context: &'static str,
) -> Result<&'a str> {
    map_field(map, key)
        .and_then(Value::as_str)
        .ok_or(Error::InvalidIdentityTopologyEventBody(context))
}

fn decode_u64_field(map: &[(Value, Value)], key: &str, context: &'static str) -> Result<u64> {
    map_field(map, key)
        .and_then(Value::as_u64)
        .ok_or(Error::InvalidIdentityTopologyEventBody(context))
}

fn decode_id_bytes(bytes: &[u8], context: &'static str) -> Result<EntityId> {
    let arr: [u8; ENTITY_ID_LEN] = bytes
        .try_into()
        .map_err(|_| Error::InvalidIdentityTopologyEventBody(context))?;
    EntityId::from_bytes(arr).map_err(|_| Error::InvalidIdentityTopologyEventBody(context))
}

fn decode_id_value(value: &Value, context: &'static str) -> Result<EntityId> {
    decode_id_bytes(
        value
            .as_slice()
            .ok_or(Error::InvalidIdentityTopologyEventBody(context))?,
        context,
    )
}

fn decode_id_field(map: &[(Value, Value)], key: &str, context: &'static str) -> Result<EntityId> {
    decode_id_value(
        map_field(map, key).ok_or(Error::InvalidIdentityTopologyEventBody(context))?,
        context,
    )
}

fn decode_ids_field(
    map: &[(Value, Value)],
    key: &str,
    context: &'static str,
) -> Result<Vec<EntityId>> {
    let Some(Value::Array(items)) = map_field(map, key) else {
        return Err(Error::InvalidIdentityTopologyEventBody(context));
    };
    items
        .iter()
        .map(|item| decode_id_value(item, context))
        .collect()
}

fn decode_actor(map: &[(Value, Value)]) -> Result<Option<WriteActor>> {
    let entity = map_field(map, BODY_KEY_ACTOR);
    let class = map_field(map, BODY_KEY_ACTOR_CLASS);
    match (entity, class) {
        (None, None) => Ok(None),
        (Some(entity), Some(class)) => {
            let entity_ref = decode_id_value(entity, "identity topology event actor")?;
            let class = class.as_str().and_then(parse_actor_class).ok_or(
                Error::InvalidIdentityTopologyEventBody("identity topology event actor class"),
            )?;
            Ok(Some(WriteActor::new(entity_ref, class)))
        }
        _ => Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology event actor requires both entity and class",
        )),
    }
}

fn parse_actor_class(value: &str) -> Option<EdgeActorClass> {
    match value {
        "human" => Some(EdgeActorClass::Human),
        "agent" => Some(EdgeActorClass::Agent),
        "system" => Some(EdgeActorClass::System),
        _ => None,
    }
}

// ─── Vault apply path ───────────────────────────────────────────────────────

/// Write metadata for one identity-topology op: the consent axes the ledger
/// event record carries. AUTO is the family default (r3); the propose lane
/// is the caller dialing `approval` to `Proposed` for the three exception
/// conditions (§6) — never an engine-imposed gate.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IdentityOpWrite {
    /// Provenance source stamped on the event record.
    pub source: ClaimSource,
    /// Consent axis: `Auto`/`Approved` apply, `Proposed` parks with zero
    /// topology effects, `Rejected` is the consent no-op.
    pub approval: ClaimApprovalStatus,
    /// Confidence stamped on the event record, finite in `[0, 1]`.
    pub confidence: f32,
    /// Deciding actor recorded on the event (r1); validated at the door
    /// (existence + type/class fit) when bound.
    pub actor: Option<WriteActor>,
}

impl IdentityOpWrite {
    /// The r3 default: auto-approved, full confidence, no bound actor.
    #[must_use]
    pub const fn auto(source: ClaimSource) -> Self {
        Self {
            source,
            approval: ClaimApprovalStatus::Auto,
            confidence: 1.0,
            actor: None,
        }
    }

    /// Binds the deciding actor recorded on the ledger event.
    #[must_use]
    pub const fn with_actor(mut self, actor: WriteActor) -> Self {
        self.actor = Some(actor);
        self
    }

    const fn is_effective(&self) -> bool {
        matches!(
            self.approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        )
    }
}

/// Receipt of one identity-topology door call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityOpOutcome {
    /// `Auto`/`Approved`: topology written, event recorded.
    Applied {
        /// The ledger event record written for this op.
        event: EntityId,
        /// Lifecycle assignments the op performed, in role order.
        transitions: Vec<(EntityId, EntityLifecycleState)>,
    },
    /// `Proposed`: the event is recorded for legibility, but no edge and no
    /// lifecycle state moved — zero topology effects until approved.
    Parked {
        /// The parked ledger event record.
        event: EntityId,
    },
    /// `Rejected`: the consent no-op — nothing validated, nothing written.
    Noop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentityTopologyParticipantValidation {
    Complete,
    Deferred,
    Invalid(IdentityTopologyRejection),
}

fn shell_edge_weight(kind: EdgeKind) -> Result<f32> {
    kind.default_weight().ok_or(Error::InvariantViolation(
        "identity topology edge missing default weight",
    ))
}

fn identity_topology_entity_type_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<u8>> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    Ok(Some(header.entity_type))
}

fn identity_topology_event_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<StoredIdentityOpEvent>> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
        return Err(Error::InvalidEntityType(header.entity_type));
    }
    decode_identity_topology_event_body(&raw[ENTITY_METADATA_HEADER_LEN..])
        .map(Some)
        .map_err(|_| Error::CorruptedIndex("identity topology event body"))
}

fn identity_topology_events_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
) -> Result<Vec<IdentityTopologyEvent>> {
    let mut events = Vec::new();
    for entry in store
        .type_index
        .prefix_iter(rtxn, &[ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT])?
    {
        let (key, _) = entry?;
        let event_id = crate::vault::entity_id_from_type_index_key(&key)?;
        let record = identity_topology_event_for_store_in_txn(store, rtxn, &event_id)?
            .ok_or(Error::CorruptedIndex("identity topology event index"))?;
        events.push(IdentityTopologyEvent {
            event_id,
            seq: record.seq,
            approval: record.approval,
            action: record.action.to_fold_action(),
        });
    }
    Ok(events)
}

fn validate_identity_op_participants_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    op: &IdentityTopologyOp,
) -> Result<IdentityTopologyParticipantValidation> {
    let is_merge = matches!(op, IdentityTopologyOp::Merge(_));
    let mut validation = IdentityTopologyParticipantValidation::Complete;
    for participant in op.participants() {
        let Some(entity_type) =
            identity_topology_entity_type_for_store_in_txn(store, rtxn, &participant)?
        else {
            validation = IdentityTopologyParticipantValidation::Deferred;
            continue;
        };
        if !is_structural_kind(entity_type) {
            return Ok(IdentityTopologyParticipantValidation::Invalid(
                IdentityTopologyRejection::NotStructural {
                    entity: participant,
                },
            ));
        }
        if is_merge && entity_type == ENTITY_TYPE_FACET {
            return Ok(IdentityTopologyParticipantValidation::Invalid(
                IdentityTopologyRejection::FacetMerge {
                    entity: participant,
                },
            ));
        }
    }
    Ok(validation)
}

fn identity_topology_actor_complete_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    record: &StoredIdentityOpEvent,
) -> Result<bool> {
    let Some(actor) = record.actor else {
        return Ok(true);
    };
    let Some(actor_type) =
        identity_topology_entity_type_for_store_in_txn(store, rtxn, &actor.entity_ref())?
    else {
        return Ok(false);
    };
    crate::provenance::validate_actor_class(actor_type, actor.actor_class())?;
    Ok(true)
}

fn fold_effective_identity_topology_events_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
) -> Result<Vec<IdentityTopologyEvent>> {
    let events = identity_topology_events_for_store_in_txn(store, rtxn)?;
    let mut effective = Vec::with_capacity(events.len());
    for event in events {
        let references_complete = match &event.action {
            IdentityTopologyAction::Apply(op) => matches!(
                validate_identity_op_participants_for_store_in_txn(store, rtxn, op)?,
                IdentityTopologyParticipantValidation::Complete
            ),
            IdentityTopologyAction::Undo { target } => {
                identity_topology_entity_type_for_store_in_txn(store, rtxn, target)?
                    .is_some_and(|kind| kind == ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT)
            }
        };
        let record = identity_topology_event_for_store_in_txn(store, rtxn, &event.event_id)?
            .ok_or(Error::CorruptedIndex("identity topology event index"))?;
        let actor_complete =
            match identity_topology_actor_complete_for_store_in_txn(store, rtxn, &record) {
                Ok(complete) => complete,
                Err(Error::ActorClassMismatch { .. }) => false,
                Err(err) => return Err(err),
            };
        if references_complete && actor_complete {
            effective.push(event);
        }
    }
    Ok(effective)
}

fn desired_shell_edges_for_store_entity_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    fold: &IdentityTopologyFold,
    entity: &EntityId,
) -> Result<Vec<(EdgeKind, EntityId, u64)>> {
    let state = fold
        .states
        .get(entity)
        .copied()
        .unwrap_or(EntityLifecycleState::Active);
    if state == EntityLifecycleState::Active {
        return Ok(Vec::new());
    }
    let event_id = fold
        .current_event
        .get(entity)
        .ok_or(Error::CorruptedIndex("identity topology fold"))?;
    let record = identity_topology_event_for_store_in_txn(store, rtxn, event_id)?
        .ok_or(Error::CorruptedIndex("identity topology event index"))?;
    Ok(match (&record.action, state) {
        (StoredIdentityOpAction::Merge { survivor, .. }, EntityLifecycleState::Merged) => {
            vec![(EdgeKind::MergedInto, *survivor, record.at)]
        }
        (StoredIdentityOpAction::Split { heads, .. }, EntityLifecycleState::Split) => heads
            .iter()
            .map(|head| (EdgeKind::SplitInto, *head, record.at))
            .collect(),
        _ => return Err(Error::CorruptedIndex("identity topology fold")),
    })
}

fn identity_topology_shell_peers_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    entity: &EntityId,
    kind: EdgeKind,
) -> Result<Vec<EntityId>> {
    let prefix = crate::vault::edge_kind_prefix(entity, kind);
    let mut peers = Vec::new();
    for (scanned, entry) in store.edges_out.prefix_iter(rtxn, &prefix)?.enumerate() {
        if scanned >= crate::vault::MAX_EDGE_QUERY_RESULTS {
            return Err(Error::IndexOverflow("identity topology"));
        }
        let (key, value) = entry?;
        peers.push(crate::edge::parse_strict_edge_record(&key, &value)?.target);
    }
    Ok(peers)
}

#[allow(clippy::too_many_arguments)]
fn reconcile_identity_topology_edges_for_store_in_txn(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    text_index_trusted: bool,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    #[cfg(test)]
    test_hooks::note_full_reconciliation();
    let stored_events = identity_topology_events_for_store_in_txn(store, &*wtxn)?;
    let mut touched = BTreeSet::new();
    for event in &stored_events {
        match &event.action {
            IdentityTopologyAction::Apply(IdentityTopologyOp::Merge(merge)) => {
                touched.extend(merge.sources.iter().copied());
            }
            IdentityTopologyAction::Apply(IdentityTopologyOp::Split(split)) => {
                touched.insert(split.entity);
            }
            IdentityTopologyAction::Apply(
                IdentityTopologyOp::Facet(_) | IdentityTopologyOp::AssertDistinct(_),
            )
            | IdentityTopologyAction::Undo { .. } => {}
        }
    }
    if touched.is_empty() {
        return Ok(());
    }

    let effective_events = fold_effective_identity_topology_events_for_store_in_txn(store, &*wtxn)?;
    let fold = fold_identity_topology_log(&effective_events);
    let mut ops = Vec::new();
    for entity in &touched {
        let desired = desired_shell_edges_for_store_entity_in_txn(store, &*wtxn, &fold, entity)?;
        for kind in [EdgeKind::MergedInto, EdgeKind::SplitInto] {
            let existing =
                identity_topology_shell_peers_for_store_in_txn(store, &*wtxn, entity, kind)?;
            for peer in &existing {
                if !desired
                    .iter()
                    .any(|(desired_kind, target, _)| *desired_kind == kind && target == peer)
                {
                    ops.push(BatchOp::DeleteEdge {
                        src: *entity,
                        kind,
                        tgt: *peer,
                        replicated_consent_verified: false,
                    });
                }
            }
            for (desired_kind, target, created_at) in &desired {
                if *desired_kind != kind {
                    continue;
                }
                if store.entities.get(&*wtxn, entity.as_bytes())?.is_none()
                    || store.entities.get(&*wtxn, target.as_bytes())?.is_none()
                {
                    continue;
                }
                let weight = shell_edge_weight(kind)?;
                let canonical = crate::edge::encode_edge_value(
                    kind,
                    weight,
                    *created_at,
                    crate::affect::Vad::NEUTRAL,
                    None,
                )?;
                let out_key = Store::encode_edge_key(entity, kind, target);
                let in_key = Store::encode_edge_key(target, kind, entity);
                let out_matches = store
                    .edges_out
                    .get(&*wtxn, &out_key)?
                    .is_some_and(|value| value == canonical.as_slice());
                let in_matches = store
                    .edges_in
                    .get(&*wtxn, &in_key)?
                    .is_some_and(|value| value == canonical.as_slice());
                if out_matches && in_matches {
                    continue;
                }
                ops.push(BatchOp::EdgeWithCreatedAt {
                    src: *entity,
                    kind,
                    tgt: *target,
                    weight,
                    created_at: *created_at,
                    vad: crate::affect::Vad::NEUTRAL,
                    provenance: None,
                });
            }
        }
    }
    if ops.is_empty() {
        return Ok(());
    }
    apply_ops(
        store,
        config,
        analyzer,
        wtxn,
        ops,
        text_index_trusted,
        false,
        true,
    )
}

/// Shared successful-put boundary for every `apply_ops` caller. All puts in
/// one batch are considered together and trigger at most one full topology
/// reconciliation; no pending-participant index is introduced.
#[allow(clippy::too_many_arguments)]
pub(crate) fn reconcile_identity_topology_for_materialized_entities_in_txn(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    text_index_trusted: bool,
    wtxn: &mut heed::RwTxn<'_>,
    materialized: &BTreeSet<EntityId>,
) -> Result<()> {
    if materialized.is_empty() {
        return Ok(());
    }
    let events = identity_topology_events_for_store_in_txn(store, &*wtxn)?;
    for event in events {
        let action_relevant = match &event.action {
            IdentityTopologyAction::Apply(op) => op
                .participants()
                .iter()
                .any(|participant| materialized.contains(participant)),
            // Type-76 targets are engine-authored and their replicated ingest
            // door performs the full reconciliation after the seq join. Do
            // not duplicate that pass from the generic put hook.
            IdentityTopologyAction::Undo { .. } => false,
        };
        let record = identity_topology_event_for_store_in_txn(store, &*wtxn, &event.event_id)?
            .ok_or(Error::CorruptedIndex("identity topology event index"))?;
        let actor_relevant = record
            .actor
            .is_some_and(|actor| materialized.contains(&actor.entity_ref()));
        if action_relevant || actor_relevant {
            return reconcile_identity_topology_edges_for_store_in_txn(
                store,
                config,
                analyzer,
                text_index_trusted,
                wtxn,
            );
        }
    }
    Ok(())
}

impl Vault {
    /// Current lifecycle state of `id`, read from its canonical redirect
    /// edges (D11: the edge is the sole state witness; the ledger fold and
    /// the apply path keep them in lockstep). An id with no shell edge —
    /// including one never written — is `Active`.
    pub fn entity_lifecycle_state(&self, id: &EntityId) -> Result<EntityLifecycleState> {
        let rtxn = self.store.env.read_txn()?;
        self.entity_lifecycle_state_in_txn(&rtxn, id)
    }

    /// Transaction-composable [`Vault::entity_lifecycle_state`]. Fails
    /// closed with `CorruptedIndex` when an id carries BOTH shell edge
    /// kinds or more than one `merged_into` target — states no apply path
    /// can produce (a merge redirects to exactly ONE canonical head; only
    /// a split resolves to a set).
    pub(crate) fn entity_lifecycle_state_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<EntityLifecycleState> {
        let merged = self.filtered_edge_peers(
            rtxn,
            &self.store.edges_out,
            id,
            EdgeKind::MergedInto,
            None,
            "identity topology",
        )?;
        let split = self.filtered_edge_peers(
            rtxn,
            &self.store.edges_out,
            id,
            EdgeKind::SplitInto,
            None,
            "identity topology",
        )?;
        match (merged.len(), split.is_empty()) {
            (0, true) => Ok(EntityLifecycleState::Active),
            (1, true) => Ok(EntityLifecycleState::Merged),
            (0, false) => Ok(EntityLifecycleState::Split),
            _ => Err(Error::CorruptedIndex("identity topology shell")),
        }
    }

    /// Applies one identity-topology op in ONE write transaction: validates
    /// the bound actor (existence + type/class fit, the provenance rule),
    /// the storage guards, and the (state, op) transition table; then per
    /// the consent axis writes the canonical shell edges plus the type-76
    /// ledger event (`Auto`/`Approved`), parks the event with zero topology
    /// effects (`Proposed`), or no-ops (`Rejected`). Fail-closed — nothing
    /// is written on any rejection. No participant is tombstoned and no
    /// claim subject is rewritten (r1/r6).
    ///
    /// Facet and assert_distinct ops are validated through the same table
    /// but their apply doors are not armed yet
    /// ([`Error::IdentityTopologyUnarmed`]): a door that recorded an event
    /// without its effect would corrupt the ledger's meaning. Facet minting
    /// arms in ONE-1745; distinct_from storage in ONE-1746.
    pub fn apply_identity_topology_op(
        &self,
        op: &IdentityTopologyOp,
        write: &IdentityOpWrite,
        now: u64,
    ) -> Result<IdentityOpOutcome> {
        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.apply_identity_topology_op_in_txn(&mut wtxn, op, write, now)?;
        wtxn.commit()?;
        Ok(outcome)
    }

    /// Transaction-composable [`Vault::apply_identity_topology_op`].
    pub(crate) fn apply_identity_topology_op_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        op: &IdentityTopologyOp,
        write: &IdentityOpWrite,
        now: u64,
    ) -> Result<IdentityOpOutcome> {
        if write.approval == ClaimApprovalStatus::Rejected {
            return Ok(IdentityOpOutcome::Noop);
        }
        self.validate_identity_op_actor_in_txn(&*wtxn, write)?;

        let participants = op.participants();
        match self.validate_identity_op_participants_in_txn(&*wtxn, op)? {
            IdentityTopologyParticipantValidation::Complete => {}
            IdentityTopologyParticipantValidation::Deferred => {
                return Err(Error::EntityNotFound);
            }
            IdentityTopologyParticipantValidation::Invalid(rejection) => {
                return Err(Error::IdentityTopologyRejected(rejection));
            }
        }
        let mut states = BTreeMap::new();
        for participant in &participants {
            states.insert(
                *participant,
                self.entity_lifecycle_state_in_txn(&*wtxn, participant)?,
            );
        }
        let transitions =
            evaluate_transition(&states, op).map_err(Error::IdentityTopologyRejected)?;

        match op {
            IdentityTopologyOp::Merge(merge) => {
                let action = StoredIdentityOpAction::Merge {
                    sources: merge.sources.clone(),
                    survivor: merge.survivor,
                };
                let mut edges = Vec::new();
                if write.is_effective() {
                    let weight = shell_edge_weight(EdgeKind::MergedInto)?;
                    for source in &merge.sources {
                        edges.push(BatchOp::EdgeWithCreatedAt {
                            src: *source,
                            kind: EdgeKind::MergedInto,
                            tgt: merge.survivor,
                            weight,
                            created_at: now,
                            vad: crate::affect::Vad::NEUTRAL,
                            provenance: None,
                        });
                    }
                }
                self.write_identity_event_in_txn(
                    wtxn,
                    write,
                    now,
                    action,
                    Some(merge.evidence.clone()),
                    edges,
                    transitions,
                )
            }
            IdentityTopologyOp::Split(split) => {
                let action = StoredIdentityOpAction::Split {
                    entity: split.entity,
                    heads: split.heads.clone(),
                    reassignment: split.reassignment.canonicalized(),
                };
                let mut edges = Vec::new();
                if write.is_effective() {
                    let weight = shell_edge_weight(EdgeKind::SplitInto)?;
                    for head in &split.heads {
                        edges.push(BatchOp::EdgeWithCreatedAt {
                            src: split.entity,
                            kind: EdgeKind::SplitInto,
                            tgt: *head,
                            weight,
                            created_at: now,
                            vad: crate::affect::Vad::NEUTRAL,
                            provenance: None,
                        });
                    }
                }
                self.write_identity_event_in_txn(
                    wtxn,
                    write,
                    now,
                    action,
                    Some(split.evidence.clone()),
                    edges,
                    transitions,
                )
            }
            IdentityTopologyOp::Facet(_) => Err(Error::IdentityTopologyUnarmed("facet minting")),
            IdentityTopologyOp::AssertDistinct(_) => {
                Err(Error::IdentityTopologyUnarmed("distinct_from assertion"))
            }
        }
    }

    /// Undoes one applied merge/split event: appends the counter-event to
    /// the ledger (never rewriting the original) and removes the shell
    /// edges it wrote, restoring `Active`. Currency is judged by the FOLD
    /// over the whole event family ordered by the engine-stamped `seq` —
    /// the event must still be the current topology writer for every entity
    /// it shelled; an already-undone, superseded, or parked event is
    /// rejected with [`IdentityTopologyRejection::NotCurrent`]. Undo of a
    /// counter-event is rejected with
    /// [`IdentityTopologyRejection::NotUndoable`]. The consent axis applies
    /// like the apply door: `Proposed` parks the counter-event with the
    /// shell edges untouched; `Rejected` is the consent no-op.
    pub fn undo_identity_topology_event(
        &self,
        event: &EntityId,
        write: &IdentityOpWrite,
        now: u64,
    ) -> Result<IdentityOpOutcome> {
        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.undo_identity_topology_event_in_txn(&mut wtxn, event, write, now)?;
        wtxn.commit()?;
        Ok(outcome)
    }

    /// Transaction-composable [`Vault::undo_identity_topology_event`].
    pub(crate) fn undo_identity_topology_event_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        event: &EntityId,
        write: &IdentityOpWrite,
        now: u64,
    ) -> Result<IdentityOpOutcome> {
        if write.approval == ClaimApprovalStatus::Rejected {
            return Ok(IdentityOpOutcome::Noop);
        }
        self.validate_identity_op_actor_in_txn(&*wtxn, write)?;

        let record = self
            .identity_topology_event_in_txn(&*wtxn, event)?
            .ok_or(Error::EntityNotFound)?;
        let (shelled, removed_edges) = match &record.action {
            StoredIdentityOpAction::Undo { .. } => {
                return Err(Error::IdentityTopologyRejected(
                    IdentityTopologyRejection::NotUndoable { event: *event },
                ));
            }
            StoredIdentityOpAction::Merge { sources, survivor } => (
                sources.clone(),
                sources
                    .iter()
                    .map(|source| (*source, EdgeKind::MergedInto, *survivor))
                    .collect::<Vec<_>>(),
            ),
            StoredIdentityOpAction::Split { entity, heads, .. } => (
                vec![*entity],
                heads
                    .iter()
                    .map(|head| (*entity, EdgeKind::SplitInto, *head))
                    .collect::<Vec<_>>(),
            ),
        };

        let events = self.fold_effective_identity_topology_events_in_txn(&*wtxn)?;
        let fold = fold_identity_topology_log(&events);
        for entity in &shelled {
            if fold.current_event.get(entity) != Some(event) {
                return Err(Error::IdentityTopologyRejected(
                    IdentityTopologyRejection::NotCurrent { event: *event },
                ));
            }
        }

        let mut edges = Vec::new();
        if write.is_effective() {
            for (src, kind, tgt) in removed_edges {
                edges.push(BatchOp::DeleteEdge {
                    src,
                    kind,
                    tgt,
                    replicated_consent_verified: false,
                });
            }
        }
        let transitions = shelled
            .into_iter()
            .map(|entity| (entity, EntityLifecycleState::Active))
            .collect();
        self.write_identity_event_in_txn(
            wtxn,
            write,
            now,
            StoredIdentityOpAction::Undo { target: *event },
            None,
            edges,
            transitions,
        )
    }

    /// Reads one type-76 ledger event record. `Ok(None)` when the id is
    /// absent; a present id of another type is a typed mismatch; a present
    /// record that fails decode is corruption (the family is engine-
    /// authored and door-validated).
    pub fn identity_topology_event(&self, id: &EntityId) -> Result<Option<StoredIdentityOpEvent>> {
        let rtxn = self.store.env.read_txn()?;
        self.identity_topology_event_in_txn(&rtxn, id)
    }

    /// Transaction-composable [`Vault::identity_topology_event`].
    pub(crate) fn identity_topology_event_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<StoredIdentityOpEvent>> {
        let Some(raw) = self.store.entities.get(rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        // A STORED row that fails decode is on-disk corruption (the family
        // is engine-authored and door-validated on every admit path) —
        // classified as `CorruptedIndex`, never as the
        // `InvalidIdentityTopologyEventBody` ingress rejection, so local
        // damage can never be quarantine-classified as a rejectable
        // remote input.
        decode_identity_topology_event_body(&raw[ENTITY_METADATA_HEADER_LEN..])
            .map(Some)
            .map_err(|_| Error::CorruptedIndex("identity topology event body"))
    }

    /// The whole identity-topology event family, read from the type-76
    /// record index — the ONE enumeration surface the fold, the receipt
    /// projection, and any rebuild share (no side index is authoritative).
    /// Fail-closed: the family is engine-authored, so an undecodable row is
    /// corruption, never skipped.
    pub(crate) fn identity_topology_events_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
    ) -> Result<Vec<IdentityTopologyEvent>> {
        let mut events = Vec::new();
        for entry in self
            .store
            .type_index
            .prefix_iter(rtxn, &[ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT])?
        {
            let (key, _) = entry?;
            let event_id = crate::vault::entity_id_from_type_index_key(&key)?;
            let record = self
                .identity_topology_event_in_txn(rtxn, &event_id)?
                .ok_or(Error::CorruptedIndex("identity topology event index"))?;
            events.push(IdentityTopologyEvent {
                event_id,
                seq: record.seq,
                approval: record.approval,
                action: record.action.to_fold_action(),
            });
        }
        Ok(events)
    }

    /// Shared participant/storage validator for both the local topology
    /// door and replicated type-76 admission. Completeness is event-wide:
    /// one absent participant defers the WHOLE event, so a multi-source
    /// merge or multi-head split can never authorize a partial shell.
    /// Available participants must be structural and merge participants
    /// may never be FACETs.
    fn validate_identity_op_participants_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        op: &IdentityTopologyOp,
    ) -> Result<IdentityTopologyParticipantValidation> {
        let is_merge = matches!(op, IdentityTopologyOp::Merge(_));
        let mut validation = IdentityTopologyParticipantValidation::Complete;
        for participant in op.participants() {
            let Some(entity_type) = self.get_entity_type_in_txn(rtxn, &participant)? else {
                validation = IdentityTopologyParticipantValidation::Deferred;
                continue;
            };
            if !is_structural_kind(entity_type) {
                return Ok(IdentityTopologyParticipantValidation::Invalid(
                    IdentityTopologyRejection::NotStructural {
                        entity: participant,
                    },
                ));
            }
            if is_merge && entity_type == ENTITY_TYPE_FACET {
                return Ok(IdentityTopologyParticipantValidation::Invalid(
                    IdentityTopologyRejection::FacetMerge {
                        entity: participant,
                    },
                ));
            }
        }
        Ok(validation)
    }

    /// Pre-mutation validation for one replicated record. Missing apply
    /// participants and a missing undo target are deferred; any available
    /// participant uses the exact same structural/FACET validator as the
    /// local apply door, and an available undo target must be a type-76
    /// event rather than an arbitrary entity row.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn validate_replicated_identity_topology_event_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        record: &StoredIdentityOpEvent,
    ) -> Result<()> {
        validate_replicated_identity_topology_seq(record.seq)?;
        // An absent actor is a reference deferral, just like an absent
        // participant: the immutable event may land, but the effective fold
        // excludes it until the actor materializes and its class can be
        // checked. An available mismatched actor rejects before mutation.
        self.validate_replicated_identity_topology_actor_in_txn(rtxn, record)?;
        match record.action.to_fold_action() {
            IdentityTopologyAction::Apply(op) => {
                if let IdentityTopologyParticipantValidation::Invalid(rejection) =
                    self.validate_identity_op_participants_in_txn(rtxn, &op)?
                {
                    return Err(Error::IdentityTopologyRejected(rejection));
                }
            }
            IdentityTopologyAction::Undo { target } => {
                let Some(entity_type) = self.get_entity_type_in_txn(rtxn, &target)? else {
                    return Ok(());
                };
                if entity_type != ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
                    return Err(Error::InvalidEntityType(entity_type));
                }
                let target_record = self
                    .identity_topology_event_in_txn(rtxn, &target)?
                    .ok_or(Error::CorruptedIndex("identity topology event index"))?;
                if let IdentityTopologyAction::Apply(op) = target_record.action.to_fold_action()
                    && let IdentityTopologyParticipantValidation::Invalid(rejection) =
                        self.validate_identity_op_participants_in_txn(rtxn, &op)?
                {
                    return Err(Error::IdentityTopologyRejected(rejection));
                }
            }
        }
        Ok(())
    }

    /// Event projection used wherever topology authority is consumed.
    /// Stored records remain immutable ledger evidence, but an apply record
    /// with an available invalid participant (or an undo naming an
    /// available non-event) is excluded from the effective fold. Missing
    /// references remain deferred and are reconsidered on materialization.
    fn fold_effective_identity_topology_events_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
    ) -> Result<Vec<IdentityTopologyEvent>> {
        let events = self.identity_topology_events_in_txn(rtxn)?;
        let mut effective = Vec::with_capacity(events.len());
        for event in events {
            let references_complete = match &event.action {
                IdentityTopologyAction::Apply(op) => matches!(
                    self.validate_identity_op_participants_in_txn(rtxn, op)?,
                    IdentityTopologyParticipantValidation::Complete
                ),
                IdentityTopologyAction::Undo { target } => self
                    .get_entity_type_in_txn(rtxn, target)?
                    .is_some_and(|entity_type| entity_type == ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT),
            };
            let actor_complete = match self.identity_topology_event_in_txn(rtxn, &event.event_id)? {
                Some(record) => {
                    match self.validate_replicated_identity_topology_actor_in_txn(rtxn, &record) {
                        Ok(complete) => complete,
                        Err(Error::ActorClassMismatch { .. }) => false,
                        Err(err) => return Err(err),
                    }
                }
                None => return Err(Error::CorruptedIndex("identity topology event index")),
            };
            if references_complete && actor_complete {
                effective.push(event);
            }
        }
        Ok(effective)
    }

    /// `true` when an event's optional actor is available and class-valid;
    /// `false` when the actor reference is absent and therefore deferred.
    fn validate_replicated_identity_topology_actor_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        record: &StoredIdentityOpEvent,
    ) -> Result<bool> {
        let Some(actor) = record.actor else {
            return Ok(true);
        };
        let Some(actor_type) = self.get_entity_type_in_txn(rtxn, &actor.entity_ref())? else {
            return Ok(false);
        };
        crate::provenance::validate_actor_class(actor_type, actor.actor_class())?;
        Ok(true)
    }

    fn validate_identity_op_actor_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        write: &IdentityOpWrite,
    ) -> Result<()> {
        let Some(actor) = write.actor else {
            return Ok(());
        };
        let actor_type = self
            .get_entity_type_in_txn(rtxn, &actor.entity_ref())?
            .ok_or(Error::EntityNotFound)?;
        crate::provenance::validate_actor_class(actor_type, actor.actor_class())
    }

    /// Reads the engine-stamped causality clock (0 when never advanced).
    fn read_identity_topology_seq_in_txn(&self, rtxn: &heed::RoTxn<'_>) -> Result<u64> {
        match self.store.vault_meta.get(rtxn, IDENTITY_TOPOLOGY_SEQ_KEY)? {
            None => Ok(0),
            Some(raw) => {
                let arr: [u8; 8] = raw
                    .as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("identity topology seq"))?;
                Ok(u64::from_be_bytes(arr))
            }
        }
    }

    /// Allocates the next engine-stamped causality sequence, inside the
    /// caller's write txn (a rolled-back op burns no committed gap).
    fn next_identity_topology_seq_in_txn(&self, wtxn: &mut heed::RwTxn<'_>) -> Result<u64> {
        let previous = self.read_identity_topology_seq_in_txn(&*wtxn)?;
        let next = previous
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("identity topology seq"))?;
        if next >= IDENTITY_TOPOLOGY_REPLICATED_SEQ_CEILING {
            return Err(Error::InvalidIdentityTopologyEventBody(
                "identity topology event seq is in the reserved terminal range",
            ));
        }
        self.store
            .vault_meta
            .put(wtxn, IDENTITY_TOPOLOGY_SEQ_KEY, &next.to_be_bytes())?;
        Ok(next)
    }

    /// Joins a replicated record's engine-stamped `seq` into the local
    /// causality clock: `seq = max(local, incoming)`, in the caller's write
    /// txn. Every sync ingest path (fresh accept, idempotent replay,
    /// rebuild) runs this join, so a LOCAL event allocated after ingest can
    /// never order before the ingested history in the `(seq, event_id)`
    /// fold — without it, an undo of a synced merge folds BEFORE the merge
    /// it targets, is rejected `NotCurrent`, and ledger and edge truth
    /// permanently diverge.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn advance_identity_topology_seq_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        incoming_seq: u64,
    ) -> Result<()> {
        if incoming_seq > self.read_identity_topology_seq_in_txn(&*wtxn)? {
            self.store.vault_meta.put(
                wtxn,
                IDENTITY_TOPOLOGY_SEQ_KEY,
                &incoming_seq.to_be_bytes(),
            )?;
        }
        Ok(())
    }

    /// The shell edges the ledger fold currently mandates for `entity`, as
    /// `(kind, target, created_at)` rows derived from its current topology
    /// writer — empty for `Active`. `created_at` is the current event's
    /// recorded `at`, matching the bytes the origin door wrote so replicas
    /// converge byte-identically.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    fn desired_shell_edges_for_entity_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        fold: &IdentityTopologyFold,
        entity: &EntityId,
    ) -> Result<Vec<(EdgeKind, EntityId, u64)>> {
        let state = fold
            .states
            .get(entity)
            .copied()
            .unwrap_or(EntityLifecycleState::Active);
        if state == EntityLifecycleState::Active {
            return Ok(Vec::new());
        }
        let event_id = fold
            .current_event
            .get(entity)
            .ok_or(Error::CorruptedIndex("identity topology fold"))?;
        let record = self
            .identity_topology_event_in_txn(rtxn, event_id)?
            .ok_or(Error::CorruptedIndex("identity topology event index"))?;
        Ok(match (&record.action, state) {
            (StoredIdentityOpAction::Merge { survivor, .. }, EntityLifecycleState::Merged) => {
                vec![(EdgeKind::MergedInto, *survivor, record.at)]
            }
            (StoredIdentityOpAction::Split { heads, .. }, EntityLifecycleState::Split) => heads
                .iter()
                .map(|head| (EdgeKind::SplitInto, *head, record.at))
                .collect(),
            _ => return Err(Error::CorruptedIndex("identity topology fold")),
        })
    }

    /// When the current ledger fold mandates exactly this shell edge,
    /// returns the mandating event's `at` (the `created_at` the door
    /// writes); `None` otherwise. This is the sync doors' admission
    /// predicate for the reserved kinds (`merged_into` / `split_into`): a
    /// replicated 21/22 edge may land ONLY as the byte-exact echo of a
    /// validated, locally ingested type-76 event that is the source
    /// entity's current topology writer — callers must also pin the value
    /// bytes (default weight + this `at`), because peer-chosen bytes on a
    /// mandated pair are still a forgery (weight 0 silently drops the
    /// shell's PPR mass, unledgered). Folds the whole (rare,
    /// quota-bounded) event family per call.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn identity_topology_mandated_shell_edge_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
    ) -> Result<Option<u64>> {
        let events = self.fold_effective_identity_topology_events_in_txn(rtxn)?;
        let fold = fold_identity_topology_log(&events);
        let desired = self.desired_shell_edges_for_entity_in_txn(rtxn, &fold, src)?;
        Ok(desired
            .iter()
            .find(|(desired_kind, target, _)| *desired_kind == kind && target == tgt)
            .map(|(_, _, at)| *at))
    }

    /// Reconciles the canonical shell edges of every source entity named by
    /// the event family to the CURRENT ledger fold, inside the caller's write txn —
    /// the sync-ingest twin of the local door's edge side-effects (the
    /// ruled invariant: a `merged_into` / `split_into` edge only ever moves
    /// as the side-effect of a validated type-76 event). Edges the fold no
    /// longer mandates are deleted; mandated edges are written when both
    /// endpoints are materialized locally — a deferred endpoint leaves the
    /// edge to the sync edges-map pass, whose admission runs the same
    /// ledger predicate after hydrating endpoints. An undo counter-event
    /// arriving before its target reconciles nothing yet: the target's own
    /// ingest reruns this with the full fold, and the seq join makes the
    /// outcome order-independent.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn reconcile_identity_topology_edges_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
    ) -> Result<()> {
        reconcile_identity_topology_edges_for_store_in_txn(
            &self.store,
            &self.config,
            &self.analyzer,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            wtxn,
        )
    }

    /// Stamps `seq`, writes the type-76 event record plus the staged edge
    /// ops atomically, and shapes the outcome from the consent axis.
    #[expect(
        clippy::too_many_arguments,
        reason = "single internal chokepoint for the door's event+edges commit"
    )]
    fn write_identity_event_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        write: &IdentityOpWrite,
        now: u64,
        action: StoredIdentityOpAction,
        evidence: Option<IdentityOpEvidence>,
        edges: Vec<BatchOp>,
        transitions: Vec<(EntityId, EntityLifecycleState)>,
    ) -> Result<IdentityOpOutcome> {
        let event_id = EntityId::now();
        let seq = self.next_identity_topology_seq_in_txn(wtxn)?;
        let record = StoredIdentityOpEvent {
            seq,
            at: now,
            actor: write.actor,
            source: write.source,
            approval: write.approval,
            confidence: write.confidence,
            evidence,
            action,
        };
        let mut ops = vec![BatchOp::Put {
            id: event_id,
            entity_type: ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            data: encode_identity_topology_event_body(&record)?,
            allow_maintenance: true,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }];
        ops.extend(edges);
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        if write.is_effective() {
            Ok(IdentityOpOutcome::Applied {
                event: event_id,
                transitions,
            })
        } else {
            Ok(IdentityOpOutcome::Parked { event: event_id })
        }
    }
}

#[cfg(test)]
mod tests;
