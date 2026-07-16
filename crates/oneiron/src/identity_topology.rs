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
//! `split_into` edges are canonical and carry no body-field twin. The ledger
//! events are type-0 CLAIM rows under [`PREDICATE_IDENTITY_TOPOLOGY_OP`]
//! riding the existing deterministic gate fold with
//! [`ClaimApprovalStatus::Auto`] by default (ARCH-0055 r3 — the propose lane
//! is an explicit caller choice, never a mandatory human queue), and they
//! project into the receipt family as `ReceiptKind::IdentityLifecycle`
//! records. Undo is a counter-event over the ledger,
//! never a rewrite (r1); claim subjects are never eagerly rewritten (r6) —
//! read-time canonicalization through the redirect projection is ONE-1744.
//! Reassignment-map application and FACET minting arm in ONE-1745;
//! `entity.distinct_from` claim storage arms in ONE-1746.

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use crate::affect::Vad;
use crate::batch::{BatchOp, apply_ops};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    encode_claim_body,
};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, is_structural_kind};
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

/// Predicate of one identity-topology ledger event CLAIM (merge / split /
/// undo counter-event). ARCH-0055 names the `entity.*` predicate namespace
/// for this family (§9 pins `entity.distinct_from`); the ledger predicate
/// itself is engine-chosen within that namespace.
pub const PREDICATE_IDENTITY_TOPOLOGY_OP: &str = "entity.identity_op";

/// Predicate of the anti-merge claim (ARCH-0055 §9 G.1 row): symmetric
/// `entity.distinct_from` pair, conflict-set keyed by [`distinct_pair_key`].
/// Declared here as the family's contract; the write path — a
/// `CLAIM_PREDICATE_REGISTRY` entry plus the literal-dispatch match arm in
/// `claim.rs` — arms in ONE-1746 together with re-proposal suppression.
pub const PREDICATE_ENTITY_DISTINCT_FROM: &str = "entity.distinct_from";

/// vault_meta key prefix indexing identity-topology ledger events for the
/// receipt projection: `idtop:` ‖ at(8 BE) ‖ event claim id(16). The index
/// is enumeration plumbing only — rebuildable from the event CLAIMs, never
/// authoritative (CID-7 law; the claim row stays the single truth).
pub(crate) const IDENTITY_TOPOLOGY_EVENT_META_PREFIX: &[u8] = b"idtop:";

fn identity_topology_event_meta_key(at: u64, event_id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(IDENTITY_TOPOLOGY_EVENT_META_PREFIX.len() + 8 + ENTITY_ID_LEN);
    key.extend_from_slice(IDENTITY_TOPOLOGY_EVENT_META_PREFIX);
    key.extend_from_slice(&at.to_be_bytes());
    key.extend_from_slice(event_id.as_bytes());
    key
}

const VALUE_KEY_KIND: &str = "kind";
const VALUE_KEY_AT: &str = "at";
const VALUE_KEY_ACTOR: &str = "actor";
const VALUE_KEY_ACTOR_CLASS: &str = "actor_class";
const VALUE_KEY_SOURCES: &str = "sources";
const VALUE_KEY_SURVIVOR: &str = "survivor";
const VALUE_KEY_PLAN: &str = "plan";
const VALUE_KEY_ENTITY: &str = "entity";
const VALUE_KEY_HEADS: &str = "heads";
const VALUE_KEY_ASSIGNED: &str = "assigned";
const VALUE_KEY_RESIDUE: &str = "residue";
const VALUE_KEY_TARGET: &str = "target";

const EVENT_KIND_MERGE: &str = "merge";
const EVENT_KIND_SPLIT: &str = "split";
const EVENT_KIND_UNDO: &str = "undo";

const PLAN_READ_THROUGH: &str = "read_through";

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
/// decision plus the agent's stated rationale. Stored on the ledger event's
/// `evid` field — receipts explain, they never gate (r3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityOpEvidence {
    /// Entities (claims, turns, mentions, …) the decision points back to.
    pub refs: Vec<EntityId>,
    /// Free-form rationale from the deciding agent or user.
    pub rationale: String,
}

impl IdentityOpEvidence {
    fn encode(&self) -> Value {
        Value::Map(vec![
            (Value::from("refs"), ids_value(&self.refs)),
            (
                Value::from("rationale"),
                Value::from(self.rationale.as_str()),
            ),
        ])
    }
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
#[derive(Debug, Clone, Copy, PartialEq)]
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
/// MS-01 records the map and validates its targets; applying it to claims,
/// edges, and mention-links arms in ONE-1745.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReassignmentMap {
    /// Per-item assignments; items absent from the map are residue.
    pub entries: Vec<ReassignmentEntry>,
}

impl ReassignmentMap {
    fn assigned_and_residue_counts(&self) -> (u64, u64) {
        let assigned = self
            .entries
            .iter()
            .filter(|entry| !matches!(entry.target, ReassignmentTarget::Residue))
            .count() as u64;
        let residue = self.entries.len() as u64 - assigned;
        (assigned, residue)
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
    /// redirect projection lands (ONE-1744 lifts [`IdentityTopologyRejection::EmptyHeads`]).
    pub heads: Vec<EntityId>,
    /// Evidence-guided item map; application arms in ONE-1745.
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
    /// entities (already undone, superseded by a later re-apply, or never
    /// applied).
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
/// per-role state cells, then reassignment-map targets.
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
            for entry in &split.reassignment.entries {
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
            for entry in &facet.reassignment.entries {
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
    /// The event's CLAIM entity id (unique per event).
    pub event_id: EntityId,
    /// Event time (Unix seconds); the fold orders by `(at, event_id)`.
    pub at: u64,
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
/// `fold_authority_log` analogue. Events are ordered by `(at, event_id)`
/// so the fold is independent of input order; rejected events change
/// nothing and are recorded.
#[must_use]
pub fn fold_identity_topology_log(events: &[IdentityTopologyEvent]) -> IdentityTopologyFold {
    let mut ordered: Vec<&IdentityTopologyEvent> = events.iter().collect();
    ordered.sort_by_key(|event| (event.at, event.event_id));

    let mut fold = IdentityTopologyFold::default();
    let mut applied: BTreeMap<EntityId, &IdentityTopologyOp> = BTreeMap::new();
    let mut undo_events: BTreeSet<EntityId> = BTreeSet::new();

    for event in ordered {
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

// ─── Wire events ────────────────────────────────────────────────────────────

/// Action payload of one stored ledger event. The wire drops what the fold
/// does not evaluate: evidence lives on the claim's `evid` field, and the
/// reassignment map is recorded as its r2 stats (assigned / residue counts;
/// full map application arms in ONE-1745).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredIdentityOpAction {
    /// A merge event.
    Merge {
        /// Losing entities.
        sources: Vec<EntityId>,
        /// Surviving canonical head.
        survivor: EntityId,
    },
    /// A split event with its r2 first-class stats.
    Split {
        /// The split original.
        entity: EntityId,
        /// Head entities.
        heads: Vec<EntityId>,
        /// Reassignment rows targeting a head.
        assigned: u64,
        /// Reassignment rows left as ambiguous residue.
        residue: u64,
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

    /// Reconstructs the fold-grade action: evidence, survivorship plan and
    /// reassignment map do not participate in transition evaluation.
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
            Self::Split { entity, heads, .. } => {
                IdentityTopologyAction::Apply(IdentityTopologyOp::Split(SplitOp {
                    entity: *entity,
                    heads: heads.clone(),
                    reassignment: ReassignmentMap::default(),
                    evidence: IdentityOpEvidence::default(),
                }))
            }
            Self::Undo { target } => IdentityTopologyAction::Undo { target: *target },
        }
    }
}

/// One identity-topology ledger event as stored on the CLAIM's `val` field
/// (MessagePack map, pinned keys).
#[derive(Debug, Clone, PartialEq)]
pub struct StoredIdentityOpEvent {
    /// Event time (Unix seconds) — the `now` the apply path stamped.
    pub at: u64,
    /// Deciding actor, when the caller bound one (r1: events carry actor).
    pub actor: Option<WriteActor>,
    /// The recorded action.
    pub action: StoredIdentityOpAction,
}

impl StoredIdentityOpEvent {
    /// Encodes the event into its pinned MessagePack map.
    #[must_use]
    pub fn encode(&self) -> Value {
        let mut entries = Vec::new();
        let kind = match &self.action {
            StoredIdentityOpAction::Merge { .. } => EVENT_KIND_MERGE,
            StoredIdentityOpAction::Split { .. } => EVENT_KIND_SPLIT,
            StoredIdentityOpAction::Undo { .. } => EVENT_KIND_UNDO,
        };
        entries.push((Value::from(VALUE_KEY_KIND), Value::from(kind)));
        entries.push((Value::from(VALUE_KEY_AT), Value::from(self.at)));
        if let Some(actor) = self.actor {
            entries.push((Value::from(VALUE_KEY_ACTOR), id_value(&actor.entity_ref())));
            entries.push((
                Value::from(VALUE_KEY_ACTOR_CLASS),
                Value::from(actor.actor_class().gate_actor_class()),
            ));
        }
        match &self.action {
            StoredIdentityOpAction::Merge { sources, survivor } => {
                entries.push((Value::from(VALUE_KEY_SOURCES), ids_value(sources)));
                entries.push((Value::from(VALUE_KEY_SURVIVOR), id_value(survivor)));
                entries.push((Value::from(VALUE_KEY_PLAN), Value::from(PLAN_READ_THROUGH)));
            }
            StoredIdentityOpAction::Split {
                entity,
                heads,
                assigned,
                residue,
            } => {
                entries.push((Value::from(VALUE_KEY_ENTITY), id_value(entity)));
                entries.push((Value::from(VALUE_KEY_HEADS), ids_value(heads)));
                entries.push((Value::from(VALUE_KEY_ASSIGNED), Value::from(*assigned)));
                entries.push((Value::from(VALUE_KEY_RESIDUE), Value::from(*residue)));
            }
            StoredIdentityOpAction::Undo { target } => {
                entries.push((Value::from(VALUE_KEY_TARGET), id_value(target)));
            }
        }
        Value::Map(entries)
    }

    /// Decodes a stored event, fail-closed on any malformed field.
    pub fn decode(value: &Value) -> Result<Self> {
        let map = value
            .as_map()
            .ok_or(Error::InvalidClaimBody("identity op event must be a map"))?;
        let kind = decode_str_field(map, VALUE_KEY_KIND, "identity op event kind")?;
        let at = decode_u64_field(map, VALUE_KEY_AT, "identity op event at")?;
        let actor = decode_actor(map)?;
        let action = match kind {
            EVENT_KIND_MERGE => {
                let plan = decode_str_field(map, VALUE_KEY_PLAN, "identity op event plan")?;
                if plan != PLAN_READ_THROUGH {
                    return Err(Error::InvalidClaimBody("identity op event plan is unknown"));
                }
                StoredIdentityOpAction::Merge {
                    sources: decode_ids_field(map, VALUE_KEY_SOURCES, "identity op event sources")?,
                    survivor: decode_id_field(
                        map,
                        VALUE_KEY_SURVIVOR,
                        "identity op event survivor",
                    )?,
                }
            }
            EVENT_KIND_SPLIT => StoredIdentityOpAction::Split {
                entity: decode_id_field(map, VALUE_KEY_ENTITY, "identity op event entity")?,
                heads: decode_ids_field(map, VALUE_KEY_HEADS, "identity op event heads")?,
                assigned: decode_u64_field(map, VALUE_KEY_ASSIGNED, "identity op event assigned")?,
                residue: decode_u64_field(map, VALUE_KEY_RESIDUE, "identity op event residue")?,
            },
            EVENT_KIND_UNDO => StoredIdentityOpAction::Undo {
                target: decode_id_field(map, VALUE_KEY_TARGET, "identity op event target")?,
            },
            _ => {
                return Err(Error::InvalidClaimBody("identity op event kind is unknown"));
            }
        };
        Ok(Self { at, actor, action })
    }
}

fn id_value(id: &EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

fn ids_value(ids: &[EntityId]) -> Value {
    Value::Array(ids.iter().map(id_value).collect())
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
        .ok_or(Error::InvalidClaimBody(context))
}

fn decode_u64_field(map: &[(Value, Value)], key: &str, context: &'static str) -> Result<u64> {
    map_field(map, key)
        .and_then(Value::as_u64)
        .ok_or(Error::InvalidClaimBody(context))
}

fn decode_id_value(value: &Value, context: &'static str) -> Result<EntityId> {
    let bytes = value.as_slice().ok_or(Error::InvalidClaimBody(context))?;
    let arr: [u8; 16] = bytes
        .try_into()
        .map_err(|_| Error::InvalidClaimBody(context))?;
    EntityId::from_bytes(arr).map_err(|_| Error::InvalidClaimBody(context))
}

fn decode_id_field(map: &[(Value, Value)], key: &str, context: &'static str) -> Result<EntityId> {
    decode_id_value(
        map_field(map, key).ok_or(Error::InvalidClaimBody(context))?,
        context,
    )
}

fn decode_ids_field(
    map: &[(Value, Value)],
    key: &str,
    context: &'static str,
) -> Result<Vec<EntityId>> {
    let Some(Value::Array(items)) = map_field(map, key) else {
        return Err(Error::InvalidClaimBody(context));
    };
    items
        .iter()
        .map(|item| decode_id_value(item, context))
        .collect()
}

fn decode_actor(map: &[(Value, Value)]) -> Result<Option<WriteActor>> {
    let entity = map_field(map, VALUE_KEY_ACTOR);
    let class = map_field(map, VALUE_KEY_ACTOR_CLASS);
    match (entity, class) {
        (None, None) => Ok(None),
        (Some(entity), Some(class)) => {
            let entity_ref = decode_id_value(entity, "identity op event actor")?;
            let class = class
                .as_str()
                .and_then(parse_actor_class)
                .ok_or(Error::InvalidClaimBody("identity op event actor class"))?;
            Ok(Some(WriteActor::new(entity_ref, class)))
        }
        _ => Err(Error::InvalidClaimBody(
            "identity op event actor requires both entity and class",
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

/// Write metadata for one identity-topology op: the ARCH-0003 consent axes
/// the ledger event claim carries. AUTO is the family default (r3); the
/// propose lane is the caller dialing `approval` to `Proposed` for the
/// three exception conditions (§6) — never an engine-imposed gate.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IdentityOpWrite {
    /// Provenance source stamped on the event claim.
    pub source: ClaimSource,
    /// Consent axis for the event claim; `Auto` by default.
    pub approval: ClaimApprovalStatus,
    /// Confidence stamped on the event claim, finite in `[0, 1]`.
    pub confidence: f32,
    /// Deciding actor recorded on the event (r1), when bound.
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
}

/// Receipt of one applied (or undone) identity-topology op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityOpOutcome {
    /// The ledger event CLAIM written for this op.
    pub event: EntityId,
    /// Lifecycle assignments the op performed, in role order.
    pub transitions: Vec<(EntityId, EntityLifecycleState)>,
}

fn identity_event_put_ops(
    event_id: EntityId,
    subject: EntityId,
    value: Value,
    evidence: Option<Value>,
    write: &IdentityOpWrite,
    now: u64,
) -> Result<Vec<BatchOp>> {
    let mut body = ClaimBody::new(
        PREDICATE_IDENTITY_TOPOLOGY_OP,
        ClaimSubject::Entity(subject),
        value,
        write.confidence,
        write.approval,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(write.source);
    body.valid_from = Some(now);
    body.evidence = evidence;
    let data = encode_claim_body(&body)?;
    let claim_of_weight = EdgeKind::ClaimOf
        .default_weight()
        .ok_or(Error::InvariantViolation(
            "ClaimOf edge missing default weight",
        ))?;
    Ok(vec![
        BatchOp::Put {
            id: event_id,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
        },
        BatchOp::EdgeWithCreatedAt {
            src: event_id,
            kind: EdgeKind::ClaimOf,
            tgt: subject,
            weight: claim_of_weight,
            created_at: now,
            vad: Vad::NEUTRAL,
            provenance: None,
        },
    ])
}

fn shell_edge_weight(kind: EdgeKind) -> Result<f32> {
    kind.default_weight().ok_or(Error::InvariantViolation(
        "identity topology edge missing default weight",
    ))
}

impl Vault {
    /// Current lifecycle state of `id`, read from its canonical redirect
    /// edges (D11: the edge is the sole source of truth; the ledger fold and
    /// the apply path keep them in lockstep). An id with no shell edge —
    /// including one never written — is `Active`.
    pub fn entity_lifecycle_state(&self, id: &EntityId) -> Result<EntityLifecycleState> {
        let rtxn = self.store.env.read_txn()?;
        self.entity_lifecycle_state_in_txn(&rtxn, id)
    }

    /// Transaction-composable [`Vault::entity_lifecycle_state`]. Fails
    /// closed with `CorruptedIndex` when an id carries BOTH shell edge
    /// kinds — a state no apply path can produce.
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
        match (merged.is_empty(), split.is_empty()) {
            (true, true) => Ok(EntityLifecycleState::Active),
            (false, true) => Ok(EntityLifecycleState::Merged),
            (true, false) => Ok(EntityLifecycleState::Split),
            (false, false) => Err(Error::CorruptedIndex("identity topology shell")),
        }
    }

    /// Applies one identity-topology op in ONE write transaction: validates
    /// the storage guards and the (state, op) transition table, writes the
    /// canonical shell edges, and appends the ledger event CLAIM (evidence,
    /// rationale, actor; `Auto` by default). Fail-closed — nothing is
    /// written on any rejection. No participant is tombstoned and no claim
    /// subject is rewritten (r1/r6).
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
        let participants = op.participants();
        let is_merge = matches!(op, IdentityTopologyOp::Merge(_));
        let mut states = BTreeMap::new();
        for participant in &participants {
            let entity_type = self
                .get_entity_type_in_txn(&*wtxn, participant)?
                .ok_or(Error::EntityNotFound)?;
            if !is_structural_kind(entity_type) {
                return Err(Error::IdentityTopologyRejected(
                    IdentityTopologyRejection::NotStructural {
                        entity: *participant,
                    },
                ));
            }
            if is_merge && entity_type == ENTITY_TYPE_FACET {
                return Err(Error::IdentityTopologyRejected(
                    IdentityTopologyRejection::FacetMerge {
                        entity: *participant,
                    },
                ));
            }
            states.insert(
                *participant,
                self.entity_lifecycle_state_in_txn(&*wtxn, participant)?,
            );
        }
        let transitions =
            evaluate_transition(&states, op).map_err(Error::IdentityTopologyRejected)?;

        match op {
            IdentityTopologyOp::Merge(merge) => {
                let weight = shell_edge_weight(EdgeKind::MergedInto)?;
                let event_id = EntityId::now();
                let stored = StoredIdentityOpEvent {
                    at: now,
                    actor: write.actor,
                    action: StoredIdentityOpAction::Merge {
                        sources: merge.sources.clone(),
                        survivor: merge.survivor,
                    },
                };
                let mut ops = identity_event_put_ops(
                    event_id,
                    merge.survivor,
                    stored.encode(),
                    Some(merge.evidence.encode()),
                    write,
                    now,
                )?;
                for source in &merge.sources {
                    ops.push(BatchOp::EdgeWithCreatedAt {
                        src: *source,
                        kind: EdgeKind::MergedInto,
                        tgt: merge.survivor,
                        weight,
                        created_at: now,
                        vad: Vad::NEUTRAL,
                        provenance: None,
                    });
                }
                self.commit_identity_event_in_txn(wtxn, ops, now, &event_id)?;
                Ok(IdentityOpOutcome {
                    event: event_id,
                    transitions,
                })
            }
            IdentityTopologyOp::Split(split) => {
                let weight = shell_edge_weight(EdgeKind::SplitInto)?;
                let event_id = EntityId::now();
                let (assigned, residue) = split.reassignment.assigned_and_residue_counts();
                let stored = StoredIdentityOpEvent {
                    at: now,
                    actor: write.actor,
                    action: StoredIdentityOpAction::Split {
                        entity: split.entity,
                        heads: split.heads.clone(),
                        assigned,
                        residue,
                    },
                };
                let mut ops = identity_event_put_ops(
                    event_id,
                    split.entity,
                    stored.encode(),
                    Some(split.evidence.encode()),
                    write,
                    now,
                )?;
                for head in &split.heads {
                    ops.push(BatchOp::EdgeWithCreatedAt {
                        src: split.entity,
                        kind: EdgeKind::SplitInto,
                        tgt: *head,
                        weight,
                        created_at: now,
                        vad: Vad::NEUTRAL,
                        provenance: None,
                    });
                }
                self.commit_identity_event_in_txn(wtxn, ops, now, &event_id)?;
                Ok(IdentityOpOutcome {
                    event: event_id,
                    transitions,
                })
            }
            IdentityTopologyOp::Facet(_) => Err(Error::IdentityTopologyUnarmed("facet minting")),
            IdentityTopologyOp::AssertDistinct(_) => {
                Err(Error::IdentityTopologyUnarmed("distinct_from assertion"))
            }
        }
    }

    /// Undoes one applied merge/split event: appends the counter-event to
    /// the ledger (never rewriting the original) and removes the shell
    /// edges it wrote, restoring `Active`. Currency is judged by the
    /// subject's own ledger fold — the event must still be the current
    /// topology writer for every entity it shelled; an already-undone or
    /// superseded event is rejected with
    /// [`IdentityTopologyRejection::NotCurrent`]. Undo of a counter-event
    /// is rejected with [`IdentityTopologyRejection::NotUndoable`].
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
        let body = self
            .get_claim_in_txn(&*wtxn, event)?
            .ok_or(Error::EntityNotFound)?;
        if body.predicate != PREDICATE_IDENTITY_TOPOLOGY_OP {
            return Err(Error::InvalidClaimBody(
                "entity is not an identity-topology op event",
            ));
        }
        let ClaimSubject::Entity(subject) = body.subject else {
            return Err(Error::InvalidClaimBody(
                "identity op event subject must be an entity",
            ));
        };
        let stored = StoredIdentityOpEvent::decode(&body.value)?;
        let (shelled, removed_edges) = match &stored.action {
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

        let events = self.identity_events_for_subject_in_txn(&*wtxn, &subject)?;
        let fold = fold_identity_topology_log(&events);
        for entity in &shelled {
            if fold.current_event.get(entity) != Some(event) {
                return Err(Error::IdentityTopologyRejected(
                    IdentityTopologyRejection::NotCurrent { event: *event },
                ));
            }
        }

        let counter = StoredIdentityOpEvent {
            at: now,
            actor: write.actor,
            action: StoredIdentityOpAction::Undo { target: *event },
        };
        let counter_id = EntityId::now();
        let mut ops =
            identity_event_put_ops(counter_id, subject, counter.encode(), None, write, now)?;
        for (src, kind, tgt) in removed_edges {
            ops.push(BatchOp::DeleteEdge { src, kind, tgt });
        }
        self.commit_identity_event_in_txn(wtxn, ops, now, &counter_id)?;
        Ok(IdentityOpOutcome {
            event: counter_id,
            transitions: shelled
                .into_iter()
                .map(|entity| (entity, EntityLifecycleState::Active))
                .collect(),
        })
    }

    /// Identity-topology ledger events attached to `subject` (via the event
    /// claims' `claim_of` edges), ready for folding. Malformed values under
    /// the predicate are skipped: the predicate namespace is public D17
    /// grammar, so a garbage row must not be able to wedge undo — the
    /// canonical edges stay the structural truth either way.
    pub(crate) fn identity_events_for_subject_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        subject: &EntityId,
    ) -> Result<Vec<IdentityTopologyEvent>> {
        let mut events = Vec::new();
        for claim_id in self.claims_for_subject_in_txn(rtxn, subject)? {
            let Some(body) = self.get_claim_in_txn(rtxn, &claim_id)? else {
                continue;
            };
            if body.predicate != PREDICATE_IDENTITY_TOPOLOGY_OP {
                continue;
            }
            let Ok(stored) = StoredIdentityOpEvent::decode(&body.value) else {
                continue;
            };
            events.push(IdentityTopologyEvent {
                event_id: claim_id,
                at: stored.at,
                action: stored.action.to_fold_action(),
            });
        }
        Ok(events)
    }

    /// Applies the staged ops and indexes the ledger event for the
    /// `ReceiptKind::IdentityLifecycle` projection, atomically in the
    /// caller's wtxn. The index row is rebuildable plumbing (CID-7); the
    /// event CLAIM stays the single truth.
    fn commit_identity_event_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        ops: Vec<BatchOp>,
        at: u64,
        event_id: &EntityId,
    ) -> Result<()> {
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
        self.store
            .vault_meta
            .put(wtxn, &identity_topology_event_meta_key(at, event_id), &[])?;
        Ok(())
    }

    /// Ledger event claim ids from the receipt-projection index, in
    /// `(at, event_id)` order, capped at `scan_cap` rows.
    pub(crate) fn identity_topology_event_refs_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        scan_cap: usize,
    ) -> Result<Vec<EntityId>> {
        let mut refs = Vec::new();
        for row in self
            .store
            .vault_meta
            .prefix_iter(rtxn, IDENTITY_TOPOLOGY_EVENT_META_PREFIX)?
        {
            if refs.len() >= scan_cap {
                break;
            }
            let (key, _) = row?;
            let id_offset = IDENTITY_TOPOLOGY_EVENT_META_PREFIX.len() + 8;
            let Some(id_bytes) = key.get(id_offset..id_offset + ENTITY_ID_LEN) else {
                return Err(Error::CorruptedIndex("identity topology event index"));
            };
            let arr: [u8; ENTITY_ID_LEN] = id_bytes
                .try_into()
                .map_err(|_| Error::CorruptedIndex("identity topology event index"))?;
            let event_id = EntityId::from_bytes(arr)
                .map_err(|_| Error::CorruptedIndex("identity topology event index"))?;
            refs.push(event_id);
        }
        Ok(refs)
    }
}

#[cfg(test)]
mod tests;
