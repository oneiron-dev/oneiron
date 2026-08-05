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
//! never eagerly rewritten (r6) — read-time canonicalization runs through
//! the redirect projection in [`crate::identity_redirect`] (ONE-1744).
//! Reassignment-map application and FACET minting arm in ONE-1745;
//! `entity.distinct_from` claim storage arms in ONE-1746.
//!
//! Zero-head split (r2 "gone", ONE-1744): `split(entity, heads: [])` is a
//! legal deliberate retire-without-successor. It shells the original like
//! any split but writes NO `split_into` edge, so it is the one topology arm
//! the canonical edges structurally cannot witness — the type-76 ledger is
//! its sole witness. Everything that derives shell truth from edges
//! therefore consults the ledger for this arm too:
//! [`zero_head_split_shells_in_txn`] is that witness, and both the
//! lifecycle read and the redirect projection route through it. D11's
//! "edges are canonical" holds unchanged for every edge-ful op.

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
    entity_type_registry_entry, is_structural_kind,
};
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

/// Masks one facet op may mint (ONE-1745). A facet op names exactly ONE
/// pre-existing entity, so the participant bound above does not reach its
/// fan-out — minting is the op's own effect. Bounded by the same number for
/// the same reason: one op's write batch stays fixed-size.
pub(crate) const MAX_IDENTITY_TOPOLOGY_EVENT_FACETS: usize =
    MAX_IDENTITY_TOPOLOGY_EVENT_PARTICIPANTS;

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
const BODY_KEY_PROPOSAL: &str = "proposal";
const BODY_KEY_OUTCOME: &str = "outcome";
const BODY_KEY_SCOPE_OP_KIND: &str = "sc_op";
const BODY_KEY_SCOPE_TARGET_CLASS: &str = "sc_cls";
const BODY_KEY_SCOPE_ACTOR: &str = "sc_actor";
const BODY_KEY_AMENDED: &str = "amended";
/// Minted FACET entity ids of a facet event, in the op's spec order.
const BODY_KEY_FACETS: &str = "facets";
/// Map rows the apply door actually recorded, and rows it left as ambiguous
/// residue. DECLARED counts live in the map itself
/// ([`ReassignmentMap::assigned_and_residue_counts`]); these two are what
/// application produced, so the receipt can show the gap without a vault.
/// Omitted from the wire when zero, which keeps parked events and amendment
/// bodies byte-identical to their pre-ONE-1745 encoding.
const BODY_KEY_APPLIED_ASSIGNED: &str = "asg";
const BODY_KEY_APPLIED_RESIDUE: &str = "res";

const MAP_KEY_ITEM: &str = "item";
const MAP_KEY_HEAD: &str = "head";
const MAP_KEY_FACET: &str = "facet";

const EVENT_KIND_MERGE: &str = "merge";
const EVENT_KIND_SPLIT: &str = "split";
/// Wire kind of the ARCH-0055 r5 facet event (ONE-1745). Pinned string, in
/// the same reservation family as the other three kinds.
const EVENT_KIND_FACET: &str = "facet";
const EVENT_KIND_UNDO: &str = "undo";
/// Wire kind of the ARCH-0055 r7 proposal-resolution event (ONE-1747). The
/// resolution event IS the retirement of the park: the projector finds a
/// proposal already resolved by this row, so a second ruling is refused.
const EVENT_KIND_PROPOSAL_RESOLUTION: &str = "proposal_resolution";

/// Ramp-scope actor stamped when the resolved proposal bound no deciding
/// actor. The DEC-0006 tuple is total — an unattributed proposer is its own
/// scope, never an absent field (MS-06 rebuilds per-scope stats from
/// receipts ALONE, so a missing component would silently merge scopes).
pub const PROPOSAL_SCOPE_ACTOR_UNATTRIBUTED: &str = "unattributed";

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

/// What [`apply_reassignment_in_txn`] recorded for one op (ARCH-0055 r2).
///
/// APPLIED counts, not declared ones: a map row naming an item this vault
/// holds no CLAIM for records nothing, so `assigned + residue` may be below
/// [`ReassignmentMap::assigned_and_residue_counts`]. The receipt projects
/// both, and the gap is the visible witness that a decision named something
/// the vault does not have.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReassignmentStats {
    /// Rows recorded against a concrete head or facet.
    pub assigned: usize,
    /// Rows recorded as explicit ambiguous residue on the origin.
    pub residue: usize,
}

/// The concrete destinations one op's reassignment rows resolve against —
/// the split's heads, or the facet op's freshly minted masks in spec order.
///
/// [`evaluate_transition`] has already refused the cross-shaped rows (a
/// facet target on a split, a head target on a facet, an out-of-range facet
/// index, a head the op does not name), so resolution here is total.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ReassignmentContext<'a> {
    /// Split heads: a [`ReassignmentTarget::Head`] row resolves to itself.
    Heads(&'a [EntityId]),
    /// Minted masks: a [`ReassignmentTarget::Facet`] row resolves by index.
    Facets(&'a [EntityId]),
}

impl ReassignmentContext<'_> {
    /// The entity one map row routes to, or `None` for ambiguous residue.
    ///
    /// A row whose target shape is foreign to the context is corruption,
    /// never caller error: the transition table rejects those shapes before
    /// any door reaches this code.
    fn resolve(self, target: &ReassignmentTarget) -> Result<Option<EntityId>> {
        let resolved = match (self, target) {
            (Self::Heads(heads), ReassignmentTarget::Head(head)) => {
                heads.iter().copied().find(|candidate| candidate == head)
            }
            (Self::Facets(facets), ReassignmentTarget::Facet { index }) => {
                facets.get(*index as usize).copied()
            }
            (_, ReassignmentTarget::Residue) => return Ok(None),
            _ => None,
        };
        resolved.map(Some).ok_or(Error::InvariantViolation(
            "identity topology reassignment target is not in the op's context",
        ))
    }
}

/// `vault_meta` key prefix of the SPLIT assignment index, keyed by ORIGIN:
/// prefix ++ origin(16) ++ event(16) ++ claim(16). The value is a
/// [`REASSIGNMENT_ROW_VERSION`]-tagged head id, or the bare version byte for
/// explicit ambiguous residue.
///
/// Keyed by event, not just by origin, so a row is owned by exactly the
/// ledger event that stated it: undo deletes its own rows and can never
/// clobber another event's.
///
/// This const lives with the family rather than in `store.rs` for the reason
/// [`IDENTITY_TOPOLOGY_SEQ_KEY`] does — the family that owns the keyspace
/// owns its key shape, and `vault_meta` readers ignore unknown prefixes.
pub(crate) const REASSIGNMENT_ORIGIN_META_PREFIX: &[u8] = b"reassign:v1:o:";

/// `vault_meta` key prefix of the same index INVERTED by destination:
/// prefix ++ head(16) ++ event(16) ++ claim(16), value = the bare version
/// byte. [`Vault::claims_assigned_to`] is a prefix scan over this half; the
/// origin half alone would force a whole-table scan per query.
pub(crate) const REASSIGNMENT_TARGET_META_PREFIX: &[u8] = b"reassign:v1:t:";

/// Only accepted assignment-row version byte.
const REASSIGNMENT_ROW_VERSION: u8 = 1;

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
    /// through [`Vault::resolve_entity`].
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

// ─── Proposal resolution (ARCH-0055 r7) ─────────────────────────────────────

/// The ruling a decider applies to a parked `Proposed` identity-topology
/// event (ARCH-0055 r7 outcome vocabulary).
///
/// `AmendThenApprove` carries the amended op body as encoded bytes — the
/// form the decider actually approved, which is what gets applied and what
/// the outcome receipt preserves verbatim. The amendment NARROWS what the
/// owner reviewed: it can never become a different op kind nor reach an
/// entity the proposal did not name
/// ([`Error::IdentityProposalAmendmentOutOfScope`]).
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
    /// [`PROPOSAL_SCOPE_ACTOR_UNATTRIBUTED`] when the proposal bound none.
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
    /// Resolution of a parked `Proposed` event (r7, ONE-1747). Carries ZERO
    /// lifecycle effects of its own: an approving ruling applies the op as
    /// its own ordinary event, which the fold already folds. The fold
    /// tracks resolutions solely to answer "is this proposal still open?".
    ResolveProposal {
        /// The resolved proposal event.
        proposal: EntityId,
        /// The recorded outcome.
        outcome: ProposalOutcome,
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
    /// Resolved `Proposed` events keyed by proposal, with the r7 outcome the
    /// ruling recorded (ONE-1747) — the "is this park still open?" witness.
    /// First resolution wins: a resolution naming an already-resolved
    /// proposal is a fold rejection, never a silent overwrite.
    pub resolved_proposals: BTreeMap<EntityId, ProposalOutcome>,
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
            // A resolution carries no lifecycle effect of its own (the
            // approved op rides its own event). It only retires the park —
            // first resolution in `(seq, event_id)` order wins, so a
            // duplicate is a deterministic rejection on every replica.
            IdentityTopologyAction::ResolveProposal { proposal, outcome } => {
                if fold.resolved_proposals.contains_key(proposal) {
                    fold.rejections.push((
                        event.event_id,
                        IdentityTopologyRejection::ProposalAlreadyResolved {
                            proposal: *proposal,
                        },
                    ));
                } else {
                    fold.resolved_proposals.insert(*proposal, *outcome);
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
        /// Map rows the apply door recorded against a head (ONE-1745).
        applied_assigned: u64,
        /// Map rows it recorded as explicit ambiguous residue.
        applied_residue: u64,
    },
    /// A facet event and the masks it minted (ARCH-0022 type-13, ONE-1745).
    /// Every stored facet event is an APPLIED one: the propose lane is not
    /// armed for this kind (see [`Vault::apply_identity_topology_op`]), so
    /// `facets` is never empty and always names live FACET entities.
    Facet {
        /// The entity whose masks were partitioned; stays `Active` (r6).
        entity: EntityId,
        /// Minted FACET entity ids, in the op's spec order — the order every
        /// [`ReassignmentTarget::Facet`] index addresses.
        facets: Vec<EntityId>,
        /// Canonically ordered scoping map.
        reassignment: ReassignmentMap,
        /// Map rows the apply door scoped to a mask.
        applied_assigned: u64,
        /// Map rows it left unscoped.
        applied_residue: u64,
    },
    /// A counter-event reverting `target`.
    Undo {
        /// The reverted ledger event.
        target: EntityId,
    },
    /// The r7 resolution of a parked `Proposed` event (ONE-1747). Appending
    /// this row IS the retirement of the park: a proposal carrying one is
    /// already resolved and refuses a second ruling. The resolution itself
    /// moves no lifecycle state — on an approving ruling the APPLIED op is
    /// recorded as its own ordinary event, and this row records the
    /// decision about it.
    ProposalResolution {
        /// The resolved type-76 `Proposed` event.
        proposal: EntityId,
        /// Which of the three r7 states the ruling produced.
        outcome: ProposalOutcome,
        /// The DEC-0006 ramp scope, stamped from the resolved proposal.
        scope: ProposalScope,
        /// The encoded amended op body, present ONLY on
        /// [`ProposalOutcome::ApprovedAmended`] — preserved verbatim as the
        /// producer artifact ED-01 (ONE-1757) diffs against the proposal.
        amended_body: Option<Vec<u8>>,
    },
}

impl StoredIdentityOpAction {
    /// The pinned wire/receipt kind string for this action.
    #[must_use]
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::Merge { .. } => EVENT_KIND_MERGE,
            Self::Split { .. } => EVENT_KIND_SPLIT,
            Self::Facet { .. } => EVENT_KIND_FACET,
            Self::Undo { .. } => EVENT_KIND_UNDO,
            Self::ProposalResolution { .. } => EVENT_KIND_PROPOSAL_RESOLUTION,
        }
    }

    /// The reassignment map this action carries, if its op kind has one —
    /// the DECLARED decision (ARCH-0055 r2/r5).
    #[must_use]
    pub const fn reassignment_map(&self) -> Option<&ReassignmentMap> {
        match self {
            Self::Split { reassignment, .. } | Self::Facet { reassignment, .. } => {
                Some(reassignment)
            }
            Self::Merge { .. } | Self::Undo { .. } | Self::ProposalResolution { .. } => None,
        }
    }

    /// What the apply door actually RECORDED for that map (ONE-1745), which
    /// may be less than the map declared: a row naming an item the vault
    /// holds no CLAIM for records nothing.
    ///
    /// Stamped onto the event at apply time precisely so this read needs no
    /// vault — the receipt projector is a pure function of the record.
    #[must_use]
    pub const fn applied_reassignment_stats(&self) -> Option<ReassignmentStats> {
        match self {
            Self::Split {
                applied_assigned,
                applied_residue,
                ..
            }
            | Self::Facet {
                applied_assigned,
                applied_residue,
                ..
            } => Some(ReassignmentStats {
                assigned: *applied_assigned as usize,
                residue: *applied_residue as usize,
            }),
            Self::Merge { .. } | Self::Undo { .. } | Self::ProposalResolution { .. } => None,
        }
    }

    /// Reconstructs the fold-grade action. Evidence and survivorship plan
    /// do not participate in transition evaluation; the split map rides
    /// along verbatim.
    ///
    /// Facet SPEC LABELS are reconstructed as placeholders, for the same
    /// reason evidence is: the transition table reads only the mask COUNT
    /// (`facets.is_empty()` and the index bound), never a label. The labels
    /// themselves are runtime data on the minted FACET entity bodies, which
    /// is where a reader wanting them looks.
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
                ..
            } => IdentityTopologyAction::Apply(IdentityTopologyOp::Split(SplitOp {
                entity: *entity,
                heads: heads.clone(),
                reassignment: reassignment.clone(),
                evidence: IdentityOpEvidence::default(),
            })),
            Self::Facet {
                entity,
                facets,
                reassignment,
                ..
            } => IdentityTopologyAction::Apply(IdentityTopologyOp::Facet(FacetOp {
                entity: *entity,
                facets: facets
                    .iter()
                    .map(|_| FacetSpec {
                        label: String::new(),
                    })
                    .collect(),
                reassignment: reassignment.clone(),
                evidence: IdentityOpEvidence::default(),
            })),
            Self::Undo { target } => IdentityTopologyAction::Undo { target: *target },
            Self::ProposalResolution {
                proposal, outcome, ..
            } => IdentityTopologyAction::ResolveProposal {
                proposal: *proposal,
                outcome: *outcome,
            },
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
        encode_action_entries(&self.action, &mut entries);
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
        Ok(Self {
            seq,
            at,
            actor,
            source,
            approval,
            confidence,
            evidence,
            action: decode_action(kind, map)?,
        })
    }
}

/// Appends one action's pinned wire entries. Shared by the ledger event
/// body and the amendment codec so an amended op can only ever carry a
/// shape the ledger itself stores — ONE encoder, no second dialect.
fn encode_action_entries(action: &StoredIdentityOpAction, entries: &mut Vec<(Value, Value)>) {
    match action {
        StoredIdentityOpAction::Merge { sources, survivor } => {
            entries.push((Value::from(BODY_KEY_SOURCES), ids_value(sources)));
            entries.push((Value::from(BODY_KEY_SURVIVOR), id_value(survivor)));
            entries.push((Value::from(BODY_KEY_PLAN), Value::from(PLAN_READ_THROUGH)));
        }
        StoredIdentityOpAction::Split {
            entity,
            heads,
            reassignment,
            applied_assigned,
            applied_residue,
        } => {
            entries.push((Value::from(BODY_KEY_ENTITY), id_value(entity)));
            entries.push((Value::from(BODY_KEY_HEADS), ids_value(heads)));
            entries.push((
                Value::from(BODY_KEY_MAP),
                encode_reassignment_map(reassignment),
            ));
            encode_applied_counts(*applied_assigned, *applied_residue, entries);
        }
        StoredIdentityOpAction::Facet {
            entity,
            facets,
            reassignment,
            applied_assigned,
            applied_residue,
        } => {
            entries.push((Value::from(BODY_KEY_ENTITY), id_value(entity)));
            entries.push((Value::from(BODY_KEY_FACETS), ids_value(facets)));
            entries.push((
                Value::from(BODY_KEY_MAP),
                encode_reassignment_map(reassignment),
            ));
            encode_applied_counts(*applied_assigned, *applied_residue, entries);
        }
        StoredIdentityOpAction::Undo { target } => {
            entries.push((Value::from(BODY_KEY_TARGET), id_value(target)));
        }
        StoredIdentityOpAction::ProposalResolution {
            proposal,
            outcome,
            scope,
            amended_body,
        } => {
            entries.push((Value::from(BODY_KEY_PROPOSAL), id_value(proposal)));
            entries.push((Value::from(BODY_KEY_OUTCOME), Value::from(outcome.as_str())));
            entries.push((
                Value::from(BODY_KEY_SCOPE_OP_KIND),
                Value::from(scope.op_kind),
            ));
            entries.push((
                Value::from(BODY_KEY_SCOPE_TARGET_CLASS),
                Value::from(scope.target_class.as_str()),
            ));
            entries.push((
                Value::from(BODY_KEY_SCOPE_ACTOR),
                Value::from(scope.actor.as_str()),
            ));
            if let Some(amended_body) = amended_body {
                entries.push((
                    Value::from(BODY_KEY_AMENDED),
                    Value::Binary(amended_body.clone()),
                ));
            }
        }
    }
}

/// Appends the ONE-1745 applied-count entries, OMITTING zeros.
///
/// The omission is load-bearing, not cosmetic: [`decode_identity_op_amendment`]
/// and the replicated-body door both demand a byte-exact re-encode, so an
/// event carrying no applied rows — a parked split, an amendment body — must
/// encode to exactly the bytes those shapes encoded to before this ticket.
fn encode_applied_counts(assigned: u64, residue: u64, entries: &mut Vec<(Value, Value)>) {
    if assigned != 0 {
        entries.push((
            Value::from(BODY_KEY_APPLIED_ASSIGNED),
            Value::from(assigned),
        ));
    }
    if residue != 0 {
        entries.push((Value::from(BODY_KEY_APPLIED_RESIDUE), Value::from(residue)));
    }
}

/// The [`encode_applied_counts`] inverse: an absent key is zero, a present
/// key must be a `u64` (a malformed one is a body rejection, never a
/// silently-zeroed count).
fn decode_applied_counts(map: &[(Value, Value)]) -> Result<(u64, u64)> {
    let count = |key: &'static str| match map_field(map, key) {
        None => Ok(0),
        Some(value) => value
            .as_u64()
            .ok_or(Error::InvalidIdentityTopologyEventBody(
                "identity topology event applied count",
            )),
    };
    Ok((
        count(BODY_KEY_APPLIED_ASSIGNED)?,
        count(BODY_KEY_APPLIED_RESIDUE)?,
    ))
}

/// Decodes one action from its wire entries — the [`encode_action_entries`]
/// inverse, shared by the ledger event body and the amendment codec.
fn decode_action(kind: &str, map: &[(Value, Value)]) -> Result<StoredIdentityOpAction> {
    match kind {
        EVENT_KIND_MERGE => {
            let plan = decode_str_field(map, BODY_KEY_PLAN, "identity topology event plan")?;
            if plan != PLAN_READ_THROUGH {
                return Err(Error::InvalidIdentityTopologyEventBody(
                    "identity topology event plan is unknown",
                ));
            }
            Ok(StoredIdentityOpAction::Merge {
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
            })
        }
        EVENT_KIND_SPLIT => {
            let (applied_assigned, applied_residue) = decode_applied_counts(map)?;
            Ok(StoredIdentityOpAction::Split {
                entity: decode_id_field(map, BODY_KEY_ENTITY, "identity topology event entity")?,
                heads: decode_ids_field(map, BODY_KEY_HEADS, "identity topology event heads")?,
                reassignment: decode_reassignment_map(map_field(map, BODY_KEY_MAP).ok_or(
                    Error::InvalidIdentityTopologyEventBody("identity topology event map"),
                )?)?,
                applied_assigned,
                applied_residue,
            })
        }
        EVENT_KIND_FACET => {
            let (applied_assigned, applied_residue) = decode_applied_counts(map)?;
            Ok(StoredIdentityOpAction::Facet {
                entity: decode_id_field(map, BODY_KEY_ENTITY, "identity topology event entity")?,
                facets: decode_ids_field(map, BODY_KEY_FACETS, "identity topology event facets")?,
                reassignment: decode_reassignment_map(map_field(map, BODY_KEY_MAP).ok_or(
                    Error::InvalidIdentityTopologyEventBody("identity topology event map"),
                )?)?,
                applied_assigned,
                applied_residue,
            })
        }
        EVENT_KIND_UNDO => Ok(StoredIdentityOpAction::Undo {
            target: decode_id_field(map, BODY_KEY_TARGET, "identity topology event target")?,
        }),
        EVENT_KIND_PROPOSAL_RESOLUTION => {
            const RESOLUTION_CONTEXT: &str = "identity topology proposal resolution";
            let outcome = ProposalOutcome::parse(decode_str_field(
                map,
                BODY_KEY_OUTCOME,
                "identity topology event outcome",
            )?)
            .ok_or(Error::InvalidIdentityTopologyEventBody(
                "identity topology event outcome",
            ))?;
            let amended_body = match map_field(map, BODY_KEY_AMENDED) {
                None => None,
                Some(value) => Some(
                    value
                        .as_slice()
                        .ok_or(Error::InvalidIdentityTopologyEventBody(RESOLUTION_CONTEXT))?
                        .to_vec(),
                ),
            };
            // The amended body is present EXACTLY on the amended outcome:
            // bytes under any other outcome would contradict the receipt
            // contract (payload iff `approved_amended`), and an amended
            // outcome without them would lose the producer artifact ED-01
            // reads.
            if amended_body.is_some() != (outcome == ProposalOutcome::ApprovedAmended) {
                return Err(Error::InvalidIdentityTopologyEventBody(
                    "identity topology proposal resolution amended body must accompany \
                     exactly the amended outcome",
                ));
            }
            Ok(StoredIdentityOpAction::ProposalResolution {
                proposal: decode_id_field(map, BODY_KEY_PROPOSAL, RESOLUTION_CONTEXT)?,
                outcome,
                scope: ProposalScope {
                    op_kind: decode_amendable_kind(decode_str_field(
                        map,
                        BODY_KEY_SCOPE_OP_KIND,
                        RESOLUTION_CONTEXT,
                    )?)?,
                    target_class: decode_str_field(
                        map,
                        BODY_KEY_SCOPE_TARGET_CLASS,
                        RESOLUTION_CONTEXT,
                    )?
                    .to_owned(),
                    actor: decode_str_field(map, BODY_KEY_SCOPE_ACTOR, RESOLUTION_CONTEXT)?
                        .to_owned(),
                },
                amended_body,
            })
        }
        _ => Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology event kind is unknown",
        )),
    }
}

/// The op's primary target — the entity whose registry class names the
/// ramp scope: the merge SURVIVOR (what the merged records become) and the
/// split ORIGINAL (what is being divided).
fn proposal_scope_target(op: &IdentityTopologyOp) -> Result<EntityId> {
    match op {
        IdentityTopologyOp::Merge(merge) => Ok(merge.survivor),
        IdentityTopologyOp::Split(split) => Ok(split.entity),
        IdentityTopologyOp::Facet(_) | IdentityTopologyOp::AssertDistinct(_) => {
            Err(Error::IdentityTopologyUnarmed("resolution of this op kind"))
        }
    }
}

/// The amendment-scope pin (ARCH-0055 r7): an amendment ADJUSTS the
/// reviewed decision, it never becomes a different one.
///
/// Two bounds, both necessary. Same op KIND: approving a merge must not
/// silently apply a split. Subject SUBSET: the amendment may drop or narrow
/// subjects the decider saw, never reach an entity the proposal never named
/// — otherwise "approve this merge, amended" would be a capability to merge
/// anything at all.
///
/// On a SPLIT the subject walk is not the whole reach: the reassignment map
/// also picks routes. A row's `Head` TARGET is where an item flows, and an
/// EDGE item is replayed by moving the edge itself — so both endpoints and
/// every head target stay bounded to the proposal's named set, and an
/// amendment may narrow the map but never route through an entity the
/// decider never saw. Bare claim items are not routes ([`reassignment_entry_in_scope`]).
fn assert_amendment_in_scope(
    proposed: &IdentityTopologyOp,
    amended: &IdentityTopologyOp,
) -> Result<()> {
    if std::mem::discriminant(proposed) != std::mem::discriminant(amended) {
        return Err(Error::IdentityProposalAmendmentOutOfScope(
            "amended body is a different op kind",
        ));
    }
    let proposed_subjects: BTreeSet<EntityId> = proposed.participants().into_iter().collect();
    let in_scope = |entity: &EntityId| proposed_subjects.contains(entity);
    if !amended.participants().iter().all(in_scope) {
        return Err(Error::IdentityProposalAmendmentOutOfScope(
            "amended body names a subject outside the proposal",
        ));
    }
    if let IdentityTopologyOp::Split(split) = amended
        && split
            .reassignment
            .entries
            .iter()
            .any(|entry| !reassignment_entry_in_scope(entry, &proposed_subjects))
    {
        return Err(Error::IdentityProposalAmendmentOutOfScope(
            "amended split map references an entity outside the proposal",
        ));
    }
    Ok(())
}

/// Every entity one map row might ROUTE TO is bounded to the proposal's
/// participant set: `Head` targets, and either side of an edge ITEM —
/// ONE-1745 replays reassignments by moving the edge, so an edge endpoint
/// outside the named set is an out-of-scope route. Row items naming a bare
/// claim (an `Entity` subject) are not routes: a split's map moves claims
/// freely across the split's own heads whether or not the proposal named
/// each one, which is how the verdict itself reviews them. Facet targets
/// are op-internal indices and residue names nothing, so neither reaches
/// an entity the proposal did not.
fn reassignment_entry_in_scope(
    entry: &ReassignmentEntry,
    proposed_subjects: &BTreeSet<EntityId>,
) -> bool {
    let item_in_scope = match &entry.item {
        ClaimSubject::Entity(_) => true,
        ClaimSubject::Edge { source, target, .. } => {
            proposed_subjects.contains(source) && proposed_subjects.contains(target)
        }
    };
    let target_in_scope = match &entry.target {
        ReassignmentTarget::Head(head) => proposed_subjects.contains(head),
        ReassignmentTarget::Facet { .. } | ReassignmentTarget::Residue => true,
    };
    item_in_scope && target_in_scope
}

/// The scope tuple one proposal row derives: op kind, registry class of the
/// op's primary target, and the PROPOSAL's actor ref. Pure so the wire
/// check below and the vault stamp share ONE derivation.
fn proposal_scope_of(record: &StoredIdentityOpEvent, target_class: &str) -> ProposalScope {
    ProposalScope {
        op_kind: record.action.kind_str(),
        target_class: target_class.to_owned(),
        actor: record.actor.map_or_else(
            || PROPOSAL_SCOPE_ACTOR_UNATTRIBUTED.to_owned(),
            |actor| actor.entity_ref().to_hex(),
        ),
    }
}

/// Stateless wire-legality of a resolution row's stamped ramp scope: the
/// tuple's op kind must be THE PROPOSAL'S recorded action kind, never an
/// amendable kind claimed about a non-op row (a resolution of an undo row,
/// say). Needs no store, so it rides the stateless decode path every
/// admission — local door and sync replay alike — passes through.
fn validate_resolution_scope_stateless(record: &StoredIdentityOpEvent) -> Result<()> {
    let StoredIdentityOpAction::ProposalResolution { scope, .. } = &record.action else {
        return Ok(());
    };
    let proposal_is_op = matches!(scope.op_kind, EVENT_KIND_MERGE | EVENT_KIND_SPLIT);
    if !proposal_is_op {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology proposal resolution scope names a non-op kind",
        ));
    }
    Ok(())
}

/// The AMENDABLE op kinds: only the two ops whose apply door is armed and
/// whose subject set is expressible on the wire. A resolution's scope
/// `op_kind` is one of these by construction (a proposal of an unarmed kind
/// never reaches the ledger), so a stored value outside the set is
/// malformed.
fn decode_amendable_kind(value: &str) -> Result<&'static str> {
    match value {
        EVENT_KIND_MERGE => Ok(EVENT_KIND_MERGE),
        EVENT_KIND_SPLIT => Ok(EVENT_KIND_SPLIT),
        _ => Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology proposal scope op kind is unknown",
        )),
    }
}

/// Encodes an amended op body: the SAME pinned MessagePack action shape the
/// ledger stores, minus the event envelope (seq/at/actor/consent are the
/// resolution's own, never the amendment's).
///
/// One codec, two directions — a decider builds the amended body with this
/// and [`decode_identity_op_amendment`] parses it back at the door, so an
/// amendment can never carry a shape the ledger cannot store.
pub fn encode_identity_op_amendment(op: &IdentityTopologyOp) -> Result<Vec<u8>> {
    let action = match op {
        IdentityTopologyOp::Merge(merge) => StoredIdentityOpAction::Merge {
            sources: merge.sources.clone(),
            survivor: merge.survivor,
        },
        IdentityTopologyOp::Split(split) => StoredIdentityOpAction::Split {
            entity: split.entity,
            heads: split.heads.clone(),
            reassignment: split.reassignment.canonicalized(),
            // An amendment is a PROPOSED body, not an applied record: it has
            // recorded nothing yet, and the counts it carries would be the
            // decider's claim about an application that has not happened.
            applied_assigned: 0,
            applied_residue: 0,
        },
        // A facet op has no propose lane (see `apply_identity_topology_op`),
        // so it has no park to amend either.
        IdentityTopologyOp::Facet(_) | IdentityTopologyOp::AssertDistinct(_) => {
            return Err(Error::IdentityTopologyUnarmed("amendment of this op kind"));
        }
    };
    let mut entries = vec![(Value::from(BODY_KEY_KIND), Value::from(action.kind_str()))];
    encode_action_entries(&action, &mut entries);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &Value::Map(entries)).map_err(|_| {
        Error::InvalidIdentityTopologyEventBody("identity topology amendment encode failed")
    })?;
    Ok(data)
}

/// Decodes an amended op body, fail-closed and canonical: the bytes must
/// re-encode identically, so a decider cannot smuggle a non-canonical
/// encoding past the scope check and have the ledger store different bytes
/// than were validated.
pub fn decode_identity_op_amendment(data: &[u8]) -> Result<IdentityTopologyOp> {
    const AMENDMENT_CONTEXT: &str = "identity topology amendment";
    if data.len() > MAX_IDENTITY_TOPOLOGY_EVENT_BODY_BYTES {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology amendment exceeds the size limit",
        ));
    }
    let mut cursor = data;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidIdentityTopologyEventBody(AMENDMENT_CONTEXT))?;
    if !cursor.is_empty() {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology amendment carries trailing bytes",
        ));
    }
    let map = value
        .as_map()
        .ok_or(Error::InvalidIdentityTopologyEventBody(AMENDMENT_CONTEXT))?;
    let kind = decode_str_field(map, BODY_KEY_KIND, AMENDMENT_CONTEXT)?;
    let action = decode_action(kind, map)?;
    let op = match action.to_fold_action() {
        IdentityTopologyAction::Apply(op) => op,
        // undo / resolution rows are not ops a proposal can name, so they
        // are not amendable shapes either.
        IdentityTopologyAction::Undo { .. } | IdentityTopologyAction::ResolveProposal { .. } => {
            return Err(Error::InvalidIdentityTopologyEventBody(
                "identity topology amendment is not an op",
            ));
        }
    };
    if encode_identity_op_amendment(&op)? != data {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology amendment is not canonical",
        ));
    }
    Ok(op)
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
    validate_resolution_scope_stateless(record)?;

    let IdentityTopologyAction::Apply(op) = record.action.to_fold_action() else {
        return Ok(());
    };
    if op.participants().len() > MAX_IDENTITY_TOPOLOGY_EVENT_PARTICIPANTS {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology event has too many participants",
        ));
    }
    // A facet op names ONE participant however many masks it mints, so the
    // participant bound above does not reach its fan-out. Bound it here, on
    // the same stateless path every admitting door runs.
    if let IdentityTopologyOp::Facet(facet) = &op
        && facet.facets.len() > MAX_IDENTITY_TOPOLOGY_EVENT_FACETS
    {
        return Err(Error::InvalidIdentityTopologyEventBody(
            "identity topology event mints too many facets",
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

fn topology_edge_weight(kind: EdgeKind) -> Result<f32> {
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
            IdentityTopologyAction::ResolveProposal { proposal, .. } => {
                identity_topology_entity_type_for_store_in_txn(store, rtxn, proposal)?
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

/// Entities the ledger currently holds in a ZERO-HEAD split shell — the one
/// topology arm that leaves no `split_into` edge, so the type-76 log is its
/// only witness (ONE-1744). Everything that would otherwise read shell truth
/// from the edges alone consults this for that arm: the lifecycle read and
/// the redirect projection both do.
///
/// Derived from the EFFECTIVE fold, so an undone or superseded zero-head
/// split correctly drops out of the set.
/// Conservative "a zero-head split has been recorded in this vault" marker.
///
/// The witness fold below is O(event family), and the apply door needs the
/// answer for every participant of every op — which would make a run of N
/// topology ops O(N²). Zero-head splits are RARE, so this marker buys the
/// common case back: absent means none has ever been recorded, and the fold
/// is skipped entirely.
///
/// It is set, never cleared: an undone or evicted zero-head split leaves it
/// standing. That direction is the safe one — a stale-SET marker costs one
/// fold that returns the empty set, while a stale-CLEAR marker would hide a
/// live shell. Correctness never depends on it, only cost.
pub(crate) const IDENTITY_TOPOLOGY_ZERO_HEAD_SEEN_KEY: &[u8] =
    b"m:identity_topology_zero_head_seen";

/// Records that a zero-head split exists, arming the witness fold.
pub(crate) fn note_zero_head_split_in_txn(store: &Store, wtxn: &mut heed::RwTxn<'_>) -> Result<()> {
    if store
        .vault_meta
        .get(&*wtxn, IDENTITY_TOPOLOGY_ZERO_HEAD_SEEN_KEY)?
        .is_some()
    {
        return Ok(());
    }
    store
        .vault_meta
        .put(wtxn, IDENTITY_TOPOLOGY_ZERO_HEAD_SEEN_KEY, &[1])?;
    Ok(())
}

/// [`zero_head_split_shells_for_store_in_txn`] behind the marker: skips the
/// fold outright on a vault that has never recorded a zero-head split.
pub(crate) fn zero_head_split_shells_if_any_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
) -> Result<BTreeSet<EntityId>> {
    if store
        .vault_meta
        .get(rtxn, IDENTITY_TOPOLOGY_ZERO_HEAD_SEEN_KEY)?
        .is_none()
    {
        return Ok(BTreeSet::new());
    }
    zero_head_split_shells_for_store_in_txn(store, rtxn)
}

pub(crate) fn zero_head_split_shells_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
) -> Result<BTreeSet<EntityId>> {
    let effective = fold_effective_identity_topology_events_for_store_in_txn(store, rtxn)?;
    let fold = fold_identity_topology_log(&effective);
    let mut shells = BTreeSet::new();
    for (entity, event_id) in &fold.current_event {
        if fold.states.get(entity) != Some(&EntityLifecycleState::Split) {
            continue;
        }
        let record = identity_topology_event_for_store_in_txn(store, rtxn, event_id)?
            .ok_or(Error::CorruptedIndex("identity topology event index"))?;
        if matches!(&record.action, StoredIdentityOpAction::Split { heads, .. } if heads.is_empty())
        {
            shells.insert(*entity);
        }
    }
    Ok(shells)
}

pub(crate) fn identity_topology_shell_peers_for_store_in_txn(
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

/// Every entity the SURVIVING type-76 apply family names as a shell-edge
/// source. This is the reconciler's touched set: the ids whose
/// `merged_into` / `split_into` rows the current ledger can still speak for.
/// It is also the redirect projection's rebuild candidate set (ONE-1744) —
/// the same derivation, since an entity with no topology event has no
/// redirect row either.
pub(crate) fn shell_edge_sources_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
) -> Result<BTreeSet<EntityId>> {
    let stored_events = identity_topology_events_for_store_in_txn(store, rtxn)?;
    let mut touched = BTreeSet::new();
    for event in &stored_events {
        match &event.action {
            IdentityTopologyAction::Apply(IdentityTopologyOp::Merge(merge)) => {
                touched.extend(merge.sources.iter().copied());
            }
            IdentityTopologyAction::Apply(IdentityTopologyOp::Split(split)) => {
                touched.insert(split.entity);
            }
            // Neither a counter-event nor a resolution names a shell-edge
            // source of its own: the undo's sources come from the event it
            // reverts, and an approved op is applied as its own event.
            IdentityTopologyAction::Apply(
                IdentityTopologyOp::Facet(_) | IdentityTopologyOp::AssertDistinct(_),
            )
            | IdentityTopologyAction::Undo { .. }
            | IdentityTopologyAction::ResolveProposal { .. } => {}
        }
    }
    Ok(touched)
}

// ─── Reassignment projection (ONE-1745) ─────────────────────────────────────

/// The `vault_meta` key of one origin-side assignment row.
fn reassignment_origin_key(origin: &EntityId, event: &EntityId, claim: &EntityId) -> Vec<u8> {
    reassignment_key(REASSIGNMENT_ORIGIN_META_PREFIX, origin, event, claim)
}

/// The `vault_meta` key of one destination-side assignment row.
fn reassignment_target_key(target: &EntityId, event: &EntityId, claim: &EntityId) -> Vec<u8> {
    reassignment_key(REASSIGNMENT_TARGET_META_PREFIX, target, event, claim)
}

fn reassignment_key(
    prefix: &[u8],
    anchor: &EntityId,
    event: &EntityId,
    claim: &EntityId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + ENTITY_ID_LEN * 3);
    key.extend_from_slice(prefix);
    key.extend_from_slice(anchor.as_bytes());
    key.extend_from_slice(event.as_bytes());
    key.extend_from_slice(claim.as_bytes());
    key
}

/// Splits a stored assignment key back into `(event, claim)`. Both halves are
/// fixed-width tails, so this is exact for either prefix.
fn decode_reassignment_key(prefix: &[u8], key: &[u8]) -> Result<(EntityId, EntityId)> {
    let corrupt = || Error::CorruptedIndex("identity reassignment key");
    let tail = key
        .get(prefix.len() + ENTITY_ID_LEN..)
        .ok_or_else(corrupt)?;
    let (event, claim) = tail.split_at_checked(ENTITY_ID_LEN).ok_or_else(corrupt)?;
    let id = |bytes: &[u8]| {
        let bytes: [u8; ENTITY_ID_LEN] = bytes.try_into().map_err(|_| corrupt())?;
        EntityId::from_bytes(bytes).map_err(|_| corrupt())
    };
    Ok((id(event)?, id(claim)?))
}

/// Encodes an assignment row: a bare version byte is explicit ambiguous
/// residue, a version byte plus a head id is an assignment.
fn encode_reassignment_row(target: Option<&EntityId>) -> Vec<u8> {
    let mut row = vec![REASSIGNMENT_ROW_VERSION];
    if let Some(target) = target {
        row.extend_from_slice(target.as_bytes());
    }
    row
}

/// Decodes an assignment row, fail-closed on any shape the encoder cannot
/// produce.
fn decode_reassignment_row(row: &[u8]) -> Result<Option<EntityId>> {
    let corrupt = || Error::CorruptedIndex("identity reassignment row");
    let [REASSIGNMENT_ROW_VERSION, target @ ..] = row else {
        return Err(corrupt());
    };
    if target.is_empty() {
        return Ok(None);
    }
    let bytes: [u8; ENTITY_ID_LEN] = target.try_into().map_err(|_| corrupt())?;
    EntityId::from_bytes(bytes).map(Some).map_err(|_| corrupt())
}

/// Resolves a decision's reassignment map into the concrete rows a vault can
/// record: `(claim, Some(destination))` or `(claim, None)` for residue.
///
/// Two filters, both deliberate:
/// - only an [`ClaimSubject::Entity`] item that names a STORED CLAIM row
///   resolves. An edge item is a later surface (the map vocabulary admits
///   one, r2, but moving an edge is not claim assignment), and an item this
///   vault holds nothing for records nothing.
/// - the destination comes from `targets`, so a row can only ever route
///   where the op itself said it could.
///
/// The gap between what the map DECLARED and what this returns is exactly
/// what [`ReassignmentStats`] reports and the receipt projects.
fn resolve_reassignment_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    map: &ReassignmentMap,
    targets: ReassignmentContext<'_>,
) -> Result<Vec<(EntityId, Option<EntityId>)>> {
    let mut rows = Vec::with_capacity(map.entries.len());
    for entry in &map.entries {
        let ClaimSubject::Entity(claim) = entry.item else {
            continue;
        };
        if identity_topology_entity_type_for_store_in_txn(store, rtxn, &claim)?
            != Some(ENTITY_TYPE_CLAIM)
        {
            continue;
        }
        rows.push((claim, targets.resolve(&entry.target)?));
    }
    Ok(rows)
}

/// Writes `rows` as `event`'s assignment rows for `origin`, both directions.
fn write_reassignment_rows_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    event: &EntityId,
    origin: &EntityId,
    rows: &[(EntityId, Option<EntityId>)],
) -> Result<()> {
    for (claim, target) in rows {
        store.vault_meta.put(
            wtxn,
            &reassignment_origin_key(origin, event, claim),
            &encode_reassignment_row(target.as_ref()),
        )?;
        if let Some(target) = target {
            store.vault_meta.put(
                wtxn,
                &reassignment_target_key(target, event, claim),
                &[REASSIGNMENT_ROW_VERSION],
            )?;
        }
    }
    Ok(())
}

/// Deletes every assignment row filed under `origin`, both directions.
///
/// `event` narrows the sweep to ONE ledger event's rows (the undo door, which
/// must not touch a sibling event's); `None` clears the origin outright (the
/// reconcile door, which re-derives the whole set from the fold).
fn clear_reassignment_rows_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    origin: &EntityId,
    event: Option<&EntityId>,
) -> Result<()> {
    let mut prefix = Vec::with_capacity(REASSIGNMENT_ORIGIN_META_PREFIX.len() + ENTITY_ID_LEN * 2);
    prefix.extend_from_slice(REASSIGNMENT_ORIGIN_META_PREFIX);
    prefix.extend_from_slice(origin.as_bytes());
    if let Some(event) = event {
        prefix.extend_from_slice(event.as_bytes());
    }
    let mut stale: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();
    for row in store.vault_meta.prefix_iter(&*wtxn, &prefix)? {
        let (key, value) = row?;
        let (event, claim) = decode_reassignment_key(REASSIGNMENT_ORIGIN_META_PREFIX, &key)?;
        let twin = decode_reassignment_row(value.as_ref())?
            .map(|target| reassignment_target_key(&target, &event, &claim));
        stale.push((key.to_vec(), twin));
    }
    for (key, twin) in stale {
        store.vault_meta.delete(wtxn, &key)?;
        if let Some(twin) = twin {
            store.vault_meta.delete(wtxn, &twin)?;
        }
    }
    Ok(())
}

/// Shared by `SplitOp` and `FacetOp` apply (ARCH-0055 r2/r5) — the ticket's
/// point is that ONE mechanism records both, never a per-op copy.
///
/// Records where each mapped claim went WITHOUT rewriting a single claim
/// subject (r6): the stored subject stays the id the writer stated, forever,
/// and assignment is a separate engine-authored record over it. Residue rows
/// are recorded as explicit ambiguous residue on the origin — never
/// force-assigned to a head the decision did not name.
///
/// The two arms differ only in WHERE the record lives, because they have
/// different canonical witnesses:
/// - a SPLIT assignment has none — no edge, no subject change — so the
///   `vault_meta` index IS the record, keyed by the event that stated it.
/// - a FACET assignment already has one: the canonical `facet_of` stamp
///   ([`EdgeKind::FacetOf`], ONE-1645's write-time type table), which the
///   local query filter and the federation selector both already read. A
///   second projection of it would be a stale twin, so the stamps are staged
///   into `stamps` and no index row is written.
///
/// `stamps` is applied by the caller's [`apply_ops`] batch AFTER the minted
/// FACET rows land in the same batch — a `facet_of` edge whose target has no
/// entity row fails closed at that table.
pub(crate) fn apply_reassignment_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    event: &EntityId,
    origin: &EntityId,
    map: &ReassignmentMap,
    targets: ReassignmentContext<'_>,
    stamps: &mut Vec<BatchOp>,
    now: u64,
) -> Result<ReassignmentStats> {
    let rows = resolve_reassignment_in_txn(store, &*wtxn, map, targets)?;
    let assigned = rows.iter().filter(|(_, target)| target.is_some()).count();
    let stats = ReassignmentStats {
        assigned,
        residue: rows.len() - assigned,
    };
    match targets {
        ReassignmentContext::Heads(_) => {
            write_reassignment_rows_in_txn(store, wtxn, event, origin, &rows)?;
        }
        ReassignmentContext::Facets(_) => {
            let weight = topology_edge_weight(EdgeKind::FacetOf)?;
            for (claim, target) in rows {
                let Some(facet) = target else {
                    continue;
                };
                stamps.push(BatchOp::EdgeWithCreatedAt {
                    src: claim,
                    kind: EdgeKind::FacetOf,
                    tgt: facet,
                    weight,
                    created_at: now,
                    vad: crate::affect::Vad::NEUTRAL,
                    provenance: None,
                });
            }
        }
    }
    Ok(stats)
}

/// Re-derives the split assignment rows of exactly `sources` from the ledger
/// fold — the reconcile-door half of the projection, the twin of
/// [`crate::identity_redirect::maintain_redirect_projection_in_txn`].
///
/// The apply and undo doors maintain their own rows directly (they hold the
/// event and its map, so they need no fold — the ONE-1744 O(N²) lesson). This
/// path exists for the doors that DON'T: sync ingest of a replicated split,
/// and the ONE-1604-D1 post-eviction unwind, both of which change which
/// events are in force without ever running the apply door.
///
/// Memoryless by construction: every source is cleared and re-derived from
/// whichever split event the fold currently has in force, so an undone,
/// superseded, or evicted split loses its rows without anyone tracking that
/// it had them.
fn maintain_split_reassignment_projection_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    sources: &BTreeSet<EntityId>,
    fold: &IdentityTopologyFold,
) -> Result<()> {
    for origin in sources {
        clear_reassignment_rows_in_txn(store, wtxn, origin, None)?;
        if fold.states.get(origin) != Some(&EntityLifecycleState::Split) {
            continue;
        }
        let Some(event) = fold.current_event.get(origin) else {
            continue;
        };
        let Some(record) = identity_topology_event_for_store_in_txn(store, &*wtxn, event)? else {
            continue;
        };
        let StoredIdentityOpAction::Split {
            heads,
            reassignment,
            ..
        } = &record.action
        else {
            continue;
        };
        let rows = resolve_reassignment_in_txn(
            store,
            &*wtxn,
            reassignment,
            ReassignmentContext::Heads(heads),
        )?;
        write_reassignment_rows_in_txn(store, wtxn, event, origin, &rows)?;
    }
    Ok(())
}

/// Claim ids filed under one assignment-index prefix scan, deduplicated and
/// in ascending id order.
fn reassignment_claims_for_prefix_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    index_prefix: &[u8],
    anchor: &EntityId,
    keep: impl Fn(Option<EntityId>) -> bool,
) -> Result<BTreeSet<EntityId>> {
    let mut prefix = Vec::with_capacity(index_prefix.len() + ENTITY_ID_LEN);
    prefix.extend_from_slice(index_prefix);
    prefix.extend_from_slice(anchor.as_bytes());
    let mut claims = BTreeSet::new();
    for row in store.vault_meta.prefix_iter(rtxn, &prefix)? {
        let (key, value) = row?;
        if !keep(decode_reassignment_row(value.as_ref())?) {
            continue;
        }
        claims.insert(decode_reassignment_key(index_prefix, &key)?.1);
    }
    Ok(claims)
}

fn reconcile_identity_topology_edges_for_store_in_txn(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    text_index_trusted: bool,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    #[cfg(test)]
    test_hooks::note_full_reconciliation();
    let touched = shell_edge_sources_for_store_in_txn(store, &*wtxn)?;
    reconcile_shell_edges_for_sources_in_txn(
        store,
        config,
        analyzer,
        text_index_trusted,
        wtxn,
        &touched,
    )
}

/// Post-eviction shell reconciliation for ONE-1604-D1 authority dominance:
/// the sources to recompute are the UNION of `evicted_sources` (the removed
/// type-76 row's own participants, captured by
/// [`identity_topology_shell_sources_for_store_in_txn`] before the row went)
/// and the SURVIVING family's sources, all against one final fold.
///
/// Neither half is sufficient alone, because removing an event replays the
/// WHOLE fold:
///
/// - The surviving-family derivation cannot see the removed event's
///   participants — it enumerates rows, and that row is gone. Only the
///   explicit capture reaches them (fix-leg 4).
/// - The explicit capture reaches only DIRECT participants, but deleting an
///   event changes which LATER events apply, and those events have their own
///   sources. Concretely: merge `T(A→B)`, a squatter undo `U(T)` (so `T` is
///   reverted and a later `M([A,C]→D)` applies), then dominance evicts `U`.
///   `T` becomes effective again, `M` folds to rejected — and `C`, which `U`
///   never named, is left holding a `merged_into D` edge no ledger event
///   justifies. That is the same ARCH-0055 wedge the eviction unwind exists
///   to prevent, one hop further out. The union closes the set: any event
///   whose effectiveness the replay can flip is, by definition, a surviving
///   event, so its sources are in the surviving half.
///
/// Runs only when `evicted_sources` is non-empty — a batch without an
/// eviction is append-only, where the surviving derivation is already exact
/// and the ordinary reconciler has already run.
pub(crate) fn reconcile_shell_edges_after_eviction_in_txn(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    text_index_trusted: bool,
    wtxn: &mut heed::RwTxn<'_>,
    evicted_sources: &BTreeSet<EntityId>,
) -> Result<()> {
    if evicted_sources.is_empty() {
        return Ok(());
    }
    let mut sources = shell_edge_sources_for_store_in_txn(store, &*wtxn)?;
    sources.extend(evicted_sources.iter().copied());
    reconcile_shell_edges_for_sources_in_txn(
        store,
        config,
        analyzer,
        text_index_trusted,
        wtxn,
        &sources,
    )
}

/// Reconciles the canonical shell edges of EXACTLY `sources` against the
/// current ledger fold: edges the fold no longer mandates are deleted,
/// mandated edges are (re)written when both endpoints are materialized.
///
/// Callers own the derivation of `sources`, and the two derivations are NOT
/// interchangeable. Append-only batches use the surviving-family set
/// ([`shell_edge_sources_for_store_in_txn`]); an eviction batch
/// must use the union in
/// [`reconcile_shell_edges_after_eviction_in_txn`], because a removed row is
/// no longer enumerable AND its removal replays the whole fold.
fn reconcile_shell_edges_for_sources_in_txn(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    text_index_trusted: bool,
    wtxn: &mut heed::RwTxn<'_>,
    sources: &BTreeSet<EntityId>,
) -> Result<()> {
    if sources.is_empty() {
        return Ok(());
    }

    let effective_events = fold_effective_identity_topology_events_for_store_in_txn(store, &*wtxn)?;
    let fold = fold_identity_topology_log(&effective_events);
    let mut ops = Vec::new();
    for entity in sources {
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
                let weight = topology_edge_weight(kind)?;
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
    if !ops.is_empty() {
        apply_ops(
            store,
            config,
            analyzer,
            wtxn,
            ops,
            text_index_trusted,
            false,
            true,
        )?;
    }
    // ONE-1744 redirect maintenance runs for EVERY reconciled source, past
    // the no-edge-ops case on purpose: a zero-head split moves no edge at
    // all, so an empty op list is exactly the shape whose redirect row would
    // otherwise never be written. This is the chokepoint BOTH reconcile
    // paths share (sync ingest and ONE-1604-D1 post-eviction unwind), so
    // hooking it covers both without duplicating the hook.
    // The reconcile path pays the UNGATED fold: it is the sync-ingest door,
    // so it must DISCOVER a replicated zero-head split (and arm the marker)
    // on a vault that has never recorded one locally. It already folds for
    // its own edge derivation, so this costs nothing extra.
    let zero_head_shells = zero_head_split_shells_for_store_in_txn(store, &*wtxn)?;
    crate::identity_redirect::maintain_redirect_projection_in_txn(
        store,
        wtxn,
        sources,
        &zero_head_shells,
    )?;
    // ONE-1745 assignment maintenance rides the same chokepoint and the same
    // already-computed fold: a replicated split arrives here with its map and
    // never touches the apply door, so this is where its assignment rows are
    // born (and where an evicted or superseded split's rows die).
    maintain_split_reassignment_projection_in_txn(store, wtxn, sources, &fold)
}

/// The shell-edge SOURCES a stored type-76 record induces — the entities
/// whose `merged_into` / `split_into` rows the reconciler derives from it.
/// `Ok(None)` when `id` holds no type-76 row (any other kind, or nothing).
///
/// An undo counter-event names no source of its own; its effect is on the
/// sources of the event it reverts, so this resolves through to the TARGET
/// record. Losing an undo row un-reverts its target, which is a shell-edge
/// change on exactly those entities. The walk is ONE hop: an undo of an undo
/// is rejected at the door ([`IdentityTopologyRejection::NotUndoable`]), so a
/// second hop reaches nothing new and no cycle can be entered.
///
/// A squatter's undo may name any id at all, so the hop is fail-SOFT: a
/// target that is missing, another kind, or undecodable contributes no
/// sources instead of failing the caller. The caller is an AUTHORITY
/// admission — letting a planted body abort it with a local-class error would
/// be exactly the ONE-1604-D1 revocation suppression dominance exists to
/// close. Only the row being evicted is read fail-closed: it passed a door
/// that decoded it, so a decode failure there is on-disk corruption.
///
/// Read this BEFORE the row is removed — afterwards the action is gone and
/// the induced sources are unrecoverable.
pub(crate) fn identity_topology_shell_sources_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<BTreeSet<EntityId>>> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
        return Ok(None);
    }
    let record = decode_identity_topology_event_body(&raw[ENTITY_METADATA_HEADER_LEN..])
        .map_err(|_| Error::CorruptedIndex("identity topology event body"))?;
    let action = match &record.action {
        StoredIdentityOpAction::Undo { target } => {
            match identity_topology_event_for_store_in_txn(store, rtxn, target) {
                Ok(Some(target_record)) => target_record.action,
                Ok(None) | Err(_) => return Ok(Some(BTreeSet::new())),
            }
        }
        action => action.clone(),
    };
    Ok(Some(match action {
        StoredIdentityOpAction::Merge { sources, .. } => sources.into_iter().collect(),
        StoredIdentityOpAction::Split { entity, .. } => BTreeSet::from([entity]),
        // A resolution shells nothing of its own: an approving ruling's
        // effects ride the applied op's OWN event, which induces its own
        // sources when evicted. Nor does a facet op — it leaves its base
        // `Active` (r6), so it induces no `merged_into`/`split_into` row for
        // this reconciler to own.
        StoredIdentityOpAction::Undo { .. }
        | StoredIdentityOpAction::Facet { .. }
        | StoredIdentityOpAction::ProposalResolution { .. } => BTreeSet::new(),
    }))
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
            // not duplicate that pass from the generic put hook. A
            // resolution moves no shell edge at all.
            IdentityTopologyAction::Undo { .. }
            | IdentityTopologyAction::ResolveProposal { .. } => false,
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
    /// Entities the ledger currently holds in a zero-head split shell — see
    /// [`zero_head_split_shells_for_store_in_txn`].
    pub(crate) fn zero_head_split_shells_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
    ) -> Result<BTreeSet<EntityId>> {
        zero_head_split_shells_if_any_for_store_in_txn(&self.store, rtxn)
    }

    /// Current lifecycle state of `id`, read from its canonical redirect
    /// edges (D11: the edge is the state witness for every op that leaves
    /// one; the ledger fold and the apply path keep them in lockstep). An id
    /// with no shell edge is `Active` — EXCEPT the zero-head split, which
    /// shells its entity while writing no edge at all, so the ledger is
    /// consulted for exactly that arm (ONE-1744).
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
        self.entity_lifecycle_state_with_zero_head_shells_in_txn(rtxn, id, None)
    }

    /// [`Vault::entity_lifecycle_state_in_txn`] with a caller-supplied
    /// zero-head-shell witness. A caller resolving several ids against one
    /// txn folds the (rare, quota-bounded) event family ONCE and passes the
    /// set here; `None` folds it on demand, and only when the edges leave
    /// the question open.
    pub(crate) fn entity_lifecycle_state_with_zero_head_shells_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        zero_head_shells: Option<&BTreeSet<EntityId>>,
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
            // No shell edge: live, UNLESS the ledger holds a zero-head split
            // over this id. Without this the retired entity would read back
            // `Active` and the apply door would admit an op the fold then
            // rejects `NotActive` — ledger and edge truth diverging, which is
            // the wedge the reconciler exists to prevent.
            (0, true) => {
                let is_zero_head_shell = match zero_head_shells {
                    Some(shells) => shells.contains(id),
                    None => self.zero_head_split_shells_in_txn(rtxn)?.contains(id),
                };
                if is_zero_head_shell {
                    Ok(EntityLifecycleState::Split)
                } else {
                    Ok(EntityLifecycleState::Active)
                }
            }
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
        // Folded ONCE for the whole op: the zero-head-shell witness is the
        // same for every participant, and folding per participant would pay
        // the family scan N times.
        let zero_head_shells = self.zero_head_split_shells_in_txn(&*wtxn)?;
        let mut states = BTreeMap::new();
        for participant in &participants {
            states.insert(
                *participant,
                self.entity_lifecycle_state_with_zero_head_shells_in_txn(
                    &*wtxn,
                    participant,
                    Some(&zero_head_shells),
                )?,
            );
        }
        let transitions =
            evaluate_transition(&states, op).map_err(Error::IdentityTopologyRejected)?;

        // Minted in the arm rather than at the write chokepoint: the
        // reassignment index files each row under the event that stated it,
        // so the event's identity has to exist before its effects do.
        let event_id = EntityId::now();
        match op {
            IdentityTopologyOp::Merge(merge) => {
                let action = StoredIdentityOpAction::Merge {
                    sources: merge.sources.clone(),
                    survivor: merge.survivor,
                };
                let mut effects = Vec::new();
                if write.is_effective() {
                    let weight = topology_edge_weight(EdgeKind::MergedInto)?;
                    for source in &merge.sources {
                        effects.push(BatchOp::EdgeWithCreatedAt {
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
                    event_id,
                    write,
                    now,
                    action,
                    Some(merge.evidence.clone()),
                    effects,
                    transitions,
                )
            }
            IdentityTopologyOp::Split(split) => {
                let mut effects = Vec::new();
                let mut stats = ReassignmentStats::default();
                if write.is_effective() {
                    let weight = topology_edge_weight(EdgeKind::SplitInto)?;
                    for head in &split.heads {
                        effects.push(BatchOp::EdgeWithCreatedAt {
                            src: split.entity,
                            kind: EdgeKind::SplitInto,
                            tgt: *head,
                            weight,
                            created_at: now,
                            vad: crate::affect::Vad::NEUTRAL,
                            provenance: None,
                        });
                    }
                    stats = apply_reassignment_in_txn(
                        &self.store,
                        wtxn,
                        &event_id,
                        &split.entity,
                        &split.reassignment,
                        ReassignmentContext::Heads(&split.heads),
                        &mut effects,
                        now,
                    )?;
                }
                let action = StoredIdentityOpAction::Split {
                    entity: split.entity,
                    heads: split.heads.clone(),
                    reassignment: split.reassignment.canonicalized(),
                    applied_assigned: stats.assigned as u64,
                    applied_residue: stats.residue as u64,
                };
                self.write_identity_event_in_txn(
                    wtxn,
                    event_id,
                    write,
                    now,
                    action,
                    Some(split.evidence.clone()),
                    effects,
                    transitions,
                )
            }
            IdentityTopologyOp::Facet(facet) => {
                // The propose lane is not armed for this kind: a parked facet
                // event would have to name masks it never minted, and the
                // resolution door has no scope target for it
                // ([`proposal_scope_target`]) — so the park could never be
                // ruled on. Refusing to record it is the honest answer;
                // recording an unresolvable one is the ledger corruption this
                // door exists to prevent.
                if !write.is_effective() {
                    return Err(Error::IdentityTopologyUnarmed("facet proposal"));
                }
                if facet.facets.len() > MAX_IDENTITY_TOPOLOGY_EVENT_FACETS {
                    return Err(Error::InvalidIdentityTopologyEventBody(
                        "identity topology event mints too many facets",
                    ));
                }
                let (minted, mut effects) = self.mint_facets_in_txn(facet, now)?;
                let stats = apply_reassignment_in_txn(
                    &self.store,
                    wtxn,
                    &event_id,
                    &facet.entity,
                    &facet.reassignment,
                    ReassignmentContext::Facets(&minted),
                    &mut effects,
                    now,
                )?;
                let action = StoredIdentityOpAction::Facet {
                    entity: facet.entity,
                    facets: minted,
                    reassignment: facet.reassignment.canonicalized(),
                    applied_assigned: stats.assigned as u64,
                    applied_residue: stats.residue as u64,
                };
                self.write_identity_event_in_txn(
                    wtxn,
                    event_id,
                    write,
                    now,
                    action,
                    Some(facet.evidence.clone()),
                    effects,
                    transitions,
                )
            }
            IdentityTopologyOp::AssertDistinct(_) => {
                Err(Error::IdentityTopologyUnarmed("distinct_from assertion"))
            }
        }
    }

    /// Mints one ARCH-0022 FACET (type-13) entity per spec and wires each to
    /// its base with a `has_facet` edge, returning the minted ids in SPEC
    /// ORDER — the order every [`ReassignmentTarget::Facet`] index addresses,
    /// and the order the ledger event stores.
    ///
    /// Mints nothing but FACET ids (r6): the base entity is untouched, the
    /// op's only new rows are the masks themselves. The label is the FACET
    /// body — runtime data, stored where a reader of that entity finds it,
    /// never on the ledger event.
    fn mint_facets_in_txn(
        &self,
        facet: &FacetOp,
        now: u64,
    ) -> Result<(Vec<EntityId>, Vec<BatchOp>)> {
        let weight = topology_edge_weight(EdgeKind::HasFacet)?;
        let mut minted = Vec::with_capacity(facet.facets.len());
        let mut ops = Vec::with_capacity(facet.facets.len() * 2);
        for spec in &facet.facets {
            let id = EntityId::now();
            minted.push(id);
            ops.push(BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_FACET,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                data: spec.label.as_bytes().to_vec(),
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            });
            ops.push(BatchOp::EdgeWithCreatedAt {
                src: facet.entity,
                kind: EdgeKind::HasFacet,
                tgt: id,
                weight,
                created_at: now,
                vad: crate::affect::Vad::NEUTRAL,
                provenance: None,
            });
        }
        Ok((minted, ops))
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
            // A counter-event is not undoable (r1: re-apply, don't unwind).
            // A resolution is not undoable either — a ruling is retracted by
            // ruling again on a fresh proposal, never by erasing the record
            // that a review happened.
            StoredIdentityOpAction::Undo { .. }
            | StoredIdentityOpAction::ProposalResolution { .. } => {
                return Err(Error::IdentityTopologyRejected(
                    IdentityTopologyRejection::NotUndoable { event: *event },
                ));
            }
            // A FACET event is not undoable either, and the fold's own undo
            // rule ([`evaluate_fold_undo`]) already says so — the door only
            // repeats it. A facet op moves NO lifecycle state (r6: the base
            // stays `Active`), so this family's undo currency test — "is this
            // event still the topology writer for the entities it shelled?" —
            // has nothing to test, and every facet event would be undoable
            // forever, repeatedly. Reversing one is also not an edge
            // retraction but an ENTITY retraction: the minted masks are live
            // ARCH-0022 entities that other records may already reference, and
            // deleting entities is ARCH-0038's door, not this one. Retiring a
            // mask is a split of that FACET, which this family already
            // expresses.
            StoredIdentityOpAction::Facet { .. } => {
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

        let mut effects = Vec::new();
        if write.is_effective() {
            for (src, kind, tgt) in removed_edges {
                effects.push(BatchOp::DeleteEdge { src, kind, tgt });
            }
            // ONE-1745: the reverted event's assignment rows go with its shell
            // edges — same lifecycle, same door. Scoped to THIS event's rows,
            // so a sibling event's assignments on the same origin survive.
            // Derived from the stored rows rather than re-resolved from the
            // map, so a claim deleted since the apply cannot strand a row.
            if let StoredIdentityOpAction::Split { entity, .. } = &record.action {
                clear_reassignment_rows_in_txn(&self.store, wtxn, entity, Some(event))?;
            }
        }
        let transitions = shelled
            .into_iter()
            .map(|entity| (entity, EntityLifecycleState::Active))
            .collect();
        self.write_identity_event_in_txn(
            wtxn,
            EntityId::now(),
            write,
            now,
            StoredIdentityOpAction::Undo { target: *event },
            None,
            effects,
            transitions,
        )
    }

    /// Resolves a parked `Proposed` identity-topology event (ARCH-0055 r7):
    /// applies the proposed op (`Approve`), applies an AMENDED form of it
    /// (`AmendThenApprove`), or retires the park with zero topology effects
    /// (`Reject`). All three paths append exactly ONE proposal-resolution
    /// event in the same write txn, which is both the retirement of the park
    /// and the substrate the `ProposalOutcome` receipt projects from.
    ///
    /// An approving ruling applies through the ordinary
    /// [`Vault::apply_identity_topology_op`] machinery under
    /// `ClaimApprovalStatus::Approved`, so the applied op lands as its own
    /// ordinary ledger event with its own effects — the resolution row
    /// records the DECISION, never a second copy of the effect. The park
    /// itself is never rewritten (r1).
    ///
    /// An amendment may only NARROW what the decider reviewed: the amended
    /// body must decode to the same op kind and name a subset of the
    /// proposal's subjects, else
    /// [`Error::IdentityProposalAmendmentOutOfScope`] and nothing is
    /// written. This is the pin that keeps amendment from being an
    /// op-substitution capability.
    ///
    /// `write` carries the RULER's consent axes (which must be effective —
    /// a ruling is the act of deciding, so it cannot itself be parked);
    /// the ramp scope stamped on the receipt describes the PROPOSER.
    ///
    /// Returns the recorded outcome and the resolution event's id, which is
    /// also the receipt handle.
    pub fn resolve_identity_proposal(
        &self,
        proposal: &EntityId,
        ruling: ProposalRuling<'_>,
        write: &IdentityOpWrite,
        now: u64,
    ) -> Result<(ProposalOutcome, EntityId)> {
        let mut wtxn = self.store.env.write_txn()?;
        let resolved =
            self.resolve_identity_proposal_in_txn(&mut wtxn, proposal, ruling, write, now)?;
        wtxn.commit()?;
        Ok(resolved)
    }

    /// Transaction-composable [`Vault::resolve_identity_proposal`].
    pub(crate) fn resolve_identity_proposal_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        proposal: &EntityId,
        ruling: ProposalRuling<'_>,
        write: &IdentityOpWrite,
        now: u64,
    ) -> Result<(ProposalOutcome, EntityId)> {
        if !write.is_effective() {
            return Err(Error::IdentityTopologyRejected(
                IdentityTopologyRejection::ProposalRulingNotEffective,
            ));
        }
        self.validate_identity_op_actor_in_txn(&*wtxn, write)?;

        let record = self
            .identity_topology_event_in_txn(&*wtxn, proposal)?
            .ok_or(Error::EntityNotFound)?;
        // The resolution rule, shared with replicated admission: the park
        // is still open, the fold has not retired it, and the ruling's own
        // axis is effective. The replicated replay of the row this door is
        // about to write re-derives exactly these cells from the ledger.
        let proposed_op = self.validate_identity_proposal_resolution_in_txn(
            &*wtxn,
            proposal,
            &record,
            write.approval,
            None,
        )?;

        // Validate the amendment BEFORE anything is written: an out-of-scope
        // body must leave the park open and untouched.
        let amended = match ruling {
            ProposalRuling::AmendThenApprove(body) => {
                let amended_op = decode_identity_op_amendment(body).map_err(|_| {
                    Error::IdentityProposalAmendmentOutOfScope("amended body is malformed")
                })?;
                assert_amendment_in_scope(&proposed_op, &amended_op)?;
                Some((amended_op, body.to_vec()))
            }
            ProposalRuling::Approve | ProposalRuling::Reject => None,
        };

        let scope = self.proposal_scope_in_txn(&*wtxn, &record, &proposed_op)?;
        let proposer_evidence = record.evidence.as_ref();
        let (outcome, amended_body) = match (&ruling, amended) {
            (ProposalRuling::Reject, _) => (ProposalOutcome::Rejected, None),
            (ProposalRuling::Approve, _) => {
                self.apply_resolved_identity_op_in_txn(
                    wtxn,
                    &proposed_op,
                    proposer_evidence,
                    write,
                    now,
                )?;
                (ProposalOutcome::ApprovedUntouched, None)
            }
            (ProposalRuling::AmendThenApprove(_), Some((amended_op, body))) => {
                self.apply_resolved_identity_op_in_txn(
                    wtxn,
                    &amended_op,
                    proposer_evidence,
                    write,
                    now,
                )?;
                (ProposalOutcome::ApprovedAmended, Some(body))
            }
            // `amended` is Some exactly when the ruling is AmendThenApprove.
            (ProposalRuling::AmendThenApprove(_), None) => {
                return Err(Error::InvariantViolation(
                    "identity proposal amendment decode state",
                ));
            }
        };

        let event = self.write_identity_event_in_txn(
            wtxn,
            EntityId::now(),
            write,
            now,
            StoredIdentityOpAction::ProposalResolution {
                proposal: *proposal,
                outcome,
                scope,
                amended_body,
            },
            None,
            Vec::new(),
            Vec::new(),
        )?;
        let IdentityOpOutcome::Applied {
            event: event_id, ..
        } = event
        else {
            // The effective-consent check at the top of this door makes the
            // parked/no-op shapes unreachable.
            return Err(Error::InvariantViolation(
                "identity proposal resolution must be effective",
            ));
        };
        Ok((outcome, event_id))
    }

    /// Applies the op a ruling approved, under `Approved` consent — the
    /// decider's ruling IS the approval, whatever axis the original
    /// proposal carried. The proposal row's evidence rides along: the
    /// stored-action codec reconstructs an op without it
    /// (`to_fold_action` carries no envelope data), and an approved ruling
    /// must not silently sever the decision from the refs and rationale
    /// that motivated it.
    fn apply_resolved_identity_op_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        op: &IdentityTopologyOp,
        proposer_evidence: Option<&IdentityOpEvidence>,
        write: &IdentityOpWrite,
        now: u64,
    ) -> Result<()> {
        let applied_write = IdentityOpWrite {
            approval: ClaimApprovalStatus::Approved,
            ..*write
        };
        let op = match (proposer_evidence, op) {
            (Some(evidence), IdentityTopologyOp::Merge(merge)) => {
                IdentityTopologyOp::Merge(MergeOp {
                    evidence: evidence.clone(),
                    ..merge.clone()
                })
            }
            (Some(evidence), IdentityTopologyOp::Split(split)) => {
                IdentityTopologyOp::Split(SplitOp {
                    evidence: evidence.clone(),
                    ..split.clone()
                })
            }
            _ => op.clone(),
        };
        self.apply_identity_topology_op_in_txn(wtxn, &op, &applied_write, now)?;
        Ok(())
    }

    /// Stamps the DEC-0006 ramp scope of a resolved proposal: the op kind,
    /// the registry class name of the op's primary target, and the
    /// PROPOSING actor.
    fn proposal_scope_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        record: &StoredIdentityOpEvent,
        op: &IdentityTopologyOp,
    ) -> Result<ProposalScope> {
        let target = proposal_scope_target(op)?;
        let target_class = self
            .get_entity_type_in_txn(rtxn, &target)?
            .and_then(entity_type_registry_entry)
            .ok_or(Error::EntityNotFound)?
            .kind;
        Ok(proposal_scope_of(record, target_class))
    }

    /// THE proposal-resolution rule, run by BOTH doors a resolution row can
    /// enter through — the local [`Vault::resolve_identity_proposal_in_txn`]
    /// ruling and replicated type-76 admission. One validator, never two
    /// drifting copies: the local door enforces exactly what a remote peer's
    /// replay of the same row must later re-derive.
    ///
    /// All four cells, evaluated in ONE read against the store:
    /// the named park EXISTS and is still `Proposed` (an op row, never an
    /// undo or a resolution); the fold has not already retired it; the
    /// RULING's consent axis is effective — `ruling_approval` is the
    /// resolution's own axis (`write.approval` at the local door,
    /// `record.approval` on the wire), because deciding is itself an
    /// effective act and a resolution authored under a parked or consent-
    /// rejected axis is no ruling at all; and the stamped ramp scope is
    /// DERIVED from the proposal's own row, so a row cannot carry a scope
    /// it was never ruled under. Returns the decoded proposed op (the door
    /// applies it; replicated admission only checks, never applies).
    fn validate_identity_proposal_resolution_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        proposal: &EntityId,
        proposal_record: &StoredIdentityOpEvent,
        ruling_approval: ClaimApprovalStatus,
        stamped: Option<&ProposalScope>,
    ) -> Result<IdentityTopologyOp> {
        if !matches!(
            ruling_approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        ) {
            return Err(Error::IdentityTopologyRejected(
                IdentityTopologyRejection::ProposalRulingNotEffective,
            ));
        }
        if proposal_record.approval != ClaimApprovalStatus::Proposed {
            return Err(Error::IdentityTopologyRejected(
                IdentityTopologyRejection::NotProposed { event: *proposal },
            ));
        }
        let IdentityTopologyAction::Apply(proposed_op) = proposal_record.action.to_fold_action()
        else {
            // Undo and resolution rows are never `Proposed`-parked ops a
            // ruling can act on; the approval check above already excludes
            // them, so this is defence at the type seam.
            return Err(Error::IdentityTopologyRejected(
                IdentityTopologyRejection::NotProposed { event: *proposal },
            ));
        };
        // The fold a fresh resolution is judged against EXCLUDES the row
        // being admitted — a replicated event validates against history
        // alone, and the local door runs this before its own row exists.
        let fold =
            fold_identity_topology_log(&self.fold_effective_identity_topology_events_in_txn(rtxn)?);
        if fold.resolved_proposals.contains_key(proposal) {
            return Err(Error::IdentityTopologyRejected(
                IdentityTopologyRejection::ProposalAlreadyResolved {
                    proposal: *proposal,
                },
            ));
        }
        if let Some(stamped) = stamped {
            let derived = self.proposal_scope_in_txn(rtxn, proposal_record, &proposed_op)?;
            if stamped.op_kind != derived.op_kind
                || stamped.target_class != derived.target_class
                || stamped.actor != derived.actor
            {
                return Err(Error::IdentityTopologyRejected(
                    IdentityTopologyRejection::ResolutionRuleMismatch {
                        reason: "stamped ramp scope is not the proposal's derived tuple",
                    },
                ));
            }
        }
        Ok(proposed_op)
    }

    /// Reads one type-76 ledger event record. `Ok(None)` when the id is
    /// absent; a present id of another type is a typed mismatch; a present
    /// record that fails decode is corruption (the family is engine-
    /// authored and door-validated).
    pub fn identity_topology_event(&self, id: &EntityId) -> Result<Option<StoredIdentityOpEvent>> {
        let rtxn = self.store.env.read_txn()?;
        self.identity_topology_event_in_txn(&rtxn, id)
    }

    /// CLAIM ids a topology decision assigned to `target` (ARCH-0055 r2/r5),
    /// ascending and deduplicated.
    ///
    /// TWO witnesses, because the two arms record assignment differently and
    /// a target is at most one of them, so the union is exact:
    /// - a SPLIT HEAD reads the reassignment index — a split assignment has
    ///   no structural witness at all (no edge moves, and r6 forbids
    ///   rewriting the claim's subject), so the engine-authored index IS the
    ///   record;
    /// - a FACET reads its canonical `facet_of` stamps, the same rows the
    ///   local query filter and the federation selector already honor.
    ///
    /// This is a READ over records ABOUT the claims. The claims themselves
    /// are untouched: every returned claim still carries the subject its
    /// writer stated, which is what keeps an unmerge possible (r6).
    pub fn claims_assigned_to(&self, target: &EntityId) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        // The destination half of the index carries no payload — the key is
        // the whole row — so every scanned row is kept.
        let mut claims = reassignment_claims_for_prefix_in_txn(
            &self.store,
            &rtxn,
            REASSIGNMENT_TARGET_META_PREFIX,
            target,
            |_| true,
        )?;
        claims.extend(self.filtered_edge_peers(
            &rtxn,
            &self.store.edges_in,
            target,
            EdgeKind::FacetOf,
            Some(ENTITY_TYPE_CLAIM),
            "facet scoped claims",
        )?);
        Ok(claims.into_iter().collect())
    }

    /// CLAIM ids a split left on `origin` as EXPLICIT ambiguous residue
    /// (r2): the decision looked at them and declined to attribute them, so
    /// they stay where they are and stay countable as unresolved.
    ///
    /// Distinct from "unmapped": a claim the map never named is simply not
    /// part of the decision, while a residue row is a recorded judgment that
    /// the claim could not be attributed. Never force-assigned to a head.
    pub fn ambiguous_residue_claims(&self, origin: &EntityId) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        let assigned = self.assigned_away_from_in_txn(&rtxn, origin)?;
        let residue = reassignment_claims_for_prefix_in_txn(
            &self.store,
            &rtxn,
            REASSIGNMENT_ORIGIN_META_PREFIX,
            origin,
            |target| target.is_none(),
        )?;
        Ok(residue
            .into_iter()
            .filter(|claim| !assigned.contains(claim))
            .collect())
    }

    /// CLAIM ids that still read as `origin`'s after its splits: everything
    /// subject-bound to it MINUS everything a split assigned to a head.
    ///
    /// The subtraction is why this is not [`Vault::claims_for_subject`]: a
    /// fully-mapped split assigns every claim away and leaves ZERO here,
    /// while the claims' stored subjects still all say `origin` (r6). The
    /// subject is provenance; the assignment is the current reading.
    pub fn claims_remaining_on_origin(&self, origin: &EntityId) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        let assigned = self.assigned_away_from_in_txn(&rtxn, origin)?;
        Ok(self
            .claims_for_subject_in_txn(&rtxn, origin)?
            .into_iter()
            .filter(|claim| !assigned.contains(claim))
            .collect())
    }

    /// The claims some split routed AWAY from `origin` to a head.
    fn assigned_away_from_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        origin: &EntityId,
    ) -> Result<BTreeSet<EntityId>> {
        reassignment_claims_for_prefix_in_txn(
            &self.store,
            rtxn,
            REASSIGNMENT_ORIGIN_META_PREFIX,
            origin,
            |target| target.is_some(),
        )
    }

    /// The ARCH-0022 FACET (type-13) masks minted for `base`, read from the
    /// canonical `has_facet` edges the facet op wired.
    ///
    /// Masks are LIVE entities, not shells: `resolve_entity` of a facet is
    /// the facet itself, and no redirect row is minted for one.
    pub fn facets_of(&self, base: &EntityId) -> Result<Vec<EntityId>> {
        self.targets(base, EdgeKind::HasFacet, Some(ENTITY_TYPE_FACET))
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
            // An undo inherits the participant validity of the event it
            // names; a resolution must instead satisfy the SAME door rule
            // the local `resolve_identity_proposal` enforced — replayed
            // verbatim, never a lighter replay-side pass.
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
            IdentityTopologyAction::ResolveProposal { proposal, .. } => {
                let StoredIdentityOpAction::ProposalResolution {
                    scope,
                    amended_body,
                    ..
                } = &record.action
                else {
                    return Err(Error::InvariantViolation(
                        "replicated resolution row desugars to ResolveProposal",
                    ));
                };
                let Some(entity_type) = self.get_entity_type_in_txn(rtxn, &proposal)? else {
                    return Ok(());
                };
                if entity_type != ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
                    return Err(Error::InvalidEntityType(entity_type));
                }
                let proposal_record = self
                    .identity_topology_event_in_txn(rtxn, &proposal)?
                    .ok_or(Error::CorruptedIndex("identity topology event index"))?;
                // Exactly the local door's rule, replayed: the ruling axis
                // is this row's own consent (`record.approval`), the stamp
                // must match the tuple the proposal row derives, and an
                // amended body must stay inside review.
                let proposed_op = self.validate_identity_proposal_resolution_in_txn(
                    rtxn,
                    &proposal,
                    &proposal_record,
                    record.approval,
                    Some(scope),
                )?;
                if let Some(amended_body) = amended_body {
                    let amended_op = decode_identity_op_amendment(amended_body).map_err(|_| {
                        Error::InvalidIdentityTopologyEventBody(
                            "identity topology proposal resolution amended body",
                        )
                    })?;
                    assert_amendment_in_scope(&proposed_op, &amended_op)?;
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
    /// `pub(crate)`: the receipt projection folds the same projection to
    /// suppress fold-rejected duplicate rulings.
    pub(crate) fn fold_effective_identity_topology_events_in_txn(
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
                IdentityTopologyAction::ResolveProposal { proposal, .. } => self
                    .get_entity_type_in_txn(rtxn, proposal)?
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

    /// Stamps `seq`, writes the type-76 event record under the caller's
    /// `event_id` plus the staged effect ops atomically, and shapes the
    /// outcome from the consent axis.
    ///
    /// The id is the CALLER's because an op's effects may have to be filed
    /// under it before the record exists — the ONE-1745 assignment index
    /// keys every row by the event that stated it.
    #[expect(
        clippy::too_many_arguments,
        reason = "single internal chokepoint for the door's event+effects commit"
    )]
    fn write_identity_event_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        event_id: EntityId,
        write: &IdentityOpWrite,
        now: u64,
        action: StoredIdentityOpAction,
        evidence: Option<IdentityOpEvidence>,
        effects: Vec<BatchOp>,
        transitions: Vec<(EntityId, EntityLifecycleState)>,
    ) -> Result<IdentityOpOutcome> {
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
        // Order matters inside the batch: a facet op's minted FACET rows
        // precede the `facet_of` stamps that point at them, and ONE-1645's
        // write-time table fails closed on a stamp whose endpoint has no row.
        ops.extend(effects);
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
            // ONE-1744 redirect maintenance, AFTER the edges land: the
            // projection derives each row from the post-op shell edges (plus
            // the ledger for the zero-head arm), so running it before
            // `apply_ops` would project the topology this event replaces.
            // A parked event moves no topology and maintains nothing.
            let touched: BTreeSet<EntityId> =
                transitions.iter().map(|(entity, _)| *entity).collect();
            // The zero-head witness comes from the ACTION, not a fold: this
            // door already knows whether the op it just wrote is a zero-head
            // split, and folding the event family here would make a run of N
            // topology ops O(N²).
            let zero_head_shells: BTreeSet<EntityId> = match &record.action {
                StoredIdentityOpAction::Split { entity, heads, .. } if heads.is_empty() => {
                    BTreeSet::from([*entity])
                }
                _ => BTreeSet::new(),
            };
            crate::identity_redirect::maintain_redirect_projection_in_txn(
                &self.store,
                wtxn,
                &touched,
                &zero_head_shells,
            )?;
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
