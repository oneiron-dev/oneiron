//! Pinned wire vocabulary of the identity-topology family: the type-76 body
//! field keys, the reassignment-map row keys, the event-kind strings, and the
//! sequence/size caps every other file in this module encodes against.

/// Predicate of the anti-merge claim (ARCH-0055 §9 G.1 row): symmetric
/// `entity.distinct_from` pair, conflict-set keyed by [`distinct_pair_key`](super::distinct_pair_key).
/// Unlike the op events (engine-authored type-76 records), distinct_from
/// stays a public CLAIM: it is a statement about the world, not an action.
///
/// The write path is the literal-dispatch arm in
/// `crate::claim::validate_claim_body_and_decode`, which routes every
/// type-0 write of this predicate — the op door's and an agent's alike —
/// through `validate_distinct_from_claim_structure`. It is deliberately
/// NOT a `CLAIM_PREDICATE_REGISTRY` entry: that list is the core/companion/
/// eiri LAYER schema list (`registered_predicates_carry_layer_prefix` pins
/// the prefix), and `entity.*` is a family namespace, not a layer — the
/// same reason the fifteen other predicate families validate through their
/// own dispatch arm without a registry row. The registry gates no write
/// (well-formed unknown predicates are accepted), so the arm alone is what
/// enforces the pair.
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
pub(super) const IDENTITY_TOPOLOGY_REPLICATED_SEQ_LIMIT: u64 =
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

pub(super) const BODY_KEY_KIND: &str = "kind";
pub(super) const BODY_KEY_SEQ: &str = "seq";
pub(super) const BODY_KEY_AT: &str = "at";
pub(super) const BODY_KEY_ACTOR: &str = "actor";
pub(super) const BODY_KEY_ACTOR_CLASS: &str = "actor_class";
pub(super) const BODY_KEY_SOURCE: &str = "src";
pub(super) const BODY_KEY_APPROVAL: &str = "appr";
pub(super) const BODY_KEY_CONFIDENCE: &str = "conf";
pub(super) const BODY_KEY_EVIDENCE: &str = "evid";
pub(super) const BODY_KEY_SOURCES: &str = "sources";
pub(super) const BODY_KEY_SURVIVOR: &str = "survivor";
pub(super) const BODY_KEY_PLAN: &str = "plan";
pub(super) const BODY_KEY_ENTITY: &str = "entity";
pub(super) const BODY_KEY_HEADS: &str = "heads";
pub(super) const BODY_KEY_MAP: &str = "map";
pub(super) const BODY_KEY_TARGET: &str = "target";
pub(super) const BODY_KEY_PROPOSAL: &str = "proposal";
pub(super) const BODY_KEY_OUTCOME: &str = "outcome";
pub(super) const BODY_KEY_SCOPE_OP_KIND: &str = "sc_op";
pub(super) const BODY_KEY_SCOPE_TARGET_CLASS: &str = "sc_cls";
pub(super) const BODY_KEY_SCOPE_ACTOR: &str = "sc_actor";
pub(super) const BODY_KEY_AMENDED: &str = "amended";
/// Minted FACET entity ids of a facet event, in the op's spec order.
pub(super) const BODY_KEY_FACETS: &str = "facets";
/// Map rows the apply door actually recorded, and rows it left as ambiguous
/// residue. DECLARED counts live in the map itself
/// ([`ReassignmentMap::assigned_and_residue_counts`](super::ReassignmentMap::assigned_and_residue_counts)); these two are what
/// application produced, so the receipt can show the gap without a vault.
/// Omitted from the wire when zero, which keeps parked events and amendment
/// bodies byte-identical to their pre-ONE-1745 encoding.
pub(super) const BODY_KEY_APPLIED_ASSIGNED: &str = "asg";
pub(super) const BODY_KEY_APPLIED_RESIDUE: &str = "res";
/// Normalized distinct-pair keys (ONE-1746), shared by the type-76
/// `assert_distinct` event body AND the `entity.distinct_from` claim value:
/// one pair shape with one spelling, so the two surfaces cannot drift.
pub(super) const BODY_KEY_PAIR_A: &str = "a";
pub(super) const BODY_KEY_PAIR_B: &str = "b";
/// The CLAIM row an `assert_distinct` event carries its assertion in — the
/// row's id, so the event's effect is auditable from the ledger alone.
pub(super) const BODY_KEY_CLAIM: &str = "claim";

pub(super) const MAP_KEY_ITEM: &str = "item";
pub(super) const MAP_KEY_HEAD: &str = "head";
pub(super) const MAP_KEY_FACET: &str = "facet";

pub(super) const EVENT_KIND_MERGE: &str = "merge";
pub(super) const EVENT_KIND_SPLIT: &str = "split";
/// Wire kind of the ARCH-0055 r5 facet event (ONE-1745). Pinned string, in
/// the same reservation family as the other three kinds.
pub(super) const EVENT_KIND_FACET: &str = "facet";
/// Wire kind of the ARCH-0055 §6 anti-merge assertion (ONE-1746). Pinned
/// string, in the same reservation family as the other kinds.
pub(super) const EVENT_KIND_ASSERT_DISTINCT: &str = "assert_distinct";
pub(super) const EVENT_KIND_UNDO: &str = "undo";
/// Wire kind of the ARCH-0055 r7 proposal-resolution event (ONE-1747). The
/// resolution event IS the retirement of the park: the projector finds a
/// proposal already resolved by this row, so a second ruling is refused.
pub(super) const EVENT_KIND_PROPOSAL_RESOLUTION: &str = "proposal_resolution";

/// Ramp-scope actor stamped when the resolved proposal bound no deciding
/// actor. The DEC-0006 tuple is total — an unattributed proposer is its own
/// scope, never an absent field (MS-06 rebuilds per-scope stats from
/// receipts ALONE, so a missing component would silently merge scopes).
pub const PROPOSAL_SCOPE_ACTOR_UNATTRIBUTED: &str = "unattributed";

pub(super) const PLAN_READ_THROUGH: &str = "read_through";

pub(super) const EVIDENCE_KEY_REFS: &str = "refs";
pub(super) const EVIDENCE_KEY_RATIONALE: &str = "rationale";
