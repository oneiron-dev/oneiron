//! Pinned wire vocabulary of the identity-topology family: the type-76 body
//! field keys, the reassignment-map row keys, the event-kind strings, and the
//! sequence/size caps every other file in this module encodes against.

pub use crate::write_envelope::identity_pair::PREDICATE_ENTITY_DISTINCT_FROM;

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

/// Hard limits of ONE stored record of the append-only replicated family,
/// never of a decision (FIX 10188). The body limit bounds decode/allocation
/// work before MessagePack parsing; the participant limit bounds one inline
/// record's fold and reconciliation fan-out. A decision past either is stored
/// as an operation manifest plus bounded operation parts
/// ([`super::operation_parts`]) and applied whole.
pub(super) const MAX_IDENTITY_TOPOLOGY_EVENT_BODY_BYTES: usize = 64 * 1024;
pub(super) const MAX_IDENTITY_TOPOLOGY_EVENT_PARTICIPANTS: usize = 256;

/// Masks one INLINE facet record may name (ONE-1745). A facet op names
/// exactly ONE pre-existing entity, so the participant bound above does not
/// reach its fan-out — minting is the op's own effect. Bounded by the same
/// number for the same reason; a facet that mints more is stored in
/// operation parts (FIX 10188).
pub(super) const MAX_IDENTITY_TOPOLOGY_EVENT_FACETS: usize =
    MAX_IDENTITY_TOPOLOGY_EVENT_PARTICIPANTS;

/// Payload bytes one operation part carries (FIX 10188). The rest of the
/// body bound is left for the part's envelope, so every part decodes under
/// [`MAX_IDENTITY_TOPOLOGY_EVENT_BODY_BYTES`].
pub(super) const IDENTITY_TOPOLOGY_OPERATION_PART_BYTES: usize =
    MAX_IDENTITY_TOPOLOGY_EVENT_BODY_BYTES - 4 * 1024;

pub(super) const BODY_KEY_KIND: &str = "kind";
pub(super) const BODY_KEY_SEQ: &str = "seq";
/// Producer proof that every participant and the bound author passed admission.
pub(super) const BODY_KEY_VERIFIED: &str = "verified";
/// Non-personal invalidity discovered before erasing an author/participant.
pub(super) const BODY_KEY_INVALIDATED: &str = "invalidated";
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
/// The op event an approving resolution applied (FIX 9966): the undo
/// currency of the approval. Omitted when the ruling applied nothing.
pub(super) const BODY_KEY_APPLIED_EVENT: &str = "applied";
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
/// The origin claims a facet event forked (r9), sorted by id. Each fork's id
/// derives from the event and its origin, so this list is the undo door's
/// authoritative dependency set. Omitted from the wire when empty.
pub(super) const BODY_KEY_FORKED: &str = "frk";
pub(super) use crate::write_envelope::identity_pair::{BODY_KEY_PAIR_A, BODY_KEY_PAIR_B};
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
/// Automatic retirement of a proposal whose participant was deleted.
pub(super) const EVENT_KIND_PROPOSAL_CANCELLATION: &str = "proposal_cancellation";
/// Wire kind of an operation manifest (FIX 10188): the root record of a
/// merge, split or facet decision too large for one record. Its id, seq and
/// consent are the decision's; its signed admission binds the payload
/// length, digest and part count it names.
pub(super) const EVENT_KIND_OPERATION_MANIFEST: &str = "operation_manifest";
/// Wire kind of one operation part: a bounded slice of its manifest's
/// payload, inert on its own.
pub(super) const EVENT_KIND_OPERATION_PART: &str = "operation_part";
/// The decision kind a manifest carries: merge, split or facet.
pub(super) const BODY_KEY_OPERATION_KIND: &str = "op_kind";
pub(super) const BODY_KEY_OPERATION_PARTS: &str = "op_parts";
pub(super) const BODY_KEY_OPERATION_LENGTH: &str = "op_len";
pub(super) const BODY_KEY_OPERATION_DIGEST: &str = "op_digest";
/// The manifest an operation part belongs to.
pub(super) const BODY_KEY_OPERATION_ROOT: &str = "op_root";
pub(super) const BODY_KEY_OPERATION_INDEX: &str = "op_index";
pub(super) const BODY_KEY_OPERATION_PAYLOAD: &str = "op_payload";

/// Ramp-scope actor stamped when the resolved proposal bound no proposer
/// handle (FIX 9870): no actor wrote it, or its seal predates admission v4.
/// The DEC-0006 tuple is total — an unattributed proposer is its own
/// scope, never an absent field (MS-06 rebuilds per-scope stats from
/// receipts ALONE, so a missing component would silently merge scopes).
pub const PROPOSAL_SCOPE_ACTOR_UNATTRIBUTED: &str = "unattributed";

pub(super) const PLAN_READ_THROUGH: &str = "read_through";

pub(super) const EVIDENCE_KEY_REFS: &str = "refs";
pub(super) const EVIDENCE_KEY_RATIONALE: &str = "rationale";

/// Signed, append-only admission disposition for one immutable decision core.
pub(super) const EVENT_KIND_ADMISSION_DISPOSITION: &str = "admission_disposition";
pub(super) const BODY_KEY_CORE_DIGEST: &str = "core_digest";
pub(super) const BODY_KEY_VERDICT: &str = "verdict";
pub(super) const BODY_KEY_REASON: &str = "reason";
pub(super) const BODY_KEY_SIGNER: &str = "signer_pk";
/// The MACHINE whose install key signed a seal: its carrier (mesh
/// PR2-topology).
pub(super) const BODY_KEY_CARRIER: &str = "carrier";
/// A decision seal's owner act (`topology_seal`), the authority-log record
/// map; exclusive with [`BODY_KEY_SEAL_CAUSE`].
pub(super) const BODY_KEY_SEAL_ACT: &str = "act";
/// An engine seal's typed cause; exclusive with [`BODY_KEY_SEAL_ACT`].
pub(super) const BODY_KEY_SEAL_CAUSE: &str = "cause";
/// A decision seal's causal point: the authority-log heads its carrier held,
/// canonical ascending 32-byte hashes, never on an engine seal (FIX 4649).
pub(super) const BODY_KEY_AUTHORITY_HEADS: &str = "authority_heads";
/// A v4 seal's proposer stamp (FIX 9870): the proposer scope handle of a
/// validated merge or split proposal, or nil for every other decision. A v3
/// seal carries no such field.
pub(super) const BODY_KEY_PROPOSER_SCOPE_ACTOR: &str = "proposer_scope_actor";
pub(super) const BODY_KEY_SIGNATURE: &str = "signature";
pub(super) const EVENT_KIND_AUTHOR_ATTRIBUTION: &str = "author_attribution";
pub(super) const EVENT_KIND_AUTHOR_REDACTION: &str = "author_redaction";
pub(super) const BODY_KEY_ATTR_ACTOR: &str = "at_actor";
pub(super) const BODY_KEY_ATTR_CLASS: &str = "at_class";
