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
//! Reassignment-map application and FACET minting arm in ONE-1745.
//!
//! Anti-merge assertions (ONE-1746): `assert_distinct` mints a public
//! `entity.distinct_from` CLAIM keyed by the normalized symmetric pair, so
//! (a, b) and (b, a) are ONE claim. Unlike the topology ops around it the
//! claim carries its own consent axis in its `appr` column — it rides the
//! ordinary claim approval flow, is agent-mintable, and is NOT a reserved
//! engine-only namespace. §6 re-proposal suppression reads that claim:
//! lifecycle-ACTIVE and approval in {`Approved`, `Auto`} suppresses a
//! PROPOSED merge over the covered pair, and nothing else — an owner's
//! explicit `Auto`/`Approved` merge is never blocked, unrelated pairs are
//! never touched, and superseding or retracting the claim lifts suppression
//! with no shadow state to unwind.
//!
//! RE-ASSERTION IS THE PARKED ASSERTION'S RESOLUTION DOOR (ONE-1746). A
//! `Proposed` assert_distinct parks on its own claim row, and unlike merge
//! and split it can never reach [`Vault::resolve_identity_proposal`](crate::Vault::resolve_identity_proposal) —
//! `proposal_scope_target` is unarmed for the kind, because the op names no
//! entity whose registry class could scope a ramp. The door that rules it is
//! therefore the op itself: an EFFECTIVE assert_distinct over a pair a parked
//! row already covers PROMOTES that row's approval in place and returns its
//! id. So the family contract holds without a second door — the park carries
//! zero effect until ruled, the ruling is an ordinary op with its own ledger
//! event, and one pair keeps exactly one claim across both writes.
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

mod distinct_claim;
mod event_body_codec;
mod ledger_fold;
mod lifecycle_state;
mod op_apply;
mod op_undo;
mod op_vocabulary;
mod proposal_resolution;
mod reassignment_map;
mod replicated_event_validation;
mod shell_edge_reconcile;
mod store_entity_helpers;
mod stored_event;
mod topology_queries;
mod transition_table;
mod wire_keys;

pub use distinct_claim::distinct_pair_key;
pub use ledger_fold::{
    IdentityTopologyAction, IdentityTopologyEvent, IdentityTopologyFold, fold_identity_topology_log,
};
pub use lifecycle_state::{EntityLifecycleState, merge_lifecycle_states};
pub use op_apply::{IdentityOpOutcome, IdentityOpWrite};
pub use op_vocabulary::{
    AssertDistinctOp, FacetOp, FacetSpec, IdentityOpEvidence, IdentityTopologyOp, MergeOp, SplitOp,
    SurvivorshipPlan,
};
pub use proposal_resolution::{decode_identity_op_amendment, encode_identity_op_amendment};
pub use reassignment_map::{
    ReassignmentEntry, ReassignmentMap, ReassignmentStats, ReassignmentTarget,
};
pub use stored_event::{StoredIdentityOpAction, StoredIdentityOpEvent};
pub use transition_table::{
    IdentityTopologyRejection, ProposalOutcome, ProposalRuling, ProposalScope, evaluate_transition,
};
pub use wire_keys::{PREDICATE_ENTITY_DISTINCT_FROM, PROPOSAL_SCOPE_ACTOR_UNATTRIBUTED};

pub(crate) use distinct_claim::validate_distinct_from_claim_structure;
pub(crate) use event_body_codec::{
    decode_identity_topology_event_body, encode_identity_topology_event_body,
    validate_identity_topology_event_body_bytes,
};
// Reached only from the sync bridge, so a plain re-export would read as unused
// in a non-sync build of the library.
#[cfg_attr(not(feature = "sync"), allow(unused_imports))]
pub(crate) use event_body_codec::decode_replicated_identity_topology_event_body;
pub(crate) use lifecycle_state::{
    identity_topology_shell_peers_for_store_in_txn, note_zero_head_split_in_txn,
    shell_edge_sources_for_store_in_txn, zero_head_split_shells_for_store_in_txn,
};
pub(crate) use op_vocabulary::is_identity_topology_op_kind;
pub(crate) use reassignment_map::{
    REASSIGNMENT_ORIGIN_META_PREFIX, REASSIGNMENT_TARGET_META_PREFIX, ReassignmentContext,
    apply_reassignment_in_txn,
};
// Reached only from the sync bridge's test lane, so a plain re-export would read
// as unused in a non-sync test build of the library.
#[cfg(test)]
#[cfg_attr(not(feature = "sync"), allow(unused_imports))]
pub(crate) use shell_edge_reconcile::test_hooks;
pub(crate) use shell_edge_reconcile::{
    identity_topology_shell_sources_for_store_in_txn,
    reconcile_identity_topology_for_materialized_entities_in_txn,
    reconcile_shell_edges_after_eviction_in_txn,
};
pub(crate) use wire_keys::{
    IDENTITY_TOPOLOGY_REPLICATED_SEQ_CEILING, IDENTITY_TOPOLOGY_SEQ_KEY,
    MAX_IDENTITY_TOPOLOGY_EVENT_BODY_BYTES, MAX_IDENTITY_TOPOLOGY_EVENT_FACETS,
    MAX_IDENTITY_TOPOLOGY_EVENT_PARTICIPANTS,
};
// Reached only from the sync bridge's test lane, so a plain re-export would read
// as unused in a non-test build of the library.
#[cfg(test)]
pub(crate) use wire_keys::IDENTITY_TOPOLOGY_LOCAL_SEQ_HEADROOM;

#[cfg(test)]
mod tests;
