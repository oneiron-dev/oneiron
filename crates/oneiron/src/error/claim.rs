//! Claim-domain errors: predicate and actor-authority refusals, claim
//! lifecycle transitions, and the provenance-claim doors.
//!
//! Reached from the root as `Error::Claim(..)`, a transparent wrapper: Display
//! and `source()` are the leaf's, so every message string is what it was when
//! these variants sat flat on `Error`.

use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::EntityId;

use super::ErrorKind;

/// Claim-domain error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClaimError {
    /// Claim predicate violates the pinned D17 grammar (≥2 segments of
    /// `[a-z][a-z0-9_]*` joined by `.`, total ≤128 bytes).
    #[error("invalid claim predicate {predicate:?}: {reason}")]
    InvalidPredicate {
        predicate: String,
        reason: &'static str,
    },
    /// Claim predicate lives in the reserved `edge.*` namespace, which only
    /// the engine's internal provenance path may write (D17).
    #[error("reserved claim predicate namespace: {predicate:?}")]
    ReservedPredicate { predicate: String },
    /// The acting actor has no authority over the CLAIM it named — it did not
    /// author the claim, or it lacks the standing the operation requires over
    /// somebody else's.
    ///
    /// An authority denial, not a malformed request: the reference resolved,
    /// the body was well formed, and the operation is one the engine
    /// supports. What is missing is the actor's standing to perform it on THIS
    /// claim, which is why it classifies with the gate family rather than
    /// falling through to a request-shape error and telling a caller to fix a
    /// shape that was never wrong.
    ///
    /// Deliberately generic. It states the relationship that failed — actor
    /// versus claim — rather than one door's version of it, so the doors that
    /// share the relationship can share the error. `reason` carries the
    /// specific standing that was missing, in the voice of the door that
    /// checked it.
    #[error("actor lacks authority over this claim: {reason}")]
    ActorLacksClaimAuthority {
        /// Which standing was missing, as the checking door words it.
        reason: &'static str,
    },
    /// `edge.provenance` may only attach to SEMANTIC edge kinds; structural
    /// kinds (12-byte layout) never carry the two hot flags.
    #[error("edge.provenance subject kind {kind} is structural, not semantic")]
    ProvenanceOnStructuralEdge { kind: u8 },
    /// The caller-supplied `actor_class` is incompatible with the actor
    /// entity's kind (D13: PERSON → human|agent, MACHINE → system, anything
    /// else is never an actor). The engine never defaults an actor class.
    #[error("actor class {actor_class} is incompatible with actor entity type {actor_entity_type}")]
    ActorClassMismatch {
        actor_entity_type: u8,
        actor_class: u8,
    },
    /// An `edge.provenance` value record failed the pinned structural
    /// validation (the 10-key snake_case ABI — ONE-1138 vocabulary).
    /// Nothing was written.
    #[error("invalid edge.provenance body: {0}")]
    InvalidProvenanceBody(&'static str),
    /// A MODEL substrate descriptor failed validation (ONE-1138): an
    /// `ensure_model_substrate` name/version that is empty or oversized, or
    /// a provenance `substrate_ref` that does not name a stored MODEL
    /// (type byte 121) entity. Nothing was written.
    #[error("invalid model substrate: {0}")]
    InvalidModelSubstrate(&'static str),
    /// A receipt surface that is defined only for emit-adjacent receipts
    /// (the OF-369/RS9 context field-set, the OF-326 session-local receipt
    /// log) was given a non-emit receipt kind. Non-emit receipts project
    /// from their own stored substrates and never carry emit context.
    /// Nothing was written.
    #[error("{surface} requires an emit-adjacent receipt kind, got {kind}")]
    EmitAdjacentReceiptRequired {
        surface: &'static str,
        kind: &'static str,
    },
    /// A claim lifecycle transition (`supersede_claim` / `retract_claim`)
    /// targeted a claim whose `life` status is not `active`. Superseded and
    /// retracted claims are closed history (ARCH-0003: all non-current
    /// states are still stored — claims are never silently deleted) and
    /// cannot transition again. Nothing was written.
    #[error("claim already closed: lifecycle status is {status:?}")]
    ClaimAlreadyClosed { status: ClaimLifecycleStatus },
    /// A NAMED write verb (`supersede_claim` / `retract_claim` / a
    /// replacement-style `attest_edge_provenance`) addressed a claim that is
    /// no longer the head of its lifecycle chain. The claim id a verb names
    /// IS its version token (ONE-1936): there is no generation counter or
    /// ETag to compare, so a target whose `life` has moved off `active` is a
    /// STALE decision made against a view the store has since replaced.
    ///
    /// Distinct from [`ClaimError::ClaimAlreadyClosed`], which is the mechanical
    /// "closed history never transitions again" rule: this variant is the
    /// concurrency answer, and it carries `successor_short_id` — the
    /// resolvable `short_id:content_hash` ref of the chain's terminal head —
    /// so the caller can re-get the current truth and issue a NEW decision.
    ///
    /// The engine never retargets the verb at the successor, never rewrites
    /// the caller's target ref, and never degrades to a warning. Nothing was
    /// written; the guard and the mutation it protects share one transaction,
    /// so a staged replacement rolls back with it.
    #[error(
        "write verb target {} is no longer the lifecycle head (life is {lifecycle:?}); current head is {successor_short_id}",
        target.to_hex()
    )]
    WriteVerbTargetStale {
        target: EntityId,
        lifecycle: ClaimLifecycleStatus,
        successor_short_id: String,
    },
    /// `supersede_claim` was called with `new_id == old_id` — a claim
    /// cannot supersede itself. Nothing was written.
    #[error("claim cannot supersede itself")]
    ClaimSelfSupersession,
    /// A generic claim lifecycle op (`supersede_claim` / `retract_claim`)
    /// targeted a reserved-namespace (`edge.*`) provenance Claim. Provenance
    /// Claims drive the subject edge's derived hot flags, so their lifecycle
    /// is owned exclusively by the edge-provenance lifecycle API (the
    /// `put_edge_provenance` / `retract_edge_provenance` surface), which
    /// re-stamps the edge whenever the Claim changes. The generic ops reject
    /// instead of bypassing that re-stamp. Nothing was written.
    #[error(
        "claim predicate {predicate:?} is a reserved edge.* provenance claim; use the edge-provenance lifecycle API (put_edge_provenance / retract_edge_provenance), not the generic claim lifecycle ops"
    )]
    ProvenanceClaimLifecycle { predicate: String },
    /// A provenance lifecycle operation (retract / supersede) named an
    /// entity that is not an `edge.provenance` Claim — wrong type byte or
    /// wrong predicate. Nothing was written.
    #[error("not an edge.provenance claim: {0}")]
    NotAProvenanceClaim(&'static str),
    /// A provenance lifecycle operation targeted a Claim whose lifecycle is
    /// no longer `active` (double-retract, or supersede-after-close). The
    /// first close wins; nothing was written.
    #[error("edge.provenance claim is already closed: lifecycle is {lifecycle}")]
    ProvenanceClaimAlreadyClosed { lifecycle: &'static str },
    /// A provenance write named a `claim_id` that already exists in storage.
    /// Provenance claim ids are WRITE-ONCE: re-putting an existing id would
    /// overwrite the stored Claim in place — resurrecting a retracted or
    /// superseded wrapper as a fresh `active` body, bypassing
    /// [`ClaimError::ProvenanceClaimAlreadyClosed`] (ARCH-0003: "claims are never
    /// silently deleted"). The lifecycle operations (retract / supersede)
    /// are the only mutators of an existing provenance Claim. Nothing was
    /// written.
    #[error("edge.provenance claim id already in use: provenance claim ids are write-once")]
    ProvenanceClaimIdInUse,
    /// The prior Claim named in a supersede call addresses a different
    /// EdgeRef than the incoming Claim. Supersession is per subject edge —
    /// two Claims naming different EdgeRefs never supersede each other.
    #[error("edge.provenance subject mismatch: prior and new claims address different EdgeRefs")]
    ProvenanceSubjectMismatch,
    /// A provenance Claim cannot supersede itself (`prior_claim_id` equals
    /// `new_claim_id`).
    #[error("edge.provenance claim cannot supersede itself")]
    ProvenanceSelfSupersession,
    /// D14 precedence violation: the incoming Claim's envelope `learned_at`
    /// is older than the live frontier for its subject edge, so it can never
    /// take precedence ("a newer Claim takes precedence"). The engine
    /// refuses to write a dead-on-arrival provenance Claim.
    #[error(
        "edge.provenance precedence violation: incoming learned_at {incoming_learned_at} predates the live frontier {frontier_learned_at}"
    )]
    ProvenancePrecedenceViolation {
        incoming_learned_at: u64,
        frontier_learned_at: u64,
    },
    /// A plain (provenance-free) edge put targeted an edge that carries a
    /// 26-byte provenanced value — the silent-downgrade hole pinned by
    /// ONE-1113 (ARCH-0034 #write-protection, ratified 2026-06-13): "an
    /// unattributed write can never displace attributed truth as current
    /// state". The write is rejected typed and routed — never a silent strip
    /// of the two hot-flag bytes, never a silent preserve of them under the
    /// caller's new value. Both edge directions stay byte-identical and the
    /// live `edge.provenance` Claim stays live; nothing was written.
    #[error(
        "edge (kind {kind}) is provenanced: a plain edge put cannot displace attributed truth; modify the relation via put_edge_provenance / the actor-bound surface (as_actor), set weight via set_edge_weight, set VAD via set_edge_vad"
    )]
    EdgeIsProvenanced { kind: u8 },
}

impl ClaimError {
    /// Returns the stable category for this error.
    #[must_use]
    pub(crate) fn kind(&self) -> ErrorKind {
        match self {
            Self::InvalidPredicate { .. } => ErrorKind::InvalidPredicate,
            Self::ReservedPredicate { .. } => ErrorKind::ReservedPredicate,
            Self::ProvenanceOnStructuralEdge { .. } => ErrorKind::ProvenanceOnStructuralEdge,
            Self::ActorLacksClaimAuthority { .. } => ErrorKind::ActorLacksClaimAuthority,
            Self::ActorClassMismatch { .. } => ErrorKind::ActorClassMismatch,
            Self::InvalidProvenanceBody(_) => ErrorKind::InvalidProvenanceBody,
            Self::InvalidModelSubstrate(_) => ErrorKind::InvalidModelSubstrate,
            Self::EmitAdjacentReceiptRequired { .. } => ErrorKind::EmitAdjacentReceiptRequired,
            Self::ClaimAlreadyClosed { .. } => ErrorKind::ClaimAlreadyClosed,
            Self::WriteVerbTargetStale { .. } => ErrorKind::WriteVerbTargetStale,
            Self::ClaimSelfSupersession => ErrorKind::ClaimSelfSupersession,
            Self::ProvenanceClaimLifecycle { .. } => ErrorKind::ProvenanceClaimLifecycle,
            Self::NotAProvenanceClaim(_) => ErrorKind::NotAProvenanceClaim,
            Self::ProvenanceClaimAlreadyClosed { .. } => ErrorKind::ProvenanceClaimAlreadyClosed,
            Self::ProvenanceClaimIdInUse => ErrorKind::ProvenanceClaimIdInUse,
            Self::ProvenanceSubjectMismatch => ErrorKind::ProvenanceSubjectMismatch,
            Self::ProvenanceSelfSupersession => ErrorKind::ProvenanceSelfSupersession,
            Self::ProvenancePrecedenceViolation { .. } => ErrorKind::ProvenancePrecedenceViolation,
            Self::EdgeIsProvenanced { .. } => ErrorKind::EdgeIsProvenanced,
        }
    }
}
