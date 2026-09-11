//! ARCH-0053 §4/§9 `actor.*` claim ledger (SK-06, ONE-1739): what the system
//! has learned ABOUT AN ACTOR, written by projectors and the Dreamer — never
//! by the actor itself.
//!
//! ```text
//! TASK lane   ATTEMPT receipt ─▶ SK-04 projector ─▶ ExecutionLapse judgment ─┐
//!                                                                            ├─▶ write_actor_claim ─▶ actor.* CLAIM
//! CHAT lane   SESSION/TURN ────▶ SessionEnd wake ─▶ Dreamer distill ─────────┘        (the ONE door)
//! ```
//!
//! **Two inlets, one ledger.** The lanes differ in what they observe (a task's
//! receipts vs. a sitting's turns) and in nothing else: both mint the same four
//! rows, through the same chokepoint, with the same evidence obligation. That
//! is the shape ARCH-0053 §3 asks for — chat and task COMPOSE, they never blur
//! — and it is why [`write_actor_claim`] takes the evidence as a typed enum
//! rather than letting each caller stamp its own provenance.
//!
//! **The rows (§G.1 cardinalities are the contract).**
//!
//! | predicate | value | cardinality |
//! |---|---|---|
//! | [`PREDICATE_ACTOR_LESSON`] | normalized note | SET, keyed on the text |
//! | [`PREDICATE_ACTOR_FAILURE_MODE`] | normalized note | SET, keyed on the text |
//! | [`PREDICATE_ACTOR_SCOPE_NOTE`] | normalized note | SET, keyed on the text |
//! | [`PREDICATE_ACTOR_SKILL_FIT`] | fit in `0..=1` | ONE per `(actor, skill)`, superseding |
//! | [`PREDICATE_ACTOR_EDIT_COST`] | cost in `0..=1` | ONE per `(actor, scope)`, superseding |
//!
//! A set row DEDUPES rather than supersedes: two different lessons are two
//! standing facts, and re-observing one is not news. `skill_fit` is the
//! opposite — it is a current estimate, so a new one closes the old head and
//! the pair scope (`{skill}`) is the conflict-set key. Scoping fit per PAIR
//! rather than per actor is load-bearing: an actor good at one skill and bad at
//! another has two live rows, and the router ([`skill_fit_for`], SK-05's
//! bandit) reads exactly the one it asked about. `edit_cost` (ED-03, ONE-1759)
//! is the same estimate shape on a different axis — `{scope}` instead of
//! `{skill}` — and its third evidence lane cites amendment receipts rather than
//! attempt receipts.
//!
//! **Namespace, not `agent.*` (r1).** Actors are agents AND humans AND peers
//! AND connectors; the ledger is about whoever acted. `actor.*` joins `edge.*`
//! and `skill.*` as an engine-reserved namespace: these are STATES with
//! meaning-by-projection (doc-13 r1/r3), so a public `put_claim` of one is
//! rejected with [`ClaimError::ReservedPredicate`](crate::error::ClaimError::ReservedPredicate) and every write goes through an
//! engine door. That reservation also closes the hole
//! [`crate::provider_confidence`] documented on its own `actor.confidence_prior`
//! head — a policy-authorized generic write could plant a trust-bearing prior
//! this engine would then honor. It cannot any more.
//!
//! **Lineage is derived, never declared.** The claim body is built INSIDE the
//! writer (the `dreamer_promotion` house law: callers never construct their own
//! provenance, so source honesty is unforgeable). Two provenance facts ride
//! different fields, deliberately:
//!
//! * `src` is [`ClaimSource::Observed`] on every row — the projector and the
//!   Dreamer OBSERVED the trace, which is the same stamp the sibling
//!   `actor.confidence_prior` and `skill.reliability` projections carry. It is
//!   also this ledger's federation boundary: the cross-vault door restamps
//!   foreign claims `src → Imported`, and `validate_actor_claim_structure`
//!   then refuses them, so a peer's opinion of who is careless never enters
//!   this vault's routing signal. (`src` is additionally the consent axis: a
//!   derived source demands an explicit policy auto-permit, and these rows are
//!   `Auto`, so a `ToolOutput` stamp here would not be a truer label — it would
//!   be a different, wrong claim about consent.)
//! * [`ACTOR_CLAIM_LINEAGE_KEY`] — the engine's own `evidence_taint` SCOPE
//!   entry (ONE-1385/ONE-1314) — carries the EVIDENCE MEET: `tool_output` for
//!   a TASK-lane row resting on attempt receipts, `generated` for a CHAT-lane
//!   row distilled from turns. It rides that key and no private one because
//!   the meet has to be READ by the trust lattice to mean anything:
//!   `claim_evidence_taint` is what blocks a `tool_output`-derived row from
//!   consolidating without a human re-stamp, and a bespoke evidence-map key no
//!   trust code looks at would be a label, not a lineage. Enforced at the door
//!   rather than kept by convention: a row whose scope carries no known
//!   lineage is refused on every write path, replication included.
//!
//! **The engine distills nothing.** Turning a sitting into a craft note is a
//! generative act, so [`run_session_end_actor_distill`] takes a
//! [`SessionActorDistiller`] — the same host-supplied-tier seam
//! [`crate::skill_attribution::AttributionJudge`] uses, budgeted under
//! [`actor_distill_call_purpose`]. This module constructs no LLM client. The
//! TASK lane needs none, and writes no lesson for the same reason: a routing
//! DECISION derives the failure-mode CLASS ([`LAPSE_FAILURE_MODE`]) and stops
//! there, because "what to do instead" is not recoverable from a boolean.

mod distill;
mod evidence;
mod rows;
mod validate;
mod write;

pub use self::distill::{
    SessionActorDistiller, SessionDistillBrief, SessionDistillTurn, SessionDistillUtterance,
    actor_distill_call_purpose, pending_session_actor_distills, run_session_end_actor_distill,
};
pub use self::evidence::ActorClaimEvidence;
pub use self::rows::{
    ACTOR_CLAIM_LINEAGE_KEY, ACTOR_CLAIM_MAX_CITED_EVIDENCE, ACTOR_DISTILL_CALL_PURPOSE_NAME,
    ACTOR_EDIT_COST_SCOPE_KEY, ACTOR_EDIT_COST_SCOPE_MAX_BYTES, ACTOR_NOTE_MAX_BYTES,
    ACTOR_SKILL_FIT_SCOPE_KEY, ActorClaimRow, ActorNote, ActorNoteKind, LAPSE_FAILURE_MODE,
    PREDICATE_ACTOR_FAILURE_MODE, PREDICATE_ACTOR_LESSON, PREDICATE_ACTOR_SCOPE_NOTE,
    PREDICATE_ACTOR_SKILL_FIT,
};
pub use self::validate::{actor_claim_lineage, is_actor_claim_predicate};
pub use self::write::{project_actor_claims_from_judgments, skill_fit_for, write_actor_claim};

pub(crate) use self::distill::register_session_end_distill_in_txn;
pub(crate) use self::rows::edit_cost_scope;
pub(crate) use self::validate::{edit_cost_scope_name, validate_actor_claim_structure};
pub(crate) use self::write::require_actor_entity;

use crate::error::Error;

#[cfg(test)]
use self::{distill::*, evidence::*, write::*};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use crate::registry::ENTITY_TYPE_PERSON;
#[cfg(test)]
use crate::skill_attribution::{AttributionJudgment, AttributionVerdict};
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use rmpv::Value;

pub(super) const fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

#[cfg(test)]
mod tests;
