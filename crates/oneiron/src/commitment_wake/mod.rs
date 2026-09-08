//! Commitment timer-wake bridge (CMT-3, ONE-1540): due phase → Dreamer
//! attempt → inbox proposal → OF-327 delivery.
//!
//! This module owns NOTHING that already exists. It is the producer-side
//! wiring between four landed surfaces:
//!
//! * CMT-2 ([`crate::commitment_schedule`]) owns the due index, its keys, and
//!   the two crate-private transaction twins this module consumes. Nothing
//!   here reads or writes a due-index key.
//! * CMT-1 ([`crate::commitment`]) owns the obligation record. Only
//!   [`CommitmentStrength::Commitment`] reaches the wake path: a `Decision` is
//!   query/check-in material and a `StatedIntention` is retrieval-only.
//! * The Dreamer ([`crate::dreamer_wake`]) owns wake enqueue and attempt
//!   execution. The wake is an ordinary `WakeTrigger::Event` MICRO attempt and
//!   [`CommitmentWakeExecutor`] is a WRAPPER — an ordinary partition attempt is
//!   delegated byte-for-byte.
//! * The inbox ([`crate::inbox`]) and OF-327 ([`crate::outbound`]) own consent
//!   and delivery. The proposal lands through the same
//!   `claim_candidate(..).apply_recording_gate_decisions(..)` door
//!   `dreamer_promotion` uses, so the pending consent row — and therefore the
//!   approval door — exists without a new grouping mechanism.
//!
//! The one invented thing is the deterministic PHASE KEY `cmt:<32-hex>:<phase>`
//! ([`CommitmentWakeDue::idempotency_key`]). It is the Dreamer enqueue's
//! advisory dedupe key, its run id (and therefore its inbox group key through
//! the existing literal-run fallback), and the outbound draft's idempotency
//! key. It is deliberately NOT a `job_ref`: `cmt:...` is not a 32-hex attempt
//! id and must never alias the attempt run index.
//!
//! Nothing here delivers. [`fire_due_commitment_wake`] enqueues; the executor
//! proposes; only [`schedule_approved_commitment_wake`], behind an inbox
//! approval and an actor binding, reaches
//! [`crate::memory::Memory::schedule_outbound`].

mod wake_approval;
mod wake_event;
mod wake_fire;
mod wake_proposal;

pub use self::wake_approval::{
    ApprovedCommitmentWake, approved_commitment_wake, schedule_approved_commitment_wake,
};
pub use self::wake_event::{
    COMMITMENT_WAKE_PROPOSAL_SCHEMA_VERSION, COMMITMENT_WAKE_RUN_PREFIX,
    COMMITMENT_WAKE_SCHEMA_VERSION, COMMITMENT_WAKE_TRIGGER, COMMITMENT_WAKE_TRIGGER_REF_PREFIX,
    CommitmentWakeDue, CommitmentWakeEvent, CommitmentWakePhase, MAX_COMMITMENT_WAKE_STRING_BYTES,
    PREDICATE_COMMITMENT_WAKE_PROPOSAL, decode_commitment_wake_event, encode_commitment_wake_event,
};
pub use self::wake_fire::{
    CommitmentWakeFireOutcome, CommitmentWakeSkip, fire_due_commitment_wake,
};
pub use self::wake_proposal::{
    CommitmentWakeExecutor, CommitmentWakeProposalDraft, CommitmentWakeProposalPlanner,
    CommitmentWakeProposalSkip, commitment_wake_proposal_claim_id,
};

#[cfg(test)]
mod tests;

// The flat commitment_wake.rs module used to provide these names to the sibling
// test module through `use super::*`: its own private crate/std import header,
// and the private helpers the tests name bare. After the directory split the
// seam re-imports both so `tests.rs` resolves exactly as it did before. The
// public names arrive through the `pub use` seam above; only `wake_proposal`
// needs a glob, for the sentinel-perturb helper the tests call directly.
#[cfg(test)]
use self::wake_proposal::*;
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
#[cfg(test)]
use crate::commitment::{CommitmentRecord, CommitmentStatus, CommitmentStrength};
#[cfg(test)]
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerConsolidationScope, DreamerRunnerStore,
};
#[cfg(test)]
use crate::dreamer_wake::{DreamerAttemptExecution, DreamerAttemptExecutor, WakeAttemptContext};
#[cfg(test)]
use crate::edge::EdgeActorClass;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};
#[cfg(test)]
use rmpv::Value;
