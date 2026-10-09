//! Dreamer consolidation algorithm + reflection gap scan (ONE-1289,
//! DREAM-002; DESIGN-PIN-20260710 Part A).
//!
//! Phases: 0 — global `learned_at` watermark scan selects dirty TURN
//! entities (claims never enter the working set, GATE-11); 1 — work
//! partitions in turn vocabulary `(conversation, world, facet)`; 2 —
//! post-extraction semantic candidate buckets keyed on
//! `(subject, predicate_root, world, facet)`; 3 — mechanical BLAKE3
//! evidence collapse, then the deterministic conflict trigger on the FULL
//! predicate, with only conflicting sets entering scoped LLM merge steps;
//! 4 — the reflection gap scan with dedupe/decay and escalate-once.
//!
//! This module NEVER writes belief claims: surviving candidates go to the
//! promotion writer (`dreamer_promotion`, ONE-1290) through a
//! [`ConsolidationSink`]. The watermark is the selection authority; the
//! landed offset pager and every `ledger_revision` hint are efficiency
//! devices only, never authority (1184-D1).
//!
//! Temporal-key writer contract, stated here as the CONSUMER-side assumption
//! of the cursor that depends on it: the watermark is a POSITION in the
//! `learned_at` temporal index, so an entity that must be re-consolidated is
//! re-stamped with a `learned_at` AHEAD of the cursor — never backdated behind
//! it. A caller-supplied `learned_at` that lands behind the cursor is simply
//! never selected again, exactly as it is under a seconds-only watermark: the
//! temporal-index writers (the batch layer) own that contract; this module only
//! reads the index and cannot enforce it. A TURN whose final words changed
//! (a finalized stream continuation, a new MESSAGE sibling) is also re-dirtied
//! through `redirty`: a carrier pending for each scope until a round of that
//! scope consumes it, selected wherever the scope cursor stands and never
//! moving it. Selection, settlement and the partition-round identity read
//! its key in place of the row's `learned_at` while it keys the TURN. A
//! continuation leaves the TURN row itself untouched.

mod assembly;
pub(crate) mod branch_scope;
mod conflict;
pub(crate) mod evidence;
mod executor;
mod extracted_people;
mod failure_rules;
#[cfg(test)]
pub(crate) use failure_rules::PREDICATE as DREAMER_FAILURE_RULES_PREDICATE;
pub(crate) use failure_rules::{
    DREAMER_FAILURE_RULES, admitted_authored_claim, prepare_authored_claim, resident_record,
    step_consolidation_eligible_in_txn, step_effector_eligible_in_txn,
};
mod gap;
mod judge_context;
mod open_conflict;
mod partition;
mod persistence;
mod provenance;
pub(crate) mod redirty;
pub(crate) mod resources;
pub mod routing;
pub mod selection;
mod step_charge;
mod support;
mod turn_text;
mod wake_plan;
mod watermark;

#[cfg(test)]
mod tests;

pub use conflict::*;
pub use executor::*;
pub use gap::*;
pub use partition::*;
pub use persistence::close_persistent_conflict;
pub use provenance::*;
pub(crate) use provenance::{
    decode_verified_citations, decode_verified_locators,
    encode_consolidation_evidence_with_locators,
};
pub use resources::ScopedConsolidationWrite;
pub use support::*;
pub(crate) use turn_text::{TurnText, cited_evidence_bytes, live_turn_text_in};
pub(crate) use wake_plan::AttemptPreparation;
pub use wake_plan::{PreparedConsolidationAttempt, PreparedWake};
pub use watermark::*;

// The flat dreamer_consolidation.rs module used to provide these names to the
// sibling test module through `use super::*`; after the directory split the
// seam re-imports them so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::batch::EntityMetadataHeader;
#[cfg(test)]
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject};
#[cfg(test)]
use crate::dreamer_runner::{
    DreamerClaimAuthoringStrategy, DreamerConsolidationScope, DreamerRunnerStore, DreamerTurnRole,
    EnqueueDreamerAttemptOutcome,
};
#[cfg(test)]
use crate::dreamer_wake::{DreamerAttemptExecution, DreamerAttemptExecutor, WakeAttemptContext};
#[cfg(test)]
use crate::edge::EdgeKind;
#[cfg(test)]
use crate::entity_id::{EntityId, bytes_to_hex_lower};
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::llm::{LlmBackend, LlmRequest};
#[cfg(test)]
use crate::registry::ENTITY_TYPE_TURN;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope};
#[cfg(test)]
use rmpv::Value;
#[cfg(test)]
use std::collections::BTreeSet;

mod value_projection;
