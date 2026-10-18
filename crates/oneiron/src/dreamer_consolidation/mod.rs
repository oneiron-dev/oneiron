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
//! A newly landed or changed TURN behind any scope's compound cursor is
//! admitted on the shared re-dirty carrier in its put transaction. Late
//! writes therefore cannot disappear behind a session-close watermark.
//! Selection is bounded by the store clock: future-dated rows wait without
//! moving the cursor past ordinary turns. Finalized MESSAGE continuations
//! also re-dirty their TURN without changing its row. Each scope consumes
//! exactly the carrier identity its queued round selected.

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
mod neighbourhood;
pub(crate) mod nightly_merge;
mod note_review;
mod open_conflict;
mod parallel;
mod partition;
mod persistence;
mod person_about;
mod provenance;
pub(crate) mod redirty;
mod resident_dream;
pub(crate) mod resources;
mod revert;
pub(crate) mod reviewed;
mod roles;
pub mod routing;
mod scope_summary_attempt;
pub mod selection;
mod settle;
mod sieve_attempt;
mod step_charge;
pub mod strength;
mod support;
mod task_realize;
mod turn_text;
mod wake_plan;
mod watermark;
mod weave_lens;

#[cfg(test)]
mod tests;

pub(crate) use conflict::topic_key_canonical_bytes;
pub use conflict::*;
pub use executor::*;
pub use gap::*;
pub(crate) use neighbourhood::unpin_neighbourhood_in_txn;
pub use partition::*;
pub use persistence::close_persistent_conflict;
pub(crate) use persistence::conflict_close_candidate;
pub(crate) use persistence::on_axes_of;
pub use person_about::{PERSON_ABOUT_INSTRUCTION, PersonAboutExecutor};
pub(crate) use person_about::{
    enqueue_person_about_on_wake, erase_person_about_in_txn, mark_person_about_moved_in_txn,
};
pub use provenance::*;
pub(crate) use provenance::{
    decode_verified_citations, decode_verified_locators,
    encode_consolidation_evidence_with_locators, kept_decisions_value,
};
pub use resident_dream::{
    RESIDENT_DREAM_WINDOW_DEFAULT_TOKENS, ResidentDreamModel, ResidentDreamProgress,
    resident_of_dream_input, run_resident_dream,
};
pub(crate) use resident_dream::{resident_dream_input, resident_dream_progress_in_txn};
pub use resources::ScopedConsolidationWrite;
pub use revert::{
    DreamerChange, DreamerChangeKind, DreamerChanges, DreamerRevertReceipt, RevertedDreamerChange,
};
pub(crate) use revert::{dreamer_changes_in_txn, revert_dreamer_change_in_txn};
pub use roles::{
    DREAMER_EXTRACTION_ROLE, DREAMER_NARRATIVE_ROLE, DREAMER_ROLES, DREAMER_VERDICT_ROLE,
    RoleBackend, RoleBackends, RoleCall,
};
pub use scope_summary_attempt::ScopeSummaryExecutor;
pub(crate) use scope_summary_attempt::{ScopeSummaryEvidence, scope_summary_evidence_in_txn};
pub use settle::{
    CONFLICT_SETTLE_DIAL, ConflictRevertReceipt, ConflictReviewScope, ConflictSettleDecisions,
    ConflictSettleReceipt, ConflictSettlement, OpenConflict, ParkedConflictPass,
    RevertedSettlement, SettledAnswer, SettledConflict, settle_parked_conflicts,
};
pub(crate) use settle::{
    apply_settlement_in_txn, marker_ids, open_conflict_in_txn, open_conflicts_in_txn,
    revert_settlement_in_txn, settled_answers_in_txn,
};
pub use support::*;
pub use task_realize::{TASK_REALIZE_UNLENT_PARK_REASON, TaskRealizeModel, run_task_realize};
pub(crate) use turn_text::{
    TurnText, cited_evidence_bytes, dreamer_may_read_messages_in, dreamer_may_read_turns_in,
    live_turn_text_in, projected_turn_text_in,
};
pub(crate) use wake_plan::AttemptPreparation;
pub use wake_plan::{PreparedConsolidationAttempt, PreparedWake};
pub use watermark::*;
pub use weave_lens::{
    WEAVE_LENS_UNLENT_PARK_REASON, WeaveLensModel, live_weave_lens_request, run_weave_lens,
};

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
