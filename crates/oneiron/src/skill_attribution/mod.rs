//! ARCH-0035 attribution projector for the ARCH-0053 §4 skills loop.
//!
//! The bottom half of the loop: an attempt's outcome plus its edit-feedback is
//! CLASSIFIED before anything lands, so a good skill is not churned because the
//! executor fumbled, and an agent is not blamed for a skill that lied.
//!
//! ```text
//! RECEIPT (outcome + pack manifest)
//!   └─ projector ──> routed verdict
//!        ├─ skill_defect    → judgment against the SKILL entity
//!        ├─ execution_lapse → judgment against the ACTOR entity
//!        ├─ discovery       → a skill EDIT PROPOSAL, never a claim
//!        ├─ environment     → no judgment: an outside fact blames nobody
//!        └─ unclear         → a row in the unclear ledger, for the Dreamer
//! ```
//!
//! A failed attempt carries no edit, so the judge answers once and its split
//! is one label at 100% — the same split path the amendment lane takes hunk by
//! hunk.
//!
//! Routing persists judgments before any measured state is written. The
//! anchored pack-outcome bridge feeds those judgments and actual-use witnesses
//! to the shared `learning.*` projector; the actor-prose projector consumes
//! the same judgment rows. Late-credit receipts retain the eligible lineage
//! chains and their fractional shares.
//!
//! House shape is [`crate::comm::run_comm_projector`]: callers RECORD evidence
//! through a door, the projector converts unprojected evidence into durable
//! output in sequence order, and a cursor makes the pass idempotent and
//! resumable. The cursor is a local u64 following the
//! [`crate::dreamer_consolidation`] `read_watermark`/`advance_watermark` shape
//! (no generic engine watermark type exists — `ConsolidationWatermark` is
//! consolidation-scoped).

mod audit;
mod calibration;
pub(crate) use self::calibration::record_unclear_floor_fit_in_txn;
pub use self::calibration::{
    AuditAnswerSource, AuditBatch, AuditCase, FloorFit, RawAnswer, UNCLEAR_FLOOR_FITTER_VERSION,
};
mod causes;
pub use self::causes::AttributionCauseRecord;
pub(crate) use self::causes::{attempt_attribution_causes, erase_attribution_cause_entity_in_txn};
mod codec;
pub(crate) use self::codec::{ground_attempt_receipt, manifest_entry_names_skill};
pub(crate) mod health_review;
mod judge;
pub(crate) use self::judge::JudgeTrace;
mod decision_receipts;
pub use self::decision_receipts::attribution_decision_receipts;
pub(crate) use self::decision_receipts::erase_decision_receipts_entity_in_txn;
mod judge_supersession;
#[cfg(test)]
pub(crate) use judge_supersession::set_pre_writer_hook;
pub(crate) use judge_supersession::{
    displacing_revision_in_txn, ensure_current_attribution_judge_in_txn, judgment_displaced,
    judgment_displaced_in_txn, judgment_judge_in_txn,
};
mod contribution;
pub use contribution::{
    ContributionCandidate, ContributionCheckRecord, ContributionFork, ContributionPair,
    contributed, contribution_check_candidates_after, record_contribution_pair,
};
mod contribution_admission;
pub(crate) use contribution_admission::erase_contribution_checks_in_txn;
pub use contribution_admission::{ContributionRecord, UnmatchedReason};
mod contribution_targets;
pub(crate) use contribution_targets::Experiment;
pub use contribution_targets::{CheckedEdge, ContributionTarget};
mod credit_join;
pub(crate) use credit_join::erase_credit_adjustments_in_txn;
pub(crate) use credit_join::standing_credit_observation_in_txn;
pub use credit_join::{CreditAdjustmentReceipt, credit_adjustments};
mod decay_fit;
mod late_credit;
mod pack_learning;
pub(crate) use late_credit::erase_late_credit_in_txn;
pub(crate) use late_credit::late_credit_receipt_in_txn;
pub use late_credit::{
    LateCreditReceipt, LateCreditShare, late_credit_receipt, late_credit_receipt_for_outcome,
};
pub use pack_learning::{
    AnchoredPackOutcome, project_anchored_pack_outcome, project_anchored_pack_outcome_as_owner,
};
mod positive;
pub(crate) use self::positive::erase_positive_proposals_in_txn;
pub use self::positive::{
    PositiveFinding, PositiveSkillProposal, pending_positive_proposals, positive_finding,
    retire_positive_proposal, run_positive_attribution_pass,
};
mod projector;
pub(crate) use self::projector::{
    attribution_judgments_in_txn, draw_proposal_sequence_in_txn, mint_edit_proposal_in_txn,
    withdraw_edit_proposal_in_txn,
};
mod skill_erase;
pub(crate) use self::skill_erase::{
    erase_attribution_evidence_skill_in_txn, erase_attribution_judgment_skill_in_txn,
    erase_scan_in_txn,
};
mod split;
pub(crate) use self::split::{
    classify_split_traced, measure_split_notes, settled_split, split_from_verdicts, unclear_floor,
    unclear_floor_sourced,
};
mod types;
mod unclear;
pub use self::unclear::{UnclearAttribution, unclear_attributions};
pub(crate) use self::unclear::{delete_unclear_in_txn, put_unclear_in_txn};

pub use self::audit::{
    AttributionAuditRecord, AttributionAuditReport, AuditFixture, attribution_audit_records,
    attribution_audit_reports, held_out_audit_fixtures, run_attribution_audit,
    run_attribution_audit_with_decisions,
};
pub use self::judge::{
    ATTRIBUTION_CALL_PURPOSE_NAME, ATTRIBUTION_DIAL, AttributionDecisions, AttributionNotes,
    AttributionRules, attribution_call_purpose,
};
pub use self::projector::{
    attribution_judgments, pending_edit_proposals, read_attribution_cursor,
    record_attribution_evidence, run_attribution_projector,
    run_attribution_projector_with_decisions,
};
pub use self::types::{
    AttemptOutcome, AttributionJudgment, AttributionLane, AttributionShare, AttributionSplit,
    AttributionVerdict, DeviationCause, EditHunk, FollowedState, HunkVerdict, JudgeRequest,
    OutcomeEvidence, SKILL_ATTRIBUTION_SCHEMA_VERSION, SkillEditProposal, UnclearNote,
    UnclearReason,
};

#[cfg(test)]
mod tests;

// The flat skill_attribution.rs module used to provide these names to the
// sibling test module through `use super::*`: its own private crate/std
// import header. After the directory split the seam re-imports the header
// (the re-exports above travel through the same glob) so `tests.rs`
// resolves exactly as it did before.
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use rmpv::Value;

mod host;
pub use host::{bind_agent_run_attribution, witness_agent_run_close};
pub(crate) use host::{run_executor_model, run_executor_model_in_txn};
mod judge_binding;
pub(crate) use judge_binding::finalize_run_judge_in_txn;
mod derivation_witness;
pub(crate) use derivation_witness::{
    erase_derivation_witness_in_txn, note_summary_landing_in_txn, note_summary_request_in_txn,
};
mod site_exposure;
pub(crate) use site_exposure::erase_site_exposure_in_txn;
pub use site_exposure::{SiteSkillExposure, record_site_exposures, site_exposed};
mod run_writes;
pub(crate) use run_writes::{
    RunDerivations, current_run_write_token, enter_run_write_token, enter_run_writes,
    note_direct_derivation_in_txn, note_promoted_ops_in_txn, note_run_derivations_in_txn,
    run_derivations,
};
pub use run_writes::{RunWriteToken, with_run_write_token};
mod sweep;
pub use sweep::{
    AttributionSweepReport, ReceiptAttributionFacts, ReceiptAttributionSource,
    run_task_attribution_sweep, run_task_attribution_sweep_with_decisions,
};
mod trace;
pub use trace::{
    LoadedSkillRevision, ReceiptTrace, receipt_attribution_trace, receipt_attribution_trace_sourced,
};

pub use self::judge_supersession::{
    DisplacedJudgeReceipt, displaced_judge_receipts, supersede_displaced_judge_receipts,
};
