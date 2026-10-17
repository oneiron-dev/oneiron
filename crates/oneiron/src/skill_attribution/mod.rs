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
//!        ├─ environment     → nothing: an outside fact blames nobody
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
mod codec;
pub(crate) use self::codec::{ground_attempt_receipt, manifest_entry_names_skill};
mod judge;
pub(crate) use self::judge::JudgeTrace;
mod judge_supersession;
#[cfg(test)]
pub(crate) use judge_supersession::set_pre_writer_hook;
pub(crate) use judge_supersession::{
    judgment_displaced, judgment_displaced_in_txn, judgment_judge_in_txn,
};
mod contribution;
pub use contribution::{
    ContributionCandidate, ContributionCheckRecord, ContributionFork, ContributionPair,
    contributed, contribution_check_candidates, record_contribution_pair,
};
mod late_credit;
mod pack_learning;
pub use late_credit::{LateCreditReceipt, LateCreditShare, late_credit_receipt};
pub use pack_learning::{AnchoredPackOutcome, project_anchored_pack_outcome};
mod positive;
pub use self::positive::{
    PositiveFinding, PositiveSkillProposal, pending_positive_proposals, positive_finding,
    retire_positive_proposal, run_positive_attribution_pass,
};
mod projector;
pub(crate) use self::projector::{
    attribution_judgments_in_txn, draw_proposal_sequence_in_txn, mint_edit_proposal_in_txn,
    withdraw_edit_proposal_in_txn,
};
mod split;
pub(crate) use self::split::{classify_split_traced, settled_split, unclear_floor};
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
pub(crate) use host::run_executor_model;
pub use host::{bind_agent_run_attribution, witness_agent_run_close};
mod run_writes;
pub(crate) use run_writes::{enter_run_writes, note_run_derivations_in_txn, run_derivations};
mod sweep;
pub use sweep::{
    AttributionSweepReport, ReceiptAttributionFacts, ReceiptAttributionSource,
    run_task_attribution_sweep, run_task_attribution_sweep_with_decisions,
};
mod trace;
pub use trace::{LoadedSkillRevision, ReceiptTrace, receipt_attribution_trace};

pub use self::judge_supersession::{
    DisplacedJudgeReceipt, displaced_judge_receipts, supersede_displaced_judge_receipts,
};
