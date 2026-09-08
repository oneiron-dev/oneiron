//! Ratified consultancy-preset content: stage order, reply codes, and brief dials.

use super::shape::RhythmAnchor;

use crate::campaign::claims::StageEvidenceClass;
use crate::campaign::stage::ReplyCode;

// ---------------------------------------------------------------------------
// Ratified content
// ---------------------------------------------------------------------------

const SECS_PER_DAY: u64 = 24 * 60 * 60;

pub(super) const STAGE_REPLIED: &str = "replied";

pub(super) const STAGE_CALL_BOOKED: &str = "call_booked";

pub(super) const STAGE_CALL_HELD: &str = "call_held";

pub(super) const STAGE_PROPOSAL_SENT: &str = "proposal_sent";

pub(super) const STAGE_DEPOSIT_PAID: &str = "deposit_paid";

pub(super) const STAGE_AUDIT_ACTIVE: &str = "audit_active";

pub(super) const STAGE_AUDIT_COMPLETE: &str = "audit_complete";

pub(super) const STAGE_DESK_CLIENT: &str = "desk_client";

/// The ratified pipeline: stage order AND the one evidence class each stage is
/// earned by. `member (cold)` is deliberately absent — membership is not
/// pipeline, and a query match earns an outreach lane rather than a head.
pub(super) const CONSULTANCY_STAGE_EVIDENCE: [(&str, StageEvidenceClass); 8] = [
    (STAGE_REPLIED, StageEvidenceClass::MeaningfulReply),
    (STAGE_CALL_BOOKED, StageEvidenceClass::CalendarEvent),
    (STAGE_CALL_HELD, StageEvidenceClass::CalendarEventOutcome),
    (
        STAGE_PROPOSAL_SENT,
        StageEvidenceClass::DocumentArtifactAndSendReceipt,
    ),
    (STAGE_DEPOSIT_PAID, StageEvidenceClass::CounterpartyLedger),
    (STAGE_AUDIT_ACTIVE, StageEvidenceClass::TaskListProgress),
    (STAGE_AUDIT_COMPLETE, StageEvidenceClass::TaskListProgress),
    (STAGE_DESK_CLIENT, StageEvidenceClass::RecurringCommitment),
];

/// Every reply code the preset must route, exactly once.
pub(super) const RATIFIED_REPLY_CODES: [ReplyCode; 6] = [
    ReplyCode::PositiveNow,
    ReplyCode::PositiveLater,
    ReplyCode::Referral,
    ReplyCode::Objection,
    ReplyCode::NotInterested,
    ReplyCode::Complaint,
];

pub(super) const CONSULTANCY_SNOOZE_MIN_SECS: u64 = 60 * SECS_PER_DAY;

pub(super) const CONSULTANCY_SNOOZE_MAX_SECS: u64 = 90 * SECS_PER_DAY;

pub(super) const CONSULTANCY_AUDIT_WINDOW_DAYS: u32 = 14;

pub(super) const CONSULTANCY_DESK_PERIOD: &str = "P1M";

pub(super) const SOW_SECTION_KEYS: [&str; 8] = [
    "context_and_evidence",
    "outcomes",
    "scope",
    "out_of_scope",
    "timeline",
    "fees_and_deposit",
    "acceptance",
    "next_step",
];

pub(super) const SOW_EVIDENCE_SECTION: &str = "context_and_evidence";

pub(super) const ONE_PAGER_SECTION_KEYS: [&str; 6] = [
    "situation",
    "observed_evidence",
    "proposed_engagement",
    "timeline",
    "commercial_shape",
    "next_step",
];

pub(super) const ONE_PAGER_EVIDENCE_SECTION: &str = "observed_evidence";

pub(super) const REQUIRED_RHYTHM_ANCHORS: [RhythmAnchor; 4] = [
    RhythmAnchor::PeriodStart,
    RhythmAnchor::Weekly,
    RhythmAnchor::BeforePeriodEnd,
    RhythmAnchor::PeriodEnd,
];

pub(super) const MOM_TEST_TEMPLATE_KEY: &str = "mom_test";

pub(super) const MOM_TEST_PARTICIPANT_ROLE: &str = "interviewee";

pub(super) const PROSPECT_PARTICIPANT_ROLE: &str = "prospect";

pub(super) const MOM_TEST_QUESTION_BLOCK_KEYS: [&str; 6] = [
    "past_behavior",
    "most_recent_occurrence",
    "current_workflow",
    "cost_and_time",
    "prior_attempts",
    "decision_process",
];
