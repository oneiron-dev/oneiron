//! CA-04 stage-ladder machinery: the mechanism, never the content.
//!
//! This module owns the pure ladder schema, coded-reply routing, evidence
//! validation, the AUTO/propose dial, the ordered `crm.stage` projector,
//! warm/cold lane selection, calendar-outcome consumption, no-show recovery
//! directives, and snooze-with-wake re-entry. It owns nothing else: send
//! execution, calendar ingestion, payment truth, delivery truth, and preset
//! content all stay with their existing owners.
//!
//! Four laws shape every function here.
//!
//! 1. **`member (cold)` is not a `crm.stage`.** A query match plus
//!    `campaign.member` provenance may choose a cold or warm-reconnect outreach
//!    lane (`route_membership_lane`), but it never creates a pipeline head.
//!    The first stage head is earned only when a configured transition's
//!    evidence lands.
//! 2. **Default promotion is AUTO.** `PromotionMode::Propose` is an optional
//!    dial a caller may pass, not an approval wall this layer inserts. Every
//!    accepted transition carries non-empty evidence references and a named
//!    evidence class.
//! 3. **`crm.stage` is projector-only.** `project_stage_transition` is the
//!    single writer; `apply_coded_reply`, `apply_event_outcome`, and
//!    `apply_external_stage_evidence` build CA-01's canonical
//!    `CrmStageValue` and route it through that door. None of them puts or
//!    supersedes a `crm.stage` claim directly, and the replacement write plus
//!    the prior head's supersession share ONE transaction via CA-01's
//!    `supersede_crm_stage_in_txn`.
//! 4. **Silence is never `held`.** Calendar outcomes are a READ-side
//!    dependency: CAL-07's `read_event_outcome` answers `None` for silence,
//!    which projects to Unknown and can never become `Held`.
//!
//! Ownership is deliberately thin. `CrmStageValue`, `StageKey`,
//! `StageEvidenceClass`, `EvidenceBasis`, the `campaign.member` value, their
//! codecs, and the in-transaction supersession helper all belong to
//! [`crate::campaign::claims`] (CA-01) and are IMPORTED, never re-spelled.
//! `EventOutcome` and `EventOutcomeClaimValue` belong to
//! [`crate::calendar::outcome`] (CAL-07). The `campaign.enrollment.macro`
//! attempt kind and its enqueue surface belong to
//! [`crate::campaign::enrollment`] (CA-03). This module mints no entity byte, no
//! registry row, no timer, no recurrence primitive, and no attempt kind.
//!
//! Stage KEYS are data. ONE-1779 supplies the consultancy preset that
//! instantiates `StageLadderDefinition`; no consultancy stage name is spelled
//! in this file, including at the owner-attestation boundary (see
//! `require_owner_attestable`).

mod external;
mod ladder;
mod outcome;
mod projector;
mod reentry;
mod reply;

/// CA-03's attempt kind, re-exported so a re-entry caller never spells a second
/// one. This module adds no attempt kind of its own.
pub use crate::campaign::enrollment::CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND;

pub use self::external::{ExternalStageEvidenceHook, apply_external_stage_evidence};
pub use self::ladder::{
    NO_SHOW_BUMP_AFTER_SECS, NoShowRecoveryRule, PromotionMode, ReplyCode, ReplyDisposition,
    ReplyRouteRule, StageDefinition, StageEvidence, StageLadderDefinition, StageTransitionRule,
    validate_ladder,
};
pub use self::outcome::{NoShowRecoveryPlan, NoShowRecoveryStep, apply_event_outcome};
pub use self::projector::{StageProjectResult, StageProjectorInput, StageRoute};
pub use self::reentry::{
    LaneClockPolicy, MembershipProvenance, OutreachLane, ReentryPlan, WakeCondition,
    route_membership_lane, snooze_with_wake,
};
pub use self::reply::{CodedCommReply, apply_coded_reply};
