//! CA-03 enrollment consequence writer: the leader-only MACRO job that turns a
//! detected SAVED_QUERY membership transition into the CA-01 `campaign.member`
//! claim and, when the campaign program declares one, an outward call.
//!
//! Four mechanisms carry correctness here, and the queue dedupe key is NOT one
//! of them:
//!
//! 1. the campaign-local home-node designation, re-checked immediately before
//!    EACH consequence — the cohort write and the outward send — so a node that
//!    lost leadership after claiming its attempt cannot still act on it;
//! 2. the attempt lease plus LMDB's single-writer transaction;
//! 3. ONE-1773's monotonic per-`(query, entity, campaign)` epoch watermark, compare-and-set
//!    inside the commit txn;
//! 4. ONE-1691's outbound intent ledger, which freezes the outward payload
//!    before transport and replays the same frozen bytes after a crash.
//!
//! Disable or corrupt the advisory dedupe key and every one of those still
//! holds. That asymmetry is the design.
//!
//! The attempt payload carries REFS ONLY. Nothing authority-bearing — cause,
//! evidence hash, epoch, timestamps, an "enrolled" flag, an outbound request —
//! travels through the queue, because a queue row is the one thing a replay or a
//! confused caller can hand us verbatim. Execution resolves the refs against
//! persisted rows and re-derives everything else through ONE-1773 under the
//! saved query's own owner actor.
//!
//! Home-node election is a deliberate local copy of the `dreamer_runner.rs`
//! candidate/designation shape rather than a shared abstraction: the Dreamer's
//! pure selector is private and its public method persists to a Dreamer-private
//! key. CA-03 keeps its own `campaign:home_node_macro:v1` row and never touches
//! the Dreamer's.

mod approval;
mod audience;
mod detection;
mod home_node;
mod manual;
mod outbound_leg;
mod program;
mod reconcile;
mod runner;
mod storage;

pub(crate) use self::manual::manual_enrollment_candidate_in_txn;
pub(crate) use self::reconcile::{
    IntakeSource, Reconciled, effective_member_in_txn, keep_isolation_stamps, reconcile,
};
pub(crate) use self::runner::reentry_dedupe_key;

pub use self::audience::{AudienceWakeReport, audience_programs, enroll_audience_wake};
pub use self::detection::{
    CampaignEnrollmentEvent, DetectEnrollment, EnrollmentDetection, accept_enrollment_baseline,
    campaign_enrollment_event, detect_enrollment,
};
pub use self::home_node::{
    CampaignHomeNodeAdmission, CampaignHomeNodeCandidate, CampaignHomeNodeClass,
    CampaignHomeNodeDesignation, campaign_home_node_designation,
    elect_campaign_home_node_designation, local_campaign_home_node_candidate,
    require_campaign_home_node,
};
pub use self::outbound_leg::{
    EnrollmentLegDrive, drive_enrollment_outbound_leg, enrollment_outbound_approval_digest,
};
pub use self::program::{
    AuthoredCampaignProgram, CAMPAIGN_PROGRAM_STEP_CHANNEL_MAX_BYTES, CampaignProgramDefinition,
    CampaignProgramDraft, CampaignProgramStepDraft, archive_campaign_program,
    create_campaign_program, read_campaign_program, update_campaign_program,
};
pub use self::program::{
    CampaignProgram, CampaignProgramOutbound, CampaignProgramStep, campaign_program,
    campaign_program_step,
};
pub(crate) use self::program::{put_campaign_program, put_campaign_program_step};
pub use self::program::{CampaignProgramAudience, campaign_programs_for_query};
pub use self::runner::{
    CampaignEnrollmentAttemptPayload, CampaignEnrollmentClaim, CampaignEnrollmentRunner,
    EnrollmentExecution, decode_enrollment_attempt_payload, derive_enrollment_outbound_request,
    encode_enrollment_attempt_payload, enrollment_dedupe_key,
};
pub use self::storage::{
    CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND, CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
};

// The outward leg reaches the host through `drive_enrollment_outbound_leg`
// (FIX 2636); `EnrollmentOutboundLeg` and `run_enrollment_outbound_leg` stay
// module-private, and the `#[cfg(test)]` seam below keeps them reachable to
// `tests.rs`.

#[cfg(test)]
mod tests;

// The flat enrollment.rs module used to provide these names to the inline test
// module through `use super::*`: every enrollment-internal item the tests name
// bare (via the per-child globs), plus the private crate/std imports the old
// header supplied. After the directory split the seam re-imports both so
// `tests.rs` resolves exactly as it did before. (`program::*` and `storage::*`
// are absent from the globs on purpose: neither child's `pub(super)` items are
// named bare by the tests anymore — the typed side tables cover what `storage`
// used to hand-roll — so either glob would be an unused import.)
#[cfg(test)]
use self::{detection::*, home_node::*, outbound_leg::*, runner::*};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::attempt_queue::{AttemptQueue, AttemptRecord, EnqueueAttempt, EnqueueOutcome};
#[cfg(test)]
use crate::campaign::claims::CampaignMemberState;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::outbound_chokepoint::OutboundTransport;
#[cfg(test)]
use crate::outbound_consent::OutboundBindingAuthority;
#[cfg(test)]
use crate::outbound_intent_ledger::IntentDispatchResult;
#[cfg(test)]
use crate::saved_query::{EVIDENCE_HASH_LEN, MembershipCause, MembershipTransition};
