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
//! 3. ONE-1773's monotonic per-`(query, entity)` epoch watermark, compare-and-set
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

mod detection;
mod home_node;
mod outbound_leg;
mod program;
mod runner;
mod storage;

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
pub use self::program::{
    CampaignProgram, CampaignProgramOutbound, CampaignProgramStep, campaign_program,
    campaign_program_step, put_campaign_program, put_campaign_program_step,
};
pub use self::runner::{
    CampaignEnrollmentAttemptPayload, CampaignEnrollmentClaim, CampaignEnrollmentRunner,
    EnrollmentExecution, decode_enrollment_attempt_payload, derive_enrollment_outbound_request,
    encode_enrollment_attempt_payload, enrollment_dedupe_key,
};
pub use self::storage::{
    CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND, CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
};

// No `pub(crate) use` for the outward leg: `EnrollmentOutboundLeg` and
// `run_enrollment_outbound_leg` are ONE-1778 staging — `pub(crate)` items with
// the `#[cfg_attr(not(test), allow(dead_code))]` carve-out, used by nothing
// outside this module yet — so a crate-visible re-export would be an unused
// import in every build. The `#[cfg(test)]` seam below keeps them reachable to
// `tests.rs`; the host driver re-adds the re-export when it lands.

#[cfg(test)]
mod tests;

// The flat enrollment.rs module used to provide these names to the inline test
// module through `use super::*`: every enrollment-internal item the tests name
// bare (via the per-child globs), plus the private crate/std imports the old
// header supplied. After the directory split the seam re-imports both so
// `tests.rs` resolves exactly as it did before. (`program::*` is absent from
// the globs on purpose: that child exposes no `pub(super)` item, so its `pub`
// names already reach the tests through the seam above and a glob would be an
// unused import.)
#[cfg(test)]
use self::{detection::*, home_node::*, outbound_leg::*, runner::*, storage::*};
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
use crate::outbound_intent_ledger::{IntentDispatchResult, derive_intent_id};
#[cfg(test)]
use crate::saved_query::{EVIDENCE_HASH_LEN, MembershipCause, MembershipTransition};
