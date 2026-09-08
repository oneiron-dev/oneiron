//! ONE-1887 failure ladder: classify → bounded retry → healer slot → surface.
//!
//! One engine-owned failure POLICY layer over the landed queue substrate. It
//! classifies a typed, tiered attempt failure, retries only T1-tripwire
//! transients through ONE-1795's fresh-row [`AttemptQueue::retry`], escalates
//! the Nth consecutive transient through the per-scope policy, terminalizes
//! every other class through the existing [`AttemptQueue::fail`], and projects
//! a `self.report_blocked` receipt as a non-triggering Issues entry.
//!
//! What this module deliberately does NOT own: ATTEMPT storage or state
//! variants, retry-row minting, the graceful-cancel/landing protocol,
//! agent-definition/skill/prompt/environment mutation, the ARCH-0066 detector
//! tiers, TASK persistence, and surface rendering.
//!
//! DECLARED DEFERRED (OF-418 open integration edge): the production failure
//! call sites in `dreamer_runner`, `companion`, and `outbound` adopt
//! [`FailureLadder::handle_attempt_failure`] only once OF-418 lands the typed
//! detector evidence substrate. This lane ships and composition-tests the
//! policy and its helpers; it deliberately adds no evidence-less caller.

mod blocked_reports;
mod classify;
mod ladder;
mod lineage;
mod scope;
mod transitions;

pub use self::blocked_reports::{BlockedReportRef, FailureIssueEntry, ingest_report_blocked};
pub use self::classify::{
    DEFAULT_MAX_CONSECUTIVE_TRANSIENTS, DetectorTier, FailureClass, TypedFailureEvidence,
    TypedFailureVerdict, classify_failure,
};
pub use self::ladder::{FailureLadder, failure_card_ref, failure_case_ref};
pub(crate) use self::lineage::retry_lineage_ordinal;
pub use self::lineage::{
    FailureLadderOutcome, HandleAttemptFailure, HealerCase, HealerRepairRoute,
    RetryLineagePathology, RetryOrdinal, SurfacedFailure,
};
pub use self::scope::{FailureEscalationMode, FailureScope, FailureScopePolicy};
pub(crate) use self::transitions::{dispatched_target_ref, verified_blocked_reports};

#[cfg(test)]
mod tests;

#[cfg(test)]
use self::{blocked_reports::*, lineage::*};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::agent_dispatch::{AgentDispatchTarget, AgentDispatcher, HealerSlot, HealerSlotOutcome};
#[cfg(test)]
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, FailAttempt, FailOutcome, RetryAttempt, RetryOutcome,
};
#[cfg(test)]
use crate::entity_id::{EntityId, bytes_to_hex_lower};
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use std::num::NonZeroU16;
