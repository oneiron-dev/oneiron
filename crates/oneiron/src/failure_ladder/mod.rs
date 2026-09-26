//! ONE-1887 failure ladder: classify → bounded retry → healer slot → surface.
//!
//! One engine-owned failure POLICY layer over the landed queue substrate. It
//! classifies a typed, tiered attempt failure, retries only T1-tripwire
//! transients through ONE-1795's fresh-row [`AttemptQueue::retry`](crate::AttemptQueue::retry), escalates
//! the Nth consecutive transient through the per-scope policy, terminalizes
//! every other class through the existing [`AttemptQueue::fail`](crate::AttemptQueue::fail), and projects
//! a `self.report_blocked` receipt as a non-triggering Issues entry.
//!
//! What this module deliberately does NOT own: ATTEMPT storage or state
//! variants, retry-row minting, the graceful-cancel/landing protocol,
//! agent-definition/skill/prompt/environment mutation, the ARCH-0066 detector
//! tiers, TASK persistence, and surface rendering.
//!
//! Agent-dispatch failures with producer-supplied typed detector evidence
//! enter through `DreamerRunnerStore::fail_agent_dispatch_with_evidence`.
//! Other queue kinds retain their own terminal doors: no error string can
//! masquerade as a T1 detector verdict.

mod blocked_reports;
mod classify;
mod healer_case;
mod ladder;
mod lineage;
pub mod oversight;
mod scope;
mod transitions;

pub use self::blocked_reports::{BlockedReportRef, FailureIssueEntry, ingest_report_blocked};
pub use self::classify::{
    DEFAULT_MAX_CONSECUTIVE_TRANSIENTS, DetectorTier, FailureClass, TypedFailureEvidence,
    TypedFailureVerdict, classify_failure,
};
pub(crate) use self::healer_case::require_in_txn as require_healer_case_in_txn;
pub use self::ladder::{FailureLadder, failure_card_ref, failure_case_ref};
pub(crate) use self::lineage::retry_lineage_ordinal;
pub use self::lineage::{
    FailureLadderOutcome, HandleAttemptFailure, HealerCase, HealerOutcome, HealerRepairRoute,
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
use crate::agent_dispatch::{AgentDispatchTarget, AgentDispatcher, HealerSlotOutcome};
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
