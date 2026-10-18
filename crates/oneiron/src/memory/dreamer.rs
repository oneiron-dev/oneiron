//! Consolidation enqueue, dreamer attempt status, and claim seeding.
//! Split from the flat `facade.rs`; surface re-exported by [`super`].

use super::outbound::*;
use super::support::*;
use super::*;

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{AttemptRecord, AttemptState};
use crate::claim::ClaimApprovalStatus;
use crate::dreamer_runner::{
    DreamerConsolidationScope, DreamerParkCause, DreamerParkedAttemptRecord, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt,
};

/// One Dreamer consolidation enqueue (BRIDGE-03).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsolidationAttemptInput {
    /// Consolidation scope: `micro` | `meso` | `macro`.
    pub scope: String,
    /// Opaque attempt input (stored as MessagePack in the queue payload).
    pub input: serde_json::Value,
    /// Optional run correlation id.
    pub run_id: Option<String>,
    /// Optional advisory dedupe key (cost coalescer, not a lock).
    pub dedupe_key: Option<String>,
    /// Unix seconds; `None` ⇒ now.
    pub now: Option<u64>,
}

/// Reference to one queued Dreamer attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerAttemptRef {
    /// 32-hex attempt id (poll via [`Memory::dreamer_attempt_status`]).
    pub job_ref: String,
    /// Queue state at enqueue time.
    pub state: String,
    /// True when the advisory dedupe key coalesced onto an existing attempt.
    pub existing: bool,
}

/// Poll-model view of one Dreamer attempt (W2: long work returns attempt ids).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerAttemptView {
    /// 32-hex attempt id.
    pub job_ref: String,
    /// `queued` | `leased` | `paused` | `completed` | `failed` | `cancelled`.
    pub state: String,
    /// Queue attempt kind.
    pub kind: String,
    /// Worker label holding the lease, if leased.
    pub lease_owner: Option<String>,
    /// Admission attempts so far.
    pub attempt_count: u32,
    /// Run correlation id, if any.
    pub run_id: Option<String>,
    /// Last failure message, if any.
    pub last_error: Option<String>,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds.
    pub updated_at: u64,
    /// The attempt's park, when the runner parked it (DOOR-144 A): the
    /// durable fact that its work remains for a later resume. Absent when
    /// the attempt holds no park row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parked: Option<DreamerParkedAttemptView>,
}

/// The public face of one parked Dreamer attempt: which attempt, why, and
/// when. The park-owner token and the free-text reason stay private; this
/// names no wake, continuation object or lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerParkedAttemptView {
    /// 32-hex attempt id.
    pub job_ref: String,
    /// What code reads of the park: why it parked.
    pub cause: DreamerParkCauseView,
    /// Unix seconds.
    pub parked_at: u64,
}

/// Why a Dreamer attempt parked, as [`DreamerParkCause`] spells it in its
/// private row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DreamerParkCauseView {
    /// Its model call failed because the provider is down.
    ProviderUnavailable,
    /// Its executor returned an error or panicked.
    ExecutorError,
    /// The wake pass hit its deadline and the attempt kept its progress.
    Checkpoint,
    /// The pass was cancelled.
    Cancelled,
    /// It waits on a signal: a budget approval, a seat login, a peer.
    Signal,
    /// Anything else.
    Other,
}

impl From<DreamerParkCause> for DreamerParkCauseView {
    fn from(cause: DreamerParkCause) -> Self {
        match cause {
            DreamerParkCause::ProviderUnavailable => Self::ProviderUnavailable,
            DreamerParkCause::ExecutorError => Self::ExecutorError,
            DreamerParkCause::Checkpoint => Self::Checkpoint,
            DreamerParkCause::Cancelled => Self::Cancelled,
            DreamerParkCause::Signal => Self::Signal,
            DreamerParkCause::Other => Self::Other,
        }
    }
}

impl Memory<'_> {
    // ── BRIDGE-03: Dreamer + seed + outbound wiring ─────────────────────

    /// Enqueues one Dreamer consolidation attempt (expose, don't rebuild: the
    /// queue verbs and leases stay engine-side; long work returns an attempt
    /// ref to poll, W2).
    pub fn enqueue_consolidation(
        &self,
        input: &ConsolidationAttemptInput,
    ) -> MemoryResult<DreamerAttemptRef> {
        let scope = match input.scope.as_str() {
            "micro" => DreamerConsolidationScope::Micro,
            "meso" => DreamerConsolidationScope::Meso,
            "macro" => DreamerConsolidationScope::Macro,
            other => {
                return Err(MemoryError::bad_request_with(
                    format!("unknown consolidation scope {other:?}"),
                    &["Use one of: micro, meso, macro."],
                ));
            }
        };
        let store = DreamerRunnerStore::new(self.vault);
        let outcome = self.with_verified_actor_write_txn(|wtxn| {
            store
                .enqueue_consolidation_in_txn(
                    wtxn,
                    EnqueueDreamerConsolidationAttempt {
                        scope,
                        input: json_to_rmpv(&input.input),
                        parent_attempt: None,
                        dedupe_key: input.dedupe_key.clone(),
                        run_id: input.run_id.clone(),
                        now: input
                            .now
                            .unwrap_or_else(|| self.vault.store.clock.now_recorded_at()),
                    },
                )
                .map_err(MemoryError::from)
        })?;
        let (status, existing) = match outcome {
            EnqueueDreamerAttemptOutcome::Enqueued(status) => (status, false),
            EnqueueDreamerAttemptOutcome::Existing(status) => (status, true),
        };
        Ok(DreamerAttemptRef {
            job_ref: hex_string(status.attempt.id.as_bytes()),
            state: attempt_state_str(status.attempt.state).to_owned(),
            existing,
        })
    }

    /// Polls one Dreamer attempt's status (poll model, no FFI await).
    pub fn dreamer_attempt_status(
        &self,
        job_ref: &str,
    ) -> MemoryResult<Option<DreamerAttemptView>> {
        let id = parse_job_ref(job_ref)?;
        let store = DreamerRunnerStore::new(self.vault);
        let Some(status) = store.status(id)? else {
            return Ok(None);
        };
        let mut view = attempt_view_from_record(&status.attempt);
        view.parked = store.parked_attempt(id)?.as_ref().map(parked_view);
        Ok(Some(view))
    }

    /// Seed-write entry point (EF-301 consumer): every element is FORCED
    /// `proposed` regardless of source — cold-start claims land below the
    /// auto-approve line, individually gated, each with its receipt or its
    /// typed refusal (OF-063).
    pub fn seed_claims(&self, claims: &[ClaimInput]) -> MemoryResult<Vec<CommitOutcome>> {
        Ok(self.commit_all(
            "vault.claims.seed",
            claims,
            false,
            Some(ClaimApprovalStatus::Proposed),
        ))
    }
}

const fn attempt_state_str(state: AttemptState) -> &'static str {
    match state {
        AttemptState::Queued => "queued",
        AttemptState::Leased => "leased",
        AttemptState::Paused => "paused",
        AttemptState::Completed => "completed",
        AttemptState::Failed => "failed",
        AttemptState::Cancelled => "cancelled",
        AttemptState::Scheduled => "scheduled",
        AttemptState::Landing => "landing",
        AttemptState::Abandoned => "abandoned",
    }
}

fn attempt_view_from_record(attempt: &AttemptRecord) -> DreamerAttemptView {
    DreamerAttemptView {
        job_ref: hex_string(attempt.id.as_bytes()),
        state: attempt_state_str(attempt.state).to_owned(),
        kind: attempt.kind.clone(),
        lease_owner: attempt.lease_owner.clone(),
        attempt_count: attempt.attempt_count,
        run_id: attempt.run_id.clone(),
        last_error: attempt.last_error.clone(),
        created_at: attempt.created_at,
        updated_at: attempt.updated_at,
        parked: None,
    }
}

fn parked_view(park: &DreamerParkedAttemptRecord) -> DreamerParkedAttemptView {
    DreamerParkedAttemptView {
        job_ref: hex_string(park.attempt_id.as_bytes()),
        cause: park.cause.into(),
        parked_at: park.parked_at,
    }
}
