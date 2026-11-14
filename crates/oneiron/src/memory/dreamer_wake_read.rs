//! `vault.consolidation.wake.status` (DOOR-144 B): the typed wake read beside
//! `vault.consolidation.status`. One page of what one wake pass recorded of
//! itself ([`Vault::dreamer_wake_observation`]), addressed by an attempt or by
//! a pass, in wire shapes: ids as hex, node ids as decimal strings, step
//! hashes as 64 hex, a lease id as the diagnostic it is (never a capability).
//! The read is the caller's own Memory read, as its sibling's is; it names no
//! owner proof and scans nothing it was not addressed to.

use super::support::hex_string;
use super::{Memory, MemoryError, MemoryResult, parse_job_ref};
use crate::entity_id::EntityId;
use crate::memory::wake_observation::ClaimAuthoringFallback;
use crate::memory::wake_observation::WAKE_OBSERVATION_PAGE_MAX;
use crate::memory::wake_observation::WakeCallState;
use crate::memory::wake_observation::WakeObservation;
use crate::memory::wake_observation::WakeObservationCursor;
use crate::memory::wake_observation::WakeObservationRequest;
use crate::memory::wake_observation::WakeObservationSelector;
use crate::memory::wake_observation::WakeObservedCall;
use crate::memory::wake_observation::WakeObservedCheckpoint;
use crate::memory::wake_observation::WakeObservedGeneration;
use crate::memory::wake_observation::WakeRef;
use oneiron_model::llm::BudgetLeaseState;

#[doc(hidden)]
pub use oneiron_verb_wire::memory::dreamer_wake_read::{
    ConsolidationWakeStatusRequest, DreamerWakeCallEndView, DreamerWakeCallStateView,
    DreamerWakeCallView, DreamerWakeCheckpointView, DreamerWakeClaimAuthoringFallbackView,
    DreamerWakeEndView, DreamerWakeGenerationView, DreamerWakeHeaderView, DreamerWakeLeaseView,
    DreamerWakeLiveCallView, DreamerWakeLiveView, DreamerWakeResumeView, DreamerWakeView,
};

impl Memory<'_> {
    /// One page of the wake observation `input` addresses (DOOR-144 B).
    /// `None` for an attempt or a pass no observed wake recorded: no
    /// observation, which is not the same as no work.
    pub fn dreamer_wake_status(
        &self,
        input: &ConsolidationWakeStatusRequest,
    ) -> MemoryResult<Option<DreamerWakeView>> {
        let request = wake_request(input)?;
        let Some(observation) = self.vault.dreamer_wake_observation(&request)? else {
            return Ok(None);
        };
        Ok(Some(wake_view(observation)))
    }
}

fn wake_request(input: &ConsolidationWakeStatusRequest) -> MemoryResult<WakeObservationRequest> {
    let wake = input.wake_ref.as_deref().map(wake_ref).transpose()?;
    let selector = match (&input.job_ref, wake) {
        (Some(job_ref), wake) => WakeObservationSelector::Attempt {
            attempt: parse_job_ref(job_ref)?,
            wake,
        },
        (None, Some(wake)) => WakeObservationSelector::Wake { wake },
        (None, None) => {
            return Err(MemoryError::bad_request_with(
                "a wake read names an attempt or a wake pass",
                &["Send job_ref for an attempt's observation, or wake_ref for a pass's."],
            ));
        }
    };
    let cursor = input
        .cursor
        .as_deref()
        .map(|cursor| parse_cursor(cursor, &selector))
        .transpose()?;
    Ok(WakeObservationRequest {
        selector,
        limit: input
            .limit
            .map(|limit| usize::try_from(limit).unwrap_or(WAKE_OBSERVATION_PAGE_MAX)),
        cursor,
    })
}

fn wake_ref(text: &str) -> MemoryResult<WakeRef> {
    EntityId::from_hex(text.trim())
        .map(WakeRef::from_entity_id)
        .map_err(|_| MemoryError::bad_request(format!("wake ref {text:?} is not a 32-hex id")))
}

/// A cursor as the previous page spelled it: `call:<32 hex>` on an
/// attempt's page, `member:<32 hex>:<count>` on a pass's.
fn parse_cursor(
    text: &str,
    selector: &WakeObservationSelector,
) -> MemoryResult<WakeObservationCursor> {
    let refused = || {
        MemoryError::bad_request_with(
            format!("cursor {text:?} is not this read's next_cursor"),
            &["Send the next_cursor the previous page of the same read answered."],
        )
    };
    match selector {
        WakeObservationSelector::Attempt { .. } => {
            let call = text.strip_prefix("call:").ok_or_else(refused)?;
            EntityId::from_hex(call)
                .map(WakeObservationCursor::Call)
                .map_err(|_| refused())
        }
        WakeObservationSelector::Wake { .. } => {
            let member = text.strip_prefix("member:").ok_or_else(refused)?;
            let (attempt, count) = member.split_once(':').ok_or_else(refused)?;
            Ok(WakeObservationCursor::Member {
                attempt: parse_job_ref(attempt).map_err(|_| refused())?,
                attempt_count: count.parse().map_err(|_| refused())?,
            })
        }
    }
}

fn cursor_text(cursor: WakeObservationCursor) -> String {
    match cursor {
        WakeObservationCursor::Call(call) => format!("call:{}", call.to_hex()),
        WakeObservationCursor::Member {
            attempt,
            attempt_count,
        } => format!("member:{}:{attempt_count}", hex_string(attempt.as_bytes())),
    }
}

fn wake_view(observation: WakeObservation) -> DreamerWakeView {
    let header = &observation.header;
    DreamerWakeView {
        wake_ref: observation.wake.entity_id().to_hex(),
        header: DreamerWakeHeaderView {
            trigger: header.trigger.clone(),
            scope: header.scope.clone(),
            worker: header.worker.clone(),
            node_id: header.node_id.to_string(),
            budget_id: header.budget_id.clone(),
            origin_unix_ms: header.origin_unix_ms,
            ceiling_ms: header.ceiling_ms,
            ceiling_unix_ms: header.ceiling_unix_ms(),
            entered_unix_ms: header.entered_unix_ms,
            entered_elapsed_ms: header.entered_elapsed_ms,
            ended: header.ended.as_ref().map(|end| DreamerWakeEndView {
                unix_ms: end.unix_ms,
                elapsed_ms: end.elapsed_ms,
                stop: end.stop.clone(),
                claim_authoring_fallback: end.claim_authoring_fallback.as_ref().map(|fallback| {
                    let ClaimAuthoringFallback::AmbiguousCampaigns { roots } = fallback;
                    DreamerWakeClaimAuthoringFallbackView::AmbiguousCampaigns {
                        roots: roots
                            .iter()
                            .map(|root| hex_string(root.as_bytes()))
                            .collect(),
                    }
                }),
            }),
        },
        generation: observation.generation.as_ref().map(generation_view),
        members: observation.members.iter().map(generation_view).collect(),
        calls: observation.calls.iter().map(call_view).collect(),
        next_cursor: observation.next.map(cursor_text),
        live: observation.live.map(|live| DreamerWakeLiveView {
            elapsed_ms: live.elapsed_ms,
            remaining_ms: live.remaining_ms,
            calls: live
                .calls
                .into_iter()
                .map(|call| DreamerWakeLiveCallView {
                    call_ref: call.call.to_hex(),
                    lease_id: call.lease_id,
                    lease: call.lease.map(|lease| match lease {
                        BudgetLeaseState::Open {
                            reserve_units,
                            dispatched,
                        } => DreamerWakeLeaseView::Open {
                            reserve_units,
                            dispatched,
                        },
                        BudgetLeaseState::Settled { used_units } => {
                            DreamerWakeLeaseView::Settled { used_units }
                        }
                        BudgetLeaseState::Aborted => DreamerWakeLeaseView::Aborted,
                    }),
                })
                .collect(),
        }),
    }
}

fn generation_view(generation: &WakeObservedGeneration) -> DreamerWakeGenerationView {
    let attempt = &generation.attempt;
    DreamerWakeGenerationView {
        job_ref: hex_string(attempt.attempt.as_bytes()),
        attempt_count: attempt.attempt_count,
        wake_ref: attempt.wake.entity_id().to_hex(),
        worker: attempt.worker.clone(),
        run_id: attempt.run_id.clone(),
        admitted_elapsed_ms: attempt.admitted_elapsed_ms,
        checkpoint: attempt
            .park
            .zip(generation.checkpoint.as_ref())
            .map(|(park, cut)| checkpoint_view(park, cut)),
        after_cut: attempt
            .after_cut
            .zip(generation.after_cut.as_ref())
            .map(|(park, cut)| checkpoint_view(park, cut)),
    }
}

fn checkpoint_view(park: EntityId, cut: &WakeObservedCheckpoint) -> DreamerWakeCheckpointView {
    DreamerWakeCheckpointView {
        park_ref: park.to_hex(),
        job_ref: hex_string(cut.attempt.as_bytes()),
        attempt_count: cut.attempt_count,
        wake_ref: cut.wake.entity_id().to_hex(),
        parked_at: cut.parked_at,
        saved_steps: cut
            .saved_steps
            .iter()
            .map(|step| hex_string(step))
            .collect(),
        resumed: cut.resumed.as_ref().map(|resumed| DreamerWakeResumeView {
            wake_ref: resumed.wake.entity_id().to_hex(),
            at: resumed.at,
            worker: resumed.worker.clone(),
        }),
    }
}

fn call_view(call: &WakeObservedCall) -> DreamerWakeCallView {
    DreamerWakeCallView {
        call_ref: call.call.to_hex(),
        job_ref: hex_string(call.attempt.as_bytes()),
        attempt_count: call.attempt_count,
        step_hash: hex_string(&call.step_hash),
        ordinal: call.ordinal,
        lease_id: call.lease_id.clone(),
        admitted_elapsed_ms: call.admitted_elapsed_ms,
        end: call.end.as_ref().map(|end| DreamerWakeCallEndView {
            state: match end.state {
                WakeCallState::Claimed => DreamerWakeCallStateView::Claimed,
                WakeCallState::Settled => DreamerWakeCallStateView::Settled,
                WakeCallState::Aborted => DreamerWakeCallStateView::Aborted,
                WakeCallState::Unsettled => DreamerWakeCallStateView::Unsettled,
            },
            at_unix_ms: end.at_unix_ms,
            used_units: end.used_units,
            claim_ref: end.claim.map(|claim| claim.to_hex()),
        }),
    }
}
