//! The media sibling of `call_as_step` (FIX 465, FIX 2245): a durable
//! step's media call keyed by its attempt and its request's canonical hash.
//! The host keeps what the call was given under the key: a call's answer,
//! or a video job's ticket and never its clip, which a later poll of the
//! ticket answers. The step sent again in the same attempt answers from
//! there and is not paid for or rendered again.
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};

use super::execute::{BUDGET_PARK_REASON, HOST_CHECK_PARK_REASON, budget_trap};
use super::{DurableStepContext, DurableStepResult, StepOutcome, TrapRef};
use crate::entity_id::bytes_to_hex_lower;
use crate::llm::media::{MediaReplayKey, MediaRequest, MediaResponse};
use crate::llm::{BudgetDenied, DreamerFailureDecision, LlmError, LlmResult, canonical_json_bytes};

/// The replay key of `request`, sent as `ctx`'s step.
///
/// # Errors
///
/// A request whose canonical bytes do not encode.
pub fn media_step_key(
    ctx: &DurableStepContext<'_>,
    request: &MediaRequest,
) -> Result<MediaReplayKey, serde_json::Error> {
    MediaReplayKey::step(bytes_to_hex_lower(ctx.attempt_id.as_bytes()), request)
}

/// A media call's answer, or the budget trap that already parked its attempt.
#[derive(Debug, Clone, PartialEq)]
pub enum MediaStepOutcome {
    Finished(MediaResponse),
    Trapped {
        trap: TrapRef,
        failure_policy: DreamerFailureDecision,
    },
}

/// Runs the caller's existing media path as its durable step.
/// The supplied path owns admission, replay, receipts, and settlement.
/// Only a typed budget or host-check denial before any rung admitted opens a trap.
/// The media path sets `admitted` before an admitted rung can run its effect.
///
/// # Errors
///
/// Returns request canonicalization, trap persistence, or the media path's error.
pub async fn call_media_as_step<SendCall, CallFuture>(
    ctx: &DurableStepContext<'_>,
    request: MediaRequest,
    admitted: &AtomicBool,
    send: SendCall,
) -> DurableStepResult<MediaStepOutcome>
where
    SendCall: FnOnce(MediaRequest) -> CallFuture,
    CallFuture: Future<Output = LlmResult<MediaResponse>>,
{
    let step_hash = *blake3::hash(&canonical_json_bytes(&request)?).as_bytes();
    match send(request).await {
        Ok(response) => Ok(MediaStepOutcome::Finished(response)),
        Err(LlmError::BudgetDenied(
            denied @ (BudgetDenied::Exhausted | BudgetDenied::HostCheck),
        )) if !admitted.load(Ordering::Acquire) => {
            let reason = match denied {
                BudgetDenied::HostCheck => HOST_CHECK_PARK_REASON,
                _ => BUDGET_PARK_REASON,
            };
            match budget_trap(ctx, step_hash, reason)? {
                StepOutcome::Trapped {
                    trap,
                    failure_policy,
                } => Ok(MediaStepOutcome::Trapped {
                    trap,
                    failure_policy,
                }),
                StepOutcome::Finished { .. } => unreachable!(),
            }
        }
        Err(error) => Err(error.into()),
    }
}
