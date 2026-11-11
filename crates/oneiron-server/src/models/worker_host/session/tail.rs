//! Preparation source failures are not worker refusals or live call releases.
use oneiron::llm::{SessionInvalidation, SessionPrepare, SessionPrepared};
use serde_json::Value as JsonValue;

use super::policy;
use super::registry::Place;
use crate::models::native_exl3::{
    OpFault, PrepareSourceCheck, PrepareSourceMiss, ReleasedPrepareFault,
    session_prepare_source_released,
};

pub(super) enum Failure {
    Invalidation(SessionInvalidation),
    Release(oneiron::LlmError),
    Source(PrepareSourceMiss),
}

pub(super) async fn send(
    place: &Place,
    body: &SessionPrepare,
    conversation: &JsonValue,
    lease: &oneiron::BudgetLease,
    source: &PrepareSourceCheck<'_>,
) -> Result<SessionPrepared, Failure> {
    session_prepare_source_released(
        &place.launch,
        &place.epoch,
        body,
        conversation,
        &place.worker,
        lease,
        source,
    )
    .await
    .map_err(|fault| match fault {
        ReleasedPrepareFault::Op(OpFault::Refused(code)) => {
            Failure::Invalidation(policy::refused(&code))
        }
        ReleasedPrepareFault::Op(OpFault::Cut) => {
            Failure::Invalidation(SessionInvalidation::Evicted)
        }
        ReleasedPrepareFault::Release(error) => Failure::Release(error),
        ReleasedPrepareFault::Source(reason) => Failure::Source(reason),
    })
}
