//! Successor append errors keep an authority rejection separate from a worker fault.
use oneiron::llm::{SessionAppend, SessionAppended, SessionInvalidation};
use serde_json::Value as JsonValue;

use super::policy;
use super::registry::Place;
use crate::models::native_exl3::{
    AppendSourceCheck, OpFault, ReleasedAppendFault, session_append_source_released,
};

pub(super) enum Failure {
    Invalidation(SessionInvalidation),
    Release(oneiron::LlmError),
    Source(SessionInvalidation),
}

pub(super) async fn send(
    place: &Place,
    body: &SessionAppend,
    conversation: &JsonValue,
    lease: &oneiron::BudgetLease,
    source: &AppendSourceCheck<'_>,
) -> Result<SessionAppended, Failure> {
    session_append_source_released(
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
        ReleasedAppendFault::Op(OpFault::Refused(code)) => {
            Failure::Invalidation(policy::refused(&code))
        }
        ReleasedAppendFault::Op(OpFault::Cut) => {
            Failure::Invalidation(SessionInvalidation::Evicted)
        }
        ReleasedAppendFault::Release(error) => Failure::Release(error),
        ReleasedAppendFault::Source(reason) => Failure::Source(reason),
    })
}
