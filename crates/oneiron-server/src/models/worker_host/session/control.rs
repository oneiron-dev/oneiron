//! Canonical control frames keep source withdrawal distinct from live release.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::llm::SessionOp;
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::append::Failure;
use super::policy;
use super::registry::Place;
use super::{AuthorityVerdict, CheckpointAuthority, ReplyCommit};
use crate::models::native_exl3::{
    ControlSourceFuture, OpFault, ReleasedControlFault, session_control_source_released,
};

pub(super) async fn send<B: Serialize, R: DeserializeOwned>(
    place: &Place,
    op: SessionOp,
    body: &B,
    lease: &oneiron::BudgetLease,
    authority: &Arc<dyn CheckpointAuthority>,
    head: EntityId,
    message: EntityId,
) -> Result<R, Failure> {
    let source = || -> ControlSourceFuture<'_> {
        let authority = Arc::clone(authority);
        let commit = ReplyCommit {
            head,
            message,
            text: String::new(),
        };
        Box::pin(async move {
            let verdict = tokio::task::spawn_blocking(move || authority.recheck(&commit))
                .await
                .unwrap_or(AuthorityVerdict::Rejects(
                    oneiron::llm::SessionInvalidation::DisclosureOrScope,
                ));
            match verdict {
                AuthorityVerdict::Holds => Ok(()),
                AuthorityVerdict::Rejects(reason) => Err(reason),
            }
        })
    };
    session_control_source_released(
        &place.launch,
        &place.epoch,
        op,
        body,
        &place.worker,
        lease,
        &source,
    )
    .await
    .map_err(|fault| match fault {
        ReleasedControlFault::Op(OpFault::Refused(code)) => {
            Failure::Invalidation(policy::refused(&code))
        }
        ReleasedControlFault::Op(OpFault::Cut) => {
            Failure::Invalidation(oneiron::llm::SessionInvalidation::Evicted)
        }
        ReleasedControlFault::Release(error) => Failure::Release(error),
        ReleasedControlFault::Source(reason) => Failure::Source(reason),
    })
}
