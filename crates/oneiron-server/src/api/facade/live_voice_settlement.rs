//! Observes an already admitted connector call; never resends or answers it.
use std::sync::Arc;

use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND, MemoryResult,
};
use oneiron::task_verb::sdk::ConnectorCallReply;
use oneiron::verbs::{ConnectorCallStatus, ConnectorCallStatusRequest};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{carrying_calling_run, credential_listing};
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use crate::voice_host::PublicSession;

pub(super) fn follow(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    session: &Arc<PublicSession>,
    call_ref: String,
    listed: Vec<EntityId>,
) -> MemoryResult<()> {
    let work = observe(
        Arc::clone(server),
        auth.clone(),
        caller,
        Arc::clone(session),
        call_ref.clone(),
        listed,
    );
    session.follow_tool(server, call_ref, carrying_calling_run(work))
}

async fn observe(
    server: Arc<SyncServer>,
    auth: CoreAuth,
    caller: (EntityId, EdgeActorClass),
    session: Arc<PublicSession>,
    call_ref: String,
    listed: Vec<EntityId>,
) {
    let mut delivered = None;
    loop {
        if !session.processed().is_ok_and(|processed| !processed.ended) {
            return;
        }
        if delivered.is_none()
            && let Some(admission) = session.tool_poll_admission(&server)
        {
            let input = ConnectorCallStatusRequest {
                call_ref: call_ref.clone(),
            };
            // Do not cancel this blocking read at shutdown: its owned guard
            // outlives the actual row consume, and the task owner joins it.
            let (status, rows) = credential_listing(
                &server,
                &auth,
                caller,
                "connector.call_status",
                move |_, _, memory| {
                    let _admission = admission;
                    oneiron::verbs::connector_call_status_read(&memory, input)
                },
            )
            .await;
            match status {
                Ok(ConnectorCallStatus::Settled {
                    reply:
                        ConnectorCallReply::Delivered {
                            result: Some(result),
                            ..
                        },
                    ..
                }) => {
                    let mut sources = listed.clone();
                    sources.extend(rows);
                    delivered = Some((result, sources));
                }
                Ok(ConnectorCallStatus::Settled {
                    reply:
                        ConnectorCallReply::Delivered { result: None, .. }
                        | ConnectorCallReply::Refused { .. }
                        | ConnectorCallReply::PendingDelivery { call_ref: None, .. },
                    ..
                }) => return,
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.code.as_str(),
                        MEMORY_CODE_NOT_FOUND | MEMORY_CODE_FORBIDDEN | MEMORY_CODE_BAD_REQUEST
                    ) =>
                {
                    return;
                }
                Err(error) => tracing::warn!(%error.code, "voice tool settlement read failed"),
            }
        }
        if let Some((result, rows)) = &delivered {
            let attached = tokio::select! {
                biased;
                () = session.closed() => return,
                attached = session.tool(result.clone(), rows.clone()) => attached,
            };
            match attached {
                Ok(_) => return,
                // The strict idle gate has attached nothing. Keep this actual
                // result until the same session can take it, without a resend.
                Err(error) if error.code == MEMORY_CODE_BAD_REQUEST => {}
                Err(_) => return,
            }
        }
        tokio::select! {
            () = session.closed() => return,
            () = tokio::time::sleep(crate::connector_call_settle::CONNECTOR_SETTLE_INTERVAL) => {},
        }
    }
}
