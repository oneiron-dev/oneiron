//! Observes an already admitted connector call; never resends or answers it.
use std::sync::Arc;

use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND, Memory, MemoryError,
    MemoryResult,
};
use oneiron::outbound_consent::ConnectorCallRequest;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{self, ConnectorCallReply};
use oneiron::verbs::{ConnectorCallStatus, ConnectorCallStatusRequest};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{carrying_calling_run, credential_listing};
use crate::auth::CoreAuth;
use crate::connector_elicitation::ConnectorResultInterest;
use crate::server::SyncServer;
use crate::voice_host::PublicSession;

/// Registers native result interest before dispatch or the held-row replay read.
pub(super) fn call(
    server: &SyncServer,
    memory: Memory<'_>,
    input: ConnectorCallRequest,
) -> MemoryResult<(
    (ConnectorCallReply, Option<Vec<EntityId>>),
    Option<ConnectorResultInterest>,
)> {
    if input.name == oneiron::web_connector::WEB_CONNECTOR_NAME {
        return super::connector_call_doors::connector_call_listing_as(server, &memory, input)
            .map(|reply| (reply, None));
    }
    let invocation = memory.invocation().unwrap_or_else(InvocationId::mint);
    let memory = memory.with_invocation(invocation);
    let native =
        sdk::connector_call_invocation(memory.actor(), invocation).map_err(MemoryError::from)?;
    let call_ref = native
        .call_ref(memory.actor())
        .map_err(sdk::connector_call_error)?;
    let interest = server
        .connector_elicitations
        .observe_result(memory.actor(), call_ref);
    let reply = super::connector_call_doors::connector_call_listing_as(server, &memory, input)?;
    Ok((reply, Some(interest)))
}

pub(super) fn follow(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    session: &Arc<PublicSession>,
    call_ref: String,
    listed: Vec<EntityId>,
    interest: Option<ConnectorResultInterest>,
) -> MemoryResult<()> {
    let work = observe(
        Arc::clone(server),
        auth.clone(),
        caller,
        Arc::clone(session),
        call_ref.clone(),
        listed,
        interest,
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
    interest: Option<ConnectorResultInterest>,
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
                    reply: ConnectorCallReply::Delivered { result: None, .. },
                    ..
                }) => {
                    // The worker retained its cleared live result before the
                    // receipt became visible. Durable rows still keep no body.
                    let Some(result) = interest.as_ref().and_then(|interest| interest.result())
                    else {
                        return;
                    };
                    let mut sources = listed.clone();
                    sources.extend(rows);
                    delivered = Some(((*result).clone(), sources));
                }
                Ok(ConnectorCallStatus::Settled {
                    reply:
                        ConnectorCallReply::Refused { .. }
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
