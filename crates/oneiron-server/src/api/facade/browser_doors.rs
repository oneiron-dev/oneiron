//! Typed browser calls on the caller's own attached run and existing guest door.
use std::sync::Arc;

use oneiron::code_run::{HostSelfDispatcher, SelfAgentVerbCall};
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{self, AgentVerb, LiveRunRequest};
use oneiron::{EdgeActorClass, EntityId};
use serde::{Serialize, de::DeserializeOwned};

use super::host_doors::{Listed, internal};
use super::live_run_doors::hold_live_run;
use crate::api::VerdictAsker;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

async fn on_browser<I, O>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    invocation: Option<InvocationId>,
    verb: AgentVerb,
    input: LiveRunRequest<I>,
) -> Listed<O>
where
    I: Serialize + Send + 'static,
    O: DeserializeOwned + Send + 'static,
{
    let answer = async {
        let (writer, run, held) = hold_live_run(server, auth, session, &input.live_run).await?;
        let (server, auth) = (Arc::clone(server), auth.clone());
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let binding = held.proof();
            let dispatcher = HostSelfDispatcher::for_live_run(server.vault(), writer, &binding)?;
            let origin = dispatcher.browser_origin_from_host(verb)?;
            let memory = crate::api::credential_memory(
                server.vault(),
                Some(&auth),
                writer.entity_ref(),
                writer.actor_class(),
            )
            .at(auth.locality())
            .with_host_origin(origin.clone());
            let memory = match invocation {
                Some(invocation) => memory.with_invocation(invocation),
                None => memory,
            };
            let call = SelfAgentVerbCall {
                verb,
                input: serde_json::to_value(input.spec)
                    .map_err(|_| MemoryError::bad_request("browser input encoding failed"))?,
            };
            let guests = run.browser_guests(&server);
            let answer = guests.call_admitted(
                &server,
                &runtime,
                &call,
                &origin,
                &memory,
                VerdictAsker::Credential(auth.clone(), writer),
                writer.entity_ref(),
            )?;
            // Release no result to a credential revoked while the guest acted.
            let proof = auth.verified_slip().ok_or_else(|| {
                MemoryError::new(
                    oneiron::memory::MEMORY_CODE_FORBIDDEN,
                    "a browser call requires its live credential",
                    &[],
                )
            })?;
            server.vault().credential_read_key(proof)?.ok_or_else(|| {
                MemoryError::new(
                    oneiron::memory::MEMORY_CODE_FORBIDDEN,
                    "the browser credential no longer holds",
                    &[],
                )
            })?;
            drop(held);
            let answer =
                answer.map_err(|refusal| MemoryError::new(&refusal.code, &refusal.code, &[]))?;
            serde_json::from_value(answer.output).map_err(|_| internal(verb.as_str()))
        })
        .await
        .map_err(|_| internal(verb.as_str()))?
    }
    .await;
    // The page is foreign data, not a listing of vault entity rows.
    (answer, Vec::new())
}

pub(crate) async fn self_browser_open(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<sdk::BrowserOpenInput>,
) -> Listed<sdk::BrowserObservationPage> {
    on_browser(
        server,
        auth,
        session,
        invocation,
        AgentVerb::SelfBrowserOpen,
        input,
    )
    .await
}

pub(crate) async fn self_browser_switch_engine(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<sdk::BrowserSwitchEngineInput>,
) -> Listed<sdk::BrowserSwitchEngineOutput> {
    on_browser(
        server,
        auth,
        session,
        invocation,
        AgentVerb::SelfBrowserSwitchEngine,
        input,
    )
    .await
}

pub(crate) async fn self_browser_observe(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<sdk::BrowserObserveInput>,
) -> Listed<sdk::BrowserObservationPage> {
    on_browser(
        server,
        auth,
        session,
        invocation,
        AgentVerb::SelfBrowserObserve,
        input,
    )
    .await
}

pub(crate) async fn self_browser_find(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<sdk::BrowserFindInput>,
) -> Listed<sdk::BrowserFindOutput> {
    on_browser(
        server,
        auth,
        session,
        invocation,
        AgentVerb::SelfBrowserFind,
        input,
    )
    .await
}

pub(crate) async fn self_browser_click(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<sdk::BrowserClickInput>,
) -> Listed<sdk::BrowserObservationPage> {
    on_browser(
        server,
        auth,
        session,
        invocation,
        AgentVerb::SelfBrowserClick,
        input,
    )
    .await
}

pub(crate) async fn self_browser_click_at(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<sdk::BrowserPointInput>,
) -> Listed<sdk::BrowserObservationPage> {
    on_browser(
        server,
        auth,
        session,
        invocation,
        AgentVerb::SelfBrowserClickAt,
        input,
    )
    .await
}

pub(crate) async fn self_browser_type(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<sdk::BrowserTypeInput>,
) -> Listed<sdk::BrowserObservationPage> {
    on_browser(
        server,
        auth,
        session,
        invocation,
        AgentVerb::SelfBrowserType,
        input,
    )
    .await
}

pub(crate) async fn self_browser_select(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<sdk::BrowserSelectInput>,
) -> Listed<sdk::BrowserObservationPage> {
    on_browser(
        server,
        auth,
        session,
        invocation,
        AgentVerb::SelfBrowserSelect,
        input,
    )
    .await
}

pub(crate) async fn self_browser_wait_for(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<sdk::BrowserWaitForInput>,
) -> Listed<sdk::BrowserWaitForOutput> {
    on_browser(
        server,
        auth,
        session,
        invocation,
        AgentVerb::SelfBrowserWaitFor,
        input,
    )
    .await
}

pub(crate) async fn self_browser_expect(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<sdk::BrowserExpectInput>,
) -> Listed<sdk::BrowserExpectOutput> {
    on_browser(
        server,
        auth,
        session,
        invocation,
        AgentVerb::SelfBrowserExpect,
        input,
    )
    .await
}

pub(crate) async fn self_browser_screenshot(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<sdk::BrowserScreenshotInput>,
) -> Listed<sdk::BrowserScreenshotOutput> {
    on_browser(
        server,
        auth,
        session,
        invocation,
        AgentVerb::SelfBrowserScreenshot,
        input,
    )
    .await
}

pub(crate) async fn self_browser_view(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<sdk::BrowserViewInput>,
) -> Listed<sdk::BrowserImageOutput> {
    on_browser(
        server,
        auth,
        session,
        invocation,
        AgentVerb::SelfBrowserView,
        input,
    )
    .await
}

pub(crate) async fn self_browser_crop(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<sdk::BrowserCropInput>,
) -> Listed<sdk::BrowserImageOutput> {
    on_browser(
        server,
        auth,
        session,
        invocation,
        AgentVerb::SelfBrowserCrop,
        input,
    )
    .await
}

pub(crate) async fn self_browser_zoom(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<sdk::BrowserZoomInput>,
) -> Listed<sdk::BrowserImageOutput> {
    on_browser(
        server,
        auth,
        session,
        invocation,
        AgentVerb::SelfBrowserZoom,
        input,
    )
    .await
}

pub(crate) async fn self_browser_batch(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<sdk::BrowserBatchInput>,
) -> Listed<sdk::BrowserBatchOutput> {
    on_browser(
        server,
        auth,
        session,
        invocation,
        AgentVerb::SelfBrowserBatch,
        input,
    )
    .await
}

pub(crate) async fn self_browser_library_find(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<sdk::BrowserLibraryFindInput>,
) -> Listed<sdk::BrowserLibraryFindOutput> {
    on_browser(
        server,
        auth,
        session,
        invocation,
        AgentVerb::SelfBrowserLibraryFind,
        input,
    )
    .await
}

pub(crate) async fn self_browser_library_propose(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<sdk::BrowserLibraryProposeInput>,
) -> Listed<sdk::BrowserLibraryProposeOutput> {
    on_browser(
        server,
        auth,
        session,
        invocation,
        AgentVerb::SelfBrowserLibraryPropose,
        input,
    )
    .await
}

pub(crate) async fn self_browser_library_retire(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<sdk::BrowserLibraryRetireInput>,
) -> Listed<sdk::BrowserLibraryRetireOutput> {
    on_browser(
        server,
        auth,
        session,
        invocation,
        AgentVerb::SelfBrowserLibraryRetire,
        input,
    )
    .await
}

pub(crate) async fn self_browser_library_retired(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<sdk::BrowserLibraryRetiredInput>,
) -> Listed<sdk::BrowserLibraryRetiredOutput> {
    on_browser(
        server,
        auth,
        session,
        invocation,
        AgentVerb::SelfBrowserLibraryRetired,
        input,
    )
    .await
}

pub(crate) async fn self_browser_library_run(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<sdk::BrowserLibraryRunInput>,
) -> Listed<sdk::BrowserLibraryRunOutput> {
    on_browser(
        server,
        auth,
        session,
        invocation,
        AgentVerb::SelfBrowserLibraryRun,
        input,
    )
    .await
}

pub(crate) async fn self_browser_handover(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<sdk::BrowserHandoverInput>,
) -> Listed<sdk::BrowserHandoverOutput> {
    on_browser(
        server,
        auth,
        session,
        invocation,
        AgentVerb::SelfBrowserHandover,
        input,
    )
    .await
}
