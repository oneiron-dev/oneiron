//! Owner-proof shared model streams: subscriptions can attach before one
//! admitted producer opens. HTTP and held-socket verb RPCs use this same
//! door, as SDK and MCP do. The engine bus owns all event fanout; only its
//! ContentPart terminal is durable, never its transient event history.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use futures_util::StreamExt;
use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::model_stream::{
    self, ModelStreamAbort, ModelStreamDetach, ModelStreamDetached, ModelStreamEvents,
    ModelStreamEventsRequest, ModelStreamOpen, ModelStreamOpened, ModelStreamStatus,
    ModelStreamSubscribe, ModelStreamSubscribed, ModelStreamTerminal, ModelStreamTerminalRequest,
};
use oneiron::llm::{LlmEventBus, StreamSubscription};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE,
    MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryResult,
};
use oneiron::{EntityId, LlmStreamEvent};
use tokio::sync::Notify;

use super::host_doors::support::{internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

#[derive(Default)]
pub(crate) struct ModelStreams {
    entries: Mutex<HashMap<String, Arc<Entry>>>,
}

struct Entry {
    auth: CoreAuth,
    stream_ref: String,
    state: Mutex<StreamState>,
    stop: Notify,
}

struct StreamState {
    status: ModelStreamStatus,
    opening: bool,
    bus: LlmEventBus,
    subs: HashMap<String, StreamSubscription>,
}

fn missing() -> MemoryError {
    MemoryError::not_found("no live model stream belongs to this credential")
}

fn no_subscription() -> MemoryError {
    MemoryError::not_found("no model-stream subscription belongs to this credential")
}

impl ModelStreams {
    fn get(&self, auth: &CoreAuth, stream_key: &str) -> MemoryResult<Arc<Entry>> {
        self.entries
            .lock()
            .map_err(|_| internal("ai.streams"))?
            .get(stream_key)
            .filter(|entry| entry.auth.same_authority(auth))
            .cloned()
            .ok_or_else(missing)
    }

    /// Reserve a credential-bound bus without starting a producer or writing
    /// a row. Open and subscribe share this operation; another credential
    /// cannot replace the standing bus or take its subscription handles.
    fn attach(
        &self,
        server: &SyncServer,
        auth: &CoreAuth,
        owner: AuthenticatedOwner,
        stream_key: &str,
    ) -> MemoryResult<Arc<Entry>> {
        let mut entries = self.entries.lock().map_err(|_| internal("ai.streams"))?;
        if let Some(entry) = entries.get(stream_key) {
            return if entry.auth.same_authority(auth) {
                Ok(Arc::clone(entry))
            } else {
                Err(missing())
            };
        }
        let sink = model_stream::sink(Arc::clone(&server.vault), owner, stream_key)?;
        let entry = Arc::new(Entry {
            auth: auth.clone(),
            stream_ref: sink.stream_ref(),
            state: Mutex::new(StreamState {
                status: ModelStreamStatus::Pending,
                opening: false,
                bus: LlmEventBus::new(Box::new(sink)),
                subs: HashMap::new(),
            }),
            stop: Notify::new(),
        });
        entries.insert(stream_key.to_owned(), Arc::clone(&entry));
        Ok(entry)
    }
}

async fn durable<T: Send + 'static>(
    server: &Arc<SyncServer>,
    verb: &'static str,
    call: impl FnOnce(&oneiron::Vault) -> MemoryResult<T> + Send + 'static,
) -> MemoryResult<T> {
    let vault = Arc::clone(&server.vault);
    super::clock_ingress::run_blocking(move || call(&vault))
        .await
        .map_err(|_| internal(verb))?
}

pub(crate) async fn ai_streams_open(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelStreamOpen,
) -> MemoryResult<ModelStreamOpened> {
    const VERB: &str = "ai.streams.open";
    let owner = owner_proof(auth, server, VERB)?;
    let server = Arc::clone(server);
    let auth = auth.clone();
    // Once open is admitted, losing its HTTP/WS caller cannot strand the
    // opening claim between the durable write and the producer spawn.
    tokio::spawn(async move { open(&server, &auth, owner, input).await })
        .await
        .map_err(|_| internal(VERB))?
}

async fn open(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    owner: AuthenticatedOwner,
    mut input: ModelStreamOpen,
) -> MemoryResult<ModelStreamOpened> {
    const VERB: &str = "ai.streams.open";
    let entry = server
        .model_streams
        .attach(server, auth, owner.clone(), &input.stream_key)?;
    let start = {
        let mut state = entry.state.lock().map_err(|_| internal(VERB))?;
        if state.opening {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "the model stream is still opening; repeat open once it answers",
                &[],
            ));
        }
        let start = state.status == ModelStreamStatus::Pending;
        if start {
            state.opening = true;
        }
        start
    };
    // The write transaction freezes the exact caller request and tells only
    // its creator to start a producer. A row recovered after a restart must
    // never dispatch the same generation again.
    let opened = durable(server, VERB, {
        let owner = owner.clone();
        let input = input.clone();
        move |vault| model_stream::open_as_owner(vault, &owner, &input)
    })
    .await;
    let (mut opened, created) = match opened {
        Ok(opened) => opened,
        Err(error) => {
            if start {
                entry.state.lock().map_err(|_| internal(VERB))?.opening = false;
            }
            return Err(error);
        }
    };
    if !start {
        return Ok(opened);
    }
    if !created {
        if opened.status == ModelStreamStatus::Live {
            let terminal = durable(server, VERB, {
                let owner = owner.clone();
                let stream_key = input.stream_key.clone();
                move |vault| {
                    model_stream::fail_as_owner(
                        vault,
                        &owner,
                        &stream_key,
                        "the model stream's producer ended before a terminal",
                    )
                }
            })
            .await?;
            opened.status = terminal.status;
        }
        let mut state = entry.state.lock().map_err(|_| internal(VERB))?;
        state.bus.close_without_terminal();
        state.status = opened.status;
        state.opening = false;
        return Ok(opened);
    }
    // Identical owner, inference policy, route-selector refusal, model
    // binding and run meter as the raw `/v1/llm/stream` sibling.
    let admitted = crate::api::llm::admit(server, auth, &mut input.request).map_err(|response| {
        let code = match response.status().as_u16() {
            401 | 403 => MEMORY_CODE_FORBIDDEN,
            503 => MEMORY_CODE_MODEL_UNAVAILABLE,
            _ => MEMORY_CODE_BAD_REQUEST,
        };
        MemoryError::new(code, "the inference door refused this model stream", &[])
    });
    let (ladder, run) = match admitted {
        Ok(admitted) => admitted,
        Err(error) => {
            close_failed(
                &entry,
                server.vault(),
                &owner,
                &input.stream_key,
                &error.message,
            );
            return Err(error);
        }
    };
    let source = match ladder.stream(&run, input.request, None) {
        Ok(source) => source,
        Err(error) => {
            close_failed(
                &entry,
                server.vault(),
                &owner,
                &input.stream_key,
                &format!("{error:?}"),
            );
            return Err(MemoryError::new(
                MEMORY_CODE_MODEL_UNAVAILABLE,
                "the model stream did not start",
                &[],
            ));
        }
    };
    {
        let mut state = entry.state.lock().map_err(|_| internal(VERB))?;
        state.status = ModelStreamStatus::Live;
        state.opening = false;
    }
    let vault = Arc::clone(&server.vault);
    tokio::spawn(async move {
        produce(entry, source, vault, owner, input.stream_key).await;
    });
    Ok(opened)
}

/// Only this task polls the admitted source. Subscribers never poll it and
/// never hold a producer lease. Stopping one subscriber cannot stop it.
async fn produce(
    entry: Arc<Entry>,
    mut source: oneiron::LlmStream<'static>,
    vault: Arc<oneiron::Vault>,
    owner: AuthenticatedOwner,
    stream_key: String,
) {
    loop {
        let item = tokio::select! {
            biased;
            _ = entry.stop.notified() => return,
            item = source.next() => item,
        };
        let event = match item {
            Some(Ok(event)) => event,
            Some(Err(error)) => {
                close_failed(&entry, &vault, &owner, &stream_key, &format!("{error:?}"));
                return;
            }
            None => {
                close_failed(
                    &entry,
                    &vault,
                    &owner,
                    &stream_key,
                    "the model stream ended without a terminal",
                );
                return;
            }
        };
        let done = matches!(event, LlmStreamEvent::Done { .. });
        let published = {
            let Ok(mut state) = entry.state.lock() else {
                return;
            };
            if state.status != ModelStreamStatus::Live {
                return;
            }
            let result = state.bus.publish(event);
            if result.is_ok() && done {
                state.status = ModelStreamStatus::Finished;
            }
            result
        };
        match published {
            Ok(()) if done => return,
            Ok(()) => {}
            Err(error) => {
                close_failed(&entry, &vault, &owner, &stream_key, &format!("{error:?}"));
                return;
            }
        }
    }
}

fn close_failed(
    entry: &Entry,
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    stream_key: &str,
    failure: &str,
) {
    let Ok(mut state) = entry.state.lock() else {
        return;
    };
    if matches!(
        state.status,
        ModelStreamStatus::Finished | ModelStreamStatus::Failed
    ) {
        return;
    }
    state.bus.close_without_terminal();
    let _ = model_stream::fail_as_owner(vault, owner, stream_key, failure);
    state.status = ModelStreamStatus::Failed;
    state.opening = false;
}

pub(crate) async fn ai_streams_subscribe(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelStreamSubscribe,
) -> MemoryResult<ModelStreamSubscribed> {
    const VERB: &str = "ai.streams.subscribe";
    let owner = owner_proof(auth, server, VERB)?;
    let entry = server
        .model_streams
        .attach(server, auth, owner, &input.stream_key)?;
    let handle = EntityId::now().to_hex();
    let mut state = entry.state.lock().map_err(|_| internal(VERB))?;
    let subscription = state.bus.subscribe();
    state.subs.insert(handle.clone(), subscription);
    Ok(ModelStreamSubscribed {
        stream_ref: entry.stream_ref.clone(),
        stream_key: input.stream_key,
        handle,
        status: state.status,
    })
}

pub(crate) async fn ai_streams_events(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelStreamEventsRequest,
) -> MemoryResult<ModelStreamEvents> {
    const VERB: &str = "ai.streams.events";
    owner_proof(auth, server, VERB)?;
    let entry = server.model_streams.get(auth, &input.stream_key)?;
    let limit =
        usize::try_from(input.limit.unwrap_or(64).clamp(1, 512)).map_err(|_| internal(VERB))?;
    let mut state = entry.state.lock().map_err(|_| internal(VERB))?;
    let subscription = state
        .subs
        .get_mut(&input.handle)
        .ok_or_else(no_subscription)?;
    let mut events = Vec::new();
    let mut closed = false;
    let waker: Waker = Waker::noop().clone();
    while events.len() < limit {
        let mut context = Context::from_waker(&waker);
        match subscription.poll_next_unpin(&mut context) {
            Poll::Ready(Some(event)) => events.push(event),
            Poll::Ready(None) => {
                closed = true;
                break;
            }
            Poll::Pending => break,
        }
    }
    Ok(ModelStreamEvents {
        stream_ref: entry.stream_ref.clone(),
        stream_key: input.stream_key,
        handle: input.handle,
        events,
        closed,
        status: state.status,
    })
}

pub(crate) async fn ai_streams_detach(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelStreamDetach,
) -> MemoryResult<ModelStreamDetached> {
    const VERB: &str = "ai.streams.detach";
    owner_proof(auth, server, VERB)?;
    let entry = server.model_streams.get(auth, &input.stream_key)?;
    let detached = entry
        .state
        .lock()
        .map_err(|_| internal(VERB))?
        .subs
        .remove(&input.handle)
        .is_some();
    if !detached {
        return Err(no_subscription());
    }
    Ok(ModelStreamDetached {
        stream_ref: entry.stream_ref.clone(),
        stream_key: input.stream_key,
        handle: input.handle,
        detached,
    })
}

pub(crate) async fn ai_streams_abort(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelStreamAbort,
) -> MemoryResult<ModelStreamTerminal> {
    const VERB: &str = "ai.streams.abort";
    let owner = owner_proof(auth, server, VERB)?;
    let entry = server.model_streams.get(auth, &input.stream_key)?;
    {
        let mut state = entry.state.lock().map_err(|_| internal(VERB))?;
        if state.opening || state.status == ModelStreamStatus::Pending {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "the model stream has not opened yet",
                &[],
            ));
        }
        if state.status == ModelStreamStatus::Live {
            state.bus.abort(input.usage).map_err(|_| {
                MemoryError::bad_request("the model stream terminal was not recorded")
            })?;
            state.status = ModelStreamStatus::Finished;
            // Unlike detach, abort also drops the source and its model lease,
            // even when the provider is silent and never yields another event.
            entry.stop.notify_one();
        }
    }
    durable(server, VERB, move |vault| {
        model_stream::terminal_as_owner(
            vault,
            &owner,
            &ModelStreamTerminalRequest {
                stream_key: input.stream_key,
            },
        )
    })
    .await
}

pub(crate) async fn ai_streams_terminal(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelStreamTerminalRequest,
) -> MemoryResult<ModelStreamTerminal> {
    const VERB: &str = "ai.streams.terminal";
    let owner = owner_proof(auth, server, VERB)?;
    let stream_key = input.stream_key.clone();
    let read = durable(server, VERB, {
        let owner = owner.clone();
        move |vault| model_stream::terminal_as_owner(vault, &owner, &input)
    })
    .await?;
    // Look for the producer, not this credential's subscription access: a
    // second owner credential reading a terminal must not fail a live call.
    let held = server
        .model_streams
        .entries
        .lock()
        .map_err(|_| internal(VERB))?
        .get(&stream_key)
        .cloned();
    // A subscription created after a restart holds a pending bus, not a
    // replacement producer. It cannot make an orphaned durable row live.
    let running = held.as_ref().is_some_and(|entry| {
        entry
            .state
            .lock()
            .is_ok_and(|state| state.opening || state.status == ModelStreamStatus::Live)
    });
    if read.status == ModelStreamStatus::Live && !running {
        let terminal = durable(server, VERB, move |vault| {
            model_stream::fail_as_owner(
                vault,
                &owner,
                &stream_key,
                "the model stream's producer ended before a terminal",
            )
        })
        .await?;
        if let Some(entry) = held {
            let mut state = entry.state.lock().map_err(|_| internal(VERB))?;
            state.bus.close_without_terminal();
            state.status = terminal.status;
        }
        return Ok(terminal);
    }
    Ok(read)
}
