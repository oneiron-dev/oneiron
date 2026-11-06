//! OpenAI Responses through the credential broker, one upgraded socket per call.
//!
//! The vault keeps the conversation and stored chain; the broker holds the key
//! only for its call. A chained `previous_response_not_found` is retried whole
//! on that same broker socket, never as a second physical call. Chat HTTP is
//! the fallback only when the provider cannot accept an upgrade/create, never
//! after an ambiguous send.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use futures_util::StreamExt;
use oneiron::llm::{SingleRouteBackend, TransportFault, TransportFaultKind};
use oneiron::{
    BudgetLease, FatalLlmError, LlmBackend, LlmCapability, LlmGenerateFuture, LlmRequest,
    LlmResult, LlmStream, LlmStreamEvent, LlmStreamResult, ModelId, RetryableLlmError,
};
use oneiron_broker::{CallHeader, Failure, Outcome, Refusal, Shape, StreamPart};
use oneiron_llm_openai::{
    OpenAiCompatConfig, OpenAiCompatProviderStream, OpenAiCompatStreamFrame,
    OpenAiCompatTransportError, OpenAiResponsesChain, OpenAiResponsesLlmStream,
    OpenAiResponsesTurn, RESPONSES_PREVIOUS_NOT_FOUND, RESPONSES_SOCKET_LIMIT,
    build_openai_responses_turn, responses_can_carry, responses_error_code,
    responses_event_is_terminal, responses_event_type, responses_item_digests,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::broker::{BrokerBackend, answered, broker_error, join, open_with_whole};
use super::http::is_cloud_node;
use super::output_cap::OutputCap;
use super::responses_socket::ResponsesContext;
use super::served::record_served_model;
use crate::config::models::ResponseFormatWire;

const CHAIN_PREFIX: &str = "models:responses-chain:v1:";
const UPGRADE_STAGE: &str = "responses_upgrade";

#[derive(Serialize, Deserialize)]
struct ChainRow {
    response_id: String,
    updated: u64,
}

/// One `key_secret` OpenAI provider's Responses sessions, with its existing
/// broker chat backend as the fallback. `config` and `catalog` keep the
/// original capabilities: broker chat strips Streaming, Responses does not.
pub(super) struct BrokerResponses {
    chat: Arc<BrokerBackend>,
    config: OpenAiCompatConfig,
    catalog: BTreeMap<ModelId, oneiron::LlmCatalogEntry>,
    context: ResponsesContext,
    cap: OutputCap,
    response_format: ResponseFormatWire,
    provider_key: String,
    refused: AtomicBool,
}

impl BrokerResponses {
    pub(super) fn new(
        chat: BrokerBackend,
        config: OpenAiCompatConfig,
        catalog: BTreeMap<ModelId, oneiron::LlmCatalogEntry>,
        context: ResponsesContext,
        cap: OutputCap,
        response_format: ResponseFormatWire,
    ) -> Self {
        let mut provider_key = blake3::Hasher::new();
        provider_key.update(chat.origin().as_bytes());
        provider_key.update(chat.prefix().as_bytes());
        provider_key.update(&[0]);
        provider_key.update(chat.secret().as_bytes());
        let provider_key = provider_key.finalize().to_hex()[..16].to_owned();
        Self {
            chat: Arc::new(chat),
            config,
            catalog,
            context,
            cap,
            response_format,
            provider_key,
            refused: AtomicBool::new(false),
        }
    }

    fn usable(&self) -> bool {
        !self.refused.load(Ordering::Relaxed)
    }

    fn carries(&self, request: &LlmRequest) -> bool {
        self.usable() && responses_can_carry(request)
    }

    fn responses_digest(&self, request: &LlmRequest, stream: bool) -> LlmResult<String> {
        let turn = self.turn(request, stream)?;
        let (header, _, _) = self.header("", &turn, None, &turn.items)?;
        Ok(header.digest)
    }

    fn responses_for_digest(
        &self,
        request: &LlmRequest,
        stream: bool,
        digest: &str,
    ) -> LlmResult<bool> {
        if responses_can_carry(request)
            && self.responses_digest(request, stream).as_deref() == Ok(digest)
        {
            return Ok(true);
        }
        if self.chat.request_digest(request, false)?.as_deref() == Some(digest) {
            return Ok(false);
        }
        Err(FatalLlmError::InvalidRequest.into())
    }

    fn preflight_route(
        &self,
        request: &LlmRequest,
        stream: bool,
        responses: bool,
    ) -> LlmResult<()> {
        if !responses {
            return self.chat.preflight(request, false);
        }
        if !stream {
            self.chat.preflight(request, false)?;
        }
        self.turn(request, stream)?;
        if let Err(error) = self.chat.client().ready() {
            tracing::warn!(%error, "no credential broker to send through");
            return Err(RetryableLlmError::StreamCut.into());
        }
        self.chat.keys().check(self.chat.secret()).map_err(|_| {
            tracing::warn!(
                reason = "key_custody_refused",
                "the custody door would refuse a provider key"
            );
            oneiron::FatalLlmError::Auth.into()
        })
    }

    fn turn(&self, request: &LlmRequest, stream: bool) -> LlmResult<OpenAiResponsesTurn> {
        let mut turn = build_openai_responses_turn(&self.config, request, stream)?;
        let mut head = JsonValue::Object(std::mem::take(&mut turn.head));
        self.cap.apply(&mut head);
        if let JsonValue::Object(head) = head {
            turn.head = head;
        }
        if self.response_format == ResponseFormatWire::Omitted {
            turn.head.remove("text");
        }
        if self.context.store() {
            turn.head.insert("store".into(), JsonValue::Bool(true));
        }
        Ok(turn)
    }

    fn header(
        &self,
        call: &str,
        turn: &OpenAiResponsesTurn,
        previous: Option<&str>,
        input: &[JsonValue],
    ) -> LlmResult<(CallHeader, Vec<u8>, Vec<u8>)> {
        let create = turn.create_frame(previous, input);
        let whole = turn.create_frame(None, &turn.items);
        let body = serde_json::to_vec(&create).map_err(|_| FatalLlmError::InvalidRequest)?;
        let digest_body = serde_json::to_vec(&whole).map_err(|_| FatalLlmError::InvalidRequest)?;
        let mut headers = self.chat.headers().clone();
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        let wire_model = create
            .get("model")
            .and_then(JsonValue::as_str)
            .ok_or(FatalLlmError::InvalidRequest)?
            .to_owned();
        let header = CallHeader::new_with_digest_body(
            call.to_owned(),
            Shape::OpenAiResponses,
            self.chat.origin().to_owned(),
            join(self.chat.prefix(), "/v1/responses"),
            headers.into_iter().collect(),
            wire_model,
            is_cloud_node(),
            &body,
            &digest_body,
        );
        header
            .check_responses(&body, &digest_body)
            .map_err(|_| FatalLlmError::InvalidRequest)?;
        Ok((header, body, digest_body))
    }

    fn chain_key(&self, digests: &[u64]) -> String {
        let mut hasher = blake3::Hasher::new();
        for digest in digests {
            hasher.update(&digest.to_le_bytes());
        }
        format!(
            "{CHAIN_PREFIX}{}:{}",
            self.provider_key,
            hasher.finalize().to_hex()
        )
    }

    async fn resume(&self, turn: &OpenAiResponsesTurn) -> OpenAiResponsesChain {
        if !turn.stored() {
            return OpenAiResponsesChain::default();
        }
        let Some(vault) = self.context.chain_vault() else {
            return OpenAiResponsesChain::default();
        };
        let digests = responses_item_digests(&turn.items);
        let mut hasher = blake3::Hasher::new();
        let mut keys = Vec::with_capacity(digests.len());
        for (covered, digest) in (1..digests.len()).zip(&digests) {
            hasher.update(&digest.to_le_bytes());
            keys.push((
                covered,
                format!(
                    "{CHAIN_PREFIX}{}:{}",
                    self.provider_key,
                    hasher.finalize().to_hex()
                ),
            ));
        }
        let found = tokio::task::spawn_blocking(move || {
            keys.into_iter().rev().find_map(|(covered, key)| {
                let bytes = vault.sync_state_get(&key).ok()??;
                let row = rmp_serde::from_slice::<ChainRow>(&bytes).ok()?;
                Some((covered, row.response_id))
            })
        })
        .await
        .ok()
        .flatten();
        if let Some((covered, response_id)) = found {
            OpenAiResponsesChain::resumed(&turn.items[..covered], response_id)
        } else {
            OpenAiResponsesChain::default()
        }
    }

    fn keep(&self, chain: &OpenAiResponsesChain, continued: Option<String>) {
        let (Some(vault), Some(response_id)) = (self.context.chain_vault(), chain.response_id())
        else {
            return;
        };
        let key = self.chain_key(chain.digests());
        let row = ChainRow {
            response_id: response_id.to_owned(),
            updated: vault.now_recorded_at(),
        };
        let Ok(bytes) = rmp_serde::to_vec_named(&row) else {
            return;
        };
        tokio::task::spawn_blocking(move || {
            if vault.sync_state_put(&key, &bytes).is_err() {
                tracing::warn!(
                    reason = "responses_chain_unwritten",
                    "a stored Responses chain could not be kept; its next new socket sends the whole conversation"
                );
                return;
            }
            if let Some(continued) = continued.filter(|continued| *continued != key) {
                let _ = vault.sync_state_delete(&continued);
            }
        });
    }

    fn forget(&self, key: String) {
        let Some(vault) = self.context.chain_vault() else {
            return;
        };
        tokio::task::spawn_blocking(move || {
            let _ = vault.sync_state_delete(&key);
        });
    }

    async fn run<'a>(
        &'a self,
        lease: &'a BudgetLease,
        turn: OpenAiResponsesTurn,
    ) -> LlmResult<OpenAiCompatProviderStream<'a>> {
        let mut chain = self.resume(&turn).await;
        let (previous, input) = chain.plan(&turn.items);
        let chained = previous.is_some();
        let (header, body, whole) = self.header(lease.id(), &turn, previous, input)?;
        // The broker's own Unreachable never reaches the provider. Return
        // that proof so the caller can release this permit before fallback.
        // The check dials and drops; the send below dials again. Any later
        // failure arrives from open_with_whole as its own LlmError.
        if let Err(error) = self.chat.client().connect().await {
            if matches!(error, oneiron_broker::BrokerError::Unreachable) {
                return Err(upgrade_error(
                    TransportFaultKind::NotSent,
                    "broker unreachable",
                ));
            }
            return Err(broker_error(error));
        }
        let reply = open_with_whole(
            self.chat.client(),
            self.chat.keys(),
            self.chat.secret(),
            &header,
            &body,
            &whole,
        )
        .await?;
        match reply.outcome().clone() {
            Outcome::Answered { status, .. } if !(200..=299).contains(&status) => {
                if (400..500).contains(&status) && !matches!(status, 408 | 429) {
                    self.refused.store(true, Ordering::Relaxed);
                }
                return Err(upgrade_error(
                    TransportFaultKind::Refused,
                    format!("Responses upgrade answered HTTP {status}"),
                ));
            }
            Outcome::Answered { .. } => {}
            Outcome::Refused {
                reason: Refusal::Connect,
            } => {
                return Err(upgrade_error(
                    TransportFaultKind::NotSent,
                    "provider connection refused before upgrade",
                ));
            }
            outcome => {
                let Err(error) = answered(outcome) else {
                    return Err(FatalLlmError::InvalidRequest.into());
                };
                return Err(error);
            }
        }
        let session = BrokerSession { reply, chain };
        Ok(Box::pin(futures_util::stream::unfold(
            Turn::Reading(session, turn, chained),
            move |state| self.step(state),
        )))
    }

    async fn step(&self, state: Turn) -> Option<(Event, Turn)> {
        let Turn::Reading(mut session, turn, mut chained) = state else {
            return None;
        };
        loop {
            match session.reply.next().await {
                Ok(StreamPart::Chunk(chunk)) => {
                    let Ok(mut event) = serde_json::from_slice::<JsonValue>(&chunk) else {
                        return Some((Err(OpenAiCompatTransportError::StreamCut), Turn::Done));
                    };
                    if responses_error_code(&event) == Some(RESPONSES_PREVIOUS_NOT_FOUND) && chained
                    {
                        if turn.stored() {
                            self.forget(self.chain_key(session.chain.digests()));
                        }
                        session.chain.clear();
                        chained = false;
                        continue;
                    }
                    if responses_error_code(&event) == Some(RESPONSES_SOCKET_LIMIT) {
                        return Some((Err(OpenAiCompatTransportError::StreamCut), Turn::Done));
                    }
                    if let Some(response) = event.get_mut("response") {
                        let served = response.get("model").cloned();
                        record_served_model(response.get_mut("usage"), served);
                    }
                    if responses_event_is_terminal(&event) {
                        match event.get("response") {
                            Some(response)
                                if responses_event_type(&event) == "response.completed" =>
                            {
                                let continued = (turn.stored() && chained)
                                    .then(|| self.chain_key(session.chain.digests()));
                                session.chain.record(&turn.items, response);
                                if turn.stored() {
                                    self.keep(&session.chain, continued);
                                }
                            }
                            _ => session.chain.clear(),
                        }
                        return Some((Ok(OpenAiCompatStreamFrame::Chunk(event)), Turn::Done));
                    }
                    return Some((
                        Ok(OpenAiCompatStreamFrame::Chunk(event)),
                        Turn::Reading(session, turn, chained),
                    ));
                }
                Ok(StreamPart::End) => {
                    return Some((Err(OpenAiCompatTransportError::StreamCut), Turn::Done));
                }
                Ok(StreamPart::Cut(reason)) => {
                    return Some((Err(cut_error(reason)), Turn::Done));
                }
                Err(_) => {
                    return Some((Err(OpenAiCompatTransportError::StreamCut), Turn::Done));
                }
            }
        }
    }
}

struct BrokerSession {
    reply: oneiron_broker::BrokerStream,
    chain: OpenAiResponsesChain,
}

enum Turn {
    Reading(BrokerSession, OpenAiResponsesTurn, bool),
    Done,
}

type Event = Result<OpenAiCompatStreamFrame, OpenAiCompatTransportError>;

fn cut_error(reason: Failure) -> OpenAiCompatTransportError {
    match reason {
        Failure::Timeout => OpenAiCompatTransportError::Timeout,
        Failure::Send => OpenAiCompatTransportError::StreamCut,
        Failure::ReplyTooLarge
        | Failure::ReplyEncoded
        | Failure::Redirect
        | Failure::ReplyHoldsKey => OpenAiCompatTransportError::Server,
    }
}

fn upgrade_error(kind: TransportFaultKind, detail: impl Into<String>) -> oneiron::LlmError {
    RetryableLlmError::TransportFault(TransportFault {
        kind,
        stage: Some(UPGRADE_STAGE.to_owned()),
        detail: detail.into(),
    })
    .into()
}

/// Chat remains buffered even when the admitted caller asked for a stream.
struct BufferedChat(Arc<BrokerBackend>);

impl LlmBackend for BufferedChat {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.0.supports(model, capability)
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.0.generate(request, lease)
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Ok(LlmStream::new(futures_util::stream::once(async move {
            let response = self.0.generate(request, lease).await?;
            Ok(LlmStreamEvent::Done {
                message: response.message,
                usage: response.usage,
                finish_reason: response.finish_reason,
                reply_assertions: response.reply_assertions,
            })
        })))
    }
}

impl SingleRouteBackend for BufferedChat {
    fn preflight(&self, request: &LlmRequest, _stream: bool) -> LlmResult<()> {
        self.0.preflight(request, false)
    }

    fn request_digest(&self, request: &LlmRequest, _stream: bool) -> LlmResult<Option<String>> {
        self.0.request_digest(request, false)
    }

    fn broker_isolation(&self) -> Option<oneiron::llm::BrokerIsolation> {
        self.0.broker_isolation()
    }
}

impl LlmBackend for BrokerResponses {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.catalog
            .get(model)
            .is_some_and(|entry| entry.supports(&capability))
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let digest = self
                .request_digest(&request, false)?
                .ok_or(FatalLlmError::InvalidRequest)?;
            self.generate_bound(request, lease, &digest).await
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        let digest = self
            .request_digest(&request, true)?
            .ok_or(FatalLlmError::InvalidRequest)?;
        self.stream_bound(request, lease, &digest)
    }
}

impl SingleRouteBackend for BrokerResponses {
    fn preflight(&self, request: &LlmRequest, stream: bool) -> LlmResult<()> {
        self.preflight_route(request, stream, self.carries(request))
    }

    fn request_digest(&self, request: &LlmRequest, stream: bool) -> LlmResult<Option<String>> {
        if !self.carries(request) {
            return self.chat.request_digest(request, false);
        }
        self.responses_digest(request, stream).map(Some)
    }

    fn dispatch_digest(
        &self,
        request: &LlmRequest,
        stream: bool,
        admitted_digest: Option<&str>,
    ) -> LlmResult<Option<String>> {
        let Some(digest) = admitted_digest else {
            self.preflight(request, stream)?;
            return self.request_digest(request, stream);
        };
        let responses = self.responses_for_digest(request, stream, digest)?;
        self.preflight_route(request, stream, responses)?;
        Ok(Some(digest.to_owned()))
    }

    fn generate_bound<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
        digest: &str,
    ) -> LlmGenerateFuture<'a> {
        let responses = self.responses_for_digest(&request, false, digest);
        Box::pin(async move {
            if !responses? {
                return self.chat.generate(request, lease).await;
            }
            let turn = self.turn(&request, false)?;
            let stream = self.run(lease, turn).await?;
            OpenAiResponsesLlmStream::new(stream).into_response().await
        })
    }

    fn stream_bound<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
        digest: &str,
    ) -> LlmStreamResult<'a> {
        if !self.responses_for_digest(&request, true, digest)? {
            // The wrapper must live as long as this stream, so keep its
            // shared chat directly in the owned one-event future.
            let chat = Arc::clone(&self.chat);
            return Ok(LlmStream::new(futures_util::stream::once(async move {
                let response = chat.generate(request, lease).await?;
                Ok(LlmStreamEvent::Done {
                    message: response.message,
                    usage: response.usage,
                    finish_reason: response.finish_reason,
                    reply_assertions: response.reply_assertions,
                })
            })));
        }
        let turn = self.turn(&request, true)?;
        let opened = async move {
            let stream = self.run(lease, turn).await?;
            Ok::<_, oneiron::LlmError>(LlmStream::new(OpenAiResponsesLlmStream::new(stream)))
        };
        Ok(LlmStream::new(futures_util::stream::once(opened).flat_map(
            |opened| match opened {
                Ok(stream) => stream.left_stream(),
                Err(error) => {
                    futures_util::stream::once(std::future::ready(Err(error))).right_stream()
                }
            },
        )))
    }

    fn fallback(&self, error: &oneiron::LlmError) -> Option<Arc<dyn SingleRouteBackend>> {
        match error {
            oneiron::LlmError::Retryable(RetryableLlmError::TransportFault(fault))
                if fault.stage.as_deref() == Some(UPGRADE_STAGE)
                    && matches!(
                        fault.kind,
                        TransportFaultKind::NotSent | TransportFaultKind::Refused
                    ) =>
            {
                Some(Arc::new(BufferedChat(Arc::clone(&self.chat))))
            }
            _ => None,
        }
    }

    fn broker_isolation(&self) -> Option<oneiron::llm::BrokerIsolation> {
        self.chat.broker_isolation()
    }
}
