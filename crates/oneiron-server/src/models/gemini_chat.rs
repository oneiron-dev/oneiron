//! The Gemini API's chat transport (FIX 1816): a `gemini` provider's chat
//! rungs send `generateContent` and `streamGenerateContent` through
//! [`GeminiBackend`], as the other provider kinds send their own wires. The
//! key rides as `x-goog-api-key`. A `key_secret` provider's chat waits for
//! the credential broker's Gemini chat shape; its media calls go through
//! the broker already.
use std::collections::BTreeMap;
use std::sync::Arc;

use futures_util::StreamExt;
use oneiron::llm::SingleRouteBackend;
use oneiron::{BudgetLease, FatalLlmError, LlmCatalogEntry, LlmResult};
use oneiron_llm_gemini::{
    GeminiBackend, GeminiFrame, GeminiFuture, GeminiHttpRequest, GeminiHttpResponse,
    GeminiProviderStream, GeminiTransport,
};

use super::http::{KeyStyle, ProviderHttp, SseItem};
use super::rerank::transport;
use crate::config::models::ProviderConfig;

/// One Gemini provider's chat client.
pub(super) struct GeminiHttp {
    http: ProviderHttp,
}

/// One `.send()` per call over [`ProviderHttp`], which follows no redirect
/// and never resends: a run's gate may wrap this transport's adapter.
impl oneiron::llm::SingleSend for GeminiHttp {}

impl GeminiTransport for GeminiHttp {
    fn execute<'a>(
        &'a self,
        request: GeminiHttpRequest,
        _lease: &'a BudgetLease,
    ) -> GeminiFuture<'a> {
        Box::pin(async move {
            let reply = self
                .http
                .post_json(&request.path, &BTreeMap::new(), &request.body)
                .await
                .map_err(transport)?;
            Ok(GeminiHttpResponse {
                status: reply.status,
                body: reply.body,
            })
        })
    }

    fn stream<'a>(
        &'a self,
        request: GeminiHttpRequest,
        _lease: &'a BudgetLease,
    ) -> LlmResult<GeminiProviderStream<'a>> {
        let events = self.http.post_sse(&request.path, &BTreeMap::new(), &request.body);
        let frames = events.map(|item| -> LlmResult<GeminiFrame> {
            match item.map_err(transport)? {
                SseItem::Status(reply) => Ok(GeminiFrame::Status(GeminiHttpResponse {
                    status: reply.status,
                    body: reply.body,
                })),
                SseItem::Event(event) => serde_json::from_str(&event.data)
                    .map(GeminiFrame::Chunk)
                    .map_err(|_| FatalLlmError::EmptyResponse.into()),
            }
        });
        Ok(Box::pin(frames))
    }
}

/// The chat backend of `provider` over the models its chat rungs name,
/// `catalog`. `None` when no chat rung names it, or its key is a
/// `key_secret` one.
pub(super) fn chat_backend(
    provider: &ProviderConfig,
    catalog: Vec<LlmCatalogEntry>,
) -> anyhow::Result<Option<Arc<dyn SingleRouteBackend>>> {
    if catalog.is_empty() || provider.key_secret.is_some() {
        return Ok(None);
    }
    // The adapter owns the versioned paths: the base is the API's origin.
    let mut provider = provider.clone();
    provider.base_url = provider
        .base_url
        .strip_suffix("/v1beta")
        .unwrap_or(&provider.base_url)
        .to_owned();
    let http = ProviderHttp::new(&provider, KeyStyle::Named("x-goog-api-key"))?;
    Ok(Some(Arc::new(GeminiBackend::from_catalog(
        catalog,
        GeminiHttp { http },
    ))))
}
