//! The Gemini API's media leg: one request per call over [`ProviderHttp`],
//! the key in `x-goog-api-key`. The adapter (`oneiron-llm-gemini`) owns the
//! versioned paths, so the provider's `base_url` is the API's origin; a base
//! written with its `/v1beta` drops it.
use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::llm::media::MediaBackend;
use oneiron::{BudgetLease, LlmError, ModelId};
use oneiron_llm_gemini::{
    GeminiMediaBackend, GeminiMediaFuture, GeminiMediaHttpRequest, GeminiMediaHttpResponse,
    GeminiMediaTransport,
};

use super::http::{KeyStyle, MediaSend, ProviderHttp};
use super::rerank::transport;
use crate::config::models::ProviderConfig;

struct GeminiMediaHttp {
    http: ProviderHttp,
}

impl GeminiMediaTransport for GeminiMediaHttp {
    fn execute<'a>(
        &'a self,
        request: GeminiMediaHttpRequest,
        _lease: &'a BudgetLease,
    ) -> GeminiMediaFuture<'a> {
        Box::pin(async move {
            let reply = match request {
                GeminiMediaHttpRequest::Post { path, body } => {
                    self.http.send_media(&path, MediaSend::Json(body)).await
                }
                GeminiMediaHttpRequest::Get { path } => {
                    self.http.send_media(&path, MediaSend::Get).await
                }
                GeminiMediaHttpRequest::Fetch { uri } => self.http.fetch_media(&uri).await,
            }
            .map_err(transport)?;
            Ok::<_, LlmError>(GeminiMediaHttpResponse {
                status: reply.status,
                headers: reply.headers,
                body: reply.body,
            })
        })
    }
}

/// The media client of a Gemini `provider`, serving `wire_models`.
pub(super) fn gemini_backend(
    provider: &ProviderConfig,
    wire_models: BTreeMap<ModelId, String>,
) -> anyhow::Result<Arc<dyn MediaBackend>> {
    let mut provider = provider.clone();
    provider.base_url = provider
        .base_url
        .strip_suffix("/v1beta")
        .unwrap_or(&provider.base_url)
        .to_owned();
    let http = ProviderHttp::new(&provider, KeyStyle::Named("x-goog-api-key"))?;
    Ok(Arc::new(GeminiMediaBackend::new(
        GeminiMediaHttp { http },
        wire_models,
    )))
}
