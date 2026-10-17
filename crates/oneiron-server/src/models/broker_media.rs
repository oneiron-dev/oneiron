//! A `key_secret` provider's media leg (OF-131): each exchange a media
//! adapter makes is one credential-broker call, as a chat call is
//! ([`super::broker`]). The exact request is built and checked as the broker
//! will check it before anything connects. Only then does the call connect,
//! read the key at the custody door and hand the broker the key with that
//! one request. The broker's shape for the exchange adds the auth: Bearer
//! for the OpenAI-compatible paths, `x-goog-api-key` for the Gemini API's.
//!
//! JSON and form bodies are capped at the broker's 16 MiB. A speech, clip or
//! file reply streams back in 1 MiB frames, checked for the key and never
//! rewritten, up to 512 MiB, and must finish within the provider's
//! `timeout_secs`.
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use oneiron::llm::media::MediaBackend;
use oneiron::{BudgetLease, FatalLlmError, LlmError, LlmResult, ModelId};
use oneiron_broker::{BrokerClient, CallHeader, FormData, Shape};
use oneiron_llm_gemini::{
    GeminiMediaBackend, GeminiMediaFuture, GeminiMediaHttpRequest, GeminiMediaHttpResponse,
    GeminiMediaTransport,
};
use oneiron_llm_openai::{
    OpenAiMediaBackend, OpenAiMediaBody, OpenAiMediaHttpRequest, OpenAiMediaHttpResponse,
    OpenAiMediaMethod, OpenAiMediaTransport, OpenAiMediaTransportFuture,
};

use super::broker::{BrokerSite, KeyDoor, REPLY_MARGIN, answered, call_with_key, join};
use crate::config::models::{ProviderConfig, ProviderKind};

const JSON: &str = "application/json";

/// One `key_secret` provider's media exchanges over the broker.
struct BrokerMedia {
    /// The provider's `https://host[:port]`.
    origin: String,
    /// The base URL's path under the origin, with no trailing `/`.
    prefix: String,
    /// The provider's extra headers, names lowercase.
    headers: BTreeMap<String, String>,
    /// The wire model a job's poll, clip or removal stands under: it names
    /// none on the wire, so the provider's name does.
    binding: String,
    secret: String,
    client: BrokerClient,
    keys: Arc<dyn KeyDoor>,
}

/// One exchange as the broker checks it: its shape, its path under the
/// origin, its content type and its exact body.
struct Exchange {
    shape: Shape,
    path: String,
    content_type: Option<String>,
    body: Vec<u8>,
}

/// The media client of `key_secret` provider `name`, serving `wire_models`
/// over the broker at `site`, its key read at `keys`.
pub(super) fn broker_media_backend(
    name: &str,
    provider: &ProviderConfig,
    wire_models: BTreeMap<ModelId, String>,
    site: Option<&Result<BrokerSite, String>>,
    keys: Option<&Arc<dyn KeyDoor>>,
) -> anyhow::Result<Arc<dyn MediaBackend>> {
    let site = site
        .ok_or_else(|| anyhow::anyhow!("no credential broker was made"))?
        .as_ref()
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    match provider.kind {
        // The adapter owns the versioned paths: the base is the API's origin.
        ProviderKind::Gemini => {
            let base = provider
                .base_url
                .strip_suffix("/v1beta")
                .unwrap_or(&provider.base_url);
            Ok(Arc::new(GeminiMediaBackend::new(
                BrokerMedia::new(name, provider, base, site, keys)?,
                wire_models,
            )))
        }
        ProviderKind::OpenaiCompat | ProviderKind::LocalOpenaiCompat => {
            Ok(Arc::new(OpenAiMediaBackend::new(
                BrokerMedia::new(name, provider, &provider.base_url, site, keys)?,
                wire_models,
            )))
        }
        kind => anyhow::bail!(
            "a {kind:?} provider's media calls do not go through the credential broker"
        ),
    }
}

impl BrokerMedia {
    fn new(
        name: &str,
        provider: &ProviderConfig,
        base_url: &str,
        site: &BrokerSite,
        keys: Option<&Arc<dyn KeyDoor>>,
    ) -> anyhow::Result<Self> {
        let secret = provider
            .key_secret
            .clone()
            .ok_or_else(|| anyhow::anyhow!("the provider names no key_secret"))?;
        let keys = keys
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("this server has no vault custody door"))?;
        let client = site.client(Duration::from_secs(provider.timeout_secs) + REPLY_MARGIN)?;
        let url = reqwest::Url::parse(base_url)?;
        Ok(Self {
            origin: url.origin().ascii_serialization(),
            prefix: url.path().trim_end_matches('/').to_owned(),
            headers: provider
                .headers
                .iter()
                .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
                .collect(),
            binding: name.to_owned(),
            secret,
            client,
            keys,
        })
    }

    /// Sends `exchange` as the call `lease` admitted: checked as the broker
    /// will check it, then the key read at the door and the one call. The
    /// provider's status, its headers (names lowercase) and the reply body.
    async fn send(
        &self,
        exchange: Exchange,
        lease: &BudgetLease,
    ) -> LlmResult<(u16, BTreeMap<String, String>, Vec<u8>)> {
        let Exchange {
            shape,
            path,
            content_type,
            body,
        } = exchange;
        let mut headers = self.headers.clone();
        if let Some(kind) = content_type {
            headers.insert("content-type".to_owned(), kind);
        }
        let headers: Vec<(String, String)> = headers.into_iter().collect();
        let wire_model = shape
            .read_model(&path, &headers, &body)
            .map_err(|_| invalid())?
            .unwrap_or_else(|| self.binding.clone());
        let header = CallHeader::new(
            lease.id().to_owned(),
            shape,
            self.origin.clone(),
            path,
            headers,
            wire_model,
            &body,
        );
        header.check(&body).map_err(|_| invalid())?;
        let mut reply =
            call_with_key(&self.client, &self.keys, &self.secret, &header, &body).await?;
        let (status, headers) = answered(reply.outcome)?;
        let body = std::mem::take(&mut *reply.body);
        Ok((
            status,
            headers
                .into_iter()
                .map(|(name, value)| (name.to_ascii_lowercase(), value))
                .collect(),
            body,
        ))
    }

    /// An OpenAI-compatible media request as its broker shape takes it.
    fn openai(&self, request: OpenAiMediaHttpRequest) -> LlmResult<Exchange> {
        let OpenAiMediaHttpRequest { method, path, body } = request;
        let segments: Vec<&str> = path
            .strip_prefix("/v1/")
            .ok_or_else(invalid)?
            .split('/')
            .collect();
        let shape = match (method, segments.as_slice(), &body) {
            (OpenAiMediaMethod::Post, ["images", "generations"], OpenAiMediaBody::Json(_)) => {
                Shape::OpenAiImages
            }
            (OpenAiMediaMethod::Post, ["images", "edits"], OpenAiMediaBody::Multipart { .. }) => {
                Shape::OpenAiImageEdits
            }
            (OpenAiMediaMethod::Post, ["audio", "speech"], OpenAiMediaBody::Json(_)) => {
                Shape::OpenAiSpeech
            }
            (
                OpenAiMediaMethod::Post,
                ["audio", "transcriptions"],
                OpenAiMediaBody::Multipart { .. },
            ) => Shape::OpenAiTranscriptions,
            (OpenAiMediaMethod::Post, ["embeddings"], OpenAiMediaBody::Json(_)) => {
                Shape::OpenAiEmbeddings
            }
            (
                OpenAiMediaMethod::Post,
                ["videos"],
                OpenAiMediaBody::Json(_) | OpenAiMediaBody::Multipart { .. },
            ) => Shape::OpenAiVideoStart,
            (OpenAiMediaMethod::Get, ["videos", _], OpenAiMediaBody::Empty) => {
                Shape::OpenAiVideoPoll
            }
            (OpenAiMediaMethod::Get, ["videos", _, "content"], OpenAiMediaBody::Empty) => {
                Shape::OpenAiVideoContent
            }
            (OpenAiMediaMethod::Delete, ["videos", _], OpenAiMediaBody::Empty) => {
                Shape::OpenAiVideoDelete
            }
            _ => return Err(invalid()),
        };
        let (content_type, body) = match body {
            OpenAiMediaBody::Empty => (None, Vec::new()),
            OpenAiMediaBody::Json(value) => (Some(JSON.to_owned()), json_bytes(&value)?),
            OpenAiMediaBody::Multipart { fields, files } => {
                let mut form = FormData::new();
                for (name, value) in fields {
                    form = form.text(name, value);
                }
                for file in files {
                    form = form.file(file.name, file.filename, file.media_type, file.bytes);
                }
                let (kind, body) = form.finish();
                (Some(kind), body)
            }
        };
        Ok(Exchange {
            shape,
            path: join(&self.prefix, &path),
            content_type,
            body,
        })
    }

    /// A Gemini API media request as its broker shape takes it. A finished
    /// job's file goes to the provider's own origin only.
    fn gemini(&self, request: GeminiMediaHttpRequest) -> LlmResult<Exchange> {
        Ok(match request {
            GeminiMediaHttpRequest::Post { path, body } => Exchange {
                shape: if path.ends_with(":generateContent") {
                    Shape::GeminiGenerate
                } else if path.ends_with(":predictLongRunning") {
                    Shape::GeminiPredict
                } else {
                    return Err(invalid());
                },
                path: format!("{}{path}", self.prefix),
                content_type: Some(JSON.to_owned()),
                body: json_bytes(&body)?,
            },
            GeminiMediaHttpRequest::Get { path } => Exchange {
                shape: Shape::GeminiOperation,
                path: format!("{}{path}", self.prefix),
                content_type: None,
                body: Vec::new(),
            },
            GeminiMediaHttpRequest::Fetch { uri } => {
                let target = reqwest::Url::parse(&uri).map_err(|_| invalid())?;
                if target.origin().ascii_serialization() != self.origin {
                    return Err(invalid());
                }
                Exchange {
                    shape: Shape::GeminiFile,
                    path: match target.query() {
                        Some(query) => format!("{}?{query}", target.path()),
                        None => target.path().to_owned(),
                    },
                    content_type: None,
                    body: Vec::new(),
                }
            }
        })
    }
}

impl OpenAiMediaTransport for BrokerMedia {
    fn execute<'a>(
        &'a self,
        request: OpenAiMediaHttpRequest,
        lease: &'a BudgetLease,
    ) -> OpenAiMediaTransportFuture<'a> {
        Box::pin(async move {
            let (status, headers, body) = self.send(self.openai(request)?, lease).await?;
            Ok(OpenAiMediaHttpResponse {
                status,
                headers,
                body,
            })
        })
    }
}

impl GeminiMediaTransport for BrokerMedia {
    fn execute<'a>(
        &'a self,
        request: GeminiMediaHttpRequest,
        lease: &'a BudgetLease,
    ) -> GeminiMediaFuture<'a> {
        Box::pin(async move {
            let (status, headers, body) = self.send(self.gemini(request)?, lease).await?;
            Ok(GeminiMediaHttpResponse {
                status,
                headers,
                body,
            })
        })
    }
}

fn json_bytes(value: &serde_json::Value) -> LlmResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| invalid())
}

fn invalid() -> LlmError {
    FatalLlmError::InvalidRequest.into()
}
