//! The media query both retrieval doors take (OF-370): `POST /v1/core/context-pack` (and the
//! Context Board's retrieval) and `POST /v1/core/query`. Each decodes its `media` field here
//! before anything is paid for, then embeds it here into its declared space through the
//! `ai.embed` rung that space's id names. On the one-space preset (the text kind slot bound
//! to a declared space) a door's text query is embedded the same way, through that space's
//! text tower, so text searches the space instead of the vault's own index. `POST
//! /api/search/semantic` embeds its `text` the same way.

use super::super::core_engine_error;
use crate::error::{ApiError, ApiErrorDetails};
use crate::server::{MediaEmbedRefusal, SyncServer};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use oneiron::embed::InputKind;
use serde::Deserialize;
use utoipa::ToSchema;

/// A retrieval request's media query (OF-370): bytes the server embeds into one
/// declared space through the `ai.embed` rung that space's id names.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "space": "local/clip-vit-b32@2024-01@own-server",
    "mime": "image/png",
    "bytes_b64": "iVBORw0KGgo="
}))]
pub(crate) struct ContextPackMediaQuery {
    /// Declared embedding space id: an `ai.embed` rung id from
    /// `GET /v1/ai/options`, then `@where`.
    #[schema(example = "local/clip-vit-b32@2024-01@own-server")]
    space: String,
    /// Media type of the bytes; it picks the space's query tower: `image/*`,
    /// `audio/*`, or `text/*` (UTF-8).
    #[schema(example = "image/png")]
    mime: String,
    /// The bytes, standard base64, at most `[limits].retrieval_query_bytes`
    /// as sent.
    #[serde(alias = "bytesB64")]
    #[schema(example = "iVBORw0KGgo=")]
    bytes_b64: String,
    /// The kinds of item the space's list keeps (`text`, `image`, `audio`);
    /// every kind the space holds when empty.
    #[serde(default)]
    #[schema(value_type = Vec<String>, example = json!(["image"]))]
    kinds: Vec<InputKind>,
}

/// A media query as a door embeds it: its space, the tower its MIME picks,
/// and its decoded bytes.
pub(crate) struct DecodedMediaQuery {
    space: String,
    kind: InputKind,
    mime: String,
    bytes: Vec<u8>,
    kinds: Vec<InputKind>,
}

/// One more ranked list a door adds: a declared space, the tower that
/// encoded the vector, and the vector.
pub(crate) struct MediaSeed {
    pub(crate) space: String,
    pub(crate) kind: InputKind,
    pub(crate) vector: Vec<f32>,
    /// The kinds of item the list keeps; every kind when empty.
    pub(crate) kinds: Vec<InputKind>,
}

/// The engine's wire twin of this query (the native context pack's and
/// `vault.recall`'s `media`), decoded and embedded by the same rules.
impl From<oneiron::code_run::vault_read::ContextPackMediaQuery> for ContextPackMediaQuery {
    fn from(media: oneiron::code_run::vault_read::ContextPackMediaQuery) -> Self {
        Self {
            space: media.space,
            mime: media.mime,
            bytes_b64: media.bytes_b64,
            kinds: media.kinds.into_iter().map(InputKind::from).collect(),
        }
    }
}

impl ContextPackMediaQuery {
    /// Decodes the query, refusing base64 past `max_bytes` before decoding it.
    pub(crate) fn decode(&self, max_bytes: usize) -> Result<DecodedMediaQuery, ApiError> {
        if self.space.trim().is_empty() {
            return Err(ApiError::bad_request(
                "media.space names a declared embedding space",
                Some("media.space"),
            ));
        }
        let mime = self.mime.trim().to_ascii_lowercase();
        let Some(kind) = InputKind::for_media_type(&mime)
            .or_else(|| mime.starts_with("text/").then_some(InputKind::Text))
        else {
            return Err(ApiError::bad_request(
                "media.mime is image/*, audio/* or text/*",
                Some("media.mime"),
            ));
        };
        if self.bytes_b64.len() > max_bytes {
            return Err(ApiError::bad_request(
                format!(
                    "media.bytes_b64 is {} bytes, past the {max_bytes} byte [limits].retrieval_query_bytes bound",
                    self.bytes_b64.len()
                ),
                Some("media.bytes_b64"),
            ));
        }
        let Some(bytes) = STANDARD
            .decode(&self.bytes_b64)
            .ok()
            .filter(|bytes| !bytes.is_empty())
        else {
            return Err(ApiError::bad_request(
                "media.bytes_b64 is nonempty standard base64",
                Some("media.bytes_b64"),
            ));
        };
        Ok(DecodedMediaQuery {
            space: self.space.clone(),
            kind,
            mime,
            bytes,
            kinds: self.kinds.clone(),
        })
    }
}

/// The request field a refusal names: the caller's `media`, or the text
/// query the one-space preset embeds (`text` on semantic search).
#[derive(Clone, Copy)]
enum SeedSource {
    Media,
    TextSlot,
    SemanticText,
}

impl SeedSource {
    fn space_field(self) -> &'static str {
        match self {
            Self::Media => "media.space",
            Self::TextSlot => "query",
            Self::SemanticText => "text",
        }
    }

    fn mime_field(self) -> &'static str {
        match self {
            Self::Media => "media.mime",
            Self::TextSlot => "query",
            Self::SemanticText => "text",
        }
    }
}

/// The media lists a door adds, embedded once every free check has passed:
/// the request's own `media`, and, when the vault's text kind slot binds a
/// declared space (the one-space preset), its text query through that
/// space's text tower. A `media` that is already a text query into that
/// space stands for it.
pub(crate) async fn embed_media_seeds(
    server: &SyncServer,
    media: Option<DecodedMediaQuery>,
    text_query: Option<&str>,
) -> Result<Vec<MediaSeed>, ApiError> {
    let text_space = match text_query {
        Some(_) => {
            server
                .vault
                .kind_slot_bindings()
                .map_err(|error| core_engine_error("kind slot bindings read failed", error))?
                .text
        }
        None => None,
    };
    let mut seeds = Vec::new();
    if let Some(media) = media {
        let mut seed = embed_seed(
            server,
            media.space,
            media.kind,
            &media.mime,
            media.bytes,
            SeedSource::Media,
        )
        .await?;
        seed.kinds = media.kinds;
        seeds.push(seed);
    }
    if let (Some(space), Some(query)) = (text_space, text_query)
        && !seeds
            .iter()
            .any(|seed| seed.space == space && seed.kind == InputKind::Text)
    {
        seeds.push(
            embed_seed(
                server,
                space,
                InputKind::Text,
                "text/plain",
                query.as_bytes().to_vec(),
                SeedSource::TextSlot,
            )
            .await?,
        );
    }
    Ok(seeds)
}

/// Semantic search's `text` on the one-space preset: the query through the
/// text tower of declared space `space`, which the text kind slot binds.
pub(crate) async fn embed_semantic_text(
    server: &SyncServer,
    space: String,
    text: &str,
) -> Result<Vec<f32>, ApiError> {
    let seed = embed_seed(
        server,
        space,
        InputKind::Text,
        "text/plain",
        text.as_bytes().to_vec(),
        SeedSource::SemanticText,
    )
    .await?;
    Ok(seed.vector)
}

/// Embeds one query into declared space `space` through the `ai.embed` rung
/// that space's id names.
async fn embed_seed(
    server: &SyncServer,
    space: String,
    kind: InputKind,
    mime: &str,
    bytes: Vec<u8>,
    source: SeedSource,
) -> Result<MediaSeed, ApiError> {
    let embedder = server
        .media_embedder(&space)
        .map_err(|refusal| media_query_refusal(refusal, source))?;
    let vector = embedder
        .embed_query(kind, mime, bytes)
        .await
        .map_err(|refusal| media_query_refusal(refusal, source))?;
    Ok(MediaSeed {
        space,
        kind,
        vector,
        kinds: Vec::new(),
    })
}

/// A media query's refusal as a door answers it: a caller's own mistake is
/// a 400, a policy refusal a 403, a seat that cannot serve the space a 503.
fn media_query_refusal(refusal: MediaEmbedRefusal, source: SeedSource) -> ApiError {
    match refusal {
        MediaEmbedRefusal::Undeclared(_) => {
            ApiError::bad_request(refusal.to_string(), Some(source.space_field()))
        }
        MediaEmbedRefusal::NoTower { .. } | MediaEmbedRefusal::NotText => {
            ApiError::bad_request(refusal.to_string(), Some(source.mime_field()))
        }
        MediaEmbedRefusal::Denied(_) => ApiError::new(
            refusal.to_string(),
            ApiErrorDetails::Forbidden {
                required_scope: None,
            },
            [
                "The vault's inference policy decides which models are called; admit this rung there.",
            ],
        ),
        MediaEmbedRefusal::Vault(error) => core_engine_error("media query failed", error),
        other => ApiError::new(
            other.to_string(),
            ApiErrorDetails::EmbedderUnavailable,
            [match source {
                SeedSource::Media => {
                    "Serve the rung the space's id names under [models.media.embed], or retry without media."
                }
                SeedSource::TextSlot | SeedSource::SemanticText => {
                    "The text slot binds this space (the one-space preset): serve the rung its id names under [models.media.embed], or unbind the text slot."
                }
            }],
        ),
    }
}
