//! The shape rows: for each wire protocol the broker speaks, the method, the
//! path, the content type, where the model selector sits, where the key goes
//! and how the reply comes back. Canon puts these rows in packs
//! (`#door-reads-model`); they ship here as data until pack loading reaches
//! the broker.
//!
//! Each row is closed: one method, one endpoint pattern under any plain
//! prefix, one body form and one key header. Nothing a call carries can widen
//! it.

use std::fmt;

use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{Refusal, form};

/// A wire protocol the broker can send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Shape {
    /// OpenAI-compatible chat: `POST …/v1/chat/completions`, top-level body
    /// `model`, `Authorization: Bearer <key>`.
    OpenAiChat,
    /// Anthropic-compatible messages: `POST …/v1/messages`, top-level body
    /// `model`, `x-api-key: <key>`.
    AnthropicMessages,
    /// OpenAI-compatible image generation: `POST …/v1/images/generations`,
    /// JSON, top-level body `model`, Bearer.
    OpenAiImages,
    /// OpenAI-compatible image edits: `POST …/v1/images/edits`, a multipart
    /// form with one `model` field, Bearer.
    OpenAiImageEdits,
    /// OpenAI-compatible speech: `POST …/v1/audio/speech`, JSON, top-level
    /// body `model`, Bearer. The reply is audio bytes, streamed.
    OpenAiSpeech,
    /// OpenAI-compatible transcription: `POST …/v1/audio/transcriptions`, a
    /// multipart form with one `model` field, Bearer.
    OpenAiTranscriptions,
    /// OpenAI-compatible embeddings: `POST …/v1/embeddings`, JSON, top-level
    /// body `model`, Bearer.
    OpenAiEmbeddings,
    /// An OpenAI-compatible video job's start: `POST …/v1/videos`, JSON or a
    /// multipart form (with a reference image), with one `model`, Bearer.
    OpenAiVideoStart,
    /// A video job's state: `GET …/v1/videos/{id}`, no body, Bearer.
    OpenAiVideoPoll,
    /// A finished video's bytes: `GET …/v1/videos/{id}/content`, no body,
    /// Bearer. The reply is streamed.
    OpenAiVideoContent,
    /// A video job's removal: `DELETE …/v1/videos/{id}`, no body, Bearer.
    OpenAiVideoDelete,
    /// Gemini generation: `POST …/v1beta/models/{model}:generateContent`,
    /// JSON, the model in the path, `x-goog-api-key: <key>`.
    GeminiGenerate,
    /// A Gemini long job's start:
    /// `POST …/v1beta/models/{model}:predictLongRunning`, JSON, the model in
    /// the path, `x-goog-api-key`.
    GeminiPredict,
    /// A Gemini long job's state:
    /// `GET …/v1beta/models/{model}/operations/{id}`, no body, the model in
    /// the path, `x-goog-api-key`.
    GeminiOperation,
    /// A file a Gemini job made:
    /// `GET …/v1beta/files/{id}:download?alt=media`, no body,
    /// `x-goog-api-key`. The provider answers with one redirect to its
    /// download path under the same origin, which is followed once, without
    /// the key. The reply is streamed.
    GeminiFile,
}

struct Row {
    method: &'static str,
    /// The endpoint's last path segments. Inside one, `{model}` stands for
    /// the wire model and `{id}` for a provider's id, each before a literal
    /// tail.
    endpoint: &'static [&'static str],
    /// The one query the path ends in, for an endpoint that takes one.
    query: Option<&'static str>,
    body: Body,
    model: Selector,
    auth_header: &'static str,
    auth_prefix: &'static str,
    /// Whether the reply streams back in chunks, checked for the key and
    /// never changed, instead of being buffered and stripped.
    streams: bool,
    /// The one redirect the shape follows: to this prefix before the call's
    /// own path and query, under the same origin, without the key.
    redirect: Option<&'static str>,
}

/// What the body is, and the content type that says so.
#[derive(Clone, Copy)]
enum Body {
    /// One JSON object, `application/json`.
    Json,
    /// One multipart form, `multipart/form-data` with its boundary.
    Form,
    /// Either of those.
    JsonOrForm,
    /// Nothing, and no content type.
    Empty,
}

/// Where the request names its model.
#[derive(Clone, Copy)]
enum Selector {
    /// The body's `model`: its top-level key, or its form field.
    Body,
    /// The path's `{model}` segment. The body names none.
    Path,
    /// Nowhere on the wire: the request reads or removes a job or a file and
    /// carries nothing that could pick a model, so the call's bound wire
    /// model stands.
    Binding,
}

const JSON: &str = "application/json";

const fn openai(
    method: &'static str,
    endpoint: &'static [&'static str],
    body: Body,
    model: Selector,
    streams: bool,
) -> Row {
    Row {
        method,
        endpoint,
        query: None,
        body,
        model,
        auth_header: "authorization",
        auth_prefix: "Bearer ",
        streams,
        redirect: None,
    }
}

const fn gemini(
    method: &'static str,
    endpoint: &'static [&'static str],
    body: Body,
    model: Selector,
) -> Row {
    Row {
        method,
        endpoint,
        query: None,
        body,
        model,
        auth_header: "x-goog-api-key",
        auth_prefix: "",
        streams: false,
        redirect: None,
    }
}

const OPENAI_CHAT: Row = openai(
    "POST",
    &["v1", "chat", "completions"],
    Body::Json,
    Selector::Body,
    false,
);

const ANTHROPIC_MESSAGES: Row = Row {
    method: "POST",
    endpoint: &["v1", "messages"],
    query: None,
    body: Body::Json,
    model: Selector::Body,
    auth_header: "x-api-key",
    auth_prefix: "",
    streams: false,
    redirect: None,
};

const OPENAI_IMAGES: Row = openai(
    "POST",
    &["v1", "images", "generations"],
    Body::Json,
    Selector::Body,
    false,
);

const OPENAI_IMAGE_EDITS: Row = openai(
    "POST",
    &["v1", "images", "edits"],
    Body::Form,
    Selector::Body,
    false,
);

const OPENAI_SPEECH: Row = openai(
    "POST",
    &["v1", "audio", "speech"],
    Body::Json,
    Selector::Body,
    true,
);

const OPENAI_TRANSCRIPTIONS: Row = openai(
    "POST",
    &["v1", "audio", "transcriptions"],
    Body::Form,
    Selector::Body,
    false,
);

const OPENAI_EMBEDDINGS: Row = openai(
    "POST",
    &["v1", "embeddings"],
    Body::Json,
    Selector::Body,
    false,
);

const OPENAI_VIDEO_START: Row = openai(
    "POST",
    &["v1", "videos"],
    Body::JsonOrForm,
    Selector::Body,
    false,
);

const OPENAI_VIDEO_POLL: Row = openai(
    "GET",
    &["v1", "videos", "{id}"],
    Body::Empty,
    Selector::Binding,
    false,
);

const OPENAI_VIDEO_CONTENT: Row = openai(
    "GET",
    &["v1", "videos", "{id}", "content"],
    Body::Empty,
    Selector::Binding,
    true,
);

const OPENAI_VIDEO_DELETE: Row = openai(
    "DELETE",
    &["v1", "videos", "{id}"],
    Body::Empty,
    Selector::Binding,
    false,
);

const GEMINI_GENERATE: Row = gemini(
    "POST",
    &["v1beta", "models", "{model}:generateContent"],
    Body::Json,
    Selector::Path,
);

const GEMINI_PREDICT: Row = gemini(
    "POST",
    &["v1beta", "models", "{model}:predictLongRunning"],
    Body::Json,
    Selector::Path,
);

const GEMINI_OPERATION: Row = gemini(
    "GET",
    &["v1beta", "models", "{model}", "operations", "{id}"],
    Body::Empty,
    Selector::Path,
);

const GEMINI_FILE: Row = Row {
    query: Some("alt=media"),
    streams: true,
    redirect: Some("/download"),
    ..gemini(
        "GET",
        &["v1beta", "files", "{id}:download"],
        Body::Empty,
        Selector::Binding,
    )
};

/// Top-level body keys, or form fields, that pick the model or the route by
/// another way than the one selector: a fallback list, a route or a provider
/// preference.
pub(crate) const ROUTE_OVERRIDES: [&str; 3] = ["models", "route", "provider"];

/// The longest model name or provider id a path segment may hold.
const MAX_NAME: usize = 256;

impl Shape {
    const fn row(self) -> &'static Row {
        match self {
            Self::OpenAiChat => &OPENAI_CHAT,
            Self::AnthropicMessages => &ANTHROPIC_MESSAGES,
            Self::OpenAiImages => &OPENAI_IMAGES,
            Self::OpenAiImageEdits => &OPENAI_IMAGE_EDITS,
            Self::OpenAiSpeech => &OPENAI_SPEECH,
            Self::OpenAiTranscriptions => &OPENAI_TRANSCRIPTIONS,
            Self::OpenAiEmbeddings => &OPENAI_EMBEDDINGS,
            Self::OpenAiVideoStart => &OPENAI_VIDEO_START,
            Self::OpenAiVideoPoll => &OPENAI_VIDEO_POLL,
            Self::OpenAiVideoContent => &OPENAI_VIDEO_CONTENT,
            Self::OpenAiVideoDelete => &OPENAI_VIDEO_DELETE,
            Self::GeminiGenerate => &GEMINI_GENERATE,
            Self::GeminiPredict => &GEMINI_PREDICT,
            Self::GeminiOperation => &GEMINI_OPERATION,
            Self::GeminiFile => &GEMINI_FILE,
        }
    }

    /// The one method this shape sends.
    #[must_use]
    pub const fn method(self) -> &'static str {
        self.row().method
    }

    /// The header the key goes into, lowercase.
    #[must_use]
    pub const fn auth_header(self) -> &'static str {
        self.row().auth_header
    }

    /// What goes before the key in that header.
    #[must_use]
    pub const fn auth_prefix(self) -> &'static str {
        self.row().auth_prefix
    }

    /// Whether the reply streams back in chunks, up to [`crate::MAX_STREAM`]
    /// bytes, instead of one buffered body up to [`crate::MAX_BODY`]. A
    /// streamed body is a binary one: it is checked for the key and passed
    /// unchanged, or cut, never stripped.
    #[must_use]
    pub const fn streams(self) -> bool {
        self.row().streams
    }

    /// The path prefix of the one redirect this shape follows, under the same
    /// origin and without the key.
    pub(crate) const fn redirect(self) -> Option<&'static str> {
        self.row().redirect
    }

    /// Accepts a path that ends in the shape's endpoint, in plain form: it
    /// starts with `/`, and has no fragment, percent escape, empty segment or
    /// dot segment, and no query but the endpoint's own, so no parser between
    /// here and the provider can read it as another path.
    pub fn check_path(self, path: &str) -> Result<(), Refusal> {
        self.match_path(path).map(drop)
    }

    /// Matches `path` to the row and returns its model segment, for a row
    /// that has one.
    fn match_path(self, path: &str) -> Result<Option<&str>, Refusal> {
        let row = self.row();
        let path = match row.query {
            Some(query) => path
                .strip_suffix(query)
                .and_then(|path| path.strip_suffix('?')),
            None => Some(path),
        }
        .ok_or(Refusal::Path)?;
        let segments: Vec<&str> = path
            .strip_prefix('/')
            .ok_or(Refusal::Path)?
            .split('/')
            .collect();
        let split = segments
            .len()
            .checked_sub(row.endpoint.len())
            .ok_or(Refusal::Path)?;
        let (prefix, tail) = segments.split_at(split);
        let mut model = None;
        let plain = prefix.iter().all(|segment| plain_segment(segment))
            && tail
                .iter()
                .zip(row.endpoint)
                .all(|(&segment, template)| matches(template, segment, &mut model));
        if plain { Ok(model) } else { Err(Refusal::Path) }
    }

    /// Reads the model selector from the exact body bytes that will be sent,
    /// as the top-level `model` string of one JSON object. Keys are counted
    /// as they are read, because a plain JSON decode keeps only the last of
    /// two equal keys, and an escaped spelling of `model` counts as `model`.
    pub fn read_selector(self, body: &[u8]) -> Result<String, Refusal> {
        scan_json(body)?.ok_or(Refusal::SelectorMissing)
    }

    /// Checks the body against the row (its content type, and one JSON
    /// object, one plain multipart form, or nothing) and reads the model the
    /// request names: the body's `model`, or the path's model segment. A
    /// shape whose request names no model on the wire gives `None`, and the
    /// call's bound wire model stands for it. `headers` are the call's, names
    /// lowercase.
    pub fn read_model(
        self,
        path: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Option<String>, Refusal> {
        let row = self.row();
        let content_type = headers
            .iter()
            .find(|(name, _)| name == "content-type")
            .map(|(_, value)| value.as_str());
        let named = match (row.body, content_type) {
            (Body::Empty, None) if body.is_empty() => None,
            (Body::Json | Body::JsonOrForm, Some(JSON)) => scan_json(body)?,
            (Body::Form | Body::JsonOrForm, Some(kind)) => form::read_model(kind, body)?,
            _ => return Err(Refusal::Body),
        };
        match row.model {
            Selector::Body => named.map(Some).ok_or(Refusal::SelectorMissing),
            Selector::Path if named.is_some() => Err(Refusal::SelectorRepeated),
            Selector::Path => self
                .match_path(path)?
                .map(|model| Some(model.to_owned()))
                .ok_or(Refusal::Path),
            Selector::Binding => Ok(None),
        }
    }
}

/// A prefix segment in plain form: not empty, not a dot segment, and only
/// letters, digits and `-._~`.
fn plain_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
}

/// Matches one endpoint segment to its template: a literal, or `{model}` or
/// `{id}` before a literal tail. A model segment is kept in `model`.
fn matches<'p>(template: &str, segment: &'p str, model: &mut Option<&'p str>) -> bool {
    if let Some(tail) = template.strip_prefix("{model}") {
        let name = segment.strip_suffix(tail).filter(|name| plain_model(name));
        *model = name;
        name.is_some()
    } else if let Some(tail) = template.strip_prefix("{id}") {
        segment.strip_suffix(tail).is_some_and(plain_id)
    } else {
        segment == template
    }
}

/// A model name as a path segment holds it: letters, digits and `-._`, and
/// not a dot segment.
fn plain_model(name: &str) -> bool {
    (1..=MAX_NAME).contains(&name.len())
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte))
}

/// A provider's job, operation or file id: letters, digits, `_` and `-`.
fn plain_id(id: &str) -> bool {
    (1..=MAX_NAME).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
}

/// The top-level `model` string of one JSON object, or `None` when it has
/// none.
fn scan_json(body: &[u8]) -> Result<Option<String>, Refusal> {
    let mut decoder = serde_json::Deserializer::from_slice(body);
    let selector = decoder
        .deserialize_map(SelectorVisitor)
        .map_err(|_| Refusal::Body)??;
    decoder.end().map_err(|_| Refusal::Body)?;
    Ok(selector)
}

struct SelectorVisitor;

impl<'de> Visitor<'de> for SelectorVisitor {
    type Value = Result<Option<String>, Refusal>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut selector: Option<Result<String, Refusal>> = None;
        let mut refusal = None;
        while let Some(key) = map.next_key::<String>()? {
            if refusal.is_some() {
                map.next_value::<IgnoredAny>()?;
                continue;
            }
            if key == "model" {
                let value = map.next_value::<serde_json::Value>()?;
                if selector.is_some() {
                    refusal = Some(Refusal::SelectorRepeated);
                }
                selector = Some(match value {
                    serde_json::Value::String(model) => Ok(model),
                    _ => Err(Refusal::SelectorNotString),
                });
            } else if ROUTE_OVERRIDES.contains(&key.as_str()) {
                refusal = Some(Refusal::RouteOverride);
                map.next_value::<IgnoredAny>()?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(match (refusal, selector) {
            (Some(refusal), _) => Err(refusal),
            (None, None) => Ok(None),
            (None, Some(selector)) => selector.map(Some),
        })
    }
}

#[cfg(test)]
mod tests;
