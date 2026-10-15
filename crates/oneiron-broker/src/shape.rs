//! The shape rows: for each wire protocol the broker speaks, the method, the
//! path, where the model selector sits and where the key goes. Canon puts these
//! rows in packs (`#door-reads-model`); the first two ship here as data until
//! pack loading reaches the broker.

use std::fmt;

use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::Refusal;

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
}

struct Row {
    method: &'static str,
    path_suffix: &'static str,
    auth_header: &'static str,
    auth_prefix: &'static str,
}

const OPENAI_CHAT: Row = Row {
    method: "POST",
    path_suffix: "/v1/chat/completions",
    auth_header: "authorization",
    auth_prefix: "Bearer ",
};

const ANTHROPIC_MESSAGES: Row = Row {
    method: "POST",
    path_suffix: "/v1/messages",
    auth_header: "x-api-key",
    auth_prefix: "",
};

/// Top-level body keys that pick the model or the route by another way than
/// the one selector: a fallback list, a route or a provider preference.
const ROUTE_OVERRIDES: [&str; 3] = ["models", "route", "provider"];

impl Shape {
    const fn row(self) -> &'static Row {
        match self {
            Self::OpenAiChat => &OPENAI_CHAT,
            Self::AnthropicMessages => &ANTHROPIC_MESSAGES,
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

    /// Accepts a path that ends in the shape's endpoint, in plain form: it
    /// starts with `/`, and has no query, fragment, percent escape, empty
    /// segment or dot segment, so no parser between here and the provider can
    /// read it as another path.
    pub fn check_path(self, path: &str) -> Result<(), Refusal> {
        let plain = path.starts_with('/')
            && path.ends_with(self.row().path_suffix)
            && path
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._~/".contains(&byte))
            && path[1..]
                .split('/')
                .all(|segment| !segment.is_empty() && segment != "." && segment != "..");
        if plain { Ok(()) } else { Err(Refusal::Path) }
    }

    /// Reads the model selector from the exact body bytes that will be sent.
    /// Both shapes put it in the top-level `model` string. Keys are counted as
    /// they are read, because a plain JSON decode keeps only the last of two
    /// equal keys, and an escaped spelling of `model` counts as `model`.
    pub fn read_selector(self, body: &[u8]) -> Result<String, Refusal> {
        let mut decoder = serde_json::Deserializer::from_slice(body);
        let selector = decoder
            .deserialize_map(SelectorVisitor)
            .map_err(|_| Refusal::Body)??;
        decoder.end().map_err(|_| Refusal::Body)?;
        Ok(selector)
    }
}

struct SelectorVisitor;

impl<'de> Visitor<'de> for SelectorVisitor {
    type Value = Result<String, Refusal>;

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
            (None, None) => Err(Refusal::SelectorMissing),
            (None, Some(selector)) => selector,
        })
    }
}

#[cfg(test)]
mod tests;
