//! API documents as connector tools (L8-31, canon agent-runtime
//! `#translator-inputs`: "The generic translator also takes OpenAPI and
//! Google Discovery documents").
//!
//! A document is a second way to list a connector's tools: each operation
//! becomes the same [`ListedTool`] an MCP `tools/list` entry does, and from
//! there the built admission takes over unchanged (screening, resolve, the
//! slate, the owner's stamp, consent and the scoped grant check). What MCP
//! learns from the wire, a translated tool carries in its
//! [`HttpOperation`]: where its call goes under the installed endpoint.
//!
//! [`ListedTool`]: crate::connector_admission_host::ListedTool

mod openapi;

use oneiron::connector_key::HttpOperation;
use reqwest::Url;
use serde_json::Value;

pub(crate) use openapi::BODY_ARGUMENT;

/// The largest document the host reads, from a file or a fetch.
pub(crate) const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

/// One operation as a tool, before admission.
#[derive(Debug, Clone)]
pub(crate) struct TranslatedTool {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) input_schema: Value,
    /// The reply's schema, when the document declares an object one.
    pub(crate) output_schema: Option<Value>,
    pub(crate) read_only: bool,
    pub(crate) destructive: bool,
    /// A retry after an ambiguous reply sends no second effect.
    pub(crate) idempotent: bool,
    pub(crate) http: HttpOperation,
}

#[derive(Debug, Default)]
pub(crate) struct Translation {
    /// The document's format and version, as the connector key pins it in
    /// place of an MCP protocol revision: `openapi-3.0` or `openapi-3.1`.
    pub(crate) revision: String,
    pub(crate) tools: Vec<TranslatedTool>,
    /// What the document holds that became no tool, each with why. The
    /// register reply lists them.
    pub(crate) skipped: Vec<String>,
}

/// Translates `document` (JSON or YAML) for the connector installed at
/// `endpoint`. Every call of the result goes to `endpoint`.
pub(crate) fn translate(document: &[u8], endpoint: &str) -> oneiron::Result<Translation> {
    if document.len() > MAX_DOCUMENT_BYTES {
        return Err(refused(format!(
            "the API document is over {} MiB",
            MAX_DOCUMENT_BYTES / (1024 * 1024)
        )));
    }
    let endpoint = Url::parse(endpoint)
        .map_err(|_| refused("the installed endpoint is not a URL".to_owned()))?;
    let document: Value = match serde_json::from_slice(document) {
        Ok(document) => document,
        Err(_) => serde_yaml_ng::from_slice(document)
            .map_err(|_| refused("the API document is neither JSON nor YAML".to_owned()))?,
    };
    if document.get("openapi").is_some() {
        return openapi::translate(&document, &endpoint);
    }
    Err(refused(
        "the API document is not an OpenAPI 3.0 or 3.1 document (no `openapi` key)".to_owned(),
    ))
}

fn refused(reason: String) -> oneiron::Error {
    oneiron::Error::InvalidConfig(reason)
}
