//! Where one call of an HTTP API connector's tool goes (L8-31): the method,
//! the path under the installed endpoint, and which arguments fill the path,
//! the query and the body.
//!
//! A tool translated from an OpenAPI document carries one of these in its
//! slate row, beside its schemas, so the owner's stamp covers where each
//! tool sends, as it covers what it takes. The document is read at register
//! and refresh only; a call never reads it, and never sends anywhere but the
//! endpoint the host installed. Header arguments are not listed here: they
//! ride the input schema's `x-mcp-header` declarations, as an MCP tool's do,
//! so the header data class applies to them unchanged.

use serde::{Deserialize, Serialize};

/// The request methods a translated operation may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HttpOperation {
    pub method: HttpMethod,
    /// The path under the installed endpoint, with one `{name}` per path
    /// argument. Each argument fills its place as one percent-encoded
    /// segment, so no value can change the path around it.
    pub path: String,
    /// The arguments sent as query parameters, in the document's order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub query: Vec<String>,
    /// The header the call's intent key fills (`Idempotency-Key`), when the
    /// operation declares one: a recovery re-sends the same key, so the
    /// server sends the effect at most once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_header: Option<String>,
    /// The `body` argument is the JSON request body.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub json_body: bool,
}
