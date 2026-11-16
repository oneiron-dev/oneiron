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

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The most compiled size of one reserved place's pattern, as the call
/// validator bounds an input schema's (outbound_consent/tool_schema.rs).
const PATTERN_SIZE_LIMIT: usize = 1 << 20;

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
    /// segment, so no value can change the path around it. A `{+name}`
    /// place (Google Discovery's reserved expansion) takes a value with `/`
    /// in it, each part one segment, and only a value its
    /// [`reserved_patterns`](Self::reserved_patterns) entry matches whole.
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
    /// The pattern each `{+name}` place's value must match whole, by the
    /// place's argument name: the document's own `pattern` for that
    /// parameter (`^notes/[^/]+/comments/[^/]+$`). A reserved value holds
    /// `/`, so without it a tool stamped for one kind of resource would
    /// reach every resource under the endpoint's path (REVIEW2 #7981
    /// P1-1). The call host refuses a value it does not match before the
    /// URL is built, and a place with no pattern that compiles is no tool.
    /// It is in the stamped row, so a changed pattern drifts the slate.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub reserved_patterns: BTreeMap<String, String>,
}

impl HttpOperation {
    /// Whether `value` may fill the `{+name}` place `name`: its stamped
    /// pattern matches the whole value. A place with no stamped pattern
    /// takes nothing.
    pub fn check_reserved_value(&self, name: &str, value: &str) -> Result<(), String> {
        let pattern = self
            .reserved_patterns
            .get(name)
            .ok_or_else(|| format!("the stamped operation has no pattern for {{+{name}}}"))?;
        if compile_reserved_pattern(pattern)?.is_match(value) {
            Ok(())
        } else {
            Err(format!(
                "path argument {name} is {value:?}, which its pattern {pattern:?} does not match"
            ))
        }
    }
}

/// `pattern` as a reserved place's value is matched: anchored at both ends,
/// so it matches the whole value or nothing. An error when it does not
/// compile here. The pattern compiles by itself first, so it is one whole
/// expression and cannot close the anchoring group (`a)|(.*`).
pub fn compile_reserved_pattern(pattern: &str) -> Result<regex::Regex, String> {
    let compile = |expression: &str| {
        regex::RegexBuilder::new(expression)
            .size_limit(PATTERN_SIZE_LIMIT)
            .build()
            .map_err(|_| format!("its pattern {pattern:?} does not compile"))
    };
    compile(pattern)?;
    compile(&format!("^(?:{pattern})$"))
}
