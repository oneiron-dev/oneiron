//! JSON schemas for endpoint tools: setup, execute-code, paging, and verbs.

use super::endpoint_args::{
    MCP_CODE_TASK_MAX_CHARS, MCP_TASK_LABEL_MAX_BYTES, verb_argument_fields, verb_required_fields,
};
use super::schema_parts::{
    actor_schema, closed_object_schema, consent_schema, entity_id_schema, nonblank_string_schema,
    schema_version_property, tool_schema_root,
};
use super::surface::McpGeneratedVerbTool;
use super::tool_catalog::MCP_SCHEMA_DRAFT;
use serde_json::Value;
use serde_json::json;

/// The advertised `ttl_ms` domain is EXACTLY the decoder's own (ONE-1704 M6).
///
/// `McpCacheHint::ttl_ms` decodes into `u64`, so the schema states that ceiling
/// instead of an unbounded integer a caller could satisfy and the runtime would
/// then refuse. Schema and decoder accept and reject the same value set.
pub const MCP_CACHE_TTL_MS_MAX: u64 = u64::MAX;

/// The advertised `page.limit` domain is EXACTLY the decoder's own.
///
/// `McpPageRequest::limit` decodes into `u32`; the budget is still ADAPTIVE
/// above the server ceiling (a caller is narrowed, or records a forceful
/// override), so the maximum here is the decode domain, not the grant.
pub const MCP_PAGE_LIMIT_MAX: u32 = u32::MAX;

/// The decode ceiling for the optional setup board budget.
pub const MCP_BOARD_BUDGET_TOK_MAX: u32 = u32::MAX;

/// The decode ceiling for board frame epochs.
pub const MCP_FRAME_EPOCH_MAX: u64 = u64::MAX;

/// The floor every runtime door enforces: a zero page is a refusal, never
/// "unset".
pub const MCP_PAGE_LIMIT_MIN: u32 = 1;

fn cache_hint_schema() -> Value {
    closed_object_schema(
        &[],
        json!({
            "ttl_ms": {
                "type": "integer",
                "minimum": 0,
                "maximum": MCP_CACHE_TTL_MS_MAX,
            },
        }),
    )
}

/// The page budget is ADAPTIVE: a caller may ask for more than the server
/// ceiling and be narrowed to it, so the advertised `maximum` is the DECODE
/// domain rather than the grant. `minimum: 1` IS enforced at every runtime door
/// ([`McpPageRequest::validate_optional`]); a zero page is refused, not
/// silently treated as "unset", and `cursor` is the same closed object's
/// nonblank continuation handle.
fn page_request_schema() -> Value {
    closed_object_schema(
        &[],
        json!({
            "limit": {
                "type": "integer",
                "minimum": MCP_PAGE_LIMIT_MIN,
                "maximum": MCP_PAGE_LIMIT_MAX,
            },
            "forceful_override": { "type": "boolean" },
            "cursor": nonblank_string_schema(),
        }),
    )
}

pub(super) fn setup_tool_schema() -> Value {
    tool_schema_root(
        "https://oneiron.local/schemas/mcp/setup_oneiron.args.v1.json",
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "consent": consent_schema(),
            "board_budget_tok": {
                "type": "integer",
                "minimum": 1,
                "maximum": MCP_BOARD_BUDGET_TOK_MAX,
            },
            "page": page_request_schema(),
            "cache": cache_hint_schema(),
        }),
        &["schema_version", "actor", "consent"],
    )
}

pub(super) fn execute_code_tool_schema() -> Value {
    tool_schema_root(
        "https://oneiron.local/schemas/mcp/execute_code.args.v1.json",
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "consent": consent_schema(),
            "run_ref": nonblank_string_schema(),
            "task": {
                "type": "string",
                "pattern": "\\S",
                "maxLength": MCP_CODE_TASK_MAX_CHARS,
            },
            "page": page_request_schema(),
            "cache": cache_hint_schema(),
        }),
        &["schema_version", "actor", "consent", "run_ref", "task"],
    )
}

/// One generated tool's schema, derived from its binding — never hand-listed.
///
/// When the binding has required argument fields, `arguments` itself is
/// top-level REQUIRED: the advertised closed schema and the decoder's own
/// admission then accept exactly the same payloads, instead of the schema
/// admitting an omission the runtime rejects.
pub(super) fn verb_tool_schema(tool: McpGeneratedVerbTool) -> Value {
    let allowed = verb_argument_fields(tool.binding);
    let mut properties = serde_json::Map::new();
    for field in allowed {
        properties.insert((*field).to_owned(), verb_argument_field_schema(field));
    }
    let arguments = json!({
        "type": "object",
        "additionalProperties": false,
        "required": verb_required_fields(tool.binding),
        "properties": Value::Object(properties),
    });
    let required: &[&'static str] = if verb_required_fields(tool.binding).is_empty() {
        &["schema_version", "actor", "consent"]
    } else {
        &["schema_version", "actor", "consent", "arguments"]
    };
    tool_schema_root_owned(
        format!(
            "https://oneiron.local/schemas/mcp/{}.args.v1.json",
            tool.name
        ),
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "consent": consent_schema(),
            "arguments": arguments,
            "page": page_request_schema(),
            "cache": cache_hint_schema(),
        }),
        required,
    )
}

fn verb_argument_field_schema(field: &str) -> Value {
    match field {
        "key" => nonblank_string_schema(),
        "frame_epoch" => json!({
            "type": "integer",
            "minimum": 0,
            "maximum": MCP_FRAME_EPOCH_MAX,
        }),
        "scopes" => json!({
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "string",
                "enum": [
                    "my_tasks", "my_children", "consults_to_me",
                    "memories", "worlds", "presence", "counts",
                ],
            },
        }),
        "task_ref" => entity_id_schema(),
        // The advertised ceiling IS the writer's ceiling, stated in the closed
        // schema so a caller learns the bound from `tools/list` instead of from
        // a refusal. `maxLength` counts code points, so the byte bound the
        // runtime enforces is the narrower of the two by construction.
        "label" => json!({
            "type": "string",
            "minLength": 1,
            "pattern": "\\S",
            "maxLength": MCP_TASK_LABEL_MAX_BYTES,
        }),
        _ => json!({}),
    }
}

fn tool_schema_root_owned(id: String, properties: Value, required: &[&'static str]) -> Value {
    json!({
        "$schema": MCP_SCHEMA_DRAFT,
        "$id": id,
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties,
    })
}
