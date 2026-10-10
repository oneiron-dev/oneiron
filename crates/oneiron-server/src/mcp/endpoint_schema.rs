//! JSON schemas for endpoint tools: setup, execute-code, paging, and verbs.

use super::endpoint_args::MCP_CODE_TASK_MAX_CHARS;
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
    let allowed = tool.argument_fields();
    let typed = oneiron::task_verb::sdk::mcp_arguments_schema(tool.name).map(close_object_schemas);
    let mut properties = serde_json::Map::new();
    for field in allowed {
        let schema = match (tool.memory_method(), *field) {
            (Some(method), "request") => method.request_schema(),
            _ => verb_argument_field_schema(field),
        };
        let schema = match typed
            .as_ref()
            .and_then(|typed| typed.get("properties"))
            .and_then(|properties| properties.get(*field))
        {
            Some(input) => merge_verb_argument_schema(input.clone(), schema),
            None => schema,
        };
        properties.insert((*field).to_owned(), schema);
    }
    let arguments = json!({
        "type": "object",
        "additionalProperties": false,
        "required": tool.required_fields(),
        "properties": Value::Object(properties),
    });
    let required: &[&'static str] = if tool.required_fields().is_empty() {
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

/// Every struct-shaped object a verb tool advertises is closed, whatever its
/// Rust input type tolerates: the client is told exactly the fields the verb
/// reads. Free-form values (no `properties`) stay open.
pub(super) fn close_object_schemas(mut schema: Value) -> Value {
    fn close(value: &mut Value) {
        match value {
            Value::Object(map) => {
                if projection_closes(map) {
                    map.insert("additionalProperties".to_owned(), Value::Bool(false));
                }
                map.values_mut().for_each(close);
            }
            Value::Array(items) => items.iter_mut().for_each(close),
            _ => {}
        }
    }
    close(&mut schema);
    schema
}

/// Whether the projection closes this object schema: it lists its fields and
/// says nothing of others.
fn projection_closes(map: &serde_json::Map<String, Value>) -> bool {
    map.contains_key("properties") && !map.contains_key("additionalProperties")
}

/// The first field `input` names that `verb`'s advertised closed schema does
/// not, as a dotted path. Both doors refuse such an input before its lenient
/// decode, so a misspelled field is an error rather than silently dropped.
///
/// Only the closure is judged here; a type or bound mismatch is left to the
/// decoder and the verb. A struct read through `allOf`/`anyOf`/`oneOf` admits
/// the fields of every part it combines, and free-form values stay open.
pub(crate) fn verb_input_unknown_field(verb: &str, input: &Value) -> Option<String> {
    let schema = oneiron::task_verb::sdk::input_schema(verb)?;
    unknown_field(schema, schema, input, "")
}

fn unknown_field(root: &Value, schema: &Value, value: &Value, path: &str) -> Option<String> {
    let kind = match value {
        Value::Object(_) => "object",
        Value::Array(_) => "array",
        _ => return None,
    };
    let mut unknown = None;
    for shape in object_shapes(root, schema, 0) {
        if !shape.admits(kind) {
            continue;
        }
        let refused = match value {
            Value::Object(fields) => shape.unknown_field(root, fields, path),
            Value::Array(items) => shape.unknown_item_field(root, items, path),
            _ => None,
        };
        match refused {
            None => return None,
            Some(field) => {
                unknown.get_or_insert(field);
            }
        }
    }
    unknown
}

/// One way a schema can read a value: the conjunction of a node, its `$ref`
/// and `allOf` parts and one branch of each `anyOf`/`oneOf`.
#[derive(Clone, Default)]
struct ObjectShape<'s> {
    types: Option<Vec<&'s str>>,
    properties: Vec<&'s serde_json::Map<String, Value>>,
    additional: Vec<&'s Value>,
    items: Vec<&'s Value>,
    closed: bool,
    patterned: bool,
}

/// `$ref` chains deeper than this are left to the decoder.
const SCHEMA_REF_DEPTH_MAX: usize = 32;

fn object_shapes<'s>(root: &'s Value, schema: &'s Value, depth: usize) -> Vec<ObjectShape<'s>> {
    let Some(node) = schema.as_object() else {
        return if schema == &Value::Bool(false) {
            Vec::new()
        } else {
            vec![ObjectShape::default()]
        };
    };
    if depth > SCHEMA_REF_DEPTH_MAX {
        return vec![ObjectShape::default()];
    }
    let mut own = ObjectShape {
        types: node.get("type").and_then(|types| match types {
            Value::String(one) => Some(vec![one.as_str()]),
            Value::Array(many) => Some(many.iter().filter_map(Value::as_str).collect()),
            _ => None,
        }),
        patterned: node.contains_key("patternProperties"),
        ..ObjectShape::default()
    };
    if let Some(Value::Object(properties)) = node.get("properties") {
        own.properties.push(properties);
    }
    match node.get("additionalProperties") {
        Some(Value::Bool(false)) => own.closed = true,
        Some(extra @ Value::Object(_)) => own.additional.push(extra),
        Some(_) => {}
        None => own.closed = projection_closes(node),
    }
    own.items.extend(node.get("items"));
    let mut shapes = vec![own];
    if let Some(target) = node
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|reference| reference.strip_prefix('#'))
        .and_then(|pointer| root.pointer(pointer))
    {
        shapes = conjoin(&shapes, &object_shapes(root, target, depth + 1));
    }
    for part in node
        .get("allOf")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        shapes = conjoin(&shapes, &object_shapes(root, part, depth + 1));
    }
    for key in ["anyOf", "oneOf"] {
        if let Some(branches) = node.get(key).and_then(Value::as_array) {
            let branches: Vec<_> = branches
                .iter()
                .flat_map(|branch| object_shapes(root, branch, depth + 1))
                .collect();
            shapes = conjoin(&shapes, &branches);
        }
    }
    shapes
}

fn conjoin<'s>(left: &[ObjectShape<'s>], right: &[ObjectShape<'s>]) -> Vec<ObjectShape<'s>> {
    let mut shapes = Vec::with_capacity(left.len() * right.len());
    for one in left {
        for other in right {
            let mut shape = one.clone();
            shape.types = match (shape.types.take(), &other.types) {
                (Some(types), Some(others)) => Some(
                    types
                        .into_iter()
                        .filter(|kind| others.contains(kind))
                        .collect(),
                ),
                (types, others) => types.or_else(|| others.clone()),
            };
            shape.properties.extend(other.properties.iter().copied());
            shape.additional.extend(other.additional.iter().copied());
            shape.items.extend(other.items.iter().copied());
            shape.closed |= other.closed;
            shape.patterned |= other.patterned;
            shapes.push(shape);
        }
    }
    shapes
}

impl ObjectShape<'_> {
    fn admits(&self, kind: &str) -> bool {
        self.types
            .as_ref()
            .is_none_or(|types| types.contains(&kind))
    }

    fn unknown_field(
        &self,
        root: &Value,
        fields: &serde_json::Map<String, Value>,
        path: &str,
    ) -> Option<String> {
        for (name, value) in fields {
            let field = if path.is_empty() {
                name.clone()
            } else {
                format!("{path}.{name}")
            };
            let declared: Vec<&Value> = self
                .properties
                .iter()
                .filter_map(|properties| properties.get(name))
                .collect();
            let schemas = if !declared.is_empty() {
                declared
            } else if self.patterned {
                continue;
            } else if self.closed {
                return Some(field);
            } else {
                self.additional.clone()
            };
            if let Some(inner) = schemas
                .into_iter()
                .find_map(|schema| unknown_field(root, schema, value, &field))
            {
                return Some(inner);
            }
        }
        None
    }

    fn unknown_item_field(&self, root: &Value, items: &[Value], path: &str) -> Option<String> {
        items.iter().enumerate().find_map(|(index, item)| {
            let field = format!("{path}[{index}]");
            self.items.iter().find_map(|schema| {
                let schema = match schema {
                    Value::Array(positional) => positional.get(index)?,
                    every => every,
                };
                unknown_field(root, schema, item, &field)
            })
        })
    }
}

pub(super) fn merge_verb_argument_schema(input: Value, constraints: Value) -> Value {
    if let (Some(mut typed), Some(mut envelope)) =
        (input.as_object().cloned(), constraints.as_object().cloned())
    {
        // Typed inputs own nullable string types. The envelope's integer
        // type instead pins fields decoded by deserialize_optional_u64:
        // explicit null is not an unsigned JSON integer at that door.
        if typed.contains_key("type")
            && envelope.get("type").and_then(Value::as_str) != Some("integer")
        {
            envelope.remove("type");
        }
        typed.extend(envelope);
        Value::Object(typed)
    } else if constraints == json!({}) {
        // An empty envelope adds no constraints; keep the original schema.
        input
    } else {
        json!({ "allOf": [input, constraints] })
    }
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

        }),
        "task_ref" | "room_ref" | "turn_ref" => entity_id_schema(),
        // The advertised ceiling IS the writer's ceiling, stated in the closed
        // schema so a caller learns the bound from `tools/list` instead of from
        // a refusal. `maxLength` counts code points, so the byte bound the
        // runtime enforces is the narrower of the two by construction.
        "label" => json!({
            "type": "string",
            "minLength": 1,
            "pattern": "\\S",
            "maxLength": oneiron::context_board::TASK_LABEL_MAX_BYTES,
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
