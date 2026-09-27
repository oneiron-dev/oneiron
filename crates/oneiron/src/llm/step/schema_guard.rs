//! Structural input bounds before serialization into the validator compartment.
//! These are not a schema interpreter; Wasmtime meters actual schema execution.

use serde_json::Value;

const MAX_SCHEMA_NODES: usize = 1024;
const MAX_VALUE_NODES: usize = 2048;
const MAX_SCHEMA_DEPTH: usize = 32;
const MAX_VALUE_DEPTH: usize = 24;
const MAX_JSON_BYTES: usize = 128 * 1024;

pub(super) fn check(schema: &Value, value: &Value) -> Result<(), String> {
    bounded_tree(schema, MAX_SCHEMA_NODES, MAX_SCHEMA_DEPTH)?;
    bounded_tree(value, MAX_VALUE_NODES, MAX_VALUE_DEPTH)?;
    Ok(())
}

fn bounded_tree(root: &Value, node_limit: usize, depth_limit: usize) -> Result<(), String> {
    let mut pending = vec![(root, 0)];
    let mut nodes = 0usize;
    let mut bytes = 0usize;
    while let Some((value, depth)) = pending.pop() {
        nodes += 1;
        if nodes > node_limit || depth > depth_limit {
            return Err("JSON schema validation input exceeds structural budget".into());
        }
        match value {
            Value::Object(fields) => {
                for (name, child) in fields {
                    bytes = bytes.saturating_add(name.len());
                    pending.push((child, depth + 1));
                }
            }
            Value::Array(items) => {
                pending.extend(items.iter().map(|child| (child, depth + 1)));
            }
            Value::String(text) => bytes = bytes.saturating_add(text.len()),
            _ => bytes = bytes.saturating_add(8),
        }
        if bytes > MAX_JSON_BYTES {
            return Err("JSON schema validation input exceeds byte budget".into());
        }
    }
    Ok(())
}
