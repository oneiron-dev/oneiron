//! The nesting bound before serialization into the validator compartment.
//! This is not a schema interpreter; Wasmtime meters actual schema execution.
//!
//! Depth is the one structural bound kept (FIX 9927): the host encodes the
//! request recursively and the guest walks it on its own bounded stack, so a
//! deeper tree is a format bound, refused before either recursion runs. Node
//! counts and byte estimates are not validity rules: a larger tree goes to
//! the compartment whole, whose request frame and metered memory and fuel
//! are the real decode bounds.

use serde_json::Value;

const MAX_SCHEMA_DEPTH: usize = 32;
const MAX_VALUE_DEPTH: usize = 24;

pub(super) fn check(schema: &Value, value: &Value) -> Result<(), String> {
    bounded_depth(schema, MAX_SCHEMA_DEPTH)?;
    bounded_depth(value, MAX_VALUE_DEPTH)?;
    Ok(())
}

fn bounded_depth(root: &Value, depth_limit: usize) -> Result<(), String> {
    let mut pending = vec![(root, 0)];
    while let Some((value, depth)) = pending.pop() {
        if depth > depth_limit {
            return Err("JSON schema validation input exceeds its nesting depth".into());
        }
        match value {
            Value::Object(fields) => {
                pending.extend(fields.values().map(|child| (child, depth + 1)));
            }
            Value::Array(items) => {
                pending.extend(items.iter().map(|child| (child, depth + 1)));
            }
            _ => {}
        }
    }
    Ok(())
}
