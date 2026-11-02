//! The values a deck body's tree and charts keep as JSON spelling, as a
//! decoded view shows them (OF-067, FIX 8995). A node's meta map and a
//! chart's entry hold each field as its JSON text ([`super::put_json`]), so
//! a key in an escaped spelling is marked in its escaped form while a view
//! shows it decoded; the lift marks the decoded values too, as it marks the
//! decoded operations of the log ([`super::deck_log_ops`]).

use super::{CHARTS, KIND, OFFICE, SCHEMA, SCHEMA_KEY, TREE};

/// Each value the tree and charts of a deck body keep as JSON spelling,
/// decoded as [`super::read`] decodes it, as JSON: a node's name, binding,
/// placeholder and payload, and a chart's family, source, categories and
/// each series' name, values and family, for the lift to mark beside the
/// stored spelling. Only a spelling with an escape in it is decoded: every
/// other one holds its strings as a view shows them, so its own marks place
/// them. `state` is a typed body's whole state as JSON; it is read only, and
/// anything but a schema-1 deck body has none.
pub(crate) fn deck_json_values(state: &serde_json::Value) -> Vec<serde_json::Value> {
    let office = &state[OFFICE];
    if office[KIND] != "pptx" || office[SCHEMA_KEY] != SCHEMA {
        return Vec::new();
    }
    let mut values = Vec::new();
    for root in [TREE, CHARTS] {
        decoded_values(&state[root], &mut values);
    }
    values
}

/// Each escaped JSON spelling under `value`, decoded, that holds a string.
fn decoded_values(value: &serde_json::Value, out: &mut Vec<serde_json::Value>) {
    match value {
        serde_json::Value::String(spelling) => {
            if spelling.contains('\\')
                && let Ok(decoded) = serde_json::from_str::<serde_json::Value>(spelling)
                && holds_string(&decoded)
            {
                out.push(decoded);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                decoded_values(item, out);
            }
        }
        serde_json::Value::Object(fields) => {
            for item in fields.values() {
                decoded_values(item, out);
            }
        }
        _ => {}
    }
}

fn holds_string(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(_) => true,
        serde_json::Value::Array(items) => items.iter().any(holds_string),
        serde_json::Value::Object(fields) => fields.values().any(holds_string),
        _ => false,
    }
}
