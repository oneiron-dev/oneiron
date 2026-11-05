//! Core half of `serialize::yaml_format`: its store-layer items live in `oneiron_store::serialize::yaml_format` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::serialize::yaml_format::*;

use super::group_labels::group_key;
use super::markdown_plaintext_format::value_to_compact_string;
use super::pack_entry::PreparedEntity;
use super::types::GroupKey;
use serde_json::Value;

pub(super) fn write_yaml_groups(
    out: &mut String,
    groups: &[(GroupKey, Vec<PreparedEntity>)],
    indent: usize,
) {
    for (entity_type, rows) in groups {
        if rows.is_empty() {
            continue;
        }

        write_indent(out, indent);
        out.push_str(group_key(*entity_type));
        out.push_str(":\n");

        for row in rows {
            write_indent(out, indent + 2);
            out.push_str("- id: ");
            out.push_str(&yaml_scalar(&Value::String(row.id.clone())));
            out.push('\n');

            for (key, value) in &row.fields {
                write_indent(out, indent + 4);
                out.push_str(&yaml_key(key));
                out.push_str(": ");
                out.push_str(&yaml_scalar(value));
                out.push('\n');
            }
        }
    }
}
