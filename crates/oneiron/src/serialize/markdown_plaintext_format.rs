//! Core half of `serialize::markdown_plaintext_format`: its store-layer items live in `oneiron_store::serialize::markdown_plaintext_format` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::serialize::markdown_plaintext_format::*;

use super::group_labels::{group_name, group_title};
use super::pack_entry::PreparedEntity;
use super::types::GroupKey;
use serde_json::Value;
use std::collections::HashSet;

pub(super) fn write_markdown_groups(
    out: &mut String,
    groups: &[(GroupKey, Vec<PreparedEntity>)],
    level: &str,
) {
    let mut first_group = true;
    for (entity_type, rows) in groups {
        if rows.is_empty() {
            continue;
        }

        if !first_group {
            out.push('\n');
        }
        first_group = false;

        out.push_str(level);
        out.push(' ');
        out.push_str(group_title(*entity_type));
        out.push_str("\n\n");

        let columns = collect_columns(rows);
        if columns.is_empty() {
            continue;
        }

        out.push('|');
        for col in &columns {
            out.push(' ');
            out.push_str(col);
            out.push(' ');
            out.push('|');
        }
        out.push('\n');

        out.push('|');
        for _ in &columns {
            out.push_str("----|");
        }
        out.push('\n');

        for row in rows {
            out.push('|');
            for col in &columns {
                let value = markdown_value_for_column(row, col);
                out.push(' ');
                out.push_str(&escape_markdown(&value));
                out.push(' ');
                out.push('|');
            }
            out.push('\n');
        }
    }
}

fn markdown_value_for_column(entity: &PreparedEntity, column: &str) -> String {
    if column == "id" {
        return entity.id.clone();
    }

    for (key, value) in &entity.fields {
        if key == column {
            return value_to_text(value, true);
        }
    }

    String::new()
}

pub(super) fn write_plaintext_groups(out: &mut String, groups: &[(GroupKey, Vec<PreparedEntity>)]) {
    let mut first_group = true;
    for (entity_type, rows) in groups {
        if rows.is_empty() {
            continue;
        }

        if !first_group {
            out.push('\n');
        }
        first_group = false;

        out.push_str(group_name(*entity_type));
        out.push('\n');

        let columns = collect_columns(rows);
        for row in rows {
            let mut first_col = true;
            for col in &columns {
                if !first_col {
                    out.push('|');
                }
                first_col = false;

                let value = if col == "id" {
                    row.id.clone()
                } else {
                    row.fields
                        .iter()
                        .find(|(key, _)| key == col)
                        .map(|(_, value)| value_to_text(value, false))
                        .unwrap_or_default()
                };
                out.push_str(&escape_plaintext(&value));
            }
            out.push('\n');
        }
    }
}

fn collect_columns(rows: &[PreparedEntity]) -> Vec<String> {
    let id_col = "id".to_owned();
    let mut seen = HashSet::<String>::new();
    seen.insert(id_col.clone());
    let mut columns = vec![id_col];

    for row in rows {
        for (key, _) in &row.fields {
            if seen.insert(key.clone()) {
                columns.push(key.clone());
            }
        }
    }

    columns
}
