//! Markdown table and compact plaintext writers, plus the shared value-to-text
//! rendering they use.

use std::collections::HashSet;

use serde_json::Value;

use super::group_labels::{group_name, group_title};
use super::pack_entry::{PreparedEntity, PreparedGroups};
use super::types::GroupKey;

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

        out.push_str(&markdown_header(&columns));
        out.push('\n');

        out.push('|');
        for _ in &columns {
            out.push_str("----|");
        }
        out.push('\n');

        for row in rows {
            out.push_str(&markdown_row(row, &columns));
            out.push('\n');
        }
    }
}

/// Clears the fields of each table row whose text, or whose own header cells,
/// read as a secret as the writer emits them (values side by side, the keys
/// left in the header), then reads the table again, since its columns can
/// change, until no row does. No two rows are read together.
pub(super) fn clear_rows_read_as_emitted(groups: &mut PreparedGroups, markdown: bool) {
    for (_, rows) in groups {
        loop {
            let columns = collect_columns(rows);
            let secret = rows.iter().position(|row| {
                !row.fields.is_empty() && row_reads_as_secret(row, &columns, markdown)
            });
            let Some(at) = secret else {
                break;
            };
            rows[at].fields.clear();
        }
    }
}

fn row_reads_as_secret(row: &PreparedEntity, columns: &[String], markdown: bool) -> bool {
    use crate::batch::secret_scan::release_reads_text;
    if !markdown {
        return release_reads_text(&plaintext_row(row, columns));
    }
    let own: Vec<String> = columns
        .iter()
        .filter(|column| *column == "id" || row.fields.iter().any(|(key, _)| key == *column))
        .cloned()
        .collect();
    release_reads_text(&markdown_row(row, columns)) || release_reads_text(&markdown_header(&own))
}

fn markdown_header(columns: &[String]) -> String {
    let mut line = String::from("|");
    for col in columns {
        line.push(' ');
        line.push_str(col);
        line.push_str(" |");
    }
    line
}

fn markdown_row(row: &PreparedEntity, columns: &[String]) -> String {
    let mut line = String::from("|");
    for col in columns {
        line.push(' ');
        line.push_str(&escape_markdown(&markdown_value_for_column(row, col)));
        line.push_str(" |");
    }
    line
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
            out.push_str(&plaintext_row(row, &columns));
            out.push('\n');
        }
    }
}

fn plaintext_row(row: &PreparedEntity, columns: &[String]) -> String {
    columns
        .iter()
        .map(|col| {
            let value = if col == "id" {
                row.id.clone()
            } else {
                row.fields
                    .iter()
                    .find(|(key, _)| key == col)
                    .map(|(_, value)| value_to_text(value, false))
                    .unwrap_or_default()
            };
            escape_plaintext(&value)
        })
        .collect::<Vec<_>>()
        .join("|")
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

fn value_to_text(value: &Value, spaced_arrays: bool) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => v.to_string(),
        Value::String(v) => v.clone(),
        Value::Array(values) => {
            let sep = if spaced_arrays { ", " } else { "," };
            values
                .iter()
                .map(|value| value_to_text(value, spaced_arrays))
                .collect::<Vec<_>>()
                .join(sep)
        }
        Value::Object(_) => value_to_compact_string(value),
    }
}

pub(super) fn value_to_compact_string(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

fn escape_markdown(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', "<br>")
}

fn escape_plaintext(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', "\\n")
}
