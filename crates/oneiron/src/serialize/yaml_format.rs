//! YAML section writer and YAML scalar/key quoting rules.

use serde_json::Value;

use super::group_labels::group_key;
use super::markdown_plaintext_format::value_to_compact_string;
use super::pack_entry::PreparedEntity;
use super::types::GroupKey;

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

pub(super) fn write_indent(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push(' ');
    }
}

fn yaml_key(key: &str) -> String {
    if needs_yaml_quotes(key) {
        format!("\"{}\"", yaml_escape_quoted(key))
    } else {
        key.to_owned()
    }
}

/// Escape a string for YAML double-quoted scalar output.
/// Handles backslash, double-quote, tab, and other control characters
/// following libyaml's escape table.
fn yaml_escape_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\0' => out.push_str("\\0"),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0B' => out.push_str("\\v"),
            '\x0C' => out.push_str("\\f"),
            '\x1B' => out.push_str("\\e"),
            c if c.is_control() => {
                let n = c as u32;
                if n <= 0xFF {
                    out.push_str(&format!("\\x{n:02X}"));
                } else {
                    out.push_str(&format!("\\u{n:04X}"));
                }
            }
            c => out.push(c),
        }
    }
    out
}

fn yaml_scalar(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => v.to_string(),
        Value::String(v) => {
            if needs_yaml_quotes(v) {
                format!("\"{}\"", yaml_escape_quoted(v))
            } else {
                v.clone()
            }
        }
        // Flow arrays: always quote string elements to avoid comma/colon ambiguity
        Value::Array(values) => {
            let inner = values
                .iter()
                .map(|v| match v {
                    Value::String(s) => format!("\"{}\"", yaml_escape_quoted(s)),
                    other => yaml_scalar(other),
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("[{inner}]")
        }
        Value::Object(_) => format!(
            "\"{}\"",
            yaml_escape_quoted(&value_to_compact_string(value))
        ),
    }
}

/// Check if a YAML plain scalar would be ambiguous (parsed as non-string type)
/// or contains characters that require quoting. Follows serde-yml/libyaml rules.
fn needs_yaml_quotes(value: &str) -> bool {
    value.is_empty()
        // YAML indicators at start position
        || value.starts_with(['-', '?', ':', '!', '&', '*', '#', '{', '[', '>', '|', '\'', '"', '%', '@', '`', '+', '.'])
        // Flow/block indicators anywhere
        || value.contains(':')
        || value.contains('#')
        || value.contains('[')
        || value.contains(']')
        || value.contains('{')
        || value.contains('}')
        || value.contains(',')
        || value.contains('\\')
        || contains_yaml_control(value)
        // Leading/trailing whitespace
        || value.starts_with(' ')
        || value.ends_with(' ')
        // YAML 1.1 boolean/null aliases (all case variants)
        || is_yaml_reserved_word(value)
        || looks_numeric(value)
}

fn contains_yaml_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}

fn is_yaml_reserved_word(value: &str) -> bool {
    matches!(
        value,
        "true"
            | "false"
            | "yes"
            | "no"
            | "on"
            | "off"
            | "null"
            | "~"
            | "True"
            | "False"
            | "Yes"
            | "No"
            | "On"
            | "Off"
            | "Null"
            | "TRUE"
            | "FALSE"
            | "YES"
            | "NO"
            | "ON"
            | "OFF"
            | "NULL"
            | "y"
            | "Y"
            | "n"
            | "N"
            | "nil"
            | "Nil"
            | "NIL"
    )
}

fn looks_numeric(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let s = if value.starts_with(['+', '-']) {
        &value[1..]
    } else {
        value
    };
    if s.is_empty() {
        return false;
    }
    // Pure integer
    if s.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    // Float (including .5, 1., 1.0, 1e10)
    if s.parse::<f64>().is_ok() {
        return true;
    }
    // YAML special floats and hex/octal
    let lower = s.to_ascii_lowercase();
    matches!(lower.as_str(), ".inf" | ".nan" | "inf" | "nan")
        || lower.starts_with("0x")
        || lower.starts_with("0o")
}
