//! Native TOON encoder for prepared pack sections.

use serde_json::{Map, Number, Value};

use super::json_format::section_object;
use super::pack_entry::PreparedEntity;
use super::types::{GroupKey, TOON_MAX_DEPTH};
use super::yaml_format::write_indent;

pub(super) fn encode_toon_section(groups: &[(GroupKey, Vec<PreparedEntity>)]) -> String {
    if groups.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    write_toon_object(&mut out, &section_object(groups, false), 0);
    out
}

fn write_toon_object(out: &mut String, object: &Map<String, Value>, depth: usize) {
    if toon_depth_limit_reached(depth) {
        write_toon_depth_limit_value(out);
        return;
    }

    for (index, (key, value)) in object.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }

        match value {
            Value::Array(values) => write_toon_array(out, Some(key), values, depth),
            Value::Object(nested) => {
                if !nested.is_empty() && toon_depth_limit_reached(depth + 1) {
                    write_toon_keyed_depth_limit_value(out, key, depth);
                } else {
                    write_indent(out, depth * 2);
                    write_toon_key(out, key);
                    out.push(':');
                }
                if !nested.is_empty() && !toon_depth_limit_reached(depth + 1) {
                    out.push('\n');
                    write_toon_object(out, nested, depth + 1);
                }
            }
            _ => {
                write_indent(out, depth * 2);
                write_toon_key(out, key);
                out.push_str(": ");
                write_toon_primitive(out, value);
            }
        }
    }
}

fn write_toon_array(out: &mut String, key: Option<&str>, values: &[Value], depth: usize) {
    if toon_depth_limit_reached(depth) {
        write_toon_array_depth_limit_value(out, key, depth);
        return;
    }

    if values.is_empty() {
        write_toon_array_header(out, key, 0, None, depth);
        return;
    }

    if let Some(fields) = toon_tabular_fields(values) {
        write_toon_tabular_array(out, key, values, &fields, depth);
    } else if values.iter().all(is_toon_primitive) {
        write_toon_primitive_array(out, key, values, depth);
    } else {
        write_toon_nested_array(out, key, values, depth);
    }
}

fn write_toon_array_header(
    out: &mut String,
    key: Option<&str>,
    length: usize,
    fields: Option<&[String]>,
    depth: usize,
) {
    if let Some(key) = key {
        write_indent(out, depth * 2);
        write_toon_key(out, key);
    }

    out.push('[');
    out.push_str(&length.to_string());
    out.push(']');

    if let Some(fields) = fields {
        out.push('{');
        for (index, field) in fields.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            write_toon_key(out, field);
        }
        out.push('}');
    }

    out.push(':');
}

fn write_toon_primitive_array(out: &mut String, key: Option<&str>, values: &[Value], depth: usize) {
    write_toon_array_header(out, key, values.len(), None, depth);
    out.push(' ');

    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_toon_primitive(out, value);
    }
}

fn write_toon_tabular_array(
    out: &mut String,
    key: Option<&str>,
    values: &[Value],
    fields: &[String],
    depth: usize,
) {
    write_toon_array_header(out, key, values.len(), Some(fields), depth);
    out.push('\n');

    for (row_index, value) in values.iter().enumerate() {
        let Some(row) = value.as_object() else {
            continue;
        };

        write_indent(out, (depth + 1) * 2);
        for (field_index, field) in fields.iter().enumerate() {
            if field_index > 0 {
                out.push(',');
            }

            if let Some(value) = row.get(field) {
                write_toon_primitive(out, value);
            } else {
                out.push_str("null");
            }
        }

        if row_index + 1 < values.len() {
            out.push('\n');
        }
    }
}

fn write_toon_nested_array(out: &mut String, key: Option<&str>, values: &[Value], depth: usize) {
    write_toon_array_header(out, key, values.len(), None, depth);
    out.push('\n');

    for (index, value) in values.iter().enumerate() {
        write_indent(out, (depth + 1) * 2);
        out.push('-');

        match value {
            Value::Array(values) => {
                out.push(' ');
                write_toon_array(out, None, values, depth + 1);
            }
            Value::Object(object) => write_toon_list_item_object(out, object, depth + 1),
            _ => {
                out.push(' ');
                write_toon_primitive(out, value);
            }
        }

        if index + 1 < values.len() {
            out.push('\n');
        }
    }
}

fn write_toon_list_item_object(out: &mut String, object: &Map<String, Value>, depth: usize) {
    if !object.is_empty() && toon_depth_limit_reached(depth) {
        out.push(' ');
        write_toon_depth_limit_value(out);
        return;
    }

    let mut fields = object.iter();
    let Some((first_key, first_value)) = fields.next() else {
        return;
    };

    out.push(' ');
    write_toon_list_item_field(out, first_key, first_value, depth, true);

    for (key, value) in fields {
        out.push('\n');
        write_indent(out, (depth + 1) * 2);
        write_toon_list_item_field(out, key, value, depth, false);
    }
}

fn write_toon_list_item_field(
    out: &mut String,
    key: &str,
    value: &Value,
    depth: usize,
    first_field: bool,
) {
    match value {
        Value::Array(values) => {
            write_toon_key(out, key);
            if toon_depth_limit_reached(depth + 1) {
                out.push_str(": ");
                write_toon_depth_limit_value(out);
            } else if first_field && let Some(fields) = toon_tabular_fields(values) {
                write_toon_list_item_tabular_array(out, values, &fields, depth);
            } else {
                write_toon_array(out, None, values, depth + 1);
            }
        }
        Value::Object(object) => {
            write_toon_key(out, key);
            out.push(':');
            if !object.is_empty() {
                if toon_depth_limit_reached(depth + 2) {
                    out.push(' ');
                    write_toon_depth_limit_value(out);
                } else {
                    out.push('\n');
                    write_toon_object(out, object, depth + 2);
                }
            }
        }
        _ => {
            write_toon_key(out, key);
            out.push_str(": ");
            write_toon_primitive(out, value);
        }
    }
}

fn write_toon_list_item_tabular_array(
    out: &mut String,
    values: &[Value],
    fields: &[String],
    depth: usize,
) {
    out.push('[');
    out.push_str(&values.len().to_string());
    out.push_str("]{");
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_toon_key(out, field);
    }
    out.push_str("}:\n");

    for (row_index, value) in values.iter().enumerate() {
        let Some(row) = value.as_object() else {
            continue;
        };

        write_indent(out, (depth + 2) * 2);
        for (field_index, field) in fields.iter().enumerate() {
            if field_index > 0 {
                out.push(',');
            }

            if let Some(value) = row.get(field) {
                write_toon_primitive(out, value);
            } else {
                out.push_str("null");
            }
        }

        if row_index + 1 < values.len() {
            out.push('\n');
        }
    }
}

fn toon_tabular_fields(values: &[Value]) -> Option<Vec<String>> {
    let first = values.first()?.as_object()?;
    if first.is_empty() {
        return None;
    }
    if first.values().any(|value| !is_toon_primitive(value)) {
        return None;
    }

    let fields: Vec<String> = first.keys().cloned().collect();
    for value in values.iter().skip(1) {
        let row = value.as_object()?;
        if row.len() != fields.len()
            || fields.iter().any(|field| !row.contains_key(field))
            || row.values().any(|value| !is_toon_primitive(value))
        {
            return None;
        }
    }

    Some(fields)
}

fn toon_depth_limit_reached(depth: usize) -> bool {
    depth >= TOON_MAX_DEPTH
}

fn write_toon_depth_limit_value(out: &mut String) {
    out.push_str("null");
}

fn write_toon_keyed_depth_limit_value(out: &mut String, key: &str, depth: usize) {
    write_indent(out, depth * 2);
    write_toon_key(out, key);
    out.push_str(": ");
    write_toon_depth_limit_value(out);
}

fn write_toon_array_depth_limit_value(out: &mut String, key: Option<&str>, depth: usize) {
    if let Some(key) = key {
        write_toon_keyed_depth_limit_value(out, key, depth);
    } else {
        write_toon_depth_limit_value(out);
    }
}

fn is_toon_primitive(value: &Value) -> bool {
    matches!(
        value,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    )
}

fn write_toon_primitive(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => out.push_str(&format_toon_number(value)),
        Value::String(value) => write_toon_string(out, value),
        Value::Array(_) | Value::Object(_) => {}
    }
}

fn format_toon_number(number: &Number) -> String {
    if let Some(value) = number.as_i64() {
        return value.to_string();
    }
    if let Some(value) = number.as_u64() {
        return value.to_string();
    }
    if let Some(value) = number.as_f64() {
        return format_toon_float(value);
    }
    number.to_string()
}

fn format_toon_float(value: f64) -> String {
    if value.is_finite() && value.fract() == 0.0 && value.abs() <= i64::MAX as f64 {
        return (value as i64).to_string();
    }

    let formatted = value.to_string();
    if formatted.contains('e') || formatted.contains('E') {
        format_toon_float_without_exponent(value)
    } else {
        trim_toon_float_zeros(&formatted)
    }
}

fn format_toon_float_without_exponent(value: f64) -> String {
    if !value.is_finite() {
        return "0".to_owned();
    }

    if value.abs() >= 1.0 {
        let abs_value = value.abs();
        let integer = abs_value.trunc();
        let fraction = abs_value.fract();
        if fraction == 0.0 {
            format!("{}{}", if value < 0.0 { "-" } else { "" }, integer as i64)
        } else {
            trim_toon_float_zeros(&format!("{value:.17}"))
        }
    } else if value == 0.0 {
        "0".to_owned()
    } else {
        trim_toon_float_zeros(&format!("{value:.17}"))
    }
}

fn trim_toon_float_zeros(value: &str) -> String {
    let Some((integer, fraction)) = value.split_once('.') else {
        return value.to_owned();
    };

    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        integer.to_owned()
    } else {
        format!("{integer}.{fraction}")
    }
}

fn write_toon_key(out: &mut String, value: &str) {
    if is_valid_unquoted_toon_key(value) {
        out.push_str(value);
    } else {
        write_quoted_toon_string(out, value);
    }
}

fn write_toon_string(out: &mut String, value: &str) {
    if needs_quoted_toon_string(value) {
        write_quoted_toon_string(out, value);
    } else {
        out.push_str(value);
    }
}

fn write_quoted_toon_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(ch),
        }
    }
    out.push('"');
}

fn is_valid_unquoted_toon_key(value: &str) -> bool {
    let Some(first) = value.chars().next() else {
        return false;
    };

    (first.is_alphabetic() || first == '_')
        && value
            .chars()
            .skip(1)
            .all(|ch| ch.is_alphanumeric() || ch == '_' || ch == '.')
}

fn needs_quoted_toon_string(value: &str) -> bool {
    if value.is_empty() || matches!(value, "null" | "true" | "false") {
        return true;
    }

    if is_numeric_like_toon_string(value)
        || value.chars().any(is_toon_structural_char)
        || value
            .chars()
            .any(|ch| matches!(ch, ',' | '\\' | '"' | '\n' | '\r' | '\t'))
        || value.chars().next().is_some_and(char::is_whitespace)
        || value.chars().last().is_some_and(char::is_whitespace)
        || value.starts_with('-')
    {
        return true;
    }

    value.starts_with('0')
        && value.len() > 1
        && value.chars().nth(1).is_some_and(|ch| ch.is_ascii_digit())
}

fn is_numeric_like_toon_string(value: &str) -> bool {
    let mut chars = value.chars();
    let first = match chars.next() {
        Some('-') => match chars.next() {
            Some(ch) => ch,
            None => return false,
        },
        Some(ch) => ch,
        None => return false,
    };

    if !first.is_ascii_digit() {
        return false;
    }
    if first == '0' && chars.clone().next().is_some_and(|ch| ch.is_ascii_digit()) {
        return false;
    }

    chars.all(|ch| ch.is_ascii_digit() || matches!(ch, '.' | 'e' | 'E' | '+' | '-'))
}

fn is_toon_structural_char(value: char) -> bool {
    matches!(value, '[' | ']' | '{' | '}' | ':' | '-')
}
