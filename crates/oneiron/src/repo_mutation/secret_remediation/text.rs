//! The text a remediation reads and writes around a marked literal (FIX
//! 7608 slice 6): the literal's quoted bounds, the name it is assigned to,
//! the env name made of it, and TOML strings.

use std::ops::Range;

use crate::secret_manifest::is_secret_env_name;

/// The quoted literal that is exactly the key at `span`, quotes included:
/// one quote byte closes it on both sides, and no prefix, escape, doubled
/// quote or line break changes how a language reads it.
pub(super) fn literal_bounds(content: &[u8], span: &Range<usize>) -> Option<Range<usize>> {
    let open = span.start.checked_sub(1)?;
    let quote = *content.get(open)?;
    if !matches!(quote, b'"' | b'\'' | b'`') || content.get(span.end) != Some(&quote) {
        return None;
    }
    if content
        .get(span.clone())?
        .iter()
        .any(|byte| *byte == quote || *byte == b'\\' || *byte == b'\n')
    {
        return None;
    }
    let before = open.checked_sub(1).and_then(|at| content.get(at)).copied();
    if before.is_some_and(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'_' | b'\\' | b'#' | b'@' | b'$')
            || byte == quote
    }) {
        return None;
    }
    let after = content.get(span.end + 1).copied();
    if after.is_some_and(|byte| byte == quote || byte == b'#') {
        return None;
    }
    Some(open..span.end + 1)
}

/// The line `content` holds before offset `at`.
pub(super) fn line_before(content: &[u8], at: usize) -> &[u8] {
    let head = content.get(..at).unwrap_or_default();
    let start = head
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |newline| newline + 1);
    head.get(start..).unwrap_or_default()
}

/// The env name of the name a literal is assigned to on its line
/// (`API_KEY = `, `apiKey: `, `"api-key": `, `key := `), if one is.
pub(super) fn assigned_name(before: &[u8]) -> Option<String> {
    let text = before.trim_ascii_end();
    let operators: [&[u8]; 4] = [b"=>", b":=", b"=", b":"];
    let text = operators
        .iter()
        .find_map(|operator| text.strip_suffix(*operator))?
        .trim_ascii_end();
    let identifier = match text.split_last()? {
        (&quote @ (b'"' | b'\''), inner) => {
            let start = inner.iter().rposition(|byte| *byte == quote)? + 1;
            inner.get(start..)?
        }
        _ => {
            let start = text
                .iter()
                .rposition(|byte| !(byte.is_ascii_alphanumeric() || *byte == b'_'))
                .map_or(0, |at| at + 1);
            text.get(start..)?
        }
    };
    env_name_from(std::str::from_utf8(identifier).ok()?)
}

/// `identifier` as an upper snake env name (`apiKey`, `api-key` ->
/// `API_KEY`), when it makes one.
fn env_name_from(identifier: &str) -> Option<String> {
    let mut name = String::new();
    let mut lower_before = false;
    for c in identifier.chars() {
        if c.is_ascii_alphanumeric() {
            if c.is_ascii_uppercase() && lower_before {
                name.push('_');
            }
            lower_before = c.is_ascii_lowercase() || c.is_ascii_digit();
            name.push(c.to_ascii_uppercase());
        } else if !name.is_empty() && !name.ends_with('_') {
            name.push('_');
            lower_before = false;
        }
    }
    let name = name.trim_end_matches('_');
    is_secret_env_name(name).then(|| name.to_owned())
}

/// The env name of a key no assignment names: its custody handle's.
pub(super) fn fallback_name(handle: Option<&str>) -> String {
    handle
        .and_then(env_name_from)
        .map_or_else(|| "SECRET".to_owned(), |handle| format!("SECRET_{handle}"))
}

/// `text` as a TOML basic string.
pub(super) fn toml_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
