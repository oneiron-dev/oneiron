//! Pack-local first-mention rendering. Citation IDs remain revision-qualified metadata.
use crate::serialize::pack_entry::PreparedEntity;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// An alias's entity: its short id, its name, and its source id.
pub type Handle = (String, String, [u8; 16]);

/// `text` with each alias that stands as a whole word rendered by `render`,
/// the first of `aliases` that matches taken.
pub fn substitute(
    text: &str,
    aliases: &[(&String, &Handle)],
    mut render: impl FnMut(&Handle) -> String,
) -> String {
    let mut output = String::with_capacity(text.len());
    let mut tail = text;
    let mut left_boundary = true;
    while !tail.is_empty() {
        let matched = aliases.iter().find_map(|(alias, handle)| {
            if !left_boundary {
                return None;
            }
            let rest = tail.strip_prefix(alias.as_str())?;
            rest.chars()
                .next()
                .is_none_or(|c| !is_word(c))
                .then_some((alias, handle, rest))
        });
        if let Some((alias, handle, rest)) = matched {
            output.push_str(&render(handle));
            left_boundary = alias.chars().next_back().is_none_or(|c| !is_word(c));
            tail = rest;
        } else {
            let mut chars = tail.chars();
            if let Some(c) = chars.next() {
                output.push(c);
                left_boundary = !is_word(c);
            }
            tail = chars.as_str();
        }
    }
    output
}

/// What an alias's edges must not touch for it to stand as a whole word.
fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}
