//! Private checked edit authority. A selected range is never exposed to callers.
use super::retained::ValidatedXmlPart;
use crate::retained_opc::{Error, Result};
use std::ops::Range;

struct LeafTextTarget {
    id: usize,
    span: Range<usize>,
}

/// Bytes parsed again with the same limits; semantics and unchanged regions
/// are checked before a package can install them.
pub(in crate::retained_opc) struct CheckedPartEdit(pub Vec<u8>);

impl ValidatedXmlPart<'_> {
    fn target(&self, path: &[&str], expected: &str) -> Result<LeafTextTarget> {
        if path.is_empty() || path.iter().any(|s| s.is_empty()) {
            return Err(Error::Edit("an absolute, nonempty QName path is required"));
        }
        let mut found = None;
        for (id, node) in self.nodes.iter().enumerate() {
            if node.name != *path.last().ok_or(Error::Edit("target missing"))? {
                continue;
            }
            let mut current = Some(id);
            let mut good = true;
            for segment in path.iter().rev() {
                let Some(at) = current else {
                    good = false;
                    break;
                };
                if self.nodes[at].name != *segment {
                    good = false;
                    break;
                }
                current = self.nodes[at].parent;
            }
            if !good || current.is_some() {
                continue;
            }
            if node.value != expected {
                continue;
            }
            if node.children || node.mixed || node.empty {
                return Err(Error::Edit("target changed or not leaf text"));
            }
            if found.is_some() {
                return Err(Error::Edit("ambiguous XML target"));
            }
            found = Some(LeafTextTarget {
                id,
                span: node.inner.clone(),
            });
        }
        found.ok_or(Error::Edit("target is absent, ambiguous, or not leaf text"))
    }

    pub(in crate::retained_opc) fn replace_text(
        &self,
        path: &[&str],
        expected: &str,
        value: &str,
        max_part_bytes: usize,
    ) -> Result<CheckedPartEdit> {
        if value.chars().any(|c| !is_xml_char(c)) {
            return Err(Error::Edit("invalid XML character"));
        }
        let target = self.target(path, expected)?;
        if value == expected {
            return Ok(CheckedPartEdit(self.source.to_vec()));
        }
        let prefix = self
            .source
            .get(..target.span.start)
            .ok_or(Error::Edit("invalid XML source span"))?;
        let suffix = self
            .source
            .get(target.span.end..)
            .ok_or(Error::Edit("invalid XML source span"))?;
        let escaped_bytes = escaped_length(value)?;
        let length = prefix
            .len()
            .checked_add(escaped_bytes)
            .and_then(|n| n.checked_add(suffix.len()))
            .ok_or(Error::Edit("edited XML size overflow"))?;
        if length > max_part_bytes {
            return Err(Error::Edit("edited XML size limit"));
        }
        let escaped = escape_text(value, escaped_bytes);
        let mut candidate = Vec::with_capacity(length);
        candidate.extend_from_slice(prefix);
        candidate.extend_from_slice(escaped.as_bytes());
        candidate.extend_from_slice(suffix);
        // Reparse candidate under the same caller budget, then verify its
        // meaning and target location. No part state changes before this check.
        let checked = ValidatedXmlPart::parse(&candidate, self.limits)?;
        let after = checked.target(path, value)?;
        if after.id != target.id
            || checked.nodes.len() != self.nodes.len()
            || !candidate.starts_with(prefix)
            || !candidate.ends_with(suffix)
        {
            return Err(Error::Edit("XML patch changed retained structure"));
        }
        Ok(CheckedPartEdit(candidate))
    }
}

fn escaped_length(value: &str) -> Result<usize> {
    value.chars().try_fold(0usize, |total, c| {
        let width = match c {
            '&' | '\r' => 5,
            '<' | '>' => 4,
            _ => c.len_utf8(),
        };
        total
            .checked_add(width)
            .ok_or(Error::Edit("edited XML size overflow"))
    })
}
fn escape_text(value: &str, length: usize) -> String {
    let mut escaped = String::with_capacity(length);
    for c in value.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '\r' => escaped.push_str("&#13;"),
            _ => escaped.push(c),
        }
    }
    escaped
}
fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}
