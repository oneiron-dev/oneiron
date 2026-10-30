//! Private checked edit authority. A selected range is never exposed to callers.
use super::retained::ValidatedXmlPart;
use crate::resource::Dimension;
use crate::retained_opc::{Error, Result};
use std::ops::Range;

struct LeafTextTarget {
    id: usize,
    span: Range<usize>,
}

/// Bytes parsed again through the same port; semantics and unchanged regions
/// are checked before a package can install them.
pub(in crate::retained_opc) struct CheckedPartEdit(pub Vec<u8>);

/// The bytes an edited part may take: the caller's ceiling on one part, and
/// what its ceiling on every part together leaves past the others. A part
/// past them is a hit on the ceiling that binds (FIX 10654).
#[derive(Debug, Clone, Copy)]
pub(in crate::retained_opc) struct PartBudget {
    /// The caller's ceiling on one part's inflated bytes.
    pub part_bytes: usize,
    /// The caller's ceiling on every part's inflated bytes together.
    pub expanded_bytes: usize,
    /// Every other part's bytes, which the expanded ceiling counts too.
    pub others: usize,
}

impl PartBudget {
    /// A part of `length` bytes within both ceilings, or the hit on the one
    /// that binds: the expanded ceiling, over the package's whole expanded
    /// bytes, when what it leaves this part is the smaller; else the part's.
    fn admit(self, length: usize) -> Result<()> {
        let left = self.expanded_bytes.saturating_sub(self.others);
        if length <= self.part_bytes.min(left) {
            return Ok(());
        }
        Err(if left < self.part_bytes {
            Error::capacity_hit(
                Dimension::ExpandedBytes,
                self.others.saturating_add(length),
                self.expanded_bytes,
            )
        } else {
            Error::capacity_hit(Dimension::PartBytes, length, self.part_bytes)
        })
    }
}

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
        budget: PartBudget,
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
        budget.admit(length)?;
        let escaped = escape_text(value, escaped_bytes);
        let mut candidate = Vec::with_capacity(length);
        candidate.extend_from_slice(prefix);
        candidate.extend_from_slice(escaped.as_bytes());
        candidate.extend_from_slice(suffix);
        // Reparse candidate under the same caller budget, then verify its
        // meaning and target location. No part state changes before this check.
        let checked = ValidatedXmlPart::parse(&candidate, &self.resources)?;
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
