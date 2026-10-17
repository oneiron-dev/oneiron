//! Policy-manifest budgets for the modern-comment writer.
//!
//! These are operational budgets, not OOXML invariants. The stored policy
//! narrows the shipped row; optional holder limits may narrow it further.
//! How many comments one edit carries is no budget here: the vault door
//! measures it against `limits.pptx_comment_patches` and serves it whole.

use oneiron_docedit::pptx_comments::PptxCommentLimits;
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Six independently bounded resource budgets for a PowerPoint comment edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PptxOperationalLimits {
    pub max_author_name_bytes: usize,
    pub max_xml_bytes: usize,
    pub max_xml_attributes: usize,
    pub max_xml_namespaces: usize,
    pub max_xml_depth: usize,
    pub max_xml_nodes: usize,
}

impl Default for PptxOperationalLimits {
    fn default() -> Self {
        Self {
            max_author_name_bytes: 4_096,
            max_xml_bytes: 32 * 1024 * 1024,
            max_xml_attributes: 4_096,
            max_xml_namespaces: 256,
            max_xml_depth: 256,
            max_xml_nodes: 500_000,
        }
    }
}

impl PptxOperationalLimits {
    /// Apply the manifest's nested-narrowing precedence, including holder caps.
    #[must_use]
    pub const fn narrow(self, holder: Self) -> Self {
        Self {
            max_author_name_bytes: min(self.max_author_name_bytes, holder.max_author_name_bytes),
            max_xml_bytes: min(self.max_xml_bytes, holder.max_xml_bytes),
            max_xml_attributes: min(self.max_xml_attributes, holder.max_xml_attributes),
            max_xml_namespaces: min(self.max_xml_namespaces, holder.max_xml_namespaces),
            max_xml_depth: min(self.max_xml_depth, holder.max_xml_depth),
            max_xml_nodes: min(self.max_xml_nodes, holder.max_xml_nodes),
        }
    }

    #[must_use]
    pub const fn valid(self) -> bool {
        self.max_author_name_bytes > 0
            && self.max_xml_bytes > 0
            && self.max_xml_attributes > 0
            && self.max_xml_namespaces > 0
            && self.max_xml_depth > 0
            && self.max_xml_nodes > 0
    }

    /// The shipped policy row, encoded exactly like owner-authored rows.
    pub(crate) fn policy_row(self) -> Value {
        Value::Map(vec![
            (Value::from("precedence"), Value::from("nested_narrowing")),
            (
                Value::from("max_author_name_bytes"),
                Value::from(self.max_author_name_bytes as u64),
            ),
            (
                Value::from("max_xml_bytes"),
                Value::from(self.max_xml_bytes as u64),
            ),
            (
                Value::from("max_xml_attributes"),
                Value::from(self.max_xml_attributes as u64),
            ),
            (
                Value::from("max_xml_namespaces"),
                Value::from(self.max_xml_namespaces as u64),
            ),
            (
                Value::from("max_xml_depth"),
                Value::from(self.max_xml_depth as u64),
            ),
            (
                Value::from("max_xml_nodes"),
                Value::from(self.max_xml_nodes as u64),
            ),
        ])
    }

    /// Strict manifest parse: missing, duplicate and unknown rows fail closed.
    pub(crate) fn from_policy_row(value: &Value) -> Option<Self> {
        let Value::Map(entries) = value else {
            return None;
        };
        if entries.len() != 7 {
            return None;
        }
        let mut seen = BTreeSet::new();
        for (key, _) in entries {
            let name = key.as_str()?;
            if !matches!(
                name,
                "precedence"
                    | "max_author_name_bytes"
                    | "max_xml_bytes"
                    | "max_xml_attributes"
                    | "max_xml_namespaces"
                    | "max_xml_depth"
                    | "max_xml_nodes"
            ) || !seen.insert(name)
            {
                return None;
            }
        }
        let field = |name: &str| -> Option<usize> {
            entries
                .iter()
                .find(|(key, _)| key.as_str() == Some(name))?
                .1
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .filter(|value| *value > 0)
        };
        if entries
            .iter()
            .find(|(key, _)| key.as_str() == Some("precedence"))?
            .1
            .as_str()?
            != "nested_narrowing"
        {
            return None;
        }
        let limits = Self {
            max_author_name_bytes: field("max_author_name_bytes")?,
            max_xml_bytes: field("max_xml_bytes")?,
            max_xml_attributes: field("max_xml_attributes")?,
            max_xml_namespaces: field("max_xml_namespaces")?,
            max_xml_depth: field("max_xml_depth")?,
            max_xml_nodes: field("max_xml_nodes")?,
        };
        limits.valid().then_some(limits)
    }

    /// The organ's codec ceilings: these budgets over the ZIP32 record
    /// bounds and the edit pipeline's archive ceilings (`opc`'s 256 MiB per
    /// entry, 1 GiB per package).
    pub(super) const fn codec(self) -> PptxCommentLimits {
        PptxCommentLimits {
            max_archive_bytes: u32::MAX as usize,
            max_entries: u16::MAX as usize,
            max_part_bytes: 256 << 20,
            max_expanded_bytes: 1 << 30,
            max_author_name_bytes: self.max_author_name_bytes,
            max_xml_bytes: self.max_xml_bytes,
            max_xml_attributes: self.max_xml_attributes,
            max_xml_namespaces: self.max_xml_namespaces,
            max_xml_depth: self.max_xml_depth,
            max_xml_nodes: self.max_xml_nodes,
        }
    }
}

const fn min(a: usize, b: usize) -> usize {
    if a < b { a } else { b }
}
