//! Policy-manifest budgets for the modern-comment writer.
//!
//! These are operational budgets, not OOXML invariants. The stored policy
//! narrows the shipped row; optional holder limits may narrow it further.

use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Seven independently bounded resource budgets for a PowerPoint comment edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PptxOperationalLimits {
    pub max_patches: usize,
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
            max_patches: 10_000,
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
            max_patches: min(self.max_patches, holder.max_patches),
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
        self.max_patches > 0
            && self.max_author_name_bytes > 0
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
                Value::from("max_patches"),
                Value::from(self.max_patches as u64),
            ),
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
        if entries.len() != 8 {
            return None;
        }
        let mut seen = BTreeSet::new();
        for (key, _) in entries {
            let name = key.as_str()?;
            if !matches!(
                name,
                "precedence"
                    | "max_patches"
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
            max_patches: field("max_patches")?,
            max_author_name_bytes: field("max_author_name_bytes")?,
            max_xml_bytes: field("max_xml_bytes")?,
            max_xml_attributes: field("max_xml_attributes")?,
            max_xml_namespaces: field("max_xml_namespaces")?,
            max_xml_depth: field("max_xml_depth")?,
            max_xml_nodes: field("max_xml_nodes")?,
        };
        limits.valid().then_some(limits)
    }
}

const fn min(a: usize, b: usize) -> usize {
    if a < b { a } else { b }
}
