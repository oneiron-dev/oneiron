//! The relationships an extraction call lists (FIX 7575). A candidate's
//! `rel` used to be read as a 32-hex relationship id no request ever
//! showed. Now each relationship a candidate may hold within (the branch's
//! own, and each one a listed head holds within) leads its listing page as
//! `relationship R<n>`, a head within one ends in `[R<n>]`, and a reply's
//! `rel` label reads back through the call's own map to the relationship id.
//! A `rel` that is no relationship label of the call is read as before.

use std::collections::BTreeSet;

use super::{CallLabelMap, LabelKind};
use crate::EntityId;

/// One `relationship <label>` line for each of `rels`, once each, in order,
/// labelled as they render.
pub(in crate::dreamer_consolidation) fn relationship_lines(
    labels: &mut CallLabelMap,
    rels: impl IntoIterator<Item = EntityId>,
) -> String {
    let mut seen = BTreeSet::new();
    let mut out = String::new();
    for rel in rels {
        if seen.insert(rel) {
            let label = labels.assign(LabelKind::Relationship, rel);
            out.push_str(&format!("relationship {label}\n"));
        }
    }
    out
}

/// A candidate's `rel` as its reply wrote it.
#[derive(Debug, Clone, PartialEq)]
pub(in crate::dreamer_consolidation) enum CandidateRel {
    /// A relationship label its call listed, read back to its id.
    Listed(EntityId),
    /// Any other value, read as before FIX 7575.
    Unlisted(serde_json::Value),
}

impl CandidateRel {
    /// `value` read through the call's `labels`.
    pub(in crate::dreamer_consolidation) fn read(
        value: &serde_json::Value,
        labels: &CallLabelMap,
    ) -> Self {
        match value
            .as_str()
            .and_then(|text| labels.resolve_as(LabelKind::Relationship, text))
        {
            Some(id) => Self::Listed(id),
            None => Self::Unlisted(value.clone()),
        }
    }
}
