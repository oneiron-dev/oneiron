//! The applied-maintenance after-notice a regular digest carries (FIX 3226,
//! OF-023): the Dreamer's maintenance that applied at once, each write by its
//! receipt and once, while the owner has not reverted it. It is told after
//! the fact and waits on no one, so it is a line of its own, apart from the
//! proposals that wait for the owner's approval. Each write's inbox finding
//! notice still goes out as before.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::super::applied;
use super::ProactivityPresentation;
use crate::{Result, Vault};

/// The derived group the applied-maintenance line renders under.
pub const APPLIED_GROUP: &str = "dreamer.applied";
/// The line's view: the owner's list of applied maintenance, where each
/// write reverts.
pub const APPLIED_VIEW: &str = "/v1/owner/dreamer/maintenance/applied";

/// The applied writes no digest carried yet, still standing, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestApplied {
    pub items: Vec<DigestAppliedItem>,
    pub view: String,
}

/// One applied write, as the owner's list names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestAppliedItem {
    /// The write's target as the revert takes it: a finding's 32 hex, an
    /// ask's 64 hex, or a project's and a fork's 32 hex joined by `:`.
    pub target: String,
    /// Its kind on the owner's list (`curator`, `reach_out`, ...).
    pub kind: String,
    pub facet: String,
    pub applied_at: u64,
    /// The receipt (`gate:<id>`) the item is keyed by: a digest carries each
    /// one once.
    pub receipt_ref: String,
}

impl DigestApplied {
    /// Renders the line under `presentation`: the group, then one item per
    /// write, its kind and facet by its target.
    pub(super) fn render(&self, presentation: &ProactivityPresentation, rendered: &mut String) {
        let group = presentation
            .group_aliases
            .get(APPLIED_GROUP)
            .map_or(APPLIED_GROUP, String::as_str);
        rendered.push_str(&presentation.group_template.replace("{group}", group));
        for item in &self.items {
            let summary = format!("{APPLIED_GROUP}: {} applied by {}", item.kind, item.facet);
            rendered.push_str(
                &presentation
                    .item_template
                    .replace("{summary}", &summary)
                    .replace("{ref}", &item.target),
            );
        }
    }

    /// Marks each write's receipt carried.
    pub(super) fn mark_seen(&self, seen: &mut BTreeSet<String>) {
        seen.extend(self.items.iter().map(|item| item.receipt_ref.clone()));
    }
}

/// The standing applied writes whose receipt no digest carried yet, as one
/// line; `None` when there are none. A write the owner reverted first is
/// left out: his revert already answered it.
pub(super) fn unseen_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    seen: &BTreeSet<String>,
) -> Result<Option<DigestApplied>> {
    let items: Vec<DigestAppliedItem> = applied::standing_list_in_txn(vault, txn)?
        .into_iter()
        .filter(|row| !seen.contains(&row.receipt_ref))
        .map(|row| DigestAppliedItem {
            target: row.target.to_hex(),
            kind: row.kind.to_owned(),
            facet: row.facet,
            applied_at: row.applied_at,
            receipt_ref: row.receipt_ref,
        })
        .collect();
    Ok((!items.is_empty()).then(|| DigestApplied {
        items,
        view: APPLIED_VIEW.to_owned(),
    }))
}
