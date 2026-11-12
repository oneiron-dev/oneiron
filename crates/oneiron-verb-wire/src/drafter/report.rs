//! Moved from `crates/oneiron/src/drafter/report.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::drafter::types::DrafterRetrainOutcome;
use crate::drafter::types::DrafterServing;
use heed::RoTxn;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// The derived group the drafter line renders under.
pub const DRAFTER_GROUP: &str = "coach.drafter";

/// The line's view: the drafter status door, where each version reverts.
pub const DRAFTER_VIEW: &str = "vault.drafters.status";

/// The drafter events no digest carried yet, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DigestDrafter {
    pub items: Vec<DigestDrafterItem>,
    /// Nights that trained nothing since the last carried line, by
    /// outcome and reason (`held:no_trainer_recipe`, `skipped:policy_off`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub nights: BTreeMap<String, u64>,
    /// The newest event the line carries: the next line starts after it.
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub through: EntityId,
    pub view: String,
}

/// One drafter event, content-free.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DigestDrafterItem {
    /// The event's id: the ref the item renders with.
    pub event: String,
    /// `trained`, `failed_training`, `qualified`, `failed_qualification`,
    /// `activated`, `rolled_back`, `reverted` or `erased`.
    pub kind: String,
    /// The versions it names, as 32 hex.
    pub versions: Vec<String>,
    /// Why, where the event says: a rollback's reason, or `stock` for an
    /// erase or a revert that left a target serving stock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub at: u64,
}

impl DigestDrafter {
    /// Whether the line makes a digest due on its own: it carries an event
    /// beyond nights that trained nothing.
    #[must_use]
    pub fn arms(&self) -> bool {
        !self.items.is_empty()
    }

    /// Renders the line under a presentation's two templates: the group,
    /// one item per event, then one item per night count.
    pub fn render(
        &self,
        group_template: &str,
        item_template: &str,
        group: &str,
        rendered: &mut String,
    ) {
        rendered.push_str(&group_template.replace("{group}", group));
        let mut item = |summary: String, reference: &str| {
            rendered.push_str(
                &item_template
                    .replace("{summary}", &summary)
                    .replace("{ref}", reference),
            );
        };
        for event in &self.items {
            let mut summary = format!("{DRAFTER_GROUP}: {}", event.kind);
            if !event.versions.is_empty() {
                summary.push(' ');
                summary.push_str(&event.versions.join(","));
            }
            if let Some(reason) = &event.reason {
                summary.push_str(" (");
                summary.push_str(reason);
                summary.push(')');
            }
            item(summary, &event.event);
        }
        for (outcome, nights) in &self.nights {
            item(
                format!("{DRAFTER_GROUP}: {nights} nights {outcome}"),
                DRAFTER_VIEW,
            );
        }
    }
}
