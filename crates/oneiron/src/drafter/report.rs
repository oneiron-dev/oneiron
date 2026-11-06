//! The drafter line of the morning report (FIX 14977; DRAFTER-ACTIVATE = A
//! + revert: "any slowdown rolls it back automatically, and the rollback
//! shows in the morning report"). A regular digest carries every drafter
//! event no digest carried yet, read from the content-free event history,
//! never from the bindings that stand now: a version activated and rolled
//! back before morning is still reported.
//!
//! Trainings, failed trainings, qualifications, activations, rollbacks,
//! reverts and erases are items of their own, and any one of them makes a digest due. Nights that trained
//! nothing (held or skipped) are only counted, by reason, and ride a digest
//! that is due anyway. The owner's own policy changes are not reported back
//! to him, nor the host's record of what a worker serves after an event the
//! line reports.
use std::collections::BTreeMap;

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use super::{DrafterEventKind, DrafterRetrainOutcome, DrafterServing, EVENTS};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

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
    #[serde(with = "crate::serialize::entity_ref")]
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

/// The snake-case name `value` serialises as, else `fallback`.
fn wire_name(value: impl Serialize, fallback: &str) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| fallback.to_owned())
}

/// The drafter events after `seen`, the newest event an earlier line
/// carried, as one line; `None` when there are none to report. An event row
/// that does not decode is no event of the line.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn unseen_drafter_line_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    seen: Option<EntityId>,
) -> Result<Option<DigestDrafter>> {
    let mut items = Vec::new();
    let mut nights: BTreeMap<String, u64> = BTreeMap::new();
    let mut through = None;
    for row in EVENTS.iter_raw_from(store, txn, &[])? {
        let (_, value) = row?;
        let Ok(event) = EVENTS.decode_value(&value) else {
            continue;
        };
        if seen.is_some_and(|seen| event.id <= seen) {
            continue;
        }
        let to_stock = event
            .change
            .as_ref()
            .is_some_and(|change| change.to == DrafterServing::Stock);
        let (kind, versions, reason) = match event.kind {
            DrafterEventKind::Retrain { outcome, .. } => {
                let key = match outcome {
                    DrafterRetrainOutcome::Held { reason } => {
                        format!("held:{}", wire_name(reason, "held"))
                    }
                    DrafterRetrainOutcome::Skipped { reason } => {
                        format!("skipped:{}", wire_name(reason, "skipped"))
                    }
                    // A night that trained, or whose training failed, is an
                    // item of its own (FIX 14974).
                    DrafterRetrainOutcome::Trained { version } => {
                        items.push(DigestDrafterItem {
                            event: event.id.to_hex(),
                            kind: "trained".to_owned(),
                            versions: vec![version.to_hex()],
                            reason: None,
                            at: event.at,
                        });
                        through = through.max(Some(event.id));
                        continue;
                    }
                    DrafterRetrainOutcome::Failed { version, reason } => {
                        items.push(DigestDrafterItem {
                            event: event.id.to_hex(),
                            kind: "failed_training".to_owned(),
                            versions: vec![version.to_hex()],
                            reason: Some(wire_name(reason, "failed")),
                            at: event.at,
                        });
                        through = through.max(Some(event.id));
                        continue;
                    }
                };
                *nights.entry(key).or_default() += 1;
                through = through.max(Some(event.id));
                continue;
            }
            // The owner's own policy changes, and the host's record of what
            // a worker serves after an event this line already reports.
            DrafterEventKind::Policy { .. } | DrafterEventKind::Served { .. } => {
                through = through.max(Some(event.id));
                continue;
            }
            DrafterEventKind::Qualify {
                version, passed, ..
            } => (
                if passed {
                    "qualified"
                } else {
                    "failed_qualification"
                },
                vec![version],
                None,
            ),
            DrafterEventKind::Activate { version } => ("activated", vec![version], None),
            DrafterEventKind::Rollback { version, reason } => (
                "rolled_back",
                vec![version],
                Some(wire_name(reason, "rolled_back")),
            ),
            DrafterEventKind::Revert { version } => (
                "reverted",
                vec![version],
                to_stock.then(|| "stock".to_owned()),
            ),
            DrafterEventKind::Erase { versions, .. } => {
                ("erased", versions, to_stock.then(|| "stock".to_owned()))
            }
        };
        items.push(DigestDrafterItem {
            event: event.id.to_hex(),
            kind: kind.to_owned(),
            versions: versions.iter().map(EntityId::to_hex).collect(),
            reason,
            at: event.at,
        });
        through = through.max(Some(event.id));
    }
    Ok(through.map(|through| DigestDrafter {
        items,
        nights,
        through,
        view: DRAFTER_VIEW.to_owned(),
    }))
}
