//! The RANK slot's default rule, `class_then_fewest_running_then_oldest@1` (pass 34, 4.5): who
//! is dispatched first among the orders runnable now. It never decides who may spend: the
//! charge's own room does, and a blocked order at the head holds nothing, so a later runnable
//! order still starts.
use std::collections::BTreeMap;

use crate::EntityId;

use super::record::{SlotDecision, SlotName, WorkOrder};

/// The RANK rule's name and version, as a decision records it.
pub const RANK_RULE: &str = "class_then_fewest_running_then_oldest@1";

/// The most orders a decision lists as options; the rest follow by the rule (1.2).
pub const RANK_OPTIONS_MAX: usize = 8;

/// `orders` in the rule's order: class (interactive, normal, background), then the order whose
/// family has the fewest running attempts in `running`, then the oldest, then the lowest id.
#[must_use]
pub fn rank<'a>(orders: &[&'a WorkOrder], running: &BTreeMap<String, u32>) -> Vec<&'a WorkOrder> {
    let mut ranked = orders.to_vec();
    ranked.sort_by(|a, b| {
        let running_of = |order: &WorkOrder| running.get(&order.family_key()).copied().unwrap_or(0);
        a.class
            .cmp(&b.class)
            .then(running_of(a).cmp(&running_of(b)))
            .then(a.ordered_at_ms.cmp(&b.ordered_at_ms))
            .then(a.id.cmp(&b.id))
    });
    ranked
}

/// The decision that put `order` at `position` (0-based) of `ranked`.
#[must_use]
pub fn rank_decision(ranked: &[EntityId], position: usize) -> SlotDecision {
    let options = ranked
        .iter()
        .take(RANK_OPTIONS_MAX)
        .map(EntityId::to_hex)
        .collect();
    let pick = ranked
        .get(position)
        .map(EntityId::to_hex)
        .unwrap_or_default();
    let why = if position == 0 {
        "first by class, then the fewest running in its family, then the oldest".to_owned()
    } else {
        format!(
            "place {} by class, running in its family, then age",
            position + 1
        )
    };
    SlotDecision::by_rule(SlotName::Rank, RANK_RULE, options, pick, &why)
}
