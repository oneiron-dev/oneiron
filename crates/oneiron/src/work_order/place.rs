//! The PLACE slot's default rule, `role_warm_waste_headroom@1` (pass 34, 4.3): among the
//! machines that fit now, the first under five steps, each breaking only the ties of the one
//! before, so "why here?" is one phrase. A decider (row P1) may later pick among the same
//! options; the rule never picks "wait" while a machine fits.
use std::cmp::Ordering;

use super::fit::{MachineFacts, Needs};
use super::record::{SlotDecision, SlotName, WorkOrder};

/// The PLACE rule's name and version, as a decision records it.
pub const PLACE_RULE: &str = "role_warm_waste_headroom@1";

/// The most machines a decision lists as options (4.4).
pub const PLACE_OPTIONS_MAX: usize = 6;

/// The work role an order matches: `experiments` for a device claim, `builds` for a CPU job.
#[must_use]
pub fn order_role(needs: &Needs) -> &'static str {
    if needs.claims_devices() {
        "experiments"
    } else {
        "builds"
    }
}

/// One candidate's place under the rule: lower sorts first.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Score {
    /// 0: its roles include the order's (or it has none); 1: another role; 2: `spill`.
    role: u8,
    /// 0: every warm key the order lists is present; 1: some; 2: none.
    warm: u8,
    /// Offered devices the order does not claim, then their memory.
    waste_devices: usize,
    waste_memory_mib: u64,
    /// Headroom after placement in tens of percent, negated so more room sorts first.
    headroom: i64,
    /// 0 for the machine the order wishes for.
    unwished: u8,
}

fn score(order: &WorkOrder, needs: &Needs, machine: &MachineFacts) -> Score {
    let role_name = order_role(needs);
    let role = if machine.roles.is_empty() || machine.roles.iter().any(|role| role == role_name) {
        0
    } else if machine.roles.iter().all(|role| role == "spill") {
        2
    } else {
        1
    };
    let wanted = &order.wishes.warm;
    let present = wanted
        .iter()
        .filter(|key| machine.warm.contains(key))
        .count();
    let warm = if present == wanted.len() {
        0
    } else if present > 0 {
        1
    } else {
        2
    };
    let claimed = machine
        .devices_for(needs, &order.limits.device_ids)
        .unwrap_or_default();
    let (waste_devices, waste_memory_mib) = machine
        .devices
        .iter()
        .flatten()
        .filter(|device| !claimed.contains(&device.id))
        .fold((0, 0_u64), |(count, memory), device| {
            (count + 1, memory.saturating_add(device.memory_mib))
        });
    let headroom = machine
        .headroom_after_tenths(needs)
        .map_or(0, |tenths| -i64::try_from(tenths).unwrap_or(i64::MAX));
    let unwished = u8::from(order.wishes.machine != Some(machine.machine));
    Score {
        role,
        warm,
        waste_devices,
        waste_memory_mib,
        headroom,
        unwished,
    }
}

/// The step that decided between the pick and the runner-up, as the reason phrase.
fn reason(first: &Score, second: Option<&Score>, order: &WorkOrder) -> String {
    let Some(second) = second else {
        return "the only machine that fits".to_owned();
    };
    if first.role != second.role {
        "its role".to_owned()
    } else if first.warm != second.warm {
        format!("already holds {}", order.wishes.warm.join(", "))
    } else if (first.waste_devices, first.waste_memory_mib)
        != (second.waste_devices, second.waste_memory_mib)
    {
        "keeps devices free".to_owned()
    } else if first.headroom != second.headroom {
        "most room".to_owned()
    } else if first.unwished != second.unwished {
        "the machine the order wishes for".to_owned()
    } else {
        "tie".to_owned()
    }
}

/// The rule's ranking of `candidates` (each fits now) for `order`, and its decision: the top
/// [`PLACE_OPTIONS_MAX`] as options and the first as the pick. `None` with no candidate.
#[must_use]
pub fn place<'a>(
    order: &WorkOrder,
    candidates: &[&'a MachineFacts],
) -> Option<(&'a MachineFacts, SlotDecision)> {
    let needs = Needs::of(&order.request);
    let mut scored: Vec<(Score, &'a MachineFacts)> = candidates
        .iter()
        .map(|machine| (score(order, &needs, machine), *machine))
        .collect();
    scored.sort_by(|(a, left), (b, right)| match a.cmp(b) {
        Ordering::Equal => left.machine.cmp(&right.machine),
        other => other,
    });
    let (first_score, first) = scored.first()?;
    let why = reason(first_score, scored.get(1).map(|(score, _)| score), order);
    let options = scored
        .iter()
        .take(PLACE_OPTIONS_MAX)
        .map(|(_, machine)| machine.machine.to_hex())
        .collect();
    let decision = SlotDecision::by_rule(
        SlotName::Place,
        PLACE_RULE,
        options,
        first.machine.to_hex(),
        &why,
    );
    Some((*first, decision))
}
