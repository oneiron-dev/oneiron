//! What a pass makes of an order no allowed machine fits: the terminal state it takes when it
//! does not wait, and the earliest time its reasons clear by themselves.
use std::collections::BTreeMap;

use crate::work_order::blocker::{BlockedOn, Blocker};
use crate::work_order::record::{CancelWhy, GiveUpWhy, OrderState, WaitRule, WorkOrder};

/// The terminal state `order` takes when blocked by `blocked` at `now_ms`, if it does not wait.
pub(super) fn closing_state(
    order: &WorkOrder,
    blocked: &[BlockedOn],
    authority_ended: bool,
    now_ms: u64,
) -> Option<OrderState> {
    if authority_ended {
        return Some(OrderState::Cancelled {
            why: CancelWhy::AuthorityEnded,
        });
    }
    // Every allowed machine reports a reason no wait clears: refused at once (1.3).
    let mut by_machine: BTreeMap<Option<&str>, Vec<Blocker>> = BTreeMap::new();
    for on in blocked {
        by_machine
            .entry(on.machine.as_deref())
            .or_default()
            .push(on.blocker.clone());
    }
    let machine_rows: Vec<&Vec<Blocker>> = by_machine
        .iter()
        .filter(|(machine, _)| machine.is_some())
        .map(|(_, reasons)| reasons)
        .collect();
    let order_level_never = by_machine
        .get(&None)
        .is_some_and(|reasons| reasons.iter().any(|blocker| !blocker.clears_by_waiting()));
    let every_machine_never = !machine_rows.is_empty()
        && machine_rows
            .iter()
            .all(|reasons| reasons.iter().any(|blocker| !blocker.clears_by_waiting()));
    if order_level_never || every_machine_never {
        return Some(OrderState::GivenUp {
            why: GiveUpWhy::NeverFits {
                blocked: blocked.to_vec(),
            },
        });
    }
    let wait_ended = order.wait == WaitRule::No || order.wait_ran_out(now_ms);
    // An unconfirmed attempt is never a reason to give up: it waits for its end (I3).
    let unconfirmed = blocked
        .iter()
        .any(|on| matches!(on.blocker, Blocker::AttemptUnconfirmed { .. }));
    if wait_ended && !unconfirmed {
        return Some(OrderState::GivenUp {
            why: GiveUpWhy::WaitEnded {
                blocked: blocked.to_vec(),
            },
        });
    }
    None
}

/// The earliest time one machine's every reason clears by itself, over the machines whose
/// reasons all carry a time.
pub(super) fn earliest_clear(blocked: &[BlockedOn]) -> Option<u64> {
    let mut by_machine: BTreeMap<Option<&str>, Option<u64>> = BTreeMap::new();
    for on in blocked {
        let at = on.blocker.clears_at_ms();
        let entry = by_machine.entry(on.machine.as_deref()).or_insert(Some(0));
        *entry = match (*entry, at) {
            (Some(known), Some(at)) => Some(known.max(at)),
            _ => None,
        };
    }
    by_machine.into_values().flatten().min()
}
