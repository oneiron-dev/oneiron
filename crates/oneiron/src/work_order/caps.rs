//! Named running caps (pass 34, 1.1 and section 13; row Q5): one mechanism for a seat, a family
//! and an array. An order names caps in its limits; while a cap's setting `jobs.caps.<name>` is
//! set, the issuer counts the orders that name it and hold a live attempt, and an order whose
//! cap is full waits with the blocker `CapFull`. An array's cap is the same counter over the
//! members of one `WORK_ORDER_GROUP`, whose row holds the number.
use std::collections::{BTreeMap, BTreeSet};

use crate::error::Result;
use crate::{EntityId, Vault};

use super::blocker::Blocker;
use super::group::WORK_ORDER_GROUPS;
use super::record::WorkOrder;
use super::setting_keys::running_cap_in_txn;

/// The most named caps one order lists.
pub const CAPS_PER_ORDER_MAX: usize = 8;

/// The most bytes a cap's name holds.
pub const CAP_NAME_MAX: usize = 64;

/// How an array group's cap is named in a `CapFull` blocker: this, then the group's id in
/// lower hex. A setting cap's name holds no `:`, so the two never meet.
pub const GROUP_CAP_PREFIX: &str = "group:";

/// Whether `name` may name a running cap: 1 to [`CAP_NAME_MAX`] bytes of `a-z`, `0-9`, `.`,
/// `_` and `-`.
#[must_use]
pub fn is_cap_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= CAP_NAME_MAX
        && name
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

/// What is wrong with an order's list of cap names `caps`, if anything: more than
/// [`CAPS_PER_ORDER_MAX`], a name [`is_cap_name`] refuses, or one named twice.
#[must_use]
pub fn caps_problem(caps: &[String]) -> Option<String> {
    if caps.len() > CAPS_PER_ORDER_MAX {
        return Some(format!(
            "limits.caps names at most {CAPS_PER_ORDER_MAX} caps"
        ));
    }
    if let Some(name) = caps.iter().find(|name| !is_cap_name(name)) {
        return Some(format!(
            "limits.caps: {name:?} is not a cap name (1 to {CAP_NAME_MAX} bytes of a-z, 0-9, '.', '_', '-')"
        ));
    }
    let unique: BTreeSet<&String> = caps.iter().collect();
    (unique.len() != caps.len()).then(|| "limits.caps names each cap once".to_owned())
}

/// The name a `CapFull` blocker gives the cap of array group `group`.
#[must_use]
pub fn group_cap_name(group: &EntityId) -> String {
    format!("{GROUP_CAP_PREFIX}{}", group.to_hex())
}

/// The live attempts that count against each named cap and each array group, over the orders
/// of one pass. An attempt counts from the moment it is made until its end is in, so one the
/// machine has not confirmed still holds its place (I3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunningCaps {
    named: BTreeMap<String, u32>,
    groups: BTreeMap<EntityId, u32>,
}

impl RunningCaps {
    /// The counts over `orders`: each order that holds a live attempt counts once against each
    /// cap it names and against its group.
    #[must_use]
    pub fn of<'a>(orders: impl IntoIterator<Item = &'a WorkOrder>) -> Self {
        let mut counts = Self::default();
        for order in orders {
            if order.holds_live_attempt() {
                counts.hold(order);
            }
        }
        counts
    }

    /// Counts a new live attempt of `order`: the pass calls it when it makes one, so a later
    /// order of the same pass sees the cap as full.
    pub fn hold(&mut self, order: &WorkOrder) {
        let names: BTreeSet<&String> = order.limits.caps.iter().collect();
        for name in names {
            let count = self.named.entry(name.clone()).or_default();
            *count = count.saturating_add(1);
        }
        if let Some(member) = &order.group {
            let count = self.groups.entry(member.group).or_default();
            *count = count.saturating_add(1);
        }
    }

    /// The live attempts that count against the cap named `name`.
    #[must_use]
    pub fn running(&self, name: &str) -> u32 {
        self.named.get(name).copied().unwrap_or(0)
    }

    /// The live attempts of the members of array group `group`.
    #[must_use]
    pub fn group_running(&self, group: &EntityId) -> u32 {
        self.groups.get(group).copied().unwrap_or(0)
    }
}

impl Vault {
    /// The caps that hold `order` now, given the live attempts `running` counts: a named cap
    /// whose setting is set and reached, and its group's cap when reached. Empty when none.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(super) fn cap_blockers_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        order: &WorkOrder,
        running: &RunningCaps,
    ) -> Result<Vec<Blocker>> {
        let mut blockers = Vec::new();
        let names: BTreeSet<&String> = order.limits.caps.iter().collect();
        for name in names {
            let Some(cap) = running_cap_in_txn(self, txn, name)? else {
                continue;
            };
            let count = running.running(name);
            if count >= cap {
                blockers.push(Blocker::CapFull {
                    cap: name.clone(),
                    running: count,
                });
            }
        }
        if let Some(member) = &order.group
            && let Some(group) = WORK_ORDER_GROUPS.get(&self.store, txn, &member.group)?
        {
            let count = running.group_running(&member.group);
            if count >= group.cap {
                blockers.push(Blocker::CapFull {
                    cap: group_cap_name(&member.group),
                    running: count,
                });
            }
        }
        Ok(blockers)
    }
}
