//! Array groups (pass 34, 1.1; row Q5): orders that share a group id are the members of one
//! array, and one `WORK_ORDER_GROUP` row caps how many of them hold a live attempt at once. The
//! issuer writes the row in the create write of the group's first member, with the cap that
//! member names and who made it; the running count is read from the member orders
//! ([`super::caps::RunningCaps`]), so the row never changes after it is written. The issuer
//! names every group: its id is its first member's order id, so no caller picks an id that
//! another requester's group may hold (row Q5-GROUP-ID-EXISTENCE-SHOWN).
use serde::{Deserialize, Serialize};

use crate::memory::verb_grant_caller::VerbGrantCaller;
use crate::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_NOT_FOUND, MemoryError};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

use super::record::{GroupMember, OrderedBy, WORK_ORDERS, WorkOrder};

pub(super) const WORK_ORDER_GROUPS: SideTable<EntityId, WorkOrderGroup, Named> =
    SideTable::new(&side_table::WORK_ORDER_GROUP);

/// One array group: its cap on running members, and who made it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorkOrderGroup {
    pub id: EntityId,
    /// The most members that hold a live attempt at once.
    pub cap: u32,
    /// The requester of the first member: only they, or the owner, order its other members.
    pub made_by: OrderedBy,
    pub made_at_ms: u64,
}

/// An order request's place in an array: `new` starts a group, `join` adds a member to one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GroupRequest {
    /// The array's first member, at `index`: its group takes this order's id, which the answer
    /// shows as the order's group, and holds `cap`, the most members that run at once.
    New { index: u32, cap: u32 },
    /// A later member, at `index`, of the group `group` (the id the first member's answer
    /// shows); the group's own cap holds.
    Join { group: EntityId, index: u32 },
}

impl GroupRequest {
    /// The member the order `order` stores: a new group takes the order's own id.
    #[must_use]
    pub const fn member(&self, order: EntityId) -> GroupMember {
        match *self {
            Self::New { index, .. } => GroupMember {
                group: order,
                index,
            },
            Self::Join { group, index } => GroupMember { group, index },
        }
    }
}

/// The door's check of `request`, by `by` (admitted as `caller`) for the new order `order`, in
/// the create's own write `txn`: the member the order stores, with the group row to write
/// beside it when the request starts a group, or the refusal.
///
/// # Errors
///
/// Storage errors. A refusal is the inner `Err`: `not_found` for a join of a group that does
/// not exist or that another requester made, which answer alike (as `after` does), so a join
/// tells an agent nothing about another's groups; the owner joins any group. `bad_request` for
/// an index another member holds.
pub(super) fn admit_group_member_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &GroupRequest,
    order: EntityId,
    by: &OrderedBy,
    caller: VerbGrantCaller,
    now_ms: u64,
) -> crate::Result<Result<(GroupMember, Option<WorkOrderGroup>), MemoryError>> {
    let member = request.member(order);
    let group = match *request {
        GroupRequest::New { cap, .. } => {
            return Ok(Ok((
                member,
                Some(WorkOrderGroup {
                    id: order,
                    cap,
                    made_by: by.clone(),
                    made_at_ms: now_ms,
                }),
            )));
        }
        GroupRequest::Join { group, .. } => group,
    };
    let joinable = WORK_ORDER_GROUPS
        .get(&vault.store, txn, &group)?
        .is_some_and(|row| match caller {
            VerbGrantCaller::Owner => true,
            VerbGrantCaller::Agent { .. } => row.made_by.actor() == by.actor(),
        });
    if !joinable {
        return Ok(Err(MemoryError::new(
            MEMORY_CODE_NOT_FOUND,
            "join names no group you can join: a group's members are ordered by the one who \
             made it, or the owner"
                .to_owned(),
            &["Start a group with a `new` member; its answer shows the group's id."],
        )));
    }
    let taken = WORK_ORDERS
        .scan(&vault.store, txn)?
        .into_iter()
        .any(|(_, order)| order.group == Some(member));
    if taken {
        return Ok(Err(MemoryError::new(
            MEMORY_CODE_BAD_REQUEST,
            format!("index {} of this group is ordered already", member.index),
            &[],
        )));
    }
    Ok(Ok((member, None)))
}

/// Whether `order`, the order a replayed request's intent key made, is the member `request`
/// asks for, read in `txn`: no member for none; for a join, the same group and index, of a group
/// `order` did not start; for a new group, the group `order` started, at the same index, holding
/// the same cap.
///
/// # Errors
///
/// Storage errors.
pub(super) fn replay_is_same_member_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    order: &WorkOrder,
    request: Option<&GroupRequest>,
) -> crate::Result<bool> {
    let Some(request) = request else {
        return Ok(order.group.is_none());
    };
    if order.group != Some(request.member(order.id)) {
        return Ok(false);
    }
    match *request {
        // The order that started a group stores its own id as the group's: a join of that
        // group at its index is not the request that made it.
        GroupRequest::Join { group, .. } => Ok(group != order.id),
        GroupRequest::New { cap, .. } => Ok(WORK_ORDER_GROUPS
            .get(&vault.store, txn, &order.id)?
            .is_some_and(|row| row.cap == cap)),
    }
}

impl Vault {
    /// Writes `group`, the row of a group's first member, in the member's create write.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(super) fn put_work_order_group_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        group: &WorkOrderGroup,
    ) -> crate::Result<()> {
        WORK_ORDER_GROUPS.put(&self.store, wtxn, &group.id, group)
    }

    /// The array group `id`, when its first member was ordered.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn work_order_group(&self, id: &EntityId) -> crate::Result<Option<WorkOrderGroup>> {
        let txn = self.store.env.read_txn()?;
        WORK_ORDER_GROUPS.get(&self.store, &txn, id)
    }
}

/// Takes the erased actor out of every group they made (the side table's actor scrub).
pub(crate) fn erase_group_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> crate::Result<()> {
    for (id, mut group) in WORK_ORDER_GROUPS.scan(&vault.store, wtxn)? {
        let changed = match &mut group.made_by {
            OrderedBy::Owner { owner } if *owner == Some(*actor) => {
                *owner = None;
                true
            }
            OrderedBy::Agent { actor: by, .. } if *by == Some(*actor) => {
                *by = None;
                true
            }
            _ => false,
        };
        if changed {
            WORK_ORDER_GROUPS.put(&vault.store, wtxn, &id, &group)?;
        }
    }
    Ok(())
}
