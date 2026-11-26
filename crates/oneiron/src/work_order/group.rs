//! Array groups (pass 34, 1.1; row Q5): orders that share a group id are the members of one
//! array, and one `WORK_ORDER_GROUP` row caps how many of them hold a live attempt at once. The
//! issuer writes the row in the create write of the group's first member, with the cap that
//! member names and who made it; the running count is read from the member orders
//! ([`super::caps::RunningCaps`]), so the row never changes after it is written.
use serde::{Deserialize, Serialize};

use crate::memory::verb_grant_caller::VerbGrantCaller;
use crate::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MemoryError};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

use super::record::{GroupMember, OrderedBy, WORK_ORDERS};

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

/// An order request's place in an array: the first member names the cap; a later member names
/// the same cap or none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupRequest {
    pub group: EntityId,
    pub index: u32,
    #[serde(default)]
    pub cap: Option<u32>,
}

impl GroupRequest {
    /// The member the order stores.
    #[must_use]
    pub const fn member(&self) -> GroupMember {
        GroupMember {
            group: self.group,
            index: self.index,
        }
    }
}

fn refused(code: &str, message: String) -> MemoryError {
    MemoryError::new(code, message, &[])
}

/// The door's check of a member `request` by `by` (admitted as `caller`), in the create's own
/// write `txn`: the group row to write with the order when it is the group's first member,
/// `None` for a later member, or the refusal.
///
/// # Errors
///
/// Storage errors. A refusal is the inner `Err`: `bad_request` for a first member with no cap,
/// a cap that differs from the group's, or an index another member holds; `forbidden` for a
/// member of another requester's group.
pub(super) fn admit_group_member_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &GroupRequest,
    by: &OrderedBy,
    caller: VerbGrantCaller,
    now_ms: u64,
) -> crate::Result<Result<Option<WorkOrderGroup>, MemoryError>> {
    let Some(group) = WORK_ORDER_GROUPS.get(&vault.store, txn, &request.group)? else {
        let Some(cap) = request.cap else {
            return Ok(Err(refused(
                MEMORY_CODE_BAD_REQUEST,
                "the first member of a group names its cap: the most members that run at once"
                    .to_owned(),
            )));
        };
        return Ok(Ok(Some(WorkOrderGroup {
            id: request.group,
            cap,
            made_by: by.clone(),
            made_at_ms: now_ms,
        })));
    };
    if matches!(caller, VerbGrantCaller::Agent { .. }) && group.made_by.actor() != by.actor() {
        return Ok(Err(refused(
            MEMORY_CODE_FORBIDDEN,
            "this group's members are ordered by the one who made it, or the owner".to_owned(),
        )));
    }
    if let Some(cap) = request.cap
        && cap != group.cap
    {
        return Ok(Err(refused(
            MEMORY_CODE_BAD_REQUEST,
            format!(
                "this group's cap is {}: a member names the same cap or none",
                group.cap
            ),
        )));
    }
    let member = request.member();
    let taken = WORK_ORDERS
        .scan(&vault.store, txn)?
        .into_iter()
        .any(|(_, order)| order.group == Some(member));
    if taken {
        return Ok(Err(refused(
            MEMORY_CODE_BAD_REQUEST,
            format!("index {} of this group is ordered already", request.index),
        )));
    }
    Ok(Ok(None))
}

/// Whether a replayed member `request` asks for its group's cap, read in `txn`: true when it
/// names no cap (the group's own then holds), or names the cap the group's row holds. A replay
/// that names another cap is another request.
///
/// # Errors
///
/// Storage errors.
pub(super) fn replay_keeps_group_cap_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: Option<&GroupRequest>,
) -> crate::Result<bool> {
    let Some((group, cap)) = request.and_then(|request| Some((request.group, request.cap?))) else {
        return Ok(true);
    };
    Ok(WORK_ORDER_GROUPS
        .get(&vault.store, txn, &group)?
        .is_some_and(|row| row.cap == cap))
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
