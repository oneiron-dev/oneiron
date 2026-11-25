//! Doors for the work order tests (pass 34, rows Q1 and Q5). Compiled only under
//! `--cfg oneiron_test_support`. A pinned workload with an approval in force is written
//! straight into `JOB_WORKLOAD`, standing for the owner's approve (whose presence check and
//! mesh grant check the workload tests prove), and an order is written as the order door
//! writes it for the caller it admitted.

use crate::job_workload::{JobWorkload, WorkloadApproval, WorkloadApprovedBy, WorkloadPin};
use crate::side_table::{self, Named, SideTable};
use crate::work_order::{WorkOrder, WorkOrderGroup};
use crate::{EntityId, Vault};

const JOB_WORKLOADS: SideTable<[u8; 32], JobWorkload, Named> =
    SideTable::new(&side_table::JOB_WORKLOAD);
const WORK_ORDERS: SideTable<EntityId, WorkOrder, Named> = SideTable::new(&side_table::WORK_ORDER);
const WORK_ORDER_GROUPS: SideTable<EntityId, WorkOrderGroup, Named> =
    SideTable::new(&side_table::WORK_ORDER_GROUP);

/// Pins `pin` and writes the owner `owner`'s approval of it on `machines` for `starters`
/// until `expires_at_ms`. Returns the workload digest.
///
/// # Panics
///
/// When the pin does not digest or the store write fails: a broken fixture.
pub fn put_approved_workload(
    vault: &Vault,
    pin: WorkloadPin,
    owner: EntityId,
    machines: Vec<EntityId>,
    starters: Vec<EntityId>,
    expires_at_ms: u64,
    now_ms: u64,
) -> String {
    let digest = pin.digest().expect("the pin digests");
    let mut key = [0_u8; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16).expect("hex digest");
    }
    let row = JobWorkload {
        digest: digest.clone(),
        pin,
        pinned_by: Some(owner),
        pinned_under: None,
        pinned_at_ms: now_ms,
        approval: Some(WorkloadApproval {
            by: WorkloadApprovedBy::Owner { owner: Some(owner) },
            machines,
            starters,
            expires_at_ms,
            at_ms: now_ms,
        }),
        revoked: None,
        project: None,
        check_in: None,
    };
    vault
        .with_write_txn_grouped(|txn| JOB_WORKLOADS.put(&vault.store, txn, &key, &row))
        .expect("the workload writes");
    digest
}

/// Writes `order` as the order door writes a new one.
///
/// # Panics
///
/// When the store write fails.
pub fn put_order(vault: &Vault, order: &WorkOrder) {
    vault
        .with_write_txn_grouped(|txn| WORK_ORDERS.put(&vault.store, txn, &order.id, order))
        .expect("the order writes");
}

/// Writes array group `group`'s row as the order door writes it with the group's first member
/// (row Q5).
///
/// # Panics
///
/// When the store write fails.
pub fn put_order_group(vault: &Vault, group: &WorkOrderGroup) {
    vault
        .with_write_txn_grouped(|txn| WORK_ORDER_GROUPS.put(&vault.store, txn, &group.id, group))
        .expect("the group writes");
}

/// The settled reply of the wait on `order` until `until`: what the order's writer delivered to
/// every run parked on it, and what a run that parks later is answered at once. `None` while
/// the order has not reached `until`.
///
/// # Panics
///
/// When the store read fails, the wait id is reserved, or the settled reply is erased or is
/// not JSON: a broken fixture.
#[must_use]
pub fn settled_order_wait(
    vault: &Vault,
    order: &EntityId,
    until: crate::work_order::WaitUntil,
) -> Option<serde_json::Value> {
    let wait = crate::work_order::order_wait_id(order, until).expect("order wait id");
    let txn = vault.store.env.read_txn().expect("read txn");
    crate::code_run::settled_wait_reply_in_txn(vault, &txn, wait)
        .expect("settled wait read")
        .map(|reply| serde_json::from_str(&reply).expect("settled reply is JSON"))
}

/// Whether the settled reply of the wait on `order` until `until` is in its erased form: the
/// wait settled, and an erase took the reply's copy, so reading it answers the typed
/// unavailable (`ResponseErased`). `false` while the wait has not settled or its reply reads.
///
/// # Panics
///
/// When the store read fails for another reason or the wait id is reserved: a broken fixture.
#[must_use]
pub fn settled_order_wait_erased(
    vault: &Vault,
    order: &EntityId,
    until: crate::work_order::WaitUntil,
) -> bool {
    let wait = crate::work_order::order_wait_id(order, until).expect("order wait id");
    let txn = vault.store.env.read_txn().expect("read txn");
    match crate::code_run::settled_wait_reply_in_txn(vault, &txn, wait) {
        Ok(_) => false,
        Err(error) if error.kind() == crate::ErrorKind::ResponseErased => true,
        Err(error) => panic!("settled wait read: {error}"),
    }
}
