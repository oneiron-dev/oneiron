//! Doors for the work order tests (pass 34, row Q1). Compiled only under
//! `--cfg oneiron_test_support`. A pinned workload with an approval in force is written
//! straight into `JOB_WORKLOAD`, standing for the owner's approve (whose presence check and
//! mesh grant check the workload tests prove), and an order is written as the order door
//! writes it for the caller it admitted.

use crate::job_workload::{JobWorkload, WorkloadApproval, WorkloadApprovedBy, WorkloadPin};
use crate::side_table::{self, Named, SideTable};
use crate::work_order::WorkOrder;
use crate::{EntityId, Vault};

const JOB_WORKLOADS: SideTable<[u8; 32], JobWorkload, Named> =
    SideTable::new(&side_table::JOB_WORKLOAD);
const WORK_ORDERS: SideTable<EntityId, WorkOrder, Named> = SideTable::new(&side_table::WORK_ORDER);

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
