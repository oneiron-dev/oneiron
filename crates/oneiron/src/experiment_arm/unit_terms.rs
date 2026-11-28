//! The fixed terms of a line unit's ask (design pass 32 r2, 5.2, checks 4 and 6): the contract,
//! the workload's pin and the seconds, the offer and the machine. The reserve checks them in its
//! write ([`super::unit_reserve_as`]); a waiting unit's door checks the same when it orders
//! ([`super::unit_order_as`], row H3), so an order that can never reserve is refused at once.

use crate::Vault;
use crate::gpu_line::GpuLine;
use crate::job_workload::JobWorkload;
use crate::memory::MemoryResult;

use super::ExperimentArm;
use super::reserve::{UnitReserveRequest, invalid_state};

/// Refuses the ask unless its contract is the arm's pin and the workload's pin carries that
/// contract and the ask's code revision, with the ask's seconds as its maximum (design 5.2,
/// check 4); answers the pinned workload. A waiting unit's door checks the same when it orders.
pub(super) fn check_contract_and_workload(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &UnitReserveRequest,
    arm: &ExperimentArm,
) -> MemoryResult<JobWorkload> {
    if request.contract_sha256 != arm.contract.sha256 {
        return Err(invalid_state(
            "contract_changed: the contract sha256 is not the arm's pin; a changed contract is a new arm",
        ));
    }
    let workload = vault
        .job_workload_in_txn(txn, &request.workload)?
        .ok_or_else(|| {
            invalid_state("workload_mismatch: no workload is pinned under this digest")
        })?;
    if workload.pin.contract_sha256 != arm.contract.sha256
        || workload.pin.commit != request.code_sha
    {
        return Err(invalid_state(
            "workload_mismatch: the workload's pin does not carry the arm's contract sha256 and this code revision",
        ));
    }
    if request.secs != workload.pin.request.maximum_secs {
        return Err(invalid_state(&format!(
            "maximum_mismatch: the unit asks {} s and its workload pin's maximum is {} s; they must be equal",
            request.secs, workload.pin.request.maximum_secs
        )));
    }
    Ok(workload)
}

/// Refuses the ask unless the line names its offer and, when it names one, its machine (design
/// 5.2, check 6). A waiting unit's door checks the same when it orders.
pub(super) fn check_offer_and_machine(
    request: &UnitReserveRequest,
    line: &GpuLine,
) -> MemoryResult<()> {
    if !line.offers.contains(&request.offer) {
        return Err(invalid_state(
            "offer_not_managed: the line does not name this offer; reserve on one of the line's offers",
        ));
    }
    if request
        .machine
        .is_some_and(|machine| !line.machines.contains(&machine))
    {
        return Err(invalid_state(
            "machine_not_allowed: the machine is not one of the line's; name one of them or none",
        ));
    }
    Ok(())
}
