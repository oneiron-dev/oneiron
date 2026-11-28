//! TEST-ONLY: an experiment arm row put as given, so a test can stand an arm
//! in a state whose writer is a later row: rung 1 closed, or the arm
//! withdrawn (row M2-E's verdict writes; design pass 32 r2, T43 and T44).
//! And a unit claim put as given, whose writer is row M2-C's reserve door
//! (T16: a forecast after the rung's first claim).
//!
//! And the line notices' engine acts, one write each (row M2-H, section 6):
//! a unit's settle as the job's terminal write makes it, the notices the
//! clock makes due as the `lines.notices` job raises them, a machine's return
//! as the issuer's guard calls it, and the line notices the vault holds.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::experiment_arm::ExperimentArm;
use crate::gpu_line::{ClaimKey, UnitClaim, UnitEndReport, UnitSettleRefused, UnitSettlement};
use crate::inbox::{NotificationBody, NotificationKind, decode_notification_body};

/// Puts `arm` as given, in one write.
///
/// # Errors
///
/// A store failure.
pub fn put_arm(vault: &Vault, arm: &ExperimentArm) -> crate::Result<()> {
    vault.with_write_txn(|wtxn| crate::experiment_arm::put_arm_in_txn(vault, wtxn, arm))
}

/// Puts `claim` under its logical attempt as given, in one write.
///
/// # Errors
///
/// A store failure.
pub fn put_claim(vault: &Vault, claim: &UnitClaim) -> crate::Result<()> {
    vault.with_write_txn(|wtxn| crate::gpu_line::claim::put_claim_row_in_txn(vault, wtxn, claim))
}

/// Settles the unit whose claim is `key` and whose job is `job` by `report`
/// at `now_ms`, in one write, as the job's terminal write does.
///
/// # Errors
///
/// A store failure; the inner refusal when the settle wrote nothing.
pub fn settle_unit(
    vault: &Vault,
    key: &ClaimKey,
    job: &EntityId,
    report: &UnitEndReport,
    now_ms: u64,
) -> crate::Result<Result<UnitSettlement, UnitSettleRefused>> {
    vault.with_write_txn(|wtxn| {
        crate::gpu_line::settle_unit_in_txn(vault, wtxn, key, job, report, now_ms)
    })
}

/// Raises the line notices the clock has made due by `now_ms`, in one
/// write, as the `lines.notices` job does. Returns how many it wrote.
///
/// # Errors
///
/// A store failure.
pub fn raise_due_line_notices(vault: &Vault, now_ms: u64) -> crate::Result<u64> {
    vault.with_write_txn(|wtxn| {
        crate::gpu_line::notice::raise_due_line_notices_in_txn(vault, wtxn, now_ms)
    })
}

/// Tells that `machine` answers again under boot `boot_id` at `now_ms`, in
/// one write, as the issuer's guard does. Returns the notices it wrote.
///
/// # Errors
///
/// A store failure.
pub fn machine_returned(
    vault: &Vault,
    machine: &EntityId,
    boot_id: &str,
    now_ms: u64,
) -> crate::Result<Vec<EntityId>> {
    vault.with_write_txn(|wtxn| {
        crate::gpu_line::notify_machine_returned_in_txn(vault, wtxn, machine, boot_id, now_ms)
    })
}

/// Every live line notice of the vault (`NotificationKind::LineNotice`), in
/// id order.
///
/// # Errors
///
/// A store failure, or a notice body that does not decode.
pub fn line_notices(vault: &Vault) -> crate::Result<Vec<NotificationBody>> {
    use crate::ports::EntityStoreRead;
    let txn = vault.store.env.read_txn()?;
    let mut notices = Vec::new();
    for id in vault.store.port_entity_ids_by_type(
        &txn,
        crate::registry::ENTITY_TYPE_NOTIFICATION,
        None,
    )? {
        let id = id?;
        let crate::vault::LiveEntityRow::Live { entity_type, body } =
            crate::vault::live_entity_row_in_txn(&vault.store, &txn, &id)?
        else {
            continue;
        };
        if entity_type != crate::registry::ENTITY_TYPE_NOTIFICATION {
            continue;
        }
        let body = decode_notification_body(&body)?;
        if body.kind == NotificationKind::LineNotice {
            notices.push(body);
        }
    }
    Ok(notices)
}
