//! Doors for `tests/skill_call_caller_sandbox.rs`: exact source persistence
//! and callable outcome evidence under the caller's attempt lease.

use crate::error::Result;
use crate::skill::SkillRecord;
use crate::skill_hub::{HubFile, HubPackage, SkillPackageFormat};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

/// Writes the candidate and its exact package in the same write transaction.
pub fn put_skill_record_and_package(
    vault: &Vault,
    id: &EntityId,
    record: &SkillRecord,
    package: &HubPackage,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    vault.with_write_txn(|txn| {
        vault.put_skill_record_in_txn(txn, id, record, occurred, learned_at)?;
        vault.persist_hub_package_in_txn(txn, id, package)
    })
}

/// Reconstructs a package from its unchanged source tree and native record.
pub fn package_from_source(
    record: &SkillRecord,
    files: Vec<HubFile>,
    format: SkillPackageFormat,
) -> Result<HubPackage> {
    crate::skill_hub::package_from_source(record, files, format)
}

/// Projects a receipt outcome onto the executors that invoked the callable.
pub fn project_callable_receipt_outcome(
    vault: &Vault,
    skill: &EntityId,
    receipt_ref: &str,
    win: bool,
    at: u64,
) -> Result<()> {
    crate::skill_reliability::project_callable_receipt_outcome(vault, skill, receipt_ref, win, at)
}

/// Opens the snapshot used by the attributed-outcome assertion.
pub fn read_txn(vault: &Vault) -> Result<heed::RoTxn<'_>> {
    Ok(vault.store.env.read_txn()?)
}

/// Reads every attributed receipt on the caller's snapshot.
pub fn attributed_outcome_receipts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<Vec<String>> {
    crate::skill_reliability::attributed_outcome_receipts(vault, txn, skill)
}

/// Formats the artifact digest with the engine's lowercase hexadecimal encoder.
pub fn bytes_to_hex_lower(bytes: &[u8]) -> String {
    crate::entity_id::bytes_to_hex_lower(bytes)
}
