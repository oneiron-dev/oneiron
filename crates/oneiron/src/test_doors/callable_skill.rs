//! Doors for the callable-skill integration tests. Compiled only under
//! `--cfg oneiron_test_support`; never API.
//!
//! - `tests/skill_call_caller_sandbox.rs`: exact source persistence and
//!   callable outcome evidence under the caller's attempt lease.
//! - `crates/oneiron-agent-runtime/tests/callable_wait_park.rs` (ENGINE CALL
//!   SANDBOX-WAIT-PARK-SEMANTICS): a first-party callable skill, stored and
//!   active, for the public `skill::execute_callable_skill` door to run. The
//!   skill store calls it needs are crate-private.

use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::error::Result;
use crate::skill::{
    SkillCallContract, SkillLifecycle, SkillRecord, SkillRole, canonical_skill_tree_hash,
};
use crate::skill_hub::{HubFile, HubPackage, SkillCapabilitySurface, SkillPackageFormat};
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

/// The stored file a door callable's call runs.
const CALL_REFERENCE: &str = "scripts/call.js";
/// A door callable's description, in its record and its frontmatter.
const DESCRIPTION: &str = "A test door callable";

/// Stores `source` as the generated first-party callable `name`, approved
/// and active, whose call takes `arguments` and returns `returns` (shapes as
/// `skill::matches_shape` reads them), and answers its id. The record and
/// its native package are written as a local callable's first revision is,
/// then activated.
///
/// # Errors
/// The skill store's.
#[doc(hidden)]
pub fn put_active_callable(
    vault: &Vault,
    name: &str,
    source: &str,
    arguments: &serde_json::Value,
    returns: &serde_json::Value,
) -> Result<EntityId> {
    let id = EntityId::now();
    // A native callable's frontmatter names the call contract its record
    // holds (`package_from_source`).
    let manifest = format!(
        "---\nname: {name}\ndescription: {DESCRIPTION}\nversion: 1\nrole: callable\ncall:\n  \
         reference: {CALL_REFERENCE}\n  arguments: {arguments}\n  returns: {returns}\n---\n\
         {DESCRIPTION}.\n"
    );
    let files = vec![
        HubFile::new("SKILL.md", manifest.into_bytes()),
        HubFile::new(CALL_REFERENCE, source.as_bytes().to_vec()),
    ];
    let hash = canonical_skill_tree_hash(
        files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )?;
    let record = SkillRecord::new(
        name,
        DESCRIPTION,
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        0.5,
        true,
        false,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("fixture"),
        )]),
    )
    .with_role(
        SkillRole::Callable,
        Some(SkillCallContract {
            reference: CALL_REFERENCE.to_owned(),
            arguments: arguments.clone(),
            returns: returns.clone(),
        }),
    )
    .with_content_hash(hash);
    let mut package = HubPackage::new(record.clone(), files, SkillCapabilitySurface::default());
    package.format = SkillPackageFormat::Native;
    vault.with_write_txn(|txn| {
        vault.put_skill_record_in_txn(txn, &id, &record, TimeRange { start: 1, end: 1 }, 1)?;
        vault.persist_hub_package_in_txn(txn, &id, &package)
    })?;
    let mut active = record;
    active.lifecycle_status = SkillLifecycle::Active;
    vault.update_skill_record(&id, &active, TimeRange { start: 2, end: 2 }, 2)?;
    Ok(id)
}
