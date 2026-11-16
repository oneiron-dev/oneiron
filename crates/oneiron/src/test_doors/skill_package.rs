//! Doors for `tests/primitive_a_skill_reader.rs` (#6986 review round 2) and
//! `tests/skillset_shared_files.rs` (0053-SKILLSET). The first lands an
//! owner-authored skill with its package files as the package store keeps
//! them, credential-bearing files included (`Vault::persist_hub_package_in_txn`
//! keeps such a tree and skips only its replicated carrier), then activates
//! it, so the test can show what a reader other than the owner is served. The
//! second reads the files a skill run reads.

use crate::error::Result;
use crate::skill::{SkillLifecycle, SkillRecord};
use crate::skill_hub::{HubFile, HubPackage, SkillCapabilitySurface};
use crate::{EntityId, TimeRange, Vault};

/// Lands `record`, a candidate whose content hash names `files`, with
/// `files` as its stored package, then moves it to `Active`, in one write.
/// An `Approved` record is then a loadable skill.
///
/// # Errors
///
/// The skill doors' refusals and storage errors.
pub fn land_active_skill_with_files(
    vault: &Vault,
    record: &SkillRecord,
    files: Vec<HubFile>,
) -> Result<EntityId> {
    let id = EntityId::now();
    let occurred = TimeRange { start: 20, end: 20 };
    let package = HubPackage::new(record.clone(), files, SkillCapabilitySurface::default());
    let mut active = record.clone();
    active.lifecycle_status = SkillLifecycle::Active;
    vault.with_write_txn(|txn| {
        vault.put_skill_record_in_txn(txn, &id, record, occurred, 21)?;
        vault.persist_hub_package_in_txn(txn, &id, &package)?;
        vault.put_skill_record_in_txn(txn, &id, &active, occurred, 22)
    })?;
    Ok(id)
}

/// The files skill `id`'s runtime package holds, as a skill run reads them
/// (`Vault::runtime_skill_package_in_txn`), for `tests/skillset_shared_files.rs`
/// (0053-SKILLSET); `None` when the skill has no package.
///
/// # Errors
///
/// The skill is unknown, or a storage error.
pub fn runtime_package_files(vault: &Vault, id: &EntityId) -> Result<Option<Vec<HubFile>>> {
    let rtxn = vault.store.env.read_txn()?;
    let record = vault.read_skill_record_in_txn(&rtxn, id)?;
    Ok(vault
        .runtime_skill_package_in_txn(&rtxn, id, &record)?
        .map(|package| package.files))
}
