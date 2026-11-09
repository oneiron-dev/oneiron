//! The grant-scoped forms of `vault.skills.get` and `vault.skills.list`
//! (primitive A, slice 6.4d; ENGINE CALL S64-4 = A: `site_skills_for`'s
//! judgment, no new policy). The owner reads the whole library, as before.
//! Any other caller reads a skill only while it is loadable (Active, Auto or
//! Approved, shared, with a runtime package) and its own read admits the row,
//! and sees the package without the owner's evidence.

use crate::EntityId;
use crate::claim::ClaimReadStatus;
use crate::memory::{MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::verbs::{
    HubSkillReceipts, HubSkillRequest, SkillLibraryListRequest, SkillLibraryPage, SkillLibraryView,
};

/// Whether the caller reads skill `entity` as a loadable package: its own
/// read admits the row in this snapshot, and the skill is live, loadable,
/// shared and has a runtime package. This is `Vault::site_skills_for`'s
/// judgment: a package that does not read admits nothing.
fn readable_loadable(
    memory: &Memory<'_>,
    read: &crate::claim::ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    policy: &crate::gate::PolicyManifestResolution,
    entity: &EntityId,
) -> MemoryResult<bool> {
    if !read.is_entity_readable_with_policy_in(txn, policy, entity)? {
        return Ok(false);
    }
    match memory.vault().loadable_skill_files_in_txn(txn, entity) {
        Ok(found) => Ok(found.is_some()),
        Err(error) => {
            tracing::warn!(
                %error,
                skill = %entity.to_hex(),
                "a skill's stored package did not read; no reader is served it"
            );
            Ok(false)
        }
    }
}

/// The package a caller other than the owner sees: the owner's evidence
/// (provenance, source messages, the stale note, fork lineage, scans and hub
/// receipts) is left out.
fn package_only(mut view: SkillLibraryView) -> SkillLibraryView {
    view.provenance = serde_json::Value::Null;
    view.source_messages = Vec::new();
    view.stale = None;
    view.lineage = Vec::new();
    view.scans = Vec::new();
    view.receipts = HubSkillReceipts {
        sources: Vec::new(),
        imports: Vec::new(),
        admission: None,
    };
    view
}

fn not_found() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_NOT_FOUND,
        "no loadable skill the caller reads has this id",
        &[],
    )
}

/// `vault.skills.get` for a caller other than the owner.
///
/// # Errors
///
/// A skill the caller does not read as a loadable package (`NOT_FOUND`, as an
/// absent one), the caller's read lane, and storage errors.
pub fn skill_library_get_as_reader(
    memory: &Memory<'_>,
    input: &HubSkillRequest,
) -> MemoryResult<SkillLibraryView> {
    let read = memory.read_lane(ClaimReadStatus::Recorded)?;
    read.persist_grant_clock()?;
    let admitted = {
        let txn = memory
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let policy = read.live_policy_manifest_in(&txn)?;
        readable_loadable(memory, &read, &txn, &policy, &input.entity)?
    };
    if !admitted {
        return Err(not_found());
    }
    Ok(package_only(crate::verbs::skill_library_view(
        memory.vault(),
        input,
    )?))
}

/// `vault.skills.list` for a caller other than the owner: a page of the
/// loadable skills it reads, after `after` in the type index.
///
/// # Errors
///
/// A zero limit, the caller's read lane, and storage errors.
pub fn skill_library_list_as_reader(
    memory: &Memory<'_>,
    input: &SkillLibraryListRequest,
) -> MemoryResult<SkillLibraryPage> {
    if input.limit == 0 {
        return Err(MemoryError::bad_request("limit must be positive"));
    }
    let vault = memory.vault();
    let ids = vault.entities_by_type_page(ENTITY_TYPE_SKILL, input.after.as_ref(), input.limit)?;
    let next_after = ids.last().copied();
    let read = memory.read_lane(ClaimReadStatus::Recorded)?;
    read.persist_grant_clock()?;
    let admitted: Vec<EntityId> = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let policy = read.live_policy_manifest_in(&txn)?;
        let mut admitted = Vec::new();
        for entity in ids {
            if readable_loadable(memory, &read, &txn, &policy, &entity)? {
                admitted.push(entity);
            }
        }
        admitted
    };
    let mut skills = Vec::with_capacity(admitted.len());
    for entity in admitted {
        skills.push(package_only(crate::verbs::skill_library_view(
            vault,
            &HubSkillRequest { entity },
        )?));
    }
    Ok(SkillLibraryPage { skills, next_after })
}

/// `vault.skills.get` on an in-process handle: the embedded owner's read, or
/// [`skill_library_get_as_reader`] for any other caller.
///
/// # Errors
///
/// As the read it takes.
pub fn skill_library_get_embedded(
    memory: &Memory<'_>,
    input: &HubSkillRequest,
) -> MemoryResult<SkillLibraryView> {
    match memory.embedded_owner("vault.skills.get") {
        Ok(owner) => crate::verbs::skill_library_get_as_owner(memory.vault(), &owner, input),
        Err(_) => skill_library_get_as_reader(memory, input),
    }
}

/// `vault.skills.list` on an in-process handle: the embedded owner's read, or
/// [`skill_library_list_as_reader`] for any other caller.
///
/// # Errors
///
/// As the read it takes.
pub fn skill_library_list_embedded(
    memory: &Memory<'_>,
    input: &SkillLibraryListRequest,
) -> MemoryResult<SkillLibraryPage> {
    match memory.embedded_owner("vault.skills.list") {
        Ok(owner) => crate::verbs::skill_library_list_as_owner(memory.vault(), &owner, input),
        Err(_) => skill_library_list_as_reader(memory, input),
    }
}
