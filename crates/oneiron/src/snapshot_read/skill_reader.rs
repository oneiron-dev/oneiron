//! The grant-scoped forms of `vault.skills.get` and `vault.skills.list`
//! (primitive A, slice 6.4d; ENGINE CALL S64-4 = A: `site_skills_for`'s
//! judgment, no new policy). The owner reads the whole library, as before.
//! Any other caller reads a skill only while it is loadable (Active, Auto or
//! Approved, shared, with a runtime package) and its own read admits the row,
//! and sees the package without the owner's evidence. The view is built in
//! the read transaction that admits the skill, so it shows the state that
//! read admitted, never a later one (#6976 review round 2).

use crate::EntityId;
use crate::claim::ClaimReadStatus;
use crate::memory::{MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::verbs::{HubSkillRequest, SkillLibraryListRequest, SkillLibraryPage, SkillLibraryView};

/// The view of skill `entity` the caller reads, built on `txn`, the read
/// that admits it. `None` unless the caller's own read admits the row in
/// this snapshot and the skill is live, loadable, shared and has a runtime
/// package: `Vault::site_skills_for`'s judgment, where a package that does
/// not read admits nothing. The view is this snapshot's record and package,
/// without the owner's evidence.
fn admitted_view_in_txn(
    memory: &Memory<'_>,
    read: &crate::claim::ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    policy: &crate::gate::PolicyManifestResolution,
    entity: &EntityId,
) -> MemoryResult<Option<SkillLibraryView>> {
    if !read.is_entity_readable_with_policy_in(txn, policy, entity)? {
        return Ok(None);
    }
    #[cfg(oneiron_test_support)]
    crate::test_doors::skill_read_hold::at_row_admitted();
    match memory.vault().loadable_skill_package_in_txn(txn, entity) {
        Ok(found) => Ok(found.map(|(record, package)| {
            crate::verbs::skill_package_view(*entity, record, Some(package))
        })),
        Err(error) => {
            tracing::warn!(
                %error,
                skill = %entity.to_hex(),
                "a skill's stored package did not read; no reader is served it"
            );
            Ok(None)
        }
    }
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
    let txn = memory
        .vault()
        .store
        .env
        .read_txn()
        .map_err(crate::Error::from)?;
    let policy = read.live_policy_manifest_in(&txn)?;
    admitted_view_in_txn(memory, &read, &txn, &policy, &input.entity)?.ok_or_else(not_found)
}

/// `vault.skills.list` for a caller other than the owner: a page of the
/// loadable skills it reads, after `after` in the type index. The page, the
/// admissions and the views read one snapshot.
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
    let read = memory.read_lane(ClaimReadStatus::Recorded)?;
    read.persist_grant_clock()?;
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let ids = vault.entities_by_type_page_in_txn(
        &txn,
        ENTITY_TYPE_SKILL,
        input.after.as_ref(),
        input.limit,
    )?;
    let next_after = ids.last().copied();
    let policy = read.live_policy_manifest_in(&txn)?;
    let mut skills = Vec::new();
    for entity in ids {
        if let Some(view) = admitted_view_in_txn(memory, &read, &txn, &policy, &entity)? {
            skills.push(view);
        }
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
