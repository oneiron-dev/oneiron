//! Owner-bound bootstrap inventory, pinned first-hub read and explicit defaults restore.

use crate::consent::AuthenticatedOwner;
use crate::memory::MemoryResult;
use crate::skill_hub::{DefaultSkillHub, HubImportReceipt};
use crate::{Error, TimeRange, Vault};

use super::{EmptyRequest, HubSkillRequest};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::skill_defaults::BootstrapSkillView;

pub fn skill_bootstrap_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: &EmptyRequest,
) -> MemoryResult<Vec<BootstrapSkillView>> {
    vault
        .bootstrap_skill_sources(owner)?
        .into_iter()
        .map(|source| {
            let resident = source
                .entity
                .map(|entity| {
                    super::skill_library_get_as_owner(vault, owner, &HubSkillRequest { entity })
                })
                .transpose()?;
            Ok(BootstrapSkillView {
                skill_id: source.skill_id,
                content_hash: source.content_hash,
                source: source.source,
                resident,
            })
        })
        .collect()
}

pub fn default_skill_hub_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: &EmptyRequest,
) -> MemoryResult<DefaultSkillHub> {
    owner.revalidate(vault)?;
    Ok(vault.default_skill_hub()?)
}

pub fn skill_restore_defaults_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: &EmptyRequest,
) -> MemoryResult<Vec<HubImportReceipt>> {
    let at = vault.now_recorded_at();
    vault
        .restore_default_skills(owner, TimeRange { start: at, end: at }, at)?
        .into_iter()
        .map(|entity| {
            vault
                .current_hub_import_receipts(&entity)?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    Error::InvariantViolation("restored default skill has no source receipt").into()
                })
        })
        .collect()
}
