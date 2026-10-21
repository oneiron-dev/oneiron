//! Owner-bound bootstrap inventory, pinned first-hub read and explicit defaults restore.
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::memory::MemoryResult;
use crate::skill_hub::{DefaultSkillHub, HubImportReceipt, HubRef};
use crate::{EntityId, Error, TimeRange, Vault};

use super::{EmptyRequest, HubSkillRequest, SkillLibraryView};

/// The expected build source beside the actual resident. Absence is reported,
/// never repaired by a read, and resident files are not replaced by build bytes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BootstrapSkillView {
    pub skill_id: String,
    pub content_hash: String,
    pub source: HubRef,
    pub resident: Option<SkillLibraryView>,
}

impl BootstrapSkillView {
    pub fn rows(&self) -> Vec<EntityId> {
        self.resident
            .as_ref()
            .map_or_else(Vec::new, SkillLibraryView::rows)
    }
}

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
                    super::sdk::skill_library_get_as_owner(
                        vault,
                        owner,
                        &HubSkillRequest { entity },
                    )
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
