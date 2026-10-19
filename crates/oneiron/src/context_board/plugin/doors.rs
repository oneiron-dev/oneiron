//! Production bindings for the plugin-section doors: the engine's own
//! section-binding resolver and the vault-backed install source/executor the
//! public `vault.packs.sections.*` verbs run on. The board implements two
//! state families (`claim` rows and the actor-private `scratchpad` blocks);
//! every other typed recipe reference fails closed here rather than being
//! admitted as prose.
use super::super::frame::{BudgetPolicyRef, PLUGIN_SECTION_BUDGET_POLICY_REF};
use super::errors::{PluginResult, PluginSectionError};
use super::install::PluginInstallTarget;
use super::manifest::{
    AuthorityLaneRef, PluginInstallExecutor, PluginInstallSource, SectionBindingResolver,
    StateFamilyRef,
};
use crate::entity_id::EntityId;
use crate::skill::SkillRecord;
use crate::skill_hub::{
    HubIndexEntry, HubPackage, HubRef, RefFetch, SkillHubAdapter, pinned_tracking,
};
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// The section bindings this engine actually implements. Shared by proposal
/// validation, post-consent admission and the registry rebuild, so a section
/// cannot be admitted under bindings no renderer honors.
pub struct EngineSectionBindings;

impl SectionBindingResolver for EngineSectionBindings {
    fn state_family_exists(&self, state_family: &StateFamilyRef) -> bool {
        state_family.version == 1 && matches!(state_family.family.as_str(), "claim" | "scratchpad")
    }

    fn authority_lane_exists(&self, authority: &AuthorityLaneRef) -> bool {
        matches!(authority.0.as_str(), "read" | "actor.private")
    }

    fn budget_policy_exists(&self, budget: &BudgetPolicyRef) -> bool {
        budget.0 == PLUGIN_SECTION_BUDGET_POLICY_REF
    }
}

/// Fetches the exact pinned package a hub ref names, through the configured
/// hub's own transport. Shared by the read-only source and the executor.
fn fetch_hub_package(vault: &Vault, hub_ref: &HubRef) -> PluginResult<HubPackage> {
    match vault.hub_ref_fetch(&pinned_tracking(hub_ref.clone())?, None)? {
        RefFetch::Git(adapter, _) => Ok(adapter.fetch_package(hub_ref)?),
        RefFetch::Http(adapter, _) => Ok(adapter.fetch_package(hub_ref)?),
    }
}

/// The vault itself as the exact-byte source: skill records by ref, hub
/// packages by their pinned ref over the configured hub transport.
pub struct VaultPluginInstallSource<'a> {
    pub vault: &'a Vault,
}

impl PluginInstallSource for VaultPluginInstallSource<'_> {
    fn skill_record(&self, skill_ref: &EntityId) -> PluginResult<Option<SkillRecord>> {
        Ok(self.vault.get_skill_record(skill_ref)?)
    }

    fn hub_package(&self, hub_ref: &HubRef) -> PluginResult<HubPackage> {
        fetch_hub_package(self.vault, hub_ref)
    }
}

/// Post-consent executor over the existing checked hub-import door. It lands
/// an uninstalled package as `Candidate` at the consented ref; activation
/// itself stays with the existing skill admission doors, so a still-Candidate
/// skill answers `PendingActivation` and the next registry rebuild admits
/// the section once the skill is `Active`.
pub struct VaultPluginInstallExecutor<'a> {
    pub vault: &'a Vault,
}

impl PluginInstallSource for VaultPluginInstallExecutor<'_> {
    fn skill_record(&self, skill_ref: &EntityId) -> PluginResult<Option<SkillRecord>> {
        Ok(self.vault.get_skill_record(skill_ref)?)
    }

    fn hub_package(&self, hub_ref: &HubRef) -> PluginResult<HubPackage> {
        fetch_hub_package(self.vault, hub_ref)
    }
}

fn ingest_checked<A: SkillHubAdapter>(
    vault: &Vault,
    adapter: &A,
    hub_ref: &HubRef,
    target_skill_ref: EntityId,
    now: u64,
) -> PluginResult<EntityId> {
    let package = adapter.fetch_package(hub_ref)?;
    let entry = HubIndexEntry {
        name: package.record.skill_id.clone(),
        description: package.record.desc.clone(),
        version: package.record.version.clone(),
        content_hash: package.content_hash()?,
        ref_string: hub_ref.ref_string.clone(),
    };
    Ok(vault.ingest_skill_from_adapter_checked(
        adapter,
        &entry,
        target_skill_ref,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?)
}

impl PluginInstallExecutor for VaultPluginInstallExecutor<'_> {
    fn import_candidate_under_claim(
        &self,
        vault: &Vault,
        target: &PluginInstallTarget,
        _approved_claim_id: &EntityId,
        now: u64,
    ) -> PluginResult<EntityId> {
        let PluginInstallTarget::HubPackage {
            hub_ref,
            target_skill_ref,
        } = target
        else {
            return Err(PluginSectionError::MissingInstallTarget {
                reference: "hub package".to_owned(),
            });
        };
        match vault.hub_ref_fetch(&pinned_tracking(hub_ref.clone())?, None)? {
            RefFetch::Git(adapter, _) => {
                ingest_checked(vault, &adapter, hub_ref, *target_skill_ref, now)
            }
            RefFetch::Http(adapter, _) => {
                ingest_checked(vault, &adapter, hub_ref, *target_skill_ref, now)
            }
        }
    }

    fn admit_candidate_under_claim(
        &self,
        vault: &Vault,
        skill_ref: &EntityId,
        _approved_claim_id: &EntityId,
        _now: u64,
    ) -> PluginResult<SkillRecord> {
        // Candidate -> Active is the existing skill admission doors' act
        // (marketplace permission ask, pack install fit), never this door's:
        // the record rides back unchanged and the caller answers
        // PendingActivation until a rebuild finds it Active.
        vault
            .get_skill_record(skill_ref)?
            .ok_or_else(|| PluginSectionError::MissingInstallTarget {
                reference: skill_ref.to_hex(),
            })
    }
}
