//! `vault.packs.sections.propose` (FIX 9752): one typed section offer on the
//! caller's own credential, decided by the deterministic fit. A code-free
//! section whose requests the caller already holds installs at once, and the
//! owner's `vault.packs.sections.revoke` undoes it; anything else waits as a
//! proposed install claim for the owner, with the fit's analysis. Neither
//! outcome grants a requested permission.

use super::{PluginSectionProposeRequest, plugin_error};
use crate::context_board::{
    EngineSectionBindings, PluginInstallOrigin, PluginInstallTarget, PluginSectionFitOutcome,
    VaultPluginInstallSource, digest_to_hex, install_plugin_section_after_fit,
};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::skill_hub::{CallerPermissions, HoldsNothing};
use crate::write_envelope::WriteProvenance;

/// The verb that undoes a fitted install: the owner's revoke.
const UNDO_VERB: &str = "vault.packs.sections.revoke";

#[doc(hidden)]
pub use oneiron_verb_wire::memory::plugin_sections::install::PluginSectionInstallOutcome;

impl Memory<'_> {
    /// Offers one typed section manifest on the caller's own credential with
    /// no host judgement of what that credential holds: every request asks,
    /// so the offer waits as a proposed install claim.
    pub fn plugin_section_propose(
        &self,
        input: &PluginSectionProposeRequest,
    ) -> MemoryResult<PluginSectionInstallOutcome> {
        self.plugin_section_propose_holding(input, &HoldsNothing)
    }

    /// Offers one typed section manifest on the caller's own credential,
    /// `caller` being its host's judgement of what that credential already
    /// holds. The fit decides between an install and the owner's ask.
    pub fn plugin_section_propose_holding(
        &self,
        input: &PluginSectionProposeRequest,
        caller: &dyn CallerPermissions,
    ) -> MemoryResult<PluginSectionInstallOutcome> {
        let vault = self.vault();
        let provenance = WriteProvenance::new(rmpv::Value::Map(vec![(
            rmpv::Value::from("surface"),
            rmpv::Value::from("vault.packs.sections.propose"),
        )]))
        .map_err(MemoryError::from)?;
        let outcome = install_plugin_section_after_fit(
            vault,
            self.write_actor(),
            provenance,
            PluginInstallTarget::from(&input.target),
            &input.manifest,
            PluginInstallOrigin::Conversation {
                turn_ref: input.turn_ref.clone(),
            },
            &VaultPluginInstallSource { vault },
            &EngineSectionBindings,
            caller,
            vault.now_recorded_at(),
        )
        .map_err(plugin_error)?;
        Ok(match outcome {
            PluginSectionFitOutcome::Installed(installed) => {
                self.produced_from([installed.claim_id]);
                PluginSectionInstallOutcome::Installed {
                    claim_ref: installed.claim_id.to_hex(),
                    section_id: installed.section_id.0,
                    skill_ref: installed.skill_ref.to_hex(),
                    manifest_digest: digest_to_hex(&installed.manifest_digest),
                    permissions: installed.permissions,
                    undo_verb: UNDO_VERB.to_owned(),
                    manifest: input.manifest.clone(),
                }
            }
            PluginSectionFitOutcome::PermissionAsk {
                proposal,
                analysis,
                permissions,
            } => {
                self.produced_from([proposal.claim_id]);
                PluginSectionInstallOutcome::PermissionAsk {
                    claim_ref: proposal.claim_id.to_hex(),
                    pending_ref: format!("gate:{}", proposal.decision_id.to_hex()),
                    manifest_digest: digest_to_hex(&proposal.manifest_digest),
                    section_id: input.manifest.manifest.section_id.0.clone(),
                    analysis,
                    permissions,
                    manifest: input.manifest.clone(),
                }
            }
        })
    }
}
