//! Plugin-section seam — the typed section manifest, its gated admission, the
//! live registry projection, and the pure plugin renderers (ONE-1706).
//!
//! ARCH-0067 §5 (“the section recipe”): every section — core or plugin — is the
//! same typed recipe `{ typed state source · typed verbs · authority lane ·
//! budget policy }`. Core sections are engine-defined; packs contribute
//! sections only through the **plugin gate**: an owner-consented install whose
//! payload is a typed section manifest, validated before the renderer touches
//! it. Conversation can *initiate* an install, but words never register a
//! section — every section enters through the gated path.
//!
//! ARCH-0067 §4 (the keystone): the renderer is one-way. Nothing here parses
//! rendered text back into state, and every caller-supplied string reaches the
//! board through exactly one escaped, quoted leaf position, so a claim value
//! cannot mint a row, a section boundary, or a wrapper tag.
//!
//! ARCH-0053 §6 (skill lifecycle): [`SkillLifecycle::loads_as_canon`] is the
//! render/admission precondition, never the proposal precondition. An
//! uninstalled or `Candidate` pack may be PROPOSED; owner consent covers
//! install plus admission; the section becomes renderable only once that same
//! approved flow turns the skill `Active`. There is no autonomous pre-consent
//! install.

mod admission;
mod claim;
mod codec;
mod errors;
mod install;
mod manifest;
mod render;
mod validate;

pub use self::admission::{
    AdmittedPluginSection, PluginSectionAdmission, PluginSectionRegistry,
    execute_approved_plugin_section_install,
};
pub use self::claim::{
    PLUGIN_INSTALL_CLAIM_SCHEMA_VERSION, PREDICATE_PLUGIN_SECTION_INSTALL,
    PluginInstallClaimPayload, PluginSectionInstallProposal, propose_plugin_section_install,
    propose_plugin_section_install_with_evidence,
};
pub use self::codec::{
    PluginSuggestionKey, decode_section_manifest, digest_to_hex, encode_section_manifest,
    section_manifest_digest,
};
pub use self::errors::{PluginResult, PluginSectionError};
pub use self::install::{PluginInstallOrigin, PluginInstallTarget, ValidatedSectionManifest};
pub use self::manifest::{
    AuthorityLaneRef, PluginInstallExecutor, PluginInstallSource, SECTION_MANIFEST_SCHEMA_VERSION,
    SectionBindingResolver, SectionId, SectionManifest, SectionManifestEnvelope,
    SectionManifestProvenance, SectionVerbAllowlist, SectionVerbRef, SkillLifecycleSource,
    StateFamilyRef,
};
pub use self::render::{
    PLUGIN_PROPOSALS_SECTION_NAME, PluginProposalRow, PluginSectionRow, PluginSectionSnapshot,
    pending_plugin_proposal_rows, quoted_leaf, render_plugin_proposal_row,
    render_plugin_proposal_section, render_plugin_row, render_plugin_sections,
};
pub use self::validate::{
    CORE_SECTION_IDS, validate_manifest_for_admission, validate_manifest_for_proposal,
};

#[cfg(test)]
mod tests;

// The flat plugin.rs module used to provide these names to the inline test
// module through `use super::*`: public items resolve through the re-exports
// above, the one `pub(super)` helper the tests name bare
// (`validate_manifest_shape`) through the glob below, and the external names
// through the old file header imports.
#[cfg(test)]
use self::validate::*;
#[cfg(test)]
use super::frame::{BoardFrameError, BudgetPolicyRef, SectionPolicy, ShedRank};
#[cfg(test)]
use crate::board_verb::BOARD_VERBS;
#[cfg(test)]
use crate::claim::ClaimApprovalStatus;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::skill::{SkillLifecycle, SkillRecord};
#[cfg(test)]
use crate::task_verb::TASKS_VERBS;
#[cfg(test)]
use rmpv::Value;
