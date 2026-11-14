//! Moved from `crates/oneiron/src/memory/plugin_sections/install.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::context_board::plugin::manifest::SectionManifestEnvelope;
use serde::Deserialize;
use serde::Serialize;

/// What `vault.packs.sections.propose` concluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PluginSectionInstallOutcome {
    /// The fit was ready: a code-free section whose requests the caller
    /// already holds is installed and renders. Installing grants none of the
    /// requested permissions.
    Installed {
        /// The install claim (32 hex) the owner's revoke retracts.
        claim_ref: String,
        section_id: String,
        /// The supplying skill (32 hex).
        skill_ref: String,
        /// SHA-256 of the canonical manifest bytes, lowercase hex.
        manifest_digest: String,
        /// Every permission the fit evaluated; none is granted.
        permissions: Vec<String>,
        /// The verb that undoes this install.
        undo_verb: String,
        /// The installed manifest.
        manifest: SectionManifestEnvelope,
    },
    /// Anything else: the offer waits as a proposed install claim for the
    /// owner.
    PermissionAsk {
        /// The install claim (32 hex).
        claim_ref: String,
        /// Its pending-consent tray row (`gate:<hex>`).
        pending_ref: String,
        /// SHA-256 of the canonical manifest bytes, lowercase hex.
        manifest_digest: String,
        section_id: String,
        /// Why it asks: what it requests that the caller does not hold.
        analysis: String,
        /// Every permission the fit evaluated.
        permissions: Vec<String>,
        /// The validated manifest the owner is asked to grant.
        manifest: SectionManifestEnvelope,
    },
}
