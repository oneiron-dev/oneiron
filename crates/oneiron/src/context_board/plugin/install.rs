//! Install origin, target, and the validated manifest.
use super::super::frame::BudgetPolicyRef;
use super::codec::{PluginSuggestionKey, encode_section_manifest};
use super::errors::PluginResult;
use super::manifest::{
    SectionId, SectionManifest, SectionManifestEnvelope, SectionManifestProvenance, SectionVerbRef,
};
use super::validate::bounded_text;
use crate::entity_id::EntityId;
use crate::skill_hub::HubRef;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// §3 — install target, origin, and the validated manifest
// ---------------------------------------------------------------------------
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginInstallOrigin {
    /// Conversation INITIATED the install ("install the CRM pack"). It triggers
    /// the gate; it does not register anything.
    Conversation { turn_ref: String },
    DreamerSuggestion {
        run_id: String,
        /// Canonical lowercase hex at the serialized claim/API boundary.
        suggestion_key: String,
        digest_window: String,
    },
}

impl PluginInstallOrigin {
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Conversation { .. } => "conversation",
            Self::DreamerSuggestion { .. } => "dreamer_suggestion",
        }
    }

    /// Validates the origin's serialized shape, including the exact canonical
    /// hex form of a Dreamer suggestion key.
    pub fn validate(&self) -> PluginResult<()> {
        match self {
            Self::Conversation { turn_ref } => {
                bounded_text(turn_ref, "origin.turn_ref")?;
                Ok(())
            }
            Self::DreamerSuggestion {
                run_id,
                suggestion_key,
                digest_window,
            } => {
                bounded_text(run_id, "origin.run_id")?;
                bounded_text(digest_window, "origin.digest_window")?;
                PluginSuggestionKey::parse_hex(suggestion_key).map(|_| ())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PluginInstallTarget {
    /// An already-imported skill, `Candidate` or `Active`.
    ExistingSkill { skill_ref: EntityId },
    /// An UNINSTALLED hub package. `target_skill_ref` is preallocated in the
    /// payload; no SKILL row is written before consent.
    HubPackage {
        hub_ref: HubRef,
        target_skill_ref: EntityId,
    },
}

impl PluginInstallTarget {
    /// The entity the install claim hangs off. For an uninstalled package that
    /// is the EXISTING hub/provider entity — never the unwritten skill row.
    #[must_use]
    pub const fn claim_subject(&self) -> EntityId {
        match self {
            Self::ExistingSkill { skill_ref } => *skill_ref,
            Self::HubPackage { hub_ref, .. } => hub_ref.hub_id,
        }
    }

    /// Where the admitted skill lives once the flow completes.
    #[must_use]
    pub const fn target_skill_ref(&self) -> EntityId {
        match self {
            Self::ExistingSkill { skill_ref } => *skill_ref,
            Self::HubPackage {
                target_skill_ref, ..
            } => *target_skill_ref,
        }
    }
}

/// A manifest that passed one full validation phase. The inner envelope is
/// private: the only way to hold one is to have validated it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedSectionManifest(pub(super) SectionManifestEnvelope);

impl ValidatedSectionManifest {
    #[must_use]
    pub const fn envelope(&self) -> &SectionManifestEnvelope {
        &self.0
    }

    #[must_use]
    pub const fn manifest(&self) -> &SectionManifest {
        &self.0.manifest
    }

    #[must_use]
    pub const fn section_id(&self) -> &SectionId {
        &self.0.manifest.section_id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.0.manifest.name
    }

    #[must_use]
    pub const fn verbs(&self) -> &Vec<SectionVerbRef> {
        &self.0.manifest.verbs
    }

    #[must_use]
    pub const fn budget_policy(&self) -> &BudgetPolicyRef {
        &self.0.manifest.budget_policy
    }

    #[must_use]
    pub const fn provenance(&self) -> &SectionManifestProvenance {
        &self.0.manifest.provenance
    }

    /// Canonical bytes of the validated envelope.
    pub fn canonical_bytes(&self) -> PluginResult<Vec<u8>> {
        encode_section_manifest(&self.0)
    }
}
