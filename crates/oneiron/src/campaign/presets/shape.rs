//! Typed consultancy-preset shape: identity consts plus every pub struct and enum.

// ---------------------------------------------------------------------------
// Ratified identity
// ---------------------------------------------------------------------------

/// The host-supplied consultancy preset this module validates.
pub const CONSULTANCY_PRESET_ID: &str = "crm.consultancy.v1";

/// The preset schema version that pairs with [`CONSULTANCY_PRESET_ID`].
pub const CONSULTANCY_PRESET_VERSION: u32 = 1;

#[doc(hidden)]
pub use oneiron_records::campaign::presets::shape::{
    BriefSectionData, BriefTemplateData, BriefTemplateKind, BriefTemplateSet, CampaignPresetData,
    CampaignTemplateData, CommitmentRhythmData, LanePolicyData, QuestionBlockData, RhythmAnchor,
    RhythmCheckpointData,
};

pub use crate::write_envelope::cohort_claims::snooze_policy::SnoozePolicyData;
