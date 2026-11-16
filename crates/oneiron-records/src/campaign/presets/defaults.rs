//! Moved from `crates/oneiron/src/campaign/presets/defaults.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::write_envelope::cohort_claims::snooze_policy::SnoozePolicyData;
use serde::Deserialize;
use serde::Serialize;

/// The shipped policy dials [`CAMPAIGN_PRESET_DEFAULTS_JSON`] holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignPresetDefaults {
    /// The positive-later pause a campaign takes until its owner sets another.
    pub reply_snooze_policy: SnoozePolicyData,
    /// The audit window a preset starts from, in days.
    pub audit_window_days: u32,
    /// The desk rhythm's period token a preset starts from.
    pub desk_period: String,
}
