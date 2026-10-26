//! Shipped preset defaults (`defaults.json`) and the campaign's reply-snooze resolver.

use serde::{Deserialize, Serialize};

use super::shape::SnoozePolicyData;
use super::validate::validate_snooze_policy;
use crate::campaign::surface::load_registered_campaign;
use crate::error::Error;
use crate::{EntityId, Result, Vault};

/// The shipped policy dials, as data (FIX 9665).
///
/// These are the values a campaign or a preset starts from, never a range one
/// must match: an owner edits any of them and the edited value is the one that
/// runs.
pub const CAMPAIGN_PRESET_DEFAULTS_JSON: &str = include_str!("defaults.json");

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

/// Parses the shipped defaults.
///
/// # Errors
///
/// [`Error::InvariantViolation`] when the shipped JSON does not parse, and the
/// snooze validator's [`Error::InvalidConfig`] when its dials are not ordered.
/// Both are build defects, not runtime conditions.
pub fn campaign_preset_defaults() -> Result<CampaignPresetDefaults> {
    let defaults: CampaignPresetDefaults = serde_json::from_str(CAMPAIGN_PRESET_DEFAULTS_JSON)
        .map_err(|_| Error::InvariantViolation("campaign preset defaults are not valid JSON"))?;
    validate_snooze_policy(&defaults.reply_snooze_policy)?;
    Ok(defaults)
}

/// The shipped positive-later pause.
///
/// # Errors
///
/// As [`campaign_preset_defaults`].
pub fn default_reply_snooze_policy() -> Result<SnoozePolicyData> {
    Ok(campaign_preset_defaults()?.reply_snooze_policy)
}

/// The positive-later pause `campaign_ref` runs now (FIX 9667): its stored
/// campaign's own policy, read at reply time so an edit applies to the next
/// reply. A ladder call naming a campaign with no surface record, or a vault
/// with no campaign kind registered, takes the shipped default; that is the
/// absence of a record, never a refusal. Storage and decode errors propagate.
///
/// # Errors
///
/// Storage and decode errors, and [`campaign_preset_defaults`]'s.
pub fn resolve_reply_snooze_policy(
    vault: &Vault,
    campaign_ref: EntityId,
) -> Result<SnoozePolicyData> {
    match load_registered_campaign(vault, campaign_ref)? {
        Some(record) => Ok(record.definition.reply_snooze_policy),
        None => default_reply_snooze_policy(),
    }
}
