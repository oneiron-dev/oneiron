//! Versioned cohort records, lifecycle values and owner-bound request shapes.

use crate::entity_id::EntityId;
use crate::write_envelope::cohort_claims::snooze_policy::SnoozePolicyData;

/// CAMPAIGN definition schema version.
pub const CAMPAIGN_SCHEMA_VERSION: u32 = 1;

/// Lifecycle state of a campaign.
///
/// Mirrors [`SavedQueryLifecycle`](crate::saved_query::SavedQueryLifecycle)'s archive-is-a-transition rule; a campaign
/// has no paused state because it holds no evaluator to pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CampaignLifecycle {
    /// Addressable and mutable.
    Active,
    /// Retired. Still readable; never re-opened.
    Archived,
}

impl CampaignLifecycle {
    /// Wire token for this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Archived => "archived",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "archived" => Some(Self::Archived),
            _ => None,
        }
    }
}

/// A versioned campaign definition.
///
/// Not serde-derived for the same reason [`SavedQueryDefinition`](crate::saved_query::SavedQueryDefinition) is not:
/// [`EntityId`] has no serde impl, so entity references cross the wire as
/// canonical hex through [`campaign_record_to_json`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignDefinition {
    /// Definition schema version.
    pub schema_version: u32,
    /// The principal that owns this campaign.
    pub owner_actor: EntityId,
    /// Operator-facing name.
    pub name: String,
    /// Monotonic version, incremented by every accepted write.
    pub definition_version: u64,
    /// Lifecycle state.
    pub lifecycle: CampaignLifecycle,
    /// The pause a positive-later reply takes (FIX 9667). Create stores the
    /// shipped default when the request names none; the owner edits it, and
    /// each reply reads the value stored when it arrives.
    pub reply_snooze_policy: SnoozePolicyData,
}

/// A stored campaign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignRecord {
    /// Identity of the campaign.
    pub campaign_ref: EntityId,
    /// Current definition.
    pub definition: CampaignDefinition,
    /// Creation time.
    pub created_at: u64,
    /// Last accepted write.
    pub updated_at: u64,
}

/// Create request. There is no owner field: the owner is bound from the
/// authenticated principal at the write boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateCampaignRequest {
    /// Definition schema version.
    pub schema_version: u32,
    /// Operator-facing name.
    pub name: String,
    /// The positive-later pause, as a loaded preset's `snooze_policy` or the
    /// owner's own; absent takes the shipped default.
    pub reply_snooze_policy: Option<SnoozePolicyData>,
}

/// Update request. Also carries no owner field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateCampaignRequest {
    /// Version the caller believes is current; the compare half of the CAS.
    pub expected_definition_version: u64,
    /// Replacement name.
    pub name: String,
    /// Replacement positive-later pause; absent keeps the stored one.
    pub reply_snooze_policy: Option<SnoozePolicyData>,
}
