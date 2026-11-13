//! Versioned cohort records, lifecycle values and owner-bound request shapes.

use crate::entity_id::EntityId;
use crate::write_envelope::cohort_claims::snooze_policy::SnoozePolicyData;

/// CAMPAIGN definition schema version.
pub const CAMPAIGN_SCHEMA_VERSION: u32 = 2;

/// Lifecycle state of a campaign.
///
/// A new campaign is authored as Draft, launches into Active, may pause with
/// an owner question, and archives once. Archive remains a one-way transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CampaignLifecycle {
    /// Authored but not launched. Programs may be edited; nothing enrolls.
    Draft,
    /// Launched and enrolling.
    Active,
    /// Held out of enrollment until the owner clears its pause or launches it.
    Paused,
    /// Retired. Still readable; never re-opened.
    Archived,
}

impl CampaignLifecycle {
    /// Wire token for this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Archived => "archived",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "draft" => Some(Self::Draft),
            "active" => Some(Self::Active),
            "paused" => Some(Self::Paused),
            "archived" => Some(Self::Archived),
            _ => None,
        }
    }
}

/// Who reviews a campaign's copy before it sends (ARCH-0059 #copy-review).
///
/// The review governs a campaign only when it names a voice guide or pins
/// human review: a [`Self::Judge`] campaign with no voice guide has nothing
/// to check its copy against, and sends as before.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CopyReviewMode {
    /// A judge model checks each body version against the voice guide; copy
    /// that passes sends, and failing or unreviewed copy is held.
    #[default]
    Judge,
    /// The owner reviews: every send holds for the owner's approve-once
    /// press on that send.
    Human,
}

impl CopyReviewMode {
    /// Wire token for this mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Judge => "judge",
            Self::Human => "human",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "judge" => Some(Self::Judge),
            "human" => Some(Self::Human),
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
    /// The NOTE whose text is this campaign's voice guide, which its copy
    /// review checks each body against; `None` when the campaign names none.
    pub voice_guide_ref: Option<EntityId>,
    /// Who reviews this campaign's copy.
    pub copy_review: CopyReviewMode,
}

impl CampaignDefinition {
    /// Whether copy review holds this campaign's sends: it names a voice
    /// guide, or it pins human review.
    #[must_use]
    pub fn copy_review_governs(&self) -> bool {
        self.voice_guide_ref.is_some() || self.copy_review == CopyReviewMode::Human
    }
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
    /// The voice guide NOTE; absent names none.
    pub voice_guide_ref: Option<EntityId>,
    /// Who reviews the copy; absent takes [`CopyReviewMode::Judge`].
    pub copy_review: Option<CopyReviewMode>,
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
    /// Replacement voice guide: absent keeps the stored one, `Some(None)`
    /// clears it, and `Some(Some(note))` names a new one.
    pub voice_guide_ref: Option<Option<EntityId>>,
    /// Replacement review mode; absent keeps the stored one.
    pub copy_review: Option<CopyReviewMode>,
}
