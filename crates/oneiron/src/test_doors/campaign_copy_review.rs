//! Doors for `tests/campaign_copy_review.rs` (lead ruling
//! COPY-REVIEW-JUDGE-BY-DEFAULT = B): a vault with no house voice guide
//! marker, as one whose campaign arrived without the create door (by sync, or
//! an archive import); and a pass a judge stored for a body while the
//! campaign's owner could still read its voice guide.

use crate::campaign::enrollment::CampaignProgramStep;
use crate::error::Result;
use crate::{EntityId, Vault};

/// Drops the house voice guide's marker; the guide NOTE stays.
///
/// # Errors
///
/// Storage errors.
pub fn forget_house_voice_guide(vault: &Vault) -> Result<()> {
    crate::campaign::house_voice_guide::forget_house_voice_guide(vault)
}

/// Stores a passing verdict for the body `step` sends for `campaign_ref`,
/// judged against the voice guide NOTE `guide` at its live version.
///
/// # Errors
///
/// Storage errors; a step with no outward call, or a guide with no document.
pub fn store_passing_copy_review_verdict(
    vault: &Vault,
    campaign_ref: EntityId,
    step: &CampaignProgramStep,
    guide: EntityId,
) -> Result<()> {
    crate::campaign::enrollment::store_passing_copy_review_verdict(vault, campaign_ref, step, guide)
}
