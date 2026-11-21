//! Door for `tests/campaign_copy_review.rs` (lead ruling
//! COPY-REVIEW-JUDGE-BY-DEFAULT = B): a vault with no house voice guide
//! marker, as one whose campaign arrived without the create door (by sync, or
//! an archive import).

use crate::Vault;
use crate::error::Result;

/// Drops the house voice guide's marker; the guide NOTE stays.
///
/// # Errors
///
/// Storage errors.
pub fn forget_house_voice_guide(vault: &Vault) -> Result<()> {
    crate::campaign::house_voice_guide::forget_house_voice_guide(vault)
}
